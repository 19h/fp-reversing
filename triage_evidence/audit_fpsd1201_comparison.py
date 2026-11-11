#!/usr/bin/env python3
"""Independent original-byte copy/comparison replay and integer/byte oracles.

Never imports the new producer. Frozen CPU/journal mechanisms are extended
with independent fixtures, exact descending copy addresses and signed-value
comparison. O(I+C*(B+F+V+P*J+R)) time and
O(I+B+F+C*(V+J+P+R)) space; solver cost separate. No native effects.
"""
import json,struct
from pathlib import Path
from hashlib import sha256
from collections import Counter
import z3
from unicorn import arm64_const as A
from audit_fpsd1201_shift import Replay as Previous,source_checks_new as shift_source,source_checks,lift_details,CS,ROOT,OWNER,CONTEXT,FP,SP,HALT,RAM,Core,source_and_proofs,reference_and_source,unpack
from verify_daemon_reader_record_payloads_publication import read

COPY=0x649430;CMP=0x33abec;IR=FP+0x100;FIRST=OWNER+0x800;SECOND=OWNER+0xa00
L1=OWNER+0x1000;L2=OWNER+0x1400;MASK=0xffffffff;BASE=0x4b0cf050;K=0x1ac70ef2
SHA=lambda b:sha256(b).hexdigest()


def count(d):
    n=(int.from_bytes(d[4:8],'little')-BASE)&MASK
    return n-(1<<32)if n>>31 else n


class Replay(Previous):
    def __init__(self,p,record,operand,shift,code,banks,D):
        baseline=p if p['configuration']['mode']=='nested'else shift['profiles'][0]
        super().__init__(baseline,record,operand,code[:12],banks,D);self.p=p;self.c=p['configuration'];self.copy_i=self.cmp_i=self.limb_i=0
        for a,n in [(0x649000,4096),(0x33a000,8192)]:self.u.mem_map(a,n)
        for r in code[12:]:
            a=int(r['start'],16);b=bytes.fromhex(r['bytes_hex']);self.u.mem_write(a,b);self.ranges.append((a,a+len(b)))
        c=self.c
        if c['mode']!='nested':
            self.phase=c['mode'];self.stats=Counter()
            if c['mode']=='copy':
                n=c['count'];self.u.mem_write(FIRST,struct.pack('<IIQ',64,(BASE+c['sign']*n)&MASK,L1 if n else 0))
                self.u.mem_write(SECOND,struct.pack('<IIQ',91,0xdeadbeef,L2 if n else 0))
                for j in range(n):
                    word=0 if c['pattern']=='zero'else(0x13579bdf+j*0x1020305)&MASK
                    self.u.mem_write(L1+j*4,(word^K).to_bytes(4,'little'))
                m=(((IR&MASK)^0x309487ae)*0x87cfdb29)&MASK
                self.u.mem_write(IR,struct.pack('<QIIQ',FIRST,(0x2f63-m)&MASK,0xa5a5a5a5,FIRST if c['same_object']else SECOND));entry=COPY
            else:
                for vk,ck,d,payload in [('first_shex','first_count',FIRST,L1),('second_shex','second_count',SECOND,L2)]:
                    v=int(c[vk],16);n=(abs(v).bit_length()+31)//32;s=(-n if v<0 else n)if not c['noncanonical']else c[ck]
                    self.u.mem_write(d,struct.pack('<IIQ',64,(BASE+s)&MASK,payload))
                    for j in range(max(abs(s),n)):self.u.mem_write(payload+4*j,(((abs(v)>>(32*j))&MASK)^K).to_bytes(4,'little'))
                m=(((IR&MASK)^0x302a1e77)*0xcae5b081)&MASK
                self.u.mem_write(IR,struct.pack('<QIIQII',FIRST,0xa5a5a5a5,0xa5a5a5a5,SECOND,(0x69d6-m)&MASK,0xa5a5a5a5));entry=CMP
            self.setreg(0,IR);self.setreg(30,HALT);self.u.reg_write(A.UC_ARM64_REG_PC,entry);self.frame(p['initial'])
            for row,(a,n)in zip(p['initial_RAM'],RAM):assert row['address']==hex(a)and unpack(row['payload'])==self.ram(a,n)
    def descriptor(self,a):
        raw=self.ram(a,16);ptr=int.from_bytes(raw[8:],'little')
        return {'address':hex(a),'descriptor16_hex':raw.hex(),'payload256_hex':self.ram(ptr,256).hex()if ptr else None}
    def numeric(self,d):
        raw=bytes.fromhex(d['descriptor16_hex']);n=count(raw);payload=bytes.fromhex(d['payload256_hex'])if d['payload256_hex']is not None else b''
        value=sum((int.from_bytes(payload[j*4:j*4+4],'little')^K)<<(32*j)for j in range(abs(n)))
        return -value if n<0 else value
    def leaf_point(self,pc):
        iscopy=pc in [COPY,0x6496b0];key='copy_points'if iscopy else'compare_points';index=self.copy_i if iscopy else self.cmp_i
        point=self.p[key][index]
        if iscopy:self.copy_i+=1
        else:self.cmp_i+=1
        self.frame(point['CPU'])
        if pc in [COPY,CMP]:
            r=self.reg(0)
            if iscopy:self.copy_record=r
            else:self.compare_record=r
        r=self.copy_record if iscopy else self.compare_record;raw=self.ram(r,32)
        src=self.descriptor(int.from_bytes(raw[:8],'little'));dst=self.descriptor(int.from_bytes(raw[16:24],'little'))
        assert {k:v for k,v in point.items()if k!='CPU'}=={'pc':hex(pc),'record_pointer':hex(r),'record32_hex':raw.hex(),'first':src,'second':dst}
        if pc==COPY:
            m=(((r&MASK)^0x309487ae)*0x87cfdb29)&MASK;assert(int.from_bytes(raw[8:12],'little')+m)&MASK==0x2f63
            self.copy_sp=self.u.reg_read(A.UC_ARM64_REG_SP)
            self.copy_entry=(raw,src,dst,self.r,self.w)
        if pc==0x6496b0:
            before,s,d,ri,wi=self.copy_entry;assert raw==before and src==s
            original=bytes.fromhex(d['descriptor16_hex']);source=bytes.fromhex(s['descriptor16_hex']);after=bytes.fromhex(dst['descriptor16_hex']);n=abs(count(source))
            reads=[q for q in self.p['source_reads'][ri:self.r]if self.p['source_visits'][q['visit']]['pc']in ['0x649624','0x649678','0x64968c']]
            writes=[q for q in self.p['source_writes'][wi:self.w]if self.p['source_visits'][q['visit']]['pc']in ['0x649588','0x64962c','0x649680','0x649694']]
            if s['address']==d['address']:
                assert dst==d and not reads and not writes;self.stats['same_descriptor_bypasses_checked']+=1
            else:
                assert after==original[:4]+source[4:8]+original[8:]
                srcptr=int.from_bytes(source[8:],'little');dstptr=int.from_bytes(original[8:],'little')
                assert [(int(q['address'],16),q['size_B'])for q in reads]==[(srcptr+4*j,4)for j in reversed(range(n))]
                assert [(int(q['address'],16),q['size_B'])for q in writes]==[(int(d['address'],16)+4,4)]+[(dstptr+4*j,4)for j in reversed(range(n))]
                if n:
                    b=bytes.fromhex(d['payload256_hex']);sbytes=bytes.fromhex(s['payload256_hex']);assert bytes.fromhex(dst['payload256_hex'])==sbytes[:4*n]+b[4*n:]
                else:assert dst['payload256_hex']==d['payload256_hex'];self.stats['zero_count_no_limb_access_checked']+=1
                self.stats['raw_limb_copies_checked']+=n;self.stats['distinct_descriptor_copies_checked']+=1
            if self.c['mode']=='nested':
                assert int(s['address'],16)==CONTEXT+0x290 and int(d['address'],16)==self.copy_sp+0xa0
                assert int.from_bytes(original[8:],'little')==self.copy_sp+0xc0
                seed=self.c['second_seed_u64'];pad=16*((((seed*0x2e9d+1)&((1<<64)-1))>>60)+1)
                assert self.copy_sp==self.caller_sp-0x3a0-pad;self.stats['seed_dependent_stack_geometries_checked']+=1
                assert int.from_bytes(source[:4],'little')==1 and int.from_bytes(original[:4],'little')==130
            self.stats['complete_copy_oracles_checked']+=1
        if pc==CMP:
            m=(((r&MASK)^0x302a1e77)*0xcae5b081)&MASK;assert(int.from_bytes(raw[24:28],'little')+m)&MASK==0x69d6
            self.cmp_entry=(raw,src,dst,self.numeric(src),self.numeric(dst))
        if pc==0x33b0fc:
            before,s,d,a,b=self.cmp_entry;assert src==s and dst==d and raw[:8]==before[:8]and raw[12:]==before[12:]
            if self.c.get('noncanonical'):
                ca,cb=count(bytes.fromhex(s['descriptor16_hex'])),count(bytes.fromhex(d['descriptor16_hex']));expected=0x312bc2c1+(cb>ca)-(cb<ca)
                assert a==b==0;self.stats['noncanonical_numeric_zero_counterexamples_checked']+=1
            else:
                expected=0x312bc2c1+(b>a)-(b<a);self.stats['signed_integer_comparison_oracles_checked']+=1
            assert int.from_bytes(raw[8:12],'little')==expected,(self.c['label'],hex(int.from_bytes(raw[8:12],'little')),hex(expected))
            self.stats['complete_compare_oracles_checked']+=1
    def hook(self,u,pc,n,data):
        self.flush()
        if pc in [COPY,0x6496b0,CMP,0x33b0fc]:self.leaf_point(pc)
        if pc in [0x33af24,0x33afd0,0x33b02c,0x33b08c]:
            q=self.p['limb_points'][self.limb_i];self.limb_i+=1;assert q['pc']==hex(pc);self.frame(q['CPU'])
            assert self.reg(3)==0x8011
            if pc==0x33af24:assert self.reg(19)==0xc67b
            if pc==0x33b02c:assert self.reg(16)==2 and self.reg(19)==0x4ee6
        if pc==0x14f9d74:
            self.stop='unretained_callee';self.frame(self.p['terminal']);e=self.p['frontier']
            assert e=={'pc':'0x14f9d74','target':'0x5e8158','modifier':'0x6144','original_slot':'0x1d03920','instruction':'blraa x8, x17','instruction_executed':False,'argument_record80_hex':self.ram(self.reg(0),80).hex()}
            assert(self.reg(8),self.reg(17))==(0x5e8158,0x6144);row=self.D[0x1d03920]
            assert row['target']=='0x5e8158'and row['diversity']=='0x6144'and row['key']=='IA'and not row['address_diversity'];self.used.add(0x1d03920);u.emu_stop();return
        if pc==0x14f94c4 or self.c['mode']!='nested':return Core.hook(self,u,pc,n,data)
        super().hook(u,pc,n,data)
    def run(self):
        if self.c['mode']=='nested':result=super().run()
        else:
            self.u.emu_start(COPY if self.c['mode']=='copy'else CMP,0,count=50000);self.flush();assert self.stop==self.p['stop_reason']=='returned'
            assert(self.v,self.r,self.w,self.pi,self.ci)==tuple(len(self.p[k])for k in ['source_visits','source_reads','source_writes','PAC_models','CPU_points'])
            assert self.u.reg_read(A.UC_ARM64_REG_SP)==SP and self.p['used_original_pointer_rows']==[self.D[a]for a in sorted(self.used)]
            for row,(a,n)in zip(self.p['final_RAM'],RAM):assert row['address']==hex(a)and unpack(row['payload'])==self.ram(a,n);self.stats['complete_final_RAM_bytes_checked']+=n
            self.stats.update({'original_visits_checked':self.v,'original_reads_checked':self.r,'original_writes_checked':self.w,'PAC_models_checked':self.pi});result=self.stats
        assert(self.copy_i,self.cmp_i,self.limb_i)==tuple(len(self.p[k])for k in ['copy_points','compare_points','limb_points'])
        for key in ['source_reads','source_writes']:assert not any(int(r['address'],16)<OWNER+0x900 and OWNER+0x880<int(r['address'],16)+r['size_B']for r in self.p[key])
        assert self.ram(OWNER+0x880,128)==b'\xa5'*128 and not self.p['native_effects'];return result


def source_checks_new(e,old):
    att=json.loads(read(ROOT/'fpsd1201_comparison_ida_readback.json'));assert len(att['spans'])==2 and not att['IDB_mutated']and not att['native_target_executed']
    assert e['code_spans'][:12]==old['code_spans']
    raw=(ROOT.parent/'CoreFP').read_bytes();assert SHA(raw)==att['input_sha256']=='68d2f0a29c63b442f60622f539357db91d4e2a4b1d775e136c40fd8effc5aa2f'
    for j in range(struct.unpack_from('>I',raw,4)[0]):
        cpu,sub,off,n,_=struct.unpack_from('>5I',raw,8+20*j)
        if(cpu,sub)==(0x100000c,0x80000002):thin=raw[off:off+n];break
    assert SHA(thin)=='8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c'
    at=32;segments=[]
    for j in range(struct.unpack_from('<I',thin,16)[0]):
        cmd,n=struct.unpack_from('<II',thin,at)
        if cmd==0x19:
            _,vm,vs,fo,fs=struct.unpack_from('<16s4Q',thin,at+8);segments.append((vm,fo,fs))
        at+=n
    starts=json.loads(read(ROOT/'corefp_library_inventory.json'))['compiler_function_starts']
    expected=[('0x649430','0x6496b8',648,'4fc734824e3d897552bd476e2d40183021699b197e3d0c31d188baea0e313542'),('0x33abec','0x33b11c',1328,'2687f36941289d3d85276683c914e7eaa28ac1b05cd791a83e602704be2fc8d8')]
    for j,(a,b,n,h)in enumerate(expected):
        r=att['spans'][j];data=bytes.fromhex(r['bytes_hex']);assert(r['start'],r['end_exclusive'],r['size_B'])==(a,b,n)
        assert len(data)==n and SHA(data)==r['sha256']==r['original_sha256']==h and r['current_equals_IDA_original_bytes']
        assert starts[starts.index(a)+1]==b;a=int(a,16);vm,fo,fs=next(s for s in segments if s[0]<=a<a+n<=s[0]+s[2]);assert thin[fo+a-vm:fo+a-vm+n]==data
        assert {k:v for k,v in e['code_spans'][12+j].items()if k!='role'}==r
    assert e['reference_file_check']=={**old['reference_file_check'],'code_bytes_checked':21528}
    for p in e['proofs']:
        q=z3.Solver();q.set(timeout=60000);q.add(z3.parse_smt2_string(p['query']));assert str(q.check())==p['result']=='unsat'
    ins={i.address:i for r in e['code_spans']for i in CS.disasm(bytes.fromhex(r['bytes_hex']),int(r['start'],16))}
    bv=lambda x:z3.BitVecVal(x,32);a,b=z3.BitVecs('audit_encoded_second audit_encoded_first',32)
    r0=lift_details(ins,{'w3':bv(0x8011),'w5':a,'w21':b},0x33af24,0x33afd0)
    regs={k:bv(v)for k,v in {'w16':2,'w19':0x4ee6,'w3':0x8011,'w7':0x4f23a7d1,'w23':0xb0dc582f,'w24':0x117763c2,'w25':0xee88325b,
      'w26':0xa8375087,'w27':0x57c8e19f,'w28':0xc1c66c16,'w30':0x3e3993ea,'w8':0x73367c85,'w20':0x8cc9837b}.items()};regs.update({'w5':a,'w21':b})
    r1=lift_details(ins,regs,0x33b02c,0x33b08c);claims=[];biases=[]
    for r in [r0,r1]:
        pair=[]
        for k,v in [('w16',a),('w17',b)]:
            bias=z3.simplify(z3.substitute(r[k],(a,bv(K)),(b,bv(K)))).as_long();pair.append(hex(bias))
            claims.extend(z3.Extract(j*8+7,j*8,r[k])==z3.Extract(j*8+7,j*8,(v^bv(K))+bv(bias))for j in range(4))
        assert pair[0]==pair[1];biases.append(pair[0])
    x,y,c=z3.BitVecs('audit_second audit_first audit_bias',32);rx=x+c;ry=y+c
    claims.append(z3.If(z3.ULT(rx,c)==z3.ULT(ry,c),z3.UGT(rx,ry),z3.ULT(rx,c))==z3.UGT(x,y))
    seed=z3.BitVec('audit_cursor_seed',64);top=z3.LShR(seed*z3.BitVecVal(0x2e9d,64)+1,60);pad=((top<<4)+31)&0x1f0
    claims.extend([pad==16*(top+1),z3.And(z3.UGE(pad,16),z3.ULE(pad,256)),(pad&15)==0])
    for claim in claims:
        q=z3.Solver();q.set(timeout=60000);q.add(z3.Not(claim));assert q.check()==z3.unsat
    exact={0x6494cc:('cmp','x8, x9'),0x649568:('ldr','w15, [x8, #4]'),0x649588:('str','w15, [x9, #4]'),
      0x649624:('ldr','w15, [x15, w13, uxtw #2]'),0x64962c:('str','w15, [x16, w13, uxtw #2]'),
      0x649684:('subs','w13, w13, #2'),0x33af18:('ldr','w5, [x16, x17]'),0x33af20:('ldr','w21, [x16, x17]'),
      0x33b018:('sub','x1, x1, #1'),0x33b0f8:('str','w16, [x0, #8]'),
      0x14fac68:('stp','x22, x21, [sp, #-0x30]!'),0x14fac78:('sub','sp, sp, #0x10'),
      0x14fad94:('madd','x2, x21, x2, x5'),0x14fad9c:('lsr','x2, x2, #0x3c'),0x14fada0:('lsl','w2, w2, #4'),
      0x14fada4:('add','w2, w2, #0x1f'),0x14fada8:('and','x2, x2, #0x1f0'),0x14fadb4:('mov','sp, x20')}
    for p,v in exact.items():assert(ins[p].mnemonic,ins[p].op_str)==v
    return {'fresh_IDA_spans':2,'fresh_IDA_bytes':1976,'compiler_bounded_bodies':2,'total_selected_code_bytes':21528,
      'retained_queries_unsat':len(e['proofs']),'independent_source_queries_unsat':len(claims),'source_limb_biases':biases,
      'exact_source_instructions_checked':len(exact),'source_lifters_use_distinct_operand_decoders':True,'complete_algorithm_universally_proved':False}


def main():
    e=json.loads(read(ROOT/'fpsd1201_comparison_checks.json'));shift=json.loads(read(ROOT/'fpsd1201_shift_checks.json'))
    operand=json.loads(read(ROOT/'fpsd1201_operand_checks.json'));imp=json.loads(read(ROOT/'fpsd1201_import_checks.json'));record=json.loads(read(ROOT/'fpsd1201_record_checks.json'))
    assert e['generator_sha256']==SHA((ROOT/'recover_fpsd1201_comparison.py').read_bytes())and e['IDA_readback_sha256']==SHA(read(ROOT/'fpsd1201_comparison_ida_readback.json').encode())
    for n,h in e['dependencies'].items():assert SHA(read(ROOT/n).encode())==h
    banks,D,prior=source_and_proofs(record);D2,prior_import=reference_and_source(imp,record);assert D==D2
    prior_operand=source_checks(operand,imp,banks,D);prior_shift=shift_source(shift,operand);source=source_checks_new(e,shift)
    ps=e['profiles'];assert len(ps)==243
    for p,old in zip(ps[:8],shift['profiles'][:8]):assert p['configuration']=={**old['configuration'],'label':'copied_'+old['configuration']['label']}
    expected=[(n,s,pattern,same)for n in [0,1,2,3,4,5,7,8,31,32,33,63,64]for s in [-1,1]for pattern in ['sequence','zero']for same in [False,True]]
    assert [(p['configuration']['count'],p['configuration']['sign'],p['configuration']['pattern'],p['configuration']['same_object'])for p in ps[8:112]]==expected
    values=[-((1<<96)-1),-(1<<64),-0xffffffff,-1,0,1,2,0xffffffff,1<<32,1<<64,(1<<96)-1];pairs=[(a,b)for a in values for b in values];x=(1<<2047)+0x12345678
    pairs.extend([(x,x),(x,x+1),(x+1,x),(-x,-x),(-x,-x-1),(-x-1,-x)])
    assert [(int(p['configuration']['first_shex'],16),int(p['configuration']['second_shex'],16))for p in ps[112:239]]==pairs
    assert [(p['configuration']['first_count'],p['configuration']['second_count'])for p in ps[239:]]==[(1,0),(0,1),(-1,0),(0,-1)]
    for p in ps[8:]:assert all(p['configuration'][k]==shift['profiles'][0]['configuration'][k]for k in ['control','seed_u64','global1_u64','global2_u64','global3_u64','global4_u64','second_seed_u64','operand_u32','backed'])
    total=Counter()
    for p in ps:total.update(Replay(p,record,operand,shift,e['code_spans'],banks,D).run())
    assert not any(e[k]for k in ['whole_parent_replayed','native_target_executed','IDB_edit_operations_requested','full_goal_complete'])
    result={'source':source,'pinned_shift_source':prior_shift,'fresh_replay':dict(total),'profiles':243,'nested_profiles':8,'isolated_copy_profiles':104,'isolated_compare_profiles':131,
      'next_callee_targets':sorted({p['frontier']['target']for p in ps[:8]}),'candidate_inline128_reads_or_writes':0,
      'whole_parent_replayed':False,'complete_operand_child_return_established':False,'native_target_executed':False,'full_goal_complete':False,'all_checks_pass':True}
    receipt={'result':result,'dependencies':e['dependencies'],'checks_sha256':SHA(read(ROOT/'fpsd1201_comparison_checks.json').encode()),
      'IDA_readback_sha256':e['IDA_readback_sha256'],'auditor_sha256':SHA(Path(__file__).read_bytes()),'fresh_replay_completed':True,'process_exit_code':0,'native_target_executed':False}
    (ROOT/'fpsd1201_comparison_audit.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(result),flush=True)


if __name__=='__main__':main()
