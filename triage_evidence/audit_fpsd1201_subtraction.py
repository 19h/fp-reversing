#!/usr/bin/env python3
"""Independent subtraction replay, canonical integer and alias oracles.

Never imports the new producer. Reconstructs diagnostic inputs independently,
replays original instructions and checks complete CPU/read/write/RAM journals.
O(I+C*(B+F+V+P*J+R)) time and O(I+B+F+C*(V+J+P+R)) space;
SMT cost separate. No native effects or whole-parent completion.
"""
import json,struct
from pathlib import Path
from hashlib import sha256
from collections import Counter
import z3
from unicorn import arm64_const as A
from audit_fpsd1201_comparison import Replay as Previous,source_checks_new as comparison_source,count
from audit_fpsd1201_shift import source_checks_new as shift_source,source_checks,CS,ROOT,OWNER,CONTEXT,FP,SP,HALT,RAM,Core,source_and_proofs,reference_and_source,unpack
from verify_daemon_reader_record_payloads_publication import read

ENTRY=0x5e8158;SUB=0x1ec40;ADD=0x443bf4;IR=FP+0x100
FIRST=OWNER+0x800;SECOND=OWNER+0xa00;THIRD=OWNER+0xc00
L1=OWNER+0x1000;L2=OWNER+0x1800;L3=OWNER+0x2800
BASE=0x4b0cf050;K=0x1ac70ef2;MASK=0xffffffff;SHA=lambda b:sha256(b).hexdigest()
ENTRIES=[ENTRY,SUB,ADD];EXITS=[0x5e8638,0x1f380,0x4441bc]
DEP_ENTRIES=[0x649430,0x624ff0,0x5dcd08];DEP_EXITS=[0x6496b0,0x625260,0x5dcec4]
STEPS=[0x1ef68,0x1ef8c,0x1f014,0x1f034,0x1f0f4,0x1f110,0x1f1e0,0x1f1f4,
 0x443ee0,0x443f00,0x443fb4,0x443fd0,0x4440c0,0x4440d8]


def numeric(d):
    if d is None:return None
    raw=bytes.fromhex(d['descriptor16_hex']);n=count(raw);payload=bytes.fromhex(d['payload512_hex'])if d['payload512_hex']else b''
    assert abs(n)<=128
    value=sum((int.from_bytes(payload[j*4:j*4+4],'little')^K)<<(32*j)for j in range(abs(n)))
    return -value if n<0 else value


class Replay(Previous):
    def __init__(self,p,record,operand,shift,comparison,code,banks,D):
        c=p['configuration'];baseline=p if c['mode']=='nested'else comparison['profiles'][0]
        super().__init__(baseline,record,operand,shift,code[:14],banks,D)
        self.p=p;self.c=c;self.active=False;self.ai=self.dep_i=self.ki=0;self.dependencies=[];self.pending_arithmetic=None
        for a,n in [(0x5e8000,4096),(0x1e000,8192),(0x443000,8192)]:self.u.mem_map(a,n)
        for row in code[14:]:
            a=int(row['start'],16);b=bytes.fromhex(row['bytes_hex']);self.u.mem_write(a,b);self.ranges.append((a,a+len(b)))
        if c['mode']!='nested':
            self.phase=c['mode'];self.stats=Counter()
            for d,payload,key in [(FIRST,L1,'first_shex'),(SECOND,L2,'second_shex'),(THIRD,L3,None)]:
                v=int(c[key],16)if key else 0;n=(abs(v).bit_length()+31)//32
                self.u.mem_write(d,struct.pack('<IIQ',91 if key is None else 64,(BASE+(-n if v<0 else n))&MASK,payload))
                for j in range(n):self.u.mem_write(payload+4*j,(((abs(v)>>(32*j))&MASK)^K).to_bytes(4,'little'))
            b=0 if c['null_second']else FIRST if c['alias']=='self'else SECOND
            out={'distinct':THIRD,'first':FIRST,'second':SECOND,'self':FIRST}[c['alias']]
            m=(((IR&MASK)^0x309487ae)*0x87cfdb29)&MASK
            if c['mode']=='root':
                rm=(((IR&MASK)^0x7043a3fa)*0x4ecee2ad)&MASK
                raw=struct.pack('<IIQQ',rm^0xf136,0xa5a5a5a5,FIRST,b);entry=ENTRY
            elif c['mode']=='leaf_sub':raw=struct.pack('<QQIIQ',FIRST,SECOND,(m+0x5c71)&MASK,0xa5a5a5a5,out);entry=SUB
            else:raw=struct.pack('<QQQII',FIRST,out,SECOND,m^0x99bf,0xa5a5a5a5);entry=ADD
            self.u.mem_write(IR,raw);self.setreg(0,IR);self.setreg(30,HALT);self.u.reg_write(A.UC_ARM64_REG_PC,entry);self.dep_irect_entry=entry
            self.frame(p['initial'])
            for row,(a,n)in zip(p['initial_RAM'],RAM):assert row['address']==hex(a)and unpack(row['payload'])==self.ram(a,n)
    def desc(self,a):
        if a==0:return None
        raw=self.ram(a,16);p=int.from_bytes(raw[8:],'little')
        return {'address':hex(a),'descriptor16_hex':raw.hex(),'payload512_hex':self.ram(p,512).hex()if p else None}
    def arithmetic_point(self,pc):
        point=self.p['arithmetic_points'][self.ai];self.ai+=1;self.frame(point['CPU'])
        extra={}
        if pc in ENTRIES:
            r=self.reg(0);raw=self.ram(r,32);u=lambda off:int.from_bytes(raw[off:off+8],'little');m=(((r&MASK)^0x309487ae)*0x87cfdb29)&MASK
            if pc==ENTRY:
                rm=(((r&MASK)^0x7043a3fa)*0x4ecee2ad)&MASK;assert int.from_bytes(raw[:4],'little')^rm==0xf136;a,b,out=u(8),u(16),u(16)
            elif pc==SUB:
                assert(int.from_bytes(raw[16:20],'little')-m)&MASK==0x5c71;a,b,out=u(0),u(8),u(24)
            else:
                assert int.from_bytes(raw[24:28],'little')^m==0x99bf;a,b,out=u(0),u(16),u(8)
            extra={'argument_pointer':hex(r),'argument32_hex':raw.hex()}
            if not self.active:
                self.root_record=r;self.ar_a=a;self.ar_b=b;self.ar_out=out;self.active=True;self.before=(self.desc(a),self.desc(b),self.desc(out))
                x,y=map(numeric,self.before[:2]);self.entry_pc=pc
                self.expected=(y-x if y is not None else None)if pc==ENTRY else (1 if x>0 else -1)*(abs(x)-abs(y))if pc==SUB else (1 if y>0 else -1)*(abs(x)+abs(y))
                if self.c['mode']=='nested':assert x==self.c['operand_u32']and y==(1<<32 if x else 1)
            elif pc==SUB:
                assert(a,b,out)==(self.ar_b,self.ar_a,self.ar_out);self.stats['root_difference_routes_checked']+=1
            elif pc==ADD:
                assert(a,b,out)==(self.ar_a,self.ar_b,self.ar_out);self.stats['root_addition_routes_checked']+=1
        actual={'pc':hex(pc),'root_record_pointer':hex(self.root_record),'root_record32_hex':self.ram(self.root_record,32).hex(),
          'first':self.desc(self.ar_a),'second':self.desc(self.ar_b),'output':self.desc(self.ar_out),**extra}
        assert actual=={k:v for k,v in point.items()if k!='CPU'}
        if pc in [HALT,0x14f9d78]:
            a,b,out=self.before
            if self.ar_out:
                result=actual['output'];assert numeric(result)==self.expected,(self.c['label'],numeric(result),self.expected)
                before=bytes.fromhex(out['descriptor16_hex']);after=bytes.fromhex(result['descriptor16_hex'])
                n=(abs(self.expected).bit_length()+31)//32;s=-n if self.expected<0 else n
                assert count(after)==s and after[:4]==before[:4]and after[8:]==before[8:]
                self.stats['canonical_integer_outcomes_checked']+=1
                for old,new in [(a,actual['first']),(b,actual['second'])]:
                    if old is not None and old['address']!=out['address']:assert old==new;self.stats['preserved_nonoutput_inputs_checked']+=1
            else:
                assert numeric(a)==0 and actual['first']==a and actual['second']is None
                assert not any(self.p['source_visits'][r['visit']]['pc']=='0x5e8334'for r in self.p['source_reads'])
                self.stats['zero_first_null_second_bypasses_checked']+=1
            if self.c['mode']=='nested':self.stats['complete_nested_subtraction_returns_checked']+=1
            elif self.c['mode']=='root':self.stats['complete_isolated_root_returns_checked']+=1
            elif self.c['mode']=='leaf_sub':self.stats['complete_direct_difference_returns_checked']+=1
            else:self.stats['complete_direct_addition_returns_checked']+=1
            if self.c.get('alias')=='self':assert self.expected==0;self.stats['self_subtraction_zero_outcomes_checked']+=1
    def dependency_point(self,pc):
        point=self.p['dependency_points'][self.dep_i];self.dep_i+=1;self.frame(point['CPU'])
        if pc in DEP_ENTRIES:r=self.reg(0)
        else:
            entry,r,before,old_src,old_dst=self.dependencies.pop();assert DEP_EXITS.index(pc)==DEP_ENTRIES.index(entry)
        raw=self.ram(r,32);src=self.desc(int.from_bytes(raw[:8],'little'));dst=self.desc(int.from_bytes(raw[16:24],'little'))if pc in [0x649430,0x6496b0]else None
        actual={'pc':hex(pc),'record_pointer':hex(r),'record32_hex':raw.hex(),'first':src}
        if pc in [0x649430,0x6496b0]:actual['second']=dst
        assert actual=={k:v for k,v in point.items()if k!='CPU'}
        m=(((r&MASK)^0x309487ae)*0x87cfdb29)&MASK
        if pc in DEP_ENTRIES:
            if pc==0x649430:assert(int.from_bytes(raw[8:12],'little')+m)&MASK==0x2f63
            elif pc==0x624ff0:
                sm=(((r&MASK)^0x341dc0b1)*0xdb676c6f)&MASK;assert(int.from_bytes(raw[8:12],'little')+sm)&MASK==0x9746
            else:assert(int.from_bytes(raw[12:16],'little')+m)&MASK==0x3f22
            self.dependencies.append((pc,r,raw,src,dst))
        else:
            assert src==old_src
            if pc==0x625260:assert int.from_bytes(raw[12:16],'little')==0x77458d7f+(numeric(src)>0)-(numeric(src)<0);self.stats['arithmetic_sign_query_returns_checked']+=1
            elif pc==0x5dcec4:assert int.from_bytes(raw[8:12],'little')==0x660d9bbd+int(count(bytes.fromhex(src['descriptor16_hex']))==0);self.stats['arithmetic_zero_query_returns_checked']+=1
            else:
                s=bytes.fromhex(src['descriptor16_hex']);d=bytes.fromhex(old_dst['descriptor16_hex']);after=bytes.fromhex(dst['descriptor16_hex']);n=abs(count(s))
                assert raw==before and after==d[:4]+s[4:8]+d[8:]
                assert bytes.fromhex(dst['payload512_hex'])==bytes.fromhex(src['payload512_hex'])[:4*n]+bytes.fromhex(old_dst['payload512_hex'])[4*n:]
                self.stats['zero_second_raw_copy_returns_checked']+=1
    def carry_point(self,pc):
        point=self.p['carry_points'][self.ki];self.ki+=1;assert point['pc']==hex(pc);self.frame(point['CPU'])
        if pc==0x1ef68:
            assert self.reg(0)==MASK and self.reg(1)==1 and self.reg(20)==K and self.reg(21)==0x358e1de4
            carry,u,v=self.reg(11),self.reg(17),self.reg(2);assert carry<=1 and u<=MASK and v<=MASK
            self.pending_arithmetic=(pc,u+carry-v+MASK)
        elif pc==0x443ee0:
            assert self.reg(0)==1 and self.reg(21)==K and self.reg(20)==0x358e1de4
            carry,u,v=self.reg(10),self.reg(17),self.reg(1);assert carry<=1 and u<=MASK and v<=MASK
            self.pending_arithmetic=(pc,u+v+carry)
        elif pc in [0x1ef8c,0x443f00]:
            start,total=self.pending_arithmetic;assert start==(0x1ef68 if pc==0x1ef8c else 0x443ee0)
            assert self.reg(11 if pc==0x1ef8c else 10)==total and self.reg(17)==((total&MASK)^K)
            d=self.reg(9 if pc==0x1ef8c else 8);index=self.reg(14 if pc==0x1ef8c else 15);payload=int.from_bytes(self.ram(d+8,8),'little')
            assert int.from_bytes(self.ram(payload+4*index,4),'little')==((total&MASK)^K)
            self.stats['common_limb_carry_and_store_steps_checked']+=1;self.pending_arithmetic=None
    def hook(self,u,pc,n,data):
        self.flush()
        if pc in ENTRIES+EXITS:self.arithmetic_point(pc)
        if self.active:
            if pc in DEP_ENTRIES+DEP_EXITS:self.dependency_point(pc)
            if pc in STEPS:self.carry_point(pc)
            if pc in [HALT,0x14f9d78]:
                self.arithmetic_point(pc);self.frame(self.p['terminal']);self.stop='returned'if pc==HALT else'after_subtraction_return'
                assert self.p['frontier']==(None if pc==HALT else{'pc':hex(pc),'instruction_executed':False,'completed_callee':hex(ENTRY)})
                u.emu_stop();return
            return Core.hook(self,u,pc,n,data)
        if pc==0x14f9d74:return Core.hook(self,u,pc,n,data)
        super().hook(u,pc,n,data)
    def run(self):
        if self.c['mode']=='nested':result=super().run()
        else:
            self.u.emu_start(self.dep_irect_entry,0,count=50000);self.flush();assert self.stop==self.p['stop_reason']=='returned'
            assert(self.v,self.r,self.w,self.pi,self.ci)==tuple(len(self.p[k])for k in ['source_visits','source_reads','source_writes','PAC_models','CPU_points'])
            assert self.u.reg_read(A.UC_ARM64_REG_SP)==SP and self.p['used_original_pointer_rows']==[self.D[a]for a in sorted(self.used)]
            for row,(a,n)in zip(self.p['final_RAM'],RAM):assert row['address']==hex(a)and unpack(row['payload'])==self.ram(a,n);self.stats['complete_final_RAM_bytes_checked']+=n
            self.stats.update({'original_visits_checked':self.v,'original_reads_checked':self.r,'original_writes_checked':self.w,'PAC_models_checked':self.pi});result=self.stats
        assert(self.ai,self.dep_i,self.ki)==tuple(len(self.p[k])for k in ['arithmetic_points','dependency_points','carry_points'])
        assert not self.dependencies and self.pending_arithmetic is None and not self.p['native_effects']
        for key in ['source_reads','source_writes']:assert not any(int(r['address'],16)<OWNER+0x900 and OWNER+0x880<int(r['address'],16)+r['size_B']for r in self.p[key])
        assert self.ram(OWNER+0x880,128)==b'\xa5'*128;return result


def source_checks_new(e,old):
    att=json.loads(read(ROOT/'fpsd1201_subtraction_ida_readback.json'));assert len(att['spans'])==3 and not att['IDB_mutated']and not att['native_target_executed']
    assert e['code_spans'][:14]==old['code_spans']
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
    expected=[('0x5e8158','0x5e8640',1256,'be97c57e32760b5f02cae70b276df86be518c247480c857d6005c7c95e2e293e'),
      ('0x1ec40','0x1f388',1864,'6c21bbed8d1d561774fed007ad99ffaca5f69cd05c7404b192266b01fff41fbc'),
      ('0x443bf4','0x4441c4',1488,'d3e326d70ee9a966cdc4b2ab125386832e0aa83ff98a293bebd1268ae79a0b1f')]
    for j,(a,b,n,h)in enumerate(expected):
        r=att['spans'][j];data=bytes.fromhex(r['bytes_hex']);assert(r['start'],r['end_exclusive'],r['size_B'])==(a,b,n)
        assert len(data)==n and SHA(data)==r['sha256']==r['original_sha256']==h and r['current_equals_IDA_original_bytes']
        assert starts[starts.index(a)+1]==b;a=int(a,16);vm,fo,fs=next(s for s in segments if s[0]<=a<a+n<=s[0]+s[2]);assert thin[fo+a-vm:fo+a-vm+n]==data
        assert {k:v for k,v in e['code_spans'][14+j].items()if k!='role'}==r
    assert e['reference_file_check']=={**old['reference_file_check'],'code_bytes_checked':26136}
    for p in e['proofs']:
        q=z3.Solver();q.set(timeout=60000);q.add(z3.parse_smt2_string(p['query']));assert str(q.check())==p['result']=='unsat'
    ins={i.address:i for r in e['code_spans']for i in CS.disasm(bytes.fromhex(r['bytes_hex']),int(r['start'],16))}
    exact={0x5e8260:('orr','w13, w13, w0, lsl #1'),0x5e826c:('sub','w13, w13, w0'),0x5e8270:('add','w13, w13, w1'),
      0x5e8294:('ldr','x13, [x0, #8]'),0x5e8298:('ldr','w1, [x13, #4]'),0x5e8334:('ldr','x20, [x0, #0x10]'),
      0x5e8428:('blraa','x8, x17'),0x5e8558:('blraa','x8, x17'),0x5e8600:('blraa','x8, x17'),
      0x1eea0:('blraa','x8, x17'),0x443e3c:('blraa','x8, x17'),0x1ef38:('mov','w0, #-1'),
      0x1ef68:('add','x11, x11, x17'),0x1ef6c:('sub','x11, x11, x2'),0x1ef70:('add','x11, x11, x0'),
      0x1ef88:('str','w17, [x2, x14, lsl #2]'),0x1ef8c:('lsr','x11, x11, #0x20'),
      0x443ee0:('add','x10, x17, x10'),0x443ee4:('add','x10, x10, x1'),0x443efc:('str','w17, [x1, x15, lsl #2]'),
      0x443f00:('lsr','x10, x10, #0x20'),0x1f348:('str','w8, [x9, #4]'),0x444184:('str','w9, [x8, #4]')}
    for a,v in exact.items():assert(ins[a].mnemonic,ins[a].op_str)==v,(hex(a),ins[a].mnemonic,ins[a].op_str)
    x,y=z3.BitVecs('audit_x audit_y',32);carry=z3.BitVec('audit_carry',64);bv=lambda v:z3.BitVecVal(v,32)
    xx,yy=z3.ZeroExt(32,x),z3.ZeroExt(32,y);valid=z3.Or(carry==0,carry==1)
    total=xx+yy+carry;diff=xx-yy+carry+MASK
    claims=[((bv(0xb53439e4)|(x<<1))-x+bv(0xa565e30e))^bv(0x2ad9bf08)==x^bv(0x7043a3fa),
      bv(2*BASE)-(x+bv(BASE))==bv(BASE)-x,(x^bv(0xe538f10d))==~(x^bv(K)),
      z3.Implies(valid,z3.LShR(total,32)==z3.If(z3.UGE(total,1<<32),z3.BitVecVal(1,64),z3.BitVecVal(0,64))),
      z3.Implies(valid,z3.Extract(31,0,diff)==x-y+z3.Extract(31,0,carry)-1),
      z3.Implies(valid,z3.LShR(diff,32)==z3.If(z3.ULT(xx+carry,yy+1),z3.BitVecVal(0,64),z3.BitVecVal(1,64)))]
    encoded=x-(bv(K<<1)&(x<<1))+bv(K)
    claims.extend(z3.Extract(j*8+7,j*8,encoded)==z3.Extract(j*8+7,j*8,x^bv(K))for j in range(4))
    for claim in claims:
        q=z3.Solver();q.set(timeout=60000);q.add(z3.Not(claim));assert q.check()==z3.unsat
    return {'fresh_IDA_spans':3,'fresh_IDA_bytes':4608,'compiler_bounded_bodies':3,'total_selected_code_bytes':26136,
      'retained_queries_unsat':len(e['proofs']),'independent_word_queries_unsat':len(claims),'exact_source_instructions_checked':len(exact),'complete_algorithm_universally_proved':False}


def main():
    e=json.loads(read(ROOT/'fpsd1201_subtraction_checks.json'));old=json.loads(read(ROOT/'fpsd1201_comparison_checks.json'))
    shift=json.loads(read(ROOT/'fpsd1201_shift_checks.json'));operand=json.loads(read(ROOT/'fpsd1201_operand_checks.json'))
    imp=json.loads(read(ROOT/'fpsd1201_import_checks.json'));record=json.loads(read(ROOT/'fpsd1201_record_checks.json'))
    assert e['generator_sha256']==SHA((ROOT/'recover_fpsd1201_subtraction.py').read_bytes())and e['IDA_readback_sha256']==SHA(read(ROOT/'fpsd1201_subtraction_ida_readback.json').encode())
    for n,h in e['dependencies'].items():assert SHA(read(ROOT/n).encode())==h
    banks,D,prior=source_and_proofs(record);D2,prior_import=reference_and_source(imp,record);assert D==D2
    source_checks(operand,imp,banks,D);shift_source(shift,operand);comparison_source(old,shift);source=source_checks_new(e,old)
    ps=e['profiles'];assert len(ps)==197
    for p,c in zip(ps[:8],old['profiles'][:8]):assert p['configuration']=={**c['configuration'],'label':'subtracted_'+c['configuration']['label']}
    values=[-((1<<96)-1),-(1<<64),-0xffffffff,-1,0,1,2,0xffffffff,1<<32,1<<64,(1<<96)-1];w=(1<<2048)-1
    pairs=[(a,b)for a in values for b in values]+[(-1,w),(1,w),(-w,1),(w,-1),(w,w),(w,w-1),(w-1,w),(-w,-w)]
    assert [(int(p['configuration']['first_shex'],16),int(p['configuration']['second_shex'],16))for p in ps[8:137]]==pairs
    assert [(int(p['configuration']['first_shex'],16),p['configuration']['alias'])for p in ps[137:148]]==[(v,'self')for v in values]
    assert ps[148]['configuration']['null_second']and int(ps[148]['configuration']['first_shex'],16)==0
    lp=[(1,2),(2,1),(-1,2),(1,-2),(-2,-1),(MASK,1),(1,MASK),(w,1)]
    assert [(p['configuration']['mode'],int(p['configuration']['first_shex'],16),int(p['configuration']['second_shex'],16),p['configuration']['alias'])for p in ps[149:]]==[(mode,a,b,alias)for mode in ['leaf_sub','leaf_add']for a,b in lp for alias in ['distinct','first','second']]
    for p in ps[8:]:assert all(p['configuration'][k]==old['profiles'][0]['configuration'][k]for k in ['control','seed_u64','global1_u64','global2_u64','global3_u64','global4_u64','second_seed_u64','operand_u32','backed'])
    total=Counter()
    for j,p in enumerate(ps):
        total.update(Replay(p,record,operand,shift,old,e['code_spans'],banks,D).run())
        if(j+1)%20==0:print(json.dumps({'audited_profiles':j+1}),flush=True)
    assert not any(e[k]for k in ['whole_parent_replayed','native_target_executed','IDB_edit_operations_requested','full_goal_complete'])
    result={'source':source,'fresh_replay':dict(total),'profiles':197,'nested_profiles':8,'isolated_root_profiles':141,'isolated_difference_profiles':24,'isolated_addition_profiles':24,
      'continued_caller_stop_pc':'0x14f9d78','candidate_inline128_reads_or_writes':0,'whole_parent_replayed':False,
      'complete_operand_child_return_established':False,'native_target_executed':False,'full_goal_complete':False,'all_checks_pass':True}
    receipt={'result':result,'dependencies':e['dependencies'],'checks_sha256':SHA(read(ROOT/'fpsd1201_subtraction_checks.json').encode()),
      'IDA_readback_sha256':e['IDA_readback_sha256'],'auditor_sha256':SHA(Path(__file__).read_bytes()),'fresh_replay_completed':True,'process_exit_code':0,'native_target_executed':False}
    (ROOT/'fpsd1201_subtraction_audit.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(result),flush=True)


if __name__=='__main__':main()
