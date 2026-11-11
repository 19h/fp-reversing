#!/usr/bin/env python3
"""Independent shift replay, signed-integer oracle and source correspondence.

Never imports the new producer. Frozen predecessor CPU/journal mechanics
are extended with independently reconstructed fixtures and descriptor queries.
O(I+C*(B+F+V+P*J+R)) time, O(I+B+F+C*(V+J+P+R)) space;
SMT cost separate. No native execution or whole-parent completion.
"""
import json,struct
from pathlib import Path
from hashlib import sha256
from collections import Counter
import z3
from unicorn import arm64_const as A
from audit_fpsd1201_operand import Replay as Previous,source_checks,lift_details,CS,ROOT,OWNER,CONTEXT,FP,SP,HALT,RAM
from audit_fpsd1201_import import reference_and_source
from audit_fpsd1201_record import Replay as Core,source_and_proofs,unpack
from verify_daemon_reader_record_payloads_publication import read

MASK=0xffffffff;BASE=0x4b0cf050;K=0x1ac70ef2
ENTRY=0x5a600c;IR=FP+0x100;DESC=OWNER+0x800;LIMBS=OWNER+0x1000
SHA=lambda b:sha256(b).hexdigest()
ENTRIES=[ENTRY,0x5a6774,0x4be1cc,0x624ff0,0x5dcd08]
POINTS=ENTRIES+[0x5a69d4,0x4be418,0x625204,0x14f940c,HALT]


class Replay(Previous):
    def __init__(self,p,record,old,code,banks,D):
        baseline=p if p['configuration']['mode']=='nested'else next(v for v in old['profiles']if v['configuration']['backed'])
        super().__init__(baseline,record,code[:7],banks,D);self.p=p;self.c=p['configuration'];self.si=0
        for a,n in [(0x5a6000,4096),(0x4be000,4096),(0x624000,8192),(0x5dc000,4096)]:self.u.mem_map(a,n)
        for row in code[7:]:
            a=int(row['start'],16);b=bytes.fromhex(row['bytes_hex']);self.u.mem_write(a,b);self.ranges.append((a,a+len(b)))
        if self.c['mode']=='isolated':
            c=self.c;self.phase='isolated';self.stats=Counter();v=int(c['value_hex'],16);count=(v.bit_length()+31)//32
            self.u.mem_write(DESC,struct.pack('<IIQ',64,(BASE+count*c['sign'])&MASK,LIMBS))
            for j in range(count):self.u.mem_write(LIMBS+4*j,(((v>>(32*j))&MASK)^K).to_bytes(4,'little'))
            m=(((IR&MASK)^0x309487ae)*0x87cfdb29)&MASK
            self.u.mem_write(IR,struct.pack('<IIQ',(m-0xa2eae272+c['shift_s32'])&MASK,(0xc215+m)&MASK,DESC))
            self.setreg(0,IR);self.setreg(30,HALT);self.u.reg_write(A.UC_ARM64_REG_PC,ENTRY)
            self.frame(p['initial'])
            for row,(a,n)in zip(p['initial_RAM'],RAM):assert row['address']==hex(a)and unpack(row['payload'])==self.ram(a,n)
    def shift_point(self,pc):
        point=self.p['shift_points'][self.si];self.si+=1;self.frame(point['CPU'])
        if pc==ENTRY:
            self.sr=self.reg(0);v=self.ram(self.sr,16);m=(((self.sr&MASK)^0x309487ae)*0x87cfdb29)&MASK
            self.shift=(int.from_bytes(v[:4],'little')-m+0xa2eae272)&MASK
            if self.shift>>31:self.shift-=1<<32
            assert(int.from_bytes(v[4:8],'little')-m)&MASK==0xc215
            self.sd=int.from_bytes(v[8:],'little');self.before=self.ram(self.sd,16);self.lp=int.from_bytes(self.before[8:],'little')
            count=(int.from_bytes(self.before[4:8],'little')-BASE)&MASK
            if count>>31:count-=1<<32
            self.sign=-1 if count<0 else 1;self.count=abs(count)
            self.value=sum((int.from_bytes(self.ram(self.lp+4*j,4),'little')^K)<<(32*j)for j in range(self.count))
            self.expected=self.value<<self.shift if self.shift>0 else self.value>>(-self.shift)
            if self.c['mode']=='isolated':assert(self.value,self.sign if self.value else 1,self.shift)==(int(self.c['value_hex'],16),self.c['sign']if self.value else 1,self.c['shift_s32'])
            else:assert self.value==1 and self.shift==(32 if self.c['operand_u32']else 0)
        d=self.ram(self.sd,16);actual={'pc':hex(pc),'root_record_pointer':hex(self.sr),'root_record16_hex':self.ram(self.sr,16).hex(),
          'descriptor_pointer':hex(self.sd),'descriptor16_hex':d.hex(),'limb256_hex':self.ram(self.lp,256).hex()}
        if pc in ENTRIES:actual.update({'argument_pointer':hex(self.reg(0)),'argument24_hex':self.ram(self.reg(0),24).hex()})
        assert actual=={k:v for k,v in point.items()if k!='CPU'}
        if pc in [0x5a6774,0x4be1cc]:
            raw=self.ram(self.reg(0),24);p=self.reg(0)&MASK;m=((p^0x542fbf9b)*0x4386951d)&MASK
            assert int.from_bytes(raw[8:16],'little')==self.sd
            state=int.from_bytes(raw[:4],'little');amount=(int.from_bytes(raw[16:20],'little')+m)&MASK
            if pc==0x5a6774:
                assert self.shift>0 and(state+m)&MASK==0xe598 and amount==(self.shift^0x86b3c60e);self.stats['left_route_records_checked']+=1
            else:
                assert self.shift<=0 and state^m==0x8ddd and amount==((-self.shift)^0x5092d4e4);self.stats['right_route_records_checked']+=1
        if pc in [0x624ff0,0x5dcd08]:
            q=self.reg(0);assert int.from_bytes(self.ram(q,8),'little')==self.sd
            if pc==0x624ff0:
                m=(((q&MASK)^0x341dc0b1)*0xdb676c6f)&MASK
                assert(int.from_bytes(self.ram(q+8,4),'little')+m)&MASK==0x9746
                self.sign_record=q
            else:
                m=(((q&MASK)^0x309487ae)*0x87cfdb29)&MASK
                assert(int.from_bytes(self.ram(q+12,4),'little')+m)&MASK==0x3f22
                self.zero_record=q
        if pc in [0x4be418,0x625204]:
            assert int.from_bytes(self.ram(self.zero_record+8,4),'little')==0x660d9bbd+int(self.value==0)
            assert self.ram(self.sd,16)==self.before;self.stats['zero_query_returns_checked']+=1
        if pc==0x5a69d4:
            assert int.from_bytes(self.ram(self.sign_record+12,4),'little')==0x77458d7f+(self.sign if self.value else 0)
            assert self.ram(self.sd,16)==self.before;self.stats['sign_query_returns_checked']+=1
        if pc in [HALT,0x14f940c]:
            count=(self.expected.bit_length()+31)//32
            assert d[:4]==self.before[:4]and d[8:]==self.before[8:]
            assert int.from_bytes(d[4:8],'little')==(BASE+self.sign*count)&MASK
            out=sum((int.from_bytes(self.ram(self.lp+4*j,4),'little')^K)<<(32*j)for j in range(count))
            assert out==self.expected,(self.c['label'],hex(out),hex(self.expected))
            self.stats['complete_shift_integer_oracles_checked']+=1
        self.stats['shift_CPU_points_checked']+=1
    def hook(self,u,pc,n,data):
        self.flush()
        if pc in POINTS:self.shift_point(pc)
        if pc==0x14f94c4:
            e=self.p['frontier'];self.frame(self.p['terminal']);self.stop='unretained_callee'
            assert e=={'pc':'0x14f94c4','target':'0x649430','modifier':'0x8dc5','original_slot':'0x1d039b8',
              'instruction':'blraa x8, x17','instruction_executed':False,'argument_record80_hex':self.ram(self.reg(0),80).hex()}
            assert self.reg(8)==0x649430 and self.reg(17)==0x8dc5;row=self.D[0x1d039b8]
            assert row['target']=='0x649430'and row['diversity']=='0x8dc5'and row['key']=='IA'and not row['address_diversity']
            self.used.add(0x1d039b8);u.emu_stop();return
        if pc==0x14f9408 or self.c['mode']=='isolated':return Core.hook(self,u,pc,n,data)
        super().hook(u,pc,n,data)
    def run(self):
        if self.c['mode']=='nested':result=super().run()
        else:
            self.u.emu_start(ENTRY,0,count=50000);self.flush();assert self.stop==self.p['stop_reason']=='returned'
            assert(self.v,self.r,self.w,self.pi,self.ci)==tuple(len(self.p[k])for k in ['source_visits','source_reads','source_writes','PAC_models','CPU_points'])
            assert self.u.reg_read(A.UC_ARM64_REG_SP)==SP
            assert self.p['used_original_pointer_rows']==[self.D[a]for a in sorted(self.used)]
            for row,(a,n)in zip(self.p['final_RAM'],RAM):assert row['address']==hex(a)and unpack(row['payload'])==self.ram(a,n);self.stats['complete_final_RAM_bytes_checked']+=n
            self.stats.update({'original_visits_checked':self.v,'original_reads_checked':self.r,'original_writes_checked':self.w,'PAC_models_checked':self.pi})
            result=self.stats
        assert self.si==len(self.p['shift_points'])and not self.p['native_effects']
        for key in ['source_reads','source_writes']:assert not any(int(r['address'],16)<OWNER+0x900 and OWNER+0x880<int(r['address'],16)+r['size_B']for r in self.p[key])
        assert self.ram(OWNER+0x880,128)==b'\xa5'*128
        return result


def source_checks_new(e,old):
    att=json.loads(read(ROOT/'fpsd1201_shift_ida_readback.json'));assert not att['IDB_mutated']and not att['native_target_executed']
    assert e['code_spans'][:7]==old['code_spans']and len(att['spans'])==5
    raw=(ROOT.parent/'CoreFP').read_bytes();assert SHA(raw)==att['input_sha256']=='68d2f0a29c63b442f60622f539357db91d4e2a4b1d775e136c40fd8effc5aa2f'
    thin=None
    for j in range(struct.unpack_from('>I',raw,4)[0]):
        cpu,sub,off,n,_=struct.unpack_from('>5I',raw,8+20*j)
        if(cpu,sub)==(0x100000c,0x80000002):thin=raw[off:off+n];break
    assert SHA(thin)=='8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c'
    segments=[];at=32
    for j in range(struct.unpack_from('<I',thin,16)[0]):
        cmd,n=struct.unpack_from('<II',thin,at)
        if cmd==0x19:
            _,vm,vs,fo,fs=struct.unpack_from('<16s4Q',thin,at+8);segments.append((vm,fo,fs))
        at+=n
    starts=json.loads(read(ROOT/'corefp_library_inventory.json'))['compiler_function_starts']
    for j,r in enumerate(att['spans']):
        a=int(r['start'],16);b=bytes.fromhex(r['bytes_hex']);n=len(b);vm,fo,fs=next(s for s in segments if s[0]<=a<a+n<=s[0]+s[2])
        assert thin[fo+a-vm:fo+a-vm+n]==b and SHA(b)==r['sha256']==r['original_sha256']and r['current_equals_IDA_original_bytes']
        assert r['size_B']==n and starts[starts.index(r['start'])+1]==r['end_exclusive']
        assert {k:v for k,v in e['code_spans'][7+j].items()if k!='role'}==r
    assert e['reference_file_check']=={**old['reference_file_check'],'code_bytes_checked':19552}
    for p in e['proofs']:
        s=z3.Solver();s.set(timeout=60000);s.add(z3.parse_smt2_string(p['query']));assert str(s.check())==p['result']=='unsat'
    # Independently decode the source constructors using structured operands.
    ins={i.address:i for r in e['code_spans']for i in CS.disasm(bytes.fromhex(r['bytes_hex']),int(r['start'],16))}
    bv=lambda v:z3.BitVecVal(v,32);s=z3.BitVec('independent_shift',32)
    r=lift_details(ins,{'w15':s+bv(0x5d151d8e),'w16':bv(0xa2eae271),'w0':bv(0xc215)},0x5a61e4,0x5a6340)
    claims=[z3.Extract(8*j+7,8*j,r['w15'])==z3.Extract(8*j+7,8*j,s^bv(0x86b3c60e))for j in range(4)]
    r=lift_details(ins,{'w20':bv(0x3e70),'w15':s+bv(0x5d151d8e)},0x5a63f8,0x5a642c)
    claims.append(bv(0xada7f272)-s-bv(0x5d151d8e)-r['w16']==((-s)^bv(0x5092d4e4)))
    for claim in claims:
        q=z3.Solver();q.set(timeout=60000);q.add(z3.Not(claim));assert q.check()==z3.unsat
    exact={0x5a615c:('ldp','w14, w6, [x0]'),0x5a63e8:('blraa','x8, x17'),0x5a64d8:('blraa','x8, x17'),
      0x5a69d0:('blraa','x8, x17'),0x4be414:('blraa','x8, x17'),0x625200:('blraa','x8, x17'),
      0x5dce8c:('ldr','w6, [x6]'),0x5dcec0:('str','w5, [x0, #8]'),0x5a6e24:('str','w8, [x19, #4]')}
    for a,pair in exact.items():assert(ins[a].mnemonic,ins[a].op_str)==pair
    return {'fresh_IDA_spans':5,'fresh_IDA_bytes':5700,'compiler_bounded_bodies':5,'total_selected_code_bytes':19552,
      'retained_queries_unsat':len(e['proofs']),'independent_source_queries_unsat':len(claims),'exact_source_instructions_checked':len(exact),
      'complete_algorithm_universally_proved':False,'source_lifters_use_distinct_operand_decoders':True}


def main():
    e=json.loads(read(ROOT/'fpsd1201_shift_checks.json'));old=json.loads(read(ROOT/'fpsd1201_operand_checks.json'))
    imp=json.loads(read(ROOT/'fpsd1201_import_checks.json'));record=json.loads(read(ROOT/'fpsd1201_record_checks.json'))
    for n,h in e['dependencies'].items():assert SHA(read(ROOT/n).encode())==h
    assert e['generator_sha256']==SHA((ROOT/'recover_fpsd1201_shift.py').read_bytes())and e['IDA_readback_sha256']==SHA(read(ROOT/'fpsd1201_shift_ida_readback.json').encode())
    banks,D,prior=source_and_proofs(record);D2,prior_import=reference_and_source(imp,record);assert D==D2
    prior_operand=source_checks(old,imp,banks,D);source=source_checks_new(e,old)
    ps=e['profiles'];assert len(ps)==144
    assert [p['configuration']['operand_u32']for p in ps[:8]]==[1,3,5,7,0,2,0x80000000,0xfffffffe]
    backed=[p['configuration']for p in old['profiles']if p['configuration']['backed']]
    for p,c in zip(ps[:8],backed[:4]+backed[-4:]):assert p['configuration']=={**c,'label':'continued_'+c['label']}
    expected=[(v,sign,s)for v in [0,1,0xffffffff,0x123456789abcdef012345678]for sign in [-1,1]for s in [-129,-65,-64,-63,-33,-32,-31,-1,0,1,31,32,33,63,64,65,129]]
    assert [(int(p['configuration']['value_hex'],16),p['configuration']['sign'],p['configuration']['shift_s32'])for p in ps[8:]]==expected
    for p in ps[8:]:
        c=p['configuration'];assert all(c[k]==backed[0][k]for k in ['control','seed_u64','global1_u64','global2_u64','global3_u64','global4_u64','second_seed_u64','operand_u32','backed'])and c['mode']=='isolated'
    totals=Counter()
    for p in ps:totals.update(Replay(p,record,old,e['code_spans'],banks,D).run())
    assert not any(e[k]for k in ['whole_parent_replayed','native_target_executed','IDB_edit_operations_requested','full_goal_complete'])
    result={'source':source,'pinned_predecessor_source':prior_operand,'fresh_replay':dict(totals),'profiles':144,'nested_profiles':8,'isolated_profiles':136,
      'next_callee_targets':sorted({p['frontier']['target']for p in ps[:8]}),'candidate_inline128_reads_or_writes':0,
      'whole_parent_replayed':False,'complete_operand_child_return_established':False,'native_target_executed':False,'full_goal_complete':False,'all_checks_pass':True}
    receipt={'result':result,'dependencies':e['dependencies'],'checks_sha256':SHA(read(ROOT/'fpsd1201_shift_checks.json').encode()),
      'IDA_readback_sha256':e['IDA_readback_sha256'],'auditor_sha256':SHA(Path(__file__).read_bytes()),'fresh_replay_completed':True,'process_exit_code':0,'native_target_executed':False}
    (ROOT/'fpsd1201_shift_audit.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(result),flush=True)


if __name__=='__main__':main()
