#!/usr/bin/env python3
"""Independent continuation replay, remainder and Montgomery-square oracles.

Never imports the new producer. Replays the pinned subtraction prefix, then
continues the same private CPU with independently checked call/record views.
O(I+C*(B+F+V+P*J+R)) time, O(I+B+F+C*(V+J+P+R)) space;
SMT cost separate. No native effects or whole-request completion.
"""
import json,struct
from pathlib import Path
from hashlib import sha256
from collections import Counter
import z3
from unicorn import arm64_const as A
from audit_fpsd1201_subtraction import Replay as Previous,numeric,source_checks_new as subtraction_source
from audit_fpsd1201_comparison import source_checks_new as comparison_source
from audit_fpsd1201_shift import source_checks_new as shift_source,source_checks,CS,ROOT,OWNER,FP,SP,HALT,RAM,Core,source_and_proofs,reference_and_source,unpack
from verify_daemon_reader_record_payloads_publication import read

SHA=lambda b:sha256(b).hexdigest();MASK=(1<<32)-1;MASK64=(1<<64)-1;CHILD=0x14f8d28;WRAP=0x9dd7e4;SQUARE=0x9dc6d4
PRINCIPALS=[CHILD,WRAP,SQUARE,0x5a600c,0x649430,0x33abec,0x5e8158]
EXITS={0x14f99e0:CHILD,0x9dd9f8:WRAP,0x9dd0fc:SQUARE,0x5a650c:0x5a600c,0x6496b4:0x649430,0x33b118:0x33abec,0x5e8638:0x5e8158}
STAGES=[0x14f9258,0x14f9d78,0x14fae3c,0x14fae5c]


class Replay(Previous):
    def __init__(self,p,record,operand,shift,comparison,code,banks,D):
        prefix={**p,**{k:v for k,v in p['prefix_boundary'].items()if k!='lengths'}}
        for k,n in p['prefix_boundary']['lengths'].items():prefix[k]=p[k][:n]
        super().__init__(prefix,record,operand,shift,comparison,code[:17],banks,D)
        self.full=p;self.following=False;self.resume_skip=False;self.family_index=0;self.call_stack=[];self.return_count=0
        self.u.mem_map(0x9dc000,8192)
        for row in code[17:]:
            a=int(row['start'],16);b=bytes.fromhex(row['bytes_hex']);self.u.mem_write(a,b);self.ranges.append((a,a+len(b)))
    def observe(self,pc):
        if pc in PRINCIPALS:
            entry,r,cursor=pc,self.reg(0),self.reg(1)
            if pc==CHILD:self.child_signature=(entry,r,cursor)
        elif pc in EXITS:entry,r,cursor,before=self.call_stack.pop();assert entry==EXITS[pc]
        elif pc in STAGES:entry,r,cursor=self.child_signature
        else:return
        point=self.full['family_points'][self.family_index];self.family_index+=1;self.frame(point['CPU'])
        raw=self.ram(r,40);ptr=lambda j:int.from_bytes(raw[j:j+8],'little');extra={}
        if entry in [CHILD,WRAP,SQUARE]:
            q=ptr(8)if entry==CHILD else ptr(16);n=ptr(16)if entry==CHILD else ptr(8);pair=self.ram(q,24)
            views={'modulus':self.desc(n),'pair_first':self.desc(int.from_bytes(pair[:8],'little')),'pair_second':self.desc(int.from_bytes(pair[8:16],'little'))}
            extra={'pair_pointer':hex(q),'pair24_hex':pair.hex(),'cursor_pointer':hex(cursor),'cursor_u64':hex(int.from_bytes(self.ram(cursor,8),'little'))}
            if entry!=CHILD:views.update({'input':self.desc(ptr(24)),'output':self.desc(ptr(32))})
        elif entry in [0x649430,0x33abec]:views={'first':self.desc(ptr(0)),'second':self.desc(ptr(16))}
        elif entry==0x5e8158:views={'first':self.desc(ptr(8)),'second':self.desc(ptr(16))}
        else:views={'operand':self.desc(ptr(8))}
        actual={'pc':hex(pc),'entry':hex(entry),'record_pointer':hex(r),'record40_hex':raw.hex(),'views':views,**extra}
        assert actual=={k:v for k,v in point.items()if k!='CPU'}
        if pc in PRINCIPALS:
            self.call_stack.append((entry,r,cursor,point));self.entry_contract(pc,r,raw,point)
        if pc in EXITS:self.return_contract(entry,before,point)
        if pc==0x14f9d78:
            self.return_count+=1
            if not self.c['operand_u32']:
                assert numeric(views['modulus'])==numeric(views['pair_first'])-1==0
                self.stats['zero_control_stable_numeric_checkpoints']+=1
        if pc==0x14fae3c:assert int(point['cursor_u64'],16)==self.c['second_seed_u64'];self.stats['outer_wrapper_child_returns_checked']+=1
        if pc==0x14fae5c:
            assert int.from_bytes(self.ram(self.operand_output,8),'little')==0;self.stats['outer_wrapper_zero_adjustments_checked']+=1
    def entry_contract(self,pc,r,raw,point):
        word=lambda off:int.from_bytes(raw[off:off+4],'little');low=r&MASK
        if pc==CHILD:
            assert word(0)^(((low^0x5f8c1ee6)*0x2a03d31f)&MASK)==0xb9d0
            assert numeric(point['views']['modulus'])==self.c['operand_u32']
        if pc in [WRAP,SQUARE]:
            assert word(0)^(((low^0x8b4ea7c9)*0x0bcb7857)&MASK)==0xcb58
            n=numeric(point['views']['modulus']);x=numeric(point['views']['input']);assert n>0 and 0<=x<n
            assert point['views']['input']['address']==point['views']['output']['address']
            if pc==SQUARE:
                wrapper=self.call_stack[-2][3];assert wrapper['entry']==hex(WRAP)
                seed=int(wrapper['cursor_u64'],16);pad=16*((((seed*0x2ecd+1)&MASK64)>>60)+1)
                assert int(point['CPU']['sp'],16)==int(wrapper['CPU']['sp'],16)-0x40-pad
                assert int(point['cursor_u64'],16)==(seed-80)&MASK64;self.stats['square_seed_frame_geometries_checked']+=1
        m=(((low^0x309487ae)*0x87cfdb29)&MASK)
        if pc==0x649430:assert(word(8)+m)&MASK==0x2f63
        if pc==0x33abec:assert(word(24)+(((low^0x302a1e77)*0xcae5b081)&MASK))&MASK==0x69d6
        if pc==0x5e8158:assert word(0)^(((low^0x7043a3fa)*0x4ecee2ad)&MASK)==0xf136
        if pc==0x5a600c:assert(word(4)-m)&MASK==0xc215
    def return_contract(self,entry,before,after):
        a=before['views'];b=after['views'];raw=bytes.fromhex(before['record40_hex'])
        if entry==0x649430:
            assert a['first']==b['first'];s=bytes.fromhex(a['first']['descriptor16_hex']);d=bytes.fromhex(a['second']['descriptor16_hex']);out=bytes.fromhex(b['second']['descriptor16_hex'])
            n=(int.from_bytes(s[4:8],'little')-0x4b0cf050)&MASK;n=n-(1<<32)if n>>31 else n;n=abs(n)
            if a['first']['address']==a['second']['address']:assert a==b
            else:
                assert out==d[:4]+s[4:8]+d[8:]
                assert bytes.fromhex(b['second']['payload512_hex'])==bytes.fromhex(a['first']['payload512_hex'])[:4*n]+bytes.fromhex(a['second']['payload512_hex'])[4*n:]
            self.stats['complete_continued_copy_oracles_checked']+=1
        elif entry==0x33abec:
            x,y=numeric(a['first']),numeric(a['second']);assert a==b
            assert int.from_bytes(bytes.fromhex(after['record40_hex'])[8:12],'little')==0x312bc2c1+(y>x)-(y<x)
            self.stats['complete_continued_comparison_oracles_checked']+=1
        elif entry==0x5a600c:
            r=int(before['record_pointer'],16);m=(((r^0x309487ae)*0x87cfdb29)&MASK);shift=(int.from_bytes(raw[:4],'little')-m+0xa2eae272)&MASK;shift=shift-(1<<32)if shift>>31 else shift
            v=numeric(a['operand']);expected=(abs(v)<<shift)if shift>=0 else(abs(v)>>(-shift));expected=-expected if v<0 else expected
            assert numeric(b['operand'])==expected;self.stats['complete_continued_shift_oracles_checked']+=1
        elif entry==0x5e8158:
            assert a['first']==b['first'];assert numeric(b['second'])==numeric(a['second'])-numeric(a['first']);self.stats['complete_continued_subtraction_oracles_checked']+=1
        elif entry in [WRAP,SQUARE]:
            n=numeric(a['modulus']);x=numeric(a['input']);c=int.from_bytes(bytes.fromhex(before['pair24_hex'])[16:20],'little');t=x*x;R=1<<32
            t=(t+(((t&MASK)*c)&MASK)*n)>>32;t=t-n if t>=n else t
            assert numeric(b['output'])==t and a['modulus']==b['modulus'];self.stats['one_word_REDC_square_oracles_checked']+=int(entry==SQUARE)
            if n&1:assert t==x*x*pow(R,-1,n)%n;self.stats['odd_Montgomery_square_oracles_checked']+=int(entry==SQUARE)
            else:self.stats['even_noninverse_square_controls_checked']+=int(entry==SQUARE)
            if entry==SQUARE:assert int(after['cursor_u64'],16)==(int(before['cursor_u64'],16)+80)&MASK64;self.stats['square_child_cursor_restores_checked']+=1
            else:assert after['cursor_u64']=='0x0';self.stats['square_wrapper_zero_adjustments_checked']+=1
        else:
            n=self.c['operand_u32'];assert n and numeric(b['pair_first'])==(1<<32)%n
            assert int(after['cursor_u64'],16)==self.c['second_seed_u64']
            if n&1:assert numeric(b['pair_second'])==(1<<64)%n;self.stats['odd_complete_R_and_R2_oracles_checked']+=1
            else:self.stats['even_complete_first_remainder_controls_checked']+=1
            self.stats['complete_arithmetic_child_returns_checked']+=1
    def hook(self,u,pc,n,data):
        self.flush()
        if self.resume_skip:assert pc==0x14f9d78;self.resume_skip=False
        else:self.observe(pc)
        if not self.following:return super().hook(u,pc,n,data)
        if not self.c['operand_u32']and pc==0x14f9d78 and self.return_count==64:
            self.stop='zero_control_iteration_limit';self.frame(self.p['terminal']);assert self.p['frontier']=={'pc':hex(pc),'instruction_executed':False,'completed_subtraction_returns':64};u.emu_stop();return
        if pc==0x9819c4:
            self.stop='unretained_callee';self.frame(self.p['terminal']);e=self.p['frontier'];slot=0x1d056a0;row=self.D[slot]
            assert(self.reg(8),self.reg(17))==(0x1142c08,0x4032)
            assert(row['target'],row['diversity'],row['key'],row['address_diversity'])==('0x1142c08','0x4032','IA',0)
            assert e=={'pc':hex(pc),'target':'0x1142c08','modifier':'0x4032','original_slot':hex(slot),'instruction':'blraa x8, x17','instruction_executed':False,'argument_record80_hex':self.ram(self.reg(0),80).hex()};self.used.add(slot);u.emu_stop();return
        Core.hook(self,u,pc,n,data)
    def run(self):
        super().run();self.following=True;self.resume_skip=True;self.stop=None;self.p=self.full
        self.u.emu_start(0x14f9d78,0,count=500000);self.flush();assert self.stop==self.p['stop_reason']
        assert(self.v,self.r,self.w,self.pi,self.ci)==tuple(len(self.p[k])for k in ['source_visits','source_reads','source_writes','PAC_models','CPU_points'])
        assert self.family_index==len(self.p['family_points'])and self.return_count==self.p['subtraction_returns']
        assert[hex(x[0])for x in self.call_stack]==self.p['pending_family_entries']==([hex(CHILD)]if not self.c['operand_u32']else[])
        assert self.p['used_original_pointer_rows']==[self.D[a]for a in sorted(self.used)]
        for row,(a,n)in zip(self.p['final_RAM'],RAM):assert row['address']==hex(a)and unpack(row['payload'])==self.ram(a,n);self.stats['continued_final_RAM_bytes_checked']+=n
        for key in ['source_reads','source_writes']:assert not any(int(r['address'],16)<OWNER+0x900 and OWNER+0x880<int(r['address'],16)+r['size_B']for r in self.p[key])
        assert self.ram(OWNER+0x880,128)==b'\xa5'*128 and not self.p['native_effects']
        for key,value in [('original_visits_checked',self.v),('original_reads_checked',self.r),('original_writes_checked',self.w),('PAC_models_checked',self.pi)]:self.stats[key]=value
        return self.stats


def source_checks_new(e,old):
    att=json.loads(read(ROOT/'fpsd1201_reduction_ida_readback.json'));assert len(att['spans'])==2 and not att['IDB_mutated']and not att['native_target_executed']
    assert e['code_spans'][:17]==old['code_spans']
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
    expected=[('0x9dd7e4','0x9dd9fc',536,'e0d3fe32053709a848e6f14922e29c0ccc02aaf34959c111806be478eeb11bff'),
      ('0x9dc6d4','0x9dd7e4',4368,'096c10d3221c94a15dac5a16b4e1051d2e41b8316480ff8a0912a871caa44666')]
    for j,(a,b,n,h)in enumerate(expected):
        r=att['spans'][j];data=bytes.fromhex(r['bytes_hex']);assert(r['start'],r['end_exclusive'],r['size_B'])==(a,b,n)
        assert len(data)==n and SHA(data)==r['sha256']==r['original_sha256']==h and r['current_equals_IDA_original_bytes']
        assert starts[starts.index(a)+1]==b;a=int(a,16);vm,fo,fs=next(s for s in segments if s[0]<=a<a+n<=s[0]+s[2]);assert thin[fo+a-vm:fo+a-vm+n]==data
        assert {k:v for k,v in e['code_spans'][17+j].items()if k!='role'}==r
    assert e['reference_file_check']=={**old['reference_file_check'],'code_bytes_checked':31040}
    for p in e['proofs']:
        q=z3.Solver();q.set(timeout=60000);q.add(z3.parse_smt2_string(p['query']));assert str(q.check())==p['result']=='unsat'
    ins={i.address:i for r in e['code_spans']for i in CS.disasm(bytes.fromhex(r['bytes_hex']),int(r['start'],16))}
    exact={0x9dd7e8:('stp','x22, x21, [sp, #-0x30]!'),0x9dd7f8:('sub','sp, sp, #0x10'),
      0x9dd8d4:('ldr','x21, [x19]'),0x9dd918:('madd','x17, x21, x17, x3'),0x9dd920:('lsr','x17, x17, #0x3c'),
      0x9dd92c:('and','x17, x17, #0x1f0'),0x9dd93c:('sub','x17, x21, #0x50'),0x9dd940:('str','x17, [x20]'),
      0x9dd9d4:('blraa','x8, x17'),0x9dd9dc:('sub','w8, w8, w21'),0x9dd9e0:('ubfiz','x8, x8, #4, #0x10'),0x9dd9e4:('str','x8, [x19]'),
      0x9dc804:('add','x9, x9, #0x50'),0x9dc808:('str','x9, [x1]'),0x9dc814:('eor','w9, w0, w9'),0x9dc820:('mul','w9, w9, w11'),
      0x9dc82c:('ldr','x9, [x0, #8]'),0x9dc85c:('ldp','x11, x7, [x0, #0x18]'),0x9dc9e0:('ldr','x11, [x0, #0x10]'),
      0x9dca68:('ldr','w13, [x13, #0x10]'),0x9dd0fc:('retab',''),0x14f99e0:('retab',''),0x14fae48:('str','x8, [x19]')}
    for a,v in exact.items():assert(ins[a].mnemonic,ins[a].op_str)==v,(hex(a),ins[a].mnemonic,ins[a].op_str)
    seed=z3.BitVec('audit_square_seed',64);top=z3.LShR(seed*z3.BitVecVal(11981,64)+1,60);pad=((top<<4)+31)&0x1f0
    claims=[seed-0x50+0x50==seed,z3.Extract(15,0,seed-0x50+0x50-seed)==0,
      pad==16*(top+1),z3.And(z3.UGE(pad,16),z3.ULE(pad,256)),(pad&15)==0]
    for claim in claims:
        q=z3.Solver();q.set(timeout=60000);q.add(z3.Not(claim));assert q.check()==z3.unsat
    return {'fresh_IDA_spans':2,'fresh_IDA_bytes':4904,'compiler_bounded_bodies':2,'total_selected_code_bytes':31040,
      'retained_queries_unsat':len(e['proofs']),'independent_cursor_queries_unsat':len(claims),'exact_source_instructions_checked':len(exact),'complete_algorithm_universally_proved':False}


def main():
    e=json.loads(read(ROOT/'fpsd1201_reduction_checks.json'));old=json.loads(read(ROOT/'fpsd1201_subtraction_checks.json'));comparison=json.loads(read(ROOT/'fpsd1201_comparison_checks.json'))
    shift=json.loads(read(ROOT/'fpsd1201_shift_checks.json'));operand=json.loads(read(ROOT/'fpsd1201_operand_checks.json'))
    imp=json.loads(read(ROOT/'fpsd1201_import_checks.json'));record=json.loads(read(ROOT/'fpsd1201_record_checks.json'))
    assert e['generator_sha256']==SHA((ROOT/'recover_fpsd1201_reduction.py').read_bytes())and e['IDA_readback_sha256']==SHA(read(ROOT/'fpsd1201_reduction_ida_readback.json').encode())
    for n,h in e['dependencies'].items():assert SHA(read(ROOT/n).encode())==h
    banks,D,prior=source_and_proofs(record);D2,prior_import=reference_and_source(imp,record);assert D==D2
    source_checks(operand,imp,banks,D);shift_source(shift,operand);comparison_source(comparison,shift);subtraction_source(old,comparison);source=source_checks_new(e,old)
    ps=e['profiles'];assert len(ps)==13
    for p,c in zip(ps[:8],old['profiles'][:8]):assert p['configuration']=={**c['configuration'],'label':'reduced_'+c['configuration']['label']}
    for j,(p,v)in enumerate(zip(ps[8:],[17,65537,0xffffffff,0x80000001,0x7fffffff])):
        assert p['configuration']=={**old['profiles'][0]['configuration'],'label':'additional_'+hex(v),'operand_u32':v,'second_seed_u64':[0,1,MASK64,0x0123456789abcdef][j%4]}
    total=Counter();summaries=[]
    for p in ps:
        total.update(Replay(p,record,operand,shift,comparison,e['code_spans'],banks,D).run())
        ends=[q for q in p['family_points']if q['pc']=='0x14f99e0'];last=ends[-1]if ends else None
        summary={'operand_u32':p['configuration']['operand_u32'],'subtraction_returns':p['subtraction_returns'],'square_returns':sum(q['pc']=='0x9dd0fc'for q in p['family_points']),
          'first_result':hex(numeric(last['views']['pair_first']))if last else None,'second_result':hex(numeric(last['views']['pair_second']))if last else None,'stop_reason':p['stop_reason']}
        summaries.append(summary);print(json.dumps(summary),flush=True)
    assert not any(e[k]for k in ['whole_parent_replayed','native_target_executed','IDB_edit_operations_requested','full_goal_complete'])
    result={'source':source,'fresh_replay':dict(total),'profiles':13,'complete_child_profiles':12,'bounded_zero_profiles':1,'profile_summaries':summaries,
      'next_callee_targets':['0x1142c08'],'candidate_inline128_reads_or_writes':0,'whole_parent_replayed':False,'native_target_executed':False,'full_goal_complete':False,'all_checks_pass':True}
    receipt={'result':result,'dependencies':e['dependencies'],'checks_sha256':SHA(read(ROOT/'fpsd1201_reduction_checks.json').encode()),'IDA_readback_sha256':e['IDA_readback_sha256'],
      'auditor_sha256':SHA(Path(__file__).read_bytes()),'fresh_replay_completed':True,'process_exit_code':0,'native_target_executed':False}
    (ROOT/'fpsd1201_reduction_audit.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(result),flush=True)


if __name__=='__main__':main()
