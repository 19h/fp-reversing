#!/usr/bin/env python3
"""Two preparation-dependent split scans and their common state recurrence.

Source proofs use typed byte/pointer interfaces, explicit shift premises and
retained PAC records. No native target/API/IPC or IDB operation.
O(C*(B+V*J+P*F+R)+N*16) time/space; 30 s/SMT query.
"""
import json,z3
from pathlib import Path
from collections import Counter
from capstone.arm64_const import *
import recover_corefp_late_preparation as L
from verify_daemon_reader_record_payloads_publication import read
A=L.A;W=L.W;C=L.C;ROOT=L.ROOT;SHA=L.SHA;S=C.Pointers();M32=(1<<32)-1
PASSES=[{'kind':0,'start':0x1b536c,'end':0x1b54d0,'init':0x1b53c4,'head':0x1b53c8,'tail':0x1b5444,'head_dispatch':0x1b5440,'tail_dispatch':0x1b54cc,'states':[26,30,22,14],'counter_head':8,'counter_tail':11,'split':11},
 {'kind':1,'start':0x1b6530,'end':0x1b66ac,'init':0x1b65a4,'head':0x1b65a8,'tail':0x1b6620,'head_dispatch':0x1b661c,'tail_dispatch':0x1b66a8,'states':[15,10,11,4],'counter_head':12,'counter_tail':13,'split':13}]
PINS={**L.PINS,'corefp_late_preparation_checks.json':'9d2e47cd821ee5a6f2ffaa8f93e9387890c5ef46ffdaab02bc9955b33b7a0fa9',
 'corefp_late_preparation_audit.json':'c4c82c683affdd92fc38fcf579cb074509acc43e78611bb8bfd431134c31e5ef'}


def fold(x):
    x=(x+(x>>16))&M32;return (x+(x>>8))&M32


def selector(p,kind):
    if kind==0:a=(p[4]+4)&15;b=(p[a]+14)&15;c=(p[b]+2)&15;v=p[c]&15;indices=[4,a,b,c]
    else:a=(p[2]+14)&15;b=(p[a]+14)&15;c=p[b]&15;v=(p[c]+3)&15;indices=[2,a,b,c]
    return max(1,v),indices


def oracle(p,kind,cpu,split=None):
    desc=PASSES[kind];r=[int(v,16)&M32 for v in cpu['X31']];aa=r[0];bb=r[9];k=r[2 if kind==0 else 6]
    state=[r[j]for j in desc['states']];initial=state[:];rows=[];n,indices=selector(p,kind)
    if split is not None:n=split
    assert 1<=n<=15
    for i,byte in enumerate(p):
        av,bv,cv,h=state;u=(byte*k)&M32;t=fold(((u^h)+i)&M32);v=fold(((((t+aa)&M32)^u)+i)&M32)
        state=[av^t^v,bv^((t+bb)&M32)^((v+bb)&M32),cv^((t+aa)&M32)^((v+aa)&M32),(v+aa)&M32]
        rows.append({'index':i,'byte_u8':byte,'first_fold_u32':hex(t),'second_fold_u32':hex(v),'state_u32':list(map(hex,state))})
    prefix=list(map(lambda x:int(x,16),rows[n-1]['state_u32']))
    residue=prefix[2]^prefix[3]if kind==0 else(int(rows[n-1]['first_fold_u32'],16)+bb)&M32
    return {'split':n,'selector_indices':indices,'initial_state_u32':list(map(hex,initial)),'final_state_u32':list(map(hex,state)),
      'head_residue_register':1 if kind==0 else 3,'head_residue_u32':hex(residue),
      'xor_deltas_u32':[hex(state[j]^initial[j])for j in range(3)],'iterations':rows}


def source_rows(lo,hi):
    return [{'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'instruction':i.mnemonic+' '+i.op_str}for i in C.CS.disasm(S.read(lo,hi-lo),lo)]


def prove(rows,label,claim,premises=()):
    q=z3.Solver();q.set(timeout=30000);q.add(*premises);q.add(z3.Not(claim));assert q.check()==z3.unsat,label
    rows.append({'label':label,'query':q.to_smt2(),'result':'unsat'})


class Lift:
    def __init__(self,registers,read_hook):
        self.r=registers.copy();self.read_hook=read_hook;self.flags={'Z':z3.Bool('unused_Z'),'N':z3.Bool('unused_N'),'C':z3.Bool('unused_C'),'V':z3.Bool('unused_V')}
    def rr(self,n):
        n={'fp':'x29','lr':'x30'}.get(n,n)
        if n in ['wzr','xzr']:return z3.BitVecVal(0,32 if n[0]=='w'else 64)
        v=self.r[int(n[1:])];return z3.Extract(31,0,v)if n[0]=='w'else v
    def put(self,n,v):
        n={'fp':'x29','lr':'x30'}.get(n,n);self.r[int(n[1:])]=z3.simplify(z3.ZeroExt(32,v)if n[0]=='w'else v)
    def value(self,i,o,bits):
        v=self.rr(i.reg_name(o.reg))if o.type==1 else z3.BitVecVal(o.imm,bits)
        if o.ext:
            assert o.ext==ARM64_EXT_SXTW;v=z3.SignExt(32,z3.Extract(31,0,v))
        if v.size()!=bits:assert v.size()==32 and bits==64;v=z3.ZeroExt(32,v)
        if o.shift.type:
            if o.shift.type==ARM64_SFT_LSL:v=v<<o.shift.value
            else:assert o.shift.type==ARM64_SFT_LSR;v=z3.LShR(v,o.shift.value)
        return v
    def execute(self,instructions):
        for i in instructions:
            m=i.mnemonic;o=i.operands;name=i.reg_name(o[0].reg);bits=32 if name.startswith('w')else 64
            if m in ['ldr','ldur','ldrb','ldurb']:
                mem=o[1];at=self.rr(i.reg_name(mem.mem.base))+mem.mem.disp
                if mem.mem.index:
                    v=self.rr(i.reg_name(mem.mem.index));v=z3.SignExt(32,v)if mem.ext==ARM64_EXT_SXTW else z3.ZeroExt(32,v)if v.size()==32 else v;at+=v<<mem.shift.value
                n=1 if m in ['ldrb','ldurb']else bits//8;v=self.read_hook(z3.simplify(at),n,i);self.put(name,z3.ZeroExt(bits-v.size(),v));continue
            if m=='mov':self.put(name,self.value(i,o[1],bits));continue
            if m=='movk':
                shift=o[1].shift.value;self.put(name,(self.rr(name)&~z3.BitVecVal(65535<<shift,bits))|(z3.BitVecVal(o[1].imm,bits)<<shift));continue
            if m in ['tst','cmp']:
                a,b=self.value(i,o[0],bits),self.value(i,o[1],bits);v=a&b if m=='tst'else a-b
                self.flags['Z']=v==0;continue
            if m=='csinc':assert i.op_str.endswith(', ne');a,b=self.value(i,o[1],bits),self.value(i,o[2],bits);self.put(name,z3.If(self.flags['Z'],b+1,a));continue
            if m=='cset':
                condition=self.flags['Z']if i.op_str.endswith(', eq')else z3.Not(self.flags['Z']);assert i.op_str.endswith((', eq',', ne'));self.put(name,z3.If(condition,z3.BitVecVal(1,bits),z3.BitVecVal(0,bits)));continue
            a,b=self.value(i,o[1],bits),self.value(i,o[2],bits)
            if m=='add':v=a+b
            elif m=='sub':v=a-b
            elif m=='mul':v=a*b
            elif m=='and':v=a&b
            elif m=='eor':v=a^b
            elif m=='lsl':v=a<<(b&(bits-1))
            else:assert m=='lsr';v=z3.LShR(a,b&(bits-1))
            self.put(name,v)
        return self


def source_proofs():
    proofs=[];slices=[];byte_vars=[z3.BitVec('scan_p'+str(j),8)for j in range(16)];base=z3.BitVec('scan_prepared_base64',64)
    def select(index):
        v=byte_vars[15]
        for j in reversed(range(15)):v=z3.If(index==j,byte_vars[j],v)
        return v
    for kind,(lo,hi)in enumerate([(0x1b536c,0x1b53b0),(0x1b6530,0x1b6570)]):
        regs={j:z3.BitVec('selector'+str(kind)+'_X'+str(j),64)for j in range(31)};regs[29]=base+0x88;read_rows=[]
        def read_byte(at,n,i):
            assert n==1;index=z3.Extract(3,0,at-base);prove(proofs,'selector'+str(kind)+'_address_'+hex(i.address),at==base+z3.ZeroExt(60,index));read_rows.append(hex(i.address));return select(index)
        instructions=list(C.CS.disasm(S.read(lo,hi-lo),lo))
        if kind:instructions+=list(C.CS.disasm(S.read(0x1b657c,4),0x1b657c))
        state=Lift(regs,read_byte).execute(instructions);r=state.rr('w11'if not kind else'w13')
        a=(z3.ZeroExt(24,byte_vars[4 if not kind else 2])+(4 if not kind else 14))&15;b=(z3.ZeroExt(24,select(z3.Extract(3,0,a)))+14)&15
        c=(z3.ZeroExt(24,select(z3.Extract(3,0,b)))+(2 if not kind else 0))&15;v=(z3.ZeroExt(24,select(z3.Extract(3,0,c)))+(0 if not kind else 3))&15
        expected=z3.If(v==0,z3.BitVecVal(1,32),v);prove(proofs,'selector'+str(kind)+'_exact_split',r==expected);prove(proofs,'selector'+str(kind)+'_range',z3.And(z3.UGE(r,1),z3.ULE(r,15)))
        assert len(read_rows)==4;slices.append({'kind':kind,'category':'selector','instructions':[{'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'instruction':i.mnemonic+' '+i.op_str}for i in instructions]})
    canonical_vectors=[]
    for kind,head,lo,hi in [(0,True,0x1b53c8,0x1b5420),(0,False,0x1b5444,0x1b54ac),(1,True,0x1b65a8,0x1b6600),(1,False,0x1b6620,0x1b6688)]:
        prefix='body'+str(kind)+str(int(head));av,bv,cv,h,k,aa,bb,dd=[z3.BitVec(prefix+'_'+n,32)for n in ['A','B','C','h','k','a','b','d']];idx=z3.BitVec(prefix+'_i64',64);p=z3.BitVec(prefix+'_byte8',8);ctrl=z3.BitVec(prefix+'_control32',32)
        regs={j:z3.BitVec(prefix+'_X'+str(j),64)for j in range(31)};desc=PASSES[kind]
        for j,v in zip(desc['states'],[av,bv,cv,h]):regs[j]=z3.ZeroExt(32,v)
        regs[2 if kind==0 else 6]=z3.ZeroExt(32,k);regs[0]=z3.ZeroExt(32,aa);regs[9]=z3.ZeroExt(32,bb)
        counter=desc['counter_head'if head else'counter_tail'];regs[counter]=idx
        pbase=z3.BitVec(prefix+'_base64',64);regs[29]=pbase+0x88
        if head:regs[13 if kind==0 else 14]=pbase
        if kind==0:regs[10]=z3.ZeroExt(32,ctrl)
        else:
            if head:regs[16]=z3.ZeroExt(32,dd)
            else:regs[8]=z3.ZeroExt(32,ctrl)
        constraints=[z3.ULT(idx,16)]
        if not head:constraints.append(((ctrl-(0x4d1d if kind==0 else 0x41f8))&31)==(8 if kind==0 else 16))
        def byte_load(at,n,i):assert n==1;prove(proofs,prefix+'_byte_address',at==pbase+idx,constraints);return p
        instructions=list(C.CS.disasm(S.read(lo,hi-lo),lo));state=Lift(regs,byte_load).execute(instructions)
        def ff(x):x=x+z3.LShR(x,16);return x+z3.LShR(x,8)
        d=dd if kind==1 and head else aa;u=z3.ZeroExt(24,p)*k;t=ff((u^h)+z3.Extract(31,0,idx));v=ff(((t+d)^u)+z3.Extract(31,0,idx))
        expected=[av^t^v,bv^(t+bb)^(v+bb),cv^(t+d)^(v+aa),v+aa]
        residue_register=1 if kind==0 else 3
        residue_expected=(cv^(t+aa)if kind==0 else t+bb)if head else z3.Extract(31,0,regs[residue_register])
        actual=[state.rr('w'+str(j))for j in desc['states']];prove(proofs,prefix+'_state_and_counter',z3.And(*[x==y for x,y in zip(actual,expected)],state.rr('x'+str(counter))==idx+1,state.rr('w'+str(residue_register))==residue_expected),constraints)
        canonical_vectors.append((kind,head,expected));slices.append({'kind':kind,'category':'head_body'if head else'tail_body','instructions':source_rows(lo,hi)})
    for kind,head,lo,hi in [(0,True,0x1b5420,0x1b5440),(0,False,0x1b54ac,0x1b54cc),(1,True,0x1b6600,0x1b661c),(1,False,0x1b6688,0x1b66a8)]:
        prefix='dispatch'+str(kind)+str(int(head));counter=z3.BitVec(prefix+'_i64',64);split=z3.BitVec(prefix+'_split64',64);control=z3.BitVec(prefix+'_control32',32);table=z3.BitVec(prefix+'_table64',64);fp=z3.BitVec(prefix+'_FP64',64);addresses=[]
        regs={j:z3.BitVec(prefix+'_X'+str(j),64)for j in range(31)};regs[29]=fp;regs[PASSES[kind]['counter_head'if head else'counter_tail']]=counter
        if head:regs[PASSES[kind]['split']]=split
        if kind==1 and head:regs[1]=z3.BitVecVal(0x4b,64)
        regs[10 if kind==0 else 7 if head else 8]=z3.ZeroExt(32,control)
        def pointer_load(at,n,i):
            assert n==8
            if len(addresses)==0:prove(proofs,prefix+'_table_slot',at==fp-0x98);addresses.append(at);return table
            addresses.append(at);return z3.BitVec(prefix+'_target64',64)
        state=Lift(regs,pointer_load).execute(list(C.CS.disasm(S.read(lo,hi-lo),lo)))
        predicate=counter!=split if kind==0 and head else counter==split if head else counter==16
        coefficient=31 if kind==0 and head else 0x974b if kind==0 else 0x4b if head else 0x5f
        index=control^z3.If(predicate,z3.BitVecVal(coefficient,32),z3.BitVecVal(0,32));prove(proofs,prefix+'_pointer_index',addresses[-1]==table+(z3.SignExt(32,index)<<3))
        slices.append({'kind':kind,'category':'head_dispatch'if head else'tail_dispatch','instructions':source_rows(lo,hi)})
    a,b,c,h,k,aa,bb=[z3.BitVec('shared_'+n,32)for n in ['A','B','C','h','k','a','b']];byte=z3.BitVec('shared_byte',8);i=z3.BitVec('shared_i',32)
    def one_step(d,initial=None):
        av,bv,cv=(a,b,c)if initial is None else initial
        u=z3.ZeroExt(24,byte)*k;t=u^h;t=t+i;t=t+z3.LShR(t,16);t=t+z3.LShR(t,8);v=((t+d)^u)+i;v=v+z3.LShR(v,16);v=v+z3.LShR(v,8)
        return [av^t^v,bv^(t+bb)^(v+bb),cv^(t+d)^(v+aa),v+aa]
    other=[z3.BitVec('other_initial_'+n,32)for n in ['A','B','C']];left=one_step(aa);right=one_step(aa,other)
    prove(proofs,'xor_deltas_independent_of_accumulator_seed',z3.And(*[(left[j]^[a,b,c][j])==(right[j]^other[j])for j in range(3)],left[3]==right[3]))
    n=z3.Int('scan_split');prove(proofs,'bounded_two_phase_loop_counts',z3.Implies(z3.And(n>=1,n<=15),z3.And(n>=1,16-n>=1,n+(16-n)==16)))
    assert len(proofs)==30
    return {'proofs':proofs,'slices':slices,'body_scope':'arbitrary u32 accumulator/seed/multiplier/bias values and u8 byte; counter 0..15; explicit tail shift premises; second head d=a for common recurrence',
      'loop_argument':'selector yields n in 1..15; unit counter progress executes head indices 0..n-1 then tail n..15; identical canonical transfer yields the same sixteen-step fold for any split'}


class Capture(A.Replay):
    def __init__(self,*args):super().__init__(*args);self.scans=[]
    def code(self,u,pc,n,d):
        self.flush()
        for spec in PASSES:
            if pc==C.BASE+spec['start']:self.scans.append({'kind':spec['kind'],'entry':A.capture(self)})
            if pc==C.BASE+spec['end']:self.scans[-1]['end']=A.capture(self)
        return super().code(u,pc,n,d)


def main():
    pinned={}
    for name,h in PINS.items():
        raw=read(ROOT/name).encode();assert SHA(raw)==h;pinned[name]=json.loads(raw)
    parent=pinned['corefp_workspace_checks.json'];blocks=[];totals=Counter();oracles=[]
    for p in parent['profiles']:
        r=Capture(p,parent['source_spans'],S);totals.update(r.run());assert len(r.scans)==2
        for b in r.scans:
            spec=PASSES[b['kind']];lo,hi=b['entry']['source_visit'],b['end']['source_visit'];b.update({'label':p['configuration']['label'],
              'reads':[x for x in p['reads']if lo<=x['visit']<hi],'writes':[x for x in p['writes']if lo<=x['visit']<hi],'PAC_models':[x for x in p['PAC_models']if lo<=x['visit']<hi],
              'visits':[x for x in p['visits'][lo:hi]],'initial_dispatch':next(x for x in p['PAC_models']if lo<=x['visit']<hi and x['pc']==hex(spec['init']))})
            prepared=bytes.fromhex(b['entry']['stack1312_hex'])[0x498:0x4a8];o=oracle(prepared,b['kind'],b['initial_dispatch']['CPU']);got=[hex(int(b['end']['CPU']['X31'][j],16)&M32)for j in spec['states']]
            assert o['final_state_u32']==got and not b['writes']and len(b['PAC_models'])==17
            assert o['split']==int(b['initial_dispatch']['CPU']['X31'][spec['split']],16)
            assert o['head_residue_u32']==hex(int(b['end']['CPU']['X31'][o['head_residue_register']],16)&M32)
            assert len(b['visits'])==(583-4*o['split']if b['kind']==0 else 590-5*o['split'])
            oracles.append({'label':b['label'],'kind':b['kind'],**o});blocks.append(b)
        assert oracles[-1]['xor_deltas_u32']==oracles[-2]['xor_deltas_u32']and oracles[-1]['final_state_u32'][3]==oracles[-2]['final_state_u32'][3]
        print(json.dumps({'captured':p['configuration']['label'],'splits':[o['split']for o in oracles[-2:]]}),flush=True)
    source=source_proofs();dependencies=['recover_corefp_late_preparation.py','audit_corefp_late_preparation.py',*pinned['corefp_late_preparation_checks.json']['dependencies']]
    counts={'profiles':6,'scan_regions':12,'static_instructions':184,'static_source_B':736,'regional_visits':sum(len(b['visits'])for b in blocks),'regional_reads':sum(len(b['reads'])for b in blocks),
      'regional_writes':0,'regional_PAC_models':204,'prepared_read_instances':240,'scan_steps':192,'new_queries_unsat':30}
    out={'scope':__doc__,'generator_sha256':SHA(Path(__file__).read_bytes()),'thin_sha256':C.THIN_SHA,'parent_pins':PINS,
      'dependencies':{name:SHA(read(ROOT/name).encode())for name in dependencies},'source_regions':[{'kind':s['kind'],'start':hex(s['start']),'end':hex(s['end']),'instructions':source_rows(s['start'],s['end'])}for s in PASSES],
      'source_checks':source,'blocks':blocks,'oracles':oracles,'replay_totals':dict(totals),'verified_counts':counts,
      'native_target_executed':False,'native_API_executed':False,'IDB_mutated':False,'new_live_IDA_claim':False,'general_raw_preparation_contract_established':False,
      'source_context_initializer_established':False,'whole_transform_algorithm':'unknown','full_goal_complete':False}
    (ROOT/'corefp_preparation_scans_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
