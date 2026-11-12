#!/usr/bin/env python3
"""Common u64 word recurrence under typed product/index/metadata interfaces.

O(C*(B+V*J+P*F+R)) replay time/space; constant-size recurrence;
30 s/SMT query. No native target/API/IPC or IDB operation.
"""
import json
from pathlib import Path
from collections import Counter
import z3
import recover_corefp_word_codec as W
from capstone.arm64_const import ARM64_CC_LO,ARM64_CC_HI,ARM64_CC_EQ,ARM64_CC_NE
ROOT=W.ROOT;C=W.C;S=C.Pointers();SHA=W.SHA;F=W.F;MASK=W.MASK;M32=2**32-1
A=0x98c9b5333f174cc8;B=0x9f8ba664;H0=0x5f3bad8804febfc3;D=0xeb3e515b
SPECS=[('first_head',0x1b4934,0x1b4d50),('first_tail',0x1b4f1c,0x1b51bc),('second_head',0x1b57d0,0x1b5c20),('second_tail',0x1b5e1c,0x1b63dc)]
# Input register, two MBA cuts and biases, two fold cuts/biases, index registers/deltas.
MODELS=[{'q':19,'u':28,'bank':[6,5,1],'out':[6,5,1],'h':19,'a':24,'b':25,'idx':[26,20],
 'mba':[(0x1b4934,0x1b49b4,19,0x4fc84954f2f0a315),(0x1b4aac,0x1b4b2c,19,0x28f482aaf618e308)],
 'fold':[(0x1b49b8,0x1b4a8c,19,0xea1994a3111eca82),(0x1b4b44,0x1b4d14,19,0xd6aee21e48c104c1)],'delta':[0,0x8ed880be33eec4f3]},
 {'q':3,'u':2,'bank':[6,5,1],'out':[6,5,1],'h':19,'a':24,'b':25,'idx':[21,7],
 'mba':[(0x1b4f1c,0x1b4f8c,3,0x244e5ace68e5835c),(0x1b508c,0x1b510c,2,0x53d4a500057eb2b8)],
 'fold':[(0x1b4f90,0x1b506c,3,0x9a786ae3dad6aace),(0x1b5124,0x1b5180,2,0xeee6c51fe30eeb7d)],'delta':[0,0x74791a59a058dc36]},
 {'q':12,'u':3,'bank':[15,6,14],'out':[15,6,14],'h':12,'a':28,'b':23,'idx':[2,16],
 'mba':[(0x1b57d0,0x1b5850,12,0xbef2bc538f768e65),(0x1b5950,0x1b59d0,2,0xfb850901ecc42272)],
 'fold':[(0x1b5854,0x1b5930,12,0xea8707f943881e74),(0x1b59e8,0x1b5bd8,16,0x868010333d95b2cc)],'delta':[0,0x2997a9c8be84ff1e]},
 {'q':12,'u':20,'bank':[15,6,14],'out':[15,6,14],'h':12,'a':28,'b':23,'idx':[2,1],
 'mba':[(0x1b5e1c,0x1b5e9c,12,0xf0802bad09d38a3a),(0x1b60cc,0x1b614c,15,0x716024ac4b0a68b8)],
 'fold':[(0x1b5ea0,0x1b60b4,12,0xba7f7c4151ad93ea),(0x1b616c,0x1b638c,15,0xab18f078f733789f)],'delta':[0,0xe0b734e758f5b6da]}]
PINS={**W.PINS,'corefp_word_codec_checks.json':'c766552ae9fa883d70da2d80dbbf80cae4a41fa29f32d7c007156ad8cf22d23e',
 'corefp_word_codec_audit.json':'5865d5245303b5d947b5b366158da41aad3d7a5b751141f4e0a9279f9f8f53a3'}


def shift(x,n):return z3.LShR(x,n)if z3.is_bv(x)else x>>n
def folded(x):
    x=(x+shift(x,32))&MASK;x=(x-shift(x,16))&MASK;return (x+shift(x,8))&MASK
def step(q,u,index,bank,a=A,b=B):
    t=folded((q+index)&MASK);v=folded((((t+a)&MASK)^u)+index&MASK)
    def low(x):return z3.Extract(31,0,x)if z3.is_bv(x)else x&M32
    out=[bank[0]^low(t)^low(v),bank[1]^low(t+b)^low(v+b),bank[2]^low(t+a)^low(v+a)]
    return out,(v+a)&MASK,v,t
def offset(m,j):return (m['mba'][j][3]+m['fold'][j][3]+m['delta'][j])&MASK


class Lift(W.Lift):
    def execute(self,instructions):
        for i in instructions:
            o=i.operands;m=i.mnemonic
            if m=='cmp':
                bits=32 if i.reg_name(o[0].reg).startswith('w')else 64;a,b=self.value(i,o[0],bits),self.value(i,o[1],bits);self.flags['Z']=a==b;self.flags['C']=z3.UGE(a,b)
            elif m in ['cset','csel']:
                cc={ARM64_CC_LO:z3.Not(self.flags['C']),ARM64_CC_HI:z3.And(self.flags['C'],z3.Not(self.flags['Z'])),ARM64_CC_EQ:self.flags['Z'],ARM64_CC_NE:z3.Not(self.flags['Z'])};condition=cc[i.cc];n=i.reg_name(o[0].reg);bits=32 if n.startswith('w')else 64
                self.put(n,z3.If(condition,z3.BitVecVal(1,bits),z3.BitVecVal(0,bits))if m=='cset'else z3.If(condition,self.value(i,o[1],bits),self.value(i,o[2],bits)))
            else:super().execute([i])
        return self


def external(instructions):
    written=set();needed=set()
    def reg(i,j):
        n={'fp':'x29','lr':'x30'}.get(i.reg_name(j),i.reg_name(j));return int(n[1:])if n[0:1]in ['x','w']and n[1:].isdigit()else None
    for i in instructions:
        reads,writes=i.regs_access()
        # Capstone also reports the LSL destination as read; use explicit sources.
        if i.mnemonic=='lsl':reads=[o.reg for o in i.operands[1:]if o.type==1]
        needed.update(k for j in reads if (k:=reg(i,j))is not None and k not in written);written.update(k for j in writes if (k:=reg(i,j))is not None)
    return needed


def source_checks(codec):
    proofs=[];cuts=[];metadata=[]
    for kind,m in enumerate(MODELS):
        seed=next(b for b in codec['blocks']if b['name']==SPECS[kind][0]);base=list(map(lambda v:int(v,16),seed['end']['CPU']['X31']));items=[]
        for typ in ['mba','fold']:
            for j,(lo,hi,reg,bias)in enumerate(m[typ]):
                ins=list(C.CS.disasm(S.read(lo,hi-lo),lo));meta={k:base[k]for k in external(ins)-{reg}}
                # Last fold's interleaved control registers do not affect its value.
                if kind==3 and typ=='fold'and j==1:meta={k:v for k,v in meta.items()if k not in [16,17,11]}
                x=z3.BitVec('cut_'+str(kind)+typ+str(j),64);regs={k:z3.BitVec('cut_X'+str(k),64)for k in range(31)};regs.update({k:z3.BitVecVal(v,64)for k,v in meta.items()});regs[reg]=x
                state=Lift(regs,z3.BitVec('cut_SP',64)).execute(ins);want=x+bias
                if typ=='fold':want=want+z3.LShR(want,32)
                label=str(kind)+'_'+typ+str(j);F.P.prove(proofs,label+'_source_identity',state.rr('x'+str(reg))==want)
                item={'kind':kind,'type':typ,'stage':j,'start':hex(lo),'end':hex(hi),'register':reg,'bias_u64':hex(bias),'metadata_u64':{str(k):hex(v)for k,v in meta.items()},'instructions':F.P.source_rows(lo,hi)};cuts.append(item);items.append(item)
        metadata.append({k:v for item in items for k,v in item['metadata_u64'].items()})
        q,u,idx,a=[z3.BitVec('body'+str(kind)+'_'+n,64)for n in ['q','u','index','a']];b=z3.BitVec('body'+str(kind)+'_b',32);bank=[z3.BitVec('body'+str(kind)+'_bank'+str(j),32)for j in range(3)];sp=z3.BitVec('body_SP',64)
        regs={k:z3.BitVec('body'+str(kind)+'_X'+str(k),64)for k in range(31)};regs.update({int(k):z3.BitVecVal(int(v,16),64)for k,v in metadata[-1].items()});regs.update({m['q']:q,m['u']:u,m['a']:a,m['b']:z3.ZeroExt(32,b),29:sp+0x520})
        for k,v in zip(m['bank'],bank):regs[k]=z3.ZeroExt(32,v)
        for j,k in enumerate(m['idx']):regs[k]=idx-offset(m,j)
        reads=[]
        def load(at,n,i):reads.append({'pc':hex(i.address),'size_B':n,'address_expression':str(at)});return z3.BitVec('body_read_'+hex(i.address),8*n)
        state=Lift(regs,sp,load);pending={}
        for ins in C.CS.disasm(S.read(SPECS[kind][1],SPECS[kind][2]-SPECS[kind][1]),SPECS[kind][1]):
            for item in items:
                if ins.address==int(item['start'],16):
                    bindings=[state.rr('x'+k)==int(v,16)for k,v in item['metadata_u64'].items()]
                    F.P.prove(proofs,str(kind)+'_'+item['type']+str(item['stage'])+'_entry_bindings',z3.And(*bindings))
                    original=state.rr('x'+str(item['register']));v=original+int(item['bias_u64'],16);pending[int(item['end'],16)]=(item['register'],v if item['type']=='mba'else v+z3.LShR(v,32))
            if ins.address in pending:
                reg,value=pending.pop(ins.address);state.put('x'+str(reg),value)
            state.execute([ins])
        assert not pending
        want,h,v,t=step(q,u,idx,bank,a,z3.ZeroExt(32,b));clauses=[state.rr('w'+str(k))==value for k,value in zip(m['out'],want)]+[state.rr('x'+str(m['h']))==h]
        if kind in [1,3]:clauses.append(state.rr('x'+str(7 if kind==1 else 1))==v)
        F.P.prove(proofs,str(kind)+'_common_word_recurrence',z3.And(*clauses));assert len(reads)==(3 if kind==3 else 0)
    words=[z3.BitVec('paired_bank'+str(j),32)for j in range(3)];x=[z3.BitVec('paired_update'+str(j),32)for j in range(3)]
    F.P.prove(proofs,'common_updates_preserve_bank_xor',z3.And(*[((a^b)^((a^D)^b))==D for a,b in zip(words,x)]))
    return {'proofs':proofs,'cuts':cuts,'metadata_by_body_u64':metadata,'read_interface':'second tail reads u32(FP-0xc8), u64(FP-0x98), then one u64 table value; arbitrary typed values; no stores',
      'index_interface':'both biased index registers plus their declared offset equal the same arbitrary u64 word index; address/control admission is separate'}


class Capture(W.Capture):
    def __init__(self,*a):super().__init__(*a);self.recurrence_components=[];self.active_recurrence=None
    def code(self,u,pc,n,d):
        self.flush()
        for name,lo,hi in SPECS:
            if pc==C.BASE+lo:assert self.active_recurrence is None;self.active_recurrence={'name':name,'entry':F.P.A.capture(self)}
            if pc==C.BASE+hi and self.active_recurrence is not None and self.active_recurrence['name']==name:
                self.active_recurrence['end']=F.P.A.capture(self);self.recurrence_components.append(self.active_recurrence);self.active_recurrence=None
        return super().code(u,pc,n,d)


def main():
    pins={}
    for n,h in PINS.items():
        raw=F.P.read(ROOT/n).encode();assert SHA(raw)==h;pins[n]=json.loads(raw)
    parent=pins['corefp_workspace_checks.json'];codec=pins['corefp_word_codec_checks.json'];blocks=[];totals=Counter();joins=[]
    checks=source_checks(codec);print(json.dumps({'source_queries_unsat':len(checks['proofs'])}),flush=True)
    for j,p in enumerate(parent['profiles']):
        r=Capture(p,parent['source_spans'],S);totals.update(r.run());assert r.active_recurrence is None
        previous=codec['blocks'][len(blocks):len(blocks)+len(r.recurrence_components)];epoch=codec['joins'][j]['epochs'];indices=Counter()
        for b,old in zip(r.recurrence_components,previous):
            assert b['entry']==old['end'];kind=next(k for k,sp in enumerate(SPECS)if sp[0]==b['name']);m=MODELS[kind];lo,hi=b['entry']['source_visit'],b['end']['source_visit']
            assert hi-lo==(SPECS[kind][2]-SPECS[kind][1])//4
            b.update({'label':p['configuration']['label'],'visits':p['visits'][lo:hi],**{k:[v for v in p[k]if lo<=v['visit']<hi]for k in ['reads','writes','PAC_models']}})
            regs=list(map(lambda v:int(v,16),b['entry']['CPU']['X31']));i=(regs[m['idx'][0]]+offset(m,0))&MASK;assert i==((regs[m['idx'][1]]+offset(m,1))&MASK);assert i==indices['first'if kind<2 else'second'];indices['first'if kind<2 else'second']+=1
            bank=[regs[k]&M32 for k in m['bank']];out,h,v,t=step(regs[m['q']],regs[m['u']],i,bank,regs[m['a']],regs[m['b']]&M32);end=list(map(lambda x:int(x,16),b['end']['CPU']['X31']))
            assert out==[end[k]&M32 for k in m['out']]and h==end[m['h']]and regs[m['a']]==A and regs[m['b']]==B
            b['normalized_index_u64']=hex(i);b['oracle']={'bank_u32':list(map(hex,out)),'h_u64':hex(h),'v_u64':hex(v),'t_u64':hex(t)};blocks.append(b)
        assert indices['first']==indices['second']==len(epoch)
        old=pins['corefp_scan_entry_checks.json'];left=old['blocks'][j*5+1]['entry'];right=old['blocks'][j*5+3]['entry'];assert left==r.components['first_initializer']['entry']and right==r.components['second_initializer']['entry']
        joins.append({'label':p['configuration']['label'],'word_count':len(epoch),'raw_words_u64':[x['raw_word_u64']for x in epoch],'first_initializer':left,'second_initializer':right});print(json.dumps({'captured':p['configuration']['label']}),flush=True)
    deps=['recover_corefp_word_codec.py','audit_corefp_word_codec.py',*codec['dependencies']]
    verified={'profiles':6,'regions':32,'source_instructions':1075,'source_B':4300,'regional_visits':8226,'regional_reads':18,'regional_writes':0,'regional_PAC_models':0,'word_steps':32,'new_queries_unsat':len(checks['proofs']),'normalization_cuts':16}
    assert sum(len(b['visits'])for b in blocks)==8226 and sum(len(b['reads'])for b in blocks)==18 and not any(b['writes']or b['PAC_models']for b in blocks)
    out={'scope':__doc__,'generator_sha256':SHA(Path(__file__).read_bytes()),'thin_sha256':C.THIN_SHA,'parent_pins':PINS,'dependencies':{n:SHA(F.P.read(ROOT/n).encode())for n in deps},
      'source_regions':[{'name':n,'start':hex(lo),'end':hex(hi),'instructions':F.P.source_rows(lo,hi)}for n,lo,hi in SPECS],
      'models':MODELS,'source_checks':checks,'blocks':blocks,'joins':joins,'verified_counts':verified,'replay_totals':dict(totals),'native_target_executed':False,'native_API_executed':False,'IDB_mutated':False,
      'new_live_IDA_claim':False,'earlier_arithmetic_passes_universally_reduced':False,'word_recurrence_universally_reduced':True,'general_raw_preparation_contract_established':False,'whole_transform_algorithm':'unknown','full_goal_complete':False}
    (ROOT/'corefp_word_recurrence_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(verified),flush=True)


if __name__=='__main__':main()
