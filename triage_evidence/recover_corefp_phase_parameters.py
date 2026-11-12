#!/usr/bin/env python3
"""Source-produced phase encodings from paired scan accumulators.

Typed private source, stack, dispatch and caller premises remain explicit.
No native target/API/IPC or IDB operation. O(C*(B+V*J+P*F+R)) replay
time/space; fixed 198-instruction component; 30 s/SMT query.
"""
import json
from pathlib import Path
from collections import Counter
import z3
import recover_corefp_preparation_scans as P
from capstone.arm64_const import ARM64_CC_EQ
ROOT=P.ROOT;C=P.C;S=C.Pointers();SHA=P.SHA;M=(1<<32)-1
START=0x1b66ac;CORE_END=0x1b6950;END=0x1b69c4;D=0xeb3e515b
PINS={**P.PINS,'corefp_preparation_scans_checks.json':'f851533a1fb3fce78c54cbb712107589e2b477d8e28e0a1ce03ee699c7cbafee',
 'corefp_preparation_scans_audit.json':'d35d4144e7d6e04d1fa8e1e3c25725f4297a82dd60eced0f33dcfec065ba22a8'}


def shift(x,n):return z3.LShR(x,n)if z3.is_bv(x)else x>>n
def u(x):return x&M
def addshift(x,n):return u(x+shift(x,n))
def subshift(x,n):return u(x-shift(x,n))


def mix(seed):
    a=addshift(addshift(u(seed+0xd01d67d8),14),6)
    b=subshift(addshift(a^0x8df2987e,11),1)
    c=addshift(subshift(u(b+0xf1b810a4),11),8)
    d=subshift(subshift(c^0x24880a0e,9),8)
    e=subshift(addshift(u(d+0xd20cac36),13),3)
    f=addshift(addshift(u(e+0x088e8841),11),5)
    g=subshift(addshift(u(f+0xd95b0f59),9),4)
    h=subshift(addshift(g^0x62167b51,13),5)
    j=addshift(subshift(u(h+0x5e588794),15),8)
    return [a^d^g,b^e^h,c^f^j]


def select(c,a,b):return z3.If(c,a,b)if z3.is_bool(c)else a if c else b
def inv(x):return x^M
def repeated(x):return u(x*0x01010101)
def parity(x):return (x^shift(x,8)^shift(x,16)^shift(x,24))&255


def masks(left,right):
    a,b,c=left;d,e,f=right;r=(c&7)^5;t=(f^6)&7;k=(-r)&7;l=(-t)&7
    q=select(r==0,0,u(255<<k));v=select(t==0,0,u(255<<l))
    # Coerce integer alternatives to u32 in symbolic conditionals.
    q=u(q);v=u(v);qb=q&255;vb=v&255
    first=(a&select(r==0,0,inv(q)))&255
    second=(d&select(t==0,0,inv(v)))&255
    hu=repeated(parity(d)^0x84)^0xfbfbfbfb
    hv=repeated(parity(e)^0x76)^0x27272727
    return {'m1':(a&127)^0x5d,'m2':(d&127)^6,'r1':r,'r2':t,'k1':k,'k2':l,'q1':qb,'q2':vb,
      'word_right':first^repeated(qb),'index_right':second^repeated(vb),
      'word_left':repeated(vb)^inv(u(vb*0xf5000000)&e),'digest_u':hu,'digest_v':hv,
      'M':repeated((d&127)^6),'b':parity(d^e)^0x2e,'K':a^b^0x7631365f,'Q':d^e^0x8b95e221,
      'registers':{23:repeated((d&127)^6),25:t,28:l,19:k,24:first^repeated(qb),27:second^repeated(vb),
       20:repeated(vb)^inv(u(vb*0xf5000000)&e),21:b,22:e,16:hv^0x27272727,10:hv^hu},
      'stores':[(0x450,c),(0x48,(a&127)^0x5d),(0x410,repeated((a&127)^0x5d)),(0x458,r),(0x1c,qb),
        (0x400,a),(0x24,repeated(qb)),(0x44,(d&127)^6),(0x3f8,d),(0x6c,hu),(0x70,hv)]}


class Lift(P.Lift):
    def __init__(self,registers,sp,read_hook=None):
        super().__init__(registers,read_hook or (lambda *a: (_ for _ in ()).throw(AssertionError('unexpected read'))))
        self.sp=sp;self.stores=[];self.normalization_input=None
    def rr(self,n):return self.sp if n=='sp'else super().rr(n)
    def execute(self,instructions,normalize=False):
        for i in instructions:
            m=i.mnemonic;o=i.operands;n=i.reg_name(o[0].reg);bits=32 if n.startswith('w')else 64
            if i.address==0x1b6854:self.normalization_input=self.rr('w3')
            if m=='ldp':
                mem=o[2];assert not mem.mem.index;at=self.rr(i.reg_name(mem.mem.base))+mem.mem.disp
                for j,reg in enumerate([n,i.reg_name(o[1].reg)]):self.put(reg,self.read_hook(at+j*bits//8,bits//8,i))
            elif m in ['str','stur','stp']:
                mem=o[2 if m=='stp'else 1];assert not mem.mem.index;at=self.rr(i.reg_name(mem.mem.base))+mem.mem.disp
                for j,reg in enumerate([n,i.reg_name(o[1].reg)]if m=='stp'else[n]):self.stores.append((at+j*bits//8,self.rr(reg)))
            elif m=='neg':self.put(n,-self.value(i,o[1],bits))
            elif m=='ands':
                v=self.value(i,o[1],bits)&self.value(i,o[2],bits);self.put(n,v);self.flags['Z']=v==0
            elif m in ['csel','csinv']:
                assert i.cc==ARM64_CC_EQ;a,b=self.value(i,o[1],bits),self.value(i,o[2],bits)
                self.put(n,z3.If(self.flags['Z'],a,b if m=='csel'else ~b))
            elif m=='eon':self.put(n,self.value(i,o[1],bits)^~self.value(i,o[2],bits))
            else:super().execute([i])
            if normalize and i.address==0x1b6864:
                # Composed with the separately source-lifted five-instruction identity.
                self.put('w5',self.normalization_input^0x62167b51)
        return self


def proofs():
    out=[];bv=lambda n:z3.BitVec(n,32);sp=z3.BitVec('phase_SP64',64)
    regs={j:z3.BitVec('phase_X'+str(j),64)for j in range(31)};regs[29]=sp+0x520
    a,b,c,d,e,f,s,t=[bv('phase_'+n)for n in ['a','b','c','d','e','f','s','t']]
    for j,v in zip([26,30,22,15,10,11,5,12],[a,b,c,d,e,f,s,t]):regs[j]=z3.ZeroExt(32,v)
    cutregs={j:z3.BitVec('cut_X'+str(j),64)for j in range(31)};cut=bv('cut_value');cutregs[3]=z3.ZeroExt(32,cut);cutregs[25]=z3.BitVecVal(0x62167b51,64)
    cutstate=Lift(cutregs,sp).execute(list(C.CS.disasm(S.read(0x1b6854,20),0x1b6854)))
    P.prove(out,'source_opaque_subtract_bias_is_xor',cutstate.rr('w5')==cut^0x62167b51)
    state=Lift(regs,sp).execute(list(C.CS.disasm(S.read(START,CORE_END-START),START)),normalize=True)
    ls=[x^y for x,y in zip([a,b,c],mix(s))];rs=[x^y for x,y in zip([d,e,f],mix(t))];p=masks(ls,rs)
    for j,v in p['registers'].items():P.prove(out,'core_register_'+str(j),state.rr('w'+str(j))==v)
    P.prove(out,'core_initial_constructor_counter',state.rr('w13')==0)
    assert len(state.stores)==len(p['stores'])==11
    for j,((at,value),(off,want))in enumerate(zip(state.stores,p['stores'])):
        P.prove(out,'core_store_'+str(j),z3.And(at==sp+off,value==want))
    # Mixer equality is composed from the single source-normalized function above.
    aa,bb,cc,xx,yy,zz=[bv('paired_'+n)for n in ['a','b','c','x','y','z']]
    left=[aa^xx,bb^yy,cc^zz];right=[aa^D^xx,bb^D^yy,cc^D^zz]
    P.prove(out,'shared_mixer_preserves_bank_xor',z3.And(*[(v^w)==D for v,w in zip(left,right)]))
    par=masks([aa,bb,cc],[aa^D,bb^D,cc^D])
    P.prove(out,'paired_masks_rotations_biases',z3.And(par['m1']==par['m2'],par['r1']==par['r2'],par['K']^par['Q']==0xfda4d47e,
      par['digest_u']^par['digest_v']==repeated(par['b']),z3.ULE(par['m1'],127),z3.ULE(par['r1'],7)))
    word=bv('rotation_word');byte=z3.BitVec('rotation_byte',8)
    for r in range(8):
        premises=[par['r1']==r]
        actual=(word&par['word_left'])<<par['r2'];actual+=z3.LShR(word&par['word_right'],par['k1'])
        want=z3.Concat(*[z3.RotateLeft(z3.Extract(j+7,j,word),r)for j in [24,16,8,0]])
        P.prove(out,'word_rotation_'+str(r),actual==want,premises)
        v=z3.ZeroExt(24,byte);actual=((v<<par['r1'])|z3.LShR((v&par['index_right'])&255,par['k2']))&255
        P.prove(out,'index_rotation_'+str(r),actual==z3.ZeroExt(24,z3.RotateLeft(byte,r)),premises)
    control=bv('tail_control');table=z3.BitVec('tail_dispatch_table64',64);target=z3.BitVec('tail_target64',64)
    pointers=[z3.BitVec('tail_pointer'+str(j),64)for j in range(4)];load_values=[table,target,*pointers];loads=[]
    tailregs={j:z3.BitVec('tail_X'+str(j),64)for j in range(31)};tailregs[29]=sp+0x520;tailregs[8]=z3.ZeroExt(32,control)
    def load(at,n,i):
        assert n==8;loads.append((at,hex(i.address)));return load_values[len(loads)-1]
    tail=Lift(tailregs,sp,load).execute(list(C.CS.disasm(S.read(CORE_END,END-4-CORE_END),CORE_END)))
    expected=[sp+0x488,table+(z3.SignExt(32,control+0x367f)<<3),sp+0x428,sp+0x430,sp+0x328,sp+0x2b8]
    assert len(loads)==6 and len(tail.stores)==1
    for j,((at,pc),want)in enumerate(zip(loads,expected)):P.prove(out,'tail_load_'+str(j),at==want)
    at,value=tail.stores[0];P.prove(out,'tail_control_scratch_store',z3.And(at==sp+0x348,value==((control+0x367f)^0x7885)*0x207b))
    P.prove(out,'tail_fixed_constructor_fields',z3.And(*[tail.rr('w'+str(j))==v for j,v in {11:0x9a7cd460,14:0xce,15:0x8c,16:0x7631365f,0:0x8b95e221,26:0x80551819,30:0x71ad47f5}.items()]),[control==0x4208])
    P.prove(out,'tail_dispatch_and_backing',z3.And(tail.rr('x2')==target,tail.rr('x17')==0x2c2a,*[tail.rr('x'+str(j))==v for j,v in zip([7,6,3,9],pointers)]))
    return {'proofs':out,'normalization_cut':{'start':'0x1b6854','end':'0x1b6868','register':'W5','premise':'W25=0x62167b51, set by original 0x1b66b8/0x1b66bc',
      'identity':'x - ((2*c mod 2^32) AND (x<<1)) + c = x XOR c, modulo 2^32'},
      'scope':'arbitrary eight u32 scalar inputs; typed FP=SP+0x520; no core reads; paired coherence requires equal mixer seeds and bank XOR 0xeb3e515b'}


class Capture(P.A.Replay):
    def __init__(self,*args):super().__init__(*args);self.phase={}
    def code(self,u,pc,n,d):
        self.flush()
        if pc==C.BASE+START:assert not self.phase;self.phase['entry']=P.A.capture(self)
        if pc==C.BASE+CORE_END:self.phase['core_end']=P.A.capture(self)
        if pc==C.BASE+END and 'end'not in self.phase:self.phase['end']=P.A.capture(self)
        return super().code(u,pc,n,d)


def parameters(cpu):
    rr=[int(x,16)&M for x in cpu['X31']];l=[rr[j]^v for j,v in zip([26,30,22],mix(rr[5]))];r=[rr[j]^v for j,v in zip([15,10,11],mix(rr[12]))]
    p=masks(l,r)
    return {'left_mixed_u32':list(map(hex,l)),'right_mixed_u32':list(map(hex,r)),'shared_seed':rr[5]==rr[12],
      'bank_xors_u32':[hex(a^b)for a,b in zip(l,r)],'mask_u32':hex(p['M']),'rotate_per_byte':p['r1'],'index_xor_u8':hex(p['b']),
      'first_xor_u32':hex(p['K']),'second_xor_u32':hex(p['Q']),'effective_bits_upper_bound':42}


def main():
    pinned={}
    for name,h in PINS.items():
        raw=P.read(ROOT/name).encode();assert SHA(raw)==h;pinned[name]=json.loads(raw)
    parent=pinned['corefp_workspace_checks.json'];scans=pinned['corefp_preparation_scans_checks.json'];audit=pinned['corefp_workspace_audit.json'];blocks=[];totals=Counter();forms=[]
    for j,p in enumerate(parent['profiles']):
        replay=Capture(p,parent['source_spans'],S);totals.update(replay.run());b=replay.phase;assert b['entry']==scans['blocks'][2*j+1]['end']
        lo,hi=b['entry']['source_visit'],b['end']['source_visit'];assert hi-lo==198
        b.update({'label':p['configuration']['label'],'visits':p['visits'][lo:hi],**{k:[x for x in p[k]if lo<=x['visit']<hi]for k in ['reads','writes','PAC_models']}})
        rr=[int(x,16)&M for x in b['entry']['CPU']['X31']];form=parameters(b['entry']['CPU']);assert form['shared_seed']and form['bank_xors_u32']==[hex(D)]*3
        for key in ['mask_u32','rotate_per_byte','index_xor_u8','first_xor_u32','second_xor_u32']:assert form[key]==audit['workspace_oracles'][j][key]
        ep=b['end']['CPU']['X31'];stack=bytes.fromhex(b['end']['stack1312_hex']);v=lambda k:int(ep[k],16)&M
        assert v(25)==form['rotate_per_byte']and v(23)==int(form['mask_u32'],16)and v(10)&255==int(form['index_xor_u8'],16)
        assert int.from_bytes(stack[0x400:0x404],'little')^v(21)^v(16)==int(form['first_xor_u32'],16)
        assert int.from_bytes(stack[0x3f8:0x3fc],'little')^v(22)^v(0)==int(form['second_xor_u32'],16)
        blocks.append(b);forms.append({'label':b['label'],**form});print(json.dumps({'captured':b['label']}),flush=True)
    source=proofs();deps=['recover_corefp_preparation_scans.py','audit_corefp_preparation_scans.py',*scans['dependencies']]
    counts={'profiles':6,'source_instructions':198,'source_B':792,'core_instructions':169,'regional_visits':1188,'regional_reads':sum(len(b['reads'])for b in blocks),
      'regional_writes':sum(len(b['writes'])for b in blocks),'regional_PAC_models':6,'new_queries_unsat':len(source['proofs']),'phase_classes':5,'paired_seed_matches':6,'bank_xor_matches':18}
    out={'scope':__doc__,'generator_sha256':SHA(Path(__file__).read_bytes()),'thin_sha256':C.THIN_SHA,'parent_pins':PINS,
      'dependencies':{n:SHA(P.read(ROOT/n).encode())for n in deps},'instructions':P.source_rows(START,END),'source_checks':source,'blocks':blocks,'parameter_oracles':forms,
      'replay_totals':dict(totals),'verified_counts':counts,'native_target_executed':False,'native_API_executed':False,'IDB_mutated':False,'new_live_IDA_claim':False,
      'upstream_shared_seed_and_bank_xor_universal':False,'general_raw_preparation_contract_established':False,'source_context_initializer_established':False,'whole_transform_algorithm':'unknown','full_goal_complete':False}
    (ROOT/'corefp_phase_parameters_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
