#!/usr/bin/env python3
"""Source word-selector chains, encoded base cache and division certificates.

Backing, native admission, normal-flow and immutable epoch premises remain
explicit. O(C*(B+V*J+P*F+R)) replay time/space; 30 s/SMT query.
No native target/API/IPC or IDB operation.
"""
import json
from pathlib import Path
from collections import Counter
import z3
from capstone.arm64_const import ARM64_EXT_UXTW,ARM64_SFT_LSL,ARM64_SFT_LSR
import recover_corefp_word_traversal as R
ROOT=R.ROOT;C=R.C;S=R.S;SHA=R.SHA;F=R.R.W.F.P;M=2**32-1;MASK=2**64-1;KEY=0xcccccccccccccccc
SPECS=[('pointer_cache',0x1b2d68,0x1b2d84),('first_selector',0x1b45dc,0x1b46c0),('second_selector',0x1b54d0,0x1b55a4)]
PINS={**R.PINS,'corefp_word_traversal_checks.json':'e1d391b7a07e5d84bda136d93e776baaddbff63bd1a85f5536641120b8a61b09',
 'corefp_word_traversal_audit.json':'2ca82c17b39cb0951e154798b2dad92e3836254bfe97c9bb062c3a536658ee9d'}
SEEDS=[0x68f4137b,0x1d486d12];ADDS=[[0x4c536b54,0xc8b88f15,0x803e016b,0xa89af9c0],[0x2311ef95,0x700fa8fa,0x3ad4ce9e,0xe18eca0e]]
LOADS=[[0x1b461c,0x1b4634,0x1b468c,0x1b46a4],[0x1b5510,0x1b5540,0x1b5564,0x1b5588]]
DIVS=[[0x1b45fc,0x1b462c,0x1b4684,0x1b469c,0x1b46b4],[0x1b54ec,0x1b5530,0x1b5554,0x1b5578,0x1b559c]]


def rows(lo,hi):return R.R.rows(lo,hi)
def ins(name):_,lo,hi=next(v for v in SPECS if v[0]==name);return list(C.CS.disasm(S.read(lo,hi-lo),lo))
def div(x,n):return z3.If(n==0,z3.BitVecVal(0,x.size()),z3.UDiv(x,n))
def rem(x,n):return x-div(x,n)*n


class Lift(R.R.W.Lift):
    def value(self,i,o,bits):
        if o.ext!=ARM64_EXT_UXTW:return super().value(i,o,bits)
        v=z3.ZeroExt(32,z3.Extract(31,0,self.rr(i.reg_name(o.reg))))
        if o.shift.type:
            if o.shift.type==ARM64_SFT_LSL:v=v<<o.shift.value
            else:assert o.shift.type==ARM64_SFT_LSR;v=z3.LShR(v,o.shift.value)
        assert bits==64;return v
    def execute(self,instructions):
        for i in instructions:
            o=i.operands;n=i.reg_name(o[0].reg);bits=32 if n.startswith('w')else 64
            if i.mnemonic=='udiv':self.put(n,div(self.value(i,o[1],bits),self.value(i,o[2],bits)))
            elif i.mnemonic=='msub':self.put(n,self.value(i,o[3],bits)-self.value(i,o[1],bits)*self.value(i,o[2],bits))
            else:super().execute([i])
        return self


def proofs():
    qs=[];prove=F.prove;sp=z3.BitVec('selector_SP64',64);base=z3.BitVec('selector_base64',64);biased=z3.BitVec('selector_biased64',64);n=z3.BitVec('selector_words32',32);nn=z3.ZeroExt(32,n);control=z3.BitVec('selector_control32',32);residual=z3.BitVec('selector_residual3',3)
    def regs():r={j:z3.BitVec('selector_X'+str(j),64)for j in range(31)};r[29]=sp+0x520;return r
    seen=[]
    def cache_read(at,k,i):assert k==8;prove(qs,'cache_raw_base_address',at==sp+0x450);seen.append(hex(i.address));return biased
    cache=Lift(regs(),sp,cache_read).execute(ins('pointer_cache'));assert len(seen)==len(cache.stores)==1
    prove(qs,'encoded_base_cache_store',z3.And(cache.stores[0][0]==sp+0x70,cache.stores[0][1]==biased+0x41ee14e61969358b))
    prove(qs,'two_pointer_biases_decode_record_base',biased+0x41ee14e61969358b+0xa22256c23a653713==biased+0xe4106ba853ce6c9e)
    effective=z3.ZeroExt(32,control+0x864e)^0xcccccccccccc1fbf
    prove(qs,'selected_first_decoder_key',effective==KEY,[control==0x4d25])
    for kind in range(2):
        r=regs();r[10]=z3.ZeroExt(32,control);word=[z3.BitVec('selector'+str(kind)+'_word'+str(j)+'64',64)for j in range(4)]
        index=z3.ZeroExt(32,rem(z3.BitVecVal(SEEDS[kind],32),n));indexes=[];dividends=[]
        for j in range(4):
            indexes.append(index);decoded=word[j]if kind==0 else word[j]^(effective if j==0 else KEY);D=decoded+ADDS[kind][j];dividends.append(D);index=rem(D,nn)
        seen=[]
        def read(at,k,i):
            if i.address in LOADS[kind]:
                j=LOADS[kind].index(i.address);assert k==8;prove(qs,'selector'+str(kind)+'_word_address_'+str(j),at==base+(indexes[j]<<3));seen.append(hex(i.address));return word[j]
            if kind==0:
                assert i.address in [0x1b45dc,0x1b4618];wanted=sp+(0x3ec if k==4 else 0x468);v=(n<<3)^z3.ZeroExt(29,residual)^0x458e3e59 if k==4 else base
            else:
                assert i.address in [0x1b54e8,0x1b54f4]and k==8;wanted=sp+(0x450 if i.address==0x1b54e8 else 0x70);v=nn if i.address==0x1b54e8 else base-0xa22256c23a653713
            prove(qs,'selector'+str(kind)+'_stack_'+hex(i.address),at==wanted);seen.append(hex(i.address));return v
        state=Lift(r,sp,read)
        if kind==0:
            state.execute(ins('first_selector')[:6]);prove(qs,'first_count_source_binding',state.rr('x1')==nn,[z3.ULE(n,0x1fffffff)])
            # Exact substitution of the preceding source count theorem.
            state.put('x1',nn);state.execute(ins('first_selector')[6:])
        else:state.execute(ins('second_selector'))
        prove(qs,'selector'+str(kind)+'_final_remainder',state.rr('x'+str(10 if kind==0 else 14))==z3.ZeroExt(32,z3.Extract(31,0,index)))
        prove(qs,'selector'+str(kind)+'_divisor_survives',state.rr('x'+str(1 if kind==0 else 15))==nn)
        assert len(seen)==6
        if kind==0:prove(qs,'first_count_u64_cache',z3.And(state.stores[-1][0]==sp+0x450,state.stores[-1][1]==nn))
        else:assert not state.stores
    D,N=z3.Ints('division_D division_N');Q=D/N;rr=D-Q*N
    prove(qs,'unsigned_euclidean_range_certificate',z3.And(Q>=0,Q<2**64,rr>=0,rr<N),[D>=0,D<2**64,N>=1,N<=0x1fffffff])
    # These Int certificates also cover the initial u32 division (D<2^32).
    prove(qs,'remainder_low32_preserves_value',rr%2**32==rr,[D>=0,D<2**64,N>=1,N<=0x1fffffff])
    prove(qs,'scaled_word_index_bound',z3.And(8*rr>=0,8*rr<=8*(N-1),8*rr<2**32),[D>=0,D<2**64,N>=1,N<=0x1fffffff])
    for bits in [32,64]:
        x=z3.BitVec('zero_dividend'+str(bits),bits);prove(qs,'aarch64_zero_quotient'+str(bits),div(x,z3.BitVecVal(0,bits))==0)
    prove(qs,'zero_count_first_index',rem(z3.BitVecVal(SEEDS[0],32),z3.BitVecVal(0,32))==SEEDS[0])
    return {'proofs':qs,'normalization_cut':{'pc':'0x1b45f4','register':'X1','replacement':'zero_extend_64(N)','premise':'N <= 0x1fffffff; encoded byte count = ((N << 3) OR residual3) XOR 0x458e3e59','source_binding_label':'first_count_source_binding'},
      'division_semantics':'unsigned architectural quotient; zero divisor returns zero; MSUB wraps at destination width','scope':'complete four-read selector source projections; mathematical Euclidean certificates for nonzero 29-bit N; arbitrary typed word values and control; no native admission/backing claim'}


class Capture(R.Capture):
    def __init__(self,*a):super().__init__(*a);self.selector_components=[];self.active_selector=None
    def code(self,u,pc,n,d):
        self.flush()
        for name,lo,hi in SPECS:
            if pc==C.BASE+lo:assert self.active_selector is None;self.active_selector={'name':name,'entry':F.A.capture(self)}
            if pc==C.BASE+hi and self.active_selector is not None and self.active_selector['name']==name:self.active_selector['end']=F.A.capture(self);self.selector_components.append(self.active_selector);self.active_selector=None
        return super().code(u,pc,n,d)


def main():
    pins={}
    for n,h in PINS.items():raw=F.read(ROOT/n).encode();assert SHA(raw)==h;pins[n]=json.loads(raw)
    source=proofs();print(json.dumps({'queries_unsat':len(source['proofs'])}),flush=True);parent=pins['corefp_workspace_checks.json'];blocks=[];totals=Counter()
    for p in parent['profiles']:
        r=Capture(p,parent['source_spans'],S);totals.update(r.run());assert r.active_selector is None
        for b in r.selector_components:
            lo,hi=b['entry']['source_visit'],b['end']['source_visit'];b.update({'label':p['configuration']['label'],'visits':p['visits'][lo:hi],**{k:[v for v in p[k]if lo<=v['visit']<hi]for k in ['reads','writes','PAC_models']}});blocks.append(b)
        print(json.dumps({'captured':p['configuration']['label']}),flush=True)
    deps=['recover_corefp_word_traversal.py','audit_corefp_word_traversal.py',*pins['corefp_word_traversal_checks.json']['dependencies']]
    counts={'profiles':6,'regions':len(blocks),'source_instructions':117,'source_B':468,'regional_visits':sum(len(b['visits'])for b in blocks),'regional_reads':sum(len(b['reads'])for b in blocks),'regional_read_B':sum(v['size_B']for b in blocks for v in b['reads']),'regional_writes':sum(len(b['writes'])for b in blocks),'regional_write_B':sum(v['size_B']for b in blocks for v in b['writes']),'regional_PAC_models':0,'new_queries_unsat':len(source['proofs'])}
    assert len(blocks)==18 and counts['regional_visits']==702 and counts['regional_reads']==78 and counts['regional_read_B']==600 and counts['regional_writes']==48 and counts['regional_write_B']==240 and not any(b['PAC_models']for b in blocks)
    out={'scope':__doc__,'generator_sha256':SHA(Path(__file__).read_bytes()),'thin_sha256':C.THIN_SHA,'parent_pins':PINS,'dependencies':{n:SHA(F.read(ROOT/n).encode())for n in deps},'source_regions':[{'name':n,'start':hex(lo),'end':hex(hi),'instructions':rows(lo,hi)}for n,lo,hi in SPECS],
      'seed_u32':list(map(hex,SEEDS)),'word_addends_u32':[[hex(v)for v in row]for row in ADDS],'word_load_sites':[[hex(v)for v in row]for row in LOADS],'division_sites':[[hex(v)for v in row]for row in DIVS],'source_checks':source,'blocks':blocks,'verified_counts':counts,'replay_totals':dict(totals),
      'native_target_executed':False,'native_API_executed':False,'IDB_mutated':False,'new_live_IDA_claim':False,'earlier_arithmetic_passes_universally_reduced':False,'general_raw_preparation_contract_established':False,'whole_transform_algorithm':'unknown','full_goal_complete':False}
    (ROOT/'corefp_word_selectors_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
