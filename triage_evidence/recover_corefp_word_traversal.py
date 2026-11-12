#!/usr/bin/env python3
"""Word-loop cyclic predicates, bounded selector encodings and target rows.

Typed remainder/count/backing/PAC interfaces remain explicit.
O(C*(B+V*J+P*F+R)) replay time/space; 30 s/SMT query.
No native target/API/IPC or IDB operation.
"""
import json
from pathlib import Path
from collections import Counter
import z3
import recover_corefp_input_lineage as R
ROOT=R.ROOT;C=R.C;S=C.Pointers();SHA=R.SHA;M=2**32-1;MOD=2**64;TABLE=0x1c81940
SPECS=[('table_cache',0x1af8b0,0x1af8c4),('word_count',0x1b45dc,0x1b45f4),('first_bound',0x1b46c0,0x1b4738),('first_key',0x1b47d0,0x1b47d4),
 ('first_lower',0x1b4828,0x1b4838),('first_delta',0x1b4880,0x1b488c),('first_header',0x1b48a0,0x1b48a8),('first_dispatch',0x1b4d24,0x1b4d70),
 ('first_tail_bound',0x1b4d74,0x1b4de4),('first_tail_delta',0x1b4e8c,0x1b4e94),('first_tail_header',0x1b4e9c,0x1b4ea4),('first_tail_dispatch',0x1b5190,0x1b51d0),
 ('second_bound_encode',0x1b55a4,0x1b55f0),('second_bound_decode',0x1b5620,0x1b567c),('second_header',0x1b56d8,0x1b56e0),('second_dispatch',0x1b5be8,0x1b5c3c),
 ('second_tail_bound',0x1b5c64,0x1b5cdc),('second_tail_header',0x1b5d20,0x1b5d2c),('second_tail_dispatch',0x1b636c,0x1b63e0)]
CONFIG=[{'name':'first','header':'first_header','dispatch':'first_dispatch','counter':9,'next':9,'target':26,'index':9,'lo':4,'hi':10,'delta':22,'bias':0x37a981c3,'lower':0x7390ff4b,'step':0x3be77d89,'scale':0x6c,'key':0xf82c,'invert':True,'branch':0x1b4d70,'modifier':0x2883},
 {'name':'first_tail','header':'first_tail_header','dispatch':'first_tail_dispatch','counter':20,'next':20,'target':2,'index':17,'lo':10,'hi':9,'delta':4,'bias':0x37a981c3,'lower':0x722872e2,'step':0x3a7ef120,'scale':1,'key':0x8568,'invert':False,'branch':0x1b51d0,'modifier':0x5e63},
 {'name':'second','header':'second_header','dispatch':'second_dispatch','counter':1,'next':1,'target':2,'index':17,'lo':11,'hi':7,'delta':None,'bias':0x20390963,'lower':0x3076d59e,'step':0x103dcc3c,'scale':0xbd,'key':0xd373,'invert':False,'branch':0x1b5c3c,'modifier':0xe8d0},
 {'name':'second_tail','header':'second_tail_header','dispatch':'second_tail_dispatch','counter':16,'next':16,'target':2,'index':12,'lo':None,'hi':11,'delta':None,'bias':0x20390963,'lower':0x1b64d3f9,'step':0xfb2bca97,'scale':0xe4,'key':0xb970,'invert':False,'branch':0x1b63e0,'modifier':0xf3d5}]
CONTRACTS=[('first_predicate',0x1b48a8,0x1b4d24,[2,3,4,9,10,17,22]),('first_tail_predicate',0x1b4ea4,0x1b5190,[4,9,10,11,17,20]),
 ('second_predicate',0x1b56e0,0x1b5be8,[1,7,11,13,17]),('second_tail_predicate',0x1b5d2c,0x1b636c,[11,16,17]),
 ('first_bound',0x1b4738,0x1b48a0,[10]),('first_tail_bound',0x1b4de4,0x1b4e9c,[9,10,11]),('second_encoded_bound',0x1b55f0,0x1b5620,[17]),
 ('second_lower',0x1b55e0,0x1b56d8,[11]),('second_bound',0x1b567c,0x1b56d8,[7]),('second_tail_bound',0x1b5cdc,0x1b5d20,[11])]
ROWS=[('first_initial',0xc644,0x1b48a0,0x774e),('first_continue',0xf82c,0x1b48a0,0x2883),('first_exit',0xf840,0x1b4d74,0x2883),
 ('first_tail_initial',0x8569,0x1b4e9c,0x5e63),('first_tail_continue',0x8569,0x1b4e9c,0x5e63),('first_tail_exit',0x8568,0x1b51d4,0x5e63),
 ('second_initial',0x6eb3,0x1b56d8,0xb144),('second_continue',0xd3ce,0x1b56d8,0xe8d0),('second_exit',0xd373,0x1b5c40,0xe8d0),
 ('second_tail_initial',0x7c09,0x1b5d20,0x6ff1),('second_tail_continue',0xb994,0x1b5d20,0xf3d5),('second_tail_exit',0xb970,0x1b63e4,0xf3d5)]
PINS={**R.PINS,'corefp_input_lineage_checks.json':'067707e91f1811a94a89e73a96ffbd54dafb6c4b8c4d0bd29933b0bdafeee3b2',
 'corefp_input_lineage_audit.json':'3ed4b338a5dd56853c213ee4168928cd093e4281e41fe5e013efaf7cbbdd2098'}


def instructions(name):_,lo,hi=next(v for v in SPECS if v[0]==name);return list(C.CS.disasm(S.read(lo,hi-lo),lo))
def rows(lo,hi):return R.rows(lo,hi)
def inside(x,lo,hi):return z3.ULT(x-lo,hi-lo)


def proofs():
    qs=[];prove=R.W.F.P.prove;sp=z3.BitVec('traversal_SP64',64);r=z3.BitVec('selector_remainder32',32);n=z3.BitVec('word_count32',32);encoded=z3.BitVec('encoded_count32',32)
    def regs():v={j:z3.BitVec('traversal_X'+str(j),64)for j in range(31)};v[29]=sp+0x520;return v
    reads=[]
    def count_load(at,k,i):assert k==4;prove(qs,'count_load_address',at==sp+0x3ec);reads.append(at);return encoded
    count=R.W.Lift(regs(),sp,count_load).execute(instructions('word_count'));N=z3.LShR(encoded,3)^0x08b1c7cb
    prove(qs,'count_decode_and_store',z3.And(count.rr('x1')==z3.ZeroExt(32,N),count.stores[0][0]==sp+0x458,count.stores[0][1]==z3.LShR(encoded,3)));assert len(reads)==len(count.stores)==1
    prove(qs,'count_is_29bit',z3.ULE(N,0x1fffffff));prove(qs,'count_from_encoded_byte_length',(z3.LShR(n^0x458e3e59,3)^0x08b1c7cb)==z3.LShR(n,3))
    rr=regs();rr[10]=z3.ZeroExt(32,r);first=R.W.Lift(rr,sp).execute(instructions('first_bound'));first_out=first.rr('w10')
    prove(qs,'first_bound_29bit_remainder',first_out==r+0x7390ff4b,[z3.ULE(r,0x1fffffff)])
    rr=regs();rr[14]=z3.ZeroExt(32,r);second=R.W.Lift(rr,sp).execute(instructions('second_bound_encode'));second.execute(instructions('second_bound_decode'));second_out=second.rr('w7')
    prove(qs,'second_bound_29bit_remainder',z3.And(second_out==r+0x3076d59e,second.rr('w11')==0x3076d59e),[z3.ULE(r,0x1fffffff)])
    outside=[]
    for name,out,base in [('first_bound',first_out,0x7390ff4b),('second_bound',second_out,0x3076d59e)]:
        q=z3.Solver();q.set(timeout=30000);q.add(out!=r+base);assert q.check()==z3.sat;model=q.model();v=model.eval(r).as_long();assert v>0x1fffffff
        outside.append({'name':name,'remainder_u32':hex(v),'actual_upper_u32':hex(model.eval(out).as_long()),'candidate_upper_u32':hex((v+base)&M),'outside_count_domain':True,'query':q.to_smt2(),'result':'sat'})
    slot=n^0x08b1c7cb
    rr=regs();rr[8]=z3.BitVecVal(0x8569,64);seen=[]
    def first_tail_load(at,k,i):assert k==4;prove(qs,'first_tail_count_slot',at==sp+0x458);seen.append(at);return slot
    tail=R.W.Lift(rr,sp,first_tail_load).execute(instructions('first_tail_bound'));assert len(seen)==1
    prove(qs,'first_tail_bounds',z3.And(tail.rr('w9')==n+0x722872e2,tail.rr('w10')==0x722872e2,tail.rr('w11')==0x8568))
    seen=[]
    def last_load(at,k,i):j=len(seen);prove(qs,'second_tail_slot_'+str(j),at==sp+(0x410 if j==0 else 0x458));assert k==[8,4][j];seen.append(at);return z3.BitVecVal(0x7c09,64)if j==0 else slot
    last=R.W.Lift(regs(),sp,last_load).execute(instructions('second_tail_bound'));assert len(seen)==2 and len(last.stores)==1
    prove(qs,'second_tail_bounds',z3.And(last.rr('w11')==n+0x1b64d3f9,last.stores[0][0]==sp+0x450,last.stores[0][1]==0x1b64d3f9))
    first_params=R.W.Lift(regs(),sp).execute(instructions('first_lower')+instructions('first_delta'));prove(qs,'first_branch_literals',z3.And(first_params.rr('w4')==0x7390ff4b,first_params.rr('w21')==0x37a981c3,first_params.rr('w22')==0x3be77d89,first_params.rr('w3')==0x6c))
    rr=regs();start=rr[22];copy=R.W.Lift(rr,sp).execute(instructions('first_key'));prove(qs,'first_branch_key_copy',copy.rr('x2')==start)
    tail_delta=R.W.Lift(regs(),sp).execute(instructions('first_tail_delta'));prove(qs,'first_tail_delta',tail_delta.rr('w4')==0x3a7ef120)
    table=z3.BitVec('dispatch_table64',64);target=z3.BitVec('dispatch_target64',64);counter=z3.BitVec('encoded_counter32',32);lo=z3.BitVec('interval_lower32',32);hi=z3.BitVec('interval_upper32',32)
    for d in CONFIG:
        lower=z3.BitVecVal(d['lower'],32)if d['lo']is None else lo;rr=regs();rr[d['counter']]=z3.ZeroExt(32,counter);rr[d['hi']]=z3.ZeroExt(32,hi)
        if d['lo']is not None:rr[d['lo']]=z3.ZeroExt(32,lower)
        if d['delta']is not None:rr[d['delta']]=z3.BitVecVal(d['step'],64)
        if d['name']=='first':rr[2]=z3.BitVecVal(d['key'],64);rr[3]=z3.BitVecVal(d['scale'],64)
        if d['name']=='first_tail':rr[11]=z3.BitVecVal(d['key'],64)
        if d['name']=='second':rr[13]=z3.BitVecVal(d['key'],64)
        def header_read(at,k,i):assert d['name']=='second_tail'and k==4;prove(qs,'second_tail_header_lower_address',at==sp+0x450);return lower
        state=R.W.Lift(rr,sp,header_read).execute(instructions(d['header']));flag=state.rr('w17');prove(qs,d['name']+'_header_wrap_flag',flag==z3.If(z3.ULT(hi,lower),z3.BitVecVal(1,32),z3.BitVecVal(0,32)))
        membership=inside(counter+d['step'],lower,hi);bit=z3.If(z3.Not(membership)if d['invert']else membership,z3.BitVecVal(1,32),z3.BitVecVal(0,32));index=(bit*d['scale'])^d['key'];seen=[]
        def dispatch_read(at,k,i):
            j=len(seen);seen.append((at,k))
            if k==4:assert d['name']=='second_tail'and j==0;prove(qs,'second_tail_dispatch_key_address',at==sp+0x458);return z3.BitVecVal(d['key'],32)
            assert k==8;part=j-(d['name']=='second_tail');prove(qs,d['name']+'_dispatch_load_'+str(part),at==(sp+0x488 if part==0 else table+(z3.ZeroExt(32,index)<<3)));return table if part==0 else target
        state.read_hook=dispatch_read;state.execute(instructions(d['dispatch']));assert len(seen)==(3 if d['name']=='second_tail'else 2)and not state.stores
        prove(qs,d['name']+'_cyclic_dispatch_and_successor',z3.And(state.rr('x'+str(d['target']))==target,state.rr('x'+str(d['next']))==z3.ZeroExt(32,counter+1)))
        i=z3.BitVec(d['name']+'_index32',32);bound=z3.BitVec(d['name']+'_bound32',32);base=z3.BitVecVal(d['lower'],32)
        prove(qs,d['name']+'_decoded_bound_test',inside((i+d['bias'])+d['step'],base,base+bound)==z3.ULT(i+1,bound),[z3.ULE(i,0x1fffffff),z3.ULE(bound,0x1fffffff)])
    lo64=z3.BitVec('projection_dividend64',64);q64=z3.BitVec('projection_quotient64',64);nn=z3.BitVec('projection_divisor32',32)
    prove(qs,'u32_msub_projects_u64_remainder',z3.Extract(31,0,lo64)-z3.Extract(31,0,q64)*nn==z3.Extract(31,0,lo64-q64*z3.ZeroExt(32,nn)))
    prove(qs,'nonempty_head_tail_split',z3.And(z3.UGE(z3.If(r==0,z3.BitVecVal(1,32),r),1),z3.ULT(z3.If(r==0,z3.BitVecVal(1,32),r),n)),[z3.UGE(n,2),z3.ULE(n,0x1fffffff),z3.ULT(r,n)])
    return {'proofs':qs,'outside_domain_controls':outside,'scope':'u32 cyclic predicates; 29-bit remainder encodings; selected operation-derived branch keys; typed dispatch/count/remainder/backing interfaces; no native admission claim'}


def census():
    unique={};contracts=[]
    for name,lo,hi,rr in CONTRACTS:
        ins=list(C.CS.disasm(S.read(lo,hi-lo),lo));names={p+str(j)for j in rr for p in ['w','x']};branches=[]
        for i in ins:
            _,ww=i.regs_access();ww=[]if i.mnemonic in ['cmp','tst','ccmp']else ww;assert not names&{i.reg_name(j)for j in ww}and not any(i.group(g)for g in [2,3]),(name,hex(i.address))
            if i.group(1):assert i.mnemonic=='braa';branches.append(hex(i.address))
        for row in rows(lo,hi):unique[int(row['pc'],16)]=row
        contracts.append({'name':name,'start':hex(lo),'end':hex(hi),'preserved_registers':rr,'instruction_count':len(ins),'branch_sites':branches})
    return {'instructions':[unique[k]for k in sorted(unique)],'contracts':contracts,'scope':'writer-free source corridors; normal-flow/native-exception premise remains explicit'}


class Capture(R.Capture):
    def __init__(self,*a):super().__init__(*a);self.traversal_components=[];self.active_traversal=None
    def code(self,u,pc,n,d):
        self.flush()
        for name,lo,hi in SPECS:
            if pc==C.BASE+lo:assert self.active_traversal is None;self.active_traversal={'name':name,'entry':R.W.F.P.A.capture(self)}
            if pc==C.BASE+hi and self.active_traversal is not None and self.active_traversal['name']==name:
                self.active_traversal['end']=R.W.F.P.A.capture(self);self.traversal_components.append(self.active_traversal);self.active_traversal=None
        return super().code(u,pc,n,d)


def main():
    pins={}
    for name,h in PINS.items():raw=R.W.F.P.read(ROOT/name).encode();assert SHA(raw)==h;pins[name]=json.loads(raw)
    source=proofs();preserved=census();target_rows=[]
    for name,index,target,diversity in ROWS:
        row=S.decoded[TABLE+8*index];assert row['target']==hex(target)and row['diversity']==hex(diversity)and row['authenticated']and row['key']=='IA'and not row['address_diversity']and row['chain_membership_verified'];target_rows.append({'name':name,'index_u32':hex(index),'row':row})
    parent=pins['corefp_workspace_checks.json'];blocks=[];totals=Counter();print(json.dumps({'queries_unsat':len(source['proofs'])}),flush=True)
    for p in parent['profiles']:
        r=Capture(p,parent['source_spans'],S);totals.update(r.run());assert r.active_traversal is None
        for b in r.traversal_components:
            lo,hi=b['entry']['source_visit'],b['end']['source_visit'];_,start,end=next(v for v in SPECS if v[0]==b['name']);assert hi-lo==(end-start)//4
            b.update({'label':p['configuration']['label'],'visits':p['visits'][lo:hi],**{k:[v for v in p[k]if lo<=v['visit']<hi]for k in ['reads','writes','PAC_models']}});blocks.append(b)
        print(json.dumps({'captured':p['configuration']['label']}),flush=True)
    deps=['recover_corefp_input_lineage.py','audit_corefp_input_lineage.py',*pins['corefp_input_lineage_checks.json']['dependencies']]
    unique={int(row['pc'],16)for region in [*[{'instructions':rows(lo,hi)}for _,lo,hi in SPECS],preserved]for row in region['instructions']}
    counts={'profiles':6,'regions':len(blocks),'source_instructions':sum((hi-lo)//4 for _,lo,hi in SPECS),'source_B':sum(hi-lo for _,lo,hi in SPECS),'regional_visits':sum(len(b['visits'])for b in blocks),
      'regional_reads':sum(len(b['reads'])for b in blocks),'regional_writes':sum(len(b['writes'])for b in blocks),'regional_PAC_models':0,'preservation_contracts':len(CONTRACTS),
      'census_instructions':len(preserved['instructions']),'census_B':4*len(preserved['instructions']),'unique_source_instructions':len(unique),'unique_source_B':4*len(unique),'logical_target_rows':12,'distinct_target_rows':11,'new_queries_unsat':len(source['proofs'])}
    assert len(blocks)==130 and counts['source_instructions']==245 and counts['regional_visits']==1634 and counts['regional_reads']==106 and counts['regional_writes']==18 and not any(b['PAC_models']for b in blocks)
    out={'scope':__doc__,'generator_sha256':SHA(Path(__file__).read_bytes()),'thin_sha256':C.THIN_SHA,'parent_pins':PINS,'dependencies':{n:SHA(R.W.F.P.read(ROOT/n).encode())for n in deps},
      'source_regions':[{'name':name,'start':hex(lo),'end':hex(hi),'instructions':rows(lo,hi)}for name,lo,hi in SPECS],'remainder_interfaces':[{'start':hex(lo),'end':hex(hi),'instructions':rows(lo,hi)}for lo,hi in [(0x1b46b4,0x1b46c0),(0x1b559c,0x1b55a4)]],
      'table_cache_origin_row':S.decoded[0x1d108e8],'target_rows':target_rows,'source_checks':source,'census':preserved,'blocks':blocks,'verified_counts':counts,'replay_totals':dict(totals),
      'native_target_executed':False,'native_API_executed':False,'IDB_mutated':False,'new_live_IDA_claim':False,'earlier_arithmetic_passes_universally_reduced':False,
      'general_raw_preparation_contract_established':False,'whole_transform_algorithm':'unknown','full_goal_complete':False}
    (ROOT/'corefp_word_traversal_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
