#!/usr/bin/env python3
"""Entry-record to word-control/base lineage under typed source interfaces.

Original private frames, normal-flow and stack-epoch premises remain explicit.
O(C*(B+V*J+P*F+R)) replay time/space; 30 s/SMT query.
No native target/API/IPC or IDB operation.
"""
import json
from pathlib import Path
from collections import Counter
import z3
import recover_corefp_word_inputs as W
ROOT=W.ROOT;C=W.C;S=C.Pointers();SHA=W.SHA;M32=2**32-1;M64=2**64-1
SPECS=[('record_decode',0x1af7dc,0x1af874),('buffer_cache',0x1af8fc,0x1af90c),('control_first_store',0x1afc1c,0x1afc44),
 ('control_first_reload',0x1afd94,0x1afd98),('control_subtract',0x1afdb0,0x1afdc0),('control_mask',0x1afe3c,0x1afe54),('control_multiply',0x1afe9c,0x1afebc),
 ('control_second_store',0x1aff88,0x1aff8c),('master_store',0x1b0270,0x1b0290),('master_reload',0x1b41a0,0x1b41a4),('first_base',0x1b4618,0x1b461c),('second_base',0x1b56c4,0x1b56c8)]
AUX=[('forward_argument',0x1af940,0x1af94c),('forward_literals',0x1af970,0x1af980),('forward_update',0x1afa60,0x1afa68)]
CONTRACTS=[('operation_before_direction',0x1af81c,0x1af92c,[9]),('operation_reverse',0x1afaa4,0x1afc1c,[9]),('forward_argument',0x1af94c,0x1afa60,[14]),
 ('forward_literal_counter',0x1af980,0x1afa60,[9]),('forward_literal_mask',0x1af980,0x1afa64,[15]),('decoded_buffer',0x1af860,0x1af908,[25]),
 ('first_control_reload',0x1afd98,0x1afdbc,[10]),('subtracted_control',0x1afdc0,0x1afe3c,[9]),('masked_control',0x1afe54,0x1afe9c,[8]),('multiplied_control',0x1afebc,0x1aff88,[12]),
 ('master_loaded',0x1b41a4,0x1b47cc,[22]),('first_buffer_loaded',0x1b461c,0x1b48a0,[23]),('second_buffer_loaded',0x1b56c8,0x1b56d8,[25]),
 ('first_buffer_loop',0x1b48a0,0x1b51d4,[23]),('second_buffer_loop',0x1b56d8,0x1b63e4,[25])]
PINS={**W.PINS,'corefp_word_inputs_checks.json':'58779662b64b33c6bc97f9014e1f59c49319d8e4d80c2310304c79e2db69f562',
 'corefp_word_inputs_audit.json':'89d8acdb397c8d2d0dd3ab246e8eecf47b719ab612f11fb159392c8163678ae1'}


def key(record):return ((record&M32)^0x542fbf9b)*0x4386951d&M32

def chain(operation):
    first=(operation^0x92b7)&M32;sub=(first-0x40fe)&M32;masked=((sub+0x7a57526e)&M32)&0x85a87fd8
    product=(((masked-0x3484)&M32)^0x4ac6)*0x6322&M32;master=((product+0xc244327b)&M32)&0x3dbbff6c
    return first,sub,masked,product,master


def rows(lo,hi):return [{'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),'instruction':i.mnemonic+' '+i.op_str}for i in C.CS.disasm(S.read(lo,hi-lo),lo)]


def source_checks():
    qs=[];prove=W.F.P.prove;sp=z3.BitVec('lineage_SP64',64);record=z3.BitVec('lineage_record64',64);raw_op=z3.BitVec('lineage_raw_operation32',32)
    raw_buffer=z3.BitVec('lineage_raw_buffer64',64);source=z3.BitVec('lineage_source64',64);raw_length=z3.BitVec('lineage_raw_length32',32)
    def regs():r={j:z3.BitVec('lineage_X'+str(j),64)for j in range(31)};r[29]=sp+0x520;return r
    def ins(name):_,lo,hi=next(v for v in SPECS+AUX if v[0]==name);return list(C.CS.disasm(S.read(lo,hi-lo),lo))
    r=regs();r[0]=record;values=[raw_op,raw_buffer,source,raw_length];offsets=[0xc,0x18,0x20,0x28];seen=[]
    def load(at,n,i):
        j=len(seen);assert n==[4,8,8,4][j];prove(qs,'record_load_'+str(j),at==record+offsets[j]);seen.append((at,n));return values[j]
    state=W.Lift(r,sp,load);instructions=ins('record_decode');state.execute([i for i in instructions if i.address<0x1af814]);k=(z3.Extract(31,0,record)^0x542fbf9b)*0x4386951d
    prove(qs,'record_source_key',state.rr('w8')==k);state.put('w8',k);state.execute([i for i in instructions if i.address>=0x1af814]);decoded=raw_op^k;buffer=raw_buffer+0xe4106ba853ce6c9e
    prove(qs,'record_decoded_fields_and_direction',z3.And(state.rr('w9')==decoded,state.rr('x1')==raw_buffer,state.rr('x10')==source,state.rr('x25')==buffer,
      state.rr('w8')==raw_length^k,state.rr('w14')==decoded|z3.If(z3.UGT(source,buffer),z3.BitVecVal(0x12,32),z3.BitVecVal(0,32))))
    assert len(state.stores)==2 and len(seen)==4
    prove(qs,'record_stack_store_widths_and_values',z3.And(state.stores[0][0]==sp+0x430,state.stores[0][1]==raw_length^k,state.stores[1][0]==sp+0x450,state.stores[1][1]==raw_buffer))
    r=regs();initial=r.copy();table_value=z3.BitVec('lineage_cache_companion64',64);seen=[]
    def load_cache(at,n,i):assert n==8;prove(qs,'buffer_cache_companion_load',at==initial[19]+0xe750);seen.append(at);return table_value
    cache=W.Lift(r,sp,load_cache).execute(ins('buffer_cache'));assert len(cache.stores)==2 and len(seen)==1
    prove(qs,'buffer_cache_two_u64_stores',z3.And(cache.stores[0][0]==sp+0x460,cache.stores[0][1]==table_value,cache.stores[1][0]==sp+0x468,cache.stores[1][1]==initial[25]))
    operation=z3.BitVec('lineage_operation32',32);first,sub,masked,product,master=chain(operation)
    for name,input_reg,value,output_reg,wanted in [('control_first_store',9,operation,10,first),('control_subtract',10,first,9,sub),('control_mask',9,sub,8,masked),('control_multiply',8,masked,12,product)]:
        r=regs();r[input_reg]=z3.ZeroExt(32,value);out=W.Lift(r,sp).execute(ins(name));claim=out.rr('w'+str(output_reg))==wanted
        if name=='control_first_store':assert len(out.stores)==1;claim=z3.And(claim,out.stores[0][0]==sp+0x438,out.stores[0][1]==z3.ZeroExt(32,first))
        else:assert not out.stores
        prove(qs,name+'_source_contract',claim)
    for name,width,offset,dest in [('control_first_reload',8,0x438,10),('master_reload',4,0x348,22),('first_base',8,0x468,23),('second_base',8,0x468,25)]:
        value=z3.BitVec(name+'_loaded',width*8);seen=[]
        def load_slot(at,n,i):assert n==width;prove(qs,name+'_address',at==sp+offset);seen.append(at);return value
        state=W.Lift(regs(),sp,load_slot).execute(ins(name));assert len(seen)==1 and not state.stores
        prove(qs,name+'_loaded_value',state.rr('x'+str(dest))==z3.ZeroExt(64-width*8,value))
    r=regs();r[12]=z3.ZeroExt(32,product);state=W.Lift(r,sp).execute(ins('control_second_store'));assert len(state.stores)==1
    prove(qs,'second_control_store_u32',z3.And(state.stores[0][0]==sp+0x438,state.stores[0][1]==product))
    seen=[]
    def load_master(at,n,i):assert n==4;prove(qs,'master_source_load_address',at==sp+0x438);seen.append(at);return product
    state=W.Lift(regs(),sp,load_master).execute(ins('master_store'));assert len(state.stores)==1 and len(seen)==1
    prove(qs,'master_source_store_u32',z3.And(state.stores[0][0]==sp+0x348,state.stores[0][1]==master))
    prove(qs,'selected_operation_to_master',z3.And(*[v==n for v,n in zip([first,sub,masked,product,master],chain(0x7f48))],master==0xf82c),[operation==0x7f48])
    r=regs();r[9]=z3.ZeroExt(32,operation);arg=W.Lift(r,sp).execute(ins('forward_argument'));prove(qs,'forward_argument_source',arg.rr('w14')==operation-0x4442)
    lit=W.Lift(regs(),sp).execute(ins('forward_literals'));prove(qs,'forward_literals_source',z3.And(lit.rr('x9')==0x189444c9,lit.rr('x15')==0xe76bff78))
    r=regs();r[14]=z3.ZeroExt(32,operation-0x4442);r[9]=lit.rr('x9');r[15]=lit.rr('x15');out=W.Lift(r,sp).execute(ins('forward_update'));f=((operation-0x4442)+0x189444c9)&0xe76bff78
    prove(qs,'forward_operation_update',out.rr('w9')==f);prove(qs,'selected_forward_fixed_point',f==operation,[operation==0x7f48])
    return {'proofs':qs,'selected_operation_u32':'0x7f48','control_chain_u32':list(map(hex,chain(0x7f48))),
      'normalization_cut':{'pc':'0x1af814','register':'W8','identity':'record_source_key','replacement':'(low32(record) XOR 0x542fbf9b)*0x4386951d mod 2^32'},
      'scope':'typed record/stack/companion reads; arbitrary decoded operation; fixed master composition under operation=0x7f48; forward source update fixed point is separate from dispatch admission'}


def census():
    unique={};contracts=[]
    for name,lo,hi,registers in CONTRACTS:
        ins=list(C.CS.disasm(S.read(lo,hi-lo),lo));names={prefix+str(j)for j in registers for prefix in ['w','x']};branches=[]
        for i in ins:
            _,ww=i.regs_access();assert not names&{i.reg_name(j)for j in ww}and not any(i.group(g)for g in [2,3]),(name,hex(i.address))
            if i.group(1):assert i.mnemonic=='braa';branches.append(hex(i.address))
        for row in rows(lo,hi):unique[int(row['pc'],16)]=row
        contracts.append({'name':name,'start':hex(lo),'end':hex(hi),'preserved_registers':registers,'instruction_count':len(ins),'branch_sites':branches})
    return {'instructions':[unique[k]for k in sorted(unique)],'contracts':contracts,'scope':'writer-free admitted paths; the operation corridor excludes the forward rewrite and treats it with separate source contracts; arbitrary target sets/native exceptions remain unknown'}


class Capture(W.Capture):
    def __init__(self,*a):super().__init__(*a);self.lineage_components=[];self.active_lineage=None
    def code(self,u,pc,n,d):
        self.flush()
        for name,lo,hi in SPECS:
            if pc==C.BASE+lo:assert self.active_lineage is None;self.active_lineage={'name':name,'entry':W.F.P.A.capture(self)}
            if pc==C.BASE+hi and self.active_lineage is not None and self.active_lineage['name']==name:
                self.active_lineage['end']=W.F.P.A.capture(self);self.lineage_components.append(self.active_lineage);self.active_lineage=None
        return super().code(u,pc,n,d)


def main():
    pins={}
    for name,h in PINS.items():
        raw=W.F.P.read(ROOT/name).encode();assert SHA(raw)==h;pins[name]=json.loads(raw)
    source=source_checks();preserved=census();parent=pins['corefp_workspace_checks.json'];blocks=[];totals=Counter()
    print(json.dumps({'queries_unsat':len(source['proofs'])}),flush=True)
    for p in parent['profiles']:
        r=Capture(p,parent['source_spans'],S);totals.update(r.run());assert r.active_lineage is None and len(r.lineage_components)==12
        for b in r.lineage_components:
            lo,hi=b['entry']['source_visit'],b['end']['source_visit'];_,start,end=next(v for v in SPECS if v[0]==b['name']);assert hi-lo==(end-start)//4
            b.update({'label':p['configuration']['label'],'visits':p['visits'][lo:hi],**{k:[v for v in p[k]if lo<=v['visit']<hi]for k in ['reads','writes','PAC_models']}});blocks.append(b)
        print(json.dumps({'captured':p['configuration']['label']}),flush=True)
    deps=['recover_corefp_word_inputs.py','audit_corefp_word_inputs.py',*pins['corefp_word_inputs_checks.json']['dependencies']]
    unique={int(v['pc'],16)for region in [*[{'instructions':rows(lo,hi)}for _,lo,hi in SPECS+AUX],preserved]for v in region['instructions']}
    counts={'profiles':6,'regions':72,'primary_source_instructions':83,'primary_source_B':332,'auxiliary_source_instructions':9,'auxiliary_source_B':36,'regional_visits':498,
      'regional_reads':sum(len(b['reads'])for b in blocks),'regional_writes':sum(len(b['writes'])for b in blocks),'regional_PAC_models':0,'preservation_contracts':15,
      'census_instructions':len(preserved['instructions']),'census_B':4*len(preserved['instructions']),'unique_source_instructions':len(unique),'unique_source_B':4*len(unique),'new_queries_unsat':len(source['proofs'])}
    assert counts['regional_reads']==60 and counts['regional_writes']==42 and sum(len(b['visits'])for b in blocks)==498 and not any(b['PAC_models']for b in blocks)
    out={'scope':__doc__,'generator_sha256':SHA(Path(__file__).read_bytes()),'thin_sha256':C.THIN_SHA,'parent_pins':PINS,'dependencies':{n:SHA(W.F.P.read(ROOT/n).encode())for n in deps},
      'source_regions':[{'name':n,'start':hex(lo),'end':hex(hi),'instructions':rows(lo,hi)}for n,lo,hi in SPECS],
      'auxiliary_regions':[{'name':n,'start':hex(lo),'end':hex(hi),'instructions':rows(lo,hi)}for n,lo,hi in AUX],'source_checks':source,'census':preserved,'blocks':blocks,'verified_counts':counts,'replay_totals':dict(totals),
      'native_target_executed':False,'native_API_executed':False,'IDB_mutated':False,'new_live_IDA_claim':False,'earlier_arithmetic_passes_universally_reduced':False,
      'general_raw_preparation_contract_established':False,'whole_transform_algorithm':'unknown','full_goal_complete':False}
    (ROOT/'corefp_input_lineage_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
