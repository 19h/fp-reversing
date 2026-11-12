#!/usr/bin/env python3
"""Word-header index/address contracts and original recurrence-input producers.

Typed private reads, master control and normal-flow premises remain explicit.
O(C*(B+V*J+P*F+R)) replay time/space; 30 s/SMT query.
No native target/API/IPC or IDB operation.
"""
import json
from pathlib import Path
from collections import Counter
import z3
import recover_corefp_word_recurrence as R
ROOT=R.ROOT;C=R.C;S=C.Pointers();F=R.F;SHA=R.SHA;M32=R.M32;MASK=R.MASK
SPECS=[('first_setup',0x1b47cc,0x1b489c),('first_head',0x1b48a0,0x1b4900),('first_tail_setup',0x1b4d74,0x1b4e98),('first_tail',0x1b4e9c,0x1b4efc),
 ('copy_a',0x1b51d4,0x1b51d8),('control_seed',0x1b54d0,0x1b54e0),('second_meta',0x1b55b0,0x1b55e0),('second_setup',0x1b5620,0x1b56d4),
 ('second_head',0x1b56d8,0x1b5738),('second_tail_setup',0x1b5c40,0x1b5d1c),('second_tail',0x1b5d20,0x1b5d84)]
HEADERS={'first_head':{'counter':9,'base':23,'bias':0x37a981c3,'kind':0,'word':28},'first_tail':{'counter':20,'base':23,'bias':0x37a981c3,'kind':1,'word':3},
 'second_head':{'counter':1,'base':25,'bias':0x20390963,'kind':2,'word':3},'second_tail':{'counter':16,'base':25,'bias':0x20390963,'kind':3,'word':3}}
PINS={**R.PINS,'corefp_word_recurrence_checks.json':'561769cd0f59a45dc0f07d7a9912453b7bfbf1ab05402be98a40776f37c8a3e8',
 'corefp_word_recurrence_audit.json':'ef828966d89deda9f6c5559e313f6dd45e3b1d1351d9ec6fd5031e2dafbfacac'}
RESETS=[(0x1b4924,0x1b492c,0x37a981c3),(0x1b5040,0x1b5048,0x37a981c3),(0x1b58bc,0x1b58c4,0x20390963),(0x1b5f9c,0x1b5fa4,0x20390963)]
COUNTERS=[(0x1b4d44,0x1b4d6c,9,9),(0x1b51c8,0x1b51cc,20,20),(0x1b5c10,0x1b5c38,1,1),(0x1b63d0,0x1b63d4,16,16)]


class Lift(R.Lift):
    def execute(self,instructions):
        for i in instructions:
            if i.mnemonic=='orr':
                o=i.operands;n=i.reg_name(o[0].reg);bits=32 if n.startswith('w')else 64;self.put(n,self.value(i,o[1],bits)|self.value(i,o[2],bits))
            else:super().execute([i])
        return self


def control_chain(master):
    k=(master^0x7d45)&M32;w11=(k-1)&M32;t=(10*(w11^0x82d1))&M32;ctrl=((t+0x32f291f3)&M32)&0xcd0d6df7;seed=(ctrl+0x864e)&M32
    one=((seed+0x5ce82c08)&M32)&0xa3177c8d;s=one^0xc579;two=((s+0x46ae3c8e)&M32)&0xb9515fbf
    return k,w11,t,ctrl,seed,one,two


def source_checks(parent):
    qs=[];sp=z3.BitVec('input_SP',64);word=z3.BitVec('input_word64',64);control=z3.BitVec('input_control32',32);table=z3.BitVec('input_table64',64);target=z3.BitVec('input_target64',64);base=z3.BitVec('input_buffer64',64)
    def regs():return {j:z3.BitVec('input_X'+str(j),64)for j in range(31)}
    def instructions(name):_,lo,hi=next(s for s in SPECS if s[0]==name);return list(C.CS.disasm(S.read(lo,hi-lo),lo))
    for name,d in HEADERS.items():
        r=regs();r[29]=sp+0x520;r[d['counter']]=z3.ZeroExt(32,control);r[d['base']]=base;r[21]=z3.BitVecVal(d['bias'],64);index=z3.ZeroExt(32,control-d['bias']);reads=[]
        def load(at,n,i):
            if n==4:assert name=='second_tail';want=sp+0x450;value=z3.BitVec('header_limit32',32)
            else:assert n==8;want=base+(index<<3);value=word
            F.P.prove(qs,name+'_load_address_'+hex(i.address),at==want);reads.append(hex(i.address));return value
        out=Lift(r,sp,load).execute(instructions(name));m=R.MODELS[d['kind']]
        F.P.prove(qs,name+'_coherent_indexes_and_word',z3.And(*[out.rr('x'+str(k))+R.offset(m,j)==index for j,k in enumerate(m['idx'])],out.rr('x'+str(d['word']))==word))
        assert len(reads)==(2 if name=='second_tail'else 1)and not out.stores
    master=z3.BitVec('master_W22',32);r=regs();r[22]=z3.ZeroExt(32,master);r[29]=sp+0x520;initial=r.copy();loaded=z3.BitVec('setup_stack32',32);reads=[]
    def first_read(at,n,i):assert n==4;F.P.prove(qs,'first_setup_read_address',at==sp+0x340);reads.append(at);return loaded
    first=Lift(r,sp,first_read).execute(instructions('first_setup'));fixed={**{int(k):int(v,16)for k,v in parent['source_checks']['metadata_by_body_u64'][0].items()},12:R.H0,19:R.H0,24:R.A,25:R.B,21:0x37a981c3,9:0x37a981c3}
    F.P.prove(qs,'first_setup_constants_and_key_control',z3.And(*[first.rr('x'+str(k))==v for k,v in fixed.items()],first.rr('x8')==z3.ZeroExt(32,master^0x7d45)))
    wanted=[(0x50,loaded^3),(0x58,z3.LShR(z3.Extract(31,0,initial[27]),8)),(0x438,z3.Extract(31,0,initial[7])),(0x90,z3.LShR(z3.Extract(31,0,initial[7]),16)),(0x104,z3.LShR(z3.Extract(31,0,initial[26]),16)),(0xec,z3.LShR(z3.Extract(31,0,initial[26]),8))]
    F.P.prove(qs,'first_setup_six_u32_stores',z3.And(*[z3.And(at==sp+off,value==v)for (at,value),(off,v)in zip(first.stores,wanted)]));assert len(first.stores)==6 and len(reads)==1
    k=z3.BitVec('first_key_control32',32);r=regs();r[8]=z3.ZeroExt(32,k);r[29]=sp+0x520;initial=r.copy();vals=[z3.BitVec('first_limit32',32),table,target];addresses=[sp+0x458,sp+0x488,table+(z3.ZeroExt(32,k)<<3)];seen=[]
    def tail_read(at,n,i):j=len(seen);assert n==[4,8,8][j];F.P.prove(qs,'first_tail_setup_load_'+str(j),at==addresses[j]);seen.append(at);return vals[j]
    tail=Lift(r,sp,tail_read).execute(instructions('first_tail_setup'));t=z3.ZeroExt(32,10*((k-1)^0x82d1));fixed={int(j):int(v,16)for j,v in parent['source_checks']['metadata_by_body_u64'][1].items()if j!='16'}
    F.P.prove(qs,'first_tail_setup_metadata_control_store',z3.And(tail.rr('w11')==k-1,tail.rr('x16')==t+0xb8442f8ce72af7a5,*[tail.rr('x'+str(j))==v for j,v in fixed.items()],tail.rr('x7')==target,tail.stores[0][0]==sp+0x348,tail.stores[0][1]==t));assert len(tail.stores)==1 and len(seen)==3
    F.P.prove(qs,'first_tail_setup_preserves_word_state',z3.And(*[tail.rr('x'+str(j))==initial[j]for j in [1,5,6,19,20,21,23,24,25]]))
    r=regs();r[10]=z3.ZeroExt(32,control);seed=Lift(r,sp).execute(instructions('control_seed'));F.P.prove(qs,'second_control_seed',z3.And(seed.rr('w13')==control+0x864e,seed.rr('w16')==control+0x218e))
    meta=Lift(regs(),sp).execute(instructions('second_meta'));F.P.prove(qs,'second_head_literal_metadata',z3.And(*[meta.rr('x'+str(j))==v for j,v in {8:0x9532dd4efb419fe8,10:0x868010333d95b2cc,11:0x3076d59e,21:0x20390963}.items()]))
    r=regs();r[13]=z3.ZeroExt(32,control);r[29]=sp+0x520;initial=r.copy();seen=[];vals=[table,target,base];addresses=[sp+0x488,table+(z3.SignExt(32,z3.Extract(31,0,r[16]))<<3),sp+0x468]
    def second_read(at,n,i):j=len(seen);assert n==8;F.P.prove(qs,'second_setup_load_'+str(j),at==addresses[j]);seen.append(at);return vals[j]
    second=Lift(r,sp,second_read).execute(instructions('second_setup'));g=z3.ZeroExt(32,(control+0x5ce82c08)&0xa3177c8d)
    F.P.prove(qs,'second_setup_metadata_and_store',z3.And(second.rr('x24')==g+0x1912e4b015aa7516,second.rr('x20')==0x1532dd4e00000000,second.rr('w23')==R.B,second.rr('w1')==0x20390963,second.rr('x25')==base,second.stores[0][0]==sp+0x410,second.stores[0][1]==g));assert len(seen)==3 and len(second.stores)==1
    F.P.prove(qs,'second_setup_preserves_word_state',z3.And(*[second.rr('x'+str(j))==initial[j]for j in [6,12,13,14,15,28]]))
    c1=z3.BitVec('second_slot_control64',64);r=regs();r[29]=sp+0x520;initial=r.copy();seen=[];vals=[c1,z3.BitVec('second_limit32',32),table,target];addresses=[sp+0x410,sp+0x458,sp+0x488,table+(z3.SignExt(32,z3.Extract(31,0,c1))<<3)]
    def last_read(at,n,i):j=len(seen);assert n==[8,4,8,8][j];F.P.prove(qs,'second_tail_setup_load_'+str(j),at==addresses[j]);seen.append(at);return vals[j]
    last=Lift(r,sp,last_read).execute(instructions('second_tail_setup'));s=z3.Extract(31,0,c1)^0xc579;g2=z3.ZeroExt(32,(s+0x46ae3c8e)&0xb9515fbf);wanted=[(0x450,z3.Extract(31,0,c1)^0x1b64aff0),(0x458,s),(0x410,g2)]
    F.P.prove(qs,'second_tail_setup_metadata_and_stores',z3.And(last.rr('x24')==0x0fa973f3ac5bfc00,last.rr('x27')==0x68c613f41a12cb00,last.rr('x8')==g2+0x86aa3caf87653ad1,*[z3.And(at==sp+off,value==v)for (at,value),(off,v)in zip(last.stores,wanted)]));assert len(last.stores)==3 and len(seen)==4
    F.P.prove(qs,'second_tail_setup_preserves_word_state',z3.And(*[last.rr('x'+str(j))==initial[j]for j in [6,12,14,15,16,21,23,25,28]]))
    r=regs();copy=Lift(r,sp).execute(instructions('copy_a'));F.P.prove(qs,'second_a_copied_from_first',copy.rr('x28')==r[24])
    chain=control_chain(master);k,w11,t,ctrl,seed,one,two=chain
    F.P.prove(qs,'master_f82c_all_control_metadata',z3.And(*[v==n for v,n in zip(chain,[0x8569,0x8568,0x4d3a,0x4d25,0xd373,0x7c09,0x55be])],z3.ZeroExt(32,t)+0xb8442f8ce72af7a5==0xb8442f8ce72b44df,z3.ZeroExt(32,one)+0x1912e4b015aa7516==0x1912e4b015aaf11f,z3.ZeroExt(32,two)+0x86aa3caf87653ad1==0x86aa3caf8765908f),[master==0xf82c])
    for lo,hi,bias in RESETS:
        state=Lift(regs(),sp).execute(list(C.CS.disasm(S.read(lo,hi-lo),lo)));F.P.prove(qs,'threshold_reset_'+hex(lo),state.rr('x21')==bias)
    for lo,hi,src,dst in COUNTERS:
        r=regs();r[src]=z3.ZeroExt(32,control);r[29]=sp+0x520
        state=Lift(r,sp,lambda at,n,i:z3.BitVec('counter_read_'+hex(i.address),8*n)).execute(list(C.CS.disasm(S.read(lo,hi-lo),lo)));F.P.prove(qs,'counter_increment_'+hex(lo),state.rr('x'+str(dst))==z3.ZeroExt(32,control+1))
    for bias in [0x37a981c3,0x20390963]:
        i=control-bias;next_i=(control+1)-bias;F.P.prove(qs,'decoded_counter_successor_'+hex(bias),z3.ZeroExt(32,next_i)==z3.ZeroExt(32,i)+1,[z3.ULT(i,0xffffffff)])
    return {'proofs':qs,'control_chain_retained_u32':list(map(hex,control_chain(0xf82c))),'scope':'arbitrary header counter/base/word with declared threshold; arbitrary setup controls and typed reads; fixed metadata composition under initial W22=0xf82c'}


def census():
    contracts=[('initial_h',0x1b4808,0x1b56d8,[12]),('first_a',0x1b47f8,0x1b51d4,[24]),('second_a',0x1b51d8,0x1b63e4,[28]),('first_b',0x1b4828,0x1b51d4,[25]),('second_b',0x1b56d0,0x1b63e4,[23]),
      ('first_codec_key',0x1b47e8,0x1b4d74,[8]),('first_scan_control',0x1b536c,0x1b54d0,[10]),('second_control_seed',0x1b54e0,0x1b5694,[13]),
      ('first_head_metadata',0x1b48a0,0x1b4d74,[0,7,11,13,14,16]),('first_tail_metadata',0x1b4e9c,0x1b51d4,[0,8,13,14,15,16,27,28,30]),('second_head_metadata',0x1b56d8,0x1b5c40,[8,10,20,24,28,23]),('second_tail_metadata',0x1b5d20,0x1b63e4,[8,24,27,28,23]),
      ('first_head_threshold',0x1b492c,0x1b4e9c,[21]),('first_tail_threshold',0x1b5048,0x1b51d4,[21]),('second_head_threshold',0x1b58c4,0x1b5d20,[21]),('second_tail_threshold',0x1b5fa4,0x1b63e4,[21])]
    rows=[]
    for name,lo,hi,regs in contracts:
        ins=list(C.CS.disasm(S.read(lo,hi-lo),lo));names={n+str(j)for j in regs for n in ['w','x']};branches=[]
        for i in ins:
            rr,ww=i.regs_access();assert not names&{i.reg_name(j)for j in ww}and not any(i.group(g)for g in [2,3])
            if i.group(1):assert i.mnemonic=='braa';branches.append(hex(i.address))
        rows.append({'name':name,'start':hex(lo),'end':hex(hi),'preserved_registers':regs,'instruction_count':len(ins),'branch_sites':branches})
    return {'start':'0x1b47e8','end':'0x1b63e4','instructions':F.P.source_rows(0x1b47e8,0x1b63e4),'contracts':rows,
      'scope':'structural writer-free intervals; preservation requires the executed path to use only the declared instructions until the next named interface; target-set/native-exception admission remains separate'}


class Capture(R.Capture):
    def __init__(self,*a):super().__init__(*a);self.input_components=[];self.active_input=None
    def code(self,u,pc,n,d):
        self.flush()
        for name,lo,hi in SPECS:
            if pc==C.BASE+lo:assert self.active_input is None;self.active_input={'name':name,'entry':F.P.A.capture(self)}
            if pc==C.BASE+hi and self.active_input is not None and self.active_input['name']==name:
                self.active_input['end']=F.P.A.capture(self);self.input_components.append(self.active_input);self.active_input=None
        return super().code(u,pc,n,d)


def main():
    pins={}
    for n,h in PINS.items():
        raw=F.P.read(ROOT/n).encode();assert SHA(raw)==h;pins[n]=json.loads(raw)
    rec=pins['corefp_word_recurrence_checks.json'];parent=pins['corefp_workspace_checks.json'];qs=source_checks(rec);preservation=census();blocks=[];totals=Counter();joins=[]
    print(json.dumps({'queries_unsat':len(qs['proofs'])}),flush=True)
    for p in parent['profiles']:
        r=Capture(p,parent['source_spans'],S);totals.update(r.run());assert r.active_input is None
        for b in r.input_components:
            lo,hi=b['entry']['source_visit'],b['end']['source_visit'];name,start,end=next(v for v in SPECS if v[0]==b['name']);assert hi-lo==(end-start)//4
            b.update({'label':p['configuration']['label'],'visits':p['visits'][lo:hi],**{k:[v for v in p[k]if lo<=v['visit']<hi]for k in ['reads','writes','PAC_models']}});blocks.append(b)
        joins.append({'label':p['configuration']['label'],'master_W22':r.input_components[0]['entry']['CPU']['X31'][22],'control_chain_u32':qs['control_chain_retained_u32']});assert int(joins[-1]['master_W22'],16)&M32==0xf82c;print(json.dumps({'captured':p['configuration']['label']}),flush=True)
    deps=['recover_corefp_word_recurrence.py','audit_corefp_word_recurrence.py',*rec['dependencies']]
    counts={'profiles':6,'regions':74,'source_instructions':339,'source_B':1356,'regional_visits':2226,'regional_reads':104,'regional_writes':66,'regional_PAC_models':0,'census_instructions':1791,'census_B':7164,'preservation_contracts':16,'new_queries_unsat':len(qs['proofs'])}
    assert len(blocks)==74 and sum(len(b['visits'])for b in blocks)==2226 and sum(len(b['reads'])for b in blocks)==104 and sum(len(b['writes'])for b in blocks)==66 and not any(b['PAC_models']for b in blocks)
    out={'scope':__doc__,'generator_sha256':SHA(Path(__file__).read_bytes()),'thin_sha256':C.THIN_SHA,'parent_pins':PINS,'dependencies':{n:SHA(F.P.read(ROOT/n).encode())for n in deps},
      'source_regions':[{'name':n,'start':hex(lo),'end':hex(hi),'instructions':F.P.source_rows(lo,hi)}for n,lo,hi in SPECS],
      'threshold_resets':[{'start':hex(lo),'end':hex(hi),'bias_u32':hex(b),'instructions':F.P.source_rows(lo,hi)}for lo,hi,b in RESETS],
      'counter_regions':[{'start':hex(lo),'end':hex(hi),'input':src,'output':dst,'instructions':F.P.source_rows(lo,hi)}for lo,hi,src,dst in COUNTERS],
      'source_checks':qs,'census':preservation,'blocks':blocks,'joins':joins,'verified_counts':counts,'replay_totals':dict(totals),'native_target_executed':False,'native_API_executed':False,'IDB_mutated':False,'new_live_IDA_claim':False,
      'earlier_arithmetic_passes_universally_reduced':False,'general_raw_preparation_contract_established':False,'whole_transform_algorithm':'unknown','full_goal_complete':False}
    (ROOT/'corefp_word_inputs_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
