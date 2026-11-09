#!/usr/bin/env python3
"""Source SSA/SMT certificates for wire-to-constructor operand lineage.
No CPU emulation,target requests or IDB mutation. Fixed-width QF_BV components.
"""
import copy,json,subprocess
from recover_daemon_outer_record_ingress import ROOT,P,SCOPE,FLAGS,build
from verify_daemon_reader_record_payloads_publication import read,sha
from validate_daemon_reader_outer_lifecycle import Engine
from validate_daemon_reader_container_origins import lut
from validate_daemon_existing_scalar_reader import DECL,bv,z,neq,prefix
SOLVER='/opt/homebrew/bin/z3';PH='(concat ((_ extract 63 32) Z30) #x00006cf4)'
EXTRA=''.join(f'(declare-fun {n} () (_ BitVec {w}))\n'for n,w in [('OBJ',64),('C',64),('ELEN',32),('RESULT',32)]+[(f'H{j}',8)for j in range(10)]+[(f'P{j}',8)for j in range(8)]+[(f'HAVOC_{j}',64)for j in list(range(1,19))+[30]])
def certificates(s):
 pp=[];tr={};fs=s['fragments'];b=s['allocation_bank'];ld=lut('IL',bytes.fromhex(b['left_bytes']))+lut('IR',bytes.fromhex(b['right_bytes']))
 frame=lambda o:f'(bvadd K {bv(o)})';at=lambda ix:f'(bvadd TABLE {bv(ix*8)})'
 total='(bvxor ELEN #x8b3dc651)';tid='(concat H0 H1 H2 H3)';tag='(concat H4 H5)';pl='(concat H6 H7 H8 H9)';end=f'(bvadd O {bv(10)} {z(pl)})';kind=f'(bvxor {tag} #x11c3)';signed=f'((_ sign_extend 16) (bvadd {kind} #x0003))'
 def solve(n,body,result='unsat',note='',reused=False,source=None):
  q='(set-option :timeout 15000)\n(set-logic QF_BV)\n'+DECL+EXTRA+ld+body+'\n(check-sat)\n';v=subprocess.run([SOLVER,'-in'],input=q,text=True,capture_output=True,timeout=20);assert v.returncode==0 and not v.stderr and v.stdout.strip()==result,(n,v.stdout,v.stderr)
  pp.append({'name':n,'query':q,'result':result,'scope':SCOPE+' '+note,'reused_lemma':reused,**({'source_certificate':source}if source else{})});print(n,result,flush=True)
 def part(n,label=None,r=None,loads=None,chain=None,a=None,end=None):
  label=label or n;f=fs[n];a=a or int(f['start'],16);end=end or int(f['instructions'][-1]['ea'],16);ii=[i for i in f['instructions']if a<=int(i['ea'],16)<end];ll={};dd=[]
  for i in ii:
   if i['mnemonic']in('ldr','ldrb','ldrh','ldrsh','ldur'):
    w=8 if i['mnemonic']=='ldrb'else 16 if i['mnemonic']in('ldrh','ldrsh')else 32 if i['operands'].startswith('w')else 64;v='TABLE'if i['operands'].endswith('[sp, #0x9d8]')else PH if i['operands'].endswith('[sp, #0x9d0]')else bv(0x100e99a00)if i['operands'].endswith('[sp, #0x600]')else bv(0x100f4e390)if i['operands'].endswith('[sp, #0x5f8]')else None
    if v is None:v=label+'_L'+str(len(dd));dd.append(f'(declare-fun {v} () (_ BitVec {w}))')
    ll[i['ea']]=(v,w)
  ll.update(loads or{});rr={j:'Z'+str(j)for j in range(31)};rr['sp']='K'
  if chain:rr.update({j:chain[-1].get('x'+str(j))for j in range(31)})
  rr.update(r or{});g=Engine(rr,ll,namespace=label+'_');g.bank_sites={0x100699828:('IL',0x100e99a00),0x100699838:('IR',0x100f4e390)};g.run({'instructions':ii},end);g.declarations='\n'.join(dd)+'\n';tr[label]=g.record();return(chain or[])+[g]
 def add(n,gs,tt,cc=(),note=''):solve(n,prefix(*gs)+''.join('(assert '+c+')\n'for c in cc)+'(assert (or '+' '.join(tt)+'))',note=note)
 def rd(g,pc):return next(q for q in g.reads if q['site']==hex(pc))
 def st(g,pc,a,v):q=next(q for q in g.stores if q['site']==hex(pc));return[neq(q['address'],a),neq(q['value'],v)]
 solve('malloc_bank_all_byte_inputs','(assert (distinct (bvxor B0 (LUT_IR (bvxor (LUT_IL B0) #x6d))) #xd0))',note='Pinned original 256-byte banks. Native root pointers and stability remain premises.')
 call=part('caller',loads={'0x1006c82f0':('OBJ',64),'0x1006c82f4':('BUF',64),'0x1006c82fc':('ELEN',32)});g=call[-1]
 add('outer_object_input_length_and_return_to_parser',call,[neq(g.get('x12'),'OBJ'),neq(g.get('x10'),'BUF'),neq(g.get('w9'),'ELEN'),neq(g.get('w11'),'#x00001649'),neq(g.get('w8'),'#x00006cf4'),neq(rd(g,0x1006c830c)['address'],at(0x18bd))],note='Frame1ae8/56f8/5d4c are the prior outer object/input/encoded-length sources. Equality across the omitted route and stable frame are explicit premises.')
 ent=part('entry','entry_pre',chain=call,loads={'0x1006997bc':('CONT',64)},end=0x100699858);g=ent[-1]
 tt=[neq(g.get('x0'),bv(16)),neq(rd(g,0x10069984c)['address'],at(0xcc0d)),neq(g.get('x17'),bv(0x6aa4)),neq(rd(g,0x1006997bc)['address'],at(0x1649))]
 for pc,off,v in[(0x1006997c0,0x5ff0,'CONT'),(0x1006997c4,0x7068,'OBJ'),(0x1006997cc,0x7550,'ELEN'),(0x1006997d0,0x3818,'BUF'),(0x1006997d4,0x4d50,bv(0)),(0x1006997e0,0x1a74,'#x8b3dc651'),(0x1006997f4,0x7768,bv(0x2c220a381b62f9ab)),(0x10069983c,0x31f0,bv(0))]:tt+=st(g,pc,frame(off),v)
 add('parser_snapshots_defaults_zero_cursor_and_malloc16',ent,tt)
 r={0:'C',**{j:'HAVOC_'+str(j)for j in list(range(1,19))+[30]},**{j:g.get('x'+str(j))for j in range(19,30)}}
 post=part('entry','entry_post',chain=ent,r=r,a=0x10069985c);g=post[-1]
 add('allocation_result_and_null_return_partition',post,st(g,0x10069985c,frame(0x2ff8),'C')+[neq(rd(g,0x100699878)['address'],f'(ite (= C {bv(0)}) {at(0x70bc)} {at(0x7081)})'),neq(g.get('w6'),'#x74c29d85')],note='Only ordinary malloc ABI preservation of SP/X19-X29 is modeled; fresh volatile GPRs and arbitrary result C. No allocation is executed.')
 init=part('initialize',chain=post);g=init[-1];assert len(g.stores)==2
 add('nonnull_collection_head_tail_zero_and_loop_phase',init,[neq(g.stores[j]['address'],'C'if j==0 else f'(bvadd C {bv(8)})')for j in range(2)]+[neq(q['value'],bv(0))for q in g.stores]+[neq(g.get('w10'),'#x0000a62b'),neq(rd(g,0x1008c3898)['address'],at(0x1892))],[f'(distinct C {bv(0)})'])
 lp=part('loop',chain=init,loads={'0x1006d54f8':('O',64),'0x1006d5500':('ELEN',32)});g=lp[-1];more=f'(bvugt {z(total)} O)'
 add('loop_uses_decoded_u32_total_and_unsigned_remaining',lp,[neq(g.get('x9'),z(total)),neq(g.get('x13'),f'(bvsub {z(total)} O)'),neq(g.get('w14'),'#x00009b50'),neq(rd(g,0x1006d552c)['address'],f'(ite {more} {at(0xa633)} {at(0xa62b)})')],note='General loop cursor O; the initial source store is zero. Stable frame-reaching definitions are premises, rather than a whole-memory alias theorem.')
 ptr=part('pointer',chain=lp,loads={'0x1008cf2f4':('BUF',64)});g=ptr[-1]
 add('nonempty_input_pointer_gate_and_length_phase',ptr,[neq(g.get('w12'),'#x00001a25'),neq(g.get('w8'),'#x00000b9e'),neq(rd(g,0x1008cf314)['address'],f'(ite (= BUF {bv(0)}) {at(0x9b55)} {at(0x9b50)})'),neq(g.get('w6'),'#x74c29d88')])
 mn=part('minimum',chain=ptr);g=mn[-1];headerfit=f'(bvugt (bvsub {z(total)} O) {bv(9)})'
 add('header_requires_at_least_ten_remaining_bytes',mn,[neq(rd(g,0x10076b290)['address'],f'(ite {headerfit} {at(0x2496)} {at(0x1a25)})'),neq(g.get('w6'),'#x74c29d8f')],[more])
 le=part('length',chain=mn,loads={hex(pc):('H'+str(j+6),8)for j,pc in enumerate([0x100670470,0x100670484,0x100670490,0x1006704a8])});g=le[-1]
 tt=[neq(g.get('x12'),end),neq(g.get('x13'),f'(bvadd O {bv(10)})'),neq(rd(g,0x1006704f8)['address'],f'(ite (bvugt {end} {z(total)}) {at(0xa49f)} {at(0xa46c)})')]
 for j,pc in enumerate([0x100670470,0x100670484,0x100670490,0x1006704a8]):tt.append(neq(rd(g,pc)['address'],f'(bvadd BUF O {bv(j+6)})'))
 add('plain_BE32_extent_addresses_end_and_fit_gate',le,tt)
 hd=part('header',chain=le,loads={hex(pc):('H'+str(j),8)for j,pc in enumerate([0x10070545c,0x100705478,0x100705494,0x1007054bc,0x1007054f0,0x1007054f8])});g=hd[-1]
 tt=[neq(g.get('w19'),f'(bvxor {tid} #x8b3dc651)'),neq(g.get('w21'),f'(bvxor {pl} #x8b3dc651)'),neq(g.get('w9'),f'((_ zero_extend 16) {kind})'),neq(g.get('w16'),signed),neq(g.get('w8'),'#x00006cf4'),neq(rd(g,0x100705538)['address'],at(0x5ac3))]
 for j,pc in enumerate([0x10070545c,0x100705478,0x100705494,0x1007054bc,0x1007054f0,0x1007054f8]):tt.append(neq(rd(g,pc)['address'],f'(bvadd BUF O {bv(j)})'))
 add('plain_header_to_identifier_extent_and_constructor_kind',hd,tt,note='Universal fixed-width scalar identity,not a finite packet sample. No internal address-dependent byte mask is applied to the ingress header.')
 tp=part('type_partition',chain=hd);g=tp[-1];lower=f'(bvslt {signed} #xffff9549)'
 add('signed_type_partition_and_phase',tp,[neq(g.get('w0'),'#x00001a25'),neq(g.get('w1'),'#x00003139'),neq(rd(g,0x100842c18)['address'],f'(ite {lower} {at(0x4232)} {at(0x4291)})')])
 t32=part('type_u32',chain=tp);g=t32[-1];is32=f'(= {tag} #x9777)'
 add('lower_partition_accepts_only_u32_wire9777',t32,[neq(rd(g,0x100893ab4)['address'],f'(ite {is32} {at(0x7700)} {at(0x1a25)})')],[lower])
 upper=part('type_upper',chain=tp);g=upper[-1];hi=f'(bvsge {signed} #x0000411b)'
 add('upper_type_partition',upper,[neq(g.get('w0'),'#x00001a25'),neq(rd(g,0x100750e2c)['address'],f'(ite {hi} {at(0x313c)} {at(0x3139)})')],['(not '+lower+')'])
 t64=part('type_u64',chain=upper);g=t64[-1];is64=f'(= {tag} #x8485)'
 add('middle_partition_accepts_only_u64_wire8485',t64,[neq(rd(g,0x1007c7988)['address'],f'(ite {is64} {at(0x65fc)} {at(0x1a25)})')],['(not '+lower+')','(not '+hi+')'])
 ts=part('type_span',chain=upper);g=ts[-1];isspan=f'(= {tag} #x50db)'
 add('upper_partition_accepts_only_span_wire50db',ts,[neq(rd(g,0x1007682a8)['address'],f'(ite {isspan} {at(0x1a2b)} {at(0x1a25)})')],['(not '+lower+')',hi])
 add('complete_local_type_forest_exact_three_wire_tags',[],[neq(f'(or (and {lower} {is32}) (and (not {lower}) (not {hi}) {is64}) (and (not {lower}) {hi} {isspan}))',f'(or {is32} {is64} {isspan})')])
 e32=part('extent_u32',chain=t32);g=e32[-1]
 add('u32_exact_four_byte_extent_gate',e32,[neq(g.get('w8'),'#x00000b9e'),neq(rd(g,0x1009b66f8)['address'],f'(ite (= {pl} #x00000004) {at(0xca49)} {at(0xa49f)})')],[is32])
 e64=part('extent_u64',chain=t64);g=e64[-1]
 add('u64_exact_eight_byte_extent_gate',e64,[neq(g.get('w8'),'#x00000b9e'),neq(rd(g,0x100778c04)['address'],f'(ite (= {pl} #x00000008) {at(0x3124)} {at(0x1a25)})')],[is64])
 values={}
 for label,pre,pcs,n,off,const,site,branch in [('u32',e32,[0x1007079c4,0x1007079d0,0x1007079dc,0x100707a08],4,0x1a74,'#x8b3dc651',0x100707a5c,0x100707a64),('u64',e64,[0x100838b54,0x100838b5c,0x100838b7c,0x100838b84,0x100838b8c,0x100838bb4,0x100838bdc,0x100838c4c],8,0x7768,'#x2c220a381b62f9ab',0x100838cc4,0x100838cf4)]:
  path=part('read_'+label,chain=pre,loads={hex(pc):('P'+str(j),8)for j,pc in enumerate(pcs)});g=path[-1];v='(bvxor (concat '+' '.join('P'+str(j)for j in range(n))+') '+const+')';values[label]=v
  tt=st(g,site,frame(off),v)+[neq(g.get('w8'),'#x00006cf4'),neq(rd(g,branch)['address'],at(0x8868))]
  for j,pc in enumerate(pcs):tt.append(neq(rd(g,pc)['address'],f'(bvadd BUF O {bv(j+10)})'))
  cc=[is32,f'(= {pl} #x00000004)']if label=='u32'else[is64,f'(= {pl} #x00000008)']
  add(label+'_plain_payload_to_raw_constructor_operand',path,tt,cc)
  adv=part('advance',label+'_advance',chain=path);g=adv[-1]
  add(label+'_cursor_commits_end_before_generic_constructor',adv,st(g,0x1008f0cb8,frame(0x4d50),end)+[neq(rd(g,0x1008f0cc0)['address'],at(0x3eff))],cc)
  raw32=v if label=='u32'else'VALUE';raw64=v if label=='u64'else'V'
  gen=part('generic',label+'_generic',chain=adv,loads={'0x10097b9b4':('C',64),'0x10097b9b8':(raw32,32),'0x10097b9bc':(raw64,64),'0x10097b9c0':('U',64)});g=gen[-1]
  add(label+'_actual_generic_constructor_arguments',gen,[neq(g.get('w11'),'#x00000228'),neq(rd(g,0x10097b9d4)['address'],at(0x5eb2)),neq(g.get('x0'),'C'),neq(g.get('w19'),f'(bvxor {tid} #x8b3dc651)'),neq(g.get('w9'),f'((_ zero_extend 16) {kind})'),neq(g.get('w21'),f'(bvxor {pl} #x8b3dc651)'),neq(g.get('w10'),raw32),neq(g.get('x12'),raw64),neq(g.get('x20'),'U')],cc,note='Named loads replay proven stores under stable frame/constructor side-effect premises. Unused typed/scalar/span fields remain arbitrary and may contain values from earlier records; entry defaults are not assumed across the loop.')
 sp=part('span',chain=ts);g=sp[-1];zeroid=f'(= {tid} #x00000000)'
 add('span_borrows_payload_advances_and_tests_zero_identifier',sp,st(g,0x1008c038c,frame(0x31f0),f'(bvadd BUF O {bv(10)})')+st(g,0x1008c0390,frame(0x4d50),end)+[neq(g.get('w8'),'#x00006cf4'),neq(rd(g,0x1008c03b8)['address'],f'(ite {zeroid} {at(0x3f49)} {at(0x3eff)})')],[isspan])
 gen=part('generic','span_generic',chain=sp,loads={'0x10097b9b4':('C',64),'0x10097b9b8':('VALUE',32),'0x10097b9bc':('V',64),'0x10097b9c0':(f'(bvadd BUF O {bv(10)})',64)});g=gen[-1]
 add('nonzero_ID_span_supplies_actual_generic_constructor',gen,[neq(g.get('w11'),'#x00000228'),neq(rd(g,0x10097b9d4)['address'],at(0x5eb2)),neq(g.get('x0'),'C'),neq(g.get('x20'),f'(bvadd BUF O {bv(10)})'),neq(g.get('w19'),f'(bvxor {tid} #x8b3dc651)'),neq(g.get('w21'),f'(bvxor {pl} #x8b3dc651)'),neq(g.get('w9'),'#x00004118')],[isspan,'(not '+zeroid+')'],note='Scalar staging cells are unused inputs for the span constructor. Their current values are arbitrary; not inferred to remain at defaults.')
 sent=part('sentinel',chain=sp);g=sent[-1]
 add('zero_ID_span_stops_without_constructing_record',sent,st(g,0x1007481d0,frame(0x850c),'#x8b3dc651')+[neq(g.get('w6'),'#x8b3dc651'),neq(g.get('w8'),'#x00006cf4'),neq(rd(g,0x1007481d8)['address'],at(0x3b30))],[isspan,zeroid],note='No requirement that payload length is zero or cursor equals total. This is an accepted local terminator contract,not a malformed-input or vulnerability claim.')
 gr=part('generic_return',r={6:z('RESULT')});g=gr[-1]
 add('constructor_success_restores_loop_phase_other_statuses_drain',gr,[neq(g.get('w10'),'#x0000a62b'),neq(g.get('w8'),'#x00000b9e'),neq(rd(g,0x10084d620)['address'],f'(ite (= RESULT #x8b3dc651) {at(0x8784)} {at(0x1a25)})')],note='Normal saved continuation228; prior constructor contract supplies ordinary return. Full allocation/append/replacement/retirement is not re-proved here.')
 ex=part('exhausted',chain=lp);g=ex[-1]
 add('cursor_exhaustion_reports_success_then_publishes',ex,st(g,0x1006c47d0,frame(0x850c),'#x8b3dc651')+[neq(g.get('w6'),'#x8b3dc651'),neq(g.get('w8'),'#x00006cf4'),neq(rd(g,0x1006c47d8)['address'],at(0x3b30))],['(not '+more+')'])
 pub=part('publish',chain=ex,loads={'0x100758ae8':('C',64),'0x100758aec':('OBJ',64)});g=pub[-1]
 add('local_collection_published_to_outer_first_child',pub,st(g,0x100758af0,'OBJ','C')+[neq(rd(g,0x100758b1c)['address'],at(0x188e)),neq(g.get('w6'),'#x8b3dc651')],note='OUTcell=OBJ establishes write toOBJ+0,under the saved-cell identity premise. Pointer publication has no Mach emission.')
 spub=part('publish','sentinel_publish',chain=sent,loads={'0x100758ae8':('C',64),'0x100758aec':('OBJ',64)});g=spub[-1]
 add('zero_ID_span_also_publishes_same_collection_and_success',spub,st(g,0x100758af0,'OBJ','C')+[neq(rd(g,0x100758b1c)['address'],at(0x188e)),neq(g.get('w6'),'#x8b3dc651')],[isspan,zeroid])
 rt=part('return',chain=pub,loads={'0x1008c8b80':('CONT',64)});g=rt[-1]
 add('parser_returns_through_saved_outer_continuation',rt,[neq(g.get('x8'),'CONT'),neq(g.get('x17'),bv(0xfc72)),neq(rd(g,0x1008c8b80)['address'],frame(0x5ff0))])
 outer=part('outer_return',r={6:z('RESULT')});g=outer[-1]
 add('outer_exact_success_continues_other_parser_statuses_error',outer,[neq(rd(g,0x1008b3abc)['address'],f'(ite (= RESULT #x8b3dc651) {at(0xc6db)} {at(0x445a)})')])
 err=part('error',r={8:bv(0xb9e),6:z('RESULT')},loads={'0x1008f046c':('C',64)});g=err[-1]
 add('parse_error_saves_raw_status_and_borrowed_collection_cell',err,st(g,0x1008f0468,frame(0x850c),'RESULT')+st(g,0x1008f0470,frame(0x1548),'C')+[neq(g.get('x19'),frame(0x1548)),neq(g.get('w24'),'#x00006cf4'),neq(rd(g,0x1008f0480)['address'],at(0x3ad1))])
 # Byte-index bounds use integer-sized zero-extensions; no native pointer mapping is inferred.
 inloop=f'(bvult O {z(total)})';fit=f'(bvule {end} {z(total)})'
 add('successful_header_extent_cannot_wrap_cursor_u64',[],[f'(bvult {end} O)',f'(bvugt {end} {bv(0x200000008)})'],[inloop],note='u32 total bounds cursor below2^32;u32 payload makes end<2^33+9 even before fit.')
 add('accepted_record_advances_at_least_ten_and_is_u32_bounded',[],[f'(bvult {end} (bvadd O {bv(10)}))',f'(bvugt {end} {bv(0xffffffff)})',f'(bvugt {z(pl)} {bv(0xfffffff5)})'],[inloop,fit])
 add('all_ten_header_byte_offsets_inside_total',[],[f'(bvuge (bvadd O {bv(j)}) {z(total)})'for j in range(10)],[inloop,headerfit])
 solve('reject_exhaustion_only_success_interpretation',f'(assert {isspan})\n(assert {zeroid})\n(assert {inloop})\n(assert {headerfit})\n(assert {fit})\n(assert (bvult {end} {z(total)}))','sat',note='Abstract source state admits a zero-ID span terminator before total exhaustion. No target packet or execution is generated.')
 reused=[];old=json.loads(read(ROOT/'daemon_constructor_callers_checks.json'))
 for q in old['proofs']:
  if q['name']in{'generic_constructor_root_frame_operands','generic_caller_status_frontiers','generic_error_status_and_collection_cell_relay'}:reused.append((q,'daemon_constructor_callers_checks.json'))
 assert len(reused)==3
 for q,fn in reused:
  assert q['result']=='unsat';v=subprocess.run([SOLVER,'-in'],input=q['query'],text=True,capture_output=True,timeout=20);assert v.returncode==0 and not v.stderr and v.stdout.strip()=='unsat';pp.append({**q,'name':'replay_'+q['name'],'reused_lemma':True,'source_certificate':fn})
 return pp,tr,[]
def verify(s):return s==build()
def alterations(s):
 ops=[('wrong_header_length',lambda t:t['fragments']['length']['instructions'][15].__setitem__('operands','x12, x11, #7')),('wrong_wire_type',lambda t:t['fragments']['header']['instructions'][66].__setitem__('operands','w16, #0')),('missing_span_termination',lambda t:t['fragments'].pop('sentinel')),('wrong_malloc_bank',lambda t:t['allocation_bank'].__setitem__('key','0')),('wrong_output_slot',lambda t:t['pointer_records'][0]['fixup'].__setitem__('target',0)),('invent_native_join',lambda t:t.__setitem__('native_target_executed',True))];out=[]
 for n,op in ops:t=copy.deepcopy(s);op(t);assert t!=s;out.append({'name':n,'rejected_by_fresh_source_comparison':True})
 return out
def main():
 s=json.loads(read(ROOT/(P+'_source.json')));assert verify(s);pp,tr,_=certificates(s);sites={pc for q in tr.values()for pc in q['source_sites']};expected={i['ea']for f in s['fragments'].values()for i in f['instructions']if i['mnemonic']not in('braa','blraa')};assert sites==expected,(expected-sites,sites-expected)
 aa=alterations(s);counts={**s['verified_source_counts'],'new_queries_unsat':sum(q['result']=='unsat'and not q['reused_lemma']for q in pp),'reused_queries_unsat':sum(q['result']=='unsat'and q['reused_lemma']for q in pp),'counterexamples_sat':sum(q['result']=='sat'for q in pp),'distinct_translated_instruction_sites':len(sites),'translated_instruction_instances':sum(len(q['source_sites'])for q in tr.values()),'SSA_definitions':sum(q['SSA_definitions']for q in tr.values()),'rejected_alterations':len(aa)}
 c={'generator_sha256':sha(__file__),'static_scope':SCOPE,'dependencies':{P+'_source.json':sha(ROOT/(P+'_source.json')),'validate_daemon_reader_outer_lifecycle.py':sha(ROOT/'validate_daemon_reader_outer_lifecycle.py')},'proofs':pp,'translations':tr,'alterations':aa,'verified_counts':counts,'solver':{'path':SOLVER,'sha256':sha(SOLVER)},'source_recapture_match':True,'all_checks_pass':True,'wire_to_constructor_operands_proved':True,'complete_parser_proved':False,**{k:False for k in FLAGS}}
 (ROOT/(P+'_checks.json')).write_text(json.dumps(c,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
