#!/usr/bin/env python3
"""Main-call source proofs, independent table parser and relational custody.
Linear source/journal/RAM/table work; CPU child rescans may be quadratic.
Retained host timelines sort O(J log J); SMT search separate, 30 s/query.
"""
import json,struct
from hashlib import sha256
import z3
from kext_port_tools import ROOT
from verify_daemon_reader_record_payloads_publication import read,sha
from replay_kernel_early_logging_execution import hydrate,publication_row
from replay_kernel_boot_cpu_identity import pages,get,put
from probe_rpc502_vm_handoff import decode
from lskd_values_symbolic import resize
from audit_kernel_initializer_pointer_signing import Model
from audit_kernel_initializer_pointer_signing import source_proofs as signing_proofs
from audit_kernel_early_logging_contract import source_proofs as logging_proofs
import audit_kernel_boot_logging_handoff as Prior
import recover_kernel_main_pointer_signing as R
import probe_kernel_main_pointer_signing as CPU
from replay_kernel_main_pointer_signing import Replay
P=0x6500000000;SIZE=1048576
def source_proofs(e):
 proofs=[];coverage=[];B=0x6d00000000
 def fresh():v=Model(e);v.regions=[(B,1024),(0xfffffe0007f8b528,8)];return v
 def cut(v,a,b):
  f=next(f for f in e['functions'] if int(f['start'],16)<=a<b<=int(f['end'],16));off=a-int(f['start'],16);v.e=v.c={'spans':[{'label':'cut','start':hex(a),'bytes_hex':bytes.fromhex(f['bytes'])[off:off+b-a].hex()}]};return v.enter('cut')
 def prove(label,v,bad):
  common=v.owned();counter=z3.simplify(z3.Or(*[z3.Not(x) for x in v.edge_checks],bad));s=z3.SolverFor('QF_AUFBV');s.set(timeout=30000);s.add(*common,*v.bindings_for(common));assert s.check()==z3.sat,('vacuous',label);s.add(*v.bindings_for([*common,counter]),counter);assert s.check()==z3.unsat,(label,s.reason_unknown());proofs.append({'label':label,'query':s.to_smt2(),'result':'unsat','premises_nonvacuous':True});coverage.append({'label':label,'PCs':sorted(map(hex,v.visited)),'instructions':v.count});print('proved',label,flush=True)
 pointer=z3.BitVec('MP_pointer64',64);word,count,index,size=z3.BitVecs('MP_word32 MP_count32 MP_index32 MP_size32',32)
 v=fresh();v.setmem(0xfffffe0007f8b528,8,pointer);cut(v,0xfffffe000c639a90,R.RETURN);prove('main_loads_published_header_into_actual_walker_call',v,z3.Or(v.read('x0')!=pointer,v.next!=R.S.WALK,v.read('x30')!=R.RETURN,v.read('sp')!=v.sp0))
 v=fresh();v.seed('x0',B);v.setmem(B+16,4,count);cut(v,0xfffffe000c47cce4,0xfffffe000c47ccec);prove('zero_root_command_count_returns_without_frame',v,v.next!=z3.If(count==0,resize(0xfffffe000c47ce28,64),resize(0xfffffe000c47ccec,64)))
 v=fresh();v.seed('x20',B);v.setmem(B,4,word);cut(v,0xfffffe000c47cd40,0xfffffe000c47cd4c);prove('root_segment_tag_selects_direct_signer_argument',v,v.next!=z3.If(word==0x19,resize(0xfffffe000c47cd20,64),resize(0xfffffe000c47cd4c,64)))
 v=fresh();v.seed('w8',word);v.seed('w23',0x80000035);cut(v,0xfffffe000c47cd4c,0xfffffe000c47cd54);prove('only_fileset_tag_enters_child_header_walk',v,v.next!=z3.If(word==0x80000035,resize(0xfffffe000c47cd54,64),resize(0xfffffe000c47cd28,64)))
 v=fresh();v.seed('x20',B);v.setmem(B+8,8,B+128);v.setmem(B+128+16,4,count);cut(v,0xfffffe000c47cd54,0xfffffe000c47cd60);prove('child_header_at_command_plus8_and_zero_count_gate',v,z3.Or(v.read('x24')!=B+128,v.next!=z3.If(count==0,resize(0xfffffe000c47cd28,64),resize(0xfffffe000c47cd60,64))))
 for label,pc,reg in [('direct_root',0xfffffe000c47cd20,'x20'),('fileset_child',0xfffffe000c47cd88,'x21')]:
  v=fresh();v.seed(reg,pointer);cut(v,pc,pc+8);prove(label+'_forwards_selected_segment_and_exact_return_PC',v,z3.Or(v.read('x0')!=pointer,v.next!=R.S.SIGN,v.read('x30')!=pc+8))
 v=fresh();v.seed('x19',B);v.seed('x20',B+128);v.seed('w22',index);v.setmem(B+16,4,count);v.setmem(B+132,4,size);cut(v,0xfffffe000c47cd28,0xfffffe000c47cd40);prove('root_command_step_uses_u32_size_count_and_unsigned_exit',v,z3.Or(v.read('x20')!=B+128+z3.ZeroExt(32,size),v.read('w22')!=index+1,v.next!=z3.If(z3.UGE(index+1,count),resize(0xfffffe000c47ce10,64),resize(0xfffffe000c47cd40,64))))
 v=fresh();v.seed('x25',pointer);v.seed('w8',count);cut(v,0xfffffe000c47cdd8,0xfffffe000c47cde8);prove('first_child_segment_remainder_uses_unsigned_count_minus_one',v,z3.Or(v.read('x9')!=pointer,v.read('w8')!=count-1,v.next!=z3.If(z3.ULE(count,1),resize(0xfffffe000c47cd28,64),resize(0xfffffe000c47cde8,64))))
 sp,sc=signing_proofs(e);lp,lc=logging_proofs(e);return proofs,coverage,sp,sc,lp,lc
def table_oracle(row,im):
 cache=pages(row['initial_image_pages']);checks=[]
 def raw(a,n):
  for pg in range(a&~4095,(a+n+4095)&~4095,4096):
   if pg not in cache:cache[pg]=bytearray(im.logical_page(pg))
  return get(cache,a,n)
 def commands(h):
  count=struct.unpack('<I',raw(h+16,4))[0];at=h+32
  for _ in range(count):
   kind,n=struct.unpack('<II',raw(at,8));assert n>=8;yield at,kind;at+=n
 def ok(label,p):assert p,('main_pointer_signing_contract',label);checks.append(label)
 start=row['module_walker_entry_checkpoint'];end=row['module_walker_return_checkpoint'];lo,hi=start['before_visit'],end['before_visit'];header=int(start['registers31'][0],16);segments=[];children=0
 for a,k in commands(header):
  if k==0x19:segments.append(a)
  elif k==0x80000035:
   children+=1;child=struct.unpack('<Q',raw(a+8,8))[0];segments += [a for a,k in commands(child) if k==0x19]
 expected=[];eligible=0
 for segment in segments:
  n=struct.unpack('<I',raw(segment+64,4))[0]
  for j in range(n):
   at=segment+72+80*j;kind=raw(at+64,1)[0]
   if kind not in [9,10]:continue
   eligible+=1;base,size=struct.unpack('<QQ',raw(at+32,16))
   if base:
    for q in range(size//8):
     slot=base+8*q;value=struct.unpack('<Q',raw(slot,8))[0]
     if value:expected.append({'slot':hex(slot),'value':hex(value),'segment':hex(segment),'section_index':j})
 writes=[w for w in row['source_writes'] if lo<=w['source_visit_index']<hi];stores=[w for w in writes if not P<=int(w['address'],16)<P+SIZE];pac=[v for v in row['logical_effects'] if v.get('scope')=='original_main_module_pointer_signing'];xpac=[v for v in pac if v['kind']=='xpaci'];sign=[v for v in pac if v['kind']=='pacia1716']
 ok('source_produced_header_actual_main_argument',header==R.S.HEADER and start['PC']==hex(R.S.WALK) and start['registers31'][30]==hex(R.RETURN));ok('exact_root_child_segment_entry_order',[v['argument'] for v in row['original_module_signer_entries']]==list(map(hex,segments)));ok('complete_pinned_child_segment_table_extent',children==362 and len(segments)==1845 and eligible==674 and len(expected)==6362)
 ok('one_store_strip_and_sign_per_nonzero_pointer',len(stores)==len(xpac)==len(sign)==len(expected))
 for j,(w,x,s,q) in enumerate(zip(stores,xpac,sign,expected)):
  ok('slot_'+str(j),w['address']==q['slot'] and w['size_bytes']==8 and w['after_hex']==int(q['value'],16).to_bytes(8,'little').hex());ok('PAC_'+str(j),x['X16']==q['value'] and s['X17']==q['value'] and s['X16']=='0x4a27' and x['before_visit']<s['before_visit']<w['source_visit_index'])
 sp=int(start['SP'],16);private=[w for w in writes if P<=int(w['address'],16)<P+SIZE];before,after=decode(start['private_RAM']),decode(end['private_RAM']);a,b=sp-P-96,sp-P
 ok('actual_frame_return_and_callee_saved_state',end['PC']==hex(R.RETURN) and end['SP']==start['SP'] and end['registers31'][19:30]==start['registers31'][19:30] and end['vectors']==start['vectors'] and end['system']==start['system']);ok('all_private_stores_inside_96B_callee_allocation',all(sp-96<=int(w['address'],16)<int(w['address'],16)+w['size_bytes']<=sp for w in private));ok('whole_private_RAM_outside_callee_allocation_unchanged',before[:a]==after[:a] and before[b:]==after[b:])
 for r in end['module_pointer_image_globals']:ok('whole_returned_table_interval_'+r['address'],raw(int(r['address'],16),len(bytes.fromhex(r['bytes_hex']))).hex()==r['bytes_hex'])
 ok('no_walker_result_model',all(m['pc']!=hex(R.S.WALK) for m in row['API_models']));ok('no_callback_target_invoked',not {q['value'] for q in expected}&{v['pc'] for v in row['source_visits'][lo:hi]})
 fairplay=[{'slot':q['slot'],'target':q['value'],'store_ordinal':j,'store_PC':stores[j]['pc'],'source_visit_index':stores[j]['source_visit_index']} for j,q in enumerate(expected) if 0xfffffe000846a5b0<=int(q['slot'],16)<0xfffffe000846a5e0]
 ok('six_original_FairPlay_pointer_stores',len(fairplay)==6 and [q['store_ordinal'] for q in fairplay]==list(range(3482,3488)))
 return {'checks':checks,'expected_pointer_sequence':expected,'helper_start_visit':lo,'helper_end_visit':hi,'helper_source_visits':hi-lo,'segment_calls':len(segments),'eligible_sections':eligible,'pointer_stores':len(expected),'private_writes':len(private),'private_allocation_bytes':96,'table_bytes':8*len(expected),'PAC_operand_events':len(pac),'fairplay_custody':fairplay,'module_callback_invocations':0}
def preservation(row,im):
 old=hydrate(json.loads(read(ROOT/(R.B.P+'_audit.json')))['component'],im);lo=row['module_walker_entry_checkpoint']['before_visit'];hi=row['module_walker_return_checkpoint']['before_visit'];delta=hi-lo
 def shift(v,key):return {**v,key:v[key]-(delta if v[key]>=hi else 0)}
 assert row['source_visits'][:lo]+row['source_visits'][hi:]==old['source_visits']
 for key in ['source_reads','source_writes']:assert [shift(v,'source_visit_index') for v in row[key] if not lo<=v['source_visit_index']<hi]==old[key]
 assert row['initial_private_RAM']==old['initial_private_RAM'] and row['initial_private_fixtures']==old['initial_private_fixtures'] and row['initial_image_fixtures']==old['initial_image_fixtures']
 for key in ['final_private_RAM','final_vectors','final_system','boundary']:assert row[key]==old[key]
 logical=[shift(v,'before_visit') for v in row['logical_effects'] if v.get('scope')!='original_main_module_pointer_signing'];assert logical==old['logical_effects']
 for key in ['callback_entries','callback_returns','original_image_lookup_entries','original_image_lookup_returns','original_character_calls','original_logging_entries','original_logging_returns']:assert [shift(v,'before_visit') for v in row[key]]==old[key]
 for p,h in old['final_page_sha256'].items():assert row['final_page_sha256'][p]==h
 for p in row['final_page_sha256'].keys()-old['final_page_sha256'].keys():assert row['final_page_sha256'][p]==sha256(im.logical_page(int(p,16))).hexdigest()
 memory=pages(old['initial_image_pages'])
 for w in old['source_writes']:
  if not P<=int(w['address'],16)<P+SIZE:put(memory,int(w['address'],16),w['size_bytes'],bytes.fromhex(w['after_hex']))
 for r in row['final_image_globals']:
  a=int(r['address'],16);raw=bytes.fromhex(r['bytes_hex'])
  for pg in range(a&~4095,(a+len(raw)+4095)&~4095,4096):
   if pg not in memory:memory[pg]=bytearray(im.logical_page(pg))
  assert get(memory,a,len(raw))==raw
 original=json.loads(read(ROOT/(R.S.P+'_audit.json')))['components'][0];assert row['source_visits'][lo:hi]==[{'pc':v['PC'],'bytes_hex':v['bytes_hex']} for v in original['source_visits']]
 model_changes=[];old_models=[m for m in old['API_models'] if m['pc']!=hex(R.S.WALK)]
 for a,b in zip(old_models,row['API_models']):
  b=shift(b,'before_source_visit_index');assert a['pc']==b['pc'] and a['symbol']==b['symbol'] and a['arguments8'][:7]==b['arguments8'][:7] and a['return_pc']==b['return_pc'] and a['return_value']==b['return_value']
  if a['arguments8'][7]!=b['arguments8'][7]:assert a['pc']=='0xfffffe000c620ec4' and a['arguments8'][7]=='0x91a2b3d5b25e3da' and b['arguments8'][7]=='0x91a2b3cc663a929'
  changes={k:{'prior':a[k],'new':b[k]} for k in a if a[k]!=b[k]};model_changes.append({'PC':a['pc'],'changes':changes})
 assert len(old_models)==len(row['API_models'])==2
 old_contract=Prior.oracle(old,json.loads(read(ROOT/(R.B.P+'_checks.json'))),im)
 return {'prior_audit_sha256':sha(ROOT/(R.B.P+'_audit.json')),'helper_source_visits':delta,'identical_projected_source_visits':len(old['source_visits']),'all_projected_reads_writes_exact':True,'all_old_callbacks_logging_lookup_events_exact':True,'final_private_RAM_GPR_SP_NZCV_vectors_system_exact':True,'all_prior_page_hashes_exact':len(old['final_page_sha256']),'additional_unchanged_original_pages':len(row['final_page_sha256'])-len(old['final_page_sha256']),'all_final_global_bytes_match_prior_or_unchanged_original_tables':True,'helper_instruction_sequence_equals_separate_pinned_signing_case':True,'retained_model_changes':model_changes,'prior_independent_global_formulas_rechecked':old_contract}
def audit(cached=None):
 e=json.loads(read(ROOT/(R.P+'_checks.json')));assert e==R.build();proofs,cov,sp,sc,lp,lc=source_proofs(e);im=R.B.BootImage();row=hydrate(cached,im) if cached else CPU.Probe(im).run();contract=table_oracle(row,im);kept=preservation(row,im);replay=Replay(im,row).run();negative=[]
 for label,pc in [('omit_scalar_pointer_store',0xfffffe000c656d98),('omit_unrolled_pointer_store',0xfffffe000c656e00)]:
  c=CPU.Probe(im,pc)
  for page in row['initial_image_pages']:c.ensure(int(page['address'],16),4096)
  q=c.run();keys=['configuration','entry_PC','entry_SP','entry_NZCV','entry_registers31','initial_private_RAM','initial_private_fixtures','initial_image_fixtures','initial_image_pages'];assert all(q[k]==row[k] for k in keys)
  try:table_oracle(q,im)
  except AssertionError as error:rejection=list(error.args[0])
  else:raise AssertionError(('changed_signer_accepted',label))
  assert q['boundary']['pc']==hex(R.RETURN) and q['module_walker_return_checkpoint']==row['module_walker_return_checkpoint'];negative.append({'label':label,'source_word_mutated_to_NOP':hex(pc),'original_bytes_hex':im.k.read(pc,4).hex(),'replacement_bytes_hex':'1f2003d5','all_initial_fields_match':True,'same_initial_fields':keys,'positive_original_pages_eagerly_mapped_before_control':True,'whole_walker_return_checkpoint_matches_positive':True,'boundary':q['boundary'],'source_visits':len(q['source_visits']),'oracle_rejection':rejection,'journal_sha256':sha256(json.dumps({k:q[k] for k in ['source_visits','source_reads','source_writes','logical_effects']},sort_keys=True,separators=(',',':')).encode()).hexdigest()});print('rejected',label,flush=True)
 totals={'components':1,'source_visits':len(row['source_visits']),'inserted_original_helper_visits':contract['helper_source_visits'],'preserved_projected_visits':kept['identical_projected_source_visits'],'source_reads':len(row['source_reads']),'source_writes':len(row['source_writes']),'new_source_queries_unsat':len(proofs),'retained_signing_queries_rebuilt':len(sp),'retained_logging_queries_rebuilt':len(lp),'segment_calls':contract['segment_calls'],'pointer_stores':contract['pointer_stores'],'PAC_operand_events':contract['PAC_operand_events'],'semantic_checks':len(contract['checks']),'mapped_pages':len(row['final_page_sha256']),'remaining_API_models':len(row['API_models']),'removed_API_models':1,'original_registry_callbacks_returned':len(row['callback_returns']),'character_callbacks':len(row['original_character_calls']),'source_controls':len(negative),'module_callback_invocations':0,'native_target_executions':0}
 return {'generator_sha256':sha(__file__),'probe_sha256':sha(CPU.__file__),'replay_sha256':sha(ROOT/'replay_kernel_main_pointer_signing.py'),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'scope':R.SCOPE,'source_proofs':proofs,'proof_coverage':cov,'retained_signing_proofs':sp,'retained_signing_coverage':sc,'retained_logging_proofs':lp,'retained_logging_coverage':lc,'component':publication_row(row,im),'independent_table_oracle':contract,'prior_modeled_case_comparison':kept,'negative_source_controls':negative,'independent_totals':totals,'independent_replay_totals':replay,'native_target_executed':False,'hardware_PAC_executed':False,'matched_FairPlay_transaction_established':False,'full_goal_complete':False}
if __name__=='__main__':
 a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True);print(json.dumps(a['independent_replay_totals']),flush=True)
