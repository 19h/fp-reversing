#!/usr/bin/env python3
"""Rebuild exhaustion/schema-key receipts and verify exact publication custody.
Linear owned-byte/journal/corpus work; source SMT search cost is separate.
"""
import json
from hashlib import sha256
from compression import zstd
import z3
from kext_port_tools import ROOT,SOURCE
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_daemon_payload_mix_publication import BASE,git,hygiene,path_hygiene
from verify_daemon_second_mix_publication import canonical_expression
from verify_kernel_magazine_bootstrap_delivery import nested_hygiene
import recover_userclient_early_schema as R
import audit_userclient_early_schema as A
PREVIOUS='259b80e120113f048750f92fbbfa99471cb93aa4'
BASELINE_SHA='e552cffce76e35a7323a4fcc15769f5ccce42b13f86e4100b59f3badb27e7355'
CHECKS_SHA='3bc245c5e60310a11bfa695d1a5f4587391778f88622d6b35ea9ad74b8da3cf4'
AUDIT_SHA='c5e7a1556d6ea45ba01a97b14ed4cf8ffbd659dc87931e443ae390ed89286d2d'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'interface_investigation_status.md','interface_abi_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','userclient_early_publication_report.md','userclient_fpttlv_entry_report.md','userclient_command_dispatch_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'userclient_early_schema_report.md','triage_evidence/recover_userclient_early_schema.py','triage_evidence/audit_userclient_early_schema.py','triage_evidence/verify_userclient_early_schema_delivery.py','triage_evidence/userclient_early_schema_checks.json','triage_evidence/userclient_early_schema_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/userclient_early_schema_checks.json','triage_evidence/userclient_early_schema_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'new_source_spans':16,'new_captured_words':139,'original_table_pointers':39,'predecessor_states':30,'additional_source_cells_per_state':9,'ADID_packets':12,'ADID_containment_levels':4,'requested_raw_key32':0xfa834112}
TOTALS={'new_source_queries_unsat':13,'prior_publication_queries_unsat':4,'lifted_instruction_instances':9070,'new_source_words_covered':139,'predecessor_bound_partial_state_evaluations':30,'additional_prefix_cells_reconstructed':270,'post_schema_fields_checked':390,'unbound_controller_premise_queries_unsat':30,'negative_source_controls':3,'missing_cells_assigned_concrete_values':0,'schema_source_stores_per_case':10,'ADID_packets_independently_parsed':12,'ADID_field_record_bytes_per_packet':14,'ADID_containment_levels':4}
def equivalent_queries(left,right):
 x,y=z3.parse_smt2_string(left),z3.parse_smt2_string(right)
 assert len(x)==len(y)>0 and all(canonical_expression(i)==canonical_expression(j)for i,j in zip(x,y))
def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')));assert e==R.build();fresh=A.audit(e);x,y=dict(a),dict(fresh)
 old,new=x.pop('source_proofs'),y.pop('source_proofs');assert len(old)==len(new)==13
 for p,q in zip(old,new):
  p,q=dict(p),dict(q);equivalent_queries(p.pop('query'),q.pop('query'));assert p==q and p['premises_nonvacuous']and p['result']=='unsat'
 controls,rebuilt=x.pop('negative_source_controls'),y.pop('negative_source_controls');assert len(controls)==len(rebuilt)==3
 for p,q in zip(controls,rebuilt):
  p,q=dict(p),dict(q);equivalent_queries(p.pop('satisfiable_violation_query'),q.pop('satisfiable_violation_query'));assert p==q and p['normal_oracle_rejected']and not p['native_target_executed']
 assert [p['mutated_PC']for p in controls]==['0xfffffe000a660b70','0xfffffe000a635960','0xfffffe000a63670c']
 assert [p['stop_boundary']for p in controls]==['before_entering_schema_helper','before_following_changed_action_branch','before_entering_schema_helper']
 assert x==y and e['verified_counts']==a['verified_counts']==COUNTS and a['independent_totals']==TOTALS
 assert len(a['rechecked_prior_publication_proofs'])==4 and all(p['result']=='unsat'for p in a['rechecked_prior_publication_proofs'])
 assert len(a['partial_state_evaluations'])==30 and all(p['all_checks_pass']and p['all_storage_branch_and_lookup_premises_checked']and p['missing_cells_bound_to_concrete_values']==0 and not p['continuous_guest_extended']and p['requested_raw_key32']=='0xfa834112'for p in a['partial_state_evaluations'])
 assert sum(p['post_schema_fields_checked']for p in a['partial_state_evaluations'])==390 and sum(p['unbound_controller_premise_queries_unsat']for p in a['partial_state_evaluations'])==30
 assert sum(p['lifted_instruction_instances']for p in old)==9070
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 assert e['kernel_collection_sha256']==a['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 assert len(e['source']['spans'])==16 and sum(len(s['instructions'])for s in e['source']['spans'])==139 and len(e['source']['branch_pointers'])==39
 assert next(q for q in e['source']['branch_pointers']if q['index']==0x7f)['target']=='0xfffffe000a661c34'
 assert len(e['predecessor_states'])==30 and all(p['stopped_boundary']['pc']=='0xfffffe000a654ae4'and p['stopped_boundary']['kind']=='before_undefined_private_value_load'for p in e['predecessor_states'])
 assert sum(len(p['additional_source_defined_cells'])for p in e['predecessor_states'])==270
 for row in e['predecessor_states']:
  assert len(row['additional_source_defined_cells'])==9
  for cell in row['additional_source_defined_cells']:assert cell['overlapping_source_stores']and len(bytes.fromhex(cell['reconstructed_bytes_hex']))==cell['size_bytes']
 adid=e['adid_evidence'];assert adid['thin_sha256']=='ad149b360cbd98c1cb6d1ce820125e944bcaaf1758c2633d2588e159cfc15fcf'and adid['uuid']=='4d24325f-3529-39b1-bbf8-64bbcf406049'and not adid['new_native_callback_executed']
 assert len(adid['packets'])==12
 for p in adid['packets']:
  assert p['packet_sha256']=='fb8563f814c1534bf411f71cba2ee7ce87e5fb8aeb4b5e1016e258b9fca7eda8'and p['packet_size_bytes']==320 and p['field_record_hex']=='fa83411297770000000400000000'and p['raw_scalar32']==0
  path=p['containment_path'];assert [r['key32']for r in path]==[0xfd2821c7,0x351bdea7,0xfd2821c7,0xfa834112]and [r['offset']for r in path]==[32,84,108,118]and [r['length32']for r in path]==[256,176,128,4]
 report=read(BASE/'userclient_early_schema_report.md')
 for j in range(1,8):assert '**QG'+str(j)+'**'in report and '| ES-A'+str(j)+':'in report
 for j in range(1,9):assert '| ES'+str(j)+' |'in report
 assert CHECKS_SHA in report and AUDIT_SHA in report
 for p in CHANGED:
  if p.endswith('.md'):assert 'userclient_early_schema_report.md'in read(BASE/p)
 for obj in [e,a]:
  hygiene(obj);nested_hygiene(obj);assert obj['conditional_exhaustion_to_schema_lookup_established']is True
  for key in R.FALSE:assert obj[key]is False
 print(json.dumps({'new_source_queries_rebuilt':13,'prior_publication_queries_rechecked':4,'predecessor_bound_partial_state_evaluations':30,'additional_prefix_cells_reconstructed':270,'post_schema_fields_checked':390,'controller_premise_queries_rebuilt':30,'mutation_controls_rebuilt':3,'ADID_packets_reparsed':12,'all_receipts_match':True}),flush=True);return e,a
def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']}for m in [old,new]);assert len(before)==9703 and len(after)==9709 and not before.keys()-after.keys()and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED and new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256']and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
 for key,value in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),('new_source_queries_unsat',13),('prior_publication_queries_unsat',4),('negative_source_controls',3)]:assert new['validation'][R.P+'_'+key]==value
 assert new['validation']['reports']==old['validation']['reports']+1==650 and new['goal_status']=='active'
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 for p in ARCHIVES:assert not(BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4]if p.endswith('.zst')else p));path_hygiene(decoded.encode())
  if p.endswith('.json.zst'):obj=json.loads(decoded);hygiene(obj);nested_hygiene(obj)
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':650,'original_inputs_preserved':3,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)
if __name__=='__main__':publication(*receipts())
