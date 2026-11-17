#!/usr/bin/env python3
"""Rebuild schema lookup-result receipts and verify exact publication custody.
Linear owned-byte/corpus/journal work; source SMT checks are separately bounded.
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
import recover_userclient_schema_lookup_result as R
import audit_userclient_schema_lookup_result as A
PREVIOUS='2735d834a41cee24c1fcd7cf843bbb7805d26859'
BASELINE_SHA='e62230f20f23fcd734eda360e321739f1ad56041d6e278aee055f6e86aa43761'
CHECKS_SHA='b5a623be2bbd10b22c15187c624997375d0cd0c703e773ff6dcba9b87eb2374f'
AUDIT_SHA='a715d19afc150fe6e385f787a8bf78fd2534bff52d04ef1ee1626bd97faeae81'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'interface_investigation_status.md','interface_abi_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','userclient_schema_registry_report.md','userclient_hash_table_lookup_report.md','userclient_uidlist_replacement_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'userclient_schema_lookup_result_report.md','triage_evidence/recover_userclient_schema_lookup_result.py','triage_evidence/audit_userclient_schema_lookup_result.py','triage_evidence/verify_userclient_schema_lookup_result_delivery.py','triage_evidence/userclient_schema_lookup_result_checks.json','triage_evidence/userclient_schema_lookup_result_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/userclient_schema_lookup_result_checks.json','triage_evidence/userclient_schema_lookup_result_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'new_source_spans': 29, 'new_captured_words': 433, 'original_table_pointers': 96, 'predecessor_states': 30, 'additional_source_cells_per_state': 2, 'additional_source_cell_bytes_per_state': 16, 'new_bank_rules': 1, 'new_bank_input_cases': 256, 'helper_frame_bytes': 112, 'entry_stride_bytes': 24}
TOTALS={'new_source_queries_unsat': 298, 'prior_source_queries_unsat': 7, 'lifted_instruction_instances': 626580, 'new_source_words_covered': 433, 'derived_predecessor_profile_projections': 24, 'ADID_profile_projections': 4, 'numeric_fields_checked': 224, 'environment_premises_sat': 28, 'conditional_environment_queries_unsat': 28, 'additional_prefix_cells_reconstructed': 60, 'additional_prefix_bytes_reconstructed': 480, 'negative_source_controls': 3, 'missing_cells_assigned_concrete_values': 0, 'native_target_calls': 0, 'source_business_outputs_replaced': 0, 'native_PAC_checks': 0, 'profiles': 4, 'helper_new_controller_reads64_per_profile': 2, 'helper_bank_cases': 256, 'ADID_protected_bytes_checked': 56}
def equivalent_queries(left,right):
 x,y=z3.parse_smt2_string(left),z3.parse_smt2_string(right)
 assert len(x)==len(y)>0 and all(canonical_expression(i)==canonical_expression(j)for i,j in zip(x,y))
def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')));assert e==R.build();fresh=A.audit(e);x,y=dict(a),dict(fresh)
 old,new=x.pop('source_proofs'),y.pop('source_proofs');assert len(old)==len(new)==TOTALS['new_source_queries_unsat']
 for p,q in zip(old,new):
  p,q=dict(p),dict(q);equivalent_queries(p.pop('query'),q.pop('query'));assert p==q and p['premises_nonvacuous']and p['result']=='unsat'
 controls,rebuilt=x.pop('negative_source_controls'),y.pop('negative_source_controls');assert len(controls)==len(rebuilt)==3
 for p,q in zip(controls,rebuilt):
  p,q=dict(p),dict(q);equivalent_queries(p.pop('satisfiable_violation_query'),q.pop('satisfiable_violation_query'));assert p==q and p['normal_oracle_rejected']and not p['native_target_executed']
 assert [p['mutated_PC']for p in controls]==['0xfffffe000a5ae834','0xfffffe000a65b59c','0xfffffe000a6368f8']
 assert x==y and e['verified_counts']==a['verified_counts']==COUNTS and a['independent_totals']==TOTALS
 assert len(a['rechecked_prior_source_proofs'])==7 and all(p['result']=='unsat'for p in a['rechecked_prior_source_proofs'])
 cases=a['partial_state_evaluations'];certs=a['ADID_field_certificates'];assert len(cases)==24 and len(certs)==4 and {q['profile']for q in certs}==set(A.PROFILES)
 for p in cases+certs:
  assert p['evaluation_kind']=='derived_tag_and_declared_table_profile'and p['raw_tag32']=='0xfa834112'and p['capacity_profile32']==128 and not p['capacity_observed_natively']
  assert p['all_checks_pass']and p['premises_sat']and p['conditional_result_query_unsat']and p['helper_source_executed']and p['missing_cells_bound_to_concrete_values']==0
  assert not any(p[k]for k in ['native_target_executed','native_PAC_verified','continuous_guest_extended','native_holder_values_supplied','native_array_values_supplied','native_payload_values_supplied'])
  assert p['final_target']==('0xfffffe000a636958'if p['profile']=='hit_nonnull'else'0xfffffe000a66229c')
 for cert in certs:
  assert cert['raw_record_hex']=='fa83411297770000000400000000'and cert['raw_scalar32']=='0x0'and cert['derived_entry_key64']=='0x1ee45f68039f9913'and cert['protected_bytes_checked']==14 and len(bytes.fromhex(cert['protected_record_hex']))==14 and cert['matches_all_twelve_frozen_field_records']
  assert not cert['whole_ADID_packet_parsed_by_kext']and not cert['transport_identity_established']
 assert sum(p['numeric_fields_checked']for p in cases+certs)==TOTALS['numeric_fields_checked']
 assert len({p['semantic_contract']for p in old})==11 and sum(p['lifted_instruction_instances']for p in old)==TOTALS['lifted_instruction_instances']
 for name in {p['semantic_contract']for p in old}:
  qs=[p for p in old if p['semantic_contract']==name];assert [p['counterexample_partition']for p in qs]==list(range(1,len(qs)+1))and all(p['counterexample_partitions']==len(qs)for p in qs)
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 assert e['kernel_collection_sha256']==a['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 assert len(e['source']['spans'])==29 and sum(len(s['instructions'])for s in e['source']['spans'])==433 and len(e['source']['branch_pointers'])==96
 for index,target in [(0x884,'0xfffffe000a6368b0'),(0xe68,'0xfffffe000a636904'),(0xac2,'0xfffffe000a636958'),(0xaca,'0xfffffe000a641c1c')]:assert next(q for q in e['source']['branch_pointers']if q['index']==index)['target']==target
 for p in e['predecessor_states']:
  assert p['stopped_boundary']['pc']=='0xfffffe000a654ae4'and p['stopped_boundary']['kind']=='before_undefined_private_value_load';cells=p['result_additional_source_cells'];assert len(cells)==2 and sum(q['size_bytes']for q in cells)==16
  for q in cells:assert q['overlapping_source_stores']and len(bytes.fromhex(q['reconstructed_bytes_hex']))==8
 rule=e['result_bank_rule'];left,right=(bytes.fromhex(e['result_banks'][n]['bytes_hex'])for n in ['BL','BR']);assert all(j^right[left[j]^int(rule['key'],16)]==int(rule['constant'],16)for j in range(256))
 report=read(BASE/'userclient_schema_lookup_result_report.md')
 for j in range(1,8):assert '**QG'+str(j)+'**'in report and '| LR-A'+str(j)+':'in report
 for j in range(1,9):assert '| LR'+str(j)+' |'in report
 assert CHECKS_SHA in report and AUDIT_SHA in report
 for p in CHANGED:
  if p.endswith('.md'):assert 'userclient_schema_lookup_result_report.md'in read(BASE/p)
 for obj in [e,a]:
  hygiene(obj);nested_hygiene(obj);assert obj['conditional_source_lookup_result_established']is True
  for key in R.FALSE:assert obj[key]is False
 print(json.dumps({'source_queries_rebuilt':len(old),'semantic_contracts':11,'prior_source_queries_rechecked':7,'derived_profile_projections':28,'numeric_fields_checked':TOTALS['numeric_fields_checked'],'additional_prefix_cells':60,'mutation_controls_rebuilt':3,'all_receipts_match':True}),flush=True);return e,a
def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']}for m in [old,new]);assert len(before)==9727 and len(after)==9733 and not before.keys()-after.keys()and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED and new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256']and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
 for key,value in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),('new_source_queries_unsat',TOTALS['new_source_queries_unsat']),('prior_source_queries_unsat',7),('negative_source_controls',3)]:assert new['validation'][R.P+'_'+key]==value
 assert new['validation']['reports']==old['validation']['reports']+1==654 and new['goal_status']=='active'
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 for p in ARCHIVES:assert not(BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4]if p.endswith('.zst')else p));path_hygiene(decoded.encode())
  if p.endswith('.json.zst'):obj=json.loads(decoded);hygiene(obj);nested_hygiene(obj)
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':654,'original_inputs_preserved':3,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)
if __name__=='__main__':publication(*receipts())
