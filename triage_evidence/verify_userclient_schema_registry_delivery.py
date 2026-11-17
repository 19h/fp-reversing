#!/usr/bin/env python3
"""Rebuild schema shared-table receipts and verify exact publication custody.
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
import recover_userclient_schema_registry as R
import audit_userclient_schema_registry as A
PREVIOUS='3c66340be07c2a059c08469dd8452a83413e7685'
BASELINE_SHA='682c90ee56aaef2501c4e50eae3acbac0c40cc392effecf2c9a3952e5dea1cc9'
CHECKS_SHA='8e32cec6eec4718c2699fc97189b15c574f9bdce395d9bd55ce4dbf74f20cc72'
AUDIT_SHA='c476c63e75e118210b73cda2052a0a756e5947b794bcb81722543989fdf899b1'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'interface_investigation_status.md','interface_abi_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','userclient_schema_scalar_report.md','userclient_uidlist_replacement_report.md','userclient_replacement_bootstrap_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'userclient_schema_registry_report.md','triage_evidence/recover_userclient_schema_registry.py','triage_evidence/audit_userclient_schema_registry.py','triage_evidence/verify_userclient_schema_registry_delivery.py','triage_evidence/userclient_schema_registry_checks.json','triage_evidence/userclient_schema_registry_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/userclient_schema_registry_checks.json','triage_evidence/userclient_schema_registry_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'new_source_spans': 17, 'new_captured_words': 313, 'original_table_pointers': 75, 'predecessor_states': 30, 'additional_source_cells_per_state': 10, 'additional_source_cell_bytes_per_state': 76, 'new_bank_rules': 4, 'new_bank_input_cases': 1024, 'lookup_record_size_bytes': 48, 'lookup_record_initialized_bytes': 40}
TOTALS={'new_source_queries_unsat': 13, 'prior_source_queries_unsat': 6, 'lifted_instruction_instances': 11602, 'new_source_words_covered': 313, 'derived_key_substitution_projections': 30, 'numeric_fields_checked': 498, 'symbolic_environment_fields_checked': 12, 'environment_premises_sat': 31, 'conditional_environment_queries_unsat': 31, 'additional_prefix_cells_reconstructed': 300, 'additional_prefix_bytes_reconstructed': 2280, 'negative_source_controls': 3, 'missing_cells_assigned_concrete_values': 0, 'native_holder_values_supplied': 0, 'native_capacity_values_supplied': 0, 'native_entries_values_supplied': 0, 'ready_composition_new_controller_reads': 4, 'ready_composition_new_bank_bytes': 2, 'null_allocation_new_controller_reads': 4, 'null_allocation_new_bank_bytes': 3, 'ADID_compatible_record_bytes_checked': 14, 'lookup_record_size_bytes': 48, 'lookup_record_initialized_bytes': 40, 'composed_domains': 4}
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
 assert [p['mutated_PC']for p in controls]==['0xfffffe000a63678c','0xfffffe000a635c54','0xfffffe000a65b4c8']
 assert x==y and e['verified_counts']==a['verified_counts']==COUNTS and a['independent_totals']==TOTALS
 assert len(a['rechecked_prior_source_proofs'])==6 and all(p['result']=='unsat'for p in a['rechecked_prior_source_proofs'])
 cases=a['partial_state_evaluations'];assert len(cases)==30 and sum(p['numeric_fields_checked']for p in cases)==498 and sum(p['symbolic_environment_fields_checked']for p in cases)==12
 assert sum(p['domain']=='u32'for p in cases)==6
 for p in cases:
  assert p['evaluation_kind']=='derived_key_substitution'and p['raw_tag32']=='0xfa834112'and p['original_raw_tag32']!=p['raw_tag32']
  assert p['all_checks_pass']and p['all_storage_branch_and_lookup_premises_checked']and p['environment_premises_nonvacuous']and p['conditional_environment_query_unsat']and p['missing_cells_bound_to_concrete_values']==0 and not p['continuous_guest_extended']and not p['native_target_executed']
  for key in ['native_holder_values_supplied','native_capacity_values_supplied','native_entries_values_supplied']:assert p[key]==0
  ready=p['domain']=='u32';assert p['pending_call']==ready and p['final_target']==('0xfffffe000a5ae354'if ready else'0xfffffe000a66229c')
  assert p['numeric_fields_checked']==(27 if ready else 14)and p['symbolic_environment_fields_checked']==(2 if ready else 0)
  assert p['new_independent_controller_reads']==(4 if ready else 0)and p['new_independent_bank_bytes']==(2 if ready else 0)
  assert len(p['packet_codec_source_shape_checks'])==(1 if ready else 0)and all(q['source_shape_checked']for q in p['packet_codec_source_shape_checks'])
 cert=a['ADID_field_certificate'];assert cert['synthetic_tag_and_scalar_substitution']and cert['raw_record_hex']=='fa83411297770000000400000000'and len(bytes.fromhex(cert['protected_record_hex']))==cert['protected_record_bytes_checked']==14 and cert['matches_all_twelve_frozen_ADID_field_records']and cert['decoded_output32']==0 and cert['derived_lookup_key64']=='0x1ee45f68039f9913'and cert['pending_lookup_target']=='0xfffffe000a5ae354'and cert['lookup_modifier']=='0x6a0f'and cert['lookup_record_size_bytes']==48 and cert['lookup_record_initialized_bytes']==40 and cert['environment_premises_nonvacuous']and cert['conditional_environment_query_unsat']
 assert not any(cert[k]for k in ['native_target_executed','lookup_helper_executed','whole_ADID_packet_parsed_by_kext','transport_identity_established'])
 for key in ['native_holder_values_supplied','native_capacity_values_supplied','native_entries_values_supplied']:assert cert[key]==0
 assert sum(p['lifted_instruction_instances']for p in old)==11602
 assert old[0]['name']=='universal_caller_decoder_pre_multiply_equality'and old[0]['lifted_instruction_instances']==0
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 assert e['kernel_collection_sha256']==a['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 assert len(e['source']['spans'])==17 and sum(len(s['instructions'])for s in e['source']['spans'])==313 and len(e['source']['branch_pointers'])==75
 for index,target in [(0x37,'0xfffffe000a6367b4'),(0x5b7,'0xfffffe000a65abf8'),(0x128,'0xfffffe000a636854'),(0x2b7,'0xfffffe000a66229c')]:assert next(q for q in e['source']['branch_pointers']if q['index']==index)['target']==target
 assert len(e['predecessor_states'])==30 and all(p['stopped_boundary']['pc']=='0xfffffe000a654ae4'and p['stopped_boundary']['kind']=='before_undefined_private_value_load'for p in e['predecessor_states'])
 for p in e['predecessor_states']:
  cells=p['registry_additional_source_cells'];assert len(cells)==10 and sum(q['size_bytes']for q in cells)==76
  for q in cells:assert q['root']=='F'and q['overlapping_source_stores']and len(bytes.fromhex(q['reconstructed_bytes_hex']))==q['size_bytes']
 assert len(e['registry_bank_rules'])==4
 for q in e['registry_bank_rules']:
  left,right=(bytes.fromhex(e['registry_banks'][q[n+'_name']]['bytes_hex'])for n in ['left','right']);assert all(j^right[left[j]^int(q['key'],16)]==int(q['constant'],16)for j in range(256))
 descriptor=e['registry_allocation_descriptor'];assert descriptor['address']=='0xfffffe000847b960'and descriptor['name']=='site.FPHashTable'and descriptor['signature']=='21'and descriptor['flags_u32']==0x64 and descriptor['size_bytes']==16
 assert len(e['adid_evidence']['packets'])==12 and all(p['field_record_hex']==cert['raw_record_hex']for p in e['adid_evidence']['packets'])
 report=read(BASE/'userclient_schema_registry_report.md')
 for j in range(1,8):assert '**QG'+str(j)+'**'in report and '| RG-A'+str(j)+':'in report
 for j in range(1,9):assert '| RG'+str(j)+' |'in report
 assert CHECKS_SHA in report and AUDIT_SHA in report
 for p in CHANGED:
  if p.endswith('.md'):assert 'userclient_schema_registry_report.md'in read(BASE/p)
 for obj in [e,a]:
  hygiene(obj);nested_hygiene(obj);assert obj['conditional_schema_registry_request_established']is True
  for key in R.FALSE:assert obj[key]is False
 print(json.dumps({'new_source_queries_rebuilt':13,'prior_source_queries_rechecked':6,'derived_key_substitution_projections':30,'numeric_fields_checked':498,'symbolic_environment_fields_checked':12,'additional_prefix_cells':300,'environment_sat_and_unsat_pairs':31,'mutation_controls_rebuilt':3,'all_receipts_match':True}),flush=True);return e,a
def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']}for m in [old,new]);assert len(before)==9721 and len(after)==9727 and not before.keys()-after.keys()and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED and new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256']and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
 for key,value in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),('new_source_queries_unsat',13),('prior_source_queries_unsat',6),('negative_source_controls',3)]:assert new['validation'][R.P+'_'+key]==value
 assert new['validation']['reports']==old['validation']['reports']+1==653 and new['goal_status']=='active'
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 for p in ARCHIVES:assert not(BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4]if p.endswith('.zst')else p));path_hygiene(decoded.encode())
  if p.endswith('.json.zst'):obj=json.loads(decoded);hygiene(obj);nested_hygiene(obj)
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':653,'original_inputs_preserved':3,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)
if __name__=='__main__':publication(*receipts())
