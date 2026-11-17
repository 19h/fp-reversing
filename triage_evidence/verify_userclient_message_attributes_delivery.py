#!/usr/bin/env python3
"""Rebuild message-attribute receipts and verify exact publication custody.
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
import recover_userclient_message_attributes as R
import audit_userclient_message_attributes as A
PREVIOUS='09b920c6799844d19d06e6d6bb49fc9e31f62f21'
BASELINE_SHA='1b840c815c1ea625bbf29c5ddc0431ee03cd224d56c9f3fe838911b95cdffc9d'
CHECKS_SHA='96933aa62724a9225566d8f3c98028eed287ba17ff313da5f575e2c333334f5c'
AUDIT_SHA='40f81d032a2c3ccf4ee0651efa887889c068bed24e59841f08f13be7efb7a1d0'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'interface_investigation_status.md','interface_abi_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','userclient_schema_lookup_result_report.md','secure_tunnel_allocation_report.md','secure_tunnel_table_insertion_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'userclient_message_attributes_report.md','triage_evidence/recover_userclient_message_attributes.py','triage_evidence/audit_userclient_message_attributes.py','triage_evidence/verify_userclient_message_attributes_delivery.py','triage_evidence/userclient_message_attributes_checks.json','triage_evidence/userclient_message_attributes_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/userclient_message_attributes_checks.json','triage_evidence/userclient_message_attributes_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'new_source_spans':22,'new_captured_words':506,'original_table_pointers':115,'predecessor_states':30,'additional_source_cells_per_state':11,'additional_source_cell_bytes_per_state':80,'new_bank_rules':4,'new_bank_input_cases':1024,'attribute_extent_bytes':112,'attribute_written_bytes':107,'attribute_untouched_bytes':5,'random_calls_per_successful_constructor':64,'minimum_payload_read_extent_bytes':56}
TOTALS={'new_source_queries_unsat':199,'new_semantic_contracts':8,'prior_source_queries_unsat':76,'lifted_instruction_instances':890169,'new_source_words_covered':506,'derived_predecessor_profile_projections':18,'ADID_profile_projections':3,'conditional_environment_sat_unsat_pairs':21,'attribute_byte_values_checked':1498,'symbolic_random_byte_values_checked':672,'payload_byte_copies_checked':504,'additional_prefix_cells_reconstructed':330,'additional_prefix_bytes_reconstructed':2400,'negative_source_controls':3,'constructor_random_calls':64,'new_controller_reads_success':130,'new_controller_reads_allocation_null':2,'new_bank_applications_success':66,'new_bank_applications_allocation_null':2,'native_target_calls':0,'concrete_unknown_workspace_values_supplied':0,'concrete_random_values_supplied':0,'concrete_payload_bytes_supplied':0}
def equivalent_queries(left,right):
 x,y=z3.parse_smt2_string(left),z3.parse_smt2_string(right)
 assert len(x)==len(y)>0 and all(canonical_expression(i)==canonical_expression(j)for i,j in zip(x,y))
def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')));assert e==R.build();fresh=A.audit(e);x,y=dict(a),dict(fresh)
 old,new=x.pop('source_proofs'),y.pop('source_proofs');assert len(old)==len(new)==199
 for p,q in zip(old,new):
  p,q=dict(p),dict(q);equivalent_queries(p.pop('query'),q.pop('query'));assert p==q and p['premises_nonvacuous']and p['result']=='unsat'
 controls,rebuilt=x.pop('negative_source_controls'),y.pop('negative_source_controls');assert len(controls)==len(rebuilt)==3
 for p,q in zip(controls,rebuilt):
  p,q=dict(p),dict(q);equivalent_queries(p.pop('satisfiable_violation_query'),q.pop('satisfiable_violation_query'));assert p==q and p['normal_oracle_rejected']and not p['native_target_executed']
 assert [p['mutated_PC']for p in controls]==['0xfffffe000a636aa0','0xfffffe000a636b58','0xfffffe000a652fdc']
 assert x==y and e['verified_counts']==a['verified_counts']==COUNTS and a['independent_totals']==TOTALS
 assert len(a['rechecked_prior_source_proofs'])==76 and all(p['result']=='unsat'for p in a['rechecked_prior_source_proofs'])
 cases=a['partial_state_evaluations'];certs=a['ADID_field_certificates'];assert len(cases)==18 and len(certs)==3 and {q['profile']for q in certs}==set(A.PROFILES)
 for p in cases+certs:
  assert p['evaluation_kind']=='derived_tag_and_declared_table_payload_profile'and p['raw_tag32']=='0xfa834112'and p['capacity_profile32']==128
  assert p['all_checks_pass']and p['environment_premises_sat']and p['conditional_output_query_unsat']and p['initial_undefined_workspace_word_remains_symbolic']
  assert not any(p[k]for k in ['native_target_executed','continuous_guest_extended','native_entropy_supplied','native_payload_bytes_supplied','native_pointer_values_supplied'])
  assert p['final_target']==('0xfffffe000a6621e4'if p['profile']=='allocation_null'else'0xfffffe000a6575b0')
  assert p['attribute_bytes_checked']==(0 if p['profile']=='allocation_null'else 107)and p['modeled_random_returns']==(0 if p['profile']=='allocation_null'else 64)
 for cert in certs:
  assert cert['raw_record_hex']=='fa83411297770000000400000000'and cert['raw_scalar32']=='0x0'and cert['protected_bytes_checked']==14 and len(bytes.fromhex(cert['protected_record_hex']))==14
  assert not cert['whole_ADID_packet_parsed_by_kext']and not cert['native_transport_identity_established']
 for field,total in [('attribute_bytes_checked','attribute_byte_values_checked'),('symbolic_random_output_bytes_checked','symbolic_random_byte_values_checked'),('payload_bytes_copied','payload_byte_copies_checked')]:assert sum(p[field]for p in cases+certs)==TOTALS[total]
 assert len({p['semantic_contract']for p in old})==8 and sum(p['lifted_instruction_instances']for p in old)==890169
 for name in {p['semantic_contract']for p in old}:
  qs=[p for p in old if p['semantic_contract']==name];assert [p['counterexample_partition']for p in qs]==list(range(1,len(qs)+1))and all(p['counterexample_partitions']==len(qs)for p in qs)
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 assert e['kernel_collection_sha256']==a['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 assert len(e['source']['spans'])==22 and sum(len(s['instructions'])for s in e['source']['spans'])==506 and len(e['source']['branch_pointers'])==115
 assert e['attribute_descriptor']['name']=='site.FPMessageAttr'and e['attribute_descriptor']['size_bytes']==112 and e['attribute_descriptor']['flags_u32']==0x6c
 assert e['kernel_random_function']['sha256']=='87f398b6e41e9ea2714e346f572f1bf38b22ee4f9811044c8a7453754aef2891'
 originals=json.loads(read(ROOT/'userclient_early_data_checks.json'))
 for p in e['predecessor_states']:
  assert p['stopped_boundary']['pc']=='0xfffffe000a654ae4'and not p['initial_workspace_d0c_defined_by_prefix'];cells=p['attribute_additional_source_cells'];assert len(cells)==11 and sum(q['size_bytes']for q in cells)==80
  for q in cells:assert q['overlapping_source_stores']and len(bytes.fromhex(q['reconstructed_bytes_hex']))==q['size_bytes']
  workspace=int(p['handoff_state']['registers31'][3],16)+0xd0c
  assert not [w for w in originals['cases'][p['predecessor_case_index']]['source_writes']if int(w['address'],16)<workspace+4 and workspace<int(w['address'],16)+w['size_bytes']]
 for rule in e['attribute_bank_rules']:
  left,right=(bytes.fromhex(e['attribute_banks'][rule['name']+'_'+n]['bytes_hex'])for n in ['L','R']);assert all(j^right[left[j]^int(rule['key'],16)]==int(rule['constant'],16)for j in range(256))
 report=read(BASE/'userclient_message_attributes_report.md')
 for j in range(1,8):assert '**QG'+str(j)+'**'in report and '| MA-A'+str(j)+':'in report
 for j in range(1,9):assert '| MA'+str(j)+' |'in report
 assert CHECKS_SHA in report and AUDIT_SHA in report
 for p in CHANGED:
  if p.endswith('.md'):assert 'userclient_message_attributes_report.md'in read(BASE/p)
 for obj in [e,a]:
  hygiene(obj);nested_hygiene(obj);assert obj['conditional_message_attribute_contract_established']is True
  for key in R.FALSE:assert obj[key]is False
 for p in OWNED-ARCHIVES-{q+'.zst'for q in ARCHIVES}:
  if(BASE/p).exists():path_hygiene((BASE/p).read_bytes())
 print(json.dumps({'source_queries_rebuilt':199,'semantic_contracts':8,'prior_source_queries_rechecked':76,'derived_profile_projections':21,'attribute_byte_values_checked':1498,'additional_prefix_cells':330,'mutation_controls_rebuilt':3,'all_receipts_match':True}),flush=True);return e,a
def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']}for m in [old,new]);assert len(before)==9733 and len(after)==9739 and not before.keys()-after.keys()and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED and new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256']and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
 for key,value in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),('new_source_queries_unsat',199),('prior_source_queries_unsat',76),('negative_source_controls',3)]:assert new['validation'][R.P+'_'+key]==value
 assert new['validation']['reports']==old['validation']['reports']+1==655 and new['goal_status']=='active'
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 for p in ARCHIVES:assert not(BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4]if p.endswith('.zst')else p));path_hygiene(decoded.encode())
  if p.endswith('.json.zst'):obj=json.loads(decoded);hygiene(obj);nested_hygiene(obj)
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':655,'original_inputs_preserved':3,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)
if __name__=='__main__':publication(*receipts())
