#!/usr/bin/env python3
"""Rebuild FPMessage initialization receipts and exact publication custody.
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
import recover_userclient_message_initialization as R
import audit_userclient_message_initialization as A
PREVIOUS='128ba5a5bb2f0824f3d8e15378d7ec53ee2c0131'
BASELINE_SHA='89a71d1c454070e1a934599f361fb12443ae179d82fde5f655c1e8460c641a13'
CHECKS_SHA='ee8476cd7d45c03decdb7b7c0262a92b996c4f0ee7bdd2edc86aaf6666c86c61'
AUDIT_SHA='d617ec6a8652f52a94965058f3279b8b4d4c776e0cb9f164e20e8428a32d4144'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'interface_investigation_status.md','interface_abi_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','userclient_message_attributes_report.md','userclient_fpttlv_entry_report.md','secure_tunnel_allocation_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'userclient_message_initialization_report.md','triage_evidence/recover_userclient_message_initialization.py','triage_evidence/audit_userclient_message_initialization.py','triage_evidence/verify_userclient_message_initialization_delivery.py','triage_evidence/userclient_message_initialization_checks.json','triage_evidence/userclient_message_initialization_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/userclient_message_initialization_checks.json','triage_evidence/userclient_message_initialization_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'new_source_spans': 24, 'new_captured_words': 628, 'original_table_pointers': 25, 'predecessor_states': 30, 'additional_source_cells_per_state': 5, 'additional_source_cell_bytes_per_state': 40, 'new_bank_rules': 6, 'new_bank_input_cases': 1536, 'zero_helper_captured_words': 90, 'zero_helper_bytes': 32, 'message_extent_bytes': 128, 'message_written_bytes': 123, 'message_unwritten_bytes': 5, 'fixed_mask_bytes': 16}
TOTALS={'new_source_queries_unsat': 425, 'new_semantic_contracts': 13, 'prior_source_queries_unsat': 157, 'lifted_instruction_instances': 2311869, 'new_source_words_covered': 628, 'zero_helper_source_words_covered': 80, 'zero_helper_alignment_contracts': 8, 'derived_predecessor_profile_projections': 24, 'ADID_profile_projections': 4, 'conditional_environment_sat_unsat_pairs': 28, 'message_byte_values_checked': 1722, 'attribute_bytes_preserved_checked': 2996, 'zero_summary_bytes_checked': 896, 'transformed_field_bytes_checked': 224, 'additional_prefix_cells_reconstructed': 150, 'additional_prefix_bytes_reconstructed': 1200, 'negative_source_controls': 3, 'new_controller_reads_success': 36, 'new_controller_reads_null': 4, 'new_bank_applications_success': 51, 'new_bank_applications_null': 3, 'native_target_calls': 0, 'concrete_unknown_workspace_values_supplied': 0, 'concrete_message_payload_values_supplied': 0}
def equivalent_queries(left,right):
 x,y=z3.parse_smt2_string(left),z3.parse_smt2_string(right)
 assert len(x)==len(y)>0 and all(canonical_expression(i)==canonical_expression(j)for i,j in zip(x,y))
def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')));assert e==R.build();fresh=A.audit(e);x,y=dict(a),dict(fresh)
 old,new=x.pop('source_proofs'),y.pop('source_proofs');assert len(old)==len(new)==425
 for p,q in zip(old,new):
  p,q=dict(p),dict(q);equivalent_queries(p.pop('query'),q.pop('query'));assert p==q and p['premises_nonvacuous']and p['result']=='unsat'
 controls,rebuilt=x.pop('negative_source_controls'),y.pop('negative_source_controls');assert len(controls)==len(rebuilt)==3
 for p,q in zip(controls,rebuilt):
  p,q=dict(p),dict(q);equivalent_queries(p.pop('satisfiable_violation_query'),q.pop('satisfiable_violation_query'));assert p==q and p['normal_oracle_rejected']and not p['native_target_executed']
 assert [p['mutated_PC']for p in controls]==['0xfffffe000a653938','0xfffffe000a653c50','0xfffffe000a653d50']
 assert x==y and e['verified_counts']==a['verified_counts']==COUNTS and a['independent_totals']==TOTALS
 assert len(a['rechecked_prior_source_proofs'])==157 and all(p['result']=='unsat'for p in a['rechecked_prior_source_proofs'])
 cases=a['partial_state_evaluations'];certs=a['ADID_field_certificates'];assert len(cases)==24 and len(certs)==4 and {q['profile']for q in certs}==set(A.PROFILES)
 for p in cases+certs:
  assert p['evaluation_kind']=='derived_tag_and_declared_message_allocation_profile'and p['raw_tag32']=='0xfa834112'and p['capacity_profile32']==128
  assert p['all_checks_pass']and p['environment_premises_sat']and p['conditional_output_query_unsat']
  assert not any(p[k]for k in ['native_target_executed','continuous_guest_extended','native_message_values_supplied','native_payload_values_supplied'])
  assert p['message_bytes_checked']==(0 if p['profile'].endswith('_null')else 123)and p['attribute_bytes_preserved']==107 and p['zero_summary_bytes_checked']==32
  assert p['final_target']==('0xfffffe000a6621e4'if p['profile'].endswith('_null')else'0xfffffe000a636338')
 for cert in certs:
  assert cert['raw_record_hex']=='fa83411297770000000400000000'and cert['raw_scalar32']=='0x0'and cert['protected_bytes_checked']==14 and len(bytes.fromhex(cert['protected_record_hex']))==14
  assert not cert['whole_ADID_packet_parsed_by_kext']and not cert['native_transport_identity_established']
 for field,total in [('message_bytes_checked','message_byte_values_checked'),('attribute_bytes_preserved','attribute_bytes_preserved_checked'),('zero_summary_bytes_checked','zero_summary_bytes_checked'),('transformed_field_bytes_checked','transformed_field_bytes_checked')]:assert sum(p[field]for p in cases+certs)==TOTALS[total]
 assert len({p['semantic_contract']for p in old})==13 and sum(p['lifted_instruction_instances']for p in old)==2311869
 assert {p['semantic_contract']for p in old if p['semantic_contract'].startswith('source_zero32_alignment_')}=={'source_zero32_alignment_'+str(j)for j in range(8)}
 for name in {p['semantic_contract']for p in old}:
  qs=[p for p in old if p['semantic_contract']==name];assert [p['counterexample_partition']for p in qs]==list(range(1,len(qs)+1))and all(p['counterexample_partitions']==len(qs)for p in qs)
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 assert e['kernel_collection_sha256']==a['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 assert len(e['source']['spans'])==24 and sum(len(s['instructions'])for s in e['source']['spans'])==628 and len(e['source']['branch_pointers'])==25
 for q in e['source']['branch_pointers']:assert int(q['target'],16)==A.qword(A.TABLE+8*q['index'])
 assert e['message_descriptor']['name']=='site.FPMessage'and e['message_descriptor']['signature']=='1122222222222222'and e['message_descriptor']['size_bytes']==128 and e['message_descriptor']['flags_u32']==0x64
 assert e['message_mask16_hex']=='e43a4ec1536f29ded6b30e155e083e20'and len(e['message_mask_arrays'])==3
 zero=e['zero_helper_envelope'];assert sha256(bytes.fromhex(zero['bytes_hex'])).hexdigest()==zero['sha256']and len(bytes.fromhex(zero['bytes_hex']))==360 and TOTALS['zero_helper_source_words_covered']==80
 for p in e['predecessor_states']:
  assert p['stopped_boundary']['pc']=='0xfffffe000a654ae4';cells=p['message_additional_source_cells'];assert len(cells)==5 and sum(q['size_bytes']for q in cells)==40
  for q in cells:assert q['overlapping_source_stores']and len(bytes.fromhex(q['reconstructed_bytes_hex']))==8
 for rule in e['message_bank_rules']:
  left,right=(bytes.fromhex(e['message_banks'][rule['name']+'_'+n]['bytes_hex'])for n in ['L','R']);assert all(j^right[left[j]^int(rule['key'],16)]==int(rule['constant'],16)for j in range(256))
 report=read(BASE/'userclient_message_initialization_report.md')
 for j in range(1,8):assert '**QG'+str(j)+'**'in report and '| MI-A'+str(j)+':'in report
 for j in range(1,9):assert '| MI'+str(j)+' |'in report
 assert CHECKS_SHA in report and AUDIT_SHA in report
 for p in CHANGED:
  if p.endswith('.md'):assert 'userclient_message_initialization_report.md'in read(BASE/p)
 for obj in [e,a]:
  hygiene(obj);nested_hygiene(obj);assert obj['conditional_message_initialization_contract_established']is True
  for key in R.FALSE:assert obj[key]is False
 for p in OWNED-{q+'.zst'for q in ARCHIVES}:
  if(BASE/p).exists():path_hygiene((BASE/p).read_bytes())
 print(json.dumps({'source_queries_rebuilt':425,'semantic_contracts':13,'prior_source_queries_rechecked':157,'derived_profile_projections':28,'message_byte_values_checked':1722,'additional_prefix_cells':150,'mutation_controls_rebuilt':3,'zero_alignment_contracts':8,'all_receipts_match':True}),flush=True);return e,a
def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']}for m in [old,new]);assert len(before)==9739 and len(after)==9745 and not before.keys()-after.keys()and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED and new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256']and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
 for key,value in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),('new_source_queries_unsat',425),('prior_source_queries_unsat',157),('negative_source_controls',3)]:assert new['validation'][R.P+'_'+key]==value
 assert new['validation']['reports']==old['validation']['reports']+1==656 and new['goal_status']=='active'
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 for p in ARCHIVES:assert not(BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4]if p.endswith('.zst')else p));path_hygiene(decoded.encode())
  if p.endswith('.json.zst'):obj=json.loads(decoded);hygiene(obj);nested_hygiene(obj)
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':656,'original_inputs_preserved':3,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)
if __name__=='__main__':publication(*receipts())
