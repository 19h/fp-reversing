#!/usr/bin/env python3
"""Rebuild schema-search receipts and verify exact publication custody.
Linear owned-byte/corpus/journal work; source SMT search cost is separate.
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
import recover_userclient_schema_search as R
import audit_userclient_schema_search as A
PREVIOUS='76c1a0532cc515bbee8b1067372f5cbf93c24571'
BASELINE_SHA='8c2306d37615eef956b78251167e0f2fa2302572526b70b5c31e5deba1a5203c'
CHECKS_SHA='4b6aa07b08d68275cb9ed0f47a744026cfe90c409606929ede81da6bb16968c0'
AUDIT_SHA='d3ecfc8a02cb3fa53a635b826b33cd58a1d005ad0a2d7cb0ca2d3ea8684cf2e9'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'interface_investigation_status.md','interface_abi_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','userclient_early_schema_report.md','userclient_input_reader_report.md','userclient_command_dispatch_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'userclient_schema_search_report.md','triage_evidence/recover_userclient_schema_search.py','triage_evidence/audit_userclient_schema_search.py','triage_evidence/verify_userclient_schema_search_delivery.py','triage_evidence/userclient_schema_search_checks.json','triage_evidence/userclient_schema_search_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/userclient_schema_search_checks.json','triage_evidence/userclient_schema_search_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'new_source_spans': 11, 'new_captured_words': 268, 'original_table_pointers': 51, 'predecessor_states': 30, 'additional_source_cells_per_state': 1, 'bank_input_cases': 256}
TOTALS={'new_source_queries_unsat': 22, 'prior_schema_queries_unsat': 4, 'lifted_instruction_instances': 14547, 'new_source_words_covered': 268, 'retained_predecessor_projections': 30, 'derived_key_substitution_projections': 30, 'post_search_fields_checked': 900, 'unbound_controller_premise_queries_unsat': 122, 'additional_prefix_cells_reconstructed': 30, 'negative_source_controls': 3, 'missing_cells_assigned_concrete_values': 0, 'independent_controller_reads_per_composition': 4, 'independent_bank_bytes_per_composition': 2, 'ADID_compatible_record_bytes_checked': 14, 'ADID_record_type16': 38775, 'ADID_record_length32': 4, 'composed_domains': 4}
def equivalent_queries(left,right):
 x,y=z3.parse_smt2_string(left),z3.parse_smt2_string(right)
 assert len(x)==len(y)>0 and all(canonical_expression(i)==canonical_expression(j)for i,j in zip(x,y))
def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')));assert e==R.build();fresh=A.audit(e);x,y=dict(a),dict(fresh)
 old,new=x.pop('source_proofs'),y.pop('source_proofs');assert len(old)==len(new)==22
 for p,q in zip(old,new):
  p,q=dict(p),dict(q);equivalent_queries(p.pop('query'),q.pop('query'));assert p==q and p['premises_nonvacuous']and p['result']=='unsat'
 controls,rebuilt=x.pop('negative_source_controls'),y.pop('negative_source_controls');assert len(controls)==len(rebuilt)==3
 for p,q in zip(controls,rebuilt):
  p,q=dict(p),dict(q);equivalent_queries(p.pop('satisfiable_violation_query'),q.pop('satisfiable_violation_query'));assert p==q and p['normal_oracle_rejected']and not p['native_target_executed']
 assert [p['mutated_PC']for p in controls]==['0xfffffe000a637158','0xfffffe000a662c4c','0xfffffe000a636104']
 assert [p['stop_boundary']for p in controls]==['before_following_wrong_tag_comparison','before_loading_unpublished_found_node','before_entering_extent_check']
 assert x==y and e['verified_counts']==a['verified_counts']==COUNTS and a['independent_totals']==TOTALS
 assert len(a['rechecked_prior_schema_proofs'])==4 and all(p['result']=='unsat'for p in a['rechecked_prior_schema_proofs'])
 cases=a['partial_state_evaluations'];assert len(cases)==60
 for p in cases:assert p['all_checks_pass']and p['all_storage_branch_and_lookup_premises_checked']and p['missing_cells_bound_to_concrete_values']==0 and not p['continuous_guest_extended']and not p['native_target_executed']and p['independent_controller_reads']==4 and p['independent_bank_bytes']==2
 retained=[p for p in cases if p['evaluation_kind']=='retained_predecessor_projection'];derived=[p for p in cases if p['evaluation_kind']=='derived_key_substitution'];assert len(retained)==len(derived)==30
 assert all(not p['found']and p['final_target']=='0xfffffe000a636728'and p['raw_tag32']==p['original_raw_tag32']and p['post_search_fields_checked']==14 for p in retained)
 assert all(p['found']and p['final_target']=='0xfffffe000a656ef0'and p['raw_tag32']=='0xfa834112'and p['post_search_fields_checked']==16 for p in derived)
 assert sum(p['post_search_fields_checked']for p in cases)==900
 cert=a['ADID_field_certificate'];assert cert['synthetic_tag_and_scalar_substitution']and cert['raw_record_hex']=='fa83411297770000000400000000'and len(bytes.fromhex(cert['protected_record_hex']))==cert['protected_record_bytes_checked']==14 and cert['matches_all_twelve_frozen_ADID_field_records']and cert['lookup_found_original_synthetic_node']and cert['all_storage_branch_and_lookup_premises_checked']and cert['next_header_request_target']=='0xfffffe000a656ef0'
 assert not any(cert[k]for k in ['native_target_executed','whole_ADID_packet_parsed_by_kext','transport_identity_established'])
 assert sum(p['unbound_controller_premise_queries_unsat']for p in cases)+cert['unbound_controller_premise_queries_unsat']==122
 assert sum(p['lifted_instruction_instances']for p in old)==14547
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 assert e['kernel_collection_sha256']==a['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 assert len(e['source']['spans'])==11 and sum(len(s['instructions'])for s in e['source']['spans'])==268 and len(e['source']['branch_pointers'])==51
 assert next(q for q in e['source']['branch_pointers']if q['index']==0x1a2)['target']=='0xfffffe000a638e68'
 assert len(e['predecessor_states'])==30 and all(p['stopped_boundary']['pc']=='0xfffffe000a654ae4'and p['stopped_boundary']['kind']=='before_undefined_private_value_load'for p in e['predecessor_states'])
 for row in e['predecessor_states']:
  assert len(row['schema_search_additional_source_cells'])==1
  for cell in row['schema_search_additional_source_cells']:assert cell['root']=='F'and cell['offset']=='0x898'and cell['size_bytes']==8 and cell['overlapping_source_stores']and len(bytes.fromhex(cell['reconstructed_bytes_hex']))==8
 bank=e['source']['bank_rule'];left,right=(bytes.fromhex(e['source']['banks'][n]['bytes_hex'])for n in ['FL','FR']);assert all(j^right[left[j]^int(bank['key'],16)]==int(bank['constant'],16)for j in range(256))
 assert len(e['adid_evidence']['packets'])==12 and all(p['field_record_hex']==cert['raw_record_hex']for p in e['adid_evidence']['packets'])
 report=read(BASE/'userclient_schema_search_report.md')
 for j in range(1,8):assert '**QG'+str(j)+'**'in report and '| SS-A'+str(j)+':'in report
 for j in range(1,9):assert '| SS'+str(j)+' |'in report
 assert CHECKS_SHA in report and AUDIT_SHA in report
 for p in CHANGED:
  if p.endswith('.md'):assert 'userclient_schema_search_report.md'in read(BASE/p)
 for obj in [e,a]:
  hygiene(obj);nested_hygiene(obj);assert obj['conditional_schema_search_step_established']is True
  for key in R.FALSE:assert obj[key]is False
 print(json.dumps({'new_source_queries_rebuilt':22,'prior_schema_queries_rechecked':4,'retained_predecessor_projections':30,'derived_key_substitution_projections':30,'additional_prefix_cells_reconstructed':30,'post_search_fields_checked':900,'controller_premise_queries_rebuilt':122,'mutation_controls_rebuilt':3,'ADID_compatible_record_bytes':14,'all_receipts_match':True}),flush=True);return e,a
def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']}for m in [old,new]);assert len(before)==9709 and len(after)==9715 and not before.keys()-after.keys()and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED and new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256']and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
 for key,value in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),('new_source_queries_unsat',22),('prior_schema_queries_unsat',4),('negative_source_controls',3)]:assert new['validation'][R.P+'_'+key]==value
 assert new['validation']['reports']==old['validation']['reports']+1==651 and new['goal_status']=='active'
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 for p in ARCHIVES:assert not(BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4]if p.endswith('.zst')else p));path_hygiene(decoded.encode())
  if p.endswith('.json.zst'):obj=json.loads(decoded);hygiene(obj);nested_hygiene(obj)
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':651,'original_inputs_preserved':3,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)
if __name__=='__main__':publication(*receipts())
