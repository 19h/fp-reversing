#!/usr/bin/env python3
"""Rebuild conditional early-payload receipts and verify exact publication custody.
Linear corpus/journal/owned-byte work; source SMT search cost is separate.
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
import recover_userclient_early_payload as R
import audit_userclient_early_payload as A
PREVIOUS='76cd14b71fc5f2567327ad1dd3f2f45cbf6d4d40'
BASELINE_SHA='9c013b2132d72877d562d06066f8449fcc1a45135934e8a7aa7efc3f451ca807'
CHECKS_SHA='6ed7378f51320046bf9d7ffea2470759ddbaf0b08dd290571147a7ba7fe504d0'
AUDIT_SHA='422eb0a76e182e8870f0870adfcea3de534268d178b9a77a0c383c29625d27d4'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'userclient_record_nodes_report.md', 'interface_investigation_status.md', 'userclient_early_writer_report.md', 'userclient_record_writer_report.md', 'triage_evidence/validate_rpc502_sidecar_delivery.py', 'interface_abi_report.md', 'obfuscated_routines_report.md', 'foundational_triage_report.md', 'mach_ports_report.md'}
ADDED={'triage_evidence/userclient_early_payload_audit.json', 'triage_evidence/recover_userclient_early_payload.py', 'triage_evidence/verify_userclient_early_payload_delivery.py', 'triage_evidence/audit_userclient_early_payload.py', 'triage_evidence/userclient_early_payload_checks.json', 'userclient_early_payload_report.md'}
ARCHIVES={MANIFEST,'triage_evidence/userclient_early_payload_checks.json','triage_evidence/userclient_early_payload_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'new_source_spans': 14, 'new_captured_words': 352, 'original_table_pointers': 16, 'direct_type_branches': 3, 'predecessor_states': 30, 'source_defined_cells_per_state': 7, 'early_payload_domains': 3}
TOTALS={'new_source_queries_unsat': 15, 'prior_header_queries_unsat': 2, 'lifted_instruction_instances': 5204, 'new_source_words_covered': 352, 'predecessor_bound_partial_state_evaluations': 30, 'serialized_bytes_checked': 468, 'saved_control_values_checked': 120, 'missing_cells_assigned_concrete_values': 0, 'negative_source_controls': 3, 'u32_case_evaluations': 6, 'u64_case_evaluations': 12, 'span_case_evaluations': 12, 'u32_record_bytes': 14, 'u64_record_bytes': 18, 'span_copy_byte_loads_per_step': 1, 'span_copy_byte_stores_per_step': 1}
def equivalent_queries(left,right):
 x,y=z3.parse_smt2_string(left),z3.parse_smt2_string(right)
 assert len(x)==len(y)>0 and all(canonical_expression(i)==canonical_expression(j)for i,j in zip(x,y))
def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')));assert e==R.build();fresh=A.audit(e);x,y=dict(a),dict(fresh)
 old,new=x.pop('source_proofs'),y.pop('source_proofs');assert len(old)==len(new)==15
 for p,q in zip(old,new):
  p,q=dict(p),dict(q);equivalent_queries(p.pop('query'),q.pop('query'));assert p==q and p['premises_nonvacuous']and p['result']=='unsat'
 controls,rebuilt=x.pop('negative_source_controls'),y.pop('negative_source_controls');assert len(controls)==len(rebuilt)==3
 for p,q in zip(controls,rebuilt):
  p,q=dict(p),dict(q);equivalent_queries(p.pop('satisfiable_violation_query'),q.pop('satisfiable_violation_query'));assert p==q and p['normal_oracle_rejected']and not p['native_target_executed']
 assert [p['domain']for p in controls]==['u32','u64','span']
 assert x==y and e['verified_counts']==a['verified_counts']==COUNTS and a['independent_totals']==TOTALS
 assert len(a['rechecked_prior_header_proofs'])==2 and all(p['result']=='unsat'for p in a['rechecked_prior_header_proofs'])
 assert len(a['partial_state_evaluations'])==30 and all(p['all_checks_pass']and p['all_storage_branch_and_lookup_premises_checked']and p['missing_cells_bound_to_concrete_values']==0 and not p['continuous_guest_extended']for p in a['partial_state_evaluations'])
 assert sum(p['zero_span_bypass_used']for p in a['partial_state_evaluations'])==6 and sum(p['serialized_bytes_checked']for p in a['partial_state_evaluations'])==468
 assert sum(p['lifted_instruction_instances']for p in old)==5204
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 assert e['kernel_collection_sha256']==a['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 assert len(e['source']['spans'])==14 and sum(len(s['instructions'])for s in e['source']['spans'])==352 and len(e['source']['branch_pointers'])==16 and len(e['source']['direct_branches'])==3
 assert len(e['predecessor_states'])==30 and all(p['stopped_boundary']['pc']=='0xfffffe000a654ae4'and p['stopped_boundary']['kind']=='before_undefined_private_value_load'for p in e['predecessor_states'])
 for row in e['predecessor_states']:
  assert len(row['source_defined_cells'])==7
  for cell in row['source_defined_cells']:assert cell['overlapping_source_stores']and cell['reconstructed_bytes_hex']==cell['last_exact_store']['after_hex']
 report=read(BASE/'userclient_early_payload_report.md')
 for j in range(1,8):assert '**QG'+str(j)+'**'in report and '| EP-A'+str(j)+':'in report
 for j in range(1,9):assert '| EP'+str(j)+' |'in report
 assert CHECKS_SHA in report and AUDIT_SHA in report
 for p in CHANGED:
  if p.endswith('.md'):assert 'userclient_early_payload_report.md'in read(BASE/p)
 for obj in [e,a]:
  hygiene(obj);nested_hygiene(obj);assert obj['conditional_three_domain_payload_serialization_established']is True
  for key in R.FALSE:assert obj[key]is False
 print(json.dumps({'new_source_queries_rebuilt':15,'prior_header_queries_rechecked':2,'predecessor_bound_partial_state_evaluations':30,'serialized_bytes_checked':468,'missing_cells_assigned_concrete_values':0,'mutation_controls_rebuilt':3,'all_receipts_match':True}),flush=True);return e,a
def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']}for m in [old,new]);assert len(before)==9691 and len(after)==9697 and not before.keys()-after.keys()and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED and new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256']and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
 for key,value in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),('new_source_queries_unsat',15),('prior_header_queries_unsat',2),('negative_source_controls',3)]:assert new['validation'][R.P+'_'+key]==value
 assert new['validation']['reports']==old['validation']['reports']+1==648 and new['goal_status']=='active'
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 for p in ARCHIVES:assert not(BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4]if p.endswith('.zst')else p));path_hygiene(decoded.encode())
  if p.endswith('.json.zst'):obj=json.loads(decoded);hygiene(obj);nested_hygiene(obj)
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':648,'original_inputs_preserved':3,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)
if __name__=='__main__':publication(*receipts())
