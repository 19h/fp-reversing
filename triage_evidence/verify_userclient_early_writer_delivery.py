#!/usr/bin/env python3
"""Rebuild conditional early-header receipts and verify exact publication custody.
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
import recover_userclient_early_writer as R
import audit_userclient_early_writer as A
PREVIOUS='11b99cf2828f722bff2c976738c94a92b458a0f0'
BASELINE_SHA='459cc81f6cba9d1e97fa91e3c0376fa78ee27ecd447276cc65de48cc2adc64ed'
CHECKS_SHA='759215006af5fe74e734b270d0e64e6b80e5973963a33074a2dab93872cf8ddf'
AUDIT_SHA='07d13d8e0b1a89a40028bbff209460a49c33e8fb2a7eb5973244446be95f76d8'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'foundational_triage_report.md', 'interface_abi_report.md', 'interface_investigation_status.md', 'userclient_early_data_report.md', 'userclient_record_writer_report.md', 'mach_ports_report.md', 'userclient_record_nodes_report.md', 'obfuscated_routines_report.md', 'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'triage_evidence/userclient_early_writer_checks.json', 'triage_evidence/recover_userclient_early_writer.py', 'triage_evidence/verify_userclient_early_writer_delivery.py', 'userclient_early_writer_report.md', 'triage_evidence/audit_userclient_early_writer.py', 'triage_evidence/userclient_early_writer_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/userclient_early_writer_checks.json','triage_evidence/userclient_early_writer_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'source_spans': 6, 'captured_words': 227, 'table_lookup_sites': 6, 'original_table_pointers': 8, 'unique_retag_sites': 4, 'predecessor_handoffs': 30, 'header_bytes': 10, 'arbitrary_missing_cells': 8}
TOTALS={'new_source_queries_unsat': 14, 'prior_reader_queries_unsat': 3, 'lifted_instruction_instances': 2305, 'captured_source_words': 227, 'normal_path_unique_PCs': 223, 'composed_path_instruction_instances': 309, 'normal_pointer_branch_instances': 8, 'header_store_instances': 10, 'all_source_store_instances': 15, 'source_load_instances': 25, 'logical_transfer_instances': 7, 'predecessor_bound_partial_state_evaluations': 30, 'projected_handoff_register_values_checked': 330, 'protected_header_bytes_checked': 300, 'arbitrary_missing_cells_per_world': 8, 'missing_cells_assigned_concrete_values': 0, 'negative_source_controls': 2}
def equivalent_queries(left,right):
 x,y=z3.parse_smt2_string(left),z3.parse_smt2_string(right)
 assert len(x)==len(y)>0 and all(canonical_expression(i)==canonical_expression(j)for i,j in zip(x,y))
def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')));assert e==R.build();fresh=A.audit(e);x,y=dict(a),dict(fresh)
 old,new=x.pop('source_proofs'),y.pop('source_proofs');assert len(old)==len(new)==14
 for p,q in zip(old,new):
  p,q=dict(p),dict(q);equivalent_queries(p.pop('query'),q.pop('query'));assert p==q and p['premises_nonvacuous']and p['result']=='unsat'
 controls,rebuilt=x.pop('negative_source_controls'),y.pop('negative_source_controls');assert len(controls)==len(rebuilt)==2
 for p,q in zip(controls,rebuilt):
  p,q=dict(p),dict(q);equivalent_queries(p.pop('satisfiable_mutated_path_query'),q.pop('satisfiable_mutated_path_query'));assert p==q and p['normal_oracle_rejected']and not p['native_target_executed']
 assert [p['header_bytes_still_correct']for p in controls]==[False,True]
 assert [p['mutated_PC']for p in controls]==['0xfffffe000a655014','0xfffffe000a654dc4']
 assert x==y and e['verified_counts']==a['verified_counts']==COUNTS and a['independent_totals']==TOTALS
 assert len(a['rechecked_prior_reader_proofs'])==3 and all(p['result']=='unsat'for p in a['rechecked_prior_reader_proofs'])
 assert len(a['partial_state_evaluations'])==30 and all(p['all_checks_pass']and p['missing_cells_bound_to_concrete_values']==0 and not p['continuous_guest_extended']for p in a['partial_state_evaluations'])
 assert sum(p['lifted_instruction_instances']for p in old)==2305
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 assert e['kernel_collection_sha256']==a['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 assert len(e['source']['spans'])==6 and sum(len(s['instructions'])for s in e['source']['spans'])==227 and len(e['source']['branch_pointers'])==8 and len(e['source']['retag_sites'])==4
 assert len(e['predecessor_handoffs'])==30 and all(p['stopped_boundary']['pc']=='0xfffffe000a654ae4'and p['stopped_boundary']['kind']=='before_undefined_private_value_load'for p in e['predecessor_handoffs'])
 report=read(BASE/'userclient_early_writer_report.md')
 for j in range(1,8):assert '**QG'+str(j)+'**'in report and '| EW-A'+str(j)+':'in report
 for j in range(1,9):assert '| EW'+str(j)+' |'in report
 assert CHECKS_SHA in report and AUDIT_SHA in report
 for p in CHANGED:
  if p.endswith('.md'):assert 'userclient_early_writer_report.md'in read(BASE/p)
 for obj in [e,a]:
  hygiene(obj);nested_hygiene(obj)
  for key in R.FALSE:assert obj[key]is False
 print(json.dumps({'new_source_queries_rebuilt':14,'prior_reader_queries_rechecked':3,'predecessor_bound_partial_state_evaluations':30,'protected_header_bytes_checked':300,'missing_cells_assigned_concrete_values':0,'mutation_controls_rebuilt':2,'all_receipts_match':True}),flush=True);return e,a
def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']}for m in [old,new]);assert len(before)==9685 and len(after)==9691 and not before.keys()-after.keys()and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED and new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256']and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
 for key,value in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),('new_source_queries_unsat',14),('prior_reader_queries_unsat',3),('negative_source_controls',2)]:assert new['validation'][R.P+'_'+key]==value
 assert new['validation']['reports']==old['validation']['reports']+1==647 and new['goal_status']=='active'
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 for p in ARCHIVES:assert not(BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4]if p.endswith('.zst')else p));path_hygiene(decoded.encode())
  if p.endswith('.json.zst'):obj=json.loads(decoded);hygiene(obj);nested_hygiene(obj)
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':647,'original_inputs_preserved':3,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)
if __name__=='__main__':publication(*receipts())
