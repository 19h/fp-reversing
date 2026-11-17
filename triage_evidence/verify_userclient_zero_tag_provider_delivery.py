#!/usr/bin/env python3
"""Rebuild source receipts and verify the exact publication delta.
O(owned bytes + corpus bytes), excluding bounded SMT search.
"""
import json
from hashlib import sha256
from compression import zstd
from kext_port_tools import ROOT,SOURCE,qword
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_daemon_payload_mix_publication import BASE,git,hygiene,path_hygiene
from verify_kernel_magazine_bootstrap_delivery import nested_hygiene
from verify_userclient_message_initialization_delivery import equivalent_queries
import recover_userclient_zero_tag_provider as R
import audit_userclient_zero_tag_provider as A
PREVIOUS='ddf0aa8ab5a04855de561208a511d0c03e35cbef'
BASELINE_SHA='85c8a43de8f49c64eb09f579b6c9c806892c7400367db4697a7fb4708f9348c2'
CHECKS_SHA='82c5b5be5bfd6dc4924c321fd8483051667fbf7c38cf989e6e7170a16bbc46f0'
AUDIT_SHA='47c915473442e57cf3bb37f3ef242353c525ceafcf15bc261d3ad010e6497a80'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED=set(['foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py','userclient_caller_return_report.md','userclient_transfer_boundary_report.md','userclient_zero_tag_return_report.md'])
ADDED=set(['triage_evidence/audit_userclient_zero_tag_provider.py','triage_evidence/recover_userclient_zero_tag_provider.py','triage_evidence/userclient_zero_tag_provider_audit.json','triage_evidence/userclient_zero_tag_provider_checks.json','triage_evidence/verify_userclient_zero_tag_provider_delivery.py','userclient_zero_tag_provider_report.md'])
ARCHIVES=set([MANIFEST,'triage_evidence/userclient_zero_tag_provider_audit.json','triage_evidence/userclient_zero_tag_provider_checks.json'])
OWNED={p+'.zst'if p in ARCHIVES else p for p in CHANGED|ADDED|{MANIFEST}}
COUNTS={'caller_source_words':191,'caller_call_sites':14,'original_bindings':8,'prefix_states':30,'argument_cells_per_prefix':3,'reconstructed_argument_cells':90,'reconstructed_argument_bytes':720,'selected_extent14_prefixes':6,'selected_extent_bytes':14,'handler_frame_bytes':64,'provider_frame_bytes':80,'core_frame_bytes':4336,'nested_frame_bytes':4480,'native_target_calls':0,'input_content_bytes_supplied':0}
TOTALS={'new_source_queries_unsat':20,'prior_queries_unsat':67,'nullable_state_admissions_sat':6,'former_model_zero_exclusion_unsat':1,'negative_source_controls':2,'proved_caller_source_words':177,'prefix_argument_cells':90,'prefix_argument_bytes':720,'native_target_calls':0}
def compare_queries(old,new,field='query'):
 assert len(old)==len(new)
 for p,q in zip(old,new):
  p,q=dict(p),dict(q);equivalent_queries(p.pop(field),q.pop(field));assert p==q
def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')));assert e==R.build();fresh=A.audit(e);x,y=dict(a),dict(fresh)
 for field in ['source_proofs','nullable_state_admissions']:compare_queries(x.pop(field),y.pop(field))
 compare_queries(x.pop('negative_source_controls'),y.pop('negative_source_controls'),'satisfiable_violation_query')
 compare_queries([x.pop('former_model_exclusion')],[y.pop('former_model_exclusion')]);assert x==y
 assert e['verified_counts']==a['verified_counts']==COUNTS and a['independent_totals']==TOTALS
 assert len(a['source_proofs'])==20 and all(p['result']=='unsat'and p['premises_nonvacuous']for p in a['source_proofs'])
 assert len(a['rechecked_prior_proofs'])==67 and all(p['result']=='unsat'for p in a['rechecked_prior_proofs'])
 assert len(a['nullable_state_admissions'])==6 and all(p['result']=='sat'and not p['native_reachability_established']for p in a['nullable_state_admissions'])
 assert a['former_model_exclusion']['result']=='unsat'and not a['former_model_exclusion']['native_fault_established']
 assert len(a['state_use_footprints'])==3 and all(p['state_dependent_load_addresses']==p['state_dependent_control_or_address_checks']==0 and p['state_only_forwarded_as_value']for p in a['state_use_footprints'])
 assert len(a['negative_source_controls'])==2 and all(p['result']=='sat'and not p['native_target_executed']for p in a['negative_source_controls'])
 contract=a['core_contract_consumed'];assert contract['sha256']==sha(ROOT/contract['artifact'])and contract['local_X0']=='0x00000000ffff5bbc'and contract['selected_path_premise_retained']and contract['ordinary_authenticated_return_to_nominal_caller_assumed']and not contract['native_return_established']
 assert e['direct_core_call']['canonical_target']=='0xfffffe000a635208'and e['direct_core_call']['nominal_return_PC']=='0xfffffe000a505300'
 rows=e['prefix_argument_custody'];assert len(rows)==30 and sum(len(p['cells'])for p in rows)==90
 assert [p['predecessor_case_index']for p in rows if p['selected_extent14']]==[5,15,25,35,45,55]
 for p in rows:
  assert p['entry_arguments64'][2]=='0x0'and not p['native_input_bytes_established']
  assert [r['known_and_provenance_bytes']for r in p['cells']]==[8,8,8]
 for b in e['caller']['bindings']:assert qword(int(b['slot'],16))==int(b['target'],16)
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 assert e['kernel_collection_sha256']==a['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 report=read(BASE/'userclient_zero_tag_provider_report.md');assert 'PENDING'not in report and CHECKS_SHA in report and AUDIT_SHA in report
 for j in range(1,8):assert '**QG'+str(j)+'**: Pass.'in report
 for j in range(1,9):assert '| ZP-A'+str(j)+':'in report and '| ZP'+str(j)+' |'in report
 for p in CHANGED:
  if p.endswith('.md'):assert 'userclient_zero_tag_provider_report.md'in read(BASE/p)
 for obj in [e,a]:
  hygiene(obj);nested_hygiene(obj);assert obj['conditional_zero_tag_provider_established']
  for k in R.FALSE:assert obj[k]is False
 for p in OWNED-{q+'.zst'for q in ARCHIVES}:
  if(BASE/p).exists():path_hygiene((BASE/p).read_bytes())
 print(json.dumps({'new_queries_rebuilt':20,'prior_queries_rechecked':67,'nullable_state_admissions':6,'former_model_exclusion':1,'source_controls':2,'argument_cells':90,'all_receipts_match':True}),flush=True);return e,a
def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']}for m in [old,new]);assert len(before)==9787 and len(after)==9793 and not before.keys()-after.keys()and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED and new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256']and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
 for key,value in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),('new_source_queries_unsat',20),('prior_queries_unsat',67),('negative_source_controls',2)]:assert new['validation'][R.P+'_'+key]==value
 assert new['validation']['reports']==old['validation']['reports']+1==664 and new['goal_status']=='active'
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 for p in ARCHIVES:assert not(BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4]if p.endswith('.zst')else p));path_hygiene(decoded.encode())
  if p.endswith('.json.zst'):obj=json.loads(decoded);hygiene(obj);nested_hygiene(obj)
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':664,'original_inputs_preserved':3,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)
if __name__=='__main__':publication(*receipts())
