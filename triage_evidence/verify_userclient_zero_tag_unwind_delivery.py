#!/usr/bin/env python3
"""Rebuild continuation/projection receipts and verify publication custody.
Linear owned-byte/corpus work; source SMT search has explicit query limits.
"""
import json
from hashlib import sha256
from compression import zstd
from kext_port_tools import ROOT,SOURCE,qword
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_daemon_payload_mix_publication import BASE,git,hygiene,path_hygiene
from verify_kernel_magazine_bootstrap_delivery import nested_hygiene
from verify_userclient_message_initialization_delivery import equivalent_queries
import recover_userclient_zero_tag_unwind as R
import audit_userclient_zero_tag_unwind as A
PREVIOUS='24c0521b4c47297b678a51310a288f689a94cabd'
BASELINE_SHA='bb0b9dcf34ab70d72c0d708450d897bd7777a8f4392868b2678d93eb1cb274fe'
CHECKS_SHA='2560e2a4bca0921c8f00a61717f25295c8d723f048c37880adefd1668fedc7f8'
AUDIT_SHA='f95f738d99cb877a7a5d4dfbf38930df700a00bd9ea7a4ad934b0c3ffafb0b8b'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED=['foundational_triage_report.md', 'interface_abi_report.md', 'interface_investigation_status.md', 'mach_ports_report.md', 'obfuscated_routines_report.md', 'triage_evidence/validate_rpc502_sidecar_delivery.py', 'userclient_caller_return_report.md', 'userclient_command_dispatch_report.md', 'userclient_fallback_metadata_report.md']
ADDED=['triage_evidence/audit_userclient_zero_tag_unwind.py', 'triage_evidence/recover_userclient_zero_tag_unwind.py', 'triage_evidence/userclient_zero_tag_unwind_audit.json', 'triage_evidence/userclient_zero_tag_unwind_checks.json', 'triage_evidence/verify_userclient_zero_tag_unwind_delivery.py', 'userclient_zero_tag_unwind_report.md']
ARCHIVES=['triage_evidence/interface_manifest.json', 'triage_evidence/userclient_zero_tag_unwind_audit.json', 'triage_evidence/userclient_zero_tag_unwind_checks.json']
OWNED=['foundational_triage_report.md', 'interface_abi_report.md', 'interface_investigation_status.md', 'mach_ports_report.md', 'obfuscated_routines_report.md', 'triage_evidence/audit_userclient_zero_tag_unwind.py', 'triage_evidence/interface_manifest.json.zst', 'triage_evidence/recover_userclient_zero_tag_unwind.py', 'triage_evidence/userclient_zero_tag_unwind_audit.json.zst', 'triage_evidence/userclient_zero_tag_unwind_checks.json.zst', 'triage_evidence/validate_rpc502_sidecar_delivery.py', 'triage_evidence/verify_userclient_zero_tag_unwind_delivery.py', 'userclient_caller_return_report.md', 'userclient_command_dispatch_report.md', 'userclient_fallback_metadata_report.md', 'userclient_zero_tag_unwind_report.md']
COUNTS={'source_spans': 27, 'captured_words': 536, 'carried_header_spans': 15, 'carried_header_words': 311, 'prefix_words': 2, 'prefix_states': 30, 'additional_prefix_bytes': 240, 'original_pointer_observations': 35, 'original_pointer_slots': 33, 'bank_rules': 7, 'bank_input_cases': 1792, 'controller_load_sites': 10, 'additional_alternate_retag_words': 1, 'fallback_extent_bytes': 14, 'new_container_extent_bytes': 16, 'body_length_values': 5, 'input_content_bytes_supplied': 0}
TOTALS={'new_source_queries_unsat': 18, 'semantic_contracts': 12, 'projection_queries_unsat': 136, 'source_entailed_domain_queries_unsat': 2, 'actual_cut_admission_SAT_queries': 10, 'prefix_queries_unsat': 1, 'prior_source_queries_unsat': 105, 'composed_source_words': 839, 'additional_source_words': 535, 'alternate_retag_words': 8, 'instruction_instances': 1151, 'negative_source_controls': 3, 'composed_modes': 2, 'live_register_views': 17, 'live_saved_cells': 31, 'entailed_normal_pointer_guards': 14, 'additional_prefix_cells': 30, 'additional_prefix_bytes': 240, 'restored_bytes': 14, 'ordinary_return_premises': 3, 'retirement_request_boundaries': 4, 'native_target_calls': 0, 'input_content_bytes_supplied': 0}

def compare_queries(old,new,field='query'):
 assert len(old)==len(new)
 for p,q in zip(old,new):
  p,q=dict(p),dict(q);equivalent_queries(p.pop(field),q.pop(field));assert p==q
CHANGED=set(CHANGED);ADDED=set(ADDED);ARCHIVES=set(ARCHIVES);OWNED=set(OWNED)
def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')));assert e==R.build();fresh=A.audit(e);x,y=dict(a),dict(fresh)
 for field in ['source_proofs','projection_proofs','source_entailed_domain_proofs','prefix_proofs','actual_cut_admission_checks']:compare_queries(x.pop(field),y.pop(field))
 compare_queries(x.pop('negative_source_controls'),y.pop('negative_source_controls'),'satisfiable_violation_query')
 assert x==y and e['verified_counts']==a['verified_counts']==COUNTS and a['independent_totals']==TOTALS
 for field in ['source_proofs','projection_proofs','source_entailed_domain_proofs','prefix_proofs']:assert all(p['result']=='unsat'and p['premises_nonvacuous']for p in a[field])
 assert len(a['source_proofs'])==18 and len(a['projection_proofs'])==136 and len(a['source_entailed_domain_proofs'])==2 and len(a['prefix_proofs'])==1
 assert len(a['actual_cut_admission_checks'])==10 and all(p['result']=='sat'and not p['native_reachability_established']for p in a['actual_cut_admission_checks'])
 assert len(a['rechecked_prior_source_proofs'])==105 and all(p['result']=='unsat'for p in a['rechecked_prior_source_proofs'])
 assert len(a['live_interfaces'])==2
 for p in a['live_interfaces']:assert len(p['live_register_views'])==17 and len(p['live_saved_cells'])==31 and p['source_written_protected_bytes']==14 and p['original_prefix_aliases_reconstructed']==['0x890','0x5a8']
 f=a['memory_footprint'];assert len(f['cells'])==78 and f['same_owner_disjoint_integer_pairs']==591 and f['all_accesses_classified']and f['retired_owner_accesses']==0 and f['workspace_retirement_pending']and f['original_input_write_indices']==list(range(13,-1,-1))
 assert f['retirement_order']==['typed_container','protected_buffer','context']==[p['retired_owner']for p in a['ordinary_return_premises']]
 for p in a['ordinary_return_premises']:assert p['ordinary_return_assumed']and p['callee_saved_SP_and_surviving_storage_preservation_assumed']and not p['native_effects_established']
 assert [p['mutated_PC']for p in a['negative_source_controls']]==['0xfffffe000a656ca8','0xfffffe000a6605e0','0xfffffe000a6660f0']and all(p['normal_oracle_rejected']and not p['native_target_executed']for p in a['negative_source_controls'])
 assert len(a['proved_pcs'])==839 and set(int(p,16)for p in a['proved_pcs']).isdisjoint(R.RETAGS.values())
 assert len(a['controller_read_PCs'])==10 and set(a['controller_read_PCs'])==set(map(hex,R.CONTROLLERS))and len(a['bank_execution_order'])==7
 assert len(a['source_edges'])==53 and a['source_edges'][-1]['source_PC']=='0xfffffe000a6662b0'
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 assert e['kernel_collection_sha256']==a['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 for p in e['source']['pointer_observations']:assert int(p['original_pointer']['target'],16)==qword(int(p['slot'],16))
 assert len(e['prefix_cells'])==30 and sum(p['size_bytes']for p in e['prefix_cells'])==240 and len(e['retirement_descriptors'])==2
 report=read(BASE/'userclient_zero_tag_unwind_report.md');assert 'PENDING'not in report and CHECKS_SHA in report and AUDIT_SHA in report
 for j in range(1,8):assert '**QG'+str(j)+'**: Pass.'in report
 for j in range(1,9):assert '| ZU-A'+str(j)+':'in report and '| ZU'+str(j)+' |'in report
 for p in CHANGED:
  if p.endswith('.md'):assert 'userclient_zero_tag_unwind_report.md'in read(BASE/p)
 for obj in [e,a]:
  hygiene(obj);nested_hygiene(obj);assert obj['conditional_zero_tag_unwind_established']is True
  for key in R.FALSE:assert obj[key]is False
 for p in OWNED-{q+'.zst'for q in ARCHIVES}:
  if(BASE/p).exists():path_hygiene((BASE/p).read_bytes())
 print(json.dumps({'source_queries_rebuilt':18,'projection_queries_rebuilt':136,'actual_cut_admission_SAT_checks':10,'prior_queries_rechecked':105,'composed_source_words':839,'source_mutation_controls':3,'restored_bytes':14,'native_target_calls':0,'all_receipts_match':True}),flush=True);return e,a
def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']}for m in [old,new]);assert len(before)==9775 and len(after)==9781 and not before.keys()-after.keys()and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED and new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256']and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
 for key,value in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),('new_source_queries_unsat',TOTALS['new_source_queries_unsat']),('prior_source_queries_unsat',TOTALS['prior_source_queries_unsat']),('negative_source_controls',3)]:assert new['validation'][R.P+'_'+key]==value
 assert new['validation']['reports']==old['validation']['reports']+1==662 and new['goal_status']=='active'
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 for p in ARCHIVES:assert not(BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4]if p.endswith('.zst')else p));path_hygiene(decoded.encode())
  if p.endswith('.json.zst'):obj=json.loads(decoded);hygiene(obj);nested_hygiene(obj)
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':662,'original_inputs_preserved':3,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)
if __name__=='__main__':publication(*receipts())
