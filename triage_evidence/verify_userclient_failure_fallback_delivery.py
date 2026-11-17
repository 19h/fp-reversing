#!/usr/bin/env python3
"""Rebuild failure fallback proofs and verify exact publication custody.
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
import recover_userclient_failure_fallback as R
import audit_userclient_failure_fallback as A
PREVIOUS='2fee638aaee73536a8115420d66a3e41243f6d51'
BASELINE_SHA='78e17afad63a700e24902501b6cc9cfa18ebf994e7823788a21420011a201334'
CHECKS_SHA='5df0f69a8c378790121a13ddb8f30576e1cb079ab60a08f8436e3db6cfee11b1'
AUDIT_SHA='fb5f2768dade65ef0a761e8dcc1522b9e2dde0b56350d49c769a3866b72c882c'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'interface_investigation_status.md','interface_abi_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','userclient_message_failure_report.md','userclient_message_parser_report.md','userclient_container_staging_report.md','userclient_parser_cleanup_report.md','userclient_entry_execution_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'userclient_failure_fallback_report.md','triage_evidence/recover_userclient_failure_fallback.py','triage_evidence/audit_userclient_failure_fallback.py','triage_evidence/verify_userclient_failure_fallback_delivery.py','triage_evidence/userclient_failure_fallback_checks.json','triage_evidence/userclient_failure_fallback_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/userclient_failure_fallback_checks.json','triage_evidence/userclient_failure_fallback_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'source_spans': 21, 'captured_words': 504, 'prefix_and_qualified_cut_words': 68, 'bank_rules': 11, 'certified_bank_inputs': 2816, 'original_pointer_observations': 28, 'original_pointer_slots': 25, 'prefix_states': 30, 'additional_cells_per_state': 11, 'additional_cell_bytes_per_state': 84, 'record_extent_bytes': 14, 'node_extent_bytes': 32, 'container_extent_bytes': 16, 'context_extent_bytes': 4096, 'workspace_extent_bytes': 16384, 'fallback_extent_bytes': 14, 'input_content_bytes_supplied': 0}
TOTALS={'new_source_queries_unsat': 1034, 'new_semantic_contracts': 14, 'prefix_and_qualified_cut_queries_unsat': 3, 'prior_source_queries_unsat': 74, 'new_source_words_covered': 503, 'alternate_retag_word_covered_by_prior_proof': 1, 'lifted_instruction_instances': 8102540, 'composed_modes': 2, 'new_retirement_returns_before_fallback_per_mode': 3, 'new_retirement_requests_NULL_fallback_per_mode': 5, 'additional_prefix_cells_reconstructed': 330, 'additional_prefix_bytes_reconstructed': 2520, 'protected_copy_bytes_per_nonnull_mode': 14, 'new_controller_reads_NULL_mode': 12, 'new_controller_reads_nonnull_mode': 10, 'new_bank_applications_NULL_mode': 9, 'new_bank_applications_nonnull_mode': 8, 'negative_source_controls': 3, 'retired_address_reuse_SAT_checks': 10, 'input_content_bytes_supplied': 0, 'native_target_calls': 0, 'static_image_separation_queries_unsat': 5, 'source_entailed_extent_domain_queries_unsat': 14, 'retired_image_ownership_queries_unsat': 14}
def compare_queries(old,new,field):
 assert len(old)==len(new)
 for p,q in zip(old,new):
  p,q=dict(p),dict(q);equivalent_queries(p.pop(field),q.pop(field));assert p==q
def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')));assert e==R.build();fresh=A.audit(e);x,y=dict(a),dict(fresh)
 for field in ['source_proofs','source_entailed_extent_domain_proofs','retired_image_ownership_proofs','prefix_and_qualified_cut_proofs','static_image_separation_proofs']:
  compare_queries(x.pop(field),y.pop(field),'query')
 compare_queries(x.pop('negative_source_controls'),y.pop('negative_source_controls'),'satisfiable_violation_query')
 assert x==y and e['verified_counts']==a['verified_counts']==COUNTS and a['independent_totals']==TOTALS
 proofs=a['source_proofs'];assert len(proofs)==TOTALS['new_source_queries_unsat']and len({q['semantic_contract']for q in proofs})==14
 for name in {p['semantic_contract']for p in proofs}:
  qs=[p for p in proofs if p['semantic_contract']==name];assert [p['counterexample_partition']for p in qs]==list(range(1,len(qs)+1))and all(p['counterexample_partitions']==len(qs)and p['result']=='unsat'and p['premises_nonvacuous']for p in qs)
 assert len(a['prefix_and_qualified_cut_proofs'])==3 and len(a['static_image_separation_proofs'])==5
 assert len(a['source_entailed_extent_domain_proofs'])==14 and all(q['source_entailed_bindings']=={'EU_outer_size32':14,'EW_L':4}and q['result']=='unsat'for q in a['source_entailed_extent_domain_proofs'])
 assert len(a['retired_image_ownership_proofs'])==14 and all(q['premises_nonvacuous']and q['result']=='unsat'for q in a['retired_image_ownership_proofs'])
 assert len(a['rechecked_prior_source_proofs'])==74 and all(q['result']=='unsat'for q in a['rechecked_prior_source_proofs'])
 assert [p['mutated_PC']for p in a['negative_source_controls']]==['0xfffffe000a6605e0','0xfffffe000a641ce8','0xfffffe000a641e44']and all(p['normal_oracle_rejected']and not p['native_target_executed']for p in a['negative_source_controls'])
 assert len(a['retired_address_reuse_checks'])==10 and all(r['new_epoch_premises_satisfiable']and not r['native_reuse_observed']for r in a['retired_address_reuse_checks'])
 assert len(a['copied_input_indices'])==2 and all(indices==list(range(13,-1,-1))for indices in a['copied_input_indices'].values())
 for name,calls in a['API_returns'].items():assert [c['kind']for c in calls]==(['record','node','container','allocate','context']if name.endswith('_workspace')else['record','node','container','allocate'])and all(not c['native_target_executed']and not c['retired_object_storage_preservation_assumed']for c in calls)
 for rows in a['static_image_reads'].values():
  for r in rows:assert r['retired_extent_separation_lemma_applied']and int(r['image_segment_start'],16)<=int(r['admitted_range_start'],16)and int(r['admitted_range_start'],16)+r['admitted_range_bytes']<=int(r['image_segment_start'],16)+r['image_segment_bytes']
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 assert e['kernel_collection_sha256']==a['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 for q in e['source']['pointer_observations']:assert int(q['original_pointer']['target'],16)==qword(int(q['slot'],16))
 for q in e['bank_rules']:
  left,right=(bytes.fromhex(e['banks'][q[k]])for k in ['left','right']);assert all(j^right[left[j]^int(q['key'],16)]==int(q['constant'],16)for j in range(256))
 assert len(e['prefix_cells'])==30 and all(len(p['source_defined_cells'])==11 and sum(c['size_bytes']for c in p['source_defined_cells'])==84 for p in e['prefix_cells'])
 report=read(BASE/'userclient_failure_fallback_report.md');assert 'PENDING'not in report and CHECKS_SHA in report and AUDIT_SHA in report
 for j in range(1,8):assert '**QG'+str(j)+'**: Pass.'in report
 for j in range(1,9):assert '| FF-A'+str(j)+':'in report and '| FF'+str(j)+' |'in report
 for p in CHANGED:
  if p.endswith('.md'):assert 'userclient_failure_fallback_report.md'in read(BASE/p)
 for obj in [e,a]:
  hygiene(obj);nested_hygiene(obj);assert obj['conditional_failure_fallback_established']is True
  for key in R.FALSE:assert obj[key]is False
 for p in OWNED-{q+'.zst'for q in ARCHIVES}:
  if(BASE/p).exists():path_hygiene((BASE/p).read_bytes())
 print(json.dumps({'source_queries_rebuilt':len(proofs),'semantic_contracts':14,'prefix_and_qualified_cut_queries':3,'static_image_separation_queries':5,'prior_queries_rechecked':74,'source_words':504,'source_mutation_controls':3,'retired_address_reuse_SAT_checks':10,'input_content_bytes_supplied':0,'all_receipts_match':True}),flush=True);return e,a
def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']}for m in [old,new]);assert len(before)==9757 and len(after)==9763 and not before.keys()-after.keys()and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED and new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256']and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
 for key,value in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),('new_source_queries_unsat',TOTALS['new_source_queries_unsat']),('prior_source_queries_unsat',74),('negative_source_controls',3),('prefix_and_qualified_cut_queries_unsat',3),('retired_address_reuse_SAT_checks',10)]:assert new['validation'][R.P+'_'+key]==value
 assert new['validation']['reports']==old['validation']['reports']+1==659 and new['goal_status']=='active'
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 for p in ARCHIVES:assert not(BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4]if p.endswith('.zst')else p));path_hygiene(decoded.encode())
  if p.endswith('.json.zst'):obj=json.loads(decoded);hygiene(obj);nested_hygiene(obj)
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':659,'original_inputs_preserved':3,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)
if __name__=='__main__':publication(*receipts())
