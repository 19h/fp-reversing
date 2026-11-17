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
import recover_userclient_fallback_metadata as R
import audit_userclient_fallback_metadata as A
PREVIOUS='ae774c7c74896c675e6b0ba0105f57b0d637c27a'
BASELINE_SHA='503a6ed2963f2203e08c457ec4541e9c1b615a2a3dbb13881411a44335f2da99'
CHECKS_SHA='4c3e3078ec44ee3b54ad6656fb72b3b7da17375e2250bbcdb1d19c45903678bb'
AUDIT_SHA='d1dad65a824851f34076fc4afd20c254a49c6f9f02c4730fe20adbcf0d225e82'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py','userclient_fallback_parser_report.md','userclient_record_metadata_report.md','userclient_container_staging_report.md'}
ADDED={'userclient_fallback_metadata_report.md','triage_evidence/recover_userclient_fallback_metadata.py','triage_evidence/audit_userclient_fallback_metadata.py','triage_evidence/verify_userclient_fallback_metadata_delivery.py','triage_evidence/userclient_fallback_metadata_checks.json','triage_evidence/userclient_fallback_metadata_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/userclient_fallback_metadata_checks.json','triage_evidence/userclient_fallback_metadata_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'source_spans':15,'captured_words':311,'prefix_words':2,'original_pointer_observations':16,'original_pointer_slots':16,'alternate_retag_words':7,'prefix_states':30,'additional_prefix_bytes':240,'fallback_extent_bytes':14,'header_bytes':10,'new_header_byte_indices':[4,5,6,7,8,9],'new_container_extent_bytes':16,'input_content_bytes_supplied':0}
TOTALS={'new_source_queries_unsat':24,'semantic_contracts':17,'projection_queries_unsat':78,'source_entailed_domain_queries_unsat':2,'actual_cut_admission_SAT_queries':16,'prefix_queries_unsat':1,'prior_source_queries_unsat':80,'new_source_words_covered':304,'alternate_retag_words':7,'negative_source_controls':3,'composed_modes':2,'live_register_views':15,'live_saved_cells':8,'entailed_normal_pointer_guards':7,'additional_prefix_cells':30,'additional_prefix_bytes':240,'header_bytes':10,'new_header_byte_reads':6,'native_target_calls':0,'input_content_bytes_supplied':0}
def compare_queries(old,new,field='query'):
 assert len(old)==len(new)
 for p,q in zip(old,new):
  p,q=dict(p),dict(q);equivalent_queries(p.pop(field),q.pop(field));assert p==q
def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')));assert e==R.build();fresh=A.audit(e);x,y=dict(a),dict(fresh)
 for field in ['source_proofs','projection_proofs','source_entailed_domain_proofs','prefix_proofs','actual_cut_admission_checks']:compare_queries(x.pop(field),y.pop(field))
 compare_queries(x.pop('negative_source_controls'),y.pop('negative_source_controls'),'satisfiable_violation_query')
 assert x==y and e['verified_counts']==a['verified_counts']==COUNTS and a['independent_totals']==TOTALS
 assert all(p['result']=='unsat'and p['premises_nonvacuous']for field in ['source_proofs','projection_proofs','source_entailed_domain_proofs','prefix_proofs']for p in a[field])
 assert len(a['source_proofs'])==TOTALS['new_source_queries_unsat']and len(a['projection_proofs'])==TOTALS['projection_queries_unsat']
 assert len(a['actual_cut_admission_checks'])==16 and all(p['result']=='sat'and not p['native_reachability_established']for p in a['actual_cut_admission_checks'])
 assert len(a['rechecked_prior_source_proofs'])==TOTALS['prior_source_queries_unsat']and all(p['result']=='unsat'for p in a['rechecked_prior_source_proofs'])
 assert len(a['live_interfaces'])==2
 assert len(a['memory_footprint']['cells'])==26 and a['memory_footprint']['same_owner_disjoint_integer_pairs']==70 and a['memory_footprint']['all_accesses_classified']and a['memory_footprint']['no_continuation_store_to_B_or_T']
 assert 'whole_fallback_header_completed'not in e and 'whole_fallback_header_completed'not in a
 for p in a['live_interfaces']:assert len(p['live_register_views'])==TOTALS['live_register_views']and len(p['live_saved_cells'])==TOTALS['live_saved_cells']and p['original_prefix_alias_reconstructed']and p['source_written_protected_bytes']==10
 assert [p['mutated_PC']for p in a['negative_source_controls']]==['0xfffffe000a6393bc','0xfffffe000a63dce0','0xfffffe000a660ad0']and all(p['normal_oracle_rejected']and not p['native_target_executed']for p in a['negative_source_controls'])
 assert len(a['proved_pcs'])==TOTALS['new_source_words_covered']and set(int(p,16)for p in a['proved_pcs']).isdisjoint(R.RETAGS.values())
 for row in a['proof_coverage']:assert row['protected_read_indices']==[4,5]or row['protected_read_indices']==[4,5,6,7,8,9]
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 assert e['kernel_collection_sha256']==a['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 for p in e['source']['pointer_observations']:assert int(p['original_pointer']['target'],16)==qword(int(p['slot'],16))
 assert len(e['prefix_cells'])==30 and sum(p['size_bytes']for p in e['prefix_cells'])==240
 assert a['selected_completion_edges'][-1]['source_PC']=='0xfffffe000a660af0'
 report=read(BASE/'userclient_fallback_metadata_report.md');assert 'PENDING'not in report and CHECKS_SHA in report and AUDIT_SHA in report
 for j in range(1,8):assert '**QG'+str(j)+'**: Pass.'in report
 for j in range(1,9):assert '| FM-A'+str(j)+':'in report and '| FM'+str(j)+' |'in report
 for p in CHANGED:
  if p.endswith('.md'):assert 'userclient_fallback_metadata_report.md'in read(BASE/p)
 for obj in [e,a]:
  hygiene(obj);nested_hygiene(obj);assert obj['conditional_fallback_metadata_established']is True
  for key in R.FALSE:assert obj[key]is False
 for p in OWNED-{q+'.zst'for q in ARCHIVES}:
  if(BASE/p).exists():path_hygiene((BASE/p).read_bytes())
 print(json.dumps({'source_queries_rebuilt':len(a['source_proofs']),'projection_queries_rebuilt':len(a['projection_proofs']),'actual_cut_admission_SAT_checks':16,'prior_queries_rechecked':len(a['rechecked_prior_source_proofs']),'source_words_composed':TOTALS['new_source_words_covered'],'source_mutation_controls':3,'native_target_calls':0,'all_receipts_match':True}),flush=True);return e,a
def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']}for m in [old,new]);assert len(before)==9769 and len(after)==9775 and not before.keys()-after.keys()and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED and new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256']and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
 for key,value in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),('new_source_queries_unsat',TOTALS['new_source_queries_unsat']),('prior_source_queries_unsat',TOTALS['prior_source_queries_unsat']),('negative_source_controls',3)]:assert new['validation'][R.P+'_'+key]==value
 assert new['validation']['reports']==old['validation']['reports']+1==661 and new['goal_status']=='active'
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 for p in ARCHIVES:assert not(BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4]if p.endswith('.zst')else p));path_hygiene(decoded.encode())
  if p.endswith('.json.zst'):obj=json.loads(decoded);hygiene(obj);nested_hygiene(obj)
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':661,'original_inputs_preserved':3,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)
if __name__=='__main__':publication(*receipts())
