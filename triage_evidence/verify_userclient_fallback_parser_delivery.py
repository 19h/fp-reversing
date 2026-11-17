#!/usr/bin/env python3
"""Rebuild fallback parser receipts and exact publication custody.
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
import recover_userclient_fallback_parser as R
import audit_userclient_fallback_parser as A
PREVIOUS='b1dddef6457e4a7d022b30637d80dd53a64fdd63'
BASELINE_SHA='bc1f89ca20693e0c4c7378c44f121e2a5466f273a26b390eb9e4c5f927fad215'
CHECKS_SHA='9ce8b6a8fb97684baa377e2b84807af8d91fdd92b54e3751adc79b4c4d51b54f'
AUDIT_SHA='a9eabdf76b55c214954776429c8cbcb31f2f5f44b5f365984dffdd0e53013386'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py','userclient_failure_fallback_report.md','userclient_container_staging_report.md','userclient_parser_cleanup_report.md','userclient_record_metadata_report.md'}
ADDED={'userclient_fallback_parser_report.md','triage_evidence/recover_userclient_fallback_parser.py','triage_evidence/audit_userclient_fallback_parser.py','triage_evidence/verify_userclient_fallback_parser_delivery.py','triage_evidence/userclient_fallback_parser_checks.json','triage_evidence/userclient_fallback_parser_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/userclient_fallback_parser_checks.json','triage_evidence/userclient_fallback_parser_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'source_spans': 19, 'captured_words': 467, 'prefix_words': 2, 'original_pointer_observations': 19, 'original_pointer_slots': 18, 'bank_rules': 1, 'certified_bank_inputs': 256, 'prefix_states': 30, 'additional_prefix_bytes': 240, 'fallback_extent_bytes': 14, 'new_container_extent_bytes': 16, 'restore_bytes_per_NULL_mode': 14, 'header_tag_bytes_per_nonnull_mode': 4, 'input_content_bytes_supplied': 0}
TOTALS={'new_source_queries_unsat': 470, 'semantic_contracts': 10, 'source_entailed_domain_queries_unsat': 10, 'retired_image_ownership_queries_unsat': 10, 'static_separation_queries_unsat': 5, 'prefix_queries_unsat': 1, 'prior_source_queries_unsat': 346, 'new_source_words_covered': 462, 'alternate_retag_words': 5, 'negative_source_controls': 3, 'composed_modes': 2, 'restored_bytes_per_NULL_mode': 14, 'header_bytes_per_nonnull_mode': 4, 'additional_prefix_cells': 30, 'additional_prefix_bytes': 240, 'native_target_calls': 0, 'input_content_bytes_supplied': 0}
def compare_queries(old,new,field):
 assert len(old)==len(new)
 for p,q in zip(old,new):
  p,q=dict(p),dict(q);equivalent_queries(p.pop(field),q.pop(field));assert p==q
def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')));assert e==R.build();fresh=A.audit(e);x,y=dict(a),dict(fresh)
 for field in ['source_proofs','source_entailed_domain_proofs','retired_image_ownership_proofs','static_separation_proofs','prefix_proofs']:compare_queries(x.pop(field),y.pop(field),'query')
 compare_queries(x.pop('negative_source_controls'),y.pop('negative_source_controls'),'satisfiable_violation_query')
 assert x==y and e['verified_counts']==a['verified_counts']==COUNTS and a['independent_totals']==TOTALS
 proofs=a['source_proofs'];assert len(proofs)==TOTALS['new_source_queries_unsat']and len({q['semantic_contract']for q in proofs})==10
 for name in {p['semantic_contract']for p in proofs}:
  qs=[p for p in proofs if p['semantic_contract']==name];assert [p['counterexample_partition']for p in qs]==list(range(1,len(qs)+1))and all(p['counterexample_partitions']==len(qs)and p['result']=='unsat'and p['premises_nonvacuous']for p in qs)
 assert len(a['source_entailed_domain_proofs'])==len(a['retired_image_ownership_proofs'])==10 and len(a['static_separation_proofs'])==5 and len(a['prefix_proofs'])==1
 assert len(a['rechecked_prior_source_proofs'])==346 and all(p['result']=='unsat'for p in a['rechecked_prior_source_proofs'])
 assert [p['mutated_PC']for p in a['negative_source_controls']]==['0xfffffe000a6420e4','0xfffffe000a6660f0','0xfffffe000a637174']and all(p['normal_oracle_rejected']and not p['native_target_executed']for p in a['negative_source_controls'])
 assert len(a['restored_indices'])==2 and all(x==list(range(13,-1,-1))for x in a['restored_indices'].values())
 assert len(a['new_buffer_reads'])==4
 for name,rows in a['new_buffer_reads'].items():assert [r['buffer_index']for r in rows]==(list(range(13,-1,-1))if name.endswith('restored')else[0,1,2,3])and all(r['live_new_buffer_epoch']for r in rows)
 assert not a['allocation_return']['native_target_executed']and a['allocation_return']['ordinary_callee_saved_SP_and_surviving_storage_preservation_assumed']
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 assert e['kernel_collection_sha256']==a['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 for q in e['source']['pointer_observations']:assert int(q['original_pointer']['target'],16)==qword(int(q['slot'],16))
 for q in e['bank_rules']:
  left,right=(bytes.fromhex(e['banks'][q[k]])for k in ['left','right']);assert all(j^right[left[j]^int(q['key'],16)]==int(q['constant'],16)for j in range(256))
 assert len(e['prefix_cells'])==30 and sum(p['size_bytes']for p in e['prefix_cells'])==240
 report=read(BASE/'userclient_fallback_parser_report.md');assert 'PENDING'not in report and CHECKS_SHA in report and AUDIT_SHA in report
 for j in range(1,8):assert '**QG'+str(j)+'**: Pass.'in report
 for j in range(1,9):assert '| FP-A'+str(j)+':'in report and '| FP'+str(j)+' |'in report
 for p in CHANGED:
  if p.endswith('.md'):assert 'userclient_fallback_parser_report.md'in read(BASE/p)
 for obj in [e,a]:
  hygiene(obj);nested_hygiene(obj);assert obj['conditional_fallback_parser_established']is True
  for key in R.FALSE:assert obj[key]is False
 for p in OWNED-{q+'.zst'for q in ARCHIVES}:
  if(BASE/p).exists():path_hygiene((BASE/p).read_bytes())
 print(json.dumps({'source_queries_rebuilt':len(proofs),'semantic_contracts':10,'prior_queries_rechecked':346,'source_words_composed':462,'alternate_retag_words_unexecuted':5,'source_mutation_controls':3,'restored_bytes_per_NULL_mode':14,'header_tag_bytes_per_nonnull_mode':4,'native_target_calls':0,'all_receipts_match':True}),flush=True);return e,a
def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']}for m in [old,new]);assert len(before)==9763 and len(after)==9769 and not before.keys()-after.keys()and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED and new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256']and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
 for key,value in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),('new_source_queries_unsat',TOTALS['new_source_queries_unsat']),('prior_source_queries_unsat',346),('negative_source_controls',3)]:assert new['validation'][R.P+'_'+key]==value
 assert new['validation']['reports']==old['validation']['reports']+1==660 and new['goal_status']=='active'
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 for p in ARCHIVES:assert not(BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4]if p.endswith('.zst')else p));path_hygiene(decoded.encode())
  if p.endswith('.json.zst'):obj=json.loads(decoded);hygiene(obj);nested_hygiene(obj)
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':660,'original_inputs_preserved':3,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)
if __name__=='__main__':publication(*receipts())
