#!/usr/bin/env python3
"""Fresh original-source contracts, private byte witnesses and publication.
O(owned bytes + source + formula DAG + journals + mapped bytes) construction/
space; SMT search separate. No native execution, IDB or history mutation.
"""
import json,re
from hashlib import sha256
from compression import zstd
import z3
from kext_port_tools import ROOT,SOURCE
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_daemon_payload_mix_publication import BASE,git,hygiene,path_hygiene
from verify_daemon_second_mix_publication import canonical_expression
from verify_kernel_magazine_bootstrap_delivery import nested_hygiene
import recover_kernel_cpu_topology_handoff as R
import audit_kernel_cpu_topology_handoff as A
PREVIOUS='df6a898b3eba532197991c0c47bd7f6865e9503d'
BASELINE_SHA='8a01dd7ae8c37f5a3ffa5ced82befb1106619af699eb020563b9b26cfbecba88'
CHECKS_SHA='19aaee1b05784059be3759ece2f2be885199ad37637bdaf45fd27887dca1bf0a'
AUDIT_SHA='e89a176ac14cb56abd6fbe993080960652deda0132b9358e104f640cb03275d5'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','kernel_boot_cpu_identity_report.md','kernel_boot_header_handoff_report.md','kernel_mapping_context_report.md','kernel_sptm_boot_inputs_report.md','mach_ports_report.md','obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'kernel_cpu_topology_handoff_report.md','triage_evidence/recover_kernel_cpu_topology_handoff.py',
 'triage_evidence/probe_kernel_cpu_topology_handoff.py','triage_evidence/replay_kernel_cpu_topology_handoff.py',
 'triage_evidence/audit_kernel_cpu_topology_handoff.py','triage_evidence/verify_kernel_cpu_topology_handoff_delivery.py',
 'triage_evidence/kernel_cpu_topology_handoff_checks.json','triage_evidence/kernel_cpu_topology_handoff_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/kernel_cpu_topology_handoff_checks.json','triage_evidence/kernel_cpu_topology_handoff_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'captured_functions': 17, 'captured_words': 3356, 'captured_bytes': 13424, 'matched_prior_functions': 10, 'captured_strings': 28, 'logical_data_blocks': 18, 'opaque_words_preserved': 3, 'original_pointer_fixups': 3}
TOTALS={'source_queries_unsat': 24, 'prior_source_queries_rechecked': 4, 'proved_source_PCs': 99, 'proof_instruction_instances': 99, 'linked_edge_obligations': 75, 'components': 23, 'source_visits': 29359, 'executed_source_PCs': 1062, 'changed_source_controls': 5, 'independent_topology_and_post_helper_checks': 3114, 'independent_thread_handoff_checks': 1104, 'completed_admitted_CPU_records': 39, 'source_boot_record_handoffs': 13, 'same_RAM_explicit_caller_epochs': 12, 'original_comparison_entries': 46, 'declared_selector0e_calls': 39, 'original_post_helper_returns': 12, 'independent_topology_nonstack_bytes_checked': 7806976, 'independent_post_helper_nonstack_bytes_checked': 4468736, 'independent_thread_nonstack_bytes_checked': 4128768}
REPLAY={'source_visits_checked': 29359, 'reads_checked': 6936, 'writes_checked': 6816, 'declared_models_checked': 929, 'logical_effects_checked': 599, 'same_RAM_epochs_checked': 12, 'whole_mapped_bytes_checked': 7901184, 'original_comparison_entries_checked': 46, 'declared_selector0e_calls_checked': 39, 'source_boot_record_handoffs_checked': 13, 'original_post_helper_returns_checked': 12}

def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
 assert e==R.build();fresh=A.audit()
 for key,count in [('source_proofs',24),('rechecked_prior_source_proofs',4)]:
  old,new=a.pop(key),fresh.pop(key);assert len(old)==len(new)==count
  for x,y in zip(old,new):
   x,y=dict(x),dict(y);p,q=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'));assert x==y and x['premises_nonvacuous'] and x['result']=='unsat'
   assert len(p)==len(q)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(p,q))
 assert a==fresh and e['verified_counts']==COUNTS and a['independent_totals']==TOTALS and a['independent_replay_totals']==REPLAY
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 assert e['kernel_collection_sha256']==a['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 assert [p['target'] for p in e['pointer_fixups']]==list(map(hex,[R.B.ARRAY,R.B.CLUSTERS,R.B.SLOT]))
 for address,names in [(R.COMPARE,{'_strncmp'}),(R.LOOKUP,{'_SecureDTLookupEntry'}),(R.ITERATE,{'_SecureDTIterateEntries'}),(R.B.COPY,{'_memcpy','_memmove'})]:assert {r['name'] for r in e['exact_symbols'][hex(address)]}==names
 coverage={r['start']:r for r in a['executed_function_coverage']}
 for address,captured,executed in [(R.B.ENUM,969,760),(R.COMPARE,99,17),(R.POST,34,34)]:assert coverage[hex(address)]=={'start':hex(address),'captured_words':captured,'executed_unique_PCs':executed}
 assert not {p['PC'] for p in e['opaque_words']}&{p['PC'] for c in a['components'] for p in c['source_visits']}
 assert {p['PC'] for p in e['opaque_words']}=={'0xfffffe000c63a3c0','0xfffffe000c620ee4','0xfffffe000c620eec'}
 assert sum(len(c['original_copy_entries']) for c in a['components'])==12
 byname={c['configuration']['label']:c for c in a['components']}
 c=byname['sixteen_CPUs_boot_ordinal15'];assert c['independent_oracle']['selected_boot_ordinal']==15 and c['start']=='0xfffffe000c639cb8'
 assert c['source_boot_record_snapshots'][0]['record_pointer']==hex(R.B.ARRAY+15*136)
 assert c['source_boot_record_snapshots'][0]['PC']=='0xfffffe000c639cbc' and c['source_main_continuation_checkpoints'][0]['PC']=='0xfffffe000c639cc0'
 assert len(c['epochs'])==1 and c['epochs'][0]['PC']=='0xfffffe000c639dd8' and c['epochs'][0]['kind']=='bootstrap_to_CPU_caller_cut'
 assert byname['prefix_matches_overwrite_boot_pointer_and_merge_PM']['independent_oracle']['selected_boot_ordinal']==2
 assert byname['post_enumeration_control4_diagnostic']['independent_oracle']['diagnostic_reason']=='post_enumeration_control_out_of_range'
 report=read(BASE/'kernel_cpu_topology_handoff_report.md')
 for j in range(1,8):assert '**QG'+str(j)+'**' in report and '| TH'+str(j)+' |' in report and '| TH-A'+str(j)+':' in report
 for item in [CHECKS_SHA,AUDIT_SHA,'4218 total','7901184','7806976','4468736','4128768','760/969','0xfffffe000c639cbc','0xfffffe000be85a94','siq_realtime_thread_mode']:assert item in report
 assert 'one in the captured main continuation and two in the lower wrapper' in read(BASE/'kernel_boot_cpu_identity_report.md')
 for p in CHANGED:
  if p.endswith('.md'):assert 'kernel_cpu_topology_handoff_report.md' in read(BASE/p)
 for obj in [e,a]:
  hygiene(obj);nested_hygiene(obj);assert obj['conditional_kernel_cpu_topology_handoff_contract_established']
  for name in R.FALSE:assert obj[name] is False
 print(json.dumps({'fresh_source_and_audit_match':True,'nonvacuous_queries_rebuilt_and_resolved':24,'prior_source_queries_rechecked':4,
  'private_components_rebuilt':23,'independent_semantic_checks':4218,'changed_source_controls_rejected':5,'original_post_helper_returns_checked':12,
  'native_target_executed':False}),flush=True)
 return e,a

def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']} for m in [old,new])
 assert len(before)==9470 and len(after)==9478 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED
 assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256'] and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
 for name,value in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),('independent_replay_checks',REPLAY),
  ('new_source_queries_unsat',24),('prior_source_queries_rechecked',4),('conditional_kernel_cpu_topology_handoff_contract_established',True)]:assert new['validation'][R.P+'_'+name]==value
 assert new['validation']['reports']==old['validation']['reports']+1==620
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references'] and new['goal_status']=='active'
 for p in ARCHIVES:assert not (BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode();path_hygiene(decoded)
  assert not re.search(rb'/(?:Users/(?!Shared(?:/|\b))|home/|tmp/|private/|Library[/]Developer/|opt[/]homebrew/)',decoded)
 path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':620,
  'original_inputs_preserved':3,'analyst_paths_absent':True,**COUNTS,**TOTALS,'all_checks_pass':True}),flush=True)

if __name__=='__main__':publication(*receipts())
