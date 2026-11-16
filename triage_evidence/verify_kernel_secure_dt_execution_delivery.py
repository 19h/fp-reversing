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
import recover_kernel_secure_dt_execution as R
import audit_kernel_secure_dt_execution as A
PREVIOUS='73408a5dccb93bfa9ab4343bac61a0ba6427874b'
BASELINE_SHA='1d23f6c6e34781174afdde0a4ff6bdfcf2ffa038cf10bc7c7a04e403dea69309'
CHECKS_SHA='adb233d79b161abf21d40ccc4c8a2ea4c474017bfb259d7609a2d7f44dc09b96'
AUDIT_SHA='d36eae06782d08b26d2575f400ab87d45e2228f772a165955b7632d841c8f71c'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'interface_investigation_status.md', 'foundational_triage_report.md', 'interface_abi_report.md', 'triage_evidence/validate_rpc502_sidecar_delivery.py', 'kernel_sptm_boot_inputs_report.md', 'obfuscated_routines_report.md', 'mach_ports_report.md', 'kernel_boot_header_handoff_report.md', 'kernel_cpu_topology_handoff_report.md', 'kernel_mapping_context_report.md'}
ADDED={'kernel_secure_dt_execution_report.md','triage_evidence/recover_kernel_secure_dt_execution.py',
 'triage_evidence/probe_kernel_secure_dt_execution.py','triage_evidence/replay_kernel_secure_dt_execution.py',
 'triage_evidence/audit_kernel_secure_dt_execution.py','triage_evidence/verify_kernel_secure_dt_execution_delivery.py',
 'triage_evidence/kernel_secure_dt_execution_checks.json','triage_evidence/kernel_secure_dt_execution_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/kernel_secure_dt_execution_checks.json','triage_evidence/kernel_secure_dt_execution_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'captured_functions': 20, 'captured_words': 3469, 'captured_bytes': 13876, 'matched_prior_functions': 17, 'captured_strings': 28, 'logical_data_blocks': 18, 'original_pointer_fixups': 3, 'opaque_words_preserved': 3}
TOTALS={'source_queries_unsat': 20, 'prior_source_queries_rechecked': 4, 'proved_source_PCs': 72, 'proof_instruction_instances': 72, 'linked_edge_obligations': 52, 'components': 11, 'source_visits': 152252, 'executed_source_PCs': 1472, 'changed_source_controls': 4, 'independent_semantic_checks': 7728, 'original_tree_API_calls': 2880, 'original_tree_API_returns': 2880, 'dedicated_API_calls': 11, 'original1472_byte_copies': 7, 'tree_initializer_returns': 11, 'source_boot_record_handoffs': 7, 'original_post_helper_returns': 7}
REPLAY={'source_visits_checked': 152252, 'reads_checked': 28608, 'writes_checked': 12550, 'declared_models_checked': 96, 'logical_effects_checked': 1750, 'same_RAM_epochs_checked': 28, 'whole_mapped_bytes_checked': 3821568, 'original_tree_API_entries_checked': 2880, 'original_tree_call_returns_checked': 2880, 'original_tree_API_returns_checked': 11, 'tree_initializer_returns_checked': 11}

def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
 assert e==R.build();fresh=A.audit()
 for key,count in [('source_proofs',20),('rechecked_prior_source_proofs',4)]:
  old,new=a.pop(key),fresh.pop(key);assert len(old)==len(new)==count
  for x,y in zip(old,new):
   x,y=dict(x),dict(y);p,q=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'));assert x==y and x['premises_nonvacuous'] and x['result']=='unsat'
   assert len(p)==len(q)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(p,q))
 assert a==fresh and e['verified_counts']==COUNTS and a['independent_totals']==TOTALS and a['independent_replay_totals']==REPLAY
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 assert e['kernel_collection_sha256']==a['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 prior=json.loads(read(ROOT/(R.B.P+'_checks.json')));assert e['functions'][:17]==prior['functions'] and e['pointer_fixups']==prior['pointer_fixups'] and e['opaque_words']==prior['opaque_words']
 for address,names in [(R.STRCMP,{'_strcmp'}),(R.B.COMPARE,{'_strncmp'}),(R.B.LOOKUP,{'_SecureDTLookupEntry'}),(R.B.ITERATE,{'_SecureDTIterateEntries'})]:assert {r['name'] for r in e['exact_symbols'][hex(address)]}==names
 coverage={r['start']:r for r in a['executed_function_coverage']}
 for address,captured,executed in [(R.INIT,27,15),(R.SKIP,74,47),(R.STRCMP,12,12),(R.B.LOOKUP,166,128),(R.B.PROPERTY,106,74),(R.B.ITERATE,97,67),(R.B.FIND,138,97)]:assert coverage[hex(address)]=={'start':hex(address),'captured_words':captured,'executed_unique_PCs':executed}
 assert not {p['PC'] for p in e['opaque_words']}&{p['PC'] for c in a['components'] for p in c['source_visits']}
 forbidden={R.INIT,R.SKIP,R.STRCMP,R.B.LOOKUP,R.B.PROPERTY,R.B.ITERATE,R.B.FIND}
 for c in a['components']:
  assert c['start']==hex(R.INIT) and c['tree_initializer_return'] and len(c['original_tree_call_returns'])==len(c['original_tree_API_entries'])
  assert not {int(m['PC'],16) for m in c['declared_models']}&forbidden
  assert all(x['kind'] in ['tree_initializer_to_main_cut','bootstrap_to_CPU_caller_cut','explicit_tree_API_call'] for x in c['epochs'])
  assert len(c['independent_oracle']['original_API_contracts']['checks'])>0
 byname={c['configuration']['label']:c for c in a['components']}
 c=byname['sixteen_CPUs'];assert c['independent_oracle']['topology']['selected_boot_ordinal']==15
 assert c['source_boot_record_snapshots'][0]['record_pointer']==hex(R.B.B.ARRAY+15*136) and len(c['epochs'])==2
 assert [x['PC'] for x in c['epochs']]==['0x650000e000','0xfffffe000c639dd8']
 c=byname['API_lookup_property_and_subtree'];assert len(c['tree_API_returns'])==11 and c['declared_models']==[]
 assert [int(c['tree_API_returns'][j]['registers'][0],16) for j in [5,7]]==[0xffffffff,0xffffffff]
 assert byname['missing_CPUs_root_fallback']['independent_oracle']['topology']['diagnostic_reason']=='state_absent'
 report=read(BASE/'kernel_secure_dt_execution_report.md')
 for j in range(1,8):assert '**QG'+str(j)+'**' in report and '| DT'+str(j)+' |' in report and '| DT-A'+str(j)+':' in report
 for item in [CHECKS_SHA,AUDIT_SHA,'7728','2880','152252','3821568','3604480','3448832','2437120','727/969','0xfffffe000cba40e8','0xffffffff']:assert item in report
 for p in CHANGED:
  if p.endswith('.md'):assert 'kernel_secure_dt_execution_report.md' in read(BASE/p)
 for obj in [e,a]:
  hygiene(obj);nested_hygiene(obj);assert obj['conditional_kernel_secure_dt_execution_contract_established']
  for name in R.FALSE:assert obj[name] is False
 print(json.dumps({'fresh_source_and_audit_match':True,'nonvacuous_queries_rebuilt_and_resolved':20,'prior_source_queries_rechecked':4,'private_components_rebuilt':11,'independent_semantic_checks':7728,'changed_source_controls_rejected':4,'original_tree_API_calls_and_returns_checked':2880,'native_target_executed':False}),flush=True)
 return e,a

def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']} for m in [old,new])
 assert len(before)==9478 and len(after)==9486 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED
 assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256'] and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
 for name,value in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),('independent_replay_checks',REPLAY),
  ('new_source_queries_unsat',20),('prior_source_queries_rechecked',4),('conditional_kernel_secure_dt_execution_contract_established',True)]:assert new['validation'][R.P+'_'+name]==value
 assert new['validation']['reports']==old['validation']['reports']+1==621
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references'] and new['goal_status']=='active'
 for p in ARCHIVES:assert not (BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode();path_hygiene(decoded)
  assert not re.search(rb'/(?:Users/(?!Shared(?:/|\b))|home/|tmp/|private/|Library[/]Developer/|opt[/]homebrew/)',decoded)
 path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':621,
  'original_inputs_preserved':3,'analyst_paths_absent':True,**COUNTS,**TOTALS,'all_checks_pass':True}),flush=True)

if __name__=='__main__':publication(*receipts())
