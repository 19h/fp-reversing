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
import recover_kernel_boot_option_execution as R
import audit_kernel_boot_option_execution as A
PREVIOUS='22c8fc47e8a4faaffb4896e7ccd19a553f7c9681'
BASELINE_SHA='20f937e74e85147d004adcadc13f690ac78a21f2b0f6a2f7531b21930e0bb727'
CHECKS_SHA='5e446c087eb354dbfcab980fa75ed1637c126e6a0d01a04725d1007a7991e23d'
AUDIT_SHA='7e7f47cc6f2624baceb1f5f1b1208a04f361b27d3095cb07b1a9d8759d947257'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'interface_abi_report.md', 'obfuscated_routines_report.md', 'kernel_sptm_boot_inputs_report.md', 'interface_investigation_status.md', 'triage_evidence/validate_rpc502_sidecar_delivery.py', 'foundational_triage_report.md', 'kernel_boot_header_handoff_report.md', 'kernel_cpu_topology_handoff_report.md', 'kernel_secure_dt_execution_report.md', 'mach_ports_report.md'}
ADDED={'kernel_boot_option_execution_report.md','triage_evidence/recover_kernel_boot_option_execution.py',
 'triage_evidence/probe_kernel_boot_option_execution.py','triage_evidence/replay_kernel_boot_option_execution.py',
 'triage_evidence/audit_kernel_boot_option_execution.py','triage_evidence/verify_kernel_boot_option_execution_delivery.py',
 'triage_evidence/kernel_boot_option_execution_checks.json','triage_evidence/kernel_boot_option_execution_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/kernel_boot_option_execution_checks.json','triage_evidence/kernel_boot_option_execution_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'captured_functions': 24, 'captured_words': 3681, 'captured_bytes': 14724, 'matched_prior_functions': 20, 'captured_strings': 29, 'logical_data_blocks': 19, 'original_pointer_fixups': 3, 'opaque_words_preserved': 3}
TOTALS={'source_queries_unsat': 26, 'prior_source_queries_rechecked': 4, 'proved_source_PCs': 72, 'proof_instruction_instances': 72, 'linked_edge_obligations': 46, 'components': 13, 'source_visits': 162451, 'executed_source_PCs': 1760, 'changed_source_controls': 4, 'independent_semantic_checks': 9194, 'original_option_API_calls': 293, 'original_option_API_returns': 293, 'original_tree_API_calls': 2526, 'original_tree_API_returns': 2526, 'dedicated_option_API_calls': 29, 'original1472_byte_copies': 8, 'tree_initializer_returns': 13, 'source_boot_record_handoffs': 8, 'original_post_helper_returns': 8, 'logical_authenticated_callback_calls': 129, 'explicit_vector_register_checks': 416}
REPLAY={'source_visits_checked': 162451, 'reads_checked': 30759, 'writes_checked': 13880, 'declared_models_checked': 42, 'logical_effects_checked': 2344, 'same_RAM_epochs_checked': 46, 'whole_mapped_bytes_checked': 4468736, 'original_tree_API_entries_checked': 2526, 'original_tree_call_returns_checked': 2526, 'dedicated_option_API_returns_checked': 29, 'tree_initializer_returns_checked': 13, 'original_option_API_calls_and_returns_checked': 293, 'vector_registers_checked': 416}

def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
 assert e==R.build();fresh=A.audit()
 for key,count in [('source_proofs',26),('rechecked_prior_source_proofs',4)]:
  old,new=a.pop(key),fresh.pop(key);assert len(old)==len(new)==count
  for x,y in zip(old,new):
   x,y=dict(x),dict(y);p,q=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'));assert x==y and x['premises_nonvacuous'] and x['result']=='unsat'
   assert len(p)==len(q)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(p,q))
 assert a==fresh and e['verified_counts']==COUNTS and a['independent_totals']==TOTALS and a['independent_replay_totals']==REPLAY
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 assert e['kernel_collection_sha256']==a['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 prior=json.loads(read(ROOT/(R.B.P+'_checks.json')));assert e['functions'][:20]==prior['functions'] and e['pointer_fixups']==prior['pointer_fixups'] and e['opaque_words']==prior['opaque_words']
 for address,names in [(R.STRLEN,{'_strlen'}),(R.B.STRCMP,{'_strcmp'}),(R.B.B.COMPARE,{'_strncmp'}),(R.B.B.LOOKUP,{'_SecureDTLookupEntry'}),(R.B.B.ITERATE,{'_SecureDTIterateEntries'})]:assert {r['name'] for r in e['exact_symbols'][hex(address)]}==names
 coverage={r['start']:r for r in a['executed_function_coverage']}
 for address,captured,executed in [(R.STRLEN,28,25),(R.FLAG,30,30),(R.NUMBER,140,139),(R.SPACE,14,14),(R.PARSE,257,204)]:assert coverage[hex(address)]=={'start':hex(address),'captured_words':captured,'executed_unique_PCs':executed}
 visited={p['PC'] for c in a['components'] for p in c['source_visits']}
 number_function=next(f for f in e['functions'] if f['start']==hex(R.NUMBER));assert {i['ea'] for i in number_function['instructions']}-visited=={'0xfffffe000c5e4e4c'}
 assert not ({p['PC'] for p in e['opaque_words']}|{i['ea'] for f in e['functions'] for i in f['instructions'] if i['mnemonic']=='udf'})&visited
 forbidden={R.PARSE,R.B.INIT,R.B.SKIP,R.B.STRCMP,R.B.B.LOOKUP,R.B.B.PROPERTY,R.B.B.ITERATE,R.B.B.FIND}
 for c in a['components']:
  assert c['start']==hex(R.B.INIT) and c['tree_initializer_return'] and len(c['original_option_call_returns'])==len(c['original_option_API_entries'])
  assert not {int(m['PC'],16) for m in c['declared_models']}&forbidden
  assert all(x['kind'] in ['tree_initializer_to_main_cut','bootstrap_to_CPU_caller_cut','explicit_boot_option_API_call'] for x in c['epochs'])
  assert c['initial_vectors']==['0x0']*32 and len(c['final_vectors'])==32 and 'final_SP' in c and 'final_NZCV' in c
  assert 'tree_API_returns' not in c and 'dedicated_option_API_returns' in c
  for event in c['logical_effects']:
   if event['kind']=='logical_authenticated_call':assert event['target']==hex(R.SPACE) and event['discriminator']=='0xba5'
 byname={c['configuration']['label']:c for c in a['components']}
 c=byname['sixteen_CPUs_from_hex'];assert c['independent_oracle']['tree_and_topology']['topology']['selected_boot_ordinal']==15 and c['independent_oracle']['derived_options']=={'cpus':16}
 assert c['source_boot_record_snapshots'][0]['record_pointer']==hex(R.B.B.B.ARRAY+15*136) and len(c['epochs'])==2
 assert [x['PC'] for x in c['epochs']]==['0x650000e000','0xfffffe000c639dd8']
 for label in ['hex_mask_and_limit','binary_mask_and_octal_limit','duplicate_last_values']:assert byname[label]['independent_oracle']['derived_options']=={'cpus':2,'cpumask':4}
 assert byname['tabs_bare_power_flag_and_thread_mode']['independent_oracle']['derived_options']=={'enable_skstb':1,'cluster_power':7,'siq_realtime_thread_mode':3}
 for c in a['components']:
  if c['configuration'].get('operations'):assert c['declared_models']==[]
 assert len(byname['API_presence_and_matching']['dedicated_option_API_returns'])==8 and int(byname['API_presence_and_matching']['dedicated_option_API_returns'][-1]['registers'][0],16)==0
 report=read(BASE/'kernel_boot_option_execution_report.md')
 for j in range(1,8):assert '**QG'+str(j)+'**' in report and '| BO'+str(j)+' |' in report and '| BO-A'+str(j)+':' in report
 for item in [CHECKS_SHA,AUDIT_SHA,'9194','293','2526','162451','4468736','9416704','3117056','2781184','204/257','139/140','0xba5','0xffffffffffffffef']:assert item in report
 for p in CHANGED:
  if p.endswith('.md'):assert 'kernel_boot_option_execution_report.md' in read(BASE/p)
 for obj in [e,a]:
  hygiene(obj);nested_hygiene(obj);assert obj['conditional_kernel_boot_option_execution_contract_established']
  for name in R.FALSE:assert obj[name] is False
 print(json.dumps({'fresh_source_and_audit_match':True,'nonvacuous_queries_rebuilt_and_resolved':26,'prior_source_queries_rechecked':4,'private_components_rebuilt':13,'independent_semantic_checks':9194,'changed_source_controls_rejected':4,'original_option_API_calls_and_returns_checked':293,'native_target_executed':False}),flush=True)
 return e,a

def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']} for m in [old,new])
 assert len(before)==9486 and len(after)==9494 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED
 assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256'] and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
 for name,value in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),('independent_replay_checks',REPLAY),
  ('new_source_queries_unsat',26),('prior_source_queries_rechecked',4),('conditional_kernel_boot_option_execution_contract_established',True)]:assert new['validation'][R.P+'_'+name]==value
 assert new['validation']['reports']==old['validation']['reports']+1==622
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references'] and new['goal_status']=='active'
 for p in ARCHIVES:assert not (BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode();path_hygiene(decoded)
  assert not re.search(rb'/(?:Users/(?!Shared(?:/|\b))|home/|tmp/|private/|Library[/]Developer/|opt[/]homebrew/)',decoded)
 path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':622,
  'original_inputs_preserved':3,'analyst_paths_absent':True,**COUNTS,**TOTALS,'all_checks_pass':True}),flush=True)

if __name__=='__main__':publication(*receipts())
