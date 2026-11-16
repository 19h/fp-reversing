#!/usr/bin/env python3
"""Rebuild source/proofs/private witnesses and verify exact owned publication.
O(owned bytes+source+formula DAG+journals+RAM) construction/space; SMT search
separate. No native target, IDB or history mutation.
"""
import contextlib,io,json,re
from hashlib import sha256
from compression import zstd
import z3
from kext_port_tools import ROOT,SOURCE
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_daemon_payload_mix_publication import BASE,git,hygiene,path_hygiene
from verify_daemon_second_mix_publication import canonical_expression
from verify_kernel_magazine_bootstrap_delivery import nested_hygiene
import recover_kernel_boot_environment_publication as R
import audit_kernel_boot_environment_publication as A

PREVIOUS='c8cb65a592a6e4a8e9ba703b95356fe8077bbb72'
BASELINE_SHA='028049efa19d065c8b6b904e199fb9d756d411af68bcb421dad868392e3d3532'
CHECKS_SHA='346ede2a25d0801840efd6af68d44f47617b4b091a904581ab4081e4004eae74'
AUDIT_SHA='c7ba26d27e131a78cb18f5fd698ff02deb1c4d8e108e4d2adb3ce94227083ebe'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'interface_abi_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_investigation_status.md','kernel_boot_header_handoff_report.md','kernel_boot_option_execution_report.md','kernel_secure_dt_execution_report.md','kernel_cpu_topology_handoff_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'kernel_boot_environment_publication_report.md',*[('triage_evidence/'+name+'_kernel_boot_environment_publication.py') for name in ['recover','probe','replay','audit']], 'triage_evidence/verify_kernel_boot_environment_publication_delivery.py','triage_evidence/kernel_boot_environment_publication_checks.json','triage_evidence/kernel_boot_environment_publication_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/kernel_boot_environment_publication_checks.json','triage_evidence/kernel_boot_environment_publication_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'captured_functions':9,'captured_words':1526,'captured_bytes':6104,'matched_prior_functions':4,'scanned_executable_segments':3,'scanned_words':2558561,'direct_platform_calls':3,'direct_early_tree_calls':1,'direct_generic_tree_calls':0,'opaque_words_preserved':3}
TOTALS={'source_queries_unsat':19,'proved_source_PCs':107,'proof_instruction_instances':107,'linked_edge_obligations':88,'components':9,'source_visits':3419,'executed_source_PCs':266,'changed_source_controls':4,'independent_semantic_checks':97,'same_mutable_image_transfers':3,'original_main_bootargs_header_copy_pairs':4,'original_call_entries':35,'whole_mutable_bytes_checked':115200,'private_nonstack_bytes_checked':9398016}
REPLAY={'source_visits_checked':3419,'logical_PAC_steps_checked':68,'writes_checked':1532,'write_bytes_checked':11870,'logical_address_PAC_steps_checked':8,'declared_API_models_checked':8,'reads_checked':1287,'read_bytes_checked':10152,'final_boundaries_checked':9,'whole_private_bytes_checked':9437184,'whole_image_page_bytes_checked':417792,'vector_registers_checked':288,'original_call_entries_checked':35}

def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')));assert e==R.build()
 with contextlib.redirect_stdout(io.StringIO()):fresh=A.audit()
 old_queries,new_queries=a['source_proofs'],fresh['source_proofs'];assert len(old_queries)==len(new_queries)==19
 for old,new in zip(old_queries,new_queries):
  x,y=dict(old),dict(new);p,q=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'));assert x==y and x['premises_nonvacuous'] and x['result']=='unsat'
  assert len(p)==len(q)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(p,q))
 assert {k:v for k,v in a.items() if k!='source_proofs'}=={k:v for k,v in fresh.items() if k!='source_proofs'}
 assert e['verified_counts']==COUNTS and a['independent_totals']==TOTALS and a['independent_replay_totals']==REPLAY
 assert e['kernel_collection_sha256']==a['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 assert a['independent_branch_census']=={'aligned_words_checked':2558561,'branch_candidates_independently_disassembled':208326,'matching_edges':4}
 assert e['exact_symbols'][hex(R.PLATFORM)]==[]
 for addr,names in [(R.STRLCPY,{'_strlcpy'}),(R.STRLEN,{'_strlen'}),(R.COPY,{'_memcpy','_memmove'})]:assert {r['name'] for r in e['exact_symbols'][hex(addr)]}==names
 forbidden={i['ea'] for f in e['functions'] for i in f['instructions'] if i['mnemonic'] in ['opaque','udf']};visited={v['pc'] for c in a['components'] for v in c['source_visits']};assert not forbidden&visited
 k=R.Kernel()
 for addr,key in [(0xfffffe00070644e0,b'icdsb'),(0xfffffe0007062148,b'user_ts_jop'),(0xfffffe0007062154,b'diversify_user_jop'),(0xfffffe0007062167,b'sptm_stability_hacks')]:assert k.read(addr,len(key)+1)==key+b'\0'
 for c in a['components']:
  assert c['initial_vectors']==['0x0']*32 and len(c['final_vectors'])==32 and c['source_word_mutated_to_NOP'] is None
  assert all(int(m['pc'],16) in A.CPU.LEAVES for m in c['API_models'])
  assert c['boundary']['pc'] in list(map(hex,[R.NEXT_CONTEXT,R.NEXT_TREE,0xfffffe000c5e6afc]))
 byname={c['configuration']['label']:c for c in a['components']}
 assert byname['mode_uses_low32']['independent_oracle']['mode_low32']=='0x0'
 assert byname['main_tree_addition_carry']['independent_oracle']['tree_addition_carry']
 for name in ['reenter_mode0_ignores_new_argument','reenter_mode1_null_context','reenter_mode1_CPU_context']:assert byname[name]['same_mutable_image_predecessor']=='main_normal' and byname[name]['independent_oracle']['bootargs_pointer']==hex(R.ARGS)
 report=read(BASE/'kernel_boot_environment_publication_report.md')
 for j in range(1,8):assert '**QG'+str(j)+'**' in report and '| EP'+str(j)+' |' in report and '| EP-A'+str(j)+':' in report
 for item in [CHECKS_SHA,AUDIT_SHA,'3419','2558561','208326','115200','9398016','9437184','417792','76/319','0xfffffe000c5e6690','0x100000000']:assert item in report
 for path in CHANGED:
  if path.endswith('.md'):assert 'kernel_boot_environment_publication_report.md' in read(BASE/path)
 for obj in [e,a]:
  hygiene(obj);nested_hygiene(obj);assert obj['conditional_kernel_boot_environment_publication_contract_established']
  for name in R.FALSE:assert obj[name] is False
 print(json.dumps({'fresh_source_and_audit_match':True,'nonvacuous_queries_rebuilt_and_resolved':19,'private_components_rebuilt':9,'independent_semantic_checks':97,'changed_source_controls_rejected':4,'native_target_executed':False}),flush=True)
 return e,a

def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']} for m in [old,new])
 assert len(before)==9494 and len(after)==9502 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED
 assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256'] and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
 for name,value in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),('independent_replay_checks',REPLAY),('new_source_queries_unsat',19),('branch_census',a['independent_branch_census']),('conditional_kernel_boot_environment_publication_contract_established',True)]:assert new['validation'][R.P+'_'+name]==value
 assert new['validation']['reports']==old['validation']['reports']+1==623
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references'] and new['goal_status']=='active'
 for p in ARCHIVES:assert not (BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode();path_hygiene(decoded)
  assert not re.search(rb'/(?:Users/(?!Shared(?:/|\b))|home/|tmp/|private/|Library[/]Developer/|opt[/]homebrew/)',decoded)
 path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':623,'original_inputs_preserved':3,'analyst_paths_absent':True,**COUNTS,**TOTALS,'all_checks_pass':True}),flush=True)

if __name__=='__main__':publication(*receipts())
