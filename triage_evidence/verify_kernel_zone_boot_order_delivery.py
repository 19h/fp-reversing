#!/usr/bin/env python3
"""Fresh source/CFG/components and exact owned publication custody.
O(owned bytes + source + query DAG + visits + RAM) construction/space;
solver search separate. No native callbacks, target writes or history scan.
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
import recover_kernel_zone_boot_order as R
import audit_kernel_zone_boot_order as A

PREVIOUS='fa43f9a722317b26bd62bc9df7c6c840678be4ee'
BASELINE_SHA='4235ff2dfb342d013c2c789a6c6a78c11bd014c94b4ebbd49f8c5abecd169007'
CHECKS_SHA='745cc81c71a9d629db071eb4cd6fc314ac0cdbc566e24627c2e18d25916db152'
AUDIT_SHA='8cb89a598d2aabfc36e587a691a2bd92bde373c8a6552f84b859d69dbcfd3600'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'obfuscated_routines_report.md','foundational_triage_report.md','interface_investigation_status.md',
 'mach_ports_report.md','interface_abi_report.md','startup_dispatch_report.md','kernel_magazine_bootstrap_report.md',
 'kernel_zone_startup_report.md','mixed_data_zone_geometry_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'kernel_zone_boot_order_report.md','triage_evidence/recover_kernel_zone_boot_order.py',
 'triage_evidence/probe_kernel_zone_boot_order.py','triage_evidence/replay_kernel_zone_boot_order.py',
 'triage_evidence/audit_kernel_zone_boot_order.py','triage_evidence/verify_kernel_zone_boot_order_delivery.py',
 'triage_evidence/kernel_zone_boot_order_checks.json','triage_evidence/kernel_zone_boot_order_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/kernel_zone_boot_order_checks.json','triage_evidence/kernel_zone_boot_order_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'captured_functions':8,'captured_instructions':966,'captured_bytes':3864,'matched_prior_functions':7,
 'source_blocks':8,'block_instructions':28,'startup_records_rechecked':3519,'startup_pointer_fixups_rechecked':6950,
 'phase6_records':13,'phase7_records':136,'unique_phase7_rank0_magazine':1,'selected_IPC_records':3,'caller_direct_call_sites':22}
TOTALS={'source_queries_unsat':9,'prior_source_queries_reconstructed_and_rechecked':13,'rechecked_separation_lemmas_unsat':2,
 'proved_source_PCs':28,'proof_instruction_instances':42,'linked_edge_obligations':32,'checked_read_store_rewrites':0,
 'components':5,'component_source_visits':74637,'executed_source_PCs':568,'independent_oracle_checks':70,
 'changed_source_controls':4,'changed_CFG_controls':1,'registered_callback_return_models':745}
REPLAY={'source_visits_checked':74637,'logical_PAC_steps_checked':1562,'writes_checked':10873,'write_bytes_checked':63068,
 'reads_checked':15284,'read_bytes_checked':86766,'declared_model_semantic_contracts_checked':4316,'declared_API_models_checked':4316,
 'logical_envelopes_checked':762,'final_boundaries_checked':5,'whole_RAM_bytes_checked':5242880,'global_bytes_checked':438622,
 'startup_events_reconstructed_and_checked':775,'string_model_inputs_and_results_checked':2}

def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
 assert e==R.build();fresh=A.audit()
 for key,n in [('source_proofs',9),('rechecked_prior_source_proofs',13),('rechecked_separation_lemmas',2)]:
  old,new=a.pop(key),fresh.pop(key);assert len(old)==len(new)==n
  for x,y in zip(old,new):
   x,y=dict(x),dict(y);p,q=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'))
   assert x==y and x.get('premises_nonvacuous',True) and x['result']=='unsat'
   assert len(p)==len(q)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(p,q))
 assert a==fresh and e['verified_counts']==COUNTS and a['independent_totals']==TOTALS and a['independent_replay_totals']==REPLAY
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 assert e['kernel_collection_sha256']==a['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 assert e['exact_symbols']['0xfffffe000cb29cb0']==[{'name':'_sane_size','entry':'com.apple.kernel','n_type':15,'n_section':34}]
 assert e['phase7_rank_histogram']=={'0':1,'1':2,'2':1,'3':71,'2147483647':10,'4294967295':51}
 assert a['original_source_sort']=={'source_sort_visits':231961,'source_sort_calls':4215,'sorted_records':3519,
  'sorted_table_sha256':'59fee911ef4245c47031c68d965e88ca030f22f1876d525aeaaf6d1f83249e2c','sort_guard_bytes':128}
 report=read(BASE/'kernel_zone_boot_order_report.md')
 for j in range(1,8):assert '**QG'+str(j)+'**' in report
 for j in range(1,7):assert '| BO'+str(j)+' |' in report and '| BO-A'+str(j)+':' in report
 for text in [CHECKS_SHA,AUDIT_SHA,'_sane_size','0xfffffe000cb29cb4','0xfffffe000c634f1c','74,637','689','rank0','rank3']:assert text in report
 for p in CHANGED:
  if p.endswith('.md'):assert 'kernel_zone_boot_order_report.md' in read(BASE/p)
 for receipt in [e,a]:
  hygiene(receipt);nested_hygiene(receipt);assert receipt['conditional_kernel_zone_boot_order_contract_established']
  for key in R.FALSE:assert receipt[key] is False
 print(json.dumps({'fresh_extraction_and_audit_match':True,'new_source_queries_reconstructed_and_resolved':9,
  'prior_queries_reconstructed_and_resolved':13,'separation_lemmas_rechecked':2,'continuous_components_rebuilt':5,
  'changed_source_controls_rejected':4,'changed_CFG_controls_rejected':1,'native_target_executed':False}),flush=True)
 return e,a

def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']} for m in [old,new])
 assert len(before)==9392 and len(after)==9400 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED
 assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256'] and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
 for key,value in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),
  ('independent_replay_checks',REPLAY),('new_source_queries_unsat',9),('prior_source_queries_rechecked',13),
  ('rechecked_separation_lemmas_unsat',2),('conditional_kernel_zone_boot_order_contract_established',True)]:assert new['validation'][R.P+'_'+key]==value
 assert new['validation']['reports']==old['validation']['reports']+1==610
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 assert new['goal_status']=='active'
 for p in ARCHIVES:assert not (BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode();path_hygiene(decoded)
  assert not re.search(rb'/(?:Users/(?!Shared(?:/|\b))|home/|tmp/|private/|Library[/]Developer/|opt[/]homebrew/)',decoded)
 path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
 assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':610,
  'original_inputs_preserved':3,**COUNTS,**TOTALS,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':publication(*receipts())
