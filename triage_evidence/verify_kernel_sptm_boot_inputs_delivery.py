#!/usr/bin/env python3
"""Fresh initialization contracts, private state joins and owned publication.
O(owned bytes + source + query DAG + visits + RAM) construction/space;
solver search separate. No native transport, history rewrite or IDB mutation.
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
import recover_kernel_sptm_boot_inputs as R
import audit_kernel_sptm_boot_inputs as A
PREVIOUS='6e5dd3b3fa20b7109fa52e26a70608d50b8d195f'
BASELINE_SHA='70d0b721e720598e57e86a0a37a63f6c8396f2a978a47ccec1c11ca7ab9bde05'
CHECKS_SHA='17cdafee8a80c5098d46f13fa41dc0a62b7cfb502af30a55d8512c7e6bad5020'
AUDIT_SHA='b02d6b8b7ecfabde8b9536d3991ccac373b18128693e62feaca74bec41347099'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'interface_investigation_status.md', 'interface_abi_report.md', 'triage_evidence/validate_rpc502_sidecar_delivery.py', 'kernel_zone_boot_inputs_report.md', 'mach_ports_report.md', 'kernel_mapping_transport_report.md', 'kernel_mapping_context_report.md', 'obfuscated_routines_report.md', 'foundational_triage_report.md'}
ADDED={'kernel_sptm_boot_inputs_report.md','triage_evidence/recover_kernel_sptm_boot_inputs.py',
 'triage_evidence/probe_kernel_sptm_boot_inputs.py','triage_evidence/replay_kernel_sptm_boot_inputs.py',
 'triage_evidence/audit_kernel_sptm_boot_inputs.py','triage_evidence/verify_kernel_sptm_boot_inputs_delivery.py',
 'triage_evidence/kernel_sptm_boot_inputs_checks.json','triage_evidence/kernel_sptm_boot_inputs_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/kernel_sptm_boot_inputs_checks.json','triage_evidence/kernel_sptm_boot_inputs_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'captured_functions': 20, 'captured_words': 4283, 'captured_bytes': 17132, 'matched_prior_functions': 15, 'undecoded_words_preserved': 4, 'sections_rehashed': 725, 'aligned_words_scanned': 15490987, 'ADRP_seeds': 3910, 'candidate_references': 324, 'candidate_store_sites': 34, 'boot_root_candidate_stores': 0, 'direct_B_BL_calls': 6}
TOTALS={'source_queries_unsat': 35, 'prior_source_queries_rechecked': 6, 'components': 73, 'component_source_visits': 45709, 'executed_source_PCs': 1007, 'proved_source_PCs': 184, 'proof_instruction_instances': 184, 'linked_edge_obligations': 149, 'independent_oracle_checks': 387, 'changed_source_controls': 4, 'exact_state_joins': 34, 'complete_five_component_chains': 7, 'original_nested_context_executions': 9, 'version_profiles': 28, 'boot_CFG_reachable_words': 121, 'boot_CFG_direct_edges': 130, 'boot_CFG_returns': 2}
REPLAY={'source_visits_checked': 45709, 'logical_PAC_steps_checked': 320, 'writes_checked': 3093, 'write_bytes_checked': 22756, 'reads_checked': 3549, 'read_bytes_checked': 24820, 'final_boundaries_checked': 73, 'whole_RAM_bytes_checked': 76546048, 'global_bytes_checked': 3665695, 'transport_entries_reconstructed': 25, 'original_clear_entries_reconstructed': 18, 'original_conversion_entries_reconstructed': 99, 'nested_source_entries_reconstructed': 27, 'declared_model_semantic_contracts_checked': 119, 'declared_API_models_checked': 119, 'logical_DC_ZVA_steps_checked': 7389}

def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
 assert e==R.build();fresh=A.audit()
 for key,n in [('source_proofs',35),('rechecked_prior_source_proofs',6)]:
  old,new=a.pop(key),fresh.pop(key);assert len(old)==len(new)==n
  for x,y in zip(old,new):
   x,y=dict(x),dict(y);p,q=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'))
   assert x==y and x['premises_nonvacuous'] and x['result']=='unsat'
   assert len(p)==len(q)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(p,q))
 assert a==fresh and e['verified_counts']==COUNTS and a['independent_totals']==TOTALS and a['independent_replay_totals']==REPLAY
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 assert e['kernel_collection_sha256']==a['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 assert e['original_boot_root_bytes_hex']==bytes(8).hex()
 assert e['topology_fixup']['target']==hex(R.TOPOBASE) and e['topology_fixup']['format']==8
 for address,rows in e['exact_symbols'].items():
  expected=([{'name':name,'entry':'com.apple.kernel','n_type':15,'n_section':19} for name in ['___bzero','_bzero']] if address==hex(R.C.Z.BZERO) else
   [{'name':'_SecureDTLookupEntry','entry':'com.apple.kernel','n_type':15,'n_section':21}] if address=='0xfffffe000c662324' else [])
  assert rows==expected
 assert {r['text'] for r in e['strings']}=={'/defaults','pmap-pv-count','pmap-kern-pv-count','pmap-kern-pv-min'}
 cfg=a['closed_boot_CFG'];assert cfg==A.boot_cfg(e) and cfg['reachable_words']==121 and len(cfg['direct_successor_edges'])==130 and cfg['returns']==['0xfffffe000c662af8','0xfffffe000c662b00']
 opaque={r['pc'] for r in e['undecoded_words']};assert len(opaque)==4 and not opaque&{v['pc'] for c in a['components'] for v in c['source_visits']}
 assert all(int(f['address'],16)!=R.C.TOPOLOGY for c in a['components'] for f in c['initial_image_fixtures'])
 assert e['boot_boundary']['file_backed_segment_end']==hex(R.BOOT_END) and e['boot_boundary']['last_compiler_start']
 report=read(BASE/'kernel_sptm_boot_inputs_report.md')
 for j in range(1,8):assert '**QG'+str(j)+'**' in report and '| SB'+str(j)+' |' in report and '| SB-A'+str(j)+':' in report
 for item in [CHECKS_SHA,AUDIT_SHA,'387 independent','76546048','0xd00f000000000000','0x1a0','0xfffffe000be7142c','0xfffffe000c662a44','524288 B','0xfffffe0007ef8260','0xfffffd8a','34 byte-exact state joins']:assert item in report
 for p in CHANGED:
  if p.endswith('.md'):assert 'kernel_sptm_boot_inputs_report.md' in read(BASE/p)
 for receipt in [e,a]:
  hygiene(receipt);nested_hygiene(receipt);assert receipt['conditional_kernel_sptm_boot_inputs_contract_established']
  for key in R.FALSE:assert receipt[key] is False
 print(json.dumps({'fresh_extraction_and_audit_match':True,'source_queries_reconstructed_and_resolved':35,
  'prior_source_queries_rechecked':6,'private_components_rebuilt':73,'exact_state_joins_checked':34,
  'changed_source_controls_rejected':4,'opaque_transport_words_executed':False,'native_target_executed':False}),flush=True)
 return e,a

def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']} for m in [old,new])
 assert len(before)==9446 and len(after)==9454 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED
 assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256'] and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
 for key,value in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),
  ('independent_replay_checks',REPLAY),('new_source_queries_unsat',35),('prior_source_queries_rechecked',6),
  ('conditional_kernel_sptm_boot_inputs_contract_established',True)]:assert new['validation'][R.P+'_'+key]==value
 assert new['validation']['reports']==old['validation']['reports']+1==617
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 assert new['goal_status']=='active'
 for p in ARCHIVES:assert not (BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode();path_hygiene(decoded)
  assert not re.search(rb'/(?:Users/(?!Shared(?:/|\b))|home/|tmp/|private/|Library[/]Developer/|opt[/]homebrew/)',decoded)
 path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
 assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':617,
  'original_inputs_preserved':3,**COUNTS,**TOTALS,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':publication(*receipts())
