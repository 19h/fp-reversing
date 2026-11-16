#!/usr/bin/env python3
"""Fresh collection-entry/copy contracts, private root joins and publication.
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
import recover_kernel_boot_header_handoff as R
import audit_kernel_boot_header_handoff as A
PREVIOUS='dfdb444bdd347109b23ae75dd2d64dfcf9490f01'
BASELINE_SHA='a4ef10616ad8542e7713eed0acf875aa1ca2e12d8bb943e75c932b3f8244d99c'
CHECKS_SHA='18a8d69b9710b595b60fd002b85987349872283530587c4078f7b3e38af284a0'
AUDIT_SHA='3a4eeaaa1de9db22d19cb2d86ccac17dd194a72594fc05335d38700a196355ed'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'mach_ports_report.md', 'kernel_mapping_context_report.md', 'foundational_triage_report.md', 'interface_investigation_status.md', 'triage_evidence/validate_rpc502_sidecar_delivery.py', 'kernel_sptm_boot_inputs_report.md', 'obfuscated_routines_report.md', 'interface_abi_report.md', 'kernel_mapping_transport_report.md', 'kernel_zone_boot_inputs_report.md'}
ADDED={'kernel_boot_header_handoff_report.md','triage_evidence/recover_kernel_boot_header_handoff.py',
 'triage_evidence/probe_kernel_boot_header_handoff.py','triage_evidence/replay_kernel_boot_header_handoff.py',
 'triage_evidence/audit_kernel_boot_header_handoff.py','triage_evidence/verify_kernel_boot_header_handoff_delivery.py',
 'triage_evidence/kernel_boot_header_handoff_checks.json','triage_evidence/kernel_boot_header_handoff_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/kernel_boot_header_handoff_checks.json','triage_evidence/kernel_boot_header_handoff_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'captured_functions': 34, 'captured_words': 6010, 'captured_bytes': 24040, 'matched_prior_functions': 20, 'opaque_words_preserved': 7, 'collection_thread_commands': 1, 'early_callback_fixups': 4, 'tagged_link_records': 271, 'unique_link_owners': 92}
TOTALS={'source_queries_unsat': 19, 'prior_source_queries_rechecked': 3, 'components': 61, 'component_source_visits': 99340, 'executed_source_PCs': 1210, 'proved_source_PCs': 82, 'proof_instruction_instances': 82, 'linked_edge_obligations': 63, 'independent_oracle_checks': 321, 'changed_source_controls': 4, 'exact_state_joins': 41, 'complete_six_component_chains': 7, 'root_bulk_copy_components': 9, 'original_reverse_link_iterations': 3523, 'original_header_copy_bytes_per_handoff': 856, 'original_bootargs_copy_bytes_per_handoff': 1152}
REPLAY={'source_visits_checked': 99340, 'logical_boot_system_steps_checked': 147, 'final_boundaries_checked': 61, 'whole_RAM_bytes_checked': 63963136, 'global_bytes_checked': 4588664, 'transport_entries_reconstructed': 25, 'original_clear_entries_reconstructed': 18, 'original_conversion_entries_reconstructed': 99, 'nested_source_entries_reconstructed': 27, 'original_copy_entries_reconstructed': 18, 'early_callback_entries_reconstructed': 52, 'writes_checked': 15644, 'write_bytes_checked': 109436, 'declared_boot_leaf_contracts_checked': 84, 'declared_API_models_checked': 203, 'logical_PAC_steps_checked': 342, 'reads_checked': 15956, 'read_bytes_checked': 110280, 'logical_envelopes_checked': 70, 'declared_model_semantic_contracts_checked': 119, 'logical_DC_ZVA_steps_checked': 7389}

def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
 assert e==R.build();fresh=A.audit()
 for key,n in [('source_proofs',19),('rechecked_prior_source_proofs',3)]:
  old,new=a.pop(key),fresh.pop(key);assert len(old)==len(new)==n
  for x,y in zip(old,new):
   x,y=dict(x),dict(y);p,q=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'))
   assert x==y and x['premises_nonvacuous'] and x['result']=='unsat'
   assert len(p)==len(q)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(p,q))
 assert a==fresh and e['verified_counts']==COUNTS and a['independent_totals']==TOTALS and a['independent_replay_totals']==REPLAY
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 assert e['kernel_collection_sha256']==a['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 t=e['collection_initial_thread'];assert t['PC']==hex(R.ENTRY) and (t['flavor'],t['state_count_u32'],t['SP'],t['CPSR'])==(6,68,'0x0','0x0')
 assert t['registers31'][16]=='0xfffffe000bc98000' and all(v=='0x0' for j,v in enumerate(t['registers31']) if j!=16)
 assert [r['sha256'] for r in e['Apple_SDK_schema_headers']]==['652760f46ee3b456efdcfcc5b5710a0bbc3aa30e0a1495f45ebdd038b323a693','30e201a2bf77b2b09163250db64760f303903590904a3daabd9b96cbcba19b7e']
 assert {r['name'] for r in e['exact_symbols'][hex(R.COPY)]}=={'_memcpy','_memmove'}
 assert len(e['early_callbacks'])==4 and [int(p['target'],16) for p in e['early_callbacks']]==R.CALLBACK_TARGETS
 assert len(e['tagged_link_records'])==271 and len(e['link_owner_blocks'])==92
 opaque={r['pc'] for r in e['opaque_words']};assert len(opaque)==7 and not opaque&{v['pc'] for c in a['components'] for v in c['source_visits']}
 assert bytes.fromhex(e['original_bulk_copy_destination_hex'])[0x658:0x660]==bytes(8)
 for chain in a['component_chains']:
  cold,handoff=[a['components'][j] for j in chain[:2]]
  assert next(r for r in cold['final_image_globals'] if r['address']==hex(R.B.C.BOOTROOT))['bytes_hex']==bytes(8).hex()
  assert next(r for r in handoff['final_image_globals'] if r['address']==hex(R.B.C.BOOTROOT))['bytes_hex']==(0x800000).to_bytes(8,'little').hex()
  assert next(r for r in handoff['final_image_globals'] if r['address']==hex(R.DEVICE_PTR))['bytes_hex']==R.HEADER_DEST.to_bytes(8,'little').hex()
 report=read(BASE/'kernel_boot_header_handoff_report.md')
 for j in range(1,8):assert '**QG'+str(j)+'**' in report and '| BH'+str(j)+' |' in report and '| BH-A'+str(j)+':' in report
 for item in [CHECKS_SHA,AUDIT_SHA,'321 independent','63963136','0xfffffe000c639ad0','0xfffffe0007e6d838','0x1d8','0xfffffe000c65c0ac','0xfffffe000c65c0b4','41 byte-exact state joins']:assert item in report
 for p in CHANGED:
  if p.endswith('.md'):assert 'kernel_boot_header_handoff_report.md' in read(BASE/p)
 for receipt in [e,a]:
  hygiene(receipt);nested_hygiene(receipt);assert receipt['conditional_kernel_boot_header_handoff_contract_established']
  for key in R.FALSE:assert receipt[key] is False
 print(json.dumps({'fresh_extraction_and_audit_match':True,'source_queries_reconstructed_and_resolved':19,'prior_source_queries_rechecked':3,
  'private_components_rebuilt':61,'exact_state_joins_checked':41,'changed_source_controls_rejected':4,'original_bulk_root_producer_checked':True,
  'opaque_words_executed':False,'native_target_executed':False}),flush=True)
 return e,a

def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']} for m in [old,new])
 assert len(before)==9454 and len(after)==9462 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED
 assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256'] and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
 for key,value in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),
  ('independent_replay_checks',REPLAY),('new_source_queries_unsat',19),('prior_source_queries_rechecked',3),
  ('conditional_kernel_boot_header_handoff_contract_established',True)]:assert new['validation'][R.P+'_'+key]==value
 assert new['validation']['reports']==old['validation']['reports']+1==618
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 assert new['goal_status']=='active'
 for p in ARCHIVES:assert not (BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode();path_hygiene(decoded)
  assert not re.search(rb'/(?:Users/(?!Shared(?:/|\b))|home/|tmp/|private/|Library[/]Developer/|opt[/]homebrew/)',decoded)
 path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
 assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':618,
  'original_inputs_preserved':3,**COUNTS,**TOTALS,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':publication(*receipts())
