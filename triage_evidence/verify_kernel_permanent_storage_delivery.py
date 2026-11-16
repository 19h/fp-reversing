#!/usr/bin/env python3
"""Fresh source proofs/components and exact owned publication custody.
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
import recover_kernel_permanent_storage as R
import audit_kernel_permanent_storage as A

PREVIOUS='51d027680ce69fd2ec8021d5d7adb0ec97068c4b'
BASELINE_SHA='a8fafc66ffe13816a04c51aa728c24925bee886ee3675d8a949e60d52a1596b2'
CHECKS_SHA='8eff8d54ed8fefa4b82296e4fd234a65283fdf9fe0f66b35c39079f8954ff97d'
AUDIT_SHA='62aed64859e94b47d50286145c1b4a9feea01b4ab4de458421e3b6b69082343a'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'obfuscated_routines_report.md','foundational_triage_report.md','interface_investigation_status.md',
 'mach_ports_report.md','interface_abi_report.md','kernel_zone_boot_order_report.md','kernel_magazine_bootstrap_report.md',
 'kernel_zone_startup_report.md','kernel_zone_boot_inputs_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'kernel_permanent_storage_report.md','triage_evidence/recover_kernel_permanent_storage.py',
 'triage_evidence/probe_kernel_permanent_storage.py','triage_evidence/replay_kernel_permanent_storage.py',
 'triage_evidence/audit_kernel_permanent_storage.py','triage_evidence/verify_kernel_permanent_storage_delivery.py',
 'triage_evidence/kernel_permanent_storage_checks.json','triage_evidence/kernel_permanent_storage_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/kernel_permanent_storage_checks.json','triage_evidence/kernel_permanent_storage_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'captured_functions': 6, 'captured_instructions': 937, 'captured_bytes': 3748, 'matched_prior_functions': 3, 'source_blocks': 12, 'block_instructions': 90, 'setup_records': 2, 'setup_pointer_fixups': 6, 'sections_rehashed': 725, 'aligned_words_scanned': 15490987, 'direct_branch_sites': 85}
TOTALS={'source_queries_unsat': 14, 'rechecked_separation_lemmas_unsat': 2, 'components': 21, 'component_source_visits': 2044, 'executed_source_PCs': 401, 'proved_source_PCs': 89, 'proof_instruction_instances': 89, 'linked_edge_obligations': 75, 'checked_read_store_rewrites': 32, 'independent_oracle_checks': 173, 'changed_source_controls': 3, 'original_permanent_entries': 19}
REPLAY={'source_visits_checked': 2044, 'logical_PAC_steps_checked': 48, 'writes_checked': 432, 'write_bytes_checked': 2850, 'declared_model_semantic_contracts_checked': 66, 'declared_API_models_checked': 66, 'reads_checked': 491, 'read_bytes_checked': 3077, 'final_boundaries_checked': 21, 'whole_RAM_bytes_checked': 22020096, 'global_bytes_checked': 942478, 'permanent_events_reconstructed_and_checked': 36, 'logical_envelopes_checked': 3}

def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
 assert e==R.build();fresh=A.audit()
 for key,n in [('source_proofs',14),('rechecked_separation_lemmas',2)]:
  old,new=a.pop(key),fresh.pop(key);assert len(old)==len(new)==n
  for x,y in zip(old,new):
   x,y=dict(x),dict(y);p,q=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'))
   assert x==y and x.get('premises_nonvacuous',True) and x['result']=='unsat'
   assert len(p)==len(q)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(p,q))
 assert a==fresh and e['verified_counts']==COUNTS and a['independent_totals']==TOTALS and a['independent_replay_totals']==REPLAY
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 assert e['kernel_collection_sha256']==a['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 assert all(not e['exact_symbols'][hex(a)] for a in R.FUNCTIONS)
 for row in e['setup_records']:
  raw=bytes.fromhex(row['raw_bytes_hex']);logical=bytes.fromhex(row['logical_bytes_hex']);base=int(row['address'],16)
  assert len(raw)==len(logical)==32 and int.from_bytes(raw[8:16],'little')==0x50000000
  for off,pointer in zip([0,16,24],row['pointers']):
   w=int.from_bytes(raw[off:off+8],'little');target=0xfffffe0007004000+(w&0xffffffff)
   assert pointer['slot']==hex(base+off) and int(pointer['raw'],16)==w
   assert pointer['format']==8 and pointer['auth']==(w>>63)==1
   assert pointer['address_diversity']==((w>>48)&1) and pointer['key']==((w>>49)&3)
   assert int(pointer['diversity'],16)==((w>>32)&0xffff) and int(pointer['target'],16)==target
   assert int.from_bytes(logical[off:off+8],'little')==target
 report=read(BASE/'kernel_permanent_storage_report.md')
 for j in range(1,8):assert '**QG'+str(j)+'**' in report
 for j in range(1,7):assert '| PS'+str(j)+' |' in report and '| PS-A'+str(j)+':' in report
 for item in [CHECKS_SHA,AUDIT_SHA,'0xbead','0xe0cf','16376','173 independent','zero-filled backing','alignment mask']:assert item in report
 for p in CHANGED:
  if p.endswith('.md'):assert 'kernel_permanent_storage_report.md' in read(BASE/p)
 for receipt in [e,a]:
  hygiene(receipt);nested_hygiene(receipt);assert receipt['conditional_kernel_permanent_storage_contract_established']
  for key in R.FALSE:assert receipt[key] is False
 print(json.dumps({'fresh_extraction_and_audit_match':True,'source_queries_reconstructed_and_resolved':14,
  'separation_lemmas_rechecked':2,'private_components_rebuilt':21,'authenticated_pointer_words_independently_decoded':6,
  'changed_source_controls_rejected':3,'native_target_executed':False}),flush=True)
 return e,a

def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']} for m in [old,new])
 assert len(before)==9406 and len(after)==9414 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED
 assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256'] and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
 for key,value in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),
  ('independent_replay_checks',REPLAY),('new_source_queries_unsat',14),
  ('rechecked_separation_lemmas_unsat',2),('conditional_kernel_permanent_storage_contract_established',True)]:assert new['validation'][R.P+'_'+key]==value
 assert new['validation']['reports']==old['validation']['reports']+1==612
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 assert new['goal_status']=='active'
 for p in ARCHIVES:assert not (BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode();path_hygiene(decoded)
  assert not re.search(rb'/(?:Users/(?!Shared(?:/|\b))|home/|tmp/|private/|Library[/]Developer/|opt[/]homebrew/)',decoded)
 path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
 assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':612,
  'original_inputs_preserved':3,**COUNTS,**TOTALS,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':publication(*receipts())
