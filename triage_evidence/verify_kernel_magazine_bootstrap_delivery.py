#!/usr/bin/env python3
"""Fresh magazine-bootstrap certificates/components and exact publication custody.
O(owned bytes + query DAG + component RAM/journals) wrapper time/space;
solver search separate. No native execution, IDB writes or history rewrite.
"""
import json,re
from hashlib import sha256
from compression import zstd
import z3
from kext_port_tools import ROOT,SOURCE
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_daemon_payload_mix_publication import BASE,git,hygiene,path_hygiene
from verify_daemon_second_mix_publication import canonical_expression
import recover_kernel_magazine_bootstrap as R
import audit_kernel_magazine_bootstrap as A
PREVIOUS='61ba0b7ffdc012b84fc65c6a7b1023749cbc7105'
BASELINE_SHA='49c62ec94cfb0cf3a7b8dfa74faa1d07865d4785334561236972d8e3ed97aa31'
CHECKS_SHA='27d60c643cb84226823882c7171cbfd32c73cc3eacc2997fa701cd13a5d960c5'
AUDIT_SHA='f80b2b0799d44936992aaa92bd2ab9519ad6ba58fd966a9d5749238b39556a69'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'obfuscated_routines_report.md','foundational_triage_report.md','interface_investigation_status.md',
 'mach_ports_report.md','interface_abi_report.md','kernel_zone_prefill_callers_report.md',
 'kernel_zone_refill_report.md','kernel_zone_startup_report.md','kernel_retirement_magazines_report.md',
 'kernel_magazine_bulk_return_report.md',
 'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'kernel_magazine_bootstrap_report.md','triage_evidence/recover_kernel_magazine_bootstrap.py',
 'triage_evidence/audit_kernel_magazine_bootstrap.py','triage_evidence/probe_kernel_magazine_bootstrap.py',
 'triage_evidence/replay_kernel_magazine_bootstrap.py',
 'triage_evidence/verify_kernel_magazine_bootstrap_delivery.py','triage_evidence/kernel_magazine_bootstrap_checks.json',
 'triage_evidence/kernel_magazine_bootstrap_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/kernel_magazine_bootstrap_checks.json','triage_evidence/kernel_magazine_bootstrap_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'captured_functions':7,'captured_instructions':1341,'captured_bytes':5364,'matched_prior_functions':2,
 'source_blocks':21,'block_instructions':97,'sections_rehashed':725,'aligned_words_scanned':15490987,
 'bounded_ADRP_references':27,'startup_callback_pointer_candidates':1,'direct_boot_branches':1}
TOTALS={'source_queries_unsat':23,'rechecked_separation_lemmas_unsat':2,'proved_source_PCs':97,
 'proof_instruction_instances':97,'linked_edge_obligations':74,'checked_read_store_rewrites':256,
 'components':47,'component_source_visits':9370,'executed_source_PCs':553,'independent_oracle_checks':220,'changed_source_controls':3}
REPLAY={'source_visits_checked':9370,'logical_PAC_steps_checked':149,'writes_checked':1609,'write_bytes_checked':11662,
 'reads_checked':1871,'read_bytes_checked':9624,'final_boundaries_checked':47,'whole_RAM_bytes_checked':49283072,
 'global_bytes_checked':6562,'string_model_inputs_and_results_checked':34,'declared_API_models_checked':168,'logical_envelopes_checked':56}

def nested_hygiene(obj):
 import base64,zlib
 if isinstance(obj,dict):
  if 'zlib_base64' in obj:
   raw=zlib.decompress(base64.b64decode(obj['zlib_base64']));path_hygiene(raw)
   assert not re.search(rb'/(?:Users/(?!Shared(?:/|\b))|home/|tmp/|private/|Library[/]Developer/|opt[/]homebrew/)',raw)
  for x in obj.values():nested_hygiene(x)
 elif isinstance(obj,list):
  for x in obj:nested_hygiene(x)

def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
 assert e==R.build();fresh=A.audit()
 for key,n in [('source_proofs',23),('rechecked_separation_lemmas',2)]:
  old,new=a.pop(key),fresh.pop(key);assert len(old)==len(new)==n
  for x,y in zip(old,new):
   x,y=dict(x),dict(y);p,q=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'))
   assert x==y and x.get('premises_nonvacuous',True) and x['result']=='unsat'
   assert len(p)==len(q)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(p,q))
 assert a==fresh and e['verified_counts']==COUNTS and a['independent_totals']==TOTALS
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 assert e['kernel_collection_sha256']==a['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 assert a['independent_replay_totals']==REPLAY
 assert [(r['pc'],r['instruction']) for r in e['bounded_ADRP_references'] if r['instruction'].startswith('str')]==[('0xfffffe000c6320f4','strh w8, [x9, #0x248]'),('0xfffffe000c6321a0','strh w9, [x10, #0x248]'),('0xfffffe000c632620','str x0, [x8, #0xf58]')]
 assert next(r for r in e['globals'] if r['address']==hex(R.CAP))['file_bytes_hex']=='0800'
 assert all(not names for names in e['exact_symbols'].values())
 report=read(BASE/'kernel_magazine_bootstrap_report.md')
 for j in range(1,8):assert '| MB'+str(j)+' |' in report and '**QG'+str(j)+'**' in report
 for j in range(1,7):assert '| MB-A'+str(j)+':' in report
 for word in [CHECKS_SHA,AUDIT_SHA,'0xfffffe000c632618','0xfffffe000c632620','220','4094','zc_mag_size','presence']:assert word in report
 for p in CHANGED:
  if p.endswith('.md'):assert 'kernel_magazine_bootstrap_report.md' in read(BASE/p)
 for receipt in [e,a]:
  hygiene(receipt);nested_hygiene(receipt);assert receipt['conditional_kernel_magazine_bootstrap_contract_established'] is True
  for key in R.FALSE:assert receipt[key] is False
 print(json.dumps({'fresh_extraction_audit_match':True,'source_queries_reconstructed_and_resolved':23,
  'separation_lemmas_rechecked':2,'components_rebuilt_and_matched':47,
  'changed_source_controls_rejected':3,'native_target_executed':False}),flush=True)
 return e,a

def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']} for m in [old,new])
 assert len(before)==9384 and len(after)==9392 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED
 assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256'] and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
 for key,x in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),
  ('new_source_queries_unsat',23),('rechecked_separation_lemmas_unsat',2),
  ('independent_replay_checks',REPLAY),('conditional_kernel_magazine_bootstrap_contract_established',True)]:assert new['validation'][R.P+'_'+key]==x
 assert new['validation']['reports']==old['validation']['reports']+1==609
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 assert new['goal_status']=='active'
 for p in ARCHIVES:assert not (BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode();path_hygiene(decoded)
  assert not re.search(rb'/(?:Users/(?!Shared(?:/|\b))|home/|tmp/|private/|Library[/]Developer/|opt[/]homebrew/)',decoded)
 path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
 assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':609,
  'original_inputs_preserved':3,**COUNTS,**TOTALS,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':publication(*receipts())
