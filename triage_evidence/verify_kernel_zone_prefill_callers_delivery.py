#!/usr/bin/env python3
"""Fresh source/proof/component checks and exact publication custody.
O(owned bytes + formula DAG + component journals/RAM) wrapper time/space;
solver search separate. No native calls, IDB writes or history rewrite.
"""
import json,re
from hashlib import sha256
from compression import zstd
import z3
from kext_port_tools import ROOT,SOURCE
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_daemon_payload_mix_publication import BASE,git,hygiene,path_hygiene
from verify_daemon_second_mix_publication import canonical_expression
import recover_kernel_zone_prefill_callers as R
import audit_kernel_zone_prefill_callers as A
PREVIOUS='06cf9e2d2fb97203c53a267f4c3b646afd22cb1e'
BASELINE_SHA='b44b3dcf5fa7818551761550c8d4748486f451dba01de29d0f92b8be9f8fb49d'
CHECKS_SHA='415b636adcbaf766e4688e68c6cc592f67848de50342005cfc928857d214f904'
AUDIT_SHA='d48d84e4eec00669f600fbf79c49af28bf7373aa2a03817c76e5dabdfdc30937'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'obfuscated_routines_report.md','foundational_triage_report.md','interface_investigation_status.md',
 'mach_ports_report.md','interface_abi_report.md','kernel_zone_observer_event_report.md',
 'kernel_cache_gate_report.md','kernel_receive_continuation_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'kernel_zone_prefill_callers_report.md','triage_evidence/recover_kernel_zone_prefill_callers.py',
 'triage_evidence/audit_kernel_zone_prefill_callers.py','triage_evidence/probe_kernel_zone_prefill_callers.py',
 'triage_evidence/verify_kernel_zone_prefill_callers_delivery.py','triage_evidence/kernel_zone_prefill_callers_checks.json',
 'triage_evidence/kernel_zone_prefill_callers_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/kernel_zone_prefill_callers_checks.json','triage_evidence/kernel_zone_prefill_callers_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'captured_functions':5,'captured_instructions':1642,'captured_bytes':6568,'prefill_instructions':141,
 'source_blocks':9,'block_instructions':22,'matched_prior_functions':2,'scan_aligned_words':15490987,'direct_branch_candidates':5}
TOTALS={'source_queries_unsat':9,'proved_source_PCs':22,'proof_instruction_instances':22,'linked_edge_obligations':13,
 'components':66,'component_source_visits':7235,'prefill_component_PCs':141,'unexecuted_prefill_PCs':0,
 'independent_oracle_checks':708,'changed_store_controls':2}

def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
 assert e==R.build();fresh=A.audit();old,new=a.pop('source_proofs'),fresh.pop('source_proofs');assert len(old)==len(new)==9
 for x,y in zip(old,new):
  x,y=dict(x),dict(y);p,q=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'))
  assert x==y and x['premises_nonvacuous'] and x['result']=='unsat'
  assert len(p)==len(q)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(p,q))
 assert a==fresh and e['verified_counts']==COUNTS and a['independent_totals']==TOTALS
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 assert e['kernel_collection_sha256']==a['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 assert len(e['direct_branch_scan']['sections'])==725
 calls=e['direct_branch_scan']['direct_branch_candidates'];assert sum(x['target']==hex(R.ARM) for x in calls)==2 and sum(x['target']==hex(R.PREFILL) for x in calls)==3
 assert all(x['mnemonic']=='bl' and x['entry']=='com.apple.kernel' for x in calls)
 for f in e['functions']:assert e['exact_symbols'][f['start']]==[]
 assert {x['name'] for x in e['exact_symbols']['0xfffffe000c6480c0']}=={'_bzero','___bzero'}
 report=read(BASE/'kernel_zone_prefill_callers_report.md')
 for j in range(1,8):assert '| PF'+str(j)+' |' in report and '**QG'+str(j)+'**' in report
 for j in range(1,7):assert '| PF-A'+str(j)+':' in report
 for word in [CHECKS_SHA,AUDIT_SHA,'0xfffffe000bd730f8','0xfffffe000bd7ac64','708','66','141','15,490,987']:assert word in report
 for p in CHANGED:
  if p.endswith('.md'):assert 'kernel_zone_prefill_callers_report.md' in read(BASE/p)
 for receipt in [e,a]:
  hygiene(receipt);assert receipt['conditional_kernel_zone_prefill_callers_contract_established'] is True
  for key in R.FALSE:assert receipt[key] is False
 print(json.dumps({'fresh_extraction_audit_match':True,'source_queries_reconstructed_and_resolved':9,
  'components_rebuilt_and_matched':66,'changed_store_controls_rejected':2,'native_target_executed':False}),flush=True)
 return e,a

def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']} for m in [old,new])
 assert len(before)==9363 and len(after)==9370 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED
 assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256'] and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
 for key,x in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),
  ('new_source_queries_unsat',9),('conditional_kernel_zone_prefill_callers_contract_established',True)]:assert new['validation'][R.P+'_'+key]==x
 assert new['validation']['reports']==old['validation']['reports']+1==606
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 assert new['goal_status']=='active'
 for p in ARCHIVES:assert not (BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode();path_hygiene(decoded)
  assert not re.search(rb'/(?:Users/(?!Shared(?:/|\b))|home/|tmp/|private/|Library[/]Developer/|opt[/]homebrew/)',decoded)
 path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
 assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':606,
  'original_inputs_preserved':3,**COUNTS,**TOTALS,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':publication(*receipts())
