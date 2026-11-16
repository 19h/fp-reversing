#!/usr/bin/env python3
"""Fresh bulk-return certificates/components and exact publication custody.
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
import recover_kernel_magazine_bulk_return as R
import audit_kernel_magazine_bulk_return as A
PREVIOUS='711c1f71714548233a54347e14f6c94fdfa43ea3'
BASELINE_SHA='46dd921373258e8cc7e384e5a6373fe78b6866f5dcfc9cb2c8dac1222b7fdd8b'
CHECKS_SHA='cea5c2bb94a496f2bc53a2b4bc15f4233b3a7b42ccf3be8ee4a1c91b68586e09'
AUDIT_SHA='8f0c6f9cc05de488a76395081022e41476d3a8857006061bf74f7d21ddce5e0d'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'obfuscated_routines_report.md','foundational_triage_report.md','interface_investigation_status.md',
 'mach_ports_report.md','interface_abi_report.md','kernel_zone_prefill_callers_report.md',
 'kernel_zone_refill_report.md','kernel_zone_bitmap_release_report.md','kernel_zone_observer_event_report.md',
 'kernel_magazine_depot_drain_report.md',
 'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'kernel_magazine_bulk_return_report.md','triage_evidence/recover_kernel_magazine_bulk_return.py',
 'triage_evidence/audit_kernel_magazine_bulk_return.py','triage_evidence/probe_kernel_magazine_bulk_return.py',
 'triage_evidence/verify_kernel_magazine_bulk_return_delivery.py','triage_evidence/kernel_magazine_bulk_return_checks.json',
 'triage_evidence/kernel_magazine_bulk_return_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/kernel_magazine_bulk_return_checks.json','triage_evidence/kernel_magazine_bulk_return_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'captured_functions':6,'captured_instructions':1236,'captured_bytes':4944,'bulk_instructions':248,
 'matched_prior_functions':6,'source_blocks':21,'block_instructions':85,'bulk_call_sites':5}
TOTALS={'source_queries_unsat':21,'rechecked_separation_lemmas_unsat':2,'proved_source_PCs':85,
 'proof_instruction_instances':115,'linked_edge_obligations':94,'checked_read_store_rewrites':208,
 'components':44,'component_source_visits':9012,'bulk_component_PCs':247,'unexecuted_bulk_PCs':1,
 'source_fill_producers':2,'source_produced_roundtrip_components':4,'independent_oracle_checks':364,'changed_source_controls':2}

def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
 assert e==R.build();fresh=A.audit()
 for key,n in [('source_proofs',21),('rechecked_separation_lemmas',2)]:
  old,new=a.pop(key),fresh.pop(key);assert len(old)==len(new)==n
  for x,y in zip(old,new):
   x,y=dict(x),dict(y);p,q=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'))
   assert x==y and x.get('premises_nonvacuous',True) and x['result']=='unsat'
   assert len(p)==len(q)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(p,q))
 assert a==fresh and e['verified_counts']==COUNTS and a['independent_totals']==TOTALS
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 assert e['kernel_collection_sha256']==a['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 assert a['unexecuted_bulk_PCs']==['0xfffffe000bd74cd4']
 assert all(not names for names in e['exact_symbols'].values())
 report=read(BASE/'kernel_magazine_bulk_return_report.md')
 for j in range(1,8):assert '| KB'+str(j)+' |' in report and '**QG'+str(j)+'**' in report
 for j in range(1,7):assert '| KB-A'+str(j)+':' in report
 for word in [CHECKS_SHA,AUDIT_SHA,'0xfffffe000bd74bec','0xfffffe000bd74f80','364','247','248','0xffffffff']:assert word in report
 for p in CHANGED:
  if p.endswith('.md'):assert 'kernel_magazine_bulk_return_report.md' in read(BASE/p)
 for receipt in [e,a]:
  hygiene(receipt);assert receipt['conditional_kernel_magazine_bulk_return_contract_established'] is True
  for key in R.FALSE:assert receipt[key] is False
 print(json.dumps({'fresh_extraction_audit_match':True,'source_queries_reconstructed_and_resolved':21,
  'separation_lemmas_rechecked':2,'components_rebuilt_and_matched':44,
  'changed_source_controls_rejected':2,'native_target_executed':False}),flush=True)
 return e,a

def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']} for m in [old,new])
 assert len(before)==9377 and len(after)==9384 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED
 assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256'] and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
 for key,x in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),
  ('new_source_queries_unsat',21),('rechecked_separation_lemmas_unsat',2),
  ('conditional_kernel_magazine_bulk_return_contract_established',True)]:assert new['validation'][R.P+'_'+key]==x
 assert new['validation']['reports']==old['validation']['reports']+1==608
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 assert new['goal_status']=='active'
 for p in ARCHIVES:assert not (BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode();path_hygiene(decoded)
  assert not re.search(rb'/(?:Users/(?!Shared(?:/|\b))|home/|tmp/|private/|Library[/]Developer/|opt[/]homebrew/)',decoded)
 path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
 assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':608,
  'original_inputs_preserved':3,**COUNTS,**TOTALS,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':publication(*receipts())
