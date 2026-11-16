#!/usr/bin/env python3
"""Fresh source/component reconstruction and exact publication custody.
O(owned bytes + formula DAG + component RAM/journals) wrapper time/space;
SMT search separate. No target effects, IDB changes or history rewrite.
"""
import json,re
from hashlib import sha256
from compression import zstd
import z3
from kext_port_tools import ROOT,SOURCE
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_daemon_payload_mix_publication import BASE,git,hygiene,path_hygiene
from verify_daemon_second_mix_publication import canonical_expression
import recover_kernel_zone_bitmap_release as R
import audit_kernel_zone_bitmap_release as A
PREVIOUS='4f9f48297ca9b9c40545b3183b3b89f9e83de8dc'
BASELINE_SHA='72a793e93f5a1548175d50181b3f8cc1ffdfcf2e011bc5f3f1777fb75fa11d84'
CHECKS_SHA='9c92ce8ad5dfa3bdbbee5b55b9de96b332dff83f677c7cd107506a2f2ecc65db'
AUDIT_SHA='30c1cc9abbe3076303416504298a51540cee36ef1351acf5841639e07cc77078'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'obfuscated_routines_report.md','foundational_triage_report.md','interface_investigation_status.md',
 'mach_ports_report.md','interface_abi_report.md','kernel_allocator_boundary_report.md','mixed_data_retirement_report.md',
 'kernel_zone_retirement_report.md','kernel_retirement_magazines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'kernel_zone_bitmap_release_report.md','triage_evidence/recover_kernel_zone_bitmap_release.py',
 'triage_evidence/audit_kernel_zone_bitmap_release.py','triage_evidence/probe_kernel_zone_bitmap_release.py',
 'triage_evidence/verify_kernel_zone_bitmap_release_delivery.py','triage_evidence/kernel_zone_bitmap_release_checks.json',
 'triage_evidence/kernel_zone_bitmap_release_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/kernel_zone_bitmap_release_checks.json','triage_evidence/kernel_zone_bitmap_release_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'complete_release_instructions':279,'complete_release_bytes':1116,'complete_unlock_instructions':26,
 'complete_unlock_bytes':104,'source_blocks':16,'block_instructions':66,'call_sites':9,'external_tail_sites':1,
 'distinct_external_targets':10,'original_function_matches':2}
TOTALS={'source_queries_unsat':16,'composition_queries_unsat':2,'rechecked_separation_lemmas_unsat':2,
 'proved_source_PCs':66,'proof_instruction_instances':107,'linked_edge_obligations':91,'checked_read_store_rewrites':200,
 'components':66,'component_source_visits':7507,'captured_component_PCs':304,'unexecuted_captured_PCs':1,
 'independent_oracle_checks':897,'changed_store_controls':2}

def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
 assert e==R.build();fresh=A.audit()
 for key,n in [('source_proofs',16),('composition_proofs',2),('rechecked_separation_lemmas',2)]:
  old,new=a.pop(key),fresh.pop(key);assert len(old)==len(new)==n
  for x,y in zip(old,new):
   x,y=dict(x),dict(y);p,q=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'))
   assert x==y and x.get('premises_nonvacuous',True) and x['result']=='unsat'
   assert len(p)==len(q)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(p,q))
  # Fresh A.audit() has solved the reconstructed queries. Canonical AST
  # equality binds those solver results to the published formulas.
 assert a==fresh and e['verified_counts']==COUNTS and a['independent_totals']==TOTALS
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 assert e['kernel_collection_sha256']==a['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 report=read(BASE/'kernel_zone_bitmap_release_report.md')
 for j in range(1,8):assert '| BR'+str(j)+' |' in report and '| BR-A'+str(j)+':' in report and '**QG'+str(j)+'**' in report
 for word in [CHECKS_SHA,AUDIT_SHA,'0xfffffe000bd756f8','0xfffffe000bd75844','0xfffffe000bd0ab18','897','2 GiB','BR-A7']:assert word in report
 for p in CHANGED:
  if p.endswith('.md'):assert 'kernel_zone_bitmap_release_report.md' in read(BASE/p)
 for receipt in [e,a]:
  hygiene(receipt);assert receipt['conditional_kernel_zone_bitmap_release_contract_established'] is True
  for key in R.FALSE:assert receipt[key] is False
 print(json.dumps({'fresh_extraction_audit_match':True,'source_queries_reconstructed_and_resolved':16,
  'composition_queries_reconstructed_and_resolved':2,'separation_lemmas_rechecked':2,
  'components_rebuilt_and_matched':66,'changed_store_controls_rejected':2,'native_target_executed':False}),flush=True)
 return e,a

def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']} for m in [old,new])
 assert len(before)==9349 and len(after)==9356 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED
 assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256'] and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
 for key,x in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),
  ('new_source_queries_unsat',16),('new_composition_queries_unsat',2),('rechecked_separation_lemmas_unsat',2),
  ('conditional_kernel_zone_bitmap_release_contract_established',True)]:assert new['validation'][R.P+'_'+key]==x
 assert new['validation']['reports']==old['validation']['reports']+1==604
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 assert new['goal_status']=='active'
 for p in ARCHIVES:assert not (BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode();path_hygiene(decoded)
  assert not re.search(rb'/(?:Users/(?!Shared(?:/|\b))|home/|tmp/|private/|Library[/]Developer/|opt[/]homebrew/)',decoded)
 path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
 assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':604,
  'original_inputs_preserved':3,**COUNTS,**TOTALS,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':publication(*receipts())
