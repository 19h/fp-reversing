#!/usr/bin/env python3
"""Fresh observer/event source/component reconstruction and publication custody.
O(owned bytes + query DAG + component RAM/journals) wrapper time/space;
SMT search separate. No target calls, IDB mutations or history rewrite.
"""
import json,re
from hashlib import sha256
from compression import zstd
import z3
from kext_port_tools import ROOT,SOURCE
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_daemon_payload_mix_publication import BASE,git,hygiene,path_hygiene
from verify_daemon_second_mix_publication import canonical_expression
import recover_kernel_zone_observer_event as R
import audit_kernel_zone_observer_event as A
PREVIOUS='ddba1c756d3589bc6ed16631f1fdee45e28a1b3d'
BASELINE_SHA='3718515fabd966c21b7830e1d17284d66379abedeaef32404beced8697bd81a6'
CHECKS_SHA='64cf3d39a1796076cf55ae3933bcd555e2672133076980bf24ac95c3a7fbbeb4'
AUDIT_SHA='be279f8e583e57a51c4d69424ab4560fdd528331f32463d32e47f54c5bec92c8'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'obfuscated_routines_report.md','foundational_triage_report.md','interface_investigation_status.md',
 'mach_ports_report.md','interface_abi_report.md','kernel_zone_retirement_report.md','kernel_retirement_magazines_report.md',
 'kernel_zone_bitmap_release_report.md','aes_event_registration_report.md','aes_event_wake_selection_report.md',
 'event_wait_table_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'kernel_zone_observer_event_report.md','triage_evidence/recover_kernel_zone_observer_event.py',
 'triage_evidence/audit_kernel_zone_observer_event.py','triage_evidence/probe_kernel_zone_observer_event.py',
 'triage_evidence/verify_kernel_zone_observer_event_delivery.py','triage_evidence/kernel_zone_observer_event_checks.json',
 'triage_evidence/kernel_zone_observer_event_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/kernel_zone_observer_event_checks.json','triage_evidence/kernel_zone_observer_event_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'new_complete_functions':2,'new_instructions':143,'captured_functions':5,'captured_instructions':305,
 'captured_bytes':1220,'source_blocks':17,'block_instructions':119,'direct_call_sites':8,
 'authenticated_indirect_call_sites':2,'original_function_matches':3}
TOTALS={'source_queries_unsat':17,'composition_queries_unsat':2,'prior_queries_unsat':10,'rechecked_separation_lemmas_unsat':2,
 'proved_source_PCs':119,'proof_instruction_instances':131,'linked_edge_obligations':114,'checked_read_store_rewrites':0,
 'components':65,'component_source_visits':9014,'new_component_PCs':143,'unexecuted_new_source_PCs':0,
 'observer_requests':84,'independent_oracle_checks':811,'changed_store_controls':2}

def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
 assert e==R.build();fresh=A.audit()
 for key,n in [('source_proofs',17),('composition_proofs',2),('rechecked_separation_lemmas',2)]:
  old,new=a.pop(key),fresh.pop(key);assert len(old)==len(new)==n
  for x,y in zip(old,new):
   x,y=dict(x),dict(y);p,q=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'))
   assert x==y and x.get('premises_nonvacuous',True) and x['result']=='unsat'
   assert len(p)==len(q)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(p,q))
  # Fresh A.audit() has solved these reconstructed queries; canonical
  # equality binds those results to the retained formulas.
 assert a==fresh and e['verified_counts']==COUNTS and a['independent_totals']==TOTALS
 assert len(a['rechecked_prior_proofs'])==10
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 assert e['kernel_collection_sha256']==a['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 root=e['observer_root'];assert root['original_bytes_hex']==root['logical_file_bytes_hex']=='0000000000000000' and root['chained_rebase'] is None
 assert len(e['root_locators']['candidates'])==2 and all(x['mnemonic']=='ldr' for x in e['root_locators']['candidates'])
 report=read(BASE/'kernel_zone_observer_event_report.md')
 for j in range(1,8):assert '| OE'+str(j)+' |' in report and '| OE-A'+str(j)+':' in report and '**QG'+str(j)+'**' in report
 for word in [CHECKS_SHA,AUDIT_SHA,'0xfffffe000bd75b54','0xfffffe000bd7332c','0xeed9','811','811 independent','OE-A7']:assert word in report
 for p in CHANGED:
  if p.endswith('.md'):assert 'kernel_zone_observer_event_report.md' in read(BASE/p)
 for receipt in [e,a]:
  hygiene(receipt);assert receipt['conditional_kernel_zone_observer_event_contract_established'] is True
  for key in R.FALSE:assert receipt[key] is False
 print(json.dumps({'fresh_extraction_audit_match':True,'source_queries_reconstructed_and_resolved':17,
  'composition_queries_reconstructed_and_resolved':2,'prior_queries_rechecked':10,'separation_lemmas_rechecked':2,
  'components_rebuilt_and_matched':65,'changed_flag_store_controls_rejected':2,'native_target_executed':False}),flush=True)
 return e,a

def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']} for m in [old,new])
 assert len(before)==9356 and len(after)==9363 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED
 assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256'] and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
 for key,x in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),
  ('new_source_queries_unsat',17),('new_composition_queries_unsat',2),('prior_queries_unsat',10),('rechecked_separation_lemmas_unsat',2),
  ('conditional_kernel_zone_observer_event_contract_established',True)]:assert new['validation'][R.P+'_'+key]==x
 assert new['validation']['reports']==old['validation']['reports']+1==605
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 assert new['goal_status']=='active'
 for p in ARCHIVES:assert not (BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode();path_hygiene(decoded)
  assert not re.search(rb'/(?:Users/(?!Shared(?:/|\b))|home/|tmp/|private/|Library[/]Developer/|opt[/]homebrew/)',decoded)
 path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
 assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':605,
  'original_inputs_preserved':3,**COUNTS,**TOTALS,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':publication(*receipts())
