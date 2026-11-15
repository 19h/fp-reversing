#!/usr/bin/env python3
"""Reconstruct the context UIDList publication receipt and verify publication custody.
O(owned bytes+query DAG) wrapper time/space, excluding documented solver cost.
No target calls, IDB mutations or history rewrite.
"""
import json
import re
from hashlib import sha256
from compression import zstd
import z3
from kext_port_tools import ROOT, SOURCE
from verify_daemon_reader_record_payloads_publication import read, sha, size
from verify_daemon_payload_mix_publication import BASE, git, hygiene, path_hygiene
from verify_daemon_second_mix_publication import canonical_expression
import recover_userclient_uidlist_publication as R
import audit_userclient_uidlist_publication as A

PREVIOUS='b04c2ddfe81368bce78b1fa794ad182d89cb2f8f'
BASELINE_SHA='cd44505094d955b1d236a5cdfcb992f6cd7f24ad4e8c5f629c2d00768af65091'
CHECKS_SHA='d9e9a2ce995fa6b3703f3eecbc63f6e22328dfd2f1e9601679b9df760dfb5b53'
AUDIT_SHA='b66d2254114e0a7d984faa024007b8193845489d9b83fa9cdcbb78661682db04'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'foundational_triage_report.md','interface_investigation_status.md','mach_ports_report.md',
 'obfuscated_routines_report.md','interface_abi_report.md','userclient_context_lifecycle_report.md',
 'userclient_hash_table_reclamation_report.md','userclient_hash_table_lookup_report.md',
 'secure_tunnel_allocation_report.md','secure_tunnel_table_insertion_report.md',
 'userclient_uidlist_cleanup_report.md','context_descriptor_task_flow_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'userclient_uidlist_publication_report.md','triage_evidence/recover_userclient_uidlist_publication.py',
 'triage_evidence/audit_userclient_uidlist_publication.py','triage_evidence/verify_userclient_uidlist_publication_delivery.py',
 'triage_evidence/userclient_uidlist_publication_checks.json','triage_evidence/userclient_uidlist_publication_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/userclient_uidlist_publication_checks.json','triage_evidence/userclient_uidlist_publication_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'source_spans': 17, 'selected_instructions': 232, 'terminal_transfers': 12, 'bank_rules': 2, 'bank_input_cases': 512, 'typed_descriptors': 2, 'node_extent_bytes': 16, 'context_extent_bytes': 24, 'payload_extent_bytes': 120}
TOTALS={'new_source_queries_unsat': 17, 'prior_source_queries_unsat': 6, 'distinct_proved_instructions': 232, 'proof_instruction_instances': 574, 'bank_input_cases_checked': 512, 'published_node_bytes_checked': 16, 'publication_stores_checked': 4}

def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
 assert e==R.build();fresh=A.audit();old,new=a.pop('source_proofs'),fresh.pop('source_proofs')
 assert a==fresh and e['verified_counts']==COUNTS and a['independent_totals']==TOTALS and len(old)==len(new)==17
 for x,y in zip(old,new):
  x,y=dict(x),dict(y);p,q=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'))
  assert x==y and x['premises_nonvacuous'] and x['result']=='unsat'
  assert len(p)==len(q)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(p,q))
  s=z3.Solver();s.set(timeout=30000);s.add(*p);assert s.check()==z3.unsat
 a['source_proofs']=old
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 report=read(BASE/'userclient_uidlist_publication_report.md')
 for j in range(1,9):assert '| UP'+str(j)+' |' in report and '| UP-A'+str(j)+':' in report
 for j in range(1,8):assert '**QG'+str(j)+'**' in report
 for word in [CHECKS_SHA,AUDIT_SHA,'0xfffffe000a65e800','0xfffffe000a65e870','0xfffffe000847b8a0',
  '0xfffffe000847b2a0','0x31ae0066','0xce515bbf','120 B','24 B','16 B','0xfffffe000a65e880']:assert word in report
 for r in e['bank_rules']:assert r['slot'] in report and r['target'] in report and r['index'] in report
 for p in CHANGED:
  if p.endswith('.md'):assert 'userclient_uidlist_publication_report.md' in read(BASE/p)
 for receipt in [e,a]:
  hygiene(receipt);assert receipt['conditional_UIDList_publication_contract_established'] is True
  for key in R.FALSE:assert receipt[key] is False
 print(json.dumps({'fresh_extraction_audit_match':True,'source_queries_reconstructed_and_resolved':17,
  'prior_source_queries_rechecked':6,'native_target_executed':False}),flush=True)
 return e,a

def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']} for m in [old,new])
 assert len(before)==9186 and len(after)==9192 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED
 assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256'] and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
 for key,x in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),
  ('new_source_queries_unsat',17),('prior_source_queries_rechecked',6),('conditional_UIDList_publication_contract_established',True)]:
  assert new['validation'][R.P+'_'+key]==x
 assert new['validation']['reports']==old['validation']['reports']+1==577
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 assert new['goal_status']=='active'
 for p in ARCHIVES:assert not (BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode();path_hygiene(decoded)
  assert not re.search(rb'/(?:Users/(?!Shared(?:/|\b))|home/|tmp/|private/|Library[/]Developer/|opt[/]homebrew/)',decoded)
 path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
 assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':577,
  'original_inputs_preserved':3,**COUNTS,**TOTALS,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':publication(*receipts())
