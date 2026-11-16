#!/usr/bin/env python3
"""Rebuild query failure obligations and verify exact publication custody.
O(owned bytes+query DAG) wrapper time/space; separate SMT search.
No target calls, IDB mutations or history rewrite.
"""
import json
import re
from hashlib import sha256
from compression import zstd
import z3
from kext_port_tools import ROOT,SOURCE
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_daemon_payload_mix_publication import BASE,git,hygiene,path_hygiene
from verify_daemon_second_mix_publication import canonical_expression
import recover_userclient_query_failure as R
import audit_userclient_query_failure as A

PREVIOUS='a062002fb02deadacedd9a8ac18a048570fea6d9'
BASELINE_SHA='00a237e2196017b8d2fb0072bba31ec260613b2d0af596fe99480a417600da6c'
CHECKS_SHA='f380d2d20a463917d898a07e55961fcf50f80893c9787978d4e6248885fdb9a8'
AUDIT_SHA='206ccc839f9581abd6256dbf2bb14a9b1e89c90bdcb6f927b33d171ad46162b6'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'userclient_context_lifecycle_report.md', 'interface_investigation_status.md', 'userclient_query_records_report.md', 'foundational_triage_report.md', 'userclient_query_publication_report.md', 'obfuscated_routines_report.md', 'interface_abi_report.md', 'mach_ports_report.md', 'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'triage_evidence/userclient_query_failure_checks.json', 'triage_evidence/verify_userclient_query_failure_delivery.py', 'triage_evidence/audit_userclient_query_failure.py', 'userclient_query_failure_report.md', 'triage_evidence/recover_userclient_query_failure.py', 'triage_evidence/userclient_query_failure_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/userclient_query_failure_checks.json','triage_evidence/userclient_query_failure_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'source_spans': 15, 'selected_instructions': 154, 'terminal_transfers': 13, 'original_branch_pointers': 4, 'bank_rules': 3, 'bank_input_cases': 768, 'cleanup_node_bytes': 32, 'literal_error_slot_accesses': 48, 'literal_error_slot_stores': 1, 'kernel_function_containers': 3}
TOTALS={'new_source_queries_unsat': 30, 'prior_source_queries_unsat': 5, 'distinct_new_proved_instructions': 154, 'distinct_predecessor_proved_instructions': 479, 'proof_instruction_instances': 8531, 'bank_composition_input_cases': 768, 'saved_request_callback_cases': 3, 'altered_status_literal_counterexample': True}

def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
 assert e==R.build();fresh=A.audit();old,new=a.pop('source_proofs'),fresh.pop('source_proofs')
 assert a==fresh and e['verified_counts']==COUNTS and a['independent_totals']==TOTALS and len(old)==len(new)==30
 for x,y in zip(old,new):
  x,y=dict(x),dict(y);p,q=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'))
  assert x==y and x['premises_nonvacuous'] and x['result']=='unsat'
  assert len(p)==len(q)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(p,q))
  s=z3.Solver();s.set(timeout=30000);s.add(*p);assert s.check()==z3.unsat
 a['source_proofs']=old
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 report=read(BASE/'userclient_query_failure_report.md')
 for j in range(1,8):
  assert '| QF'+str(j)+' |' in report and '| QF-A'+str(j)+':' in report and '**QG'+str(j)+'**' in report
 for word in [CHECKS_SHA,AUDIT_SHA,'0xfffffe000a6641e4','0xfffffe000a66413c','0xce515bb2','154','8,531','768','QF-A7','0xd1044']:assert word in report
 for p in CHANGED:
  if p.endswith('.md'):assert 'userclient_query_failure_report.md' in read(BASE/p)
 for receipt in [e,a]:
  hygiene(receipt);assert receipt['conditional_query_failure_contract_established'] is True
  for key in R.FALSE:assert receipt[key] is False
 print(json.dumps({'fresh_extraction_audit_match':True,'source_queries_reconstructed_and_resolved':30,
  'prior_source_queries_rechecked':5,'native_target_executed':False}),flush=True)
 return e,a

def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']} for m in [old,new])
 assert len(before)==9306 and len(after)==9312 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED
 assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256'] and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
 for key,x in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),
  ('new_source_queries_unsat',30),('prior_source_queries_rechecked',5),('conditional_query_failure_contract_established',True)]:
  assert new['validation'][R.P+'_'+key]==x
 assert new['validation']['reports']==old['validation']['reports']+1==597
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 assert new['goal_status']=='active'
 for p in ARCHIVES:assert not (BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode();path_hygiene(decoded)
  assert not re.search(rb'/(?:Users/(?!Shared(?:/|\b))|home/|tmp/|private/|Library[/]Developer/|opt[/]homebrew/)',decoded)
 path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
 assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':597,
  'original_inputs_preserved':3,**COUNTS,**TOTALS,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':publication(*receipts())
