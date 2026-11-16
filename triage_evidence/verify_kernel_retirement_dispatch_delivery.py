#!/usr/bin/env python3
"""Rebuild kernel retirement dispatch obligations and verify exact publication custody.
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
import recover_kernel_retirement_dispatch as R
import audit_kernel_retirement_dispatch as A

PREVIOUS='c2e8e567fe3eee69bdf7d2e2e67fb5b7eb04e983'
BASELINE_SHA='f27344b705e324f1309994d7279d16b47833e89c20d09ddb050735af7d370966'
CHECKS_SHA='5845261a55f5222e41d7a405a1666d3775a2d4285909947f4dffb77b2e823c62'
AUDIT_SHA='b3a0c655276c8cce73a29e33fe7843e65f3c3ac5b5a90fd8819559b50ea10d40'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'userclient_query_failure_report.md', 'kernel_retirement_query_report.md', 'interface_abi_report.md', 'interface_investigation_status.md', 'triage_evidence/validate_rpc502_sidecar_delivery.py', 'mach_ports_report.md', 'foundational_triage_report.md', 'mixed_data_retirement_report.md', 'obfuscated_routines_report.md', 'kernel_allocator_boundary_report.md', 'mixed_data_zone_geometry_report.md'}
ADDED={'triage_evidence/verify_kernel_retirement_dispatch_delivery.py', 'triage_evidence/audit_kernel_retirement_dispatch.py', 'kernel_retirement_dispatch_report.md', 'triage_evidence/kernel_retirement_dispatch_checks.json', 'triage_evidence/recover_kernel_retirement_dispatch.py', 'triage_evidence/kernel_retirement_dispatch_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/kernel_retirement_dispatch_checks.json','triage_evidence/kernel_retirement_dispatch_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'source_spans': 14, 'selected_instructions': 73, 'captured_function_bytes': 292, 'original_function_matches': 2, 'direct_transfer_sites': 4, 'named_clear_aliases': 2}
TOTALS={'new_source_queries_unsat': 20, 'prior_source_queries_unsat': 5, 'distinct_proved_instructions': 73, 'proof_instruction_instances': 449, 'linked_edge_obligations': 429, 'normal_request_contexts': 2, 'altered_ordinary_fallback_class_counterexample': True}

def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
 assert e==R.build();fresh=A.audit();old,new=a.pop('source_proofs'),fresh.pop('source_proofs')
 negative,rebuilt_negative=a.pop('negative_control'),fresh.pop('negative_control')
 x,y=dict(negative),dict(rebuilt_negative);p,q=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'))
 assert x==y and len(p)==len(q)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(p,q))
 s=z3.Solver();s.set(timeout=30000);s.add(*p);assert s.check()==z3.sat
 assert a==fresh and e['verified_counts']==COUNTS and a['independent_totals']==TOTALS and len(old)==len(new)==20
 for x,y in zip(old,new):
  x,y=dict(x),dict(y);p,q=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'))
  assert x==y and x['premises_nonvacuous'] and x['result']=='unsat'
  assert len(p)==len(q)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(p,q))
  s=z3.SolverFor(x['logic']) if 'logic' in x else z3.Solver();s.set(timeout=30000);s.add(*p);assert s.check()==z3.unsat
 a['source_proofs']=old;a['negative_control']=negative
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 assert e['kernel_collection_sha256']==a['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 report=read(BASE/'kernel_retirement_dispatch_report.md')
 for j in range(1,8):
  assert '| KD'+str(j)+' |' in report and '| KD-A'+str(j)+':' in report and '**QG'+str(j)+'**' in report
 for word in [CHECKS_SHA,AUDIT_SHA,'0xfffffe000bcfee78','0xfffffe000bcfeea4','73','449','429','KD-A7','132480']:assert word in report
 for p in CHANGED:
  if p.endswith('.md'):assert 'kernel_retirement_dispatch_report.md' in read(BASE/p)
 for receipt in [e,a]:
  hygiene(receipt);assert receipt['conditional_kernel_retirement_dispatch_contract_established'] is True
  for key in R.FALSE:assert receipt[key] is False
 print(json.dumps({'fresh_extraction_audit_match':True,'source_queries_reconstructed_and_resolved':20,
  'prior_source_queries_rechecked':5,'native_target_executed':False}),flush=True)
 return e,a

def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']} for m in [old,new])
 assert len(before)==9324 and len(after)==9330 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED
 assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256'] and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
 for key,x in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),
  ('new_source_queries_unsat',20),('prior_source_queries_rechecked',5),('conditional_kernel_retirement_dispatch_contract_established',True)]:
  assert new['validation'][R.P+'_'+key]==x
 assert new['validation']['reports']==old['validation']['reports']+1==600
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 assert new['goal_status']=='active'
 for p in ARCHIVES:assert not (BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode();path_hygiene(decoded)
  assert not re.search(rb'/(?:Users/(?!Shared(?:/|\b))|home/|tmp/|private/|Library[/]Developer/|opt[/]homebrew/)',decoded)
 path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
 assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':600,
  'original_inputs_preserved':3,**COUNTS,**TOTALS,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':publication(*receipts())
