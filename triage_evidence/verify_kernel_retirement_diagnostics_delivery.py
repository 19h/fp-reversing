#!/usr/bin/env python3
"""Rebuild kernel retirement diagnostics obligations and verify exact publication custody.
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
import recover_kernel_retirement_diagnostics as R
import audit_kernel_retirement_diagnostics as A

PREVIOUS='cc13f5c1ed77cd4caabc975fb51303d0b8a407bd'
BASELINE_SHA='a6785d84de630da7df952988500253e0168834c9f40f197363c44d7ba41b506a'
CHECKS_SHA='6dcd5c0912c7d6ddf346dda4746f5f5b55411b9279b18b1d1e3180e34237efc9'
AUDIT_SHA='3cd8a3d4c466c3877a6668991634020cb658c8807452d9bf111053b0b2ff48ac'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'obfuscated_routines_report.md', 'kernel_retirement_query_report.md', 'foundational_triage_report.md', 'kernel_allocator_boundary_report.md', 'interface_investigation_status.md', 'triage_evidence/validate_rpc502_sidecar_delivery.py', 'mach_ports_report.md', 'mixed_data_retirement_report.md', 'kernel_retirement_dispatch_report.md', 'interface_abi_report.md', 'userclient_query_failure_report.md'}
ADDED={'triage_evidence/verify_kernel_retirement_diagnostics_delivery.py', 'triage_evidence/audit_kernel_retirement_diagnostics.py', 'kernel_retirement_diagnostics_report.md', 'triage_evidence/kernel_retirement_diagnostics_checks.json', 'triage_evidence/recover_kernel_retirement_diagnostics.py', 'triage_evidence/kernel_retirement_diagnostics_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/kernel_retirement_diagnostics_checks.json','triage_evidence/kernel_retirement_diagnostics_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'kernel_functions': 2, 'source_spans': 10, 'selected_instructions': 80, 'captured_function_bytes': 320, 'reused_caller_spans': 2, 'reused_caller_instructions': 5, 'literal_records': 7, 'name_table_fixups': 5, 'direct_call_sites': 5}
TOTALS={'new_source_queries_unsat': 15, 'prior_source_queries_unsat': 5, 'distinct_new_proved_instructions': 80, 'distinct_reused_proved_instructions': 5, 'proof_instruction_instances': 412, 'linked_edge_obligations': 397, 'linked_valid_zone_panic_routes': 4, 'explicit_metadata_intervention_queries': 2, 'altered_typed_diagnostic_store_counterexample': True}

def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
 assert e==R.build();fresh=A.audit();old,new=a.pop('source_proofs'),fresh.pop('source_proofs')
 negative,rebuilt_negative=a.pop('negative_control'),fresh.pop('negative_control')
 x,y=dict(negative),dict(rebuilt_negative);p,q=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'))
 assert x==y and len(p)==len(q)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(p,q))
 s=z3.Solver();s.set(timeout=30000);s.add(*p);assert s.check()==z3.sat
 assert a==fresh and e['verified_counts']==COUNTS and a['independent_totals']==TOTALS and len(old)==len(new)==15
 assert sum('environment_intervention' in q for q in old)==2
 for x,y in zip(old,new):
  x,y=dict(x),dict(y);p,q=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'))
  assert x==y and x['premises_nonvacuous'] and x['result']=='unsat'
  assert len(p)==len(q)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(p,q))
  s=z3.SolverFor(x['logic']) if 'logic' in x else z3.Solver();s.set(timeout=30000);s.add(*p);assert s.check()==z3.unsat
 a['source_proofs']=old;a['negative_control']=negative
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 assert e['kernel_collection_sha256']==a['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 report=read(BASE/'kernel_retirement_diagnostics_report.md')
 for j in range(1,8):
  assert '| KE'+str(j)+' |' in report and '| KE-A'+str(j)+':' in report and '**QG'+str(j)+'**' in report
 for word in [CHECKS_SHA,AUDIT_SHA,'0xfffffe000c62a2b0','0xfffffe000c62d4dc','80','412','397','KE-A7','_panic']:assert word in report
 for p in CHANGED:
  if p.endswith('.md'):assert 'kernel_retirement_diagnostics_report.md' in read(BASE/p)
 for receipt in [e,a]:
  hygiene(receipt);assert receipt['conditional_kernel_retirement_diagnostics_contract_established'] is True
  for key in R.FALSE:assert receipt[key] is False
 print(json.dumps({'fresh_extraction_audit_match':True,'source_queries_reconstructed_and_resolved':15,
  'prior_source_queries_rechecked':5,'native_target_executed':False}),flush=True)
 return e,a

def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']} for m in [old,new])
 assert len(before)==9330 and len(after)==9336 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED
 assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256'] and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
 for key,x in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),
  ('new_source_queries_unsat',15),('prior_source_queries_rechecked',5),('conditional_kernel_retirement_diagnostics_contract_established',True)]:
  assert new['validation'][R.P+'_'+key]==x
 assert new['validation']['reports']==old['validation']['reports']+1==601
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 assert new['goal_status']=='active'
 for p in ARCHIVES:assert not (BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode();path_hygiene(decoded)
  assert not re.search(rb'/(?:Users/(?!Shared(?:/|\b))|home/|tmp/|private/|Library[/]Developer/|opt[/]homebrew/)',decoded)
 path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
 assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':601,
  'original_inputs_preserved':3,**COUNTS,**TOTALS,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':publication(*receipts())
