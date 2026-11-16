#!/usr/bin/env python3
"""Rebuild kernel allocator boundary obligations and verify exact publication custody.
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
import recover_kernel_allocator_boundary as R
import audit_kernel_allocator_boundary as A

PREVIOUS='107e3828406beaa79b91cca104f5398d02193987'
BASELINE_SHA='41cfef1665949501943203e675ad3200b9fce2bd83c87c9edc1e74b92b0c6c0c'
CHECKS_SHA='3a5cc821c3e6527e0e5058ccaab1a21982d96fd5e8bfa68ccc8518f5f08f3e83'
AUDIT_SHA='02b90e8e2341842d4c2ae6131d3ff0a38da20481bd3dd649bba8ef64ced91863'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'triage_evidence/validate_rpc502_sidecar_delivery.py', 'userclient_parser_cleanup_report.md', 'userclient_query_failure_report.md', 'interface_abi_report.md', 'userclient_context_lifecycle_report.md', 'userclient_hash_table_reclamation_report.md', 'foundational_triage_report.md', 'mach_ports_report.md', 'interface_investigation_status.md', 'aes_carrier_initialization_report.md', 'obfuscated_routines_report.md'}
ADDED={'kernel_allocator_boundary_report.md', 'triage_evidence/verify_kernel_allocator_boundary_delivery.py', 'triage_evidence/audit_kernel_allocator_boundary.py', 'triage_evidence/recover_kernel_allocator_boundary.py', 'triage_evidence/kernel_allocator_boundary_audit.json', 'triage_evidence/kernel_allocator_boundary_checks.json'}
ARCHIVES={MANIFEST,'triage_evidence/kernel_allocator_boundary_checks.json','triage_evidence/kernel_allocator_boundary_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'kernel_functions': 8, 'captured_function_instructions': 340, 'source_spans': 27, 'selected_instructions': 131, 'authenticated_return_envelopes': 6, 'small_query_data_bytes': 14, 'typed_query_node_bytes': 32}
TOTALS={'new_source_queries_unsat': 19, 'prior_source_queries_unsat': 7, 'distinct_proved_instructions': 131, 'proof_instruction_instances': 291, 'linked_edge_obligations': 272, 'small_query_extents': 2, 'altered_return_register_counterexample': True}

def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
 assert e==R.build();fresh=A.audit();old,new=a.pop('source_proofs'),fresh.pop('source_proofs')
 assert a==fresh and e['verified_counts']==COUNTS and a['independent_totals']==TOTALS and len(old)==len(new)==19
 for x,y in zip(old,new):
  x,y=dict(x),dict(y);p,q=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'))
  assert x==y and x['premises_nonvacuous'] and x['result']=='unsat'
  assert len(p)==len(q)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(p,q))
  s=z3.Solver();s.set(timeout=30000);s.add(*p);assert s.check()==z3.unsat
 a['source_proofs']=old
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 assert e['kernel_collection_sha256']==a['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 report=read(BASE/'kernel_allocator_boundary_report.md')
 for j in range(1,8):
  assert '| KA'+str(j)+' |' in report and '| KA-A'+str(j)+':' in report and '**QG'+str(j)+'**' in report
 for word in [CHECKS_SHA,AUDIT_SHA,'0xfffffe000bcfe774','0xfffffe000bcfec9c','131','291','272','KA-A7','mod65536']:assert word in report
 for p in CHANGED:
  if p.endswith('.md'):assert 'kernel_allocator_boundary_report.md' in read(BASE/p)
 for receipt in [e,a]:
  hygiene(receipt);assert receipt['conditional_kernel_allocator_boundary_contract_established'] is True
  for key in R.FALSE:assert receipt[key] is False
 print(json.dumps({'fresh_extraction_audit_match':True,'source_queries_reconstructed_and_resolved':19,
  'prior_source_queries_rechecked':7,'native_target_executed':False}),flush=True)
 return e,a

def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']} for m in [old,new])
 assert len(before)==9312 and len(after)==9318 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED
 assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256'] and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
 for key,x in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),
  ('new_source_queries_unsat',19),('prior_source_queries_rechecked',7),('conditional_kernel_allocator_boundary_contract_established',True)]:
  assert new['validation'][R.P+'_'+key]==x
 assert new['validation']['reports']==old['validation']['reports']+1==598
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 assert new['goal_status']=='active'
 for p in ARCHIVES:assert not (BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode();path_hygiene(decoded)
  assert not re.search(rb'/(?:Users/(?!Shared(?:/|\b))|home/|tmp/|private/|Library[/]Developer/|opt[/]homebrew/)',decoded)
 path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
 assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':598,
  'original_inputs_preserved':3,**COUNTS,**TOTALS,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':publication(*receipts())
