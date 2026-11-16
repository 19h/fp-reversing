#!/usr/bin/env python3
"""Rebuild query writer obligations and verify exact publication custody.
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
import recover_userclient_query_writer as R
import audit_userclient_query_writer as A

PREVIOUS='6b8a9240559a70be338e46a1f7037c4416ddb8fb'
BASELINE_SHA='c653fd266c388237fd079a4b9cf491fa006799435eec6cbed390d4e10582b2bd'
CHECKS_SHA='1a183d8958078e52c40c5cdd817d317134781888c9a0159aa732520ffac7b1bb'
AUDIT_SHA='93fdbacd3030e57c85cb8a13a31592f5529568892a65caa66f88c2562ff44db2'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'userclient_record_writer_report.md', 'userclient_serializer_emission_report.md', 'userclient_record_metadata_report.md', 'obfuscated_routines_report.md', 'userclient_query_records_report.md', 'interface_investigation_status.md', 'mach_ports_report.md', 'foundational_triage_report.md', 'interface_abi_report.md', 'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'userclient_query_writer_report.md', 'triage_evidence/userclient_query_writer_audit.json', 'triage_evidence/verify_userclient_query_writer_delivery.py', 'triage_evidence/audit_userclient_query_writer.py', 'triage_evidence/recover_userclient_query_writer.py', 'triage_evidence/userclient_query_writer_checks.json'}
ARCHIVES={MANIFEST,'triage_evidence/userclient_query_writer_checks.json','triage_evidence/userclient_query_writer_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'source_spans': 8, 'selected_instructions': 264, 'terminal_transfers': 8, 'original_branch_pointers': 11, 'nominal_pointer_guards': 4, 'request_cases': 3, 'record_extent_bytes': 14}
TOTALS={'new_source_queries_unsat': 29, 'prior_source_queries_unsat': 6, 'distinct_new_proved_instructions': 260, 'distinct_predecessor_proved_instructions': 436, 'proof_instruction_instances': 15474, 'excluded_retag_instructions': 4, 'record_profiles': 24, 'profile_byte_stores': 336, 'profile_base_mod8_cases': 8, 'bank_composition_input_cases': 1280, 'altered_type_literal_counterexample': True}

def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
 assert e==R.build();fresh=A.audit();old,new=a.pop('source_proofs'),fresh.pop('source_proofs')
 assert a==fresh and e['verified_counts']==COUNTS and a['independent_totals']==TOTALS and len(old)==len(new)==29
 for x,y in zip(old,new):
  x,y=dict(x),dict(y);p,q=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'))
  assert x==y and x['premises_nonvacuous'] and x['result']=='unsat'
  assert len(p)==len(q)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(p,q))
  s=z3.Solver();s.set(timeout=30000);s.add(*p);assert s.check()==z3.unsat
 a['source_proofs']=old
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 report=read(BASE/'userclient_query_writer_report.md')
 for j in range(1,8):
  assert '| QW'+str(j)+' |' in report and '| QW-A'+str(j)+':' in report and '**QG'+str(j)+'**' in report
 for word in [CHECKS_SHA,AUDIT_SHA,'0xfffffe000a655014','0xfffffe000a655d34','0xa129','260','15,474','1,280','QW-A7']:assert word in report
 for p in CHANGED:
  if p.endswith('.md'):assert 'userclient_query_writer_report.md' in read(BASE/p)
 for receipt in [e,a]:
  hygiene(receipt);assert receipt['conditional_query_writer_contract_established'] is True
  for key in R.FALSE:assert receipt[key] is False
 print(json.dumps({'fresh_extraction_audit_match':True,'source_queries_reconstructed_and_resolved':29,
  'prior_source_queries_rechecked':6,'native_target_executed':False}),flush=True)
 return e,a

def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']} for m in [old,new])
 assert len(before)==9294 and len(after)==9300 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED
 assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256'] and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
 for key,x in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),
  ('new_source_queries_unsat',29),('prior_source_queries_rechecked',6),('conditional_query_writer_contract_established',True)]:
  assert new['validation'][R.P+'_'+key]==x
 assert new['validation']['reports']==old['validation']['reports']+1==595
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 assert new['goal_status']=='active'
 for p in ARCHIVES:assert not (BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode();path_hygiene(decoded)
  assert not re.search(rb'/(?:Users/(?!Shared(?:/|\b))|home/|tmp/|private/|Library[/]Developer/|opt[/]homebrew/)',decoded)
 path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
 assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':595,
  'original_inputs_preserved':3,**COUNTS,**TOTALS,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':publication(*receipts())
