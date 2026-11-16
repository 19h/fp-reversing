#!/usr/bin/env python3
"""Rebuild query publication obligations and verify exact publication custody.
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
import recover_userclient_query_publication as R
import audit_userclient_query_publication as A

PREVIOUS='396df595abf749e5ed93e7f4ac8cd6d28e250ce7'
BASELINE_SHA='a277929077668baba8768b14c8d51a8868b520fc61e756fb1fe624acaa637e50'
CHECKS_SHA='5d83e2204a81e68d86908a80548779057004a915d36d977af33edbab8c170ff1'
AUDIT_SHA='afd14d7d595374732c477db69b527ef6dee0f56c3a0c84c799ebc2e6bf2707ea'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'userclient_record_publication_report.md', 'userclient_serializer_emission_report.md', 'userclient_query_records_report.md', 'interface_investigation_status.md', 'foundational_triage_report.md', 'userclient_query_writer_report.md', 'triage_evidence/validate_rpc502_sidecar_delivery.py', 'userclient_serializer_extent_report.md', 'obfuscated_routines_report.md', 'mach_ports_report.md', 'interface_abi_report.md'}
ADDED={'userclient_query_publication_report.md', 'triage_evidence/userclient_query_publication_audit.json', 'triage_evidence/verify_userclient_query_publication_delivery.py', 'triage_evidence/audit_userclient_query_publication.py', 'triage_evidence/recover_userclient_query_publication.py', 'triage_evidence/userclient_query_publication_checks.json'}
ARCHIVES={MANIFEST,'triage_evidence/userclient_query_publication_checks.json','triage_evidence/userclient_query_publication_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'source_spans': 32, 'selected_instructions': 427, 'terminal_transfers': 29, 'original_branch_pointers': 27, 'bank_rules': 4, 'bank_input_cases': 1024, 'nominal_pointer_guards': 4, 'retirement_node_bytes': 32, 'inventoried_output_slot_accesses': 3}
TOTALS={'new_source_queries_unsat': 75, 'prior_source_queries_unsat': 12, 'distinct_proved_instructions': 423, 'proof_instruction_instances': 6845, 'excluded_retag_instructions': 4, 'bank_composition_input_cases': 1024, 'new_composition_queries_unsat': 4, 'append_cases': 2, 'replacement_positions': 4, 'replacement_data_cases': 8, 'saved_request_callback_cases': 3, 'altered_append_store_counterexample': True}

def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
 assert e==R.build();fresh=A.audit();composition,new_composition=a.pop('composition_proofs'),fresh.pop('composition_proofs');old,new=a.pop('source_proofs'),fresh.pop('source_proofs')
 assert a==fresh and e['verified_counts']==COUNTS and a['independent_totals']==TOTALS and len(old)==len(new)==75
 assert len(composition)==len(new_composition)==4
 for x,y in [*zip(old,new),*zip(composition,new_composition)]:
  x,y=dict(x),dict(y);p,q=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'))
  assert x==y and x['premises_nonvacuous'] and x['result']=='unsat'
  assert len(p)==len(q)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(p,q))
  s=z3.Solver();s.set(timeout=30000);s.add(*p);assert s.check()==z3.unsat
 a['source_proofs']=old;a['composition_proofs']=composition
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 report=read(BASE/'userclient_query_publication_report.md')
 for j in range(1,8):
  assert '| QP'+str(j)+' |' in report and '| QP-A'+str(j)+':' in report and '**QG'+str(j)+'**' in report
 for word in [CHECKS_SHA,AUDIT_SHA,'0xfffffe000a663ffc','0xfffffe000a664018','0x6c','423','6,845','1,024','QP-A7','M=N>=64']:assert word in report
 for p in CHANGED:
  if p.endswith('.md'):assert 'userclient_query_publication_report.md' in read(BASE/p)
 for receipt in [e,a]:
  hygiene(receipt);assert receipt['conditional_query_publication_contract_established'] is True
  for key in R.FALSE:assert receipt[key] is False
 print(json.dumps({'fresh_extraction_audit_match':True,'source_queries_reconstructed_and_resolved':75,
  'composition_queries_reconstructed_and_resolved':4,'prior_source_queries_rechecked':12,'native_target_executed':False}),flush=True)
 return e,a

def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']} for m in [old,new])
 assert len(before)==9300 and len(after)==9306 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED
 assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256'] and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
 for key,x in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),
  ('new_source_queries_unsat',75),('prior_source_queries_rechecked',12),('new_composition_queries_unsat',4),('conditional_query_publication_contract_established',True)]:
  assert new['validation'][R.P+'_'+key]==x
 assert new['validation']['reports']==old['validation']['reports']+1==596
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 assert new['goal_status']=='active'
 for p in ARCHIVES:assert not (BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode();path_hygiene(decoded)
  assert not re.search(rb'/(?:Users/(?!Shared(?:/|\b))|home/|tmp/|private/|Library[/]Developer/|opt[/]homebrew/)',decoded)
 path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
 assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':596,
  'original_inputs_preserved':3,**COUNTS,**TOTALS,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':publication(*receipts())
