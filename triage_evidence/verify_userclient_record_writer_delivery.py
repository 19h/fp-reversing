#!/usr/bin/env python3
"""Reconstruct the record writer receipt and verify publication custody.
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
import recover_userclient_record_writer as R
import audit_userclient_record_writer as A

PREVIOUS='9a75633e94812a0e96eb80c23ae21708919fd98e'
BASELINE_SHA='a7da7d30cfa625f55fd2864b1995f5546eba80a3d1b59d436252e2dabaef9e28'
CHECKS_SHA='7aafa0ddba91a2f8f2a4894e72da60756202f97f153247eba88d3f07c1c1a344'
AUDIT_SHA='0f55c6456491252ba0ed20cc8a4b4d687c5261645a60180a9967b4e6a1385df3'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'foundational_triage_report.md','interface_investigation_status.md','mach_ports_report.md',
 'obfuscated_routines_report.md','interface_abi_report.md','userclient_context_lifecycle_report.md',
 'userclient_record_nodes_report.md','userclient_input_reader_report.md',
 'userclient_replacement_bootstrap_report.md','userclient_container_staging_report.md',
 'context_descriptor_task_flow_report.md','userclient_discriminator_origin_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'userclient_record_writer_report.md','triage_evidence/recover_userclient_record_writer.py',
 'triage_evidence/audit_userclient_record_writer.py','triage_evidence/verify_userclient_record_writer_delivery.py',
 'triage_evidence/userclient_record_writer_checks.json','triage_evidence/userclient_record_writer_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/userclient_record_writer_checks.json','triage_evidence/userclient_record_writer_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'source_spans': 10, 'selected_instructions': 260, 'terminal_transfers': 6, 'header_bytes': 10, 'retag_sites': 6, 'token_retention_instructions': 319, 'inventoried_stack_cells': 2}
TOTALS={'new_source_queries_unsat': 16, 'prior_source_queries_unsat': 5, 'distinct_new_proved_instructions': 260, 'distinct_predecessor_proved_instructions': 331, 'proof_instruction_instances': 4408, 'altered_evidence_rejections': 4}

def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
 assert e==R.build();fresh=A.audit();old,new=a.pop('source_proofs'),fresh.pop('source_proofs')
 assert a==fresh and e['verified_counts']==COUNTS and a['independent_totals']==TOTALS and len(old)==len(new)==16
 for x,y in zip(old,new):
  x,y=dict(x),dict(y);p,q=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'))
  assert x==y and x['premises_nonvacuous'] and x['result']=='unsat'
  assert len(p)==len(q)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(p,q))
  s=z3.Solver();s.set(timeout=30000);s.add(*p);assert s.check()==z3.unsat
 a['source_proofs']=old
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 report=read(BASE/'userclient_record_writer_report.md')
 for j in range(1,10):assert '| RW'+str(j)+' |' in report
 for j in range(1,9):assert '| RW-A'+str(j)+':' in report
 for j in range(1,8):assert '**QG'+str(j)+'**' in report
 for word in [CHECKS_SHA,AUDIT_SHA,'0xfffffe000a654ccc','0xfffffe000a655ecc',
  '0xfffffe000a655ef0','0x02e859d27e491464','0x4dae26df20976138','0x365e',
  '260','331','4,408','16','RW-A7']:assert word in report
 for r in e['branch_pointers']:assert r['slot'] in report and r['target'] in report and hex(r['index']) in report
 for p in CHANGED:
  if p.endswith('.md'):assert 'userclient_record_writer_report.md' in read(BASE/p)
 for receipt in [e,a]:
  hygiene(receipt);assert receipt['conditional_record_writer_contract_established'] is True
  for key in R.FALSE:assert receipt[key] is False
 print(json.dumps({'fresh_extraction_audit_match':True,'source_queries_reconstructed_and_resolved':16,
  'prior_source_queries_rechecked':5,'native_target_executed':False}),flush=True)
 return e,a

def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']} for m in [old,new])
 assert len(before)==9228 and len(after)==9234 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED
 assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256'] and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
 for key,x in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),
  ('new_source_queries_unsat',16),('prior_source_queries_rechecked',5),('conditional_record_writer_contract_established',True)]:
  assert new['validation'][R.P+'_'+key]==x
 assert new['validation']['reports']==old['validation']['reports']+1==584
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 assert new['goal_status']=='active'
 for p in ARCHIVES:assert not (BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode();path_hygiene(decoded)
  assert not re.search(rb'/(?:Users/(?!Shared(?:/|\b))|home/|tmp/|private/|Library[/]Developer/|opt[/]homebrew/)',decoded)
 path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
 assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':584,
  'original_inputs_preserved':3,**COUNTS,**TOTALS,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':publication(*receipts())
