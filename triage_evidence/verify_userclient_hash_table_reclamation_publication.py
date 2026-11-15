#!/usr/bin/env python3
"""Reconstruct reclamation proofs/replays and verify publication custody.
O(owned bytes+receipts+proof DAG) wrapper time/space plus documented
solver/replay costs. No target call, IDB mutation or history rewrite.
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
import recover_userclient_hash_table_reclamation as R
import audit_userclient_hash_table_reclamation as A

PREVIOUS='44b8686a40f77437a862ad0e560f0e38240ec920'
BASELINE_SHA='5cf9651e2616be6df78b03a1d1416546024912f8459be36bbd5e9b2a48949af1'
CHECKS_SHA='831f3e6b1a7283f2b1b6a87df5a99a1bb627f3552e0c72da0c65d7e88b6757c0'
AUDIT_SHA='c3bea10d4cdbc608f9f03d208249ea2cb94e30f91a16c2b146f40d59e968aab4'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'foundational_triage_report.md','interface_investigation_status.md','mach_ports_report.md',
 'obfuscated_routines_report.md','interface_abi_report.md','userclient_context_lifecycle_report.md',
 'context_descriptor_task_flow_report.md','iokit_connection_lifecycle_report.md',
 'triage_evidence/validate_rpc502_sidecar_delivery.py','userclient_hash_table_bootstrap_report.md',
 'userclient_hash_table_initializer_report.md','userclient_hash_table_lookup_report.md'}
ADDED={'userclient_hash_table_reclamation_report.md','triage_evidence/recover_userclient_hash_table_reclamation.py',
 'triage_evidence/audit_userclient_hash_table_reclamation.py','triage_evidence/verify_userclient_hash_table_reclamation_publication.py',
 'triage_evidence/userclient_hash_table_reclamation_checks.json','triage_evidence/userclient_hash_table_reclamation_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/userclient_hash_table_reclamation_checks.json','triage_evidence/userclient_hash_table_reclamation_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'writer_captured_instructions':124,'reclaimer_captured_instructions':318,'caller_region_instructions':201,
 'source_spans':31,'selected_instructions':603,'terminal_transfers':25,'literal_bank_arrays':6,'bank_rules':9,
 'bank_input_cases':2304,'branch_pointers':18,'pool_pointers':6,'writer_record_bytes':48,'reclaimer_record_bytes':40,
 'entry_stride_bytes':24,'typed_free_bytes':120}
TOTALS={'new_source_queries_unsat':36,'prior_source_queries_unsat':4,'bank_input_cases_checked':2304,
 'distinct_source_instructions':603,'source_instruction_instances':3149,'writer_replay_cases':49,
 'writer_replay_instruction_instances':5104,'reclamation_replay_cases':15,'reclamation_replay_instruction_instances':29763,
 'replay_distinct_instructions':412,'reclamation_nested_writer_calls':140,'altered_evidence_rejections':4}

def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 evidence=json.loads(read(ROOT/(R.P+'_checks.json')));audit=json.loads(read(ROOT/(R.P+'_audit.json')))
 assert evidence==R.build();fresh=A.audit()
 old,new=audit.pop('source_proofs'),fresh.pop('source_proofs')
 assert audit==fresh and evidence['verified_counts']==COUNTS and audit['independent_totals']==TOTALS
 assert evidence['source_sha256']==audit['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 assert len(old)==len(new)==36
 for a,b in zip(old,new):
  x,y=dict(a),dict(b);p,q=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'))
  assert x==y and x['premises_nonvacuous'] and x['result']=='unsat'
  assert len(p)==len(q)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(p,q))
  s=z3.Solver();s.set(timeout=30000);s.add(*p);assert s.check()==z3.unsat
 audit['source_proofs']=old
 report=read(BASE/'userclient_hash_table_reclamation_report.md')
 assert all('| HR'+str(j)+' |' in report for j in range(1,9))
 assert all('| HR-A'+str(j)+':' in report for j in range(1,9))
 assert all('**QG'+str(j)+'**' in report for j in range(1,8)) and CHECKS_SHA in report and AUDIT_SHA in report
 for word in ['0xfffffe000a5aec24','0xfffffe000a616860','0xfffffe000a6273e8','site.FPSecureTunnel','120 B','0xc28','0x559']:
  assert word in report
 for r in evidence['bank_rules']:assert r['slot'] in report and r['target'] in report and r['index'] in report
 for ix in [0x4fa,0x518,0x39b]:
  p=next(p for p in evidence['branch_pointers'] if p['index']==ix);assert hex(ix) in report and p['target'] in report
 selected={int(i['ea'],16) for s in evidence['spans'] for i in s['instructions']}
 for f in [*evidence['functions'].values(),evidence['caller_region']]:
  ii=list(A.DEC.disasm(bytes.fromhex(f['bytes_hex']),int(f['start'],16)));pcs={i.address for i in ii}
  transfers={int(i['ea'],16) for i in evidence['transfers']}&pcs
  remaining=[i for i in ii if i.address not in selected|transfers]
  assert all(i.mnemonic in ['pacibsp','bti'] for i in remaining)
  assert len(ii)==len(pcs&selected)+len(transfers)+len(remaining)
 assert len(selected)==603 and sum(len(f['instructions']) for f in evidence['functions'].values())==442
 assert any(s['name']=='_IOFreeTypeImpl' for s in evidence['exact_symbols']['0xfffffe000c4ba368'])
 for p in CHANGED:
  if p.endswith('.md'):assert 'userclient_hash_table_reclamation_report.md' in read(BASE/p)
 for receipt in [evidence,audit]:
  hygiene(receipt);assert receipt['conditional_hash_table_reclamation_contract_established'] is True
  for key in R.FALSE:assert receipt[key] is False
 print(json.dumps({'fresh_extraction_audit_match':True,'source_queries_reconstructed_and_resolved':36,
  'predecessor_queries_resolved':4,'writer_cases_reconstructed':49,'reclamation_cases_reconstructed':15,
  'native_target_executed':False}),flush=True)
 return evidence,audit

def publication(evidence,audit):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST))
 before,after=({r['path']:r for r in m['files']} for m in [old,new])
 assert len(before)==9168 and len(after)==9174
 assert not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED
 assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
 for r in new['inputs_preserved']:
  p=r['path'];assert sha(BASE/p)==r['sha256'] and size(BASE/p)==r['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==r['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
 for key,value in [('increment_checks',COUNTS),('static_scope',evidence['scope']),('independent_checks',TOTALS),
  ('new_source_queries_unsat',36),('prior_source_queries_rechecked',4),('conditional_hash_table_reclamation_contract_established',True)]:
  assert new['validation'][R.P+'_'+key]==value
 assert new['validation']['reports']==old['validation']['reports']+1==574
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 assert new['goal_status']=='active'
 for p in ARCHIVES:assert not (BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode();path_hygiene(decoded)
  assert not re.search(rb'/(?:Users/(?!Shared(?:/|\b))|home/|tmp/|private/|Library[/]Developer/|opt[/]homebrew/)',decoded)
 path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
 assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':574,
  'original_inputs_preserved':3,**COUNTS,**TOTALS,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':publication(*receipts())
