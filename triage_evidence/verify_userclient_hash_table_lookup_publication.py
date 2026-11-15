#!/usr/bin/env python3
"""Fresh lookup receipts, proof reconstruction and exact publication custody.
O(owned bytes+receipts+proof DAG) wrapper time/space plus documented solver
and replay costs. No native target operation or database mutation.
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
import recover_userclient_hash_table_lookup as R
import audit_userclient_hash_table_lookup as A

PREVIOUS='c88272483f07acbdc58b253936834cb9d28f5c69'
BASELINE_SHA='5cad58294d8b11bf25a68d4c56430bf317c0ec7bdcb703a5a2ad42e8fc61fd0e'
CHECKS_SHA='16fba57feb5ae001eb4309a331352acc8ec6a512045171d45d878e5a3b970f22'
AUDIT_SHA='7f9b62cf8034038c7443678fd0f13e8eb257ec7c453e8f6d0596be3a6fe46e68'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'foundational_triage_report.md','interface_investigation_status.md','mach_ports_report.md',
 'obfuscated_routines_report.md','interface_abi_report.md','userclient_context_lifecycle_report.md',
 'context_descriptor_task_flow_report.md','iokit_connection_lifecycle_report.md',
 'triage_evidence/validate_rpc502_sidecar_delivery.py','userclient_hash_table_bootstrap_report.md',
 'userclient_hash_table_initializer_report.md'}
ADDED={'userclient_hash_table_lookup_report.md','triage_evidence/recover_userclient_hash_table_lookup.py',
 'triage_evidence/audit_userclient_hash_table_lookup.py','triage_evidence/verify_userclient_hash_table_lookup_publication.py',
 'triage_evidence/userclient_hash_table_lookup_checks.json','triage_evidence/userclient_hash_table_lookup_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/userclient_hash_table_lookup_checks.json','triage_evidence/userclient_hash_table_lookup_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'lookup_captured_instructions':334,'caller_region_instructions':197,'lookup_selected_instructions':303,
 'caller_selected_instructions':188,'source_spans':29,'selected_instructions':491,'terminal_transfers':24,
 'literal_bank_arrays':6,'bank_rules':3,'bank_input_cases':768,'pool_pointers':4,'branch_pointers':21,
 'lookup_record_bytes':48,'entry_stride_bytes':24,'cleanup_lookup_calls':2}
TOTALS={'new_source_queries_unsat':37,'prior_source_queries_unsat':4,'bank_input_cases_checked':768,
 'distinct_source_instructions':491,'source_instruction_instances':2142,'source_replay_cases':18,
 'source_replay_instruction_instances':29134,'source_replay_distinct_instructions':302,
 'source_replay_entry_visits':407,'altered_evidence_rejections':4}

def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 evidence=json.loads(read(ROOT/(R.P+'_checks.json')));audit=json.loads(read(ROOT/(R.P+'_audit.json')))
 assert evidence==R.build();fresh=A.audit()
 old,new=audit.pop('source_proofs'),fresh.pop('source_proofs')
 assert audit==fresh and evidence['verified_counts']==COUNTS and audit['independent_totals']==TOTALS
 assert evidence['source_sha256']==audit['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 assert len(old)==len(new)==37
 for a,b in zip(old,new):
  x,y=dict(a),dict(b);p,q=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'))
  assert x==y and x['premises_nonvacuous'] and x['result']=='unsat'
  assert len(p)==len(q)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(p,q))
  s=z3.Solver();s.set(timeout=30000);s.add(*p);assert s.check()==z3.unsat
 audit['source_proofs']=old
 report=read(BASE/'userclient_hash_table_lookup_report.md')
 assert all('| HL'+str(j)+' |' in report for j in range(1,9))
 assert all('| HL-A'+str(j)+':' in report for j in range(1,9))
 assert all('**QG'+str(j)+'**' in report for j in range(1,8)) and CHECKS_SHA in report and AUDIT_SHA in report
 for word in ['0xfffffe000a626f10','0xfffffe000a6270a0','0xfffffe000a5ae354','0xce515bd9','0x629f8776','0x1ee45f68039f9913']:
  assert word in report
 # All displayed branch/call bindings come from original chained pointers.
 for r in evidence['bank_rules']:assert r['slot'] in report and r['target'] in report and r['index'] in report
 for ix in [0x4ff,0x2d4,0x2fc,0xaf7,0xa8f]:
  p=next(p for p in evidence['branch_pointers'] if p['index']==ix)
  assert hex(ix) in report and p['target'] in report
 selected={int(i['ea'],16) for s in evidence['spans'] for i in s['instructions']}
 for f in [evidence['lookup_function'],evidence['caller_region']]:
  raw=bytes.fromhex(f['bytes_hex']);ii=list(A.DEC.disasm(raw,int(f['start'],16)));pcs={i.address for i in ii}
  transfers={int(i['ea'],16) for i in evidence['transfers']}&pcs
  remaining=[i for i in ii if i.address not in selected|transfers]
  assert all(i.mnemonic in ['pacibsp','bti'] for i in remaining)
  assert len(ii)==len(pcs&selected)+len(transfers)+len(remaining)
 for p in CHANGED:
  if p.endswith('.md'):assert 'userclient_hash_table_lookup_report.md' in read(BASE/p)
 for receipt in [evidence,audit]:
  hygiene(receipt);assert receipt['conditional_hash_table_lookup_contract_established'] is True
  for key in R.FALSE:assert receipt[key] is False
 print(json.dumps({'fresh_extraction_audit_match':True,'source_queries_reconstructed_and_resolved':37,
  'predecessor_queries_resolved':4,'synthetic_cases_reconstructed':18,'native_target_executed':False}),flush=True)
 return evidence,audit

def publication(evidence,audit):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST))
 before,after=({r['path']:r for r in m['files']} for m in [old,new])
 assert len(before)==9162 and len(after)==9168
 assert not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED
 assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
 for r in new['inputs_preserved']:
  p=r['path'];assert sha(BASE/p)==r['sha256'] and size(BASE/p)==r['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==r['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
 for key,value in [('increment_checks',COUNTS),('static_scope',evidence['scope']),('independent_checks',TOTALS),
  ('new_source_queries_unsat',37),('prior_source_queries_rechecked',4),('conditional_hash_table_lookup_contract_established',True)]:
  assert new['validation'][R.P+'_'+key]==value
 assert new['validation']['reports']==old['validation']['reports']+1==573
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 assert new['goal_status']=='active'
 for p in ARCHIVES:assert not (BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode();path_hygiene(decoded)
  assert not re.search(rb'/(?:Users/(?!Shared(?:/|\b))|home/|tmp/|private/|Library[/]Developer/|opt[/]homebrew/)',decoded)
 path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
 assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':573,
  'original_inputs_preserved':3,**COUNTS,**TOTALS,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':publication(*receipts())
