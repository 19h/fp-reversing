#!/usr/bin/env python3
"""Reconstruct the local tunnel-allocation receipt and verify publication custody.
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
import recover_secure_tunnel_allocation as R
import audit_secure_tunnel_allocation as A

PREVIOUS='feb0bb521e3419bdaa755c253b7f01405a0f074a'
BASELINE_SHA='e5d578e28e5e23c867edddba4689d135d5f37b4d568a4a35802ad253fbac2f49'
CHECKS_SHA='447c0147f900d5da40c67b314f3e41c82a34ded9045699e4e7b761b96e0e81fe'
AUDIT_SHA='58bbb935c0cbb2fb4121f69a43b3887ac5a3d04982922874dcf5728da1111d8c'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'foundational_triage_report.md','interface_investigation_status.md','mach_ports_report.md',
 'obfuscated_routines_report.md','interface_abi_report.md','userclient_context_lifecycle_report.md',
 'userclient_hash_table_reclamation_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'secure_tunnel_allocation_report.md','triage_evidence/recover_secure_tunnel_allocation.py',
 'triage_evidence/audit_secure_tunnel_allocation.py','triage_evidence/verify_secure_tunnel_allocation_publication.py',
 'triage_evidence/secure_tunnel_allocation_checks.json','triage_evidence/secure_tunnel_allocation_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/secure_tunnel_allocation_checks.json','triage_evidence/secure_tunnel_allocation_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'source_spans':17,'selected_instructions':434,'terminal_transfers':9,'bank_rules':2,'bank_input_cases':512,
 'typed_descriptors':2,'object_extent_bytes':120,'copied_field16_bytes':16,'copied_field32_bytes':32,'retained_fill_bytes':48}
TOTALS={'new_source_queries_unsat':10,'distinct_proved_instructions':349,'proof_instruction_instances':456,
 'allocation_select_cases':256,'bank_input_cases_checked':512,'final_object_extent_bytes':120,'altered_evidence_rejections':3}

def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
 assert e==R.build();fresh=A.audit();old,new=a.pop('source_proofs'),fresh.pop('source_proofs')
 assert a==fresh and e['verified_counts']==COUNTS and a['independent_totals']==TOTALS and len(old)==len(new)==10
 for x,y in zip(old,new):
  x,y=dict(x),dict(y);p,q=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'))
  assert x==y and x['premises_nonvacuous'] and x['result']=='unsat'
  assert len(p)==len(q)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(p,q))
  s=z3.Solver();s.set(timeout=30000);s.add(*p);assert s.check()==z3.unsat
 a['source_proofs']=old
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 report=read(BASE/'secure_tunnel_allocation_report.md')
 for j in range(1,9):assert '| ST'+str(j)+' |' in report and '| ST-A'+str(j)+':' in report
 for j in range(1,8):assert '**QG'+str(j)+'**' in report
 for word in [CHECKS_SHA,AUDIT_SHA,'0xfffffe000a65a55c','0xfffffe000847c120','0xfffffe000847bf60',
  'site.FPSecureTunnel','120 B','0x06..+0x07','0x69..+0x6b','0xfffffe000a65ef50']:assert word in report
 for r in e['bank_rules']:assert r['slot'] in report and r['target'] in report and r['index'] in report
 for p in CHANGED:
  if p.endswith('.md'):assert 'secure_tunnel_allocation_report.md' in read(BASE/p)
 for receipt in [e,a]:
  hygiene(receipt);assert receipt['conditional_secure_tunnel_allocation_contract_established'] is True
  for key in R.FALSE:assert receipt[key] is False
 assert any(x['name']=='_IOMallocTypeImpl' for x in e['allocation_adapter_symbols']['0xfffffe000c4ba154'])
 print(json.dumps({'fresh_extraction_audit_match':True,'source_queries_reconstructed_and_resolved':10,
  'allocation_select_cases_reconstructed':256,'native_target_executed':False}),flush=True)
 return e,a

def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']} for m in [old,new])
 assert len(before)==9174 and len(after)==9180 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED
 assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256'] and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
 for key,x in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),
  ('new_source_queries_unsat',10),('conditional_secure_tunnel_allocation_contract_established',True)]:
  assert new['validation'][R.P+'_'+key]==x
 assert new['validation']['reports']==old['validation']['reports']+1==575
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 assert new['goal_status']=='active'
 for p in ARCHIVES:assert not (BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode();path_hygiene(decoded)
  assert not re.search(rb'/(?:Users/(?!Shared(?:/|\b))|home/|tmp/|private/|Library[/]Developer/|opt[/]homebrew/)',decoded)
 path_hygiene(git('show','-s','--format=fuller','HEAD'))
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
 assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':575,
  'original_inputs_preserved':3,**COUNTS,**TOTALS,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':publication(*receipts())
