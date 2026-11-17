#!/usr/bin/env python3
"""Rebuild early wire-header receipts and verify exact publication custody.
Linear corpus/journal/owned-byte work; source SMT search cost separate.
"""
import json
from hashlib import sha256
from compression import zstd
import z3
from kext_port_tools import ROOT,SOURCE
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_daemon_payload_mix_publication import BASE,git,hygiene,path_hygiene
from verify_daemon_second_mix_publication import canonical_expression
from verify_kernel_magazine_bootstrap_delivery import nested_hygiene
import recover_userclient_early_header as R
import audit_userclient_early_header as A
PREVIOUS='5dc8d4e6cd45a696dad21ef86f9acefb413a30f9'
BASELINE_SHA='65c70addfe934c2592fa1f6794b2daac5f7735aa099f5bf0313b31811ed16eea'
CHECKS_SHA='7ee41a58e79feb63c87fb5642245eb2328afb6f7acb355271553884d4547fdf1'
AUDIT_SHA='b8834843c39433e4e3fa6b1bbed8c275e7c5d0d51f09260a651a975ca6a8b2ef'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'userclient_fpttlv_entry_report.md', 'userclient_parser_cleanup_report.md', 'obfuscated_routines_report.md', 'mach_ports_report.md', 'userclient_record_writer_report.md', 'userclient_record_metadata_report.md', 'foundational_triage_report.md', 'triage_evidence/validate_rpc502_sidecar_delivery.py', 'interface_investigation_status.md', 'userclient_record_nodes_report.md', 'interface_abi_report.md', 'userclient_container_staging_report.md'}
ADDED={'userclient_early_header_report.md',*[('triage_evidence/'+name+'_userclient_early_header.py')for name in ['recover','probe','replay','audit']],
 'triage_evidence/verify_userclient_early_header_delivery.py','triage_evidence/userclient_early_header_checks.json','triage_evidence/userclient_early_header_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/userclient_early_header_checks.json','triage_evidence/userclient_early_header_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'cases': 72, 'matched_parent_cases': 48, 'new_size_cases': 24, 'source_visits': 128538, 'source_reads': 11520, 'source_writes': 27150, 'new_source_spans': 13, 'new_source_words': 873, 'bank_rules': 2, 'bank_input_cases': 512, 'API_models_per_case': 3, 'initial_input_bytes_declared': 924}
TOTALS={'GPR_values_checked': 3986910, 'NZCV_values_checked': 128610, 'source_visits_checked': 128538, 'write_bytes_checked': 203148, 'source_writes_checked': 27150, 'read_bytes_checked': 59256, 'source_reads_checked': 11520, 'register_only_API_models_checked': 216, 'D_register_values_checked': 2304, 'logical_edges_checked': 1560, 'snapshot_bytes_checked': 1786752, 'cases_checked': 72, 'earlier_object_bytes_checked': 1152, 'declared_input_bytes_checked': 924}
def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
 assert e==R.build();fresh=A.audit(e);x,y=dict(a),dict(fresh);old,new=x.pop('source_proofs'),y.pop('source_proofs');assert len(old)==len(new)==10
 for p,q in zip(old,new):
  p,q=dict(p),dict(q);left,right=z3.parse_smt2_string(p.pop('query')),z3.parse_smt2_string(q.pop('query'));assert p==q and p['premises_nonvacuous']and len(left)==len(right)>0 and all(canonical_expression(i)==canonical_expression(j)for i,j in zip(left,right))
 assert x==y and e['verified_counts']==a['verified_counts']==COUNTS and a['independent_totals']==TOTALS and a['matched_parent_prefixes']==48
 assert len(a['negative_source_controls'])==2 and all(q['normal_oracle_rejected']for q in a['negative_source_controls'])
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 assert e['kernel_collection_sha256']==a['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 k=A.Kernel()
 for row in e['source']['bank_rules']:
  for address,payload in [('left','left256_hex'),('right','right256_hex')]:assert k.read(int(row[address],16),256).hex()==row[payload]
 d=e['source']['descriptors'];assert d[0]['normalized64_hex']==d[1]['normalized64_hex']and d[0]['signature']==d[1]['signature']=='1121'and d[0]['size_bytes']==d[1]['size_bytes']==32
 assert sum(q['lifted_instruction_instances']for q in old)==333
 visited={v['pc']for r in e['cases']for v in r['source_visits']};newvisited={v['pc']for r in e['cases']for v in r['source_visits'][1464:]};captured={i['pc']for s in e['source']['spans']for i in s['instructions']};assert len(visited)==2330 and len(newvisited)==870 and len(captured)==873 and newvisited<=captured
 report=read(BASE/'userclient_early_header_report.md')
 for j in range(1,8):assert '**QG'+str(j)+'**'in report and '| EH-A'+str(j)+':'in report
 for j in range(1,10):assert '| EH'+str(j)+' |'in report
 assert CHECKS_SHA in report and AUDIT_SHA in report
 for p in CHANGED:
  if p.endswith('.md'):assert 'userclient_early_header_report.md'in read(BASE/p)
 for obj in [e,a]:
  hygiene(obj);nested_hygiene(obj)
  for key in R.FALSE:assert obj[key]is False
 print(json.dumps({'continuous_cases_rebuilt_and_independently_interpreted':72,'source_visits':128538,'source_queries_rebuilt':10,'store_controls_rebuilt':2,'all_receipts_match':True}),flush=True);return e,a
def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']}for m in [old,new]);assert len(before)==9661 and len(after)==9669 and not before.keys()-after.keys()and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED and new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256']and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
 for key,value in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),('new_source_queries_unsat',10),('negative_source_controls',2)]:assert new['validation'][R.P+'_'+key]==value
 assert new['validation']['reports']==old['validation']['reports']+1==644 and new['goal_status']=='active'
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 for p in ARCHIVES:assert not(BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4]if p.endswith('.zst')else p));path_hygiene(decoded.encode())
  if p.endswith('.json.zst'):obj=json.loads(decoded);hygiene(obj);nested_hygiene(obj)
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':644,'original_inputs_preserved':3,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)
if __name__=='__main__':publication(*receipts())
