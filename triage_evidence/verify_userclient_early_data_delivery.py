#!/usr/bin/env python3
"""Rebuild early data-return receipts and verify exact publication custody.
Linear corpus/journal/owned-byte work; source SMT search cost is separate.
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
import recover_userclient_early_data as R
import audit_userclient_early_data as A
PREVIOUS='baf25b6196056b9bf9f08de75fbe5e82c9d8991e'
BASELINE_SHA='0e7cc34ece5f0d1a85c30baea1e75dafe814f59eb3509752685620cec6abcc88'
CHECKS_SHA='1528647bc86b5a33d1da3bb156346aa0b30b46e5f8cc44437f3b00a61b8bd7bb'
AUDIT_SHA='c2a584dacc8d8d909b28406d10179bb05f649ddf1169264026b9554da299fb3d'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'interface_investigation_status.md','interface_abi_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','userclient_early_node_report.md','userclient_record_nodes_report.md','userclient_record_writer_report.md','userclient_container_staging_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'userclient_early_data_report.md',*[('triage_evidence/'+n+'_userclient_early_data.py')for n in ['recover','probe','replay','audit']],'triage_evidence/verify_userclient_early_data_delivery.py','triage_evidence/userclient_early_data_checks.json','triage_evidence/userclient_early_data_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/userclient_early_data_checks.json','triage_evidence/userclient_early_data_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'cases':60,'matched_parent_cases':60,'nonnull_data_cases':30,'NULL_data_fixture_cases':30,'source_visits':118782,'source_reads':10950,'source_writes':23100,'captured_words':164,'source_spans':9,'bank_input_cases':512,'API_models_per_case':5,'writer_required_cells':12,'writer_required_bytes':64,'call_return_store_sites':5,'syntactic_inventory_sites':69,'initial_input_bytes_declared':936}
TOTALS={'GPR_values_checked':3684102,'NZCV_values_checked':118842,'source_visits_checked':118782,'write_bytes_checked':172452,'source_writes_checked':23100,'read_bytes_checked':56028,'source_reads_checked':10950,'register_only_API_models_checked':300,'D_register_values_checked':1920,'logical_edges_checked':1332,'snapshot_bytes_checked':1488960,'cases_checked':60,'earlier_object_bytes_checked':960,'declared_input_bytes_checked':936,'node_snapshot_bytes_checked':1920,'data_snapshot_bytes_checked':3840,'writer_input_snapshot_bytes_checked':3840}
def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')));assert e==R.build();fresh=A.audit(e);x,y=dict(a),dict(fresh);old,new=x.pop('source_proofs'),y.pop('source_proofs');assert len(old)==len(new)==9
 for p,q in zip(old,new):
  p,q=dict(p),dict(q);left,right=z3.parse_smt2_string(p.pop('query')),z3.parse_smt2_string(q.pop('query'));assert p==q and p['premises_nonvacuous']and len(left)==len(right)>0 and all(canonical_expression(i)==canonical_expression(j)for i,j in zip(left,right))
 assert x==y and e['verified_counts']==a['verified_counts']==COUNTS and a['independent_totals']==TOTALS and a['matched_parent_prefixes']==60
 assert len(a['negative_source_controls'])==2 and all(q['normal_oracle_rejected']and not q['undefined_or_unbacked_load_executed']for q in a['negative_source_controls'])
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 assert e['kernel_collection_sha256']==a['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 assert sum(q['lifted_instruction_instances']for q in old)==104
 assert len(e['source']['bank_rules'])==2 and all(q['inputs_checked']==256 and q['target']==q['original_pointer']['target']for q in e['source']['bank_rules'])
 d=e['source']['descriptors'];assert d[0]['normalized64_hex']==d[1]['normalized64_hex']and d[0]['size_bytes']==d[1]['size_bytes']==32 and d[0]['signature']==d[1]['signature']=='1121'and d[0]['flags32']==d[1]['flags32']==0x64
 assert len(e['source']['writer_requirements'])==12 and sum(q['size_bytes']for q in e['source']['writer_requirements'])==64
 assert {q['offset']for q in e['source']['call_return_store_sites']}=={'0x768','0x458','0x140','0x6b8','0x58'}and not e['source']['inventory_alias_complete']and len(e['source']['syntactic_exact_displacement_inventory'])==69
 assert all(q['writer_required_defined_bytes']==18 and q['writer_required_unknown_bytes']==46 and q['node_defined_bytes']==28 and q['data_defined_bytes']==0 for q in a['cases'])
 parent=json.loads(read(ROOT/'userclient_early_node_checks.json'));captured={int(i['pc'],16)for s in e['source']['spans']for i in s['instructions']};visited={int(v['pc'],16)for r in e['cases']for v in r['source_visits'][len(parent['cases'][r['input']['data_parent_case_index']]['source_visits']):]};assert visited<=captured and len(captured)==164
 assert sum(len(r['source_visits'])-len(parent['cases'][r['input']['data_parent_case_index']]['source_visits'])for r in e['cases'])==3510
 report=read(BASE/'userclient_early_data_report.md')
 for j in range(1,8):assert '**QG'+str(j)+'**'in report and '| ED-A'+str(j)+':'in report
 for j in range(1,9):assert '| ED'+str(j)+' |'in report
 assert CHECKS_SHA in report and AUDIT_SHA in report
 for p in CHANGED:
  if p.endswith('.md'):assert 'userclient_early_data_report.md'in read(BASE/p)
 for obj in [e,a]:
  hygiene(obj);nested_hygiene(obj)
  for key in R.FALSE:assert obj[key]is False
 print(json.dumps({'continuous_cases_rebuilt_and_independently_interpreted':60,'source_visits':118782,'continuation_visits':3510,'source_queries_rebuilt':9,'store_controls_rebuilt':2,'all_receipts_match':True}),flush=True);return e,a
def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']}for m in [old,new]);assert len(before)==9677 and len(after)==9685 and not before.keys()-after.keys()and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED and new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256']and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
 for key,value in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),('new_source_queries_unsat',9),('negative_source_controls',2)]:assert new['validation'][R.P+'_'+key]==value
 assert new['validation']['reports']==old['validation']['reports']+1==646 and new['goal_status']=='active'
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 for p in ARCHIVES:assert not(BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4]if p.endswith('.zst')else p));path_hygiene(decoded.encode())
  if p.endswith('.json.zst'):obj=json.loads(decoded);hygiene(obj);nested_hygiene(obj)
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':646,'original_inputs_preserved':3,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)
if __name__=='__main__':publication(*receipts())
