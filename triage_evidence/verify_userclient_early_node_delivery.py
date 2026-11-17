#!/usr/bin/env python3
"""Rebuild early node receipts and verify the exact publication delta.
Linear corpus/journal/owned-byte work; SMT search cost is separate.
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
import recover_userclient_early_node as R
import audit_userclient_early_node as A
PREVIOUS='c30c2354f329d970fdfa483531aa8f1e95d5f308'
BASELINE_SHA='4eeec7f7532a9ff08610af27a26aa553cbf773b0fcb79dd1d9ae680cd544fe58'
CHECKS_SHA='3376d0d190a8232484d92074e75335086aabaffe545e590388bcc886a83f79bb'
AUDIT_SHA='d6b3b0f4b052311c33d374105c862ac7e21547f524bd327f163186553d292265'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'interface_investigation_status.md','interface_abi_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','userclient_early_header_report.md','userclient_record_nodes_report.md','userclient_container_staging_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'userclient_early_node_report.md',*[('triage_evidence/'+n+'_userclient_early_node.py')for n in ['recover','probe','replay','audit']],'triage_evidence/verify_userclient_early_node_delivery.py','triage_evidence/userclient_early_node_checks.json','triage_evidence/userclient_early_node_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/userclient_early_node_checks.json','triage_evidence/userclient_early_node_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'cases':60,'matched_parent_cases':60,'nonnull_node_cases':30,'NULL_node_fixture_cases':30,'source_visits':113172,'source_reads':10110,'source_writes':22920,'continuation_words':132,'continuation_spans':2,'allocator_function_words':83,'bank_input_cases':256,'API_models_per_case':4,'initial_input_bytes_declared':936}
TOTALS={'GPR_values_checked':3510192,'NZCV_values_checked':113232,'source_visits_checked':113172,'write_bytes_checked':171132,'source_writes_checked':22920,'read_bytes_checked':51168,'source_reads_checked':10110,'register_only_API_models_checked':240,'D_register_values_checked':1920,'logical_edges_checked':1242,'snapshot_bytes_checked':1488960,'cases_checked':60,'earlier_object_bytes_checked':960,'declared_input_bytes_checked':936,'node_snapshot_bytes_checked':1920}
def receipts():
 assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
 e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')));assert e==R.build();fresh=A.audit(e);x,y=dict(a),dict(fresh);old,new=x.pop('source_proofs'),y.pop('source_proofs');assert len(old)==len(new)==10
 for p,q in zip(old,new):
  p,q=dict(p),dict(q);left,right=z3.parse_smt2_string(p.pop('query')),z3.parse_smt2_string(q.pop('query'));assert p==q and p['premises_nonvacuous']and len(left)==len(right)>0 and all(canonical_expression(i)==canonical_expression(j)for i,j in zip(left,right))
 assert x==y and e['verified_counts']==a['verified_counts']==COUNTS and a['independent_totals']==TOTALS and a['matched_parent_prefixes']==60
 assert len(a['negative_source_controls'])==2 and all(q['normal_oracle_rejected']and not q['undefined_or_unbacked_load_executed']for q in a['negative_source_controls'])
 assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
 assert e['kernel_collection_sha256']==a['kernel_collection_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'
 assert sum(q['lifted_instruction_instances']for q in old)==97
 assert e['public_source_context']==R.PUBLIC_CONTEXT and not R.PUBLIC_CONTEXT['matches_target_version']and len(R.PUBLIC_CONTEXT['sources'])==3
 rule=e['source']['data_allocation_bank'];assert rule['inputs_checked']==256 and rule['target']==rule['original_pointer']['target']=='0xfffffe000c4ba60c'and rule['index']=='0xf10'
 assert e['source']['node_descriptor']['size_bytes']==32 and e['source']['node_descriptor']['flags32']==0x64
 assert [f['sha256']for f in e['source']['allocator_functions']]==['2be5777872d60de5b0513968f8aaaaa1b3947085f183f933b4ba7b7607290029','c2741f4a72af1e2a358007be4a36398fdc0aab0a092cd4ba85afafb495330892','0bc800f390215db6847c0e74814ad727ac2d56d59c4b8c04eed740b600efd0dd']
 parent=json.loads(read(ROOT/'userclient_early_header_checks.json'));visited={int(v['pc'],16)for r in e['cases']for v in r['source_visits'][len(parent['cases'][r['input']['node_parent_case_index']]['source_visits']):]};captured={int(i['pc'],16)for s in e['source']['spans'][:2]for i in s['instructions']};assert visited<=captured and len(captured)==132
 assert sum(len(r['source_visits'])-len(parent['cases'][r['input']['node_parent_case_index']]['source_visits'])for r in e['cases'])==4320
 report=read(BASE/'userclient_early_node_report.md')
 for j in range(1,8):assert '**QG'+str(j)+'**'in report and '| EN-A'+str(j)+':'in report
 for j in range(1,9):assert '| EN'+str(j)+' |'in report
 assert CHECKS_SHA in report and AUDIT_SHA in report
 for p in CHANGED:
  if p.endswith('.md'):assert 'userclient_early_node_report.md'in read(BASE/p)
 for obj in [e,a]:
  hygiene(obj);nested_hygiene(obj)
  for key in R.FALSE:assert obj[key]is False
 print(json.dumps({'continuous_cases_rebuilt_and_independently_interpreted':60,'source_visits':113172,'continuation_visits':4320,'source_queries_rebuilt':10,'store_controls_rebuilt':2,'all_receipts_match':True}),flush=True);return e,a
def publication(e,a):
 raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
 old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before,after=({r['path']:r for r in m['files']}for m in [old,new]);assert len(before)==9669 and len(after)==9677 and not before.keys()-after.keys()and after.keys()-before.keys()==ADDED
 assert {p for p in before if before[p]!=after[p]}==CHANGED and new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
 for row in new['inputs_preserved']:
  p=row['path'];assert sha(BASE/p)==row['sha256']and size(BASE/p)==row['size_bytes']
  if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==row['sha256']
 for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
 for key,value in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',TOTALS),('new_source_queries_unsat',10),('negative_source_controls',2)]:assert new['validation'][R.P+'_'+key]==value
 assert new['validation']['reports']==old['validation']['reports']+1==645 and new['goal_status']=='active'
 assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
 for p in ARCHIVES:assert not(BASE/p).exists()
 for p in OWNED:
  path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4]if p.endswith('.zst')else p));path_hygiene(decoded.encode())
  if p.endswith('.json.zst'):obj=json.loads(decoded);hygiene(obj);nested_hygiene(obj)
 delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,delta^OWNED
 print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':645,'original_inputs_preserved':3,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)
if __name__=='__main__':publication(*receipts())
