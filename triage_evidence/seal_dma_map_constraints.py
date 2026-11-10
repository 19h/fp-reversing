#!/usr/bin/env python3
"""Replay source/role proofs and seal the narrowly owned publication increment."""
import ast,json,re
from pathlib import Path
from recover_dma_map_constraints import ROOT,P,FLAGS
from validate_dma_map_constraints import verify,certificates,alterations,SOLVER
from verify_daemon_reader_record_payloads_publication import read,sha,size,exists
BASE=ROOT.parent
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','buffer_construction_flow_report.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
SCRIPTS=['recover_'+P+'.py','validate_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
REQUIRED_COUNTS = {'captured_functions': 4, 'captured_instructions': 1221, 'captured_code_bytes': 4884, 'source_fragments': 33, 'selected_graph_instruction_sites': 61, 'selected_graph_edges': 65, 'selected_graph_call_frontiers': 1, 'selected_graph_store_instructions': 8, 'selected_graph_returns': 1, 'fresh_branch_overrides': 3, 'helper_instructions': 117, 'creator_instructions': 58, 'SDK_syntax_only_exit': 0, 'queries_unsat': 44, 'queries_sat': 0, 'source_instruction_instances_translated': 127, 'distinct_source_instruction_sites_translated': 127, 'metadata_bytes_touched': 38, 'metadata_bytes_fully_defined_without_old_contents': 37, 'metadata_unwritten_bytes': 10, 'predecessor_queries_replayed': 1, 'rejected_alterations': 6}
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='8411819ba5f7fe9ef95f410080f1e773a2fd5e561456c736da444b57e76f8980';m=json.loads(read(prior));assert len(m['files'])==7934
 unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert exists(q);digest=sha(q)
  if row['path']in CHANGED:assert digest!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':digest})
  else:assert digest==row['sha256']and size(q)==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==7927 and {r['path']for r in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
 s=json.loads(read(ROOT/(P+'_source.json')));c=json.loads(read(ROOT/(P+'_checks.json')));assert verify(s)and c['all_checks_pass']and c['DMA_mapping_constraints_proved']and not c['complete_operation_proved']
 pp,sem=certificates(s);assert c['proofs']==pp and c['semantics']==json.loads(json.dumps(sem))and c['alterations']==alterations(s)
 counts=c['verified_counts'];required=REQUIRED_COUNTS;assert counts==required
 assert c['semantics']['operation_u32']==0x4000000 and c['semantics']['specification_bytes']==40 and c['semantics']['metadata_record_bytes']==48 and c['semantics']['metadata_initialization_written_bytes']==38 and c['semantics']['local_method_graph_closed_for_selected_operation_and_size'] and c['semantics']['fast_path_explicit_field_noninterference_under_disjointness_proved'] and not c['semantics']['helper_and_lower_call_effects_fully_proved'] and not c['semantics']['actual_allocation_capacity_proved'] and not c['semantics']['allocation_zeroing_proved'] and not c['semantics']['complete_constructor_path_proved'] and not c['semantics']['native_mapping_transfer_or_transaction_proved'] and c['semantics']['Mach_port_emissions']==0


 for obj,script in[(s,SCRIPTS[0]),(c,SCRIPTS[1])]:
  assert obj['generator_sha256']==sha(ROOT/script)and all(obj[k]is False for k in FLAGS)
  for n,digest in obj.get('dependencies',{}).items():assert sha(ROOT/n)==digest
 assert sha(SOLVER)==c['solver']['sha256']
 for n in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse(read(ROOT/n),filename=n)
 report=read(BASE/REPORTS[0]);assert report.isascii()and all('| DM'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8))
 links=0
 for name in REPORTS:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',read(BASE/name)):
   target=target.strip('<>')
   if target.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',target):continue
   q=Path(target.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:
    alias=re.sub(r'^/(?:Users|home)/_+(?=/|$)',lambda _:str(Path.home()),str(q));assert exists(q)or exists(Path(alias)),(name,target)
   links+=1
 delivery={'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':7934,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':5,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False}
 (ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 g={'generator_sha256':sha(__file__),'static_scope':c['static_scope'],'verified_counts':counts,'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in[P+'_source.json',P+'_checks.json']+SCRIPTS},'goal_status':'active',**{k:False for k in FLAGS}}
 for j in range(1,8):g['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+' and DM1-DM8;source specification packing,selected61-node/65-edge graph,min/max merge,metadata helper/creator interfaces and partial48-byte initialization. Forty-four UNSAT,127 translated source sites,syntax-only SDK corroboration and six freshness alterations pass. Full lower call effects,zeroing,actual backing,complete constructor and native mappings/transfers remain unproved.'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(g,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
