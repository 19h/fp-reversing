#!/usr/bin/env python3
"""Replay source/role proofs and seal the narrowly owned publication increment."""
import ast,json,re
from pathlib import Path
from recover_context_descriptor_task_flow import ROOT,P,FLAGS
from validate_context_descriptor_task_flow import verify,certificates,alterations,SOLVER
from verify_daemon_reader_record_payloads_publication import read,sha,size,exists
BASE=ROOT.parent
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','userclient_context_lifecycle_report.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
SCRIPTS=['recover_'+P+'.py','validate_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
REQUIRED_COUNTS = {'captured_kext_functions': 7, 'captured_instructions': 53728, 'captured_code_bytes': 214912, 'core_aligned_words': 50634, 'source_fragments': 30, 'literal_context_reloads': 11, 'literal_context_stores': 1, 'literal_scratch_overlaps': 23, 'SP_mutation_sites': 9, 'private_SP_delta_sites': 3, 'literal_bank_arrays': 6, 'bank_rules': 3, 'bank_input_cases': 768, 'original_pointer_records': 8, 'mode_branch_pointers': 2, 'factory_stub_bytes': 16, 'queries_unsat': 43, 'queries_sat': 3, 'source_instruction_instances_translated': 547, 'distinct_source_instruction_sites_translated': 356, 'fresh_bank_cuts': 3, 'predecessor_queries_replayed': 4, 'rejected_alterations': 7}
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='b9c93b807749ce7dab8723bfd6d6a20d8c9e5a805309271ef567dfb036cd8290';m=json.loads(read(prior));assert len(m['files'])==7894
 unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert exists(q);digest=sha(q)
  if row['path']in CHANGED:assert digest!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':digest})
  else:assert digest==row['sha256']and size(q)==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==7887 and {r['path']for r in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
 s=json.loads(read(ROOT/(P+'_source.json')));c=json.loads(read(ROOT/(P+'_checks.json')));assert verify(s)and c['all_checks_pass']and c['typed_context_to_descriptor_task_flow_proved']and not c['complete_operation_proved']
 pp,sem=certificates(s);assert c['proofs']==pp and c['semantics']==json.loads(json.dumps(sem))and c['alterations']==alterations(s)
 counts=c['verified_counts'];required=REQUIRED_COUNTS;assert counts==required
 assert c['semantics']['selector']==26 and c['semantics']['core_context_frame_offset']==1848 and c['semantics']['context_task_offset']==16 and not c['semantics']['private_delta_values_proved_zero'] and not c['semantics']['global_descriptor_serialization_proved'] and not c['semantics']['native_connection_or_mapping_proved'] and c['semantics']['Mach_port_emissions']==0


 for obj,script in[(s,SCRIPTS[0]),(c,SCRIPTS[1])]:
  assert obj['generator_sha256']==sha(ROOT/script)and all(obj[k]is False for k in FLAGS)
  for n,digest in obj.get('dependencies',{}).items():assert sha(ROOT/n)==digest
 assert sha(SOLVER)==c['solver']['sha256']
 for n in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse(read(ROOT/n),filename=n)
 report=read(BASE/REPORTS[0]);assert report.isascii()and all('| DF'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8))
 links=0
 for name in REPORTS:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',read(BASE/name)):
   target=target.strip('<>')
   if target.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',target):continue
   q=Path(target.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:
    alias=re.sub(r'^/(?:Users|home)/_+(?=/|$)',lambda _:str(Path.home()),str(q));assert exists(q)or exists(Path(alias)),(name,target)
   links+=1
 delivery={'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':7894,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':5,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False}
 (ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 g={'generator_sha256':sha(__file__),'static_scope':c['static_scope'],'verified_counts':counts,'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in[P+'_source.json',P+'_checks.json']+SCRIPTS},'goal_status':'active',**{k:False for k in FLAGS}}
 for j in range(1,8):g['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+' and DF1-DF8;typed context/task flow through selector26,two task-bearing record protocols,descriptor factories,global result publication and three SP-delta boundaries. Forty-three UNSAT including four replays,three abstract SAT,356 distinct source sites and seven freshness alterations pass. Frame/alias closure,task references,global serialization,native mappings and complete transactions remain unproved.'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(g,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
