#!/usr/bin/env python3
"""Replay source/role proofs and seal the narrowly owned publication increment."""
import ast,json,re
from pathlib import Path
from recover_daemon_mode_one_budget_store_audit import ROOT,P,FLAGS
from validate_daemon_mode_one_budget_store_audit import verify,certificates,alterations,SOLVER
from verify_daemon_reader_record_payloads_publication import read,sha,size,exists
BASE=ROOT.parent
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','daemon_mode_one_second_phase_handoff_report.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
SCRIPTS=['recover_'+P+'.py','validate_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
REQUIRED_COUNTS = {'inventory_artifacts': 46, 'retained_range_instances': 209, 'retained_bytes_recaptured': 518140, 'core_instruction_sites': 110556, 'core_store_sites': 3754, 'SP_store_encodings_independently_decoded': 3307, 'retained_frame_offset_sites': 236, 'retained_array_contract_sites': 174, 'LOCAL_byte_store_sites': 32, 'special_destination_sites': 5, 'translated_source_ranges': 4, 'translated_source_instructions': 81, 'translated_source_bytes': 324, 'structural_frame_ranges': 2, 'structural_frame_instructions': 33, 'controller_bank_byte_cases': 512, 'original_pointer_records': 4, 'IDA_text_bytes_matched': 14849960, 'queries_unsat': 27, 'queries_sat': 2, 'predecessor_queries_replayed': 14, 'source_nonbranch_sites_translated': 81, 'fresh_controller_value_cuts': 0, 'current_store_effects': 6, 'rejected_alterations': 8}
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='76d2cefd12d38616a38115f2fbac20b19189a7dcb64412dacf71a9d07845cf76';m=json.loads(read(prior));assert len(m['files'])==7844
 unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert exists(q);digest=sha(q)
  if row['path']in CHANGED:assert digest!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':digest})
  else:assert digest==row['sha256']and size(q)==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==7837 and {r['path']for r in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
 s=json.loads(read(ROOT/(P+'_source.json')));c=json.loads(read(ROOT/(P+'_checks.json')));assert verify(s)and c['all_checks_pass']and c['captured_core_store_catalogue_and_conditional_budget_law_proved']and not c['complete_operation_proved']
 pp,sem=certificates(s);assert c['proofs']==pp and c['semantics']==json.loads(json.dumps(sem))and c['alterations']==alterations(s)
 counts=c['verified_counts'];required=REQUIRED_COUNTS;assert counts==required
 assert c['semantics']['core_store_catalogue_sites']==3754 and c['semantics']['independently_decoded_SP_stores']==3307 and c['semantics']['retained_array_envelope_premise_sites']==174 and c['semantics']['captured_path_budget_preservation_and_zero_delta_law_proved'] and c['semantics']['controller_pair_represents_one_u64_carrier_after_both_source_stores'] and c['semantics']['IDA_text_identity_established'] and not c['semantics']['whole_file_IDB_identity_established'] and not c['semantics']['whole_core_control_closure_proved'] and not c['semantics']['native_return_observed'] and c['semantics']['Mach_port_emissions']==0


 for obj,script in[(s,SCRIPTS[0]),(c,SCRIPTS[1])]:
  assert obj['generator_sha256']==sha(ROOT/script)and all(obj[k]is False for k in FLAGS)
  for n,digest in obj.get('dependencies',{}).items():assert sha(ROOT/n)==digest
 assert sha(SOLVER)==c['solver']['sha256']
 for n in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse(read(ROOT/n),filename=n)
 report=read(BASE/REPORTS[0]);assert report.isascii()and all('| BA'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8))
 links=0
 for name in REPORTS:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',read(BASE/name)):
   target=target.strip('<>')
   if target.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',target):continue
   q=Path(target.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:
    alias=re.sub(r'^/(?:Users|home)/_+(?=/|$)',lambda _:str(Path.home()),str(q));assert exists(q)or exists(Path(alias)),(name,target)
   links+=1
 delivery={'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':7844,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':5,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False}
 (ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 g={'generator_sha256':sha(__file__),'static_scope':c['static_scope'],'verified_counts':counts,'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in[P+'_source.json',P+'_checks.json']+SCRIPTS},'goal_status':'active',**{k:False for k in FLAGS}}
 for j in range(1,8):g['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+' and BA1-BA8;3754 captured core stores,3307 independently decoded SP stores,81 translated source instructions,27 UNSAT/two abstract SAT and14 predecessor replays. Exact controller/canary/budget/request/delta equations,one-carrier controller encodings,byte preservation and conditional zero-delta law are covered. The236 retained frame-offset and174 array-site contracts,logical control closure,callee/owner behavior and native return remain explicit premises. Loaded code matches the pinned text;whole-file IDB identity and matched transport remain unestablished.'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(g,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
