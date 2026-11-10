#!/usr/bin/env python3
"""Replay source/role proofs and seal the narrowly owned publication increment."""
import ast,json,re
from pathlib import Path
from recover_daemon_mode_one_second_phase_handoff import ROOT,P,FLAGS
from validate_daemon_mode_one_second_phase_handoff import verify,certificates,alterations,SOLVER
from verify_daemon_reader_record_payloads_publication import read,sha,size,exists
BASE=ROOT.parent
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','daemon_mode_one_phase_handoff_report.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
SCRIPTS=['recover_'+P+'.py','validate_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
REQUIRED_COUNTS = {'source_ranges': 8, 'source_instructions': 569, 'source_bytes': 2276, 'branch_bindings': 14, 'pointer_records': 13, 'ISA_decodes_checked': 5, 'comparison_role_corrections': 4, 'prior_ranges_recaptured': 232, 'prior_bytes_recaptured': 519616, 'locator_artifacts': 45, 'locator_distinct_ranges': 183, 'locator_distinct_instruction_sites': 111274, 'locator_candidate_store_sites': 3781, 'SP_writes': 0, 'queries_unsat': 35, 'queries_sat': 2, 'predecessor_queries_replayed': 14, 'source_nonbranch_sites_translated': 561, 'second_repack_u32_stores': 16, 'combined_sparse_words': 32, 'workspace_word_codecs_rechecked': 32, 'workspace_literal_bytes_rechecked': 168, 'workspace_distinct_bytes_written': 312, 'retained_repeat_stage_lifetime_components': 7, 'source_value_cuts': 0, 'rejected_alterations': 8}
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='5d2f0afa8f7a8c36122fc27bff8f3eea411af78f075ee07e7c4163d1dd04281e';m=json.loads(read(prior));assert len(m['files'])==7834
 unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert exists(q);digest=sha(q)
  if row['path']in CHANGED:assert digest!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':digest})
  else:assert digest==row['sha256']and size(q)==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==7827 and {r['path']for r in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
 s=json.loads(read(ROOT/(P+'_source.json')));c=json.loads(read(ROOT/(P+'_checks.json')));assert verify(s)and c['all_checks_pass']and c['second_phase_bank_completion_and_workspace_handoff_proved']and not c['complete_operation_proved']
 pp,sem=certificates(s);assert c['proofs']==pp and c['semantics']==json.loads(json.dumps(sem))and c['alterations']==alterations(s)
 counts=c['verified_counts'];required=REQUIRED_COUNTS;assert counts==required
 assert c['semantics']['combined_sparse_words']==32 and c['semantics']['repack_sets_disjoint'] and c['semantics']['workspace_word_codecs_rechecked']==32 and c['semantics']['workspace_literal_bytes_rechecked']==168 and c['semantics']['workspace_frame_store_bytes_distinct']==312 and c['semantics']['phase86_set_bit_workspace_handoff_proved'] and c['semantics']['Mach_port_emissions']==0 and not c['semantics']['whole_core_budget_history_proved'] and not c['semantics']['native_normal_return_proved']


 for obj,script in[(s,SCRIPTS[0]),(c,SCRIPTS[1])]:
  assert obj['generator_sha256']==sha(ROOT/script)and all(obj[k]is False for k in FLAGS)
  for n,digest in obj.get('dependencies',{}).items():assert sha(ROOT/n)==digest
 assert sha(SOLVER)==c['solver']['sha256']
 for n in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse(read(ROOT/n),filename=n)
 report=read(BASE/REPORTS[0]);assert report.isascii()and all('| SH'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8))
 links=0
 for name in REPORTS:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',read(BASE/name)):
   target=target.strip('<>')
   if target.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',target):continue
   q=Path(target.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:
    alias=re.sub(r'^/(?:Users|home)/_+(?=/|$)',lambda _:str(Path.home()),str(q));assert exists(q)or exists(Path(alias)),(name,target)
   links+=1
 delivery={'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':7834,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':5,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False}
 (ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 g={'generator_sha256':sha(__file__),'static_scope':c['static_scope'],'verified_counts':counts,'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in[P+'_source.json',P+'_checks.json']+SCRIPTS},'goal_status':'active',**{k:False for k in FLAGS}}
 for j in range(1,8):g['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+' and SH1-SH8;561 source sites,35 UNSAT/two abstract SAT and14 predecessor replays. Exact86 bridge,complementary16-word repack,hidden addition,phase-one workspace ABI,32 word/168 literal-byte rechecks and bounded lifetime/budget facts are covered. The45-artifact locator union is not whole-program coverage. Full budget history,zero processing delta,native return,ownership,algorithm and matched transport remain unknown.'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(g,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
