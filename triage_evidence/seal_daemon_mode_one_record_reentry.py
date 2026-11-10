#!/usr/bin/env python3
"""Replay source/role proofs and seal the narrowly owned publication increment."""
import ast,json,re
from pathlib import Path
from recover_daemon_mode_one_record_reentry import ROOT,P,FLAGS
from validate_daemon_mode_one_record_reentry import verify,certificates,alterations,SOLVER
from verify_daemon_reader_record_payloads_publication import read,sha,size,exists
BASE=ROOT.parent
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','daemon_mode_one_record_rounds_report.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
SCRIPTS=['recover_'+P+'.py','validate_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='147bec6db5eb37775f6eabcb322af78d9f015ee9411c1cac2d34aa7f89f82c47';m=json.loads(read(prior));assert len(m['files'])==7684
 unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert exists(q);digest=sha(q)
  if row['path']in CHANGED:assert digest!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':digest})
  else:assert digest==row['sha256']and size(q)==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==7677 and {r['path']for r in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
 s=json.loads(read(ROOT/(P+'_source.json')));c=json.loads(read(ROOT/(P+'_checks.json')));assert verify(s)and c['all_checks_pass']and c['parameterized_short_full_absorption_and_bounded_cycle_proved']and not c['complete_operation_proved']
 pp,sem=certificates(s);assert c['proofs']==pp and c['semantics']==json.loads(json.dumps(sem))and c['alterations']==alterations(s)
 counts=c['verified_counts'];required={'queries_unsat':97,'queries_sat':6,'predecessor_queries_replayed':45,'source_nonbranch_sites_translated':9591,'initializer_frame_aliases':27,'initializer_indexed_store_addresses':5,'initializer_universal_intermediate_overapproximations':4,'initializer_plane_stores':128,'short_parameterized_body_sites':271,'short_max_byte_reads':63,'short_finite_plane_address_cases':128,'short_source_cuts':3,'full_body_steps':4,'full_record_byte_reads':64,'full_plane_byte_reads':128,'full_plane_byte_stores':128,'full_original_byte_addresses_proved':320,'full_selected_instances_including_seed_exit':19194,'full_selected_instances_including_initializer':23368,'full_seed_state_words':8,'full_seed_control_coordinate_words':39,'full_seed_fixed_words':24,'full_seed_position_words':15,'full_CSEL_arm_equalities':4,'full_V_linearity_certificates':4,'retained_codebook_cells':800,'cycle_progress_preservation_stages':3,'cycle_max_COUNT_proved':4294967232,'positive_reentry_overwritten_plane_bytes':128,'rejected_alterations':8};assert all(counts[k]==v for k,v in required.items())
 assert c['semantics']['independent_branch_pointer_symbols']and not c['semantics']['entire_length_domain_proved']and not c['semantics']['whole_algorithm_identified']and c['semantics']['short_final_target']=='0x100c74750'and c['semantics']['full_next_target']=='0x100b8ed9c'

 for obj,script in[(s,SCRIPTS[0]),(c,SCRIPTS[1])]:
  assert obj['generator_sha256']==sha(ROOT/script)and all(obj[k]is False for k in FLAGS)
  for n,digest in obj.get('dependencies',{}).items():assert sha(ROOT/n)==digest
 assert sha(SOLVER)==c['solver']['sha256']
 for n in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse(read(ROOT/n),filename=n)
 report=read(BASE/REPORTS[0]);assert report.isascii()and all('| RE'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8))
 links=0
 for name in REPORTS:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',read(BASE/name)):
   target=target.strip('<>')
   if target.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',target):continue
   q=Path(target.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:
    alias=re.sub(r'^/(?:Users|home)/_+(?=/|$)',lambda _:str(Path.home()),str(q));assert exists(q)or exists(Path(alias)),(name,target)
   links+=1
 delivery={'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':7684,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':5,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False}
 (ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 g={'generator_sha256':sha(__file__),'static_scope':c['static_scope'],'verified_counts':counts,'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in[P+'_source.json',P+'_checks.json']+SCRIPTS},'goal_status':'active',**{k:False for k in FLAGS}}
 for j in range(1,8):g['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+' and RE1-RE8;9591 unique sites,97 UNSAT/six SAT including45 selected predecessor queries;parameterized short/full addresses and XOR updates,24 fixed/15 position seed words,64-byte progress,conditional bounded cycle coverage and128 overwritten-before-read plane bytes. Full-u32 length conformance,caller limits,native traversal/output,decoded state and daemon-kext pairing remain unknown.'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(g,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
