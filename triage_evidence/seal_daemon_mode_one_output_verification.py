#!/usr/bin/env python3
"""Replay source/role proofs and seal the narrowly owned publication increment."""
import ast,json,re
from pathlib import Path
from recover_daemon_mode_one_output_verification import ROOT,P,FLAGS
from validate_daemon_mode_one_output_verification import verify,certificates,alterations,SOLVER
from verify_daemon_reader_record_payloads_publication import read,sha,size,exists
BASE=ROOT.parent
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','daemon_mode_one_result_publication_report.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
SCRIPTS=['recover_'+P+'.py','validate_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
REQUIRED_COUNTS = {'source_ranges': 24, 'source_instructions': 555, 'source_bytes': 2220, 'branch_bindings': 32, 'saved_continuation_bindings': 4, 'pointer_records': 30, 'ISA_decodes_checked': 36, 'comparison_role_corrections': 11, 'prior_ranges_recaptured': 67, 'prior_bytes_recaptured': 49428, 'internal_call_bytes_checked': 8, 'wrapper_prefix_seed_preservation_instructions': 97, 'SP_writes': 0, 'queries_unsat': 71, 'queries_sat': 3, 'predecessor_queries_replayed': 13, 'source_nonbranch_sites_translated': 533, 'comparison_iterations': 32, 'SPAN_byte_reads': 32, 'LOCAL_byte_reads': 32, 'retry_LOCAL_halfword_zero_stores': 16, 'retry_LOCAL_bytes_zeroed': 32, 'source_value_cuts': 0, 'rejected_alterations': 8}
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='5b46de71b949204b3de8efe03ac0aaa46ef2ce5c489bdfccad38fa8f2adf9003';m=json.loads(read(prior));assert len(m['files'])==7824
 unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert exists(q);digest=sha(q)
  if row['path']in CHANGED:assert digest!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':digest})
  else:assert digest==row['sha256']and size(q)==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==7817 and {r['path']for r in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
 s=json.loads(read(ROOT/(P+'_source.json')));c=json.loads(read(ROOT/(P+'_checks.json')));assert verify(s)and c['all_checks_pass']and c['mode_one_caller_output_verification_and_retry_interfaces_proved']and not c['complete_operation_proved']
 pp,sem=certificates(s);assert c['proofs']==pp and c['semantics']==json.loads(json.dumps(sem))and c['alterations']==alterations(s)
 counts=c['verified_counts'];required=REQUIRED_COUNTS;assert counts==required
 assert c['semantics']['comparison_iterations']==32 and c['semantics']['SPAN_bytes_read']==32 and c['semantics']['LOCAL_bytes_read']==32 and c['semantics']['retry_LOCAL_bytes_zeroed']==32 and c['semantics']['actual_retry_cycle_seed_preservation_proved'] and c['semantics']['Mach_port_emissions']==0 and not c['semantics']['native_comparison_observed']


 for obj,script in[(s,SCRIPTS[0]),(c,SCRIPTS[1])]:
  assert obj['generator_sha256']==sha(ROOT/script)and all(obj[k]is False for k in FLAGS)
  for n,digest in obj.get('dependencies',{}).items():assert sha(ROOT/n)==digest
 assert sha(SOLVER)==c['solver']['sha256']
 for n in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse(read(ROOT/n),filename=n)
 report=read(BASE/REPORTS[0]);assert report.isascii()and all('| OV'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8))
 links=0
 for name in REPORTS:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',read(BASE/name)):
   target=target.strip('<>')
   if target.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',target):continue
   q=Path(target.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:
    alias=re.sub(r'^/(?:Users|home)/_+(?=/|$)',lambda _:str(Path.home()),str(q));assert exists(q)or exists(Path(alias)),(name,target)
   links+=1
 delivery={'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':7824,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':5,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False}
 (ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 g={'generator_sha256':sha(__file__),'static_scope':c['static_scope'],'verified_counts':counts,'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in[P+'_source.json',P+'_checks.json']+SCRIPTS},'goal_status':'active',**{k:False for k in FLAGS}}
 for j in range(1,8):g['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+' and OV1-OV8;533 source sites,71 UNSAT/three abstract SAT and13 predecessor replays. Exact32-byte address-bound comparison,reduction,alternate-source retry,seed continuity,option join and raw failure staging are covered. Whole processing budget history,normal native return,ownership/extents/alias policy,algorithm identity and matched transport remain unknown.'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(g,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
