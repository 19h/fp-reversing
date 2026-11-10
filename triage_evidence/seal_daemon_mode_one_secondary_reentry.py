#!/usr/bin/env python3
"""Replay source/role proofs and seal the narrowly owned publication increment."""
import ast,json,re
from pathlib import Path
from recover_daemon_mode_one_secondary_reentry import ROOT,P,FLAGS
from validate_daemon_mode_one_secondary_reentry import verify,certificates,alterations,SOLVER
from verify_daemon_reader_record_payloads_publication import read,sha,size,exists
BASE=ROOT.parent
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','daemon_mode_one_secondary_rounds_report.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
SCRIPTS=['recover_'+P+'.py','validate_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
REQUIRED_COUNTS = {'source_ranges': 5, 'source_instructions': 2423, 'source_bytes': 9692, 'branch_bindings': 8, 'pointer_records': 7, 'ISA_decodes_checked': 2, 'comparison_role_corrections': 2, 'prior_ranges_recaptured': 14, 'prior_bytes_recaptured': 81496, 'frontier_ranges_hashed': 2, 'frontier_bytes_hashed': 248, 'SP_writes': 0, 'queries_unsat': 28, 'queries_sat': 3, 'predecessor_queries_replayed': 9, 'source_nonbranch_sites_translated': 2418, 'finish_u32_stores': 13, 'chained_saved_state_fields_written': 16, 'chained_saved_state_bytes': 64, 'plane_byte_stores': 128, 'arithmetic_cells_preserved': 800, 'refresh_proved_value_cuts': 2, 'refresh_store_address_normalizations': 4, 'current_distinct_bytes_written': 196, 'guarded_first_plane_byte_XOR_sites': 1, 'guarded_byte_address_normalizations': 2, 'rejected_alterations': 7}
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='126bd6380764aca13d940b9a4ba9d9f60f99ffd9f61a38dd856edd8ff3c174d7';m=json.loads(read(prior));assert len(m['files'])==7794
 unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert exists(q);digest=sha(q)
  if row['path']in CHANGED:assert digest!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':digest})
  else:assert digest==row['sha256']and size(q)==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==7787 and {r['path']for r in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
 s=json.loads(read(ROOT/(P+'_source.json')));c=json.loads(read(ROOT/(P+'_checks.json')));assert verify(s)and c['all_checks_pass']and c['secondary_state_commit_generalized_refresh_and_reentry_proved']and not c['complete_operation_proved']
 pp,sem=certificates(s);assert c['proofs']==pp and c['semantics']==json.loads(json.dumps(sem))and c['alterations']==alterations(s)
 counts=c['verified_counts'];required=REQUIRED_COUNTS;assert counts==required
 assert c['semantics']['chained_state_fields_written']==16 and c['semantics']['plane_bytes_written']==128 and c['semantics']['guarded_toggle_cell']=='C(0)=F+0x8b0' and c['semantics']['Mach_port_emissions']==0 and not c['semantics']['whole_arithmetic_proved']


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
 delivery={'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':7794,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':5,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False}
 (ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 g={'generator_sha256':sha(__file__),'static_scope':c['static_scope'],'verified_counts':counts,'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in[P+'_source.json',P+'_checks.json']+SCRIPTS},'goal_status':'active',**{k:False for k in FLAGS}}
 for j in range(1,8):g['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+' and RE1-RE8;2418 source sites,28 UNSAT/three abstract SAT,including9 selected predecessor replays;16-field commit,modular progression,generalized128-byte refresh,both parity gates and correlated C(0) XOR80. Native meanings,termination,output,whole arithmetic and cross-layer pairing remain explicit unknowns.'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(g,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
