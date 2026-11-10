#!/usr/bin/env python3
"""Replay source/role proofs and seal the narrowly owned publication increment."""
import ast,json,re
from pathlib import Path
from recover_daemon_mode_one_record_checkpoint import ROOT,P,FLAGS
from validate_daemon_mode_one_record_checkpoint import verify,certificates,alterations,SOLVER
from verify_daemon_reader_record_payloads_publication import read,sha,size,exists
BASE=ROOT.parent
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','daemon_mode_one_record_reentry_report.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
SCRIPTS=['recover_'+P+'.py','validate_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='76423fbd211b967e68d38eaf3b374508ec294fdc42daed79bf8a3a5acbe5d617';m=json.loads(read(prior));assert len(m['files'])==7694
 unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert exists(q);digest=sha(q)
  if row['path']in CHANGED:assert digest!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':digest})
  else:assert digest==row['sha256']and size(q)==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==7687 and {r['path']for r in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
 s=json.loads(read(ROOT/(P+'_source.json')));c=json.loads(read(ROOT/(P+'_checks.json')));assert verify(s)and c['all_checks_pass']and c['checkpoint_iterator_and_wrapper_gate_proved']and not c['complete_operation_proved']
 pp,sem=certificates(s);assert c['proofs']==pp and c['semantics']==json.loads(json.dumps(sem))and c['alterations']==alterations(s)
 counts=c['verified_counts'];required={'source_ranges': 5, 'source_instructions': 7072, 'source_bytes': 28288, 'pointer_records': 6, 'branch_bindings': 7, 'SP_writes': 0, 'comparison_role_corrections': 4, 'bitfield_decodes_checked': 25, 'pair_store_decodes_checked': 0, 'EON_decodes_checked': 0, 'pair_load_decodes_checked': 5, 'ADRP_decodes_checked': 0, 'TST_decodes_checked': 1, 'CNEG_decodes_checked': 1, 'EXTR_decodes_checked': 2, 'prior_ranges_recaptured': 58, 'prior_bytes_recaptured': 193604, 'queries_unsat': 59, 'queries_sat': 2, 'predecessor_queries_replayed': 45, 'source_nonbranch_sites_translated': 7068, 'checkpoint_frame_reads': 592, 'checkpoint_loads': 622, 'checkpoint_stores': 250, 'checkpoint_u32_stores': 245, 'checkpoint_u64_stores': 5, 'checkpoint_store_bytes': 1020, 'checkpoint_distinct_written_bytes': 796, 'checkpoint_plane_byte_reads': 128, 'checkpoint_workspace_u32_stores': 74, 'checkpoint_workspace_bytes': 296, 'checkpoint_GPR_liveins': 0, 'checkpoint_paired_loads': 5, 'protected_precheckpoint_stages': 7, 'LOCAL_present_stores': 3, 'rejected_alterations': 8};assert all(counts[k]==v for k,v in required.items())
 assert c['semantics']['checkpoint_no_GPR_liveins']and not c['semantics']['arbitrary_selector_inverse_proved']and not c['semantics']['checkpoint_workspace_decoded_function_proved']and c['semantics']['LOCAL_true_target']=='0x100d3ce60'and c['semantics']['next_nonnull_target']=='0x100bda488'

 for obj,script in[(s,SCRIPTS[0]),(c,SCRIPTS[1])]:
  assert obj['generator_sha256']==sha(ROOT/script)and all(obj[k]is False for k in FLAGS)
  for n,digest in obj.get('dependencies',{}).items():assert sha(ROOT/n)==digest
 assert sha(SOLVER)==c['solver']['sha256']
 for n in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse(read(ROOT/n),filename=n)
 report=read(BASE/REPORTS[0]);assert report.isascii()and all('| CP'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8))
 links=0
 for name in REPORTS:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',read(BASE/name)):
   target=target.strip('<>')
   if target.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',target):continue
   q=Path(target.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:
    alias=re.sub(r'^/(?:Users|home)/_+(?=/|$)',lambda _:str(Path.home()),str(q));assert exists(q)or exists(Path(alias)),(name,target)
   links+=1
 delivery={'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':7694,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':5,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False}
 (ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 g={'generator_sha256':sha(__file__),'static_scope':c['static_scope'],'verified_counts':counts,'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in[P+'_source.json',P+'_checks.json']+SCRIPTS},'goal_status':'active',**{k:False for k in FLAGS}}
 for j in range(1,8):g['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+' and CP1-CP8;7068 unique sites,59 UNSAT/two SAT including45 selected predecessor queries;128 exact plane reads,296-byte workspace replacement,typed word lifetime,iterator/decoder restoration and original-wrapper request-field sufficiency. Arbitrary selector inverse,decoded workspace function,native traversal/output and daemon-kext pairing remain unknown.'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(g,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
