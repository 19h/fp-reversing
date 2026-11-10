#!/usr/bin/env python3
"""Replay source/role proofs and seal the narrowly owned publication increment."""
import ast,json,re
from pathlib import Path
from recover_daemon_mode_one_encoded_addition import ROOT,P,FLAGS
from validate_daemon_mode_one_encoded_addition import verify,certificates,alterations,SOLVER
from verify_daemon_reader_record_payloads_publication import read,sha,size,exists
BASE=ROOT.parent
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','daemon_mode_one_workspace_passes_report.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
SCRIPTS=['recover_'+P+'.py','validate_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='1ffff2993a704eef74aadd3eccaa8a1330d4972ba13806215583fd353322755a';m=json.loads(read(prior));assert len(m['files'])==7714
 unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert exists(q);digest=sha(q)
  if row['path']in CHANGED:assert digest!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':digest})
  else:assert digest==row['sha256']and size(q)==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==7707 and {r['path']for r in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
 s=json.loads(read(ROOT/(P+'_source.json')));c=json.loads(read(ROOT/(P+'_checks.json')));assert verify(s)and c['all_checks_pass']and c['inverse_second_permutation_and_encoded_addition_proved']and not c['complete_operation_proved']
 pp,sem=certificates(s);assert c['proofs']==pp and c['semantics']==json.loads(json.dumps(sem))and c['alterations']==alterations(s)
 counts=c['verified_counts'];required={'source_ranges': 3, 'source_instructions': 438, 'source_bytes': 1752, 'pointer_records': 5, 'branch_bindings': 5, 'SP_writes': 0, 'comparison_role_corrections': 3, 'bitfield_decodes_checked': 1, 'pair_store_decodes_checked': 0, 'EON_decodes_checked': 0, 'pair_load_decodes_checked': 0, 'ADRP_decodes_checked': 1, 'TST_decodes_checked': 1, 'CNEG_decodes_checked': 0, 'EXTR_decodes_checked': 0, 'UMULL_decodes_checked': 18, 'UDIV_decodes_checked': 1, 'prior_ranges_recaptured': 12, 'prior_bytes_recaptured': 97016, 'selector_byte_cases': 256, 'selector_image_bytes': 512, 'ROM_image_bytes': 928, 'selected_ROM_cells': 256, 'data_rebase_records': 1, 'queries_unsat': 685, 'queries_sat': 1, 'predecessor_queries_replayed': 174, 'source_nonbranch_sites_translated': 435, 'inverse_iterations': 16, 'inverse_source_address_cases': 16, 'inverse_destination_address_cases': 16, 'inverse_array_cells': 16, 'second_shuffle_overapproximations': 14, 'second_shuffle_address_cases': 133, 'second_shuffle_identity_stores': 16, 'second_shuffle_swaps': 15, 'second_shuffle_byte_reads': 29, 'second_shuffle_byte_stores': 46, 'builder_iterations': 256, 'builder_inverse_address_cases': 32, 'builder_Q_address_cases': 16, 'builder_ROM_address_cases': 256, 'builder_byte_reads_per_iteration': 6, 'builder_byte_stores_per_iteration': 1, 'ROM_associativity_cases': 4096, 'ROM_encoded_addition_cases': 256, 'ROM_order16_generators': 8, 'known_frame_cells': 288, 'rejected_alterations': 8};assert all(counts[k]==v for k,v in required.items())
 assert c['semantics']['ROM_identity_symbol']==12 and c['semantics']['generated_table_is_Latin']and c['semantics']['generated_table_is_commutative']and not c['semantics']['generated_table_associativity_or_identity_proved']and c['semantics']['next_target']=='0x100c1c8a0'

 for obj,script in[(s,SCRIPTS[0]),(c,SCRIPTS[1])]:
  assert obj['generator_sha256']==sha(ROOT/script)and all(obj[k]is False for k in FLAGS)
  for n,digest in obj.get('dependencies',{}).items():assert sha(ROOT/n)==digest
 assert sha(SOLVER)==c['solver']['sha256']
 for n in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse(read(ROOT/n),filename=n)
 report=read(BASE/REPORTS[0]);assert report.isascii()and all('| EA'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8))
 links=0
 for name in REPORTS:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',read(BASE/name)):
   target=target.strip('<>')
   if target.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',target):continue
   q=Path(target.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:
    alias=re.sub(r'^/(?:Users|home)/_+(?=/|$)',lambda _:str(Path.home()),str(q));assert exists(q)or exists(Path(alias)),(name,target)
   links+=1
 delivery={'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':7714,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':5,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False}
 (ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 g={'generator_sha256':sha(__file__),'static_scope':c['static_scope'],'verified_counts':counts,'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in[P+'_source.json',P+'_checks.json']+SCRIPTS},'goal_status':'active',**{k:False for k in FLAGS}}
 for j in range(1,8):g['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+' and EA1-EA8;435 source sites,685 UNSAT/one abstract SAT including174 predecessor queries;16-cell inverse,second15-swap permutation,256-entry encoded modulo16 addition;source ROM/fixup and selected-cell range,256 addition/4096 associativity cases,eight generators and exact input/output encoding roles. Native ownership/output and daemon-kext pairing remain unknown.'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(g,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
