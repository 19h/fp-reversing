#!/usr/bin/env python3
"""Replay source/role proofs and seal the narrowly owned publication increment."""
import ast,json,re
from pathlib import Path
from recover_daemon_mode_one_workspace_passes import ROOT,P,FLAGS
from validate_daemon_mode_one_workspace_passes import verify,certificates,alterations,SOLVER
from verify_daemon_reader_record_payloads_publication import read,sha,size,exists
BASE=ROOT.parent
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','daemon_mode_one_record_checkpoint_report.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
SCRIPTS=['recover_'+P+'.py','validate_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='d9236a20db59b951686d5daa582a06f99be44846be54bd120f37a76be6f4bf3d';m=json.loads(read(prior));assert len(m['files'])==7704
 unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert exists(q);digest=sha(q)
  if row['path']in CHANGED:assert digest!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':digest})
  else:assert digest==row['sha256']and size(q)==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==7697 and {r['path']for r in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
 s=json.loads(read(ROOT/(P+'_source.json')));c=json.loads(read(ROOT/(P+'_checks.json')));assert verify(s)and c['all_checks_pass']and c['dual_workspace_passes_and_byte_permutation_proved']and not c['complete_operation_proved']
 pp,sem=certificates(s);assert c['proofs']==pp and c['semantics']==json.loads(json.dumps(sem))and c['alterations']==alterations(s)
 counts=c['verified_counts'];required={'source_ranges': 3, 'source_instructions': 731, 'source_bytes': 2924, 'pointer_records': 5, 'branch_bindings': 5, 'SP_writes': 0, 'comparison_role_corrections': 3, 'bitfield_decodes_checked': 0, 'pair_store_decodes_checked': 0, 'EON_decodes_checked': 0, 'pair_load_decodes_checked': 0, 'ADRP_decodes_checked': 0, 'TST_decodes_checked': 1, 'CNEG_decodes_checked': 0, 'EXTR_decodes_checked': 0, 'UMULL_decodes_checked': 13, 'UDIV_decodes_checked': 1, 'prior_ranges_recaptured': 10, 'prior_bytes_recaptured': 34804, 'queries_unsat': 174, 'queries_sat': 0, 'predecessor_queries_replayed': 3, 'source_nonbranch_sites_translated': 728, 'entry_sites_translated': 142, 'words_per_pass': 74, 'workspace_read_operations': 148, 'workspace_read_bytes': 592, 'state_words_per_pass': 4, 'integer_division_theorems': 12, 'source_remainder_shape_proofs': 11, 'source_mask_bounds': 3, 'source_overapproximations': 14, 'selected_address_cases': 133, 'identity_seed_stores': 16, 'source_swaps': 15, 'source_byte_reads': 29, 'source_byte_stores': 46, 'shuffle_stores': 47, 'shuffle_distinct_byte_destinations': 16, 'shuffle_root_stores': 1, 'generic_array_laws': 2, 'finite_index_transpositions': 256, 'rejected_alterations': 8};assert all(counts[k]==v for k,v in required.items())
 assert c['semantics']['two_independent_state_seeds_proved']and c['semantics']['final_values_are_a_permutation_of_0_to15']and not c['semantics']['uniform_or_random_permutation_proved']and not c['semantics']['decoded_workspace_recurrence_identity_proved']and c['semantics']['next_target']=='0x100a4f144'

 for obj,script in[(s,SCRIPTS[0]),(c,SCRIPTS[1])]:
  assert obj['generator_sha256']==sha(ROOT/script)and all(obj[k]is False for k in FLAGS)
  for n,digest in obj.get('dependencies',{}).items():assert sha(ROOT/n)==digest
 assert sha(SOLVER)==c['solver']['sha256']
 for n in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse(read(ROOT/n),filename=n)
 report=read(BASE/REPORTS[0]);assert report.isascii()and all('| WP'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8))
 links=0
 for name in REPORTS:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',read(BASE/name)):
   target=target.strip('<>')
   if target.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',target):continue
   q=Path(target.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:
    alias=re.sub(r'^/(?:Users|home)/_+(?=/|$)',lambda _:str(Path.home()),str(q));assert exists(q)or exists(Path(alias)),(name,target)
   links+=1
 delivery={'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':7704,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':5,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False}
 (ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 g={'generator_sha256':sha(__file__),'static_scope':c['static_scope'],'verified_counts':counts,'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in[P+'_source.json',P+'_checks.json']+SCRIPTS},'goal_status':'active',**{k:False for k in FLAGS}}
 for j in range(1,8):g['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+' and WP1-WP8;728 unique current sites plus142 entry sites,174 UNSAT including three predecessor queries;two74-word scalar passes,16 identity bytes and15 suffix swaps;12 integer division facts,11 source shapes,three mask bounds,14 bounded cuts,133 residue cases and two coherent-array laws. Decoded scalar/permutation identity,native ownership/output and daemon-kext pairing remain unknown.'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(g,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
