#!/usr/bin/env python3
"""Replay source/role proofs and seal the narrowly owned publication increment."""
import ast,json,re
from pathlib import Path
from recover_daemon_mode_one_secondary_word_extension import ROOT,P,FLAGS
from validate_daemon_mode_one_secondary_word_extension import verify,certificates,alterations,SOLVER
from verify_daemon_reader_record_payloads_publication import read,sha,size,exists
BASE=ROOT.parent
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','daemon_mode_one_secondary_word_import_report.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
SCRIPTS=['recover_'+P+'.py','validate_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
REQUIRED_COUNTS = {'exit_block_full_instructions': 10637, 'exit_block_untranslated_instructions': 10630, 'exit_block_bytes_hashed': 42548, 'source_ranges': 2, 'source_instructions': 2252, 'source_bytes': 9008, 'pointer_records': 2, 'branch_bindings': 2, 'SP_writes': 0, 'EON_decodes_checked': 1, 'TST_decodes_checked': 1, 'CNEG_decodes_checked': 1, 'UDIV_decodes_checked': 1, 'UMULL_decodes_checked': 74, 'bitfield_decodes_checked': 39, 'register_shift_decodes_checked': 2, 'comparison_role_corrections': 2, 'prior_ranges_recaptured': 4, 'prior_bytes_recaptured': 12088, 'queries_unsat': 36, 'queries_sat': 6, 'predecessor_queries_replayed': 14, 'source_nonbranch_sites_translated': 2251, 'selected_traversal_nonbranch_instances': 107719, 'iterations': 48, 'word_read_operations': 384, 'new_word_stores': 192, 'new_word_bytes': 768, 'final_populated_words': 256, 'final_populated_word_bytes': 1024, 'unclaimed_grid_slots': 30, 'primary_byte_reads_bounded': 69, 'primary_byte_reads_total': 3312, 'short_reciprocal_sites': 40, 'full_reciprocal_sites': 29, 'short_numerator_upper_bound': 759849, 'proved_bank_membership_sites': 40, 'proved_SUM_sites': 11, 'proved_CARRY_sites': 3, 'proved_XOR_sites': 3, 'proved_ENC_sites': 15, 'proved_DEC_sites': 8, 'source_sigma_identities': 4, 'state_parametric_additive_streams': 1, 'rejected_second_additive_streams': 1, 'rejected_pair_XOR_groups': 2, 'per_iteration_loads': 169, 'per_iteration_stores': 27, 'per_iteration_read_bytes': 729, 'per_iteration_store_bytes': 108, 'private_frame_stores': 23, 'private_frame_distinct_written_bytes': 76, 'loop_and_prefix_loads': 8113, 'loop_and_prefix_stores': 1297, 'loop_and_prefix_read_bytes': 34996, 'loop_and_prefix_store_bytes': 5188, 'loop_and_prefix_distinct_written_bytes': 844, 'source_value_cuts': 0, 'computed_address_normalizations': 0, 'initial_unprescribed_frame_inputs': 0, 'primary_standard_bytes': 833315, 'rejected_alterations': 8}
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='ffab2e9b22ba36c295b8d29c37d657eb4c2cfaa337de5e3fa8671a16f72efab1';m=json.loads(read(prior));assert len(m['files'])==7774
 unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert exists(q);digest=sha(q)
  if row['path']in CHANGED:assert digest!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':digest})
  else:assert digest==row['sha256']and size(q)==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==7767 and {r['path']for r in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
 s=json.loads(read(ROOT/(P+'_source.json')));c=json.loads(read(ROOT/(P+'_checks.json')));assert verify(s)and c['all_checks_pass']and c['secondary_word_extension_geometry_bounds_sigma_and_state_dependence_proved']and not c['complete_operation_proved']
 pp,sem=certificates(s);assert c['proofs']==pp and c['semantics']==json.loads(json.dumps(sem))and c['alterations']==alterations(s)
 counts=c['verified_counts'];required=REQUIRED_COUNTS;assert counts==required
 assert c['semantics']['iterations']==48 and c['semantics']['new_word_stores']==192 and c['semantics']['exit_target']=='0x100c2c25c'and c['semantics']['Mach_port_emissions']==0 and not c['semantics']['whole_decoded_standard_schedule_proved']


 for obj,script in[(s,SCRIPTS[0]),(c,SCRIPTS[1])]:
  assert obj['generator_sha256']==sha(ROOT/script)and all(obj[k]is False for k in FLAGS)
  for n,digest in obj.get('dependencies',{}).items():assert sha(ROOT/n)==digest
 assert sha(SOLVER)==c['solver']['sha256']
 for n in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse(read(ROOT/n),filename=n)
 report=read(BASE/REPORTS[0]);assert report.isascii()and all('| SX'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8))
 links=0
 for name in REPORTS:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',read(BASE/name)):
   target=target.strip('<>')
   if target.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',target):continue
   q=Path(target.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:
    alias=re.sub(r'^/(?:Users|home)/_+(?=/|$)',lambda _:str(Path.home()),str(q));assert exists(q)or exists(Path(alias)),(name,target)
   links+=1
 delivery={'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':7774,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':5,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False}
 (ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 g={'generator_sha256':sha(__file__),'static_scope':c['static_scope'],'verified_counts':counts,'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in[P+'_source.json',P+'_checks.json']+SCRIPTS},'goal_status':'active',**{k:False for k in FLAGS}}
 for j in range(1,8):g['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+' and SX1-SX8;2251 source sites,36 UNSAT/six abstract SAT,including14 selected predecessor replays;48-step word expansion,69 byte bounds,40 bank roles,four exact sigma components,one state-parametric additive dependence and F4e4 exit prefix. Full recurrence,29 bank roles,current table validity,native ownership/output and cross-layer pairing remain explicit unknowns.'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(g,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
