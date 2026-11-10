#!/usr/bin/env python3
"""Replay source/role proofs and seal the narrowly owned publication increment."""
import ast,json,re
from pathlib import Path
from recover_daemon_mode_one_nibble_operation_suite import ROOT,P,FLAGS
from validate_daemon_mode_one_nibble_operation_suite import verify,certificates,alterations,SOLVER
from verify_daemon_reader_record_payloads_publication import read,sha,size,exists
BASE=ROOT.parent
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','daemon_mode_one_encoded_addition_report.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
SCRIPTS=['recover_'+P+'.py','validate_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='e08ef2f891d75d64aaeedbf6222329096bfcd7c0568e7700bcb475bdf589eba9';m=json.loads(read(prior));assert len(m['files'])==7724
 unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert exists(q);digest=sha(q)
  if row['path']in CHANGED:assert digest!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':digest})
  else:assert digest==row['sha256']and size(q)==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==7717 and {r['path']for r in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
 s=json.loads(read(ROOT/(P+'_source.json')));c=json.loads(read(ROOT/(P+'_checks.json')));assert verify(s)and c['all_checks_pass']and c['carry_xor_input_decoder_output_encoder_proved']and not c['complete_operation_proved']
 pp,sem=certificates(s);assert c['proofs']==pp and c['semantics']==json.loads(json.dumps(sem))and c['alterations']==alterations(s)
 counts=c['verified_counts'];required={'source_ranges': 4, 'source_instructions': 249, 'source_bytes': 996, 'pointer_records': 6, 'branch_bindings': 8, 'SP_writes': 0, 'comparison_role_corrections': 4, 'bitfield_decodes_checked': 3, 'pair_store_decodes_checked': 0, 'EON_decodes_checked': 0, 'pair_load_decodes_checked': 0, 'ADRP_decodes_checked': 0, 'TST_decodes_checked': 0, 'CNEG_decodes_checked': 0, 'EXTR_decodes_checked': 0, 'UMULL_decodes_checked': 14, 'UDIV_decodes_checked': 1, 'prior_ranges_recaptured': 6, 'prior_bytes_recaptured': 4676, 'ROM_image_bytes': 928, 'carry_ROM_cells': 256, 'xor_ROM_cells': 256, 'decoder_ROM_cells': 16, 'encoder_ROM_cells': 16, 'cumulative_selected_ROM_cells': 800, 'register_shift_decodes_checked': 1, 'queries_unsat': 1378, 'queries_sat': 2, 'predecessor_queries_replayed': 686, 'source_nonbranch_sites_translated': 245, 'incoming_register_contracts': 2, 'carry_iterations': 256, 'xor_iterations': 256, 'decoder_iterations': 16, 'encoder_iterations': 16, 'current_byte_writes': 544, 'carry_inverse_address_cases': 32, 'carry_ROM_address_cases': 256, 'carry_Q_address_cases': 16, 'xor_inverse_address_cases': 32, 'xor_ROM_address_cases': 256, 'xor_Q_alphabet_cases': 16, 'decoder_inverse_cases': 16, 'decoder_ROM_cases': 16, 'encoder_ROM_candidate_proofs': 16, 'encoder_Q_cases': 16, 'universal_ROM_operation_queries': 3, 'static_numeric_codec_inverse_query': 1, 'fresh_register_shift_and_divisor_proofs': 2, 'full_outgoing_ABI_contracts': 4, 'known_frame_cells': 832, 'unclaimed_frame_cells': 130, 'numeric_operation_cases': 256, 'carry_zero_pairs': 136, 'carry_one_pairs': 120, 'joint_sum_carry_numeric_results': 31, 'rejected_alterations': 8};assert all(counts[k]==v for k,v in required.items())
 assert c['semantics']['carry_fixes_generator_symbol']==11 and c['semantics']['static_decoder_encoder_inverse']and not c['semantics']['private_decoder_encoder_mutual_inverse_proved']and c['semantics']['known_frame_cells']==832 and c['semantics']['next_target']=='0x100d845e0'

 for obj,script in[(s,SCRIPTS[0]),(c,SCRIPTS[1])]:
  assert obj['generator_sha256']==sha(ROOT/script)and all(obj[k]is False for k in FLAGS)
  for n,digest in obj.get('dependencies',{}).items():assert sha(ROOT/n)==digest
 assert sha(SOLVER)==c['solver']['sha256']
 for n in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse(read(ROOT/n),filename=n)
 report=read(BASE/REPORTS[0]);assert report.isascii()and all('| OP'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8))
 links=0
 for name in REPORTS:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',read(BASE/name)):
   target=target.strip('<>')
   if target.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',target):continue
   q=Path(target.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:
    alias=re.sub(r'^/(?:Users|home)/_+(?=/|$)',lambda _:str(Path.home()),str(q));assert exists(q)or exists(Path(alias)),(name,target)
   links+=1
 delivery={'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':7724,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':5,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False}
 (ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 g={'generator_sha256':sha(__file__),'static_scope':c['static_scope'],'verified_counts':counts,'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in[P+'_source.json',P+'_checks.json']+SCRIPTS},'goal_status':'active',**{k:False for k in FLAGS}}
 for j in range(1,8):g['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+' and OP1-OP8;245 source sites,1378 UNSAT/two abstract SAT including686 predecessor queries;carry/XOR and role-specific numeric maps under shared generator11 encoding;four full ABI boundaries,incoming W9 provenance,832 private cells/800 selected ROM cells and source-bound encoder candidates. Full-word behavior,native ownership/output and daemon-kext pairing remain unknown.'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(g,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
