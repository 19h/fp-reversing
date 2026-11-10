#!/usr/bin/env python3
"""Replay source/role proofs and seal the narrowly owned publication increment."""
import ast,json,re
from pathlib import Path
from recover_inner_write_frontier import ROOT,P,FLAGS
from validate_inner_write_frontier import verify,certificates,alterations,SOLVER
from verify_daemon_reader_record_payloads_publication import read,sha,size,exists
BASE=ROOT.parent
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','core_stack_delta_abi_report.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
SCRIPTS=['recover_'+P+'.py','validate_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
REQUIRED_COUNTS = {'captured_functions_and_stubs': 7, 'captured_instructions': 1255, 'captured_code_bytes': 5020, 'source_fragments': 23, 'inner_store_instructions': 40, 'private_frame_store_instructions': 36, 'inner_call_instructions': 15, 'selected_indirect_call_sites': 14, 'additional_global_root_selections': 1, 'literal_bank_arrays': 10, 'bank_input_cases': 3840, 'inner_indirect_jump_sites': 22, 'jump_diversity_groups': 8, 'original_matching_diversity_entries': 69, 'matching_diversity_entries_outside_inner': 47, 'scanned_const_words': 9230, 'queries_unsat': 49, 'queries_sat': 0, 'source_instruction_instances_translated': 275, 'distinct_source_instruction_sites_translated': 274, 'fresh_bank_cuts': 15, 'fill_symbolic_branch_paths': 24, 'predecessor_queries_replayed': 2, 'rejected_alterations': 6}
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='2d059112e2650f70f2f7d741cbc5555154faea20389f64246e5303ad3b73a930';m=json.loads(read(prior));assert len(m['files'])==7914
 unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert exists(q);digest=sha(q)
  if row['path']in CHANGED:assert digest!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':digest})
  else:assert digest==row['sha256']and size(q)==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==7907 and {r['path']for r in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
 s=json.loads(read(ROOT/(P+'_source.json')));c=json.loads(read(ROOT/(P+'_checks.json')));assert verify(s)and c['all_checks_pass']and c['inner_write_frontier_established']and not c['complete_operation_proved']
 pp,sem=certificates(s);assert c['proofs']==pp and c['semantics']==json.loads(json.dumps(sem))and c['alterations']==alterations(s)
 counts=c['verified_counts'];required=REQUIRED_COUNTS;assert counts==required
 assert c['semantics']['scratch_global_pointer_address']=='0xfffffe000ccc7848' and c['semantics']['private_destination_calls']==7 and c['semantics']['external_copy_calls']==4 and c['semantics']['external_fill_calls']==1 and c['semantics']['zero_fill_footprint_proved_under_valid_nonwrapping_destination'] and not c['semantics']['full_inner_header_preservation_proved'] and not c['semantics']['all_actual_deltas_proved_zero'] and not c['semantics']['nominal_inner_CFG_closed'] and not c['semantics']['native_frame_or_transaction_proved'] and c['semantics']['Mach_port_emissions']==0


 for obj,script in[(s,SCRIPTS[0]),(c,SCRIPTS[1])]:
  assert obj['generator_sha256']==sha(ROOT/script)and all(obj[k]is False for k in FLAGS)
  for n,digest in obj.get('dependencies',{}).items():assert sha(ROOT/n)==digest
 assert sha(SOLVER)==c['solver']['sha256']
 for n in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse(read(ROOT/n),filename=n)
 report=read(BASE/REPORTS[0]);assert report.isascii()and all('| IW'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8))
 links=0
 for name in REPORTS:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',read(BASE/name)):
   target=target.strip('<>')
   if target.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',target):continue
   q=Path(target.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:
    alias=re.sub(r'^/(?:Users|home)/_+(?=/|$)',lambda _:str(Path.home()),str(q));assert exists(q)or exists(Path(alias)),(name,target)
   links+=1
 delivery={'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':7914,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':5,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False}
 (ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 g={'generator_sha256':sha(__file__),'static_scope':c['static_scope'],'verified_counts':counts,'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in[P+'_source.json',P+'_checks.json']+SCRIPTS},'goal_status':'active',**{k:False for k in FLAGS}}
 for j in range(1,8):g['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+' and IW1-IW8;complete40-store/15-call census,14 nominal indirect selections,global staging-pointer join,zero-fill footprint,hardware argument widths and discriminator reuse. Forty-nine UNSAT,274 distinct translated source sites,24 symbolic fill paths and six freshness alterations pass. Full reaching CFG,external ranges,provider effects,actual zero deltas and native transactions remain unproved.'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(g,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
