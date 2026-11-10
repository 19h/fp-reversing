#!/usr/bin/env python3
"""Replay source/role proofs and seal the narrowly owned publication increment."""
import ast,json,re
from pathlib import Path
from recover_mixed_data_lifecycle import ROOT,P,FLAGS
from validate_mixed_data_lifecycle import verify,certificates,alterations,SOLVER
from verify_daemon_reader_record_payloads_publication import read,sha,size,exists
BASE=ROOT.parent
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','dma_map_constraints_report.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
SCRIPTS=['recover_'+P+'.py','validate_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
REQUIRED_COUNTS = {'captured_functions': 11, 'captured_instructions': 529, 'captured_code_bytes': 2116, 'source_fragments': 34, 'original_vtable_slots': 9, 'original_initializer_entries': 91, 'matching_initializer_entries': 1, 'kernel_text_words_scanned': 2540432, 'ADRP_page_candidates': 328, 'adjacent_metaclass_materializers': 4, 'registered_class_name_bytes': 29, 'owner_instance_size_bytes': 40, 'constraint_record_size_bytes': 48, 'complete_store_call_censuses': 4, 'queries_unsat': 43, 'queries_sat': 0, 'source_instruction_instances_translated': 144, 'distinct_source_instruction_sites_translated': 144, 'symbolic_PACDA_sites': 2, 'atomic_add_relations': 4, 'owner_explicit_payload_zero_bytes': 24, 'owner_unwritten_padding_bytes': 4, 'predecessor_queries_replayed': 2, 'rejected_alterations': 6}
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='0e458127a6884bfa390837ab892de6210bb45509a0afaf76ff22c3a136a78b9c';m=json.loads(read(prior));assert len(m['files'])==7944
 unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert exists(q);digest=sha(q)
  if row['path']in CHANGED:assert digest!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':digest})
  else:assert digest==row['sha256']and size(q)==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==7937 and {r['path']for r in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
 s=json.loads(read(ROOT/(P+'_source.json')));c=json.loads(read(ROOT/(P+'_checks.json')));assert verify(s)and c['all_checks_pass']and c['MixedData_construction_and_retirement_interfaces_proved']and not c['complete_operation_proved']
 pp,sem=certificates(s);assert c['proofs']==pp and c['semantics']==json.loads(json.dumps(sem))and c['alterations']==alterations(s)
 counts=c['verified_counts'];required=REQUIRED_COUNTS;assert counts==required
 sem=c["semantics"];assert sem["registered_class_name"]=="_IOMemoryDescriptorMixedData" and sem["owner_size_bytes"]==40 and sem["data_record_request_bytes"]==48 and sem["owner_explicit_payload_zero_bytes"]==24 and sem["reference_word_initial_width_bits"]==32 and sem["retain_count_getter_width_bits"]==16 and sem["source_construction_chain_identified"] and sem["source_retirement_operand_pairing_proved"] and not sem["backing_record_48_zeroing_proved"] and not sem["native_allocation_or_reference_balance_proved"] and sem["Mach_port_emissions"]==0


 for obj,script in[(s,SCRIPTS[0]),(c,SCRIPTS[1])]:
  assert obj['generator_sha256']==sha(ROOT/script)and all(obj[k]is False for k in FLAGS)
  for n,digest in obj.get('dependencies',{}).items():assert sha(ROOT/n)==digest
 assert sha(SOLVER)==c['solver']['sha256']
 for n in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse(read(ROOT/n),filename=n)
 report=read(BASE/REPORTS[0]);assert report.isascii()and all('| ML'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8))
 links=0
 for name in REPORTS:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',read(BASE/name)):
   target=target.strip('<>')
   if target.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',target):continue
   q=Path(target.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:
    alias=re.sub(r'^/(?:Users|home)/_+(?=/|$)',lambda _:str(Path.home()),str(q));assert exists(q)or exists(Path(alias)),(name,target)
   links+=1
 delivery={'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':7944,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':5,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False}
 (ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 g={'generator_sha256':sha(__file__),'static_scope':c['static_scope'],'verified_counts':counts,'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in[P+'_source.json',P+'_checks.json']+SCRIPTS},'goal_status':'active',**{k:False for k in FLAGS}}
 for j in range(1,8):g['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+' and ML1-ML8; source class identity, 40-byte owner initialization, creator join and retirement operands. Forty-three UNSAT, 144 translated sites, two symbolic PAC sites, four atomic relations and six freshness alterations pass. Lower call effects, backing zeroing and native ownership remain unproved.'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(g,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
