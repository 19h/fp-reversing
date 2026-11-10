#!/usr/bin/env python3
"""Replay source/role proofs and seal the narrowly owned publication increment."""
import ast,json,re
from pathlib import Path
from recover_versioned_request_abi import ROOT,P,FLAGS
from validate_versioned_request_abi import verify,certificates,alterations,SOLVER
from verify_daemon_reader_record_payloads_publication import read,sha,size,exists
BASE=ROOT.parent
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','kext_query_getter_values_report.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
SCRIPTS=['recover_'+P+'.py','validate_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
REQUIRED_COUNTS = {'daemon_ranges': 18, 'daemon_range_instruction_instances': 1005, 'daemon_range_bytes': 4020, 'kext_ranges': 2, 'kext_instructions': 60, 'kext_bytes': 240, 'census_instruction_words': 3712490, 'census_slot_loads': 368, 'census_direct_field14_hits': 2, 'literal_bank_arrays': 8, 'bank_byte_inputs': 1024, 'literal_pool_roots': 6, 'branch_pointer_records': 10, 'selector_record_bytes': 48, 'loop_image_bytes': 16, 'queries_unsat': 42, 'queries_sat': 3, 'source_nonbranch_instruction_instances_translated': 370, 'source_exact_bank_cuts': 1, 'prefix_iterations': 16, 'rejected_alterations': 8}
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='d980e7624f589181c4fb3b30e5040c40097a738eaa6ebc3d10037b44e02f9cfe';m=json.loads(read(prior));assert len(m['files'])==7874
 unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert exists(q);digest=sha(q)
  if row['path']in CHANGED:assert digest!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':digest})
  else:assert digest==row['sha256']and size(q)==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==7867 and {r['path']for r in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
 s=json.loads(read(ROOT/(P+'_source.json')));c=json.loads(read(ROOT/(P+'_checks.json')));assert verify(s)and c['all_checks_pass']and c['capability_gates_and_selector21_provider_ABI_proved']and not c['complete_operation_proved']
 pp,sem=certificates(s);assert c['proofs']==pp and c['semantics']==json.loads(json.dumps(sem))and c['alterations']==alterations(s)
 counts=c['verified_counts'];required=REQUIRED_COUNTS;assert counts==required
 assert c['semantics']['daemon_selector']==21 and c['semantics']['kernel_output_count_offset']==544 and c['semantics']['kernel_embedded_provider_status_offset']==548 and c['semantics']['core_argument_count']==10 and not c['semantics']['decompiler_fixed512_output_claim_corroborated'] and not c['semantics']['native_connection_provider_build_pairing_proved'] and not c['semantics']['552_build_buffer_identity_with_API_buffer_proved'] and c['semantics']['Mach_port_emissions']==0


 for obj,script in[(s,SCRIPTS[0]),(c,SCRIPTS[1])]:
  assert obj['generator_sha256']==sha(ROOT/script)and all(obj[k]is False for k in FLAGS)
  for n,digest in obj.get('dependencies',{}).items():assert sha(ROOT/n)==digest
 assert sha(SOLVER)==c['solver']['sha256']
 for n in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse(read(ROOT/n),filename=n)
 report=read(BASE/REPORTS[0]);assert report.isascii()and all('| VA'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8))
 links=0
 for name in REPORTS:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',read(BASE/name)):
   target=target.strip('<>')
   if target.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',target):continue
   q=Path(target.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:
    alias=re.sub(r'^/(?:Users|home)/_+(?=/|$)',lambda _:str(Path.home()),str(q));assert exists(q)or exists(Path(alias)),(name,target)
   links+=1
 delivery={'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':7874,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':5,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False}
 (ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 g={'generator_sha256':sha(__file__),'static_scope':c['static_scope'],'verified_counts':counts,'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in[P+'_source.json',P+'_checks.json']+SCRIPTS},'goal_status':'active',**{k:False for k in FLAGS}}
 for j in range(1,8):g['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+' and VA1-VA8;two capability readers,16-byte descending prefix,fixed16-byte field,private-call delta,six daemon arguments,eleven provider arguments and ten core arguments. Forty-two UNSAT,three abstract SAT,370 translated instances and eight freshness alterations pass. The kernel mutable-count source corrects the fixed512 decompilation claim. Same-frame lifetime,construction/API-buffer identity,wire-mode identity,extended preparation,provider capacity compliance and native pairing remain unproved.'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(g,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
