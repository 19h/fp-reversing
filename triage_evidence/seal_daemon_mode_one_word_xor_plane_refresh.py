#!/usr/bin/env python3
"""Replay source/role proofs and seal the narrowly owned publication increment."""
import ast,json,re
from pathlib import Path
from recover_daemon_mode_one_word_xor_plane_refresh import ROOT,P,FLAGS
from validate_daemon_mode_one_word_xor_plane_refresh import verify,certificates,alterations,SOLVER
from verify_daemon_reader_record_payloads_publication import read,sha,size,exists
BASE=ROOT.parent
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','daemon_mode_one_parity_state_adapters_report.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
SCRIPTS=['recover_'+P+'.py','validate_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='000cbf2e232bb89b5efae9e5b0751e0d75accee5ae606498f24b0af35258b1af';m=json.loads(read(prior));assert len(m['files'])==7754
 unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert exists(q);digest=sha(q)
  if row['path']in CHANGED:assert digest!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':digest})
  else:assert digest==row['sha256']and size(q)==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==7747 and {r['path']for r in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
 s=json.loads(read(ROOT/(P+'_source.json')));c=json.loads(read(ROOT/(P+'_checks.json')));assert verify(s)and c['all_checks_pass']and c['compact_word_XOR_plane_refresh_and_secondary_root_ABI_proved']and not c['complete_operation_proved']
 pp,sem=certificates(s);assert c['proofs']==pp and c['semantics']==json.loads(json.dumps(sem))and c['alterations']==alterations(s)
 counts=c['verified_counts'];required={'source_ranges': 3, 'source_instructions': 2401, 'source_bytes': 9604, 'pointer_records': 4, 'branch_bindings': 4, 'SP_writes': 0, 'UMULL_decodes_checked': 0, 'bitfield_decodes_checked': 2, 'register_shift_decodes_checked': 2, 'comparison_role_corrections': 0, 'prior_ranges_recaptured': 10, 'prior_bytes_recaptured': 7832, 'queries_unsat': 48, 'queries_sat': 6, 'predecessor_queries_replayed': 39, 'source_nonbranch_sites_translated': 2398, 'fresh_caller_nonbranch_sites': 217, 'word_bytes_updated': 4, 'word_computed_read_normalizations': 1, 'refresh_plane_bytes': 128, 'refresh_literal_byte_stores': 124, 'refresh_computed_store_normalizations': 4, 'refresh_scalar_u32_stores': 2, 'proved_address_source_cuts': 2, 'address_source_slice_lemmas': 2, 'abstract_refresh_valuations': 2, 'source_load_operations': 16, 'source_store_operations': 137, 'source_read_bytes': 76, 'source_store_bytes': 152, 'source_distinct_bytes_written_union': 148, 'private_byte_store_effects': 132, 'scalar_u32_store_effects': 5, 'saved_secondary_root_consumptions': 1, 'materialized_divisor': 962, 'arithmetic_cells_written': 0, 'rejected_alterations': 8};assert all(counts[k]==v for k,v in required.items())
 assert c['semantics']['plane_byte_writes']==128 and c['semantics']['refresh_source_value_cuts_per_model']==2 and c['semantics']['seed_target']=='0x100d524a8'and not c['semantics']['refresh_word_and_seed_write_arithmetic_cells']and c['semantics']['Mach_port_emissions']==0

 for obj,script in[(s,SCRIPTS[0]),(c,SCRIPTS[1])]:
  assert obj['generator_sha256']==sha(ROOT/script)and all(obj[k]is False for k in FLAGS)
  for n,digest in obj.get('dependencies',{}).items():assert sha(ROOT/n)==digest
 assert sha(SOLVER)==c['solver']['sha256']
 for n in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse(read(ROOT/n),filename=n)
 report=read(BASE/REPORTS[0]);assert report.isascii()and all('| WR'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8))
 links=0
 for name in REPORTS:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',read(BASE/name)):
   target=target.strip('<>')
   if target.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',target):continue
   q=Path(target.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:
    alias=re.sub(r'^/(?:Users|home)/_+(?=/|$)',lambda _:str(Path.home()),str(q));assert exists(q)or exists(Path(alias)),(name,target)
   links+=1
 delivery={'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':7754,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':5,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False}
 (ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 g={'generator_sha256':sha(__file__),'static_scope':c['static_scope'],'verified_counts':counts,'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in[P+'_source.json',P+'_checks.json']+SCRIPTS},'goal_status':'active',**{k:False for k in FLAGS}}
 for j in range(1,8):g['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+' and WR1-WR8;2398 source sites,48 UNSAT/six abstract SAT,including39 predecessor replays;compact four-cell word XOR,128-byte refresh with two proved address cuts,and saved-secondary-root entry with divisor962. Earlier table-validity uncertainty,native ownership/output,algorithm identity and daemon-kext pairing remain explicit.'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(g,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
