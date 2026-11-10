#!/usr/bin/env python3
"""Replay source/role proofs and seal the narrowly owned publication increment."""
import ast,json,re
from pathlib import Path
from recover_kext_query_getter_values import ROOT,P,FLAGS
from validate_kext_query_getter_values import verify,certificates,alterations,SOLVER
from verify_daemon_reader_record_payloads_publication import read,sha,size,exists
BASE=ROOT.parent
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','daemon_iokit_census_report.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
SCRIPTS=['recover_'+P+'.py','validate_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
REQUIRED_COUNTS = {'kext_source_ranges': 9, 'kext_source_instructions': 453, 'kext_source_bytes': 1812, 'exhaustive_bank_rules': 12, 'exhaustive_bank_inputs': 3072, 'literal_bank_bytes': 2048, 'literal_pool_records': 8, 'saved_IDA_functions_matched': 5, 'saved_IDA_bytes_matched': 1620, 'daemon_ranges_recaptured': 21, 'daemon_bytes_recaptured': 2904, 'queries_unsat': 38, 'queries_sat': 2, 'predecessor_queries_replayed': 9, 'source_nonbranch_instruction_instances_translated': 354, 'fresh_source_bank_cuts': 12, 'rejected_alterations': 8}
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='ede51d4a7684c83f8a0927bf59f997a4f82f621efe51db0c3ba4359ceedaac81';m=json.loads(read(prior));assert len(m['files'])==7864
 unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert exists(q);digest=sha(q)
  if row['path']in CHANGED:assert digest!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':digest})
  else:assert digest==row['sha256']and size(q)==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==7857 and {r['path']for r in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
 s=json.loads(read(ROOT/(P+'_source.json')));c=json.loads(read(ROOT/(P+'_checks.json')));assert verify(s)and c['all_checks_pass']and c['constant_query_getter_values_and_conditional_daemon_cache_proved']and not c['complete_operation_proved']
 pp,sem=certificates(s);assert c['proofs']==pp and c['semantics']==json.loads(json.dumps(sem))and c['alterations']==alterations(s)
 counts=c['verified_counts'];required=REQUIRED_COUNTS;assert counts==required
 assert c['semantics']['version_u32']=='0x4c0b0000' and c['semantics']['capability_u32']=='0x1f8' and c['semantics']['all12_bank_cuts_freshly_source_proved'] and len(c['semantics']['four_guarded_query_outcomes'])==4 and not c['semantics']['whole_native_transaction_observed'] and not c['semantics']['live_daemon_kext_build_pairing_proved'] and c['semantics']['Mach_port_emissions']==0


 for obj,script in[(s,SCRIPTS[0]),(c,SCRIPTS[1])]:
  assert obj['generator_sha256']==sha(ROOT/script)and all(obj[k]is False for k in FLAGS)
  for n,digest in obj.get('dependencies',{}).items():assert sha(ROOT/n)==digest
 assert sha(SOLVER)==c['solver']['sha256']
 for n in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse(read(ROOT/n),filename=n)
 report=read(BASE/REPORTS[0]);assert report.isascii()and all('| KG'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8))
 links=0
 for name in REPORTS:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',read(BASE/name)):
   target=target.strip('<>')
   if target.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',target):continue
   q=Path(target.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:
    alias=re.sub(r'^/(?:Users|home)/_+(?=/|$)',lambda _:str(Path.home()),str(q));assert exists(q)or exists(Path(alias)),(name,target)
   links+=1
 delivery={'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':7864,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':5,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False}
 (ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 g={'generator_sha256':sha(__file__),'static_scope':c['static_scope'],'verified_counts':counts,'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in[P+'_source.json',P+'_checks.json']+SCRIPTS},'goal_status':'active',**{k:False for k in FLAGS}}
 for j in range(1,8):g['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+' and KG1-KG8;nine kext ranges453 instructions,354 translated instances,twelve original bank equalities,three exact call targets,two constant leaves and record-result joins. Thirty-eight UNSAT,two abstract SAT,nine predecessor replays and eight rejected alterations pass. Version4c0b0000/capability1f8 specialize the daemon cache and four query outcomes. Saved read-only IDA input/function hashes match;native connection/provider/build pairing,PAC,ordinary returns and capability-bit meanings remain separate.'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(g,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
