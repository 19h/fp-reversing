#!/usr/bin/env python3
"""Replay source/role proofs and seal the narrowly owned publication increment."""
import ast,json,re
from pathlib import Path
from recover_daemon_mode_one_record_long_prefix import ROOT,P,FLAGS
from validate_daemon_mode_one_record_long_prefix import verify,certificates,alterations,SOLVER
from verify_daemon_reader_record_payloads_publication import read,sha,size,exists
BASE=ROOT.parent
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','daemon_mode_one_record_long_planes_report.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
SCRIPTS=['recover_'+P+'.py','validate_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='c73a280cf576caa11e65be98b69de7cccfd14b02cf9e7704825e59f5fe9965d9';m=json.loads(read(prior));assert len(m['files'])==7643
 unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert exists(q);digest=sha(q)
  if row['path']in CHANGED:assert digest!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':digest})
  else:assert digest==row['sha256']and size(q)==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==7636 and {r['path']for r in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
 s=json.loads(read(ROOT/(P+'_source.json')));c=json.loads(read(ROOT/(P+'_checks.json')));assert verify(s)and c['all_checks_pass']and c['long64_prefix_absorption_and_exit_proved']and not c['complete_operation_proved']
 pp,sem=certificates(s);assert c['proofs']==pp and c['semantics']==json.loads(json.dumps(sem))and c['alterations']==alterations(s)
 counts=c['verified_counts'];assert counts['queries_unsat']==48 and counts['queries_sat']==11 and counts['predecessor_queries_replayed']==23 and counts['source_nonbranch_sites_translated']==5034 and counts['translated_instances']==19194 and counts['iterations']==4 and counts['record_byte_reads']==64 and counts['plane_byte_reads']==128 and counts['plane_byte_stores']==128 and counts['all_byte_addresses_certified']==320 and counts['seed_state_words']==8 and counts['seed_constant_words']==39 and counts['CSEL_arm_equalities']==4 and counts['V_XOR_source_linearity_certificates']==4 and counts['arithmetic_and_codebook_cells_retained']==800 and counts['rejected_alterations']==7 and counts['source_store_effects']==433 and counts['source_read_operations']==730 and counts['read_bytes']==3020 and counts['store_bytes']==1684 and counts['distinct_store_bytes']==528
 assert c['semantics']['original_planes_updated_exactly_once']and c['semantics']['eight_seed_words_preserved_through_all_four_rounds']and not c['semantics']['canonical_mask_identity_proved']and c['semantics']['exit_target']=='0x100b8ed9c'
 for obj,script in[(s,SCRIPTS[0]),(c,SCRIPTS[1])]:
  assert obj['generator_sha256']==sha(ROOT/script)and all(obj[k]is False for k in FLAGS)
  for n,digest in obj.get('dependencies',{}).items():assert sha(ROOT/n)==digest
 assert sha(SOLVER)==c['solver']['sha256']
 for n in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse(read(ROOT/n),filename=n)
 report=read(BASE/REPORTS[0]);assert report.isascii()and all('| PF'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8))
 links=0
 for name in REPORTS:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',read(BASE/name)):
   target=target.strip('<>')
   if target.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',target):continue
   q=Path(target.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:
    alias=re.sub(r'^/(?:Users|home)/_+(?=/|$)',lambda _:str(Path.home()),str(q));assert exists(q)or exists(Path(alias)),(name,target)
   links+=1
 delivery={'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':7643,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':5,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False}
 (ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 g={'generator_sha256':sha(__file__),'static_scope':c['static_scope'],'verified_counts':counts,'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in[P+'_source.json',P+'_checks.json']+SCRIPTS},'goal_status':'active',**{k:False for k in FLAGS}}
 for j in range(1,8):g['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+' and PF1-PF8;5034 unique sites/19194 instances,four exact16-byte iterations,all320 byte addresses,64 U XOR updates,64 address-only V mask functions,source CSEL case equalities,eight retained state words and exact biased64-byte exit;48 UNSAT/11 SAT results including23 predecessor queries. Canonical-mask identity,compact state/algorithm,native reachability,successful output and daemon-kext pairing remain unproved.'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(g,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
