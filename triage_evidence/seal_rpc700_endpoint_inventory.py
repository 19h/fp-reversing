#!/usr/bin/env python3
"""Seal static spawn descriptor interface reporting. O(prior bytes+capture+links).
No native target effects. Existing inputs and owned prior evidence preserved.
"""
import ast,json,re
from pathlib import Path
from recover_rpc700_endpoint_inventory import ROOT,P,FLAGS,sha,build
from validate_rpc700_endpoint_inventory import verify,sdk_checks,proofs,alterations,verify_observation,COUNTS
BASE=ROOT.parent
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md',
         'foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
SCRIPTS=['recover_'+P+'.py','validate_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='93e2f846760d776c0676da0bc84aa1cb69a459958ab78baa7c8ef82ebd07a5bc'
 m=json.loads(prior.read_text());assert len(m['files'])==6925;unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert q.is_file();digest=sha(q)
  if row['path']in CHANGED:
   assert digest!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':digest})
  else:assert digest==row['sha256']and q.stat().st_size==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==6919 and{r['path']for r in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and(BASE/row['path']).stat().st_size==row['size_bytes']
 assert sha('/Users/___/Downloads/zut/fairplayd.arm64e')=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 assert sha('/Users/___/Downloads/zut/annotated-strace-rax-user.txt')=='78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e'
 s=json.loads((ROOT/(P+'_source.json')).read_text());c=json.loads((ROOT/(P+'_checks.json')).read_text());o=json.loads((ROOT/(P+'_observations.json')).read_text())
 assert s==build()and verify(s)==c['instruction_assertions']and c['source_recapture_match']and c['all_checks_pass']
 assert c['SDK_checks']==sdk_checks()and c['proofs']==proofs()and c['alterations']==alterations(s,o)and c['observation_checks']==verify_observation(o)
 for obj,script in[(s,SCRIPTS[0]),(c,SCRIPTS[1])]:
  assert obj['generator_sha256']==sha(ROOT/script)and all(obj[k]is False for k in FLAGS)
  for n,digest in obj.get('dependencies',{}).items():assert sha(ROOT/n)==digest
 counts=c['verified_counts'];assert counts=={**COUNTS,**s['observation_counts'],'instruction_assertions':14,'SDK_assertions':11,'SDK_compilations':1,'scalar_queries_unsat':1,'rejected_evidence_alterations':8}
 assert c['native_inspection_executed']and c['native_launchd_interrogation_executed']
 for row in s['inspection_tools']+s['SDK_headers']+s['cache_files']+[c['solver']]:assert sha(row['path'])==row['sha256']
 assert sha(c['SDK_checks']['compiler_path'])==c['SDK_checks']['compiler_sha256']
 for name in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse((ROOT/name).read_text(),filename=name)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| EI'+str(j)+' |'in report for j in range(1,8))and all('QG'+str(j)+':'in report for j in range(1,8))
 links=0
 for name in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   q=Path(raw.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:assert q.exists(),(name,raw)
   links+=1
 d={'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':6925,
    'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),
    'Python_syntax_checks':5,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False}
 (ROOT/(P+'_delivery.json')).write_text(json.dumps(d,indent=2)+'\n')
 quality={'scope':c['static_scope'],
    'generator_sha256':sha(__file__),'verified_counts':counts,'static_scope':c['static_scope'],'native_observation_scope':c['native_observation_scope'],'native_inspection_executed':True,'native_launchd_interrogation_executed':True,
    'report_sha256':{n:sha(BASE/n)for n in REPORTS},
    'evidence_sha256':{n:sha(ROOT/n)for n in[P+'_source.json',P+'_checks.json',P+'_observations.json']+SCRIPTS},
    'goal_status':'active',**{k:False for k in FLAGS}}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+' and EI1-EI7;4113 image headers,30802349 v5 entries,65480381 branch words,7 complete bodies/513 instructions,14 instruction assertions,11 SDK assertions,one branch-domain proof,8 rejected alterations; frozen880 job queries/2038 endpoints/18 printed host associations; native slot34 and RPC700 receiver unknown'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(quality,indent=2)+'\n')
 print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
