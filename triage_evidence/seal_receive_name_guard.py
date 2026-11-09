#!/usr/bin/env python3
"""Seal receive-name/guard increment; O(prior bytes+capture+links), no target effects."""
import ast,json,re
from pathlib import Path
from recover_receive_name_guard import ROOT,P,FLAGS,sha,build
from validate_receive_name_guard import verify,sdk_checks,proofs,guard_bank
BASE=ROOT.parent
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
SCRIPTS=['recover_'+P+'.py','validate_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='895d5646096b004108e6a27414798400317185a420c0df254cba8e139ae5add0';m=json.loads(prior.read_text());assert len(m['files'])==6823;unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert q.is_file();digest=sha(q)
  if row['path']in CHANGED:assert digest!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':digest})
  else:assert digest==row['sha256']and q.stat().st_size==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==6817 and{r['path']for r in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and(BASE/row['path']).stat().st_size==row['size_bytes']
 assert sha(Path('/Users/___/Downloads/zut/fairplayd.arm64e'))=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 assert sha(Path('/Users/___/Downloads/zut/annotated-strace-rax-user.txt'))=='78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e'
 s=json.loads((ROOT/(P+'_source.json')).read_text());c=json.loads((ROOT/(P+'_checks.json')).read_text());assert s==build();records=verify(s);assert records==c['instruction_assertions']and c['source_recapture_match']and c['all_checks_pass']and c['SDK_checks']==sdk_checks()and c['proofs']==proofs()and c['guard_scalar_bank']==guard_bank()
 for obj,script in[(s,SCRIPTS[0]),(c,SCRIPTS[1])]:
  assert obj['generator_sha256']==sha(ROOT/script)and all(obj[k]is False for k in FLAGS)
  for n,digest in obj.get('dependencies',{}).items():assert sha(ROOT/n)==digest
 counts=c['verified_counts'];assert counts=={**s['verified_source_counts'],'instruction_assertions':119,'SDK_assertions':24,'SDK_compilations':1,'scalar_queries_unsat':4,'finite_guard_inputs_checked':384,'rejected_evidence_alterations':6}
 for row in s['inspection_tools']+s['SDK_headers']+s['cache_files']+[c['solver']]:assert sha(row['path'])==row['sha256']
 assert sha(c['SDK_checks']['compiler_path'])==c['SDK_checks']['compiler_sha256']
 for name in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse((ROOT/name).read_text(),filename=name)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| NG'+str(j)+' |'in report for j in range(1,7))and all('QG'+str(j)+':'in report for j in range(1,8));links=0
 for name in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   q=Path(raw.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:assert q.exists(),(name,raw)
   links+=1
 delivery={'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':6823,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':5,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 evidence=[P+'_source.json',P+'_checks.json']+SCRIPTS
 quality={'scope':'Selected original name reuse, service-label context preservation, receiver state transition and guard restoration/assertion, including unguard trap42/MIG3234 and assertion MIG3242. Native name/object/label epoch, metadata admission, guard state, ownership and hardware ISA/PAC excluded.','generator_sha256':sha(__file__),'verified_counts':counts,'static_scope':c['static_scope'],'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in evidence},'goal_status':'active',**{k:False for k in FLAGS}}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+' and NG1-NG6;36 bodies/4186 instructions/16744 B,119 instruction assertions,4894 independent fixup comparisons,24 SDK assertions,four scalar proofs,384 finite guard inputs,six rejected evidence alterations; native name/label epoch,metadata admission,guard state and ownership unknown'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
