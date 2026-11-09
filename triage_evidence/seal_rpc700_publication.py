#!/usr/bin/env python3
"""Seal bounded publication/environment increment and preservation of the preceding corpus.
O(prior bytes+source+links) time, O(manifest+source) space. No target effects.
"""
import ast,json,re
from pathlib import Path
from recover_rpc700_publication import P,FLAGS,sha,build
from validate_rpc700_publication import check
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
SCRIPTS=['recover_'+P+'.py','validate_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='c7d2c3194770294507c57b62369d9cf61b6c08c6f1c278f3eface9df025e4bc9';m=json.loads(prior.read_text());assert len(m['files'])==6731;unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert q.is_file();h=sha(q)
  if row['path']in CHANGED:assert h!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':h})
  else:assert h==row['sha256']and q.stat().st_size==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==6725 and{e['path']for e in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and(BASE/row['path']).stat().st_size==row['size_bytes']
 assert sha(Path('/Users/___/Downloads/zut/fairplayd.arm64e'))=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 s=json.loads((ROOT/(P+'_source.json')).read_text());o=json.loads((ROOT/(P+'_observations.json')).read_text());c=json.loads((ROOT/(P+'_checks.json')).read_text());assert s==build()and c['source_recapture_match']and c['all_checks_pass'];counts=check(s,o);counts['rejected_alterations']=8;assert c['verified_counts']==counts
 for obj,script in[(s,SCRIPTS[0]),(o,SCRIPTS[0]),(c,SCRIPTS[1])]:
  assert obj['generator_sha256']==sha(ROOT/script)and all(obj[k]is False for k in FLAGS)
 for n,h in c['dependencies'].items():assert sha(ROOT/n)==h
 for e in o['inspection_tools']:assert sha(e['path'])==e['sha256']and Path(e['path']).stat().st_size==e['size_bytes']
 assert sha(Path('/Users/___/Downloads/zut/annotated-strace-rax-user.txt'))=='78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e'
 for name in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse((ROOT/name).read_text(),filename=name)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| RP'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8));links=0
 for name in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   q=Path(raw.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:assert q.exists(),(name,raw)
   links+=1
 delivery={'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':6731,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':5,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'Four-root plist declaration census and frozen read-only native launchd/sysctl observations. Native inspection occurs; no FairPlay request, target execution/emulation or registration mutation. Slot34 occupancy, RPC700 receiver and native target success remain unknown.','generator_sha256':sha(__file__),'verified_counts':counts,'static_scope':c['static_scope'],'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in[P+'_source.json',P+'_observations.json',P+'_checks.json']+SCRIPTS},'goal_status':'active',**{k:False for k in FLAGS}}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+' and RP1-RP8;931 plists,one native-parser fallback,19 declarations/18 indices,three observed jobs/ten endpoints/two host associations,eight rejected alterations; slot34 occupancy and receiver unknown'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
