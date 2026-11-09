#!/usr/bin/env python3
"""Seal conditional A70 terminal reporting. O(prior bytes+capture+links).
No target execution; previous owned evidence and original inputs preserved.
"""
import ast,json,re
from pathlib import Path
from recover_daemon_xpc_error_outputs import ROOT,P,FLAGS,sha,build
from validate_daemon_xpc_error_outputs import verify,sdk_checks,proofs,alterations,models
BASE=ROOT.parent
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md',
         'foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
SCRIPTS=['recover_'+P+'.py','validate_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='b761e93a26e2e1955250314753be6c0ce5a5b45488a5884bf216ef1add298dd0'
 m=json.loads(prior.read_text());assert len(m['files'])==7037;unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert q.is_file();digest=sha(q)
  if row['path']in CHANGED:
   assert digest!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':digest})
  else:assert digest==row['sha256']and q.stat().st_size==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==7031 and {r['path']for r in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and(BASE/row['path']).stat().st_size==row['size_bytes']
 assert sha('/Users/___/Downloads/zut/fairplayd.arm64e')=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 assert sha('/Users/___/Downloads/zut/annotated-strace-rax-user.txt')=='78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e'
 s=json.loads((ROOT/(P+'_source.json')).read_text());c=json.loads((ROOT/(P+'_checks.json')).read_text())
 assert s==build()and verify(s)==c['instruction_assertions']and c['source_recapture_match']and c['all_checks_pass']
 assert c['SDK_checks']==sdk_checks()and c['proofs']==proofs()and c['alterations']==alterations(s)and c['models']==models()
 for obj,script in[(s,SCRIPTS[0]),(c,SCRIPTS[1])]:
  assert obj['generator_sha256']==sha(ROOT/script)and all(obj[k]is False for k in FLAGS)
  for n,digest in obj.get('dependencies',{}).items():assert sha(ROOT/n)==digest
 counts=c['verified_counts'];assert counts=={**s['verified_source_counts'],'instruction_assertions':81,'SDK_assertions':11,'SDK_compilations':1,'component_queries_unsat':5,'terminal_component_cases':36,'rejected_evidence_alterations':8}
 assert s['verified_source_counts']=={'fragments':14,'instructions':239,'fragment_bytes':956,'branch_bindings':3,'selected_pointer_records':6,'fixup_catalog_memberships_compared':61737,'prior_source_ranges_checked':35,'prior_source_bytes_checked':6044,'historical_cases_inspected':80,'historical_boundaries_checked':64,'historical_instruction_visits_recaptured':291680,'historical_unique_instructions_recaptured':2689}
 for row in s['inspection_tools']+s['SDK_headers']+[c['solver']]:assert sha(row['path'])==row['sha256']
 assert sha(c['SDK_checks']['compiler_path'])==c['SDK_checks']['compiler_sha256']
 for name in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse((ROOT/name).read_text(),filename=name)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| EO'+str(j)+' |'in report for j in range(1,8))and all('QG'+str(j)+':'in report for j in range(1,8))
 links=0
 for name in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   q=Path(raw.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:assert q.exists(),(name,raw)
   links+=1
 d={'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':7037,
    'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),
    'Python_syntax_checks':5,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False}
 (ROOT/(P+'_delivery.json')).write_text(json.dumps(d,indent=2)+'\n')
 quality={'scope':c['static_scope'],'generator_sha256':sha(__file__),'verified_counts':counts,'static_scope':c['static_scope'],
    'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in[P+'_source.json',P+'_checks.json']+SCRIPTS},
    'goal_status':'active',**{k:False for k in FLAGS}}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+' and EO1-EO7;14 ranges/239 instructions,81 assertions,11 compile-only assertions,five component proofs,36 cases,64 recaptured historical boundaries,eight altered controls. Delta zero/full budget history, success output writers, continuous/native XPC reachability, return/PAC/ownership and daemon-kext exchange remain unproved.'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(quality,indent=2)+'\n')
 print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
