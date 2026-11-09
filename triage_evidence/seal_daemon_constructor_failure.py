#!/usr/bin/env python3
"""Read-only evidence recapture/solver sealing, then owned delivery ledgers.
O(prior bytes + source bytes + links); solver complexity is separate.
"""
import ast,json,re
from pathlib import Path
from recover_daemon_constructor_failure import ROOT,P,FLAGS,sha,build
from validate_daemon_constructor_failure import verify,proofs,alterations
BASE=ROOT.parent
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','daemon_constructor_inputs_report.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
SCRIPTS=['recover_'+P+'.py','validate_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='e650f2b4035e432490ba8afcacfc9846e97b6d85c6ed1ef41f07253e27f89b30'
 m=json.loads(prior.read_text());assert len(m['files'])==7128;unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert q.is_file();digest=sha(q)
  if row['path']in CHANGED:
   assert digest!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':digest})
  else:assert digest==row['sha256']and q.stat().st_size==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==7121 and {r['path']for r in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and(BASE/row['path']).stat().st_size==row['size_bytes']
 assert sha('/Users/___/Downloads/zut/fairplayd.arm64e')=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 assert sha('/Users/___/Downloads/zut/annotated-strace-rax-user.txt')=='78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e'
 s=json.loads((ROOT/(P+'_source.json')).read_text());c=json.loads((ROOT/(P+'_checks.json')).read_text())
 assert s==build()and verify(s)and c['source_recapture_match']and c['all_checks_pass']
 pp,tr=proofs(s);assert c['proofs']==pp and c['translations']==tr and c['alterations']==alterations(s)
 for obj,script in[(s,SCRIPTS[0]),(c,SCRIPTS[1])]:
  assert obj['generator_sha256']==sha(ROOT/script)and all(obj[k]is False for k in FLAGS)
  for n,digest in obj.get('dependencies',{}).items():assert sha(ROOT/n)==digest
 counts=c['verified_counts'];assert counts=={**s['verified_source_counts'],'component_queries_unsat':14,'translated_instruction_instances':260,'SSA_definitions':239,'rejected_alterations':9}
 assert s['verified_source_counts']=={'fragments':12,'instructions':366,'fragment_bytes':1464,'pointer_records':15,'bank_inputs_checked':512,'prior_ranges':44,'prior_bytes':11220,'liveness_intervals':4,'retained_profiles':12,'node_results_nonnull':60,'buffer_results_nonnull':60,'cleanup_entries_observed':0,'metadata_labels_corrected':1}
 assert '`100fc4130`,`101031ea0`; K+`0x968`/`0x960`'in(BASE/'daemon_constructor_inputs_report.md').read_text()
 assert sha(s['fixup_reference']['command'][0])==s['fixup_reference']['tool_sha256'];assert sha(c['solver']['path'])==c['solver']['sha256']
 for n in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse((ROOT/n).read_text(),filename=n)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| CF'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8))
 links=0
 for n in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/n).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   q=Path(raw.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:assert q.exists(),(n,raw)
   links+=1
 d={'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':7128,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':5,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False}
 (ROOT/(P+'_delivery.json')).write_text(json.dumps(d,indent=2)+'\n')
 quality={'scope':c['static_scope'],'generator_sha256':sha(__file__),'verified_counts':counts,'static_scope':c['static_scope'],'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in[P+'_source.json',P+'_checks.json']+SCRIPTS},'goal_status':'active',**{k:False for k in FLAGS}}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+' and CF1-CF8;12 fragments/366 instructions,15 pointers,512 bank cases,four liveness intervals,14 UNSAT queries,260 translated instances/239 definitions,60 frozen nonnull allocation pairs,zero cleanup observations and nine rejected alterations. Conditional candidate retirement/status/continuation and explicit968 slot erratum; native phase/owners/banks/PAC/fault behavior and daemon-kext pairing remain unknown.'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(quality,indent=2)+'\n')
 print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
