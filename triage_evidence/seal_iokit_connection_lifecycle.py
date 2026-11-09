#!/usr/bin/env python3
"""Seal static IOKit connection lifecycle increment and preservation of the preceding corpus.
O(prior bytes+source+links) time, O(manifest+source) space. No target effects.
"""
import ast,json,re
from pathlib import Path
from recover_iokit_connection_lifecycle import P,FLAGS,sha,build
from validate_iokit_connection_lifecycle import verify
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
SCRIPTS=['recover_'+P+'.py','validate_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='122e095b71bfa198e156ca4d173ebfd3a25b139dd5dbc9de5ee16676d1d501f3';m=json.loads(prior.read_text());assert len(m['files'])==6691;unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert q.is_file();h=sha(q)
  if row['path']in CHANGED:assert h!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':h})
  else:assert h==row['sha256']and q.stat().st_size==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==6685 and{e['path']for e in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and(BASE/row['path']).stat().st_size==row['size_bytes']
 assert sha(Path('/Users/___/Downloads/zut/fairplayd.arm64e'))=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
 s=json.loads((ROOT/(P+'_source.json')).read_text());c=json.loads((ROOT/(P+'_checks.json')).read_text());assert s==build()and verify(s)==79 and c['source_recapture_match']and c['all_checks_pass']
 for obj,script in[(s,SCRIPTS[0]),(c,SCRIPTS[1])]:
  assert obj['generator_sha256']==sha(ROOT/script)and all(obj[k]is False for k in FLAGS)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h
 counts=c['verified_counts'];assert counts=={'kernel_functions': 17, 'kext_functions': 3, 'cache_functions': 2, 'original_instructions': 2347, 'original_function_bytes': 9388, 'exact_instruction_assertions': 79, 'chained_bindings': 10, 'MIG_records': 3, 'selector_table_slots': 40, 'admitted_selectors': 17, 'SDK_assertions': 10, 'SDK_headers': 4, 'rejected_static_alterations': 10, 'flag_bytes': 256, 'cache_stub_bindings': 2}
 for e in c['SDK_headers']+s['cache_files']:assert sha(e['path'])==e['sha256']and Path(e['path']).stat().st_size==e['size_bytes']
 for name in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse((ROOT/name).read_text(),filename=name)
 report=(BASE/REPORTS[0]).read_text();assert report.isascii()and all('| CL'+str(j)+' |'in report for j in range(1,9))and all('QG'+str(j)+':'in report for j in range(1,8));links=0
 for name in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   q=Path(raw.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:assert q.exists(),(name,raw)
   links+=1
 delivery={'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':6691,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':5,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/(P+'_delivery.json')).write_text(json.dumps(delivery,indent=2)+'\n')
 quality={'scope':'Original static connection export/import, service/IORPC type distinction, MIG2816/2862/2865, guarded inherited legacy dispatch, sparse selector table, close termination request and public name deallocation. No target execution/emulation or new runtime observations. Native connection identity, ownership retirement, policy/argument details and successful FairPlay processing remain unknown.','generator_sha256':sha(__file__),'verified_counts':counts,'static_scope':c['static_scope'],'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in[P+'_source.json',P+'_checks.json']+SCRIPTS},'goal_status':'active',**{k:False for k in FLAGS}}
 for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+' and CL1-CL8;2347 original instructions/9388 B,79 assertions,ten vtable bindings,three MIG records,forty selector slots,seventeen admitted selectors,ten SDK assertions/four header hashes,256 flag bytes,ten rejected alterations; native lifetime unknown'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
