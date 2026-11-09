#!/usr/bin/env python3
"""Owned-path preservation, fresh static/solver recapture and scoped gates."""
import ast,json,re
from pathlib import Path
from recover_daemon_mode_one_scatter import ROOT,P,FLAGS,sha,build
from validate_daemon_mode_one_scatter import verify,certificates,alterations
BASE=ROOT.parent
REPORTS=[P+'_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','daemon_mode_one_source_passes_report.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
SCRIPTS=['recover_'+P+'.py','validate_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
from verify_daemon_mode_one_scatter_publication import sha,read,exists,size

def main():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='9e1d4a434e1a75d5a1df7ac098f45d10494087cc6e75e32aa08e2981d714d135'
 m=json.loads(read(prior));assert len(m['files'])==7388;unchanged=0;changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert exists(q);digest=sha(q)
  if row['path']in CHANGED:assert digest!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':digest})
  else:assert digest==row['sha256']and size(q)==row['size_bytes'],row['path'];unchanged+=1
 assert unchanged==7381 and {r['path']for r in changed}==CHANGED
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
 s=json.loads(read(ROOT/(P+'_source.json')));c=json.loads(read(ROOT/(P+'_checks.json')));assert verify(s)and c['all_checks_pass']and c['dependencies'][P+'_source.json']==sha(ROOT/(P+'_source.json'))
 pp,tr,ctx=certificates(s);assert c['proofs']==pp and c['translations']==tr and c['alterations']==alterations(s) and c['semantics']==json.loads(json.dumps(ctx))
 counts=c['verified_counts'];assert counts==json.loads(read(ROOT/(P+'_checks.json')))['verified_counts']
 assert counts['queries_unsat']==66 and counts['source_instructions']==451 and counts['source_swaps']==15 and counts['finite_address_cases']==145 and counts['transposition_cases']==135
 for obj,script in[(s,SCRIPTS[0]),(c,SCRIPTS[1])]:
  assert obj['generator_sha256']==sha(ROOT/script)and all(obj[k]is False for k in FLAGS)
  for n,digest in obj.get('dependencies',{}).items():assert sha(ROOT/n)==digest
 from validate_daemon_mode_one_scatter import SOLVER
 assert sha(SOLVER)==c['solver']['sha256']and not c['complete_operation_proved']
 for n in SCRIPTS+['validate_rpc502_sidecar_delivery.py']:ast.parse(read(ROOT/n),filename=n)
 report=read(BASE/REPORTS[0]);assert report.isascii()and all('| SC'+str(j)+' |'in report for j in range(1,11))and all('QG'+str(j)+':'in report for j in range(1,8))
 links=0
 for n in REPORTS:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',read(BASE/n)):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   q=Path(raw.split('#',1)[0]);q=q if q.is_absolute()else BASE/q
   if q.name not in[P+'_delivery.json',P+'_quality_gates.json']:assert exists(q),(n,raw)
   links+=1
 d={'preservation_basis':'Decoded logical artifact bytes;canonical JSON may reside in .json.zst after external migration. Seven owned logical-content updates remain explicit;this seal precedes the separately audited mandatory path/history redaction.','generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':7388,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'Python_syntax_checks':5,'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False}
 (ROOT/(P+'_delivery.json')).write_text(json.dumps(d,indent=2)+'\n')
 g={'scope':c['static_scope'],'generator_sha256':sha(__file__),'verified_counts':counts,'static_scope':c['static_scope'],'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in[P+'_source.json',P+'_checks.json']+SCRIPTS},'goal_status':'active',**{k:False for k in FLAGS}}
 for j in range(1,8):g['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+' and SC1-SC10;16-byte scatter initialization and15 forward transpositions.3 ranges/451 instructions,448 modeled sites/527 instances/517 definitions;66 UNSAT,one domain SAT,145 finite address cases,135 transpositions,a coherent-memory theorem and six integrity controls. Short-reciprocal bounds,selector correlation and comparison aliases are explicit. Later consumers/algorithm purpose/complete return/native daemon-kext exchange remain unknown.'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(g,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'allowed_existing_changes':len(changed),'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
def main_redacted():
 prior=ROOT/(P+'_prior_manifest.json');assert sha(prior)=='9e1d4a434e1a75d5a1df7ac098f45d10494087cc6e75e32aa08e2981d714d135'
 m=json.loads(read(prior));assert len(m['files'])==7388
 history=json.loads(read(ROOT/'username_path_scrub_history_rewrite.json'));migration=json.loads(read(ROOT/'username_path_scrub_current_files.json'));audit=json.loads(read(ROOT/'username_path_scrub_history_audit.json'))
 assert history['source_commit_count']==history['destination_commit_count']==77 and audit['all_checks_pass']and not audit['offending_objects']
 mapping={}
 for row in history['changed_records']+migration['changed_logical_files']:
  if 'original_logical_sha256'in row:mapping.setdefault(row['original_logical_sha256'],set()).add(row['sanitized_logical_sha256'])
 owned=CHANGED|{'triage_evidence/daemon_receive_tools.py','triage_evidence/resolve_kernel_collection_interfaces.py'};unchanged=0;redacted=[];changed=[]
 for row in m['files']:
  q=BASE/row['path'];assert exists(q);digest=sha(q)
  if row['path']in owned:assert digest!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':digest})
  elif digest==row['sha256']:assert size(q)==row['size_bytes'];unchanged+=1
  else:assert digest in mapping.get(row['sha256'],set()),row['path'];redacted.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':digest})
 assert len(changed)==9 and len(changed)+len(redacted)+unchanged==7388
 for row in m['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']or sha(BASE/row['path'])in mapping.get(row['sha256'],set())
 s=json.loads(read(ROOT/(P+'_source.json')));c=json.loads(read(ROOT/(P+'_checks.json')));assert verify(s)and c['all_checks_pass']
 pp,tr,ctx=certificates(s);assert c['proofs']==pp and c['translations']==tr and c['semantics']==json.loads(json.dumps(ctx))and c['alterations']==alterations(s)
 counts=c['verified_counts'];assert counts['queries_unsat']==66 and counts['source_instructions']==451 and counts['source_swaps']==15 and counts['finite_address_cases']==145
 for obj,script in[(s,SCRIPTS[0]),(c,SCRIPTS[1])]:
  assert obj['generator_sha256']==sha(ROOT/script)and all(obj[k]is False for k in FLAGS)
  for n,digest in obj.get('dependencies',{}).items():assert sha(ROOT/n)==digest
 from validate_daemon_mode_one_scatter import SOLVER
 assert sha(SOLVER)==c['solver']['sha256']and not c['complete_operation_proved']
 scripts=SCRIPTS+['scrub_username_paths.py','verify_username_paths_history.py','publish_username_path_scrub.py','validate_rpc502_sidecar_delivery.py','daemon_receive_tools.py','resolve_kernel_collection_interfaces.py']
 for n in scripts:ast.parse(read(ROOT/n),filename=n)
 reports=REPORTS+['username_path_scrub_report.md'];report=read(BASE/REPORTS[0]);assert report.isascii()and all('| SC'+str(j)+' |'in report for j in range(1,11))and all('QG'+str(j)+':'in report for j in range(1,8))
 d={'generator_sha256':sha(__file__),'preservation_basis':'Pre-redaction prior logical hashes are matched either exactly,through audited deterministic username-path transformations,or through nine explicit owned report/publisher/reference-locator changes. Historical hash claims retain their original validation epoch.','prior_manifest_sha256':sha(prior),'prior_artifacts_checked':7388,'prior_artifacts_unchanged':unchanged,'prior_artifacts_username_redacted':len(redacted),'redacted_artifacts':redacted,'allowed_changes':changed,'original_inputs_checked':len(m['inputs_preserved']),'Python_syntax_checks':len(scripts),'all_checks_pass':True,'goal_status':'active','full_goal_complete':False}
 (ROOT/(P+'_delivery.json')).write_text(json.dumps(d,indent=2)+'\n')
 g={'generator_sha256':sha(__file__),'static_scope':c['static_scope'],'verified_counts':counts,'report_sha256':{n:sha(BASE/n)for n in reports},'evidence_sha256':{n:sha(ROOT/n)for n in[P+'_source.json',P+'_checks.json']+SCRIPTS},'privacy_history_audit_sha256':sha(ROOT/'username_path_scrub_history_audit.json'),'goal_status':'active',**{k:False for k in FLAGS}}
 for j in range(1,8):g['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+' and SC1-SC10;fresh post-redaction source recapture,66 UNSAT queries,145 address cases,135 transpositions and coherent-memory theorem. Prior metadata changes are bounded by the separately audited username-path rewrite;older scientific checks are not all replayed.'}
 (ROOT/(P+'_quality_gates.json')).write_text(json.dumps(g,indent=2)+'\n');print(json.dumps({'prior_artifacts_unchanged':unchanged,'prior_artifacts_username_redacted':len(redacted),'allowed_existing_changes':len(changed),'all_scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':
 if exists(ROOT/'username_path_scrub_history_rewrite.json'):main_redacted()
 else:main()

