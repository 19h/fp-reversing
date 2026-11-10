#!/usr/bin/env python3
"""Independent read-only logical hash,JSON,link and ownership audit."""
import json,re
from pathlib import Path
from verify_daemon_reader_record_payloads_publication import read,sha,size,exists,storage,canonical
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent;P='daemon_mode_one_second_phase_handoff'
def main():
 m=json.loads(read(ROOT/'interface_manifest.json'));assert m['goal_status']=='active';seen=set();reports=[];jsons=links=0;unavailable=[];aliases=0
 for row in m['inputs_preserved']:assert size(BASE/row['path'])==row['size_bytes']and sha(BASE/row['path'])==row['sha256']
 for row in m['files']:
  name=row['path'];assert name not in seen;seen.add(name);q=BASE/name;assert exists(q)and size(q)==row['size_bytes']and sha(q)==row['sha256'],name
  if q.parent==ROOT and q.suffix=='.json':json.loads(read(q));jsons+=1
  if q.parent==BASE and q.suffix=='.md':reports.append(q)
 for report in reports:
  for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',read(report)):
   target=target.strip('<>')
   if target.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',target):continue
   name=target.split('#',1)[0];q=Path(name)if name.startswith('/')else report.parent/name
   if not exists(q):
    alias=re.sub(r'^/(?:Users|home)/_+(?=/|$)',lambda _:str(Path.home()),str(q))
    if alias!=str(q)and exists(Path(alias)):aliases+=1
    else:
     sdk=json.loads(read(ROOT/'kernel_root_port_construct_source.json'))['SDK_context'];assert report.name=='kernel_root_port_construct_report.md'and name==sdk['path'];assert sdk['sha256']=='959cc098bb307ccc44a2193a9ff7b8ec8bbcedc335933512cdbe13d3c9088185';unavailable=m['validation']['unavailable_external_primary_references']
   links+=1
 assert len(seen)==7844 and len(reports)==360 and jsons==2460,(len(seen),len(reports),jsons)
 assert m['validation']['reports']==len(reports)and m['validation']['direct_json_files']==jsons and m['validation']['local_markdown_links']==links and len(unavailable)==1
 scripts=['recover_'+P+'.py','validate_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
 owned={'triage_evidence/'+n for n in scripts}|{P+'_report.md'}|{'triage_evidence/'+P+'_'+n+'.json'for n in['source','checks','prior_manifest','delivery','quality_gates']};assert len(owned)==10 and owned<=seen
 prior=json.loads(read(ROOT/(P+'_prior_manifest.json')));assert seen-{r['path']for r in prior['files']}==owned
 c=json.loads(read(ROOT/(P+'_checks.json')));d=json.loads(read(ROOT/(P+'_delivery.json')));g=json.loads(read(ROOT/(P+'_quality_gates.json')))
 assert c['all_checks_pass']and c['second_phase_bank_completion_and_workspace_handoff_proved']and d['all_checks_pass']and not c['complete_operation_proved']
 assert d['prior_artifacts_checked']==7834 and d['prior_artifacts_unchanged']==7827 and len(d['allowed_changes'])==7
 changed={r['path']for r in d['allowed_changes']}
 for row in prior['files']:
  if row['path']not in changed:assert sha(BASE/row['path'])==row['sha256']
 for n,h in g['report_sha256'].items():assert sha(BASE/n)==h
 for n,h in g['evidence_sha256'].items():assert sha(ROOT/n)==h
 assert all(g['QG'+str(j)]['status']=='pass_for_increment'for j in range(1,8))and m['validation'][P+'_increment_checks']==g['verified_counts']and m['validation'][P+'_static_scope']==c['static_scope']
 print(json.dumps({'manifest_sha256':sha(ROOT/'interface_manifest.json'),'artifacts_rehashed':len(seen),'reports_checked':len(reports),'direct_JSON_parsed':jsons,'local_links_checked':links,'runtime_resolved_redacted_external_links':aliases,'unavailable_external_primary_references':len(unavailable),'prior_artifacts_unchanged':7827,'allowed_existing_changes':7,'all_checks_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
