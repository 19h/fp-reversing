#!/usr/bin/env python3
"""Independent read-only full publication hash/JSON/link and ownership audit.
O(total bytes+links), O(manifest+largest JSON). No target effects.
"""
import hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent;P='kext_context_retirement'
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 path=ROOT/'interface_manifest.json';m=json.loads(path.read_text());assert m['goal_status']=='active';seen=set();reports=[];jsons=links=0
 for row in m['inputs_preserved']:
  q=BASE/row['path'];assert q.stat().st_size==row['size_bytes']and sha(q)==row['sha256']
 for row in m['files']:
  assert row['path']not in seen;seen.add(row['path']);q=BASE/row['path'];assert q.is_file()and q.stat().st_size==row['size_bytes']and sha(q)==row['sha256'],row['path']
  if q.parent==ROOT and q.suffix=='.json':json.loads(q.read_text());jsons+=1
  if q.parent==BASE and q.suffix=='.md':reports.append(q)
 for report in reports:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',report.read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   name=raw.split('#',1)[0];target=Path(name)if name.startswith('/')else report.parent/name;assert target.exists(),(report.name,raw);links+=1
 assert len(m['files'])==5778 and len(reports)==176 and jsons==1463
 assert m['validation']['reports']==len(reports)and m['validation']['direct_json_files']==jsons and m['validation']['local_markdown_links']==links
 names=['recover_'+P+'.py','probe_'+P+'.py','replay_'+P+'.py','validate_'+P+'.py','seal_'+P+'.py','verify_'+P+'_publication.py']
 owned={str(q.relative_to(BASE))for q in ROOT.glob(P+'_*')if q.is_file()}|{'triage_evidence/'+n for n in names}|{P+'_report.md'};assert len(owned)==14 and owned<=seen
 prior=json.loads((ROOT/(P+'_prior_manifest.json')).read_text());assert seen-{r['path']for r in prior['files']}==owned
 checks=json.loads((ROOT/(P+'_checks.json')).read_text());delivery=json.loads((ROOT/(P+'_delivery.json')).read_text());quality=json.loads((ROOT/(P+'_quality_gates.json')).read_text());assert checks['all_checks_pass']and delivery['all_checks_pass']and all(quality['QG'+str(j)]['status']=='pass_for_increment'for j in range(1,8))
 assert delivery['prior_artifacts_checked']==5764 and delivery['prior_artifacts_unchanged']==5758 and len(delivery['allowed_changes'])==6
 changed={r['path']for r in delivery['allowed_changes']}
 for row in prior['files']:
  if row['path']not in changed:assert sha(BASE/row['path'])==row['sha256']
 assert m['validation']['kext_context_retirement_increment_checks']==quality['verified_counts']and m['validation']['kext_context_retirement_A64_totals']==checks['independent_A64_replay']
 for n,h in quality['report_sha256'].items():assert sha(BASE/n)==h
 for n,h in quality['evidence_sha256'].items():assert sha(ROOT/n)==h
 print(json.dumps({'manifest_sha256':sha(path),'artifacts_rehashed':len(seen),'reports_checked':len(reports),'direct_JSON_parsed':jsons,'local_links_checked':links,'prior_artifacts_preserved':5758,'allowed_existing_changes':6,'all_checks_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
