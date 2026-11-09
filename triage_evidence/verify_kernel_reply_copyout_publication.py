#!/usr/bin/env python3
"""Independent read-only full artifact hash, JSON, link and publication audit.
O(total bytes+links) time; O(manifest+largest JSON) space. No target effects.
"""
import hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 path=ROOT/'interface_manifest.json';m=json.loads(path.read_text());assert m['goal_status']=='active';seen=set();reports=[];jsons=links=0
 for row in m['inputs_preserved']:
  p=BASE/row['path'];assert p.stat().st_size==row['size_bytes']and sha(p)==row['sha256']
 for row in m['files']:
  assert row['path']not in seen;seen.add(row['path']);p=BASE/row['path'];assert p.is_file()and p.stat().st_size==row['size_bytes']and sha(p)==row['sha256'],row['path']
  if p.parent==ROOT and p.suffix=='.json':json.loads(p.read_text());jsons+=1
  if p.parent==BASE and p.suffix=='.md':reports.append(p)
 for p in reports:
  for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',p.read_text()):
   raw=raw.strip('<>')
   if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
   n=raw.split('#',1)[0];target=Path(n)if n.startswith('/')else p.parent/n;assert target.exists(),(p.name,raw);links+=1
 assert len(m['files'])==5675 and len(reports)==169 and jsons==1421
 assert m['validation']['reports']==len(reports)and m['validation']['direct_json_files']==jsons and m['validation']['local_markdown_links']==links
 names=['recover_kernel_reply_copyout.py','probe_kernel_reply_copyout.py','validate_kernel_reply_copyout.py','replay_kernel_reply_copyout.py','seal_kernel_reply_copyout.py','verify_kernel_reply_copyout_publication.py'];owned={str(p.relative_to(BASE))for p in ROOT.glob('kernel_reply_copyout_*')if p.is_file()}|{'triage_evidence/'+n for n in names}|{'kernel_reply_copyout_report.md'};assert len(owned)==13 and owned<=seen
 prior=json.loads((ROOT/'kernel_reply_copyout_prior_manifest.json').read_text());assert seen-{r['path']for r in prior['files']}==owned
 checks=json.loads((ROOT/'kernel_reply_copyout_checks.json').read_text());delivery=json.loads((ROOT/'kernel_reply_copyout_delivery.json').read_text());quality=json.loads((ROOT/'kernel_reply_copyout_quality_gates.json').read_text());assert checks['all_checks_pass']and delivery['all_checks_pass']and all(quality['QG'+str(j)]['status']=='pass_for_increment'for j in range(1,8));assert delivery['prior_artifacts_checked']==5662 and delivery['prior_artifacts_unchanged']==5656 and len(delivery['allowed_changes'])==6
 for r in prior['files']:
  if r['path']not in {x['path']for x in delivery['allowed_changes']}:assert sha(BASE/r['path'])==r['sha256']
 assert m['validation']['kernel_reply_copyout_increment_checks']==quality['verified_counts']and m['validation']['kernel_reply_copyout_A64_totals']==checks['independent_A64_replay']
 for n,h in quality['report_sha256'].items():assert sha(BASE/n)==h
 for n,h in quality['evidence_sha256'].items():assert sha(ROOT/n)==h
 print(json.dumps({'manifest_sha256':sha(path),'artifacts_rehashed':len(seen),'reports_checked':len(reports),'direct_JSON_parsed':jsons,'local_links_checked':links,'prior_artifacts_preserved':5656,'allowed_existing_changes':6,'all_checks_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
