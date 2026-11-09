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
 assert len(m['files'])==5688 and len(reports)==170 and jsons==1427
 assert m['validation']['reports']==len(reports)and m['validation']['direct_json_files']==jsons and m['validation']['local_markdown_links']==links
 names=['recover_rpc502_reply_copyin.py','probe_rpc502_reply_copyin.py','validate_rpc502_reply_copyin.py','replay_rpc502_reply_copyin.py','seal_rpc502_reply_copyin.py','verify_rpc502_reply_copyin_publication.py'];owned={str(p.relative_to(BASE))for p in ROOT.glob('rpc502_reply_copyin_*')if p.is_file()}|{'triage_evidence/'+n for n in names}|{'rpc502_reply_copyin_report.md'};assert len(owned)==13 and owned<=seen
 prior=json.loads((ROOT/'rpc502_reply_copyin_prior_manifest.json').read_text());assert seen-{r['path']for r in prior['files']}==owned
 checks=json.loads((ROOT/'rpc502_reply_copyin_checks.json').read_text());delivery=json.loads((ROOT/'rpc502_reply_copyin_delivery.json').read_text());quality=json.loads((ROOT/'rpc502_reply_copyin_quality_gates.json').read_text());assert checks['all_checks_pass']and delivery['all_checks_pass']and all(quality['QG'+str(j)]['status']=='pass_for_increment'for j in range(1,8));assert delivery['prior_artifacts_checked']==5675 and delivery['prior_artifacts_unchanged']==5669 and len(delivery['allowed_changes'])==6
 for r in prior['files']:
  if r['path']not in {x['path']for x in delivery['allowed_changes']}:assert sha(BASE/r['path'])==r['sha256']
 assert m['validation']['rpc502_reply_copyin_increment_checks']==quality['verified_counts']and m['validation']['rpc502_reply_copyin_A64_totals']==checks['independent_A64_replay']
 for n,h in quality['report_sha256'].items():assert sha(BASE/n)==h
 for n,h in quality['evidence_sha256'].items():assert sha(ROOT/n)==h
 print(json.dumps({'manifest_sha256':sha(path),'artifacts_rehashed':len(seen),'reports_checked':len(reports),'direct_JSON_parsed':jsons,'local_links_checked':links,'prior_artifacts_preserved':5669,'allowed_existing_changes':6,'all_checks_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
