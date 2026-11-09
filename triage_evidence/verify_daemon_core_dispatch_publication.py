#!/usr/bin/env python3
"""Read-only independent full manifest/JSON/link/hash readback.
O(artifact bytes + JSON bytes + report links) time, O(manifest + largest JSON)
space. No target, report, IDB or memory state is modified.
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
 assert len(m['files'])==4898 and len(reports)==151 and jsons==1284
 assert m['validation']['reports']==len(reports)and m['validation']['direct_json_files']==jsons and m['validation']['local_markdown_links']==links
 extra={'triage_evidence/'+n for n in ['capture_daemon_core_dispatch.py','prove_daemon_core_dispatch.py','validate_daemon_core_dispatch.py','seal_daemon_core_dispatch.py','verify_daemon_core_dispatch_publication.py']}
 owned={str(p.relative_to(BASE))for p in ROOT.glob('daemon_core_dispatch_*')if p.is_file()}|extra|{'daemon_core_dispatch_report.md'};assert len(owned)==42 and owned<=seen
 prior=json.loads((ROOT/'daemon_core_dispatch_prior_manifest.json').read_text());assert seen-{r['path']for r in prior['files']}==owned
 checks=json.loads((ROOT/'daemon_core_dispatch_checks.json').read_text());delivery=json.loads((ROOT/'daemon_core_dispatch_delivery.json').read_text());quality=json.loads((ROOT/'daemon_core_dispatch_quality_gates.json').read_text());assert checks['all_checks_pass']and delivery['all_checks_pass']and all(quality['QG'+str(j)]['status']=='pass_for_increment'for j in range(1,8))
 assert delivery['prior_artifacts_checked']==4856 and delivery['prior_artifacts_unchanged']==4850 and len(delivery['allowed_changes'])==6
 assert m['validation']['daemon_core_dispatch_increment_checks']==quality['verified_counts']and m['validation']['daemon_core_dispatch_A64_totals']==checks['independent_A64_totals']
 for n,h in quality['report_sha256'].items():assert sha(BASE/n)==h
 for n,h in quality['evidence_sha256'].items():assert sha(ROOT/n)==h
 print(json.dumps({'manifest_sha256':sha(path),'artifacts_rehashed':len(seen),'reports_checked':len(reports),'direct_JSON_parsed':jsons,'local_links_checked':links,'prior_artifacts_preserved':4850,'allowed_existing_changes':6,'all_checks_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
