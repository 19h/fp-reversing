#!/usr/bin/env python3
"""Independent full published-manifest readback. Read-only, O(artifact bytes
+ JSON bytes + report links) time and O(largest JSON + manifest) space.
No target, IDB, IPC, source profile or report is modified.
"""
import hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent

def sha(p):
    with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()

def main():
    p=ROOT/'interface_manifest.json';m=json.loads(p.read_text());assert m['goal_status']=='active';seen=set();reports=[];jsons=0;links=0
    for r in m['inputs_preserved']:
        q=BASE/r['path'];assert q.stat().st_size==r['size_bytes']and sha(q)==r['sha256']
    for r in m['files']:
        assert r['path']not in seen;seen.add(r['path']);q=BASE/r['path'];assert q.is_file()and q.stat().st_size==r['size_bytes']and sha(q)==r['sha256'],r['path']
        if q.parent==ROOT and q.suffix=='.json':json.loads(q.read_text());jsons+=1
        if q.parent==BASE and q.suffix=='.md':reports.append(q)
    for q in reports:
        for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',q.read_text()):
            raw=raw.strip('<>')
            if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
            name=raw.split('#',1)[0];target=Path(name)if name.startswith('/')else q.parent/name;assert target.exists(),(q.name,raw);links+=1
    assert len(m['files'])==4605 and len(reports)==144 and jsons==1225
    assert m['validation']['reports']==len(reports)and m['validation']['direct_json_files']==jsons and m['validation']['local_markdown_links']==links
    assert set(r['path']for r in m['files']if r['path'].startswith('triage_evidence/daemon_arena_list_')or r['path'].endswith('/capture_daemon_arena_list.py')or r['path'].endswith('/prove_daemon_arena_list.py')or r['path'].endswith('/validate_daemon_arena_list.py')or r['path'].endswith('/seal_daemon_arena_list.py')or r['path'].endswith('/verify_daemon_arena_list_publication.py')or r['path']=='daemon_arena_list_report.md')==set(str(q.relative_to(BASE))for q in ROOT.glob('daemon_arena_list_*')if q.is_file())|{'daemon_arena_list_report.md'}|{'triage_evidence/'+n for n in ['capture_daemon_arena_list.py','prove_daemon_arena_list.py','validate_daemon_arena_list.py','seal_daemon_arena_list.py','verify_daemon_arena_list_publication.py']}
    checks=json.loads((ROOT/'daemon_arena_list_checks.json').read_text());delivery=json.loads((ROOT/'daemon_arena_list_delivery.json').read_text());quality=json.loads((ROOT/'daemon_arena_list_quality_gates.json').read_text());assert checks['all_checks_pass']and delivery['all_checks_pass']and all(quality['QG'+str(j)]['status']=='pass_for_increment'for j in range(1,8))
    assert delivery['prior_artifacts_checked']==4574 and delivery['prior_artifacts_unchanged']==4568 and len(delivery['allowed_changes'])==6
    assert m['validation']['daemon_arena_list_increment_checks']==checks['verified_counts']and m['validation']['daemon_arena_list_witness_totals']==checks['independent_witness_totals']
    for n,h in quality['report_sha256'].items():assert sha(BASE/n)==h
    for n,h in quality['evidence_sha256'].items():assert sha(ROOT/n)==h
    print(json.dumps({'manifest_sha256':sha(p),'artifacts_rehashed':len(seen),'reports_checked':len(reports),'direct_JSON_parsed':jsons,'local_links_checked':links,'prior_artifacts_preserved':4568,'allowed_existing_changes':6,'all_checks_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
