#!/usr/bin/env python3
"""Preserve the preceding publication and seal this source-analysis increment.
O(prior artifact bytes + report links) time; O(manifest + report text) memory.
"""
import ast,hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
REPORTS=['daemon_record720_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
    prior=ROOT/'daemon_record720_prior_manifest.json';assert sha(prior)=='37b7cca4b545cc13b42af810f6a5a2ce205d771b0118df4f75d84f6cb0197dee';m=json.loads(prior.read_text());same=[];changed=[]
    for row in m['files']:
        p=BASE/row['path'];assert p.is_file();h=sha(p)
        if row['path']in CHANGED:
            assert h!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':h})
        else:assert h==row['sha256'] and p.stat().st_size==row['size_bytes'],row['path'];same.append(row['path'])
    assert {r['path']for r in changed}==CHANGED
    for r in m['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256'] and (BASE/r['path']).stat().st_size==r['size_bytes']
    assert sha(Path('/Users/___/Downloads/zut/fairplayd.arm64e'))=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    c=json.loads((ROOT/'daemon_record720_checks.json').read_text());assert c['all_checks_pass'] and not c['full_goal_complete'] and not c['native_target_executed'] and not c['registry_value_identity_established']
    for n in ['capture_daemon_record720.py','prove_daemon_record720.py','validate_daemon_record720.py','seal_daemon_record720.py']:ast.parse((ROOT/n).read_text(),filename=n)
    text=(BASE/REPORTS[0]).read_text();assert all('| R'+str(j)+' |'in text for j in range(1,11));assert all('QG'+str(j)+':'in text for j in range(1,8));assert text.isascii()
    counts=c['verified_counts'];assert counts['fresh_A64_cases']==64 and counts['source_proofs_rebuilt']==7 and counts['initializer_defined_bytes']==161
    proofs=json.loads((ROOT/'daemon_record720_proofs.json').read_text());used={r[k]for r in proofs['proofs']for k in ['original_file','file']}
    assert used=={p.name for p in ROOT.glob('daemon_record720_*.smt2')} and len(used)==14
    assert c['generator_sha256']==sha(ROOT/'validate_daemon_record720.py') and proofs['generator_sha256']==sha(ROOT/'prove_daemon_record720.py')
    for n,h in c['dependencies'].items():assert sha(ROOT/n)==h
    delivery={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':len(m['files']),'prior_artifacts_unchanged':len(same),'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'all_checks_pass':True,'full_goal_complete':False,'goal_status':'active'}
    (ROOT/'daemon_record720_delivery.json').write_text(json.dumps(delivery,indent=2)+'\n')
    quality={'scope':'Seven gates pass for the allocation/initializer/census increment; native registry and transport joins remain unknown.','generator_sha256':sha(Path(__file__)),'verified_counts':counts,'A64_totals':c['totals'],'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in ['daemon_record720_source.json','daemon_record720_proofs.json','daemon_record720_checks.json','daemon_record720_ida_bytes.json']},'native_target_executed':False,'idb_mutated':False,'new_port_emission_established':False,'registry_value_identity_established':False,'full_goal_complete':False,'goal_status':'active'}
    for j in range(1,8):quality['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+' and R1-R10, source/case checks and preserved prior artifacts'}
    (ROOT/'daemon_record720_quality_gates.json').write_text(json.dumps(quality,indent=2)+'\n')
    links=0
    for n in REPORTS:
        for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/n).read_text()):
            raw=raw.strip('<>')
            if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
            target=Path(raw.split('#',1)[0]);target=target if target.is_absolute()else BASE/target;assert target.exists(),(n,raw);links+=1
    delivery['local_links_checked']=links;(ROOT/'daemon_record720_delivery.json').write_text(json.dumps(delivery,indent=2)+'\n')
    print(json.dumps({'prior_artifacts_checked':len(m['files']),'unchanged':len(same),'changed':len(changed),'links':links,'scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
