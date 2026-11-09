#!/usr/bin/env python3
"""Preserve the prior publication, audit actual stopped-read definitions and
seal this increment. O(prior bytes+profiles/effects+links) time;
O(manifest+profiles+largest decoded case) space. No native or IDB mutation.
"""
import ast,base64,hashlib,json,re,zlib
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
REPORTS=['daemon_record720_handoff_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
SCRIPTS=['capture_daemon_record720_handoff.py','prove_daemon_record720_handoff.py','probe_daemon_record720_handoff.py','daemon_record720_handoff_replay.py','replay_daemon_record720_handoff.py','validate_daemon_record720_handoff.py','seal_daemon_record720_handoff.py']
def sha(p):
    with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def load(n):return json.loads((ROOT/n).read_text())
def main():
    prior=ROOT/'daemon_record720_handoff_prior_manifest.json';assert sha(prior)=='ec6596a32f1838ea61e5c9702bb51238d8189f1c5997f9cf266f1115a617e12b';m=json.loads(prior.read_text());unchanged=0;changed=[]
    for r in m['files']:
        p=BASE/r['path'];assert p.is_file();h=sha(p)
        if r['path']in CHANGED:assert h!=r['sha256'];changed.append({'path':r['path'],'prior_sha256':r['sha256'],'sha256':h})
        else:assert h==r['sha256']and p.stat().st_size==r['size_bytes'],r['path'];unchanged+=1
    assert {r['path']for r in changed}==CHANGED
    for r in m['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and (BASE/r['path']).stat().st_size==r['size_bytes']
    assert sha(Path('/Users/___/Downloads/zut/fairplayd.arm64e'))=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    c=load('daemon_record720_handoff_checks.json');p=load('daemon_record720_handoff_proofs.json');prof=load('daemon_record720_handoff_profiles.json');src=load('daemon_record720_handoff_source.json')
    for obj,script in [(c,'validate_daemon_record720_handoff.py'),(p,'prove_daemon_record720_handoff.py'),(prof,'probe_daemon_record720_handoff.py'),(src,'capture_daemon_record720_handoff.py')]:
        assert obj['generator_sha256']==sha(ROOT/script)
        for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h,(script,n)
    assert c['all_checks_pass']and not c['full_goal_complete']and not c['native_target_executed']and not c['registry_publication_established'];assert c['verified_counts']['source_proofs_rebuilt']==17 and c['independent_A64_totals']['fresh_cases_checked']==384
    smt={r[k]for r in p['proofs']for k in ['file','original_file']};assert len(smt)==34 and smt=={p.name for p in ROOT.glob('daemon_handoff720_*.smt2')}
    # The preceding increment's exact SMT namespace must remain isolated.
    old=load('daemon_record720_proofs.json');old_smt={r[k]for r in old['proofs']for k in ['file','original_file']};assert old_smt=={p.name for p in ROOT.glob('daemon_record720_*.smt2')}
    frontier_checks=0
    for row in prof['cases']:
        b=zlib.decompress(base64.b64decode(row['payload_zlib_base64']));assert hashlib.sha256(b).hexdigest()==row['payload_sha256'];t=json.loads(b);bd=t['boundary'];pc=bd['pc'];w=int.from_bytes(bytes.fromhex(t['source_pool'][pc]['bytes_hex']),'little');assert w&0x3b000000==0x39000000 and(w>>22)&3==1
        n=1<<(w>>30);base=(w>>5)&31;reg=int(bd['SP']if base==31 else bd['registers31'][base],16);a=(reg+((w>>10)&4095)*n)&((1<<64)-1);assert a==int(bd['detail']['address'],16)and n==bd['detail']['size_bytes']
        defined={int(g['address'],16)+j for g in row['context']['known_byte_groups']for j in range(len(g['bytes_hex'])//2)}
        for e in t['events']:
            if e['kind']=='write':defined.update(range(int(e['address'],16),int(e['address'],16)+e['size_bytes']))
        assert not all(a+j in defined for j in range(n));frontier_checks+=1
    assert frontier_checks==384
    for n in SCRIPTS:ast.parse((ROOT/n).read_text(),filename=n)
    text=(BASE/REPORTS[0]).read_text();assert text.isascii()and all('| H'+str(j)+' |'in text for j in range(1,13))and all('QG'+str(j)+':'in text for j in range(1,8))
    delivery={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':len(m['files']),'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'stopped_read_definedness_checks':frontier_checks,'Python_syntax_checks':len(SCRIPTS),'accepted_SMT_files':len(smt),'previous_SMT_namespace_preserved':True,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False}
    (ROOT/'daemon_record720_handoff_delivery.json').write_text(json.dumps(delivery,indent=2)+'\n')
    q={'scope':'Private record/cursor/dispatcher and finite successor increment; native ownership and IPC joins remain unknown.','generator_sha256':sha(Path(__file__)),'verified_counts':c['verified_counts'],'independent_A64_totals':c['independent_A64_totals'],'frontier_counts':c['frontier_counts'],'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in ['daemon_record720_handoff_source.json','daemon_record720_handoff_proofs.json','daemon_record720_handoff_profiles.json','daemon_record720_handoff_checks.json','daemon_record720_handoff_ida.json']},'native_target_executed':False,'idb_mutated':False,'registry_publication_established':False,'new_port_emission_established':False,'full_goal_complete':False,'goal_status':'active'}
    for j in range(1,8):q['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', H1-H12, source/case checks, frontier definitions and preservation'}
    (ROOT/'daemon_record720_handoff_quality_gates.json').write_text(json.dumps(q,indent=2)+'\n');links=0
    for n in REPORTS:
        for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/n).read_text()):
            raw=raw.strip('<>')
            if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
            target=Path(raw.split('#',1)[0]);target=target if target.is_absolute()else BASE/target;assert target.exists(),(n,raw);links+=1
    delivery['local_links_checked']=links;(ROOT/'daemon_record720_handoff_delivery.json').write_text(json.dumps(delivery,indent=2)+'\n');print(json.dumps({'prior_artifacts_checked':len(m['files']),'unchanged':unchanged,'changed':len(changed),'frontier_checks':frontier_checks,'local_links_checked':links,'scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
