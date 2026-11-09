#!/usr/bin/env python3
"""Preserve the prior publication, audit actual stopped-read definitions and
seal the allocation-to-fingerprint increment. O(prior bytes+profiles/effects+links) time;
O(manifest+profiles+largest decoded case) space. No native or IDB mutation.
"""
import ast,base64,hashlib,json,re,struct,zlib
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
REPORTS=['daemon_record720_fingerprint_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
SCRIPTS=['capture_daemon_record720_fingerprint.py','prove_daemon_record720_fingerprint.py','probe_daemon_record720_fingerprint.py','validate_daemon_record720_fingerprint.py','seal_daemon_record720_fingerprint.py']
def sha(p):
    with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def load(n):return json.loads((ROOT/n).read_text())
def main():
    prior=ROOT/'daemon_record720_fingerprint_prior_manifest.json';assert sha(prior)=='c86ae14fc5181d5f764eea9d18185d929791c3a2808eb6e57f750c6924bee023';m=json.loads(prior.read_text());unchanged=0;changed=[]
    for r in m['files']:
        p=BASE/r['path'];assert p.is_file();h=sha(p)
        if r['path']in CHANGED:assert h!=r['sha256'];changed.append({'path':r['path'],'prior_sha256':r['sha256'],'sha256':h})
        else:assert h==r['sha256']and p.stat().st_size==r['size_bytes'],r['path'];unchanged+=1
    assert {r['path']for r in changed}==CHANGED
    for r in m['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and (BASE/r['path']).stat().st_size==r['size_bytes']
    assert sha(Path('/Users/___/Downloads/zut/fairplayd.arm64e'))=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    c=load('daemon_record720_fingerprint_checks.json');p=load('daemon_record720_fingerprint_proofs.json');prof=load('daemon_record720_fingerprint_profiles.json');src=load('daemon_record720_fingerprint_source.json')
    for obj,script in [(c,'validate_daemon_record720_fingerprint.py'),(p,'prove_daemon_record720_fingerprint.py'),(prof,'probe_daemon_record720_fingerprint.py'),(src,'capture_daemon_record720_fingerprint.py')]:
        assert obj['generator_sha256']==sha(ROOT/script)
        for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h,(script,n)
    assert c['all_checks_pass']and not c['full_goal_complete']and not c['native_target_executed'];assert c['verified_counts']['source_proofs_rebuilt']==10 and c['independent_A64_totals']['fresh_cases_checked']==112
    smt={r[k]for r in p['proofs']for k in ['file','original_file']};assert len(smt)==20 and smt=={p.name for p in ROOT.glob('daemon_fingerprint720_*.smt2')}
    # The preceding increment's exact SMT namespace must remain isolated.
    old=load('daemon_record720_proofs.json');old_smt={r[k]for r in old['proofs']for k in ['file','original_file']};assert old_smt=={p.name for p in ROOT.glob('daemon_record720_*.smt2')}
    frontier_checks=0
    for row in prof['cases']:
        b=zlib.decompress(base64.b64decode(row['payload_zlib_base64']));assert hashlib.sha256(b).hexdigest()==row['payload_sha256'];t=json.loads(b);bd=t['boundary'];pc=bd['pc'];w=int.from_bytes(bytes.fromhex(t['source_pool'][pc]['bytes_hex']),'little');base=(w>>5)&31;reg=int(bd['SP']if base==31 else bd['registers31'][base],16)
        assert pc in ['0x100b90ef4','0x10041f770']
        assert w&0x3b000000==0x39000000 and(w>>22)&3==1;n=1<<(w>>30);offset=((w>>10)&4095)*n
        a=(reg+offset)&((1<<64)-1);assert a==int(bd['detail']['address'],16)and n==bd['detail']['size_bytes']
        defined={int(g['address'],16)+j for g in row['context']['known_byte_groups']for j in range(len(g['bytes_hex'])//2)}
        for e in t['events']:
            if e['kind']=='write':defined.update(range(int(e['address'],16),int(e['address'],16)+e['size_bytes']))
        for model in t['API_models']:
            if 'invalidated_range'in model:rng=model['invalidated_range'];defined.difference_update(range(int(rng['address'],16),int(rng['address'],16)+rng['size_bytes']))
        assert not all(a+j in defined for j in range(n));frontier_checks+=1
    assert frontier_checks==112
    # Compare the two actual callback callers using retained source/ABI evidence.
    # This is a caller census of these fixtures, not a native reachability join.
    oldworker=load('rpc502_certificate_profiles.json');worker_roots=0
    oldpool={int(r['ea'],16):r for r in oldworker['original_instruction_pool']}
    assert 0x100bae048 not in oldpool
    image=Path('/Users/___/Downloads/zut/fairplayd.arm64e').read_bytes()
    def source_bytes(address,n):
        at=32
        for _ in range(struct.unpack_from('<I',image,16)[0]):
            command,size=struct.unpack_from('<II',image,at)
            if command==0x19:
                vm,extent,offset,filesize=struct.unpack_from('<4Q',image,at+24)
                if vm<=address<address+n<=vm+filesize:return image[offset+address-vm:offset+address-vm+n]
            at+=size
        raise AssertionError(('unbacked source',hex(address)))
    assert source_bytes(0x100924554,4)==source_bytes(0x100478ef4,4)==bytes.fromhex('1f093fd6')
    assert bytes.fromhex(oldpool[0x100924554]['bytes'])==source_bytes(0x100924554,4)
    for row in oldworker['cases']:
        t=json.loads(zlib.decompress(base64.b64decode(row['payload_zlib_base64'])))
        for call in t['schema_callbacks']:
            if call['entry']!='0x10040f7a4':continue
            C=int(call['registers'][0],16);I=int(call['registers'][1],16);Q=struct.unpack_from('<Q',bytes.fromhex(call['x0_prefix256_hex']),0x60)[0]
            assert call['return_pc']=='0x100924558'and I==C+0x1f8 and Q==C+0x248 and int(call['return_registers'][0],16)==0;worker_roots+=1
    assert worker_roots==23
    routes={'retained_worker_root_calls_checked':worker_roots,'source_call_sites_checked':2,'common_callback':'0x10040f7a4','allocation_route_call':'0x100478ef4','worker_route_call':'0x100924554','item_minus_user_bytes':0x1f8,'new_work_minus_user_bytes':-0x6f0,'worker_work_minus_user_bytes':0x248,'allocation_call_absent_from_retained_worker_pool':True,'native_caller_continuity_established':False}
    for n in SCRIPTS:ast.parse((ROOT/n).read_text(),filename=n)
    text=(BASE/REPORTS[0]).read_text();assert text.isascii()and all('| F'+str(j)+' |'in text for j in range(1,13))and all('QG'+str(j)+':'in text for j in range(1,8))
    delivery={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':len(m['files']),'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'stopped_read_definedness_checks':frontier_checks,'Python_syntax_checks':len(SCRIPTS),'accepted_SMT_files':len(smt),'previous_SMT_namespace_preserved':True,'route_comparison':routes,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False}
    (ROOT/'daemon_record720_fingerprint_delivery.json').write_text(json.dumps(delivery,indent=2)+'\n')
    q={'scope':'Allocation-to-root-fingerprint convergence, callback output records and source release/error boundaries; native reachability and IPC joins remain unknown.','generator_sha256':sha(Path(__file__)),'verified_counts':c['verified_counts'],'independent_A64_totals':c['independent_A64_totals'],'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in ['daemon_record720_fingerprint_source.json','daemon_record720_fingerprint_proofs.json','daemon_record720_fingerprint_profiles.json','daemon_record720_fingerprint_checks.json','daemon_record720_fingerprint_ida.json']},'native_target_executed':False,'idb_mutated':False,'registry_publication_established':False,'new_port_emission_established':False,'full_goal_complete':False,'goal_status':'active'}
    q['route_comparison']=routes
    for j in range(1,8):q['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', F1-F12, source/case checks, frontier definitions and preservation'}
    (ROOT/'daemon_record720_fingerprint_quality_gates.json').write_text(json.dumps(q,indent=2)+'\n');links=0
    for n in REPORTS:
        for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/n).read_text()):
            raw=raw.strip('<>')
            if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
            target=Path(raw.split('#',1)[0]);target=target if target.is_absolute()else BASE/target;assert target.exists(),(n,raw);links+=1
    delivery['local_links_checked']=links;(ROOT/'daemon_record720_fingerprint_delivery.json').write_text(json.dumps(delivery,indent=2)+'\n');print(json.dumps({'prior_artifacts_checked':len(m['files']),'unchanged':unchanged,'changed':len(changed),'frontier_checks':frontier_checks,'local_links_checked':links,'scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
