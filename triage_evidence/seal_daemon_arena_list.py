#!/usr/bin/env python3
"""Preservation, missing-byte and publication gates for arena-list component work.
O(prior artifact bytes + known bytes + links) time, O(manifest + largest JSON)
space. Original target/inputs/IDB are never written; full goal stays active.
"""
import ast,hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
REPORTS=['daemon_arena_list_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
SCRIPTS=['capture_daemon_arena_list.py','daemon_arena_list_symbolic.py','prove_daemon_arena_list.py','validate_daemon_arena_list.py','seal_daemon_arena_list.py','verify_daemon_arena_list_publication.py']
def sha(p):
    with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def load(n):return json.loads((ROOT/n).read_text())
def main():
    prior=ROOT/'daemon_arena_list_prior_manifest.json';assert sha(prior)=='7f526f73b0c95cee67e3fa798bf05f9225a03945f96003190695c6b8e65c769b';m=json.loads(prior.read_text());unchanged=0;changed=[]
    for r in m['files']:
        p=BASE/r['path'];assert p.is_file();h=sha(p)
        if r['path']in CHANGED:assert h!=r['sha256'];changed.append({'path':r['path'],'prior_sha256':r['sha256'],'sha256':h})
        else:assert h==r['sha256']and p.stat().st_size==r['size_bytes'],r['path'];unchanged+=1
    assert {r['path']for r in changed}==CHANGED and len(m['files'])==4574
    for r in m['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and(BASE/r['path']).stat().st_size==r['size_bytes']
    assert sha('/Users/___/Downloads/zut/fairplayd.arm64e')=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    source=load('daemon_arena_list_source.json');symbolic=load('daemon_arena_list_symbolic.json');proofs=load('daemon_arena_list_proofs.json');checks=load('daemon_arena_list_checks.json')
    for obj,script in [(source,SCRIPTS[0]),(symbolic,SCRIPTS[1]),(proofs,SCRIPTS[2]),(checks,SCRIPTS[3])]:
        assert obj['generator_sha256']==sha(ROOT/script)
        for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h,(script,n)
    assert checks['all_checks_pass']and not checks['native_target_executed']and not checks['unknown_bytes_assigned_source_values']and not checks['full_goal_complete']
    assert checks['verified_counts']['source_obligations_rebuilt']==8 and checks['independent_witness_totals']['witnesses_checked']==12
    smt={r[k]for r in proofs['proofs']for k in ['file','original_file']};assert len(smt)==16 and smt=={p.name for p in ROOT.glob('daemon_arena_list_*.smt2')}
    for case,row in zip(source['cases'],symbolic['cases'],strict=True):
        result=row['result'];known={int(g['address'],16)+j for g in case['context']['known_byte_groups']for j in range(len(g['bytes_hex'])//2)};unknown={int(r['address'],16)for r in result['unknown_bytes']};assert len(unknown)==104 and not(unknown&known)
        assert not result['unknown_bytes_assigned_values']and not case['declared_epoch_continuity']
    assert [r['result']['boundary']['kind']for r in symbolic['cases']]==['before_import_call','before_allocator_continuation','before_allocator_continuation']
    for name in SCRIPTS:ast.parse((ROOT/name).read_text(),filename=name)
    text=(BASE/REPORTS[0]).read_text();assert text.isascii()and all('| AL'+str(j)+' |'in text for j in range(1,12))and all('QG'+str(j)+':'in text for j in range(1,8))
    d={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':len(m['files']),'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'unavailable_frame_bytes_preserved':104,'descriptor_read_is_component_input':True,'accepted_SMT_files':len(smt),'Python_syntax_checks':len(SCRIPTS),'all_checks_pass':True,'goal_status':'active','full_goal_complete':False}
    (ROOT/'daemon_arena_list_delivery.json').write_text(json.dumps(d,indent=2)+'\n')
    q={'scope':'Arena-list component, split metadata and private continuation ABI; native descriptor/caller epoch and transport join unproved.','generator_sha256':sha(__file__),'verified_counts':checks['verified_counts'],'independent_witness_totals':checks['independent_witness_totals'],'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in ['daemon_arena_list_source.json','daemon_arena_list_symbolic.json','daemon_arena_list_proofs.json','daemon_arena_list_checks.json','daemon_arena_list_ida.json']},'native_target_executed':False,'idb_mutated':False,'unknown_bytes_assigned_source_values':False,'new_port_emission_established':False,'registry_publication_established':False,'full_goal_complete':False,'goal_status':'active'}
    for j in range(1,8):q['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', AL1-AL11, source/witness checks and preservation'}
    (ROOT/'daemon_arena_list_quality_gates.json').write_text(json.dumps(q,indent=2)+'\n');links=0
    for n in REPORTS:
        for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/n).read_text()):
            raw=raw.strip('<>')
            if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
            target=Path(raw.split('#',1)[0]);target=target if target.is_absolute()else BASE/target;assert target.exists(),(n,raw);links+=1
    d['local_links_checked']=links;(ROOT/'daemon_arena_list_delivery.json').write_text(json.dumps(d,indent=2)+'\n');print(json.dumps({'prior_artifacts_checked':len(m['files']),'unchanged':unchanged,'changed':len(changed),'opaque_frame_bytes_preserved':104,'local_links_checked':links,'scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
