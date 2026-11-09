#!/usr/bin/env python3
"""Preserve prior artifacts and seal the lifetime/output/cleanup increment.
O(prior bytes + links) time, O(manifest + largest JSON) space. No target, native
API, IDB or memory-store mutation. Broad interface objective remains active.
"""
import ast,hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
REPORTS=['daemon_arena_lifetime_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
SCRIPTS=['capture_daemon_arena_lifetime.py','daemon_arena_lifetime_symbolic.py','recover_daemon_arena_lifetime_refs.py','prove_daemon_arena_lifetime.py','validate_daemon_arena_lifetime.py','seal_daemon_arena_lifetime.py','verify_daemon_arena_lifetime_publication.py']
def sha(p):
    with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def load(n):return json.loads((ROOT/n).read_text())
def main():
    prior=ROOT/'daemon_arena_lifetime_prior_manifest.json';assert sha(prior)=='b6e072760e297cf199c407b530c1eccc419a1e90f946c03cc3d80203c3a433f5';m=json.loads(prior.read_text());assert len(m['files'])==4647;changed=[];unchanged=0
    for row in m['files']:
        p=BASE/row['path'];assert p.is_file();h=sha(p)
        if row['path']in CHANGED:assert h!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':h})
        else:assert h==row['sha256']and p.stat().st_size==row['size_bytes'],row['path'];unchanged+=1
    assert {r['path']for r in changed}==CHANGED and unchanged==4641
    for r in m['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and(BASE/r['path']).stat().st_size==r['size_bytes']
    assert sha('/Users/___/Downloads/zut/fairplayd.arm64e')=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    evidence=['daemon_arena_lifetime_source.json','daemon_arena_lifetime_symbolic.json','daemon_arena_lifetime_refs.json','daemon_arena_lifetime_proofs.json','daemon_arena_lifetime_checks.json','daemon_arena_lifetime_ida.json'];source,symbolic,refs,proofs,checks=[load(n)for n in evidence[:5]]
    for obj,script in [(source,SCRIPTS[0]),(symbolic,SCRIPTS[1]),(refs,SCRIPTS[2]),(proofs,SCRIPTS[3]),(checks,SCRIPTS[4])]:
        assert obj['generator_sha256']==sha(ROOT/script)
        for n,h in obj.get('dependencies',{}).items():assert sha(ROOT/n)==h,(script,n)
    assert checks['all_checks_pass']and not checks['runtime_flag_concretized_in_source']and not checks['host_free_executed']and not checks['native_target_executed']and not checks['full_goal_complete']
    assert checks['verified_counts']['source_obligations_rebuilt']==8 and checks['independent_A64_totals']['witnesses_checked']==8 and checks['independent_A64_totals']['A64_instructions_checked']==1135556
    smt={r[k]for r in proofs['proofs']for k in ['file','original_file']};assert len(smt)==16 and smt=={p.name for p in ROOT.glob('daemon_arena_lifetime_*.smt2')}
    for r in proofs['proofs']:assert sha(ROOT/r['file'])==r['sha256']and sha(ROOT/r['original_file'])==r['original_sha256']
    for case,row,audit in zip(source['cases'],symbolic['cases'],checks['audits'],strict=True):
        r=row['result'];assert r['context']==case['context']and len(r['unknown_bytes'])==104 and len(r['resolution_certificates'])==1 and len(r['return_edges'])==2
        assert not case['runtime_flag_assigned_value']and not case['native_epoch_continuity']and r['boundary']['kind']=='before_import_call'and r['boundary']['binding']['symbol']=='_free'
        known={int(g['address'],16)+j for g in case['context']['known_byte_groups']for j in range(len(g['bytes_hex'])//2)};assert all(0x1010b6cb8+j not in known for j in range(4));assert audit['record_result']=='0x74c29d8a'and audit['cursor_adjustment_bytes']==0
    for name in SCRIPTS:ast.parse((ROOT/name).read_text(),filename=name)
    text=(BASE/REPORTS[0]).read_text();assert text.isascii()and all('| L'+str(j)+' |'in text for j in range(1,11))and all('QG'+str(j)+':'in text for j in range(1,8))
    d={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':4647,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'source_original_frame_variables':104,'source_runtime_flag_bits':32,'source_runtime_flag_concretized':False,'accepted_SMT_files':len(smt),'Python_syntax_checks':len(SCRIPTS),'host_free_executed':False,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/'daemon_arena_lifetime_delivery.json').write_text(json.dumps(d,indent=2)+'\n')
    q={'scope':'Universal stable-flag-class arena releases, private output channels, logical return provenance and known720-byte cleanup convergence. Native writer/epoch/allocator/IPC effects unproved.','generator_sha256':sha(__file__),'verified_counts':checks['verified_counts'],'independent_A64_totals':checks['independent_A64_totals'],'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in evidence},'native_target_executed':False,'runtime_flag_concretized_in_source':False,'host_free_executed':False,'idb_mutated':False,'new_port_emission_established':False,'full_goal_complete':False,'goal_status':'active'}
    for j in range(1,8):q['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', L1-L10, continuous source/CPU checks and prior-artifact preservation'}
    (ROOT/'daemon_arena_lifetime_quality_gates.json').write_text(json.dumps(q,indent=2)+'\n');links=0
    for name in REPORTS:
        for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
            raw=raw.strip('<>')
            if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
            target=Path(raw.split('#',1)[0]);target=target if target.is_absolute()else BASE/target;assert target.exists(),(name,raw);links+=1
    d['local_links_checked']=links;(ROOT/'daemon_arena_lifetime_delivery.json').write_text(json.dumps(d,indent=2)+'\n');print(json.dumps({'prior_artifacts_checked':4647,'unchanged':unchanged,'changed':len(changed),'local_links_checked':links,'scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
