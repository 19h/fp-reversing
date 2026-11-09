#!/usr/bin/env python3
"""Seal cleanup-return component evidence, preserve all frozen artifacts except
six explicitly owned index/publisher files, and validate scoped report coverage.
O(prior artifact bytes + links) time, O(manifest + largest JSON) space.
No native target/API, IDB, memory store or port operation.
"""
import ast,hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
REPORTS=['daemon_cleanup_return_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
SCRIPTS=['capture_daemon_cleanup_return.py','daemon_cleanup_return_symbolic.py','recover_daemon_cleanup_return.py','prove_daemon_cleanup_return.py','validate_daemon_cleanup_return.py','seal_daemon_cleanup_return.py','verify_daemon_cleanup_return_publication.py']
EVIDENCE=['daemon_cleanup_return_source.json','daemon_cleanup_return_symbolic.json','daemon_cleanup_return_contracts.json','daemon_cleanup_return_proofs.json','daemon_cleanup_return_checks.json','daemon_cleanup_return_ida.json']
def sha(p):
    with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def load(n):return json.loads((ROOT/n).read_text())
def main():
    prior=ROOT/'daemon_cleanup_return_prior_manifest.json';assert sha(prior)=='2ade75ade332f86fd7f959cdee186a245955064e54cf0d9b3ed33f439bbaad2c';m=json.loads(prior.read_text());assert len(m['files'])==4680;changed=[];unchanged=0
    for row in m['files']:
        p=BASE/row['path'];assert p.is_file();h=sha(p)
        if row['path']in CHANGED:assert h!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':h})
        else:assert h==row['sha256']and p.stat().st_size==row['size_bytes'],row['path'];unchanged+=1
    assert {r['path']for r in changed}==CHANGED and unchanged==4674
    for r in m['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and(BASE/r['path']).stat().st_size==r['size_bytes']
    assert sha('/Users/___/Downloads/zut/fairplayd.arm64e')=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    source,symbolic,contracts,proofs,checks=[load(n)for n in EVIDENCE[:5]]
    for obj,script in zip([source,symbolic,contracts,proofs,checks],SCRIPTS[:5],strict=True):
        assert obj['generator_sha256']==sha(ROOT/script)
        for n,h in obj.get('dependencies',{}).items():assert sha(ROOT/n)==h,(script,n)
    assert checks['all_checks_pass']and checks['normal_free_return_assumed']and not checks['runtime_flag_concretized_in_source']and not checks['host_free_executed']and not checks['native_target_executed']and not checks['full_goal_complete']
    assert checks['verified_counts']['source_obligations_rebuilt']==7 and checks['independent_A64_totals']['witnesses_checked']==8 and checks['independent_A64_totals']['A64_instructions_checked']==121980 and len(checks['owned_output_component_cases'])==16
    assert contracts['candidate_count']==7 and contracts['X0_candidate_count']==5 and sum(r['matching_bytes']for r in contracts['live_IDA_matches'])==960
    smt={r[k]for r in proofs['proofs']for k in ['file','original_file']};assert len(smt)==14 and smt=={p.name for p in ROOT.glob('daemon_cleanup_return_*.smt2')}
    for r in proofs['proofs']:assert r['result']=='unsat'and sha(ROOT/r['file'])==r['sha256']and sha(ROOT/r['original_file'])==r['original_sha256']
    from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
    cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
    for case,row,audit in zip(source['cases'],symbolic['cases'],checks['audits'],strict=True):
        r=row['result'];assert r['context']==case['context']and len(r['unknown_bytes'])==112 and len(r['return_edges'])==1 and len(r['steps'])==133 and len(r['effects'])==24 and len(r['edges'])==9 and not r['ABI_reads_before_definition']and not r['active_calls']
        assert r['boundary']['kind']=='nonunique_write_address'and r['boundary']['pc']=='0x10095f074'and r['boundary']['solver_answer']=='sat'and r['end_GPR_expressions']['x23']=='#x0000000074c29f37'
        assert len(r['ABI_symbolic_variables'])==23 and sum(b['width_bits']for b in r['ABI_symbolic_variables'])==1220
        assert r['API_models'][0]['previously_defined_bytes_removed']==161 and r['API_models'][0]['retired_owner_size_bytes']==720
        assert not case['runtime_flag_assigned_value']and not case['native_epoch_continuity']
        for pc,raw in r['steps']:
            i=next(cs.disasm(bytes.fromhex(raw),pc));assert not any(re.fullmatch(r'[bhsdqv][0-9]+',i.reg_name(n))for ns in i.regs_access()for n in ns),'unexpected SIMD/FP register consumption'
    for name in SCRIPTS:ast.parse((ROOT/name).read_text(),filename=name)
    text=(BASE/REPORTS[0]).read_text();assert text.isascii()and all('| CR'+str(j)+' |'in text for j in range(1,11))and all('QG'+str(j)+':'in text for j in range(1,8))
    links=0
    for name in REPORTS:
        for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
            raw=raw.strip('<>')
            if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
            target=Path(raw.split('#',1)[0]);target=target if target.is_absolute()else BASE/target
            # New delivery/gates are generated below; all other links exist.
            if target.name not in ['daemon_cleanup_return_delivery.json','daemon_cleanup_return_quality_gates.json']:assert target.exists(),(name,raw)
            links+=1
    d={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':4680,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'source_frame_variables':112,'source_runtime_flag_bits':32,'scalar_ABI_bits':1220,'SIMD_FP_register_accesses':0,'accepted_SMT_files':len(smt),'Python_syntax_checks':len(SCRIPTS),'local_links_checked':links,'host_free_executed':False,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/'daemon_cleanup_return_delivery.json').write_text(json.dumps(d,indent=2)+'\n')
    q={'scope':'Declared normal free return, exact cleanup result/epilogue and prospective outer u32 result field; native pointer/caller/transport unknown.','generator_sha256':sha(__file__),'verified_counts':checks['verified_counts'],'independent_A64_totals':checks['independent_A64_totals'],'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in EVIDENCE},'normal_free_return_assumed':True,'native_target_executed':False,'runtime_flag_concretized_in_source':False,'host_free_executed':False,'idb_mutated':False,'new_port_emission_established':False,'full_goal_complete':False,'goal_status':'active'}
    for j in range(1,8):q['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', CR1-CR10, source/CPU checks and prior-artifact preservation'}
    (ROOT/'daemon_cleanup_return_quality_gates.json').write_text(json.dumps(q,indent=2)+'\n')
    print(json.dumps({'prior_artifacts_checked':4680,'unchanged':unchanged,'changed':len(changed),'local_links_checked':links,'scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
