#!/usr/bin/env python3
"""Seal caller-record/auxiliary evidence and preserve frozen publications.
O(prior bytes + report links) time, O(manifest + largest JSON) space.
Only six owned existing index/publisher paths may change; no target/IDB writes.
"""
import ast,hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
REPORTS=['daemon_output_base_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
SCRIPTS=['daemon_output_base_dispatch.py','recover_daemon_output_base.py','prove_daemon_output_base.py','validate_daemon_output_base.py','seal_daemon_output_base.py','verify_daemon_output_base_publication.py']
EVIDENCE=['daemon_output_base_dispatch.json','daemon_output_base_branches.json','daemon_output_base_contracts.json','daemon_output_base_proofs.json','daemon_output_base_checks.json','daemon_output_base_ida.json']
def sha(p):
    with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def load(n):return json.loads((ROOT/n).read_text())
def main():
    prior=ROOT/'daemon_output_base_prior_manifest.json';assert sha(prior)=='63a28501f941f88f420f3028f258e665e19a4324b42186653c58e0246881b481';m=json.loads(prior.read_text());assert len(m['files'])==4711;changed=[];unchanged=0
    for row in m['files']:
        p=BASE/row['path'];assert p.is_file();h=sha(p)
        if row['path']in CHANGED:assert h!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':h})
        else:assert h==row['sha256']and p.stat().st_size==row['size_bytes'],row['path'];unchanged+=1
    assert {r['path']for r in changed}==CHANGED and unchanged==4705
    for r in m['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and(BASE/r['path']).stat().st_size==r['size_bytes']
    assert sha('/Users/___/Downloads/zut/fairplayd.arm64e')=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    dispatch,branches,contracts,proofs,checks=[load(n)for n in EVIDENCE[:5]]
    for obj,script in [(dispatch,SCRIPTS[0]),(branches,SCRIPTS[0]),(contracts,SCRIPTS[1]),(proofs,SCRIPTS[2]),(checks,SCRIPTS[3])]:
        assert obj['generator_sha256']==sha(ROOT/script)
        for n,h in obj.get('dependencies',{}).items():assert sha(ROOT/n)==h,(script,n)
    assert checks['all_checks_pass']and not checks['native_target_executed']and not checks['host_API_executed']and not checks['native_frame_epoch_join_established']and not checks['full_goal_complete']
    assert checks['verified_counts']['source_obligations_rebuilt']==14 and checks['independent_A64_totals']['witnesses_checked']==125 and checks['independent_A64_totals']['A64_instructions_checked']==18630 and checks['verified_counts']['frozen_original_prefix_A64_cases']==6
    assert len(dispatch['paths'])==9 and len(branches['cases'])==5 and len(contracts['source_frame_origin_audits'])==24 and sum(r['matching_bytes']for r in contracts['live_IDA_matches'])==640
    assert contracts['interval_cardinality_u32']==1196639446 and contracts['default_cardinality_u32']==3098327846
    assert contracts['CoreFoundation_data_binding']['import_table_addend']==0x6ae8388f and not contracts['CoreFoundation_data_binding']['authenticated']
    assert contracts['rejected_hypothesis']['counterexample_result']=='sat'and contracts['rejected_hypothesis']['counterexample_aux']=='0x7484eeab'
    smt={r[k]for r in proofs['proofs']for k in ['file','original_file']};assert len(smt)==28
    assert smt|{'daemon_output_base_rejected_singleton.smt2'}=={p.name for p in ROOT.glob('daemon_output_base_*.smt2')}
    for r in proofs['proofs']:assert r['result']=='unsat'and sha(ROOT/r['file'])==r['sha256']and sha(ROOT/r['original_file'])==r['original_sha256']
    assert sha(ROOT/contracts['rejected_hypothesis']['query_file'])==contracts['rejected_hypothesis']['query_sha256']
    for r in contracts['source_frame_origin_audits']:assert not r['X0_write_PCs_before_spill']and r['spill']['pc']=='0x10097c778'
    for b in branches['cases']:
        assert len(b['paths'])==1 and b['paths'][0]['boundary']['pc']=='0x1009d0624'and len(b['unavailable_frame_byte_variables'])==28 and len(b['borrowed_input_byte_variables'])==8
        assert b['continuation_tag_is_representative_only']==(b['continuation_tag']=='0x7bed772d')
    for name in SCRIPTS:ast.parse((ROOT/name).read_text(),filename=name)
    text=(BASE/REPORTS[0]).read_text();assert text.isascii()and all('| OB'+str(j)+' |'in text for j in range(1,11))and all('QG'+str(j)+':'in text for j in range(1,8))
    links=0
    for name in REPORTS:
        for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
            raw=raw.strip('<>')
            if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
            target=Path(raw.split('#',1)[0]);target=target if target.is_absolute()else BASE/target
            if target.name not in ['daemon_output_base_delivery.json','daemon_output_base_quality_gates.json']:assert target.exists(),(name,raw)
            links+=1
    d={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':4711,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'accepted_SMT_files':28,'rejected_SAT_hypotheses':1,'Python_syntax_checks':len(SCRIPTS),'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/'daemon_output_base_delivery.json').write_text(json.dumps(d,indent=2)+'\n')
    q={'scope':'Private caller-record provenance, complete mode471C auxiliary partition and five shared byte-decoding/data-import boundaries. Native alternative callers and720-byte/transport epochs unknown.','generator_sha256':sha(__file__),'verified_counts':checks['verified_counts'],'independent_A64_totals':checks['independent_A64_totals'],'original_prefix_A64_totals':checks['original_prefix_A64_totals'],'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in EVIDENCE},'native_target_executed':False,'native_frame_epoch_join_established':False,'host_API_executed':False,'idb_mutated':False,'new_port_emission_established':False,'full_goal_complete':False,'goal_status':'active'}
    for j in range(1,8):q['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', OB1-OB10, source/CPU checks, corrected singleton counterexample and artifact preservation'}
    (ROOT/'daemon_output_base_quality_gates.json').write_text(json.dumps(q,indent=2)+'\n');print(json.dumps({'prior_artifacts_checked':4711,'unchanged':unchanged,'changed':len(changed),'local_links_checked':links,'scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
