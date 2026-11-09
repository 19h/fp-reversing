#!/usr/bin/env python3
"""Seal nine-emitter caller evidence and preserve the published baseline.
O(prior bytes + links) time, O(manifest + largest JSON) space. Six owned existing
index/publisher changes only; no target, host API, memory-store or IDB mutation.
"""
import ast,hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
REPORTS=['daemon_aux_callers_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
SCRIPTS=['probe_daemon_aux_callers.py','recover_daemon_aux_callers.py','prove_daemon_aux_callers.py','validate_daemon_aux_callers.py','seal_daemon_aux_callers.py','verify_daemon_aux_callers_publication.py']
EVIDENCE=['daemon_aux_callers_profiles.json','daemon_aux_callers_contracts.json','daemon_aux_callers_proofs.json','daemon_aux_callers_checks.json','daemon_aux_callers_ida.json']
def sha(p):
    with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def load(n):return json.loads((ROOT/n).read_text())
def main():
    prior=ROOT/'daemon_aux_callers_prior_manifest.json';assert sha(prior)=='843007c434ba3db2300b51c26ae18d98cb8d9673a101eabd70f78e22abb34d74';m=json.loads(prior.read_text());assert len(m['files'])==4756;changed=[];unchanged=0
    for row in m['files']:
        p=BASE/row['path'];assert p.is_file();h=sha(p)
        if row['path']in CHANGED:assert h!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':h})
        else:assert h==row['sha256']and p.stat().st_size==row['size_bytes'],row['path'];unchanged+=1
    assert {r['path']for r in changed}==CHANGED and unchanged==4750
    for r in m['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and(BASE/r['path']).stat().st_size==r['size_bytes']
    assert sha('/Users/___/Downloads/zut/fairplayd.arm64e')=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    profiles,contracts,proofs,checks=[load(n)for n in EVIDENCE[:4]]
    for obj,script in zip([profiles,contracts,proofs,checks],SCRIPTS[:4],strict=True):
        assert obj['generator_sha256']==sha(ROOT/script)
        for n,h in obj.get('dependencies',{}).items():assert sha(ROOT/n)==h,(script,n)
    assert checks['all_checks_pass']and not checks['native_target_executed']and not checks['host_API_executed']and not checks['full_goal_complete']and checks['primary_and_replay_use_same_ISA_engine']
    assert not checks['native_bank_root_writers_established']and not checks['native_incoming_phase_writers_established']and not checks['new_port_emission_established']
    assert checks['verified_counts']['source_obligations_rebuilt']==29 and checks['independent_A64_totals']['source_visits']==16654 and len(checks['fresh_replay_cases'])==36
    assert len(profiles['specifications'])==9 and len(profiles['cases'])==36 and len(contracts['conditional_bank_rules'])==8 and sum(r['matching_bytes']for r in contracts['live_IDA_matches'])==1536
    assert len(contracts['literal_CA54_call_candidates'])==16 and len(contracts['unclassified_literal_CA54_candidates'])==7 and len(contracts['discriminator_collision_slots'])==4
    smt={r[k]for r in proofs['proofs']for k in ['file','original_file']};assert len(smt)==58 and smt|{'daemon_aux_callers_rejected_unaligned_key.smt2'}=={p.name for p in ROOT.glob('daemon_aux_callers_*.smt2')}
    for r in proofs['proofs']:assert r['result']=='unsat'and sha(ROOT/r['file'])==r['sha256']and sha(ROOT/r['original_file'])==r['original_sha256']
    rejected=contracts['rejected_unaligned_hypothesis'];assert rejected['result']=='sat'and sha(ROOT/rejected['query_file'])==rejected['query_sha256']
    for row in profiles['cases']:
        r=row['profile'];assert r['fixture_PC_transitions']==0 and r['boundary']['kind']=='after_original_record_spill'
        assert all(int(e['address'],16)+e['size_bytes']<=0x6800001000 or int(e['address'],16)>=0x6800001008 for e in r['source_reads']),'input bytes read before selected stop'
    for name in SCRIPTS:ast.parse((ROOT/name).read_text(),filename=name)
    text=(BASE/REPORTS[0]).read_text();assert text.isascii()and all('| AC'+str(j)+' |'in text for j in range(1,13))and all('QG'+str(j)+':'in text for j in range(1,8))
    links=0
    for name in REPORTS:
        for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
            raw=raw.strip('<>')
            if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
            target=Path(raw.split('#',1)[0]);target=target if target.is_absolute()else BASE/target
            if target.name not in ['daemon_aux_callers_delivery.json','daemon_aux_callers_quality_gates.json']:assert target.exists(),(name,raw)
            links+=1
    d={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':4756,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'accepted_SMT_files':58,'rejected_SAT_hypotheses':1,'input_byte_reads_before_stop':0,'Python_syntax_checks':len(SCRIPTS),'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/'daemon_aux_callers_delivery.json').write_text(json.dumps(d,indent=2)+'\n')
    q={'scope':'Nine original24-byte record producers and conditional source paths to adapter/entry/save; native bank/phase writers, input owners and720-byte/transport joins unknown.','generator_sha256':sha(__file__),'verified_counts':checks['verified_counts'],'independent_A64_totals':checks['independent_A64_totals'],'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in EVIDENCE},'primary_and_replay_use_same_ISA_engine':True,'native_target_executed':False,'native_bank_root_writers_established':False,'native_incoming_phase_writers_established':False,'host_API_executed':False,'idb_mutated':False,'new_port_emission_established':False,'full_goal_complete':False,'goal_status':'active'}
    for j in range(1,8):q['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', AC1-AC12, source identities, fresh replay, alignment counterexample and artifact preservation'}
    (ROOT/'daemon_aux_callers_quality_gates.json').write_text(json.dumps(q,indent=2)+'\n');print(json.dumps({'prior_artifacts_checked':4756,'unchanged':unchanged,'changed':len(changed),'local_links_checked':links,'scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
