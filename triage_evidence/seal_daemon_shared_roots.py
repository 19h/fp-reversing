#!/usr/bin/env python3
"""Seal shared-core initialization evidence and preserve prior publications.
O(prior bytes + links) time, O(manifest + largest JSON) space. Six owned existing
index/publisher paths may change; native targets, APIs, IDBs and memories do not.
"""
import ast,hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
REPORTS=['daemon_shared_roots_report.md','obfuscated_routines_report.md','mach_ports_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md']
CHANGED=set(REPORTS[1:]+['triage_evidence/validate_rpc502_sidecar_delivery.py'])
SCRIPTS=['probe_daemon_shared_roots.py','capture_daemon_shared_roots.py','prove_daemon_shared_roots.py','validate_daemon_shared_roots.py','seal_daemon_shared_roots.py','verify_daemon_shared_roots_publication.py']
EVIDENCE=['daemon_shared_roots_profiles.json','daemon_shared_roots_source.json','daemon_shared_roots_proofs.json','daemon_shared_roots_checks.json']
def sha(p):
    with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def load(n):return json.loads((ROOT/n).read_text())
def main():
    prior=ROOT/'daemon_shared_roots_prior_manifest.json';assert sha(prior)=='9271ae8ce7daf3fa720133edbd7925845cc672781e698704ded959cf8f312577';m=json.loads(prior.read_text());assert len(m['files'])==4830;changed=[];unchanged=0
    for row in m['files']:
        p=BASE/row['path'];assert p.is_file();h=sha(p)
        if row['path']in CHANGED:assert h!=row['sha256'];changed.append({'path':row['path'],'prior_sha256':row['sha256'],'sha256':h})
        else:assert h==row['sha256']and p.stat().st_size==row['size_bytes'],row['path'];unchanged+=1
    assert {r['path']for r in changed}==CHANGED and unchanged==4824
    for r in m['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and(BASE/r['path']).stat().st_size==r['size_bytes']
    assert sha('/Users/___/Downloads/zut/fairplayd.arm64e')=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    profiles,source,proofs,checks=[load(n)for n in EVIDENCE]
    for obj,script in zip([profiles,source,proofs,checks],SCRIPTS[:4],strict=True):
        assert obj['generator_sha256']==sha(ROOT/script)
        for n,h in obj.get('dependencies',{}).items():assert sha(ROOT/n)==h,(script,n)
    assert checks['all_checks_pass']and not checks['native_target_executed']and not checks['host_API_executed']and not checks['full_goal_complete']and checks['primary_and_replay_use_same_ISA_engine']
    assert not checks['complete_prologue_all_state_invariance_proved']and not checks['later_emitter_epoch_join_established']and not checks['new_port_emission_established']
    assert checks['verified_counts']['source_obligations_rebuilt']==6 and checks['independent_A64_totals']['source_visits']==13056 and len(checks['fresh_replay_cases'])==8
    assert len(profiles['cases'])==8 and len(source['field_ledgers'])==8 and len(source['protected_key_projection'])==20
    assert source['actual_controller_pointer_at_F9C8']=='0x1010b8dc8'and source['prior_aux_caller_controller_fixture']=='0x1010b66a8'
    assert checks['next_target_counts']=={'0x100610388':4,'0x1004d4aac':4}
    for l in source['field_ledgers']:
        assert len(l['fields'])==10 and l['setup_source_stores']==129
        for f in l['fields']:assert f['subsequent_overwrites_before_stop']==0 and f['writer']['size_bytes']==8
    smt={r[k]for r in proofs['proofs']for k in ['file','original_file']};assert len(smt)==12 and smt=={p.name for p in ROOT.glob('daemon_shared_roots_*.smt2')}
    for r in proofs['proofs']:assert r['result']=='unsat'and sha(ROOT/r['file'])==r['sha256']and sha(ROOT/r['original_file'])==r['original_sha256']
    for name in SCRIPTS:ast.parse((ROOT/name).read_text(),filename=name)
    text=(BASE/REPORTS[0]).read_text();assert text.isascii()and all('| SR'+str(j)+' |'in text for j in range(1,11))and all('QG'+str(j)+':'in text for j in range(1,8))
    links=0
    for name in REPORTS:
        for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)',(BASE/name).read_text()):
            raw=raw.strip('<>')
            if raw.startswith('#')or re.match(r'^[a-zA-Z][\w+.-]*://',raw):continue
            target=Path(raw.split('#',1)[0]);target=target if target.is_absolute()else BASE/target
            if target.name not in ['daemon_shared_roots_delivery.json','daemon_shared_roots_quality_gates.json']:assert target.exists(),(name,raw)
            links+=1
    d={'scope':__doc__,'generator_sha256':sha(__file__),'prior_manifest_sha256':sha(prior),'prior_artifacts_checked':4830,'prior_artifacts_unchanged':unchanged,'allowed_changes':changed,'original_inputs_preserved':len(m['inputs_preserved']),'accepted_SMT_files':12,'Python_syntax_checks':len(SCRIPTS),'local_links_checked':links,'all_checks_pass':True,'goal_status':'active','full_goal_complete':False};(ROOT/'daemon_shared_roots_delivery.json').write_text(json.dumps(d,indent=2)+'\n')
    q={'scope':'Strict core entry/setup initialization epoch, ten field writers, local key/tag/gate/frame equations. Complete all-state prologue invariance and later emitter/native/transport epochs unproved.','generator_sha256':sha(__file__),'verified_counts':checks['verified_counts'],'independent_A64_totals':checks['independent_A64_totals'],'report_sha256':{n:sha(BASE/n)for n in REPORTS},'evidence_sha256':{n:sha(ROOT/n)for n in EVIDENCE},'primary_and_replay_use_same_ISA_engine':True,'native_target_executed':False,'complete_prologue_all_state_invariance_proved':False,'later_emitter_epoch_join_established':False,'host_API_executed':False,'idb_mutated':False,'fresh_IDA_query_performed':False,'new_port_emission_established':False,'full_goal_complete':False,'goal_status':'active'}
    for j in range(1,8):q['QG'+str(j)]={'status':'pass_for_increment','evidence':'Report QG'+str(j)+', SR1-SR10, source identities, strict/fresh replay, writer ledgers and artifact preservation'}
    (ROOT/'daemon_shared_roots_quality_gates.json').write_text(json.dumps(q,indent=2)+'\n');print(json.dumps({'prior_artifacts_checked':4830,'unchanged':unchanged,'changed':len(changed),'local_links_checked':links,'scoped_gates_pass':True,'goal_status':'active'}),flush=True)
if __name__=='__main__':main()
