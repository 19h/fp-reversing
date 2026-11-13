#!/usr/bin/env python3
"""Pin result-channel proofs, independent A64 coverage and publication delta.

O(receipts+owned decoded content+manifest) time/space plus 30 s/query.
Native APIs/IPC, IDA mutation and Git-history rewriting do not execute.
"""
import json
import subprocess
from collections import Counter
from hashlib import sha256
from pathlib import Path
from compression import zstd
import z3
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene
import verify_corefp_late_preparation_publication as H
import recover_daemon_iokit_result as R
import audit_daemon_iokit_result as A

ROOT=Path(__file__).resolve().parent; BASE=ROOT.parent
PREVIOUS='9b2af45764f91538d5e9f2d003e695bc35d18720'
BASELINE_SHA='7cd7181930e6588333877375b9d1982e095093c62acb50c0ff2a629d9e73a948'
CHECKS_SHA='8602bdf334f6f52a96e4fe5be4528d89b4653369bda02c17b607e64b6f4f1525'
AUDIT_SHA='6b4ab1acb2a39c5390f46f6517fd3cca35a2ea0d552c22c3a1b9cd5ceee3d634'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','foundational_triage_report.md','interface_abi_report.md',
         'interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md',
         'daemon_postblock_dispatch_report.md','versioned_wrapper_error_return_report.md',
         'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'daemon_iokit_result_report.md','triage_evidence/recover_daemon_iokit_result.py',
       'triage_evidence/audit_daemon_iokit_result.py','triage_evidence/verify_daemon_iokit_result_publication.py',
       'triage_evidence/daemon_iokit_result_checks.json','triage_evidence/daemon_iokit_result_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/daemon_iokit_result_checks.json','triage_evidence/daemon_iokit_result_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'parent_cases':4,'cases':20,'intervals':28,'source_visits':15612,'read_events':1448,'write_events':968}
INDEPENDENT={'source_visits': 31224, 'read_bytes_checked': 18912, 'register_effects_checked': 27896, 'NZCV_effects_checked': 720, 'write_bytes_checked': 9536, 'write_effects_checked': 1936, 'unknown_copied_bytes_checked': 0}

def git(*args): return subprocess.check_output(['git',*args],cwd=BASE)

def decoded_hex_hygiene(obj):
    n=0; extent=0
    if isinstance(obj,dict):
        for key,value in obj.items():
            if isinstance(value,str) and (key in ['hex','bytes'] or key.endswith('_hex')):
                raw=bytes.fromhex(value); path_hygiene(raw); n+=1; extent+=len(raw)
            else:
                a,b=decoded_hex_hygiene(value); n+=a; extent+=b
    elif isinstance(obj,list):
        for value in obj:
            a,b=decoded_hex_hygiene(value); n+=a; extent+=b
    return n,extent

def receipts():
    assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
    e=json.loads(read(ROOT/(R.P+'_checks.json'))); a=json.loads(read(ROOT/(R.P+'_audit.json')))
    assert e['generator_sha256']==a['generator_sha256']==sha(R.__file__) and a['auditor_sha256']==sha(A.__file__)
    assert a['checks_sha256']==CHECKS_SHA and e['dependencies']==a['dependencies']=={n:sha(ROOT/n) for n in e['dependencies']}
    assert e['parent_checks_sha256']==R.PIN==sha(ROOT/'daemon_postblock_dispatch_checks.json')
    assert e['wrapper_checks_sha256']==R.WRAPPER_PIN==sha(ROOT/'versioned_wrapper_error_return_checks.json')
    assert e['source_sha256']==a['source_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert e['source_regions']==R.source() and e['verified_counts']==a['verified_counts']==COUNTS
    used={int(s,16) for c in e['cases'] for t in c['intervals'] for s in t['used_fixups']}
    assert e['source_fixups']==R.Core.verify_fixups(used)
    fresh=R.obligations(); assert len(fresh)==len(e['source_proofs'])==a['source_queries_unsat']==8
    assert [q['label'] for q in fresh]==[q['label'] for q in e['source_proofs']]
    for q in e['source_proofs']:
        s=z3.Solver(); s.set(timeout=30000); s.from_string(q['query'])
        assert q['premises_nonvacuous'] and q['result']=='unsat' and s.check()==z3.unsat
    post=json.loads(read(ROOT/'daemon_postblock_dispatch_checks.json'))
    assert len(a['independent_replays'])==40 and a['independent_totals']==INDEPENDENT
    assert INDEPENDENT['source_visits']==2*COUNTS['source_visits']==31224
    counts=Counter(); intervals=0; retired=0; copied=0
    for ix,c in enumerate(e['cases']):
        p=post['cases'][c['parent_case_index']]
        assert c['configuration']==p['configuration'] and a['interface_joins'][ix]==A.interface(c,p)
        counts.update(c['counts']); retired+=32 if c['free_return_premise'] else 0
        copied+=16 if a['interface_joins'][ix]['extended_copyback'] else 0
        for pattern,run in zip([0,3],a['independent_replays'][2*ix:2*ix+2]):
            assert run['parent_case_index']==c['parent_case_index'] and run['variant']==c['variant'] and run['pattern']==pattern and run['all_checks_pass']
            assert len(run['intervals'])==len(c['intervals'])
            for trace,check in zip(c['intervals'],run['intervals']):
                assert check['boundary']==trace['boundary'] and check['all_checks_pass'] and not check['native_target_executed']
                assert check['verified_counts']['source_visits']==len(trace['steps']); intervals+=1
        model=c['API_return_premise']; assert model['pc']==hex(R.CALL) and not model['native_API_executed']
        assert set(model['preserved'])=={'sp',*('x'+str(j) for j in range(18,30))} and set(model['preserved_D8_D15'])==set(map(str,range(8,16)))
    assert counts==Counter({k:v for k,v in COUNTS.items() if k not in ['parent_cases','cases']})
    assert intervals==56 and retired==256 and copied==64
    for obj in [e,a]: assert not obj['native_API_executed'] and not obj['native_daemon_kext_pairing_established'] and not obj['full_goal_complete']
    assert a['all_checks_pass'] and a['reproduced_parent_totals']['source_visits']==13300
    report=read(BASE/'daemon_iokit_result_report.md')
    assert all(f'| IR{j} |' in report for j in range(1,9)) and all(f'**QG{j}**' in report for j in range(1,8))
    return e,a

def main():
    e,a=receipts(); raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST))
    before={r['path']:r for r in old['files']}; after={r['path']:r for r in new['files']}
    assert len(before)==8639 and len(after)==8645 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
    assert {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']: assert sha(BASE/r['path'])==r['sha256'] and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED: assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
    assert new['validation']['daemon_iokit_result_increment_checks']==COUNTS and new['validation']['daemon_iokit_result_replay_checks']==INDEPENDENT
    assert new['validation']['daemon_iokit_result_static_scope']==e['scope'] and new['validation']['reports']==old['validation']['reports']+1==488
    assert new['goal_status']=='active' and new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
    for p in ARCHIVES: assert not(BASE/p).exists()
    for p in OWNED: path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    fields=0; extent=0
    for obj in [e,a]:
        path_hygiene(json.dumps(H.paths_in_typed_payloads(obj)).encode()); n,b=decoded_hex_hygiene(obj); fields+=n; extent+=b
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
    assert delta==OWNED,delta^OWNED
    print(json.dumps({'unchanged_manifest_entries':8630,'owned_physical_files':len(OWNED),'original_inputs_preserved':3,'reports':488,
                      'source_cases':20,'independent_case_replays':40,'independent_intervals':56,'new_original_A64_visits':31224,
                      'separately_replayed_parent_visits':13300,'source_queries_unsat':8,'retirement_overwrite_bytes':256,
                      'extended_copyback_bytes':64,'decoded_hex_fields_path_checked':fields,'decoded_hex_bytes_path_checked':extent,
                      'native_API_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__': main()
