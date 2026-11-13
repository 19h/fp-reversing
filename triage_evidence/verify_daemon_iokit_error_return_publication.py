#!/usr/bin/env python3
"""Pin error-return source/replay receipts and the exact publication delta.

O(receipts+owned decoded content+manifest) time/space, 30 s/query.
No native API/IPC, IDA mutation or Git-history rewriting executes.
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
from verify_daemon_iokit_result_publication import decoded_hex_hygiene
import verify_corefp_late_preparation_publication as H
import recover_daemon_iokit_error_return as R
import audit_daemon_iokit_error_return as A

ROOT=Path(__file__).resolve().parent; BASE=ROOT.parent
PREVIOUS='dffb83d7915ebad64368f202a461fc8ca814aaf6'
BASELINE_SHA='b8e6efee7199e6779b9beddea09c20cb98d14da036e7d813a95103eb5d181b36'
CHECKS_SHA='191d641b67e9200cb7f906a0b96f3c89715cfeb1936a910cb4febdbfa9b6cc83'
AUDIT_SHA='122c82e86a193613de78446f60a398f9e84124a8614594115bc130129e1b820d'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','foundational_triage_report.md','interface_abi_report.md',
         'interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md',
         'daemon_iokit_result_report.md','daemon_versioned_ingress_report.md',
         'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'daemon_iokit_error_return_report.md','triage_evidence/recover_daemon_iokit_error_return.py',
       'triage_evidence/audit_daemon_iokit_error_return.py','triage_evidence/verify_daemon_iokit_error_return_publication.py',
       'triage_evidence/daemon_iokit_error_return_checks.json','triage_evidence/daemon_iokit_error_return_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/daemon_iokit_error_return_checks.json','triage_evidence/daemon_iokit_error_return_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'cases':8,'source_visits':4200,'read_events':472,'write_events':328}
INDEPENDENT={'source_visits':8400,'read_bytes_checked':6880,'register_effects_checked':7648,
             'NZCV_effects_checked':96,'write_bytes_checked':4320,'write_effects_checked':656,'unknown_copied_bytes_checked':128}

def git(*args): return subprocess.check_output(['git',*args],cwd=BASE)

def receipts():
    assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
    e=json.loads(read(ROOT/(R.P+'_checks.json'))); a=json.loads(read(ROOT/(R.P+'_audit.json')))
    assert e['generator_sha256']==a['generator_sha256']==sha(R.__file__) and a['auditor_sha256']==sha(A.__file__)
    assert a['checks_sha256']==CHECKS_SHA and e['dependencies']==a['dependencies']=={n:sha(ROOT/n) for n in e['dependencies']}
    assert e['parent_checks_sha256']==R.PIN==sha(ROOT/'daemon_iokit_result_checks.json')
    assert e['source_sha256']==a['source_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert e['source_regions']==R.source() and e['verified_counts']==a['verified_counts']==COUNTS
    assert e['source_fixups']==R.Parent.Core.verify_fixups({int(x,16) for c in e['cases'] for x in c['trace']['used_fixups']})
    fresh=R.obligations(); assert len(fresh)==len(e['source_proofs'])==a['source_queries_unsat']==11
    assert [q['label'] for q in fresh]==[q['label'] for q in e['source_proofs']]
    for q in e['source_proofs']:
        solver=z3.Solver(); solver.set(timeout=30000); solver.from_string(q['query'])
        assert q['premises_nonvacuous'] and q['result']=='unsat' and solver.check()==z3.unsat
    pins,old,ingress,preparations,previous=R.Parent.Parent.inputs()
    parent=json.loads(read(ROOT/'daemon_iokit_result_checks.json')); post=json.loads(read(ROOT/'daemon_postblock_dispatch_checks.json'))
    assert len(a['independent_replays'])==16 and a['independent_totals']==INDEPENDENT
    counts=Counter(); copied=0
    assert {(c['parent_case_index'],c['variant']) for c in e['cases']}=={(j,v) for j in range(4) for v in ['API_error','provider_error_word']}
    for ix,c in enumerate(e['cases']):
        cfg=c['configuration']; p=next(x for x in parent['cases'] if x['parent_case_index']==c['parent_case_index'] and x['variant']==c['variant'])
        po=post['cases'][c['parent_case_index']]; assert cfg==p['configuration']==po['configuration']
        original=next(x for x in ingress['cases'] if x['configuration']['epoch']==cfg['epoch'] and x['configuration']['name']==cfg['parent_variant'])
        prep=next(x for x in preparations['cases'] if x['configuration']['epoch']==cfg['epoch'] and x['configuration']['name']==cfg['preparation_variant'])
        processing=next(x for x in previous['cases'] if x['configuration']['epoch']==cfg['epoch'] and x['configuration']['name']==cfg['name'])
        assert a['interface_joins'][ix]==A.interface(c,p,original,prep,processing,po)
        counts.update(c['counts']); copied+=8
        for pattern,run in zip([0,3],a['independent_replays'][2*ix:2*ix+2]):
            assert run['parent_case_index']==c['parent_case_index'] and run['variant']==c['variant'] and run['pattern']==pattern
            assert run['boundary']==c['trace']['boundary'] and run['all_checks_pass'] and not run['native_target_executed']
            assert run['verified_counts']['source_visits']==len(c['trace']['steps'])==525
    assert counts==Counter({k:v for k,v in COUNTS.items() if k!='cases'}) and copied==64
    assert INDEPENDENT['source_visits']==2*COUNTS['source_visits']==8400 and INDEPENDENT['unknown_copied_bytes_checked']==2*copied
    for obj in [e,a]: assert not obj['native_API_executed'] and not obj['native_daemon_kext_pairing_established'] and not obj['full_goal_complete']
    assert a['all_checks_pass'] and a['separately_replayed_prefix_totals']['source_visits']==31632
    report=read(BASE/'daemon_iokit_error_return_report.md')
    assert all(f'| ER{j} |' in report for j in range(1,9)) and all(f'**QG{j}**' in report for j in range(1,8))
    assert all(f'| ER-A{j} |' in report for j in range(1,7))
    return e,a

def main():
    e,a=receipts(); raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST))
    before={r['path']:r for r in old['files']}; after={r['path']:r for r in new['files']}
    assert len(before)==8645 and len(after)==8651 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
    assert {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']: assert sha(BASE/r['path'])==r['sha256'] and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED: assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
    assert new['validation']['daemon_iokit_error_return_increment_checks']==COUNTS and new['validation']['daemon_iokit_error_return_replay_checks']==INDEPENDENT
    assert new['validation']['daemon_iokit_error_return_static_scope']==e['scope'] and new['validation']['reports']==old['validation']['reports']+1==489
    assert new['goal_status']=='active' and new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
    for p in ARCHIVES: assert not(BASE/p).exists()
    for p in OWNED: path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    fields=0; extent=0
    for obj in [e,a]:
        path_hygiene(json.dumps(H.paths_in_typed_payloads(obj)).encode()); n,b=decoded_hex_hygiene(obj); fields+=n; extent+=b
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
    assert delta==OWNED,delta^OWNED
    print(json.dumps({'unchanged_manifest_entries':8636,'owned_physical_files':len(OWNED),'original_inputs_preserved':3,'reports':489,
                      'source_cases':8,'independent_case_replays':16,'new_original_A64_visits':8400,'separately_replayed_prefix_visits':31632,
                      'source_queries_unsat':11,'unknown_copied_bytes_checked':128,'decoded_hex_fields_path_checked':fields,
                      'decoded_hex_bytes_path_checked':extent,'native_API_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__': main()
