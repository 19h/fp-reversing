#!/usr/bin/env python3
"""Verify bank-origin evidence, explicit continuity gap and exact publication.

O(receipts+owned decoded content+text words+manifest) time/space, 30 s/query.
No native API/IPC, IDA mutation or Git-history rewriting executes.
"""
import json,subprocess
from collections import Counter
from hashlib import sha256
from pathlib import Path
from compression import zstd
import z3
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene
from verify_daemon_iokit_result_publication import decoded_hex_hygiene
import verify_corefp_late_preparation_publication as H
import recover_daemon_return_bank_origins as R
import audit_daemon_return_bank_origins as A

ROOT=Path(__file__).resolve().parent; BASE=ROOT.parent
PREVIOUS='34494bc7ecc624638dc727202756b3450d5d6dc4'
BASELINE_SHA='c17076ab86ca96bbf4b377c62e5cb223eb1e383c0835a84203bf3a477f159548'
CHECKS_SHA='9e5d75cb4a1f452a8499a3a917351283e8763335a44f264809024aaaeded3c69'
AUDIT_SHA='29b025a5602d441a2b293ed1387d6c03dec94e42d44d6aebaf472ad2cd43a96d'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','foundational_triage_report.md','interface_abi_report.md',
         'interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md',
         'daemon_iokit_error_return_report.md','daemon_shared_roots_report.md','daemon_prng_output_report.md',
         'daemon_context_transfer_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'daemon_return_bank_origins_report.md','triage_evidence/recover_daemon_return_bank_origins.py',
       'triage_evidence/audit_daemon_return_bank_origins.py','triage_evidence/verify_daemon_return_bank_origins_publication.py',
       'triage_evidence/daemon_return_bank_origins_checks.json','triage_evidence/daemon_return_bank_origins_audit.json',
       'triage_evidence/daemon_return_bank_origins_IDA_context.json'}
ARCHIVES={MANIFEST,'triage_evidence/daemon_return_bank_origins_checks.json','triage_evidence/daemon_return_bank_origins_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'conditional_caller_cases':8,'source_visits':124064,'read_events':25528,'write_events':5192,
        'upstream_cases':12,'upstream_source_visits':21396}

def git(*args): return subprocess.check_output(['git',*args],cwd=BASE)

def receipts():
    assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
    e=json.loads(read(ROOT/(R.P+'_checks.json'))); a=json.loads(read(ROOT/(R.P+'_audit.json')))
    assert e['generator_sha256']==a['generator_sha256']==sha(R.__file__) and a['auditor_sha256']==sha(A.__file__)
    assert a['checks_sha256']==CHECKS_SHA and e['dependencies']==a['dependencies']=={n:sha(ROOT/n) for n in e['dependencies']}
    assert e['parent_checks_sha256']==R.PIN==sha(ROOT/'daemon_iokit_error_return_checks.json')
    assert e['source_sha256']==a['source_sha256']=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert e['source_regions']==R.source() and e['decoder']==R.decoder() and e['literal_store_census']==R.census()
    assert e['verified_counts']==a['verified_counts']==COUNTS
    assert e['source_fixups']==R.Parent.Parent.Core.verify_fixups({int(x,16) for c in e['cases'] for x in c['trace']['used_fixups']})
    fresh=R.obligations(); assert len(fresh)==len(e['source_proofs'])==a['source_queries_unsat']==9
    assert [{k:v for k,v in q.items() if k!='query'} for q in fresh]==[{k:v for k,v in q.items() if k!='query'} for q in e['source_proofs']]
    for q in e['source_proofs']:
        solver=z3.Solver(); solver.set(timeout=30000); solver.from_string(q['query'])
        assert q['premises_nonvacuous'] and q['result']=='unsat' and solver.check()==z3.unsat
    # Independently check the report's closed key expression against source.
    q=z3.BitVec('publication_record64',64); v=R.Parent.Ingress.Algebra(); v.seed('x0',q); v.run_block(0x100427514,0x100427560)
    key=(((((q<<1)|0x5a2dd95b7f1fcb68)-q+0xd2e9135240701a4c)^0x2c6f16a258bd37d6)*0xba209ef7)
    assert z3.is_true(z3.simplify(v.read('x8')==key))
    assert len(a['conditional_caller_replays'])==16 and len(a['upstream_replays'])==24
    assert len(a['interface_joins'])==len(e['cases'])==8 and len(e['upstream_cases'])==12
    upstream_totals=Counter(); caller_totals=Counter()
    for ix,c in enumerate(e['upstream_cases']):
        for pattern,run in zip([0,3],a['upstream_replays'][2*ix:2*ix+2]):
            assert run['variant']==c['variant'] and run['configuration']==c['configuration'] and run['physical_pattern']==pattern
            assert run['boundary']==c['boundary']['pc'] and run['all_checks_pass']
            assert run['verified_counts']['source_visits']==len(c['source_visits'])
            upstream_totals.update(run['verified_counts'])
    assert dict(upstream_totals)==a['upstream_independent_totals']
    assert upstream_totals['source_visits']==42792 and upstream_totals['live_bank_cells_checked']==48
    assert upstream_totals['helper_preservation_checks']==24 and upstream_totals['restored_outer_frames_checked']==8
    assert {(c['parent_case_index'],c['variant']) for c in e['cases']}=={(j,v) for j in range(4) for v in ['API_error','provider_error_word']}
    counts=Counter()
    for ix,c in enumerate(e['cases']):
        assert a['interface_joins'][ix]==A.caller_join(c); counts.update(c['counts'])
        assert c['counts']=={'source_visits':15508,'read_events':3191,'write_events':649}
        for pattern,run in zip([0,3],a['conditional_caller_replays'][2*ix:2*ix+2]):
            assert run['parent_case_index']==c['parent_case_index'] and run['variant']==c['variant'] and run['pattern']==pattern
            assert run['boundary']==c['trace']['boundary'] and run['all_checks_pass'] and not run['native_target_executed']
            assert run['verified_counts']['source_visits']==15508
            caller_totals.update(run['verified_counts'])
    assert dict(caller_totals)==a['conditional_caller_independent_totals']
    assert caller_totals['source_visits']==248128 and caller_totals['read_bytes_checked']==286080
    assert caller_totals['register_effects_checked']==217584 and caller_totals['NZCV_effects_checked']==10080
    assert caller_totals['write_bytes_checked']==42176 and caller_totals['write_effects_checked']==10384
    assert counts==Counter({k:v for k,v in COUNTS.items() if k in ['source_visits','read_events','write_events']})
    for obj in [e,a]:
        assert not any(obj[k] for k in ['initializer_to_caller_control_join_established','native_API_executed','native_daemon_kext_pairing_established','full_goal_complete'])
    assert a['all_checks_pass'] and a['separately_replayed_prefix_totals']['source_visits']==40032
    report=read(BASE/'daemon_return_bank_origins_report.md')
    assert all(f'| BR{j} |' in report for j in range(1,10)) and all(f'**QG{j}**' in report for j in range(1,8))
    assert all(f'| BR-A{j} |' in report for j in range(1,9))
    return e,a

def main():
    e,a=receipts(); raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST))
    before={r['path']:r for r in old['files']}; after={r['path']:r for r in new['files']}
    assert len(before)==8651 and len(after)==8658 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
    assert {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']: assert sha(BASE/r['path'])==r['sha256'] and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED: assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
    assert new['validation']['daemon_return_bank_origins_increment_checks']==COUNTS
    assert new['validation']['daemon_return_bank_origins_upstream_replay_checks']==a['upstream_independent_totals']
    assert new['validation']['daemon_return_bank_origins_caller_replay_checks']==a['conditional_caller_independent_totals']
    assert new['validation']['daemon_return_bank_origins_static_scope']==e['scope'] and new['validation']['reports']==old['validation']['reports']+1==490
    assert new['goal_status']=='active' and new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
    for p in ARCHIVES: assert not(BASE/p).exists()
    for p in OWNED: path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    fields=extent=0
    for obj in [e,a,json.loads(read(ROOT/'daemon_return_bank_origins_IDA_context.json'))]:
        path_hygiene(json.dumps(H.paths_in_typed_payloads(obj)).encode()); n,b=decoded_hex_hygiene(obj); fields+=n; extent+=b
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
    assert delta==OWNED,delta^OWNED
    print(json.dumps({'unchanged_manifest_entries':8640,'owned_physical_files':len(OWNED),'original_inputs_preserved':3,'reports':490,
                      'conditional_caller_cases':8,'upstream_cases':12,'independent_case_replays':40,
                      'source_queries_unsat':9,'new_original_A64_visits':290920,'separately_replayed_prefix_visits':40032,
                      'source_state_words_checked':4992,'decoded_hex_fields_path_checked':fields,'decoded_hex_bytes_path_checked':extent,
                      'initializer_control_join_established':False,'native_API_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__': main()
