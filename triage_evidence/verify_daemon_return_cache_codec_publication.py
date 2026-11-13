#!/usr/bin/env python3
"""Verify cache-codec source/replay evidence and the exact publication delta.

O(receipts+owned decoded content+manifest+queries) time/space,30 s/query.
No native API/IPC, IDA mutation or history rewriting executes.
"""
import json,subprocess
from collections import Counter
from hashlib import sha256
from pathlib import Path
from compression import zstd
import z3
from daemon_receive_tools import SOURCE
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene
from verify_daemon_iokit_result_publication import decoded_hex_hygiene
import verify_corefp_late_preparation_publication as H
import recover_daemon_return_cache_codec as R
import audit_daemon_return_cache_codec as A

ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='01d4a49110fb441908b13432efa0e17897904e92'
BASELINE_SHA='f8359c43852c3d686e1a51abe9431653206df56f9d82cdc53981a0497605317d'
CHECKS_SHA='c398d6cbc96ac40a40585a744430e73319eb534f6362ab52a341c7090dbb0428'
AUDIT_SHA='d5298b6e731ca81ad87b56ea00fa7a1ecc5ea91f92c99ee9c2d13a5baa25c7e4'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','foundational_triage_report.md','interface_abi_report.md',
         'interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md',
         'daemon_return_bank_origins_report.md','daemon_buffer_consumer_report.md','daemon_cache_publication_report.md',
         'daemon_prng_output_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'daemon_return_cache_codec_report.md','triage_evidence/recover_daemon_return_cache_codec.py',
       'triage_evidence/audit_daemon_return_cache_codec.py','triage_evidence/verify_daemon_return_cache_codec_publication.py',
       'triage_evidence/daemon_return_cache_codec_checks.json','triage_evidence/daemon_return_cache_codec_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/daemon_return_cache_codec_checks.json','triage_evidence/daemon_return_cache_codec_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'cases':8,'source_visits':2112,'read_events':360,'write_events':72}
INDEPENDENT={'source_visits':4224,'read_bytes_checked':4672,'register_effects_checked':3808,'write_bytes_checked':832,
             'write_effects_checked':144,'unknown_copied_bytes_checked':128,'NZCV_effects_checked':128}

def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)

def receipts():
    assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
    e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
    parent=json.loads(read(ROOT/'daemon_return_bank_origins_checks.json'))
    assert e['generator_sha256']==a['generator_sha256']==sha(R.__file__) and a['auditor_sha256']==sha(A.__file__)
    assert a['checks_sha256']==CHECKS_SHA and e['dependencies']==a['dependencies']=={n:sha(ROOT/n) for n in e['dependencies']}
    assert e['parent_checks_sha256']==R.PIN==sha(ROOT/'daemon_return_bank_origins_checks.json')
    assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert e['source_regions']==R.source() and e['upstream_field_lifetimes']==R.upstream_fields(parent) and e['next_gate_dispatch']==R.gate_dispatch()
    assert e['verified_counts']==a['verified_counts']==COUNTS and a['independent_totals']==INDEPENDENT
    assert e['source_fixups']==R.Parent.Parent.Parent.Core.verify_fixups({int(x,16) for c in e['cases'] for x in c['trace']['used_fixups']})
    fresh=R.obligations();assert len(fresh)==len(e['source_proofs'])==a['source_queries_unsat']==6
    assert [q['label'] for q in fresh]==[q['label'] for q in e['source_proofs']]
    assert A.loop_proof()['label']==a['additional_loop_source_proof']['label']
    for q in [*e['source_proofs'],a['additional_loop_source_proof']]:
        solver=z3.Solver();solver.set(timeout=30000);solver.from_string(q['query'])
        assert q['premises_nonvacuous'] and q['result']=='unsat' and solver.check()==z3.unsat
    assert len(e['cases'])==len(a['interface_joins'])==8 and len(a['independent_replays'])==16 and len(a['upstream_replays'])==24
    assert {(c['parent_case_index'],c['variant']) for c in e['cases']}=={(j,v) for j in range(4) for v in ['API_error','provider_error_word']}
    expected={0:([0xce,0x97],18),1:([0xb3,0x90],26),2:([6,0x4d],18),3:([0x14,0x3a],18)}
    totals=Counter()
    for ix,(c,p) in enumerate(zip(e['cases'],parent['cases'])):
        join=A.interface(c,p);assert join==a['interface_joins'][ix]
        assert c['counts']=={'source_visits':264,'read_events':45,'write_events':9}
        values,count=expected[c['parent_case_index']]
        assert [A.scalar(r['output']['value']) for r in join['codec_iterations']]==values and join['next_gate_count_low16']==count
        for r in join['codec_iterations']:
            assert r['decoded_window_base']=='0x100822058' and r['decoded_window_mask']=='0xfff0c01200007fff'
        assert join['new_post_frontier_visits']==241 and join['overlapping_parent_tail_visits']==23
        for pattern,run in zip([0,3],a['independent_replays'][2*ix:2*ix+2]):
            assert run['parent_case_index']==c['parent_case_index'] and run['variant']==c['variant'] and run['pattern']==pattern
            assert run['boundary']==c['trace']['boundary'] and run['all_checks_pass'] and not run['native_target_executed']
            assert run['verified_counts']['source_visits']==264;totals.update(run['verified_counts'])
    assert dict(totals)==INDEPENDENT and a['separately_replayed_prefix_totals']['source_visits']==287792
    up=Counter()
    for ix,p in enumerate(parent['upstream_cases']):
        for pattern,run in zip([0,3],a['upstream_replays'][2*ix:2*ix+2]):
            assert run['variant']==p['variant'] and run['configuration']==p['configuration'] and run['physical_pattern']==pattern
            assert run['boundary']==p['boundary']['pc'] and run['all_checks_pass'];up.update(run['verified_counts'])
    assert dict(up)==a['upstream_independent_totals'] and up['source_visits']==42792 and up['live_cache_root_cells_checked']==48
    assert len(a['gate_controls'])==len(a['loop_controls'])==24
    assert {(int(c['count32'],16),int(c['pointer64'],16)) for c in a['gate_controls']}=={(n,p) for n in [0,1,18,65536,0xffff0000,0xffffffff] for p in [0,1,1<<63,(1<<64)-1]}
    assert {(c['byte'],int(c['left32'],16),int(c['target32'],16)) for c in a['loop_controls']}=={(b,n,t) for b in [0,1,127,128,254,255] for n,t in [(0,0),(1,0),(2,0),(0,0xffffffff)]}
    assert all(c['all_checks_pass'] for c in a['gate_controls']+a['loop_controls'])
    assert sum(c['source_visits'] for c in a['gate_controls']+a['loop_controls'])==432
    for obj in [e,a]:assert not any(obj[k] for k in ['initializer_to_caller_control_join_established','native_API_executed','native_daemon_kext_pairing_established','full_goal_complete'])
    assert a['all_checks_pass'];report=read(BASE/'daemon_return_cache_codec_report.md')
    assert all(f'| RC{j} |' in report for j in range(1,9)) and all(f'| RC-A{j} |' in report for j in range(1,9))
    assert all(f'**QG{j}**' in report for j in range(1,8))
    return e,a

def main():
    e,a=receipts();raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST))
    before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==8658 and len(after)==8664 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
    assert {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256'] and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
    assert new['validation']['daemon_return_cache_codec_increment_checks']==COUNTS
    assert new['validation']['daemon_return_cache_codec_replay_checks']==INDEPENDENT
    assert new['validation']['daemon_return_cache_codec_upstream_replay_checks']==a['upstream_independent_totals']
    assert new['validation']['daemon_return_cache_codec_static_scope']==e['scope'] and new['validation']['reports']==old['validation']['reports']+1==491
    assert new['goal_status']=='active' and new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    fields=extent=0
    for obj in [e,a]:
        path_hygiene(json.dumps(H.paths_in_typed_payloads(obj)).encode());n,b=decoded_hex_hygiene(obj);fields+=n;extent+=b
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
    assert delta==OWNED,delta^OWNED
    print(json.dumps({'unchanged_manifest_entries':8647,'owned_physical_files':len(OWNED),'original_inputs_preserved':3,'reports':491,
                      'conditional_caller_cases':8,'independent_case_replays':40,'source_queries_unsat':7,'local_A64_controls':48,
                      'caller_replay_visits':4224,'new_post_frontier_replay_visits':3856,'overlapping_parent_tail_replay_visits':368,
                      'separately_replayed_prefix_visits':287792,'upstream_replay_visits':42792,'local_A64_control_visits':432,
                      'generated_bytes':16,'loop_readbacks':16,'copied_unknown_byte_effects_checked':128,
                      'decoded_hex_fields_path_checked':fields,'decoded_hex_bytes_path_checked':extent,
                      'initializer_control_join_established':False,'native_API_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':main()
