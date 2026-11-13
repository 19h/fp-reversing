#!/usr/bin/env python3
"""Verify source evidence, path hygiene and the exact network-report delta.

O(receipts+owned bytes+source+manifest+queries) time/space; 30 s/query.
No native API/IPC, allocation/free, hardware PAC or IDB mutation.
"""
import json,subprocess
from collections import Counter
from pathlib import Path
from hashlib import sha256
from compression import zstd
import z3
from daemon_receive_tools import SOURCE,IMAGE
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene
from verify_daemon_iokit_result_publication import decoded_hex_hygiene
import verify_corefp_late_preparation_publication as H
import recover_daemon_network_record as R
import audit_daemon_network_record as A

ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='b2f88394c7d20751fc9e046a7b3e3818f6c89134'
BASELINE_SHA='9e64daa02c1d53e1673c358434e59a175ca600cf6218c23d7061201539fb5b66'
CHECKS_SHA='64fc7eb0c7c84641109e9fd7512595118561f4d44cae33128d78bdb4ded064c0'
AUDIT_SHA='7f7a5b59058ca28bf0f64e72aa069875373d4504366d219aee5724a5699e2b50'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'mach_ports_report.md', 'interface_abi_report.md', 'interface_investigation_status.md', 'obfuscated_routines_report.md', 'daemon_network_identity_report.md', 'foundational_triage_report.md', 'daemon_iokit_sync_report.md', 'corefp_client_paths_report.md', 'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'daemon_network_record_report.md','triage_evidence/recover_daemon_network_record.py',
       'triage_evidence/audit_daemon_network_record.py','triage_evidence/verify_daemon_network_record_publication.py',
       'triage_evidence/daemon_network_record_checks.json','triage_evidence/daemon_network_record_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/daemon_network_record_checks.json','triage_evidence/daemon_network_record_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'conditional_cases': 8, 'cold_cases': 8, 'warm_cases': 96, 'zero_cases': 8, 'intervals': 432, 'source_visits': 39616, 'reads': 9128, 'writes': 3488, 'logical_edges': 1008}
INDEPENDENT={'authenticated_entry_origins_checked': 8, 'register_values_checked': 1281536, 'NZCV_values_checked': 40048, 'read_bytes_checked': 50040, 'source_visits': 39616, 'original_authenticated_edges_checked': 712, 'write_bytes_checked': 22112, 'saved_continuation_origins_checked': 16}
INITIALIZER={'source_visits': 42792, 'cache_helper_visits': 1296, 'logical_PAC_instructions': 24, 'write_effects_checked': 5672, 'write_bytes_checked': 36360, 'uninterpreted_probe_read_bytes': 1632, 'read_effects_checked': 8872, 'read_bytes_checked': 43240, 'logical_edges_checked': 168, 'helper_preservation_checks': 24, 'new_live_root_cells_checked': 120, 'live_bank_cells_checked': 48, 'final_boundaries_checked': 24, 'restored_outer_frames_checked': 8}

def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)

def receipts():
    assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
    e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
    assert e['generator_sha256']==a['generator_sha256']==sha(R.__file__) and a['auditor_sha256']==sha(A.__file__)
    assert a['checks_sha256']==CHECKS_SHA and e['dependencies']==a['dependencies']=={n:sha(ROOT/n) for n in R.DEPS}
    assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert e['verified_counts']==a['verified_counts']==COUNTS and a['independent_totals']==INDEPENDENT and a['initializer_totals']==INITIALIZER
    for name,n,want in [('independent_lifts',432,INDEPENDENT),('initializer_lifts',24,INITIALIZER)]:
        assert len(a[name])==n;total=Counter()
        for result in a[name]:assert result['all_checks_pass'];total.update(result['verified_counts'])
        assert dict(total)==want
    counts=Counter()
    for row in R.intervals(e):
        assert len(row['source_visits'])==len(row['source_frames']) and not row['native_target_executed']
        counts.update(source_visits=len(row['source_visits']),reads=len(row['source_reads']),writes=len(row['source_writes']),logical_edges=len(row['logical_edges']))
        for v in row['source_visits']:assert v['bytes_hex']==IMAGE.read(int(v['pc'],16),4).hex()
    assert {k:COUNTS[k] for k in counts}==dict(counts)
    assert e['root_writer_evidence']==R.root_evidence() and len(e['root_writer_evidence'])==12
    assert sum(len(c['fields']) for c in e['root_writer_evidence'])==60
    assert e['source_regions']==R.source() and e['bank_rules']==R.banks() and len(e['bank_rules'])==3
    used={int(x['address'],16) for r in R.intervals(e) for x in r['source_reads'] if int(x['address'],16) in R.FIXUPS}
    assert e['source_fixups']==R.Parent.Parent.Env.fixups(used) and len(e['source_fixups']['records'])==38
    starts,joins=A.interfaces(e);assert a['consumer_interfaces']==A.consumers(e,starts,joins)
    assert a['consumer_interfaces']['verified_counts']=={'additional_root_joins':216,'cold_main_port_joins':8,
        'additional_controller_image_joins':96,'warm_record_joins':96,'zero_return_and_restoration_joins':8}
    assert len(e['source_proofs'])==len(R.obligations())==a['source_queries_unsat']==8
    for q in e['source_proofs']:
        solver=z3.Solver();solver.set(timeout=30000);solver.from_string(q['query']);assert solver.check()==z3.unsat and q['premises_nonvacuous']
    assert a['SDK_checks']==A.sdk_checks() and a['SDK_checks']['exit_code']==0 and a['all_checks_pass']
    assert all(not x[k] for x in [e,a] for k in ['native_API_executed','native_daemon_kext_pairing_established','native_epoch_join_established','full_goal_complete'])
    report=read(BASE/'daemon_network_record_report.md')
    assert all(f'| NR{j} |' in report for j in range(1,8)) and all(f'| NR-A{j} |' in report for j in range(1,10))
    assert all(f'**QG{j}**' in report for j in range(1,8))
    return e,a

def main():
    e,a=receipts();raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST))
    before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==8706 and len(after)==8712 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
    assert {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256'] and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
    assert new['validation']['daemon_network_record_increment_checks']==COUNTS
    assert new['validation']['daemon_network_record_replay_checks']==INDEPENDENT
    assert new['validation']['daemon_network_record_initializer_checks']==INITIALIZER
    assert new['validation']['daemon_network_record_static_scope']==e['scope']
    assert new['validation']['daemon_network_record_source_queries_unsat']==8
    assert new['validation']['daemon_network_record_SDK_compile_exit']==0
    assert new['validation']['reports']==old['validation']['reports']+1==499
    assert new['goal_status']=='active' and new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    fields=extent=0
    for obj in [e,a]:
        path_hygiene(json.dumps(H.paths_in_typed_payloads(obj)).encode());n,b=decoded_hex_hygiene(obj);fields+=n;extent+=b
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
    assert delta==OWNED,delta^OWNED
    print(json.dumps({'unchanged_manifest_entries':8697,'owned_physical_files':len(OWNED),'original_inputs_preserved':3,'reports':499,
                      'independent_lifts':432,'initializer_lifts':24,'source_queries_unsat':8,'original_fixup_records':38,
                      'source_root_writers':60,'live_root_checks':120,'cold_main_port_boundaries':8,'warm_records':96,
                      'zero_return_restorations':8,'SDK_compile_exit':0,'decoded_hex_fields_path_checked':fields,
                      'decoded_hex_bytes_path_checked':extent,'native_API_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':main()
