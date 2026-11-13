#!/usr/bin/env python3
"""Verify exact network-gate publication, source receipts and path scrub.

O(receipts+owned bytes+source+manifest+queries) time/space; 30 s/query.
No native API/IPC, allocation/free or hardware PAC executes.
"""
import json,subprocess
from collections import Counter
from pathlib import Path
from hashlib import sha256
from compression import zstd
import z3
from daemon_receive_tools import SOURCE,IMAGE,FIXUPS,verify_original_fixups
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene
from verify_daemon_iokit_result_publication import decoded_hex_hygiene
import verify_corefp_late_preparation_publication as H
import recover_daemon_network_gate as R
import audit_daemon_network_gate as A

ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='6688ef2d4f786af93dc1d31f707262ace9754a94'
BASELINE_SHA='b8dcdd1e074bfaff0153179a11146b7f6edca263a2a24085cb6869b2140a5a94'
CHECKS_SHA='734dab1b800e9c528a2073b9c093d9fe481565308f48b72ea9af178764561884'
AUDIT_SHA='7d8a3ea103a5b8a5775d30e895a4f8061e27d0ba10fa7f874d927d183409aad5'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'mach_ports_report.md','interface_abi_report.md','interface_investigation_status.md',
         'obfuscated_routines_report.md','foundational_triage_report.md','corefp_client_paths_report.md',
         'daemon_network_record_report.md','daemon_iokit_sync_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'daemon_network_gate_report.md','triage_evidence/recover_daemon_network_gate.py',
       'triage_evidence/audit_daemon_network_gate.py','triage_evidence/verify_daemon_network_gate_publication.py',
       'triage_evidence/daemon_network_gate_checks.json','triage_evidence/daemon_network_gate_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/daemon_network_gate_checks.json','triage_evidence/daemon_network_gate_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'acquisition_cases':32,'callback_cases':16,'consumer_cases':128,'intervals':528,
        'source_visits':78416,'reads':15616,'writes':4080,'logical_edges':2000}
INDEPENDENT={'register_values_checked': 2526208, 'NZCV_values_checked': 78944, 'source_visits': 78416, 'read_bytes_checked': 81216, 'original_authenticated_edges_checked': 1744, 'write_bytes_checked': 17440}

def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)

def receipts():
    assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
    e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
    assert e['generator_sha256']==a['generator_sha256']==sha(R.__file__) and a['auditor_sha256']==sha(A.__file__)
    assert a['checks_sha256']==CHECKS_SHA and e['dependencies']==a['dependencies']=={n:sha(ROOT/n) for n in R.DEPS}
    assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert e['verified_counts']==a['verified_counts']==COUNTS and a['independent_totals']==INDEPENDENT
    total=Counter();assert len(a['independent_lifts'])==528
    for result in a['independent_lifts']:assert result['all_checks_pass'];total.update(result['verified_counts'])
    assert dict(total)==INDEPENDENT
    counts=Counter()
    for row in R.intervals(e):
        assert len(row['source_visits'])==len(row['source_frames']) and not row['native_target_executed']
        counts.update(source_visits=len(row['source_visits']),reads=len(row['source_reads']),writes=len(row['source_writes']),logical_edges=len(row['logical_edges']))
        for v in row['source_visits']:assert v['bytes_hex']==IMAGE.read(int(v['pc'],16),4).hex()
    assert {k:COUNTS[k] for k in counts}==dict(counts)
    assert e['root_writer_evidence']==R.root_evidence() and len(e['root_writer_evidence'])==12
    assert sum(len(c['fields']) for c in e['root_writer_evidence'])==24
    assert e['source_regions']==R.source() and a['interfaces']==A.interfaces(e)
    for case in e['consumer_cases']:
        end=case['intervals'][-1]['boundary']
        if case['final_boundary']=='0x1005fadd4':
            assert end['registers31'][22]==case['cache_pointer64']==hex(R.Parent.RECORD)
            assert IMAGE.read(0x1005fadd4,4).hex()=='c90640f9'
        if case['final_boundary']=='0x10048192c':
            assert end['SP']==case['intervals'][0]['caller_SP']
            assert not any(int(f['address'],16)<=int(end['SP'],16)+0x878<int(f['address'],16)+len(bytes.fromhex(f['bytes_hex']))
                           for f in case['intervals'][-1]['initial_private_fixtures'])
        for row in case['intervals']:
            assert not any(int(x['address'],16)<R.Parent.RECORD+10 and R.Parent.RECORD<int(x['address'],16)+x['size_bytes'] for x in row['source_reads'])
    used={int(x['address'],16) for r in R.intervals(e) for x in r['source_reads'] if int(x['address'],16) in FIXUPS}
    verify_original_fixups({at for at in used if FIXUPS[at]['kind']!='bind'})
    assert e['source_fixups']==R.Parent.Parent.Parent.Env.fixups(used) and len(used)==45
    assert len(e['source_proofs'])==len(R.obligations())==a['source_queries_unsat']==4
    for q in e['source_proofs']:
        solver=z3.Solver();solver.set(timeout=30000);solver.from_string(q['query']);assert solver.check()==z3.unsat and q['premises_nonvacuous']
    assert a['SDK_checks']==A.sdk_checks() and a['SDK_checks']['exit_code']==0 and a['all_checks_pass']
    assert all(not x[k] for x in [e,a] for k in ['native_API_executed','native_daemon_kext_pairing_established','native_epoch_join_established','full_goal_complete'])
    report=read(BASE/'daemon_network_gate_report.md')
    assert all(f'| NG{j} |' in report for j in range(1,7)) and all(f'| NG-A{j}:' in report for j in range(1,8))
    assert all(f'**QG{j}**' in report for j in range(1,8))
    return e,a

def main():
    e,a=receipts();raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==8712 and len(after)==8718 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
    assert {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256'] and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
    assert new['validation']['daemon_network_gate_increment_checks']==COUNTS
    assert new['validation']['daemon_network_gate_replay_checks']==INDEPENDENT
    assert new['validation']['daemon_network_gate_interface_checks']==a['interfaces']['verified_counts']
    assert new['validation']['daemon_network_gate_static_scope']==e['scope']
    assert new['validation']['daemon_network_gate_source_queries_unsat']==4 and new['validation']['daemon_network_gate_SDK_compile_exit']==0
    assert new['validation']['reports']==old['validation']['reports']+1==500
    assert new['goal_status']=='active' and new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    fields=extent=0
    for obj in [e,a]:
        path_hygiene(json.dumps(H.paths_in_typed_payloads(obj)).encode());n,b=decoded_hex_hygiene(obj);fields+=n;extent+=b
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
    assert delta==OWNED,delta^OWNED
    print(json.dumps({'unchanged_manifest_entries':8703,'owned_physical_files':16,'original_inputs_preserved':3,'reports':500,
        'independent_lifts':528,'source_visits':78416,'source_queries_unsat':4,'original_fixup_records':45,'source_root_writers':24,
        'decoded_hex_fields_path_checked':fields,'decoded_hex_bytes_path_checked':extent,
        'native_API_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':main()
