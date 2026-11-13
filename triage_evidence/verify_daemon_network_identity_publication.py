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
import recover_daemon_network_identity as R
import audit_daemon_network_identity as A

ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='e2ca83570bafc569d4224db7dfee433cd9d3a991'
BASELINE_SHA='f9c32cd68ef072d364eab68d684a24002875a36644502ceac64ffadfcaefc76c'
CHECKS_SHA='c7475bfa2803e66ee6ced5f6e0862e789860589cb4f4f487ff81a328a155b29e'
AUDIT_SHA='15042ecb573ad014570b0c22ee3d4c7ce2c99363e6ebf322302db1303557227b'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'interface_investigation_status.md','interface_abi_report.md','foundational_triage_report.md',
         'mach_ports_report.md','obfuscated_routines_report.md','corefp_client_paths_report.md',
         'daemon_pidpath_consumer_report.md','daemon_return_cache_codec_report.md',
         'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'daemon_network_identity_report.md','triage_evidence/recover_daemon_network_identity.py',
       'triage_evidence/audit_daemon_network_identity.py','triage_evidence/verify_daemon_network_identity_publication.py',
       'triage_evidence/daemon_network_identity_checks.json','triage_evidence/daemon_network_identity_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/daemon_network_identity_checks.json','triage_evidence/daemon_network_identity_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'retained_cases':8,'cache_cases':512,'inner_cases':8,'intervals':592,'source_visits':9077,'reads':2744,'writes':3512,'logical_edges':280}
INDEPENDENT={'register_values_checked':309408,'NZCV_values_checked':9669,'source_visits':9077,
             'read_bytes_checked':15256,'original_authenticated_edges_checked':16,'write_bytes_checked':26608}

def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)

def receipts():
    assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
    e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
    assert e['generator_sha256']==a['generator_sha256']==sha(R.__file__) and a['auditor_sha256']==sha(A.__file__)
    assert a['checks_sha256']==CHECKS_SHA and e['dependencies']==a['dependencies']=={n:sha(ROOT/n) for n in R.DEPS}
    assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert e['verified_counts']==a['verified_counts']==COUNTS and a['independent_totals']==INDEPENDENT
    assert len(a['independent_lifts'])==592 and a['all_checks_pass']
    totals=Counter();counts=Counter()
    for r in a['independent_lifts']:assert r['all_checks_pass'] and not r['native_target_executed'];totals.update(r['verified_counts'])
    assert dict(totals)==INDEPENDENT
    for row in R.intervals(e):
        assert len(row['source_visits'])==len(row['source_frames']) and not row['native_target_executed']
        counts.update(source_visits=len(row['source_visits']),reads=len(row['source_reads']),writes=len(row['source_writes']),logical_edges=len(row['logical_edges']))
        for v in row['source_visits']:assert v['bytes_hex']==IMAGE.read(int(v['pc'],16),4).hex()
    assert {k:COUNTS[k] for k in counts}==dict(counts)
    assert e['source']==R.source() and a['interfaces']==A.interfaces(e) and a['source_audit']==A.source_audit(e)
    assert len(e['source_proofs'])==len(R.obligations())==a['source_queries_unsat']==3
    for q in e['source_proofs']:
        s=z3.Solver();s.set(timeout=30000);s.from_string(q['query']);assert s.check()==z3.unsat and q['premises_nonvacuous']
    assert a['SDK_checks']==A.sdk_checks() and a['SDK_checks']['exit_code']==0
    assert all(not x[k] for x in [e,a] for k in ['native_API_executed','native_daemon_kext_pairing_established','full_goal_complete'])
    report=read(BASE/'daemon_network_identity_report.md')
    assert all(f'| NI{j} |' in report for j in range(1,7)) and all(f'| NI-A{j} |' in report for j in range(1,8))
    assert all(f'**QG{j}**' in report for j in range(1,8))
    return e,a

def main():
    e,a=receipts();raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST))
    before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==8700 and len(after)==8706 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
    assert {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256'] and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
    assert new['validation']['daemon_network_identity_increment_checks']==COUNTS
    assert new['validation']['daemon_network_identity_replay_checks']==INDEPENDENT
    assert new['validation']['daemon_network_identity_static_scope']==e['scope']
    assert new['validation']['daemon_network_identity_source_queries_unsat']==3
    assert new['validation']['daemon_network_identity_SDK_compile_exit']==0
    assert new['validation']['reports']==old['validation']['reports']+1==498
    assert new['goal_status']=='active' and new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    fields=extent=0
    for obj in [e,a]:
        path_hygiene(json.dumps(H.paths_in_typed_payloads(obj)).encode());n,b=decoded_hex_hygiene(obj);fields+=n;extent+=b
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
    assert delta==OWNED,delta^OWNED
    print(json.dumps({'unchanged_manifest_entries':8691,'owned_physical_files':len(OWNED),'original_inputs_preserved':3,'reports':498,
                      'independent_lifts':592,'source_queries_unsat':3,'original_fixup_records':16,'original_stubs':10,
                      'original_direct_calls':33,'SDK_compile_exit':0,'retained_undefined_roots':8,
                      'warm_cache_controls':256,'cold_pending_main_port_controls':256,'nested_controls':8,
                      'decoded_hex_fields_path_checked':fields,'decoded_hex_bytes_path_checked':extent,
                      'native_API_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':main()
