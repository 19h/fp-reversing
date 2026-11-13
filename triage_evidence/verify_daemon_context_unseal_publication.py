#!/usr/bin/env python3
"""Verify exact context-unseal publication, provenance and path hygiene.

O(receipts+owned bytes+source+manifest+query DAG) time/space; solver work
separate, 30 s/query. No native operations, hardware PAC or IDB mutation.
"""
import json,subprocess,zlib,base64
from pathlib import Path
from hashlib import sha256
from collections import Counter
from compression import zstd
import z3
from daemon_receive_tools import SOURCE,IMAGE,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene
from verify_daemon_iokit_result_publication import decoded_hex_hygiene
from verify_corefp_late_preparation_publication import paths_in_typed_payloads
import recover_daemon_context_unseal as R
import audit_daemon_context_unseal as A

ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='c36d9d3616c48e796a92db2addbdf915abbcfe61'
BASELINE_SHA='ca5cb5de2491a5f2300c4615909d5f805a2c1a2b61793f1b403e330cf5d2ad03'
CHECKS_SHA='b4f3b10a7c3b5f57d9a680c1e88a4fb2a9b473af27fb0b353e23fd7ab87048fe';AUDIT_SHA='ddc6d19ff112ee651d234e1ab8c0daf7a606d0b199f97084d123427e6a449173'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'mach_ports_report.md','interface_abi_report.md','interface_investigation_status.md',
         'obfuscated_routines_report.md','foundational_triage_report.md','corefp_client_paths_report.md',
         'daemon_network_gate_report.md','daemon_context_lock_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'daemon_context_unseal_report.md','triage_evidence/recover_daemon_context_unseal.py',
       'triage_evidence/audit_daemon_context_unseal.py','triage_evidence/verify_daemon_context_unseal_publication.py',
       'triage_evidence/daemon_context_unseal_checks.json','triage_evidence/daemon_context_unseal_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/daemon_context_unseal_checks.json','triage_evidence/daemon_context_unseal_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'cases':20,'producer_profiles':13,'caller_contexts':8,'reference_controls':72,'intervals':296,
        'source_visits':70572,'reads':12268,'writes':10532,'logical_edges':0}
INDEPENDENT={'register_values_checked':2267776,'NZCV_values_checked':70868,'vector_register_values_checked':2267776,
             'read_bytes_checked':71340,'source_visits':70572,'write_bytes_checked':54664}

def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)

def receipts():
    assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
    e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
    assert e['generator_sha256']==a['generator_sha256']==sha(R.__file__) and a['auditor_sha256']==sha(A.__file__)
    assert a['checks_sha256']==CHECKS_SHA and e['dependencies']==a['dependencies']=={n:sha(ROOT/n) for n in R.DEPS}
    assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert e['verified_counts']==a['verified_counts']==COUNTS and a['independent_totals']==INDEPENDENT
    assert len(a['independent_lifts'])==296;total=Counter();counts=Counter()
    for lift in a['independent_lifts']:assert lift['all_checks_pass'];total.update(lift['verified_counts'])
    assert dict(total)==INDEPENDENT
    for row in R.intervals(e):
        assert len(row['source_visits'])==len(row['source_frames']) and not row['native_target_executed']
        assert len(row['entry_Q_registers32'])==len(row['boundary']['Q_registers32'])==32
        counts.update(source_visits=len(row['source_visits']),reads=len(row['source_reads']),writes=len(row['source_writes']),logical_edges=len(row['logical_edges']))
        for v,frame in zip(row['source_visits'],row['source_frames']):
            assert v['bytes_hex']==IMAGE.read(int(v['pc'],16),4).hex() and len(frame['Q_registers32'])==32
    assert dict(counts)=={k:COUNTS[k] for k in counts}
    assert e['source_regions']==R.source() and e['root_writer_evidence']==R.root_evidence() and len(e['root_writer_evidence'])==12
    assert a['interfaces']==A.interfaces(e) and a['producer_audit']==A.producer_audit(e)
    prod,_,_=R.producer();assert e['producer_evidence']==prod
    used={int(x['address'],16) for r in R.intervals(e) for x in r['source_reads'] if int(x['address'],16) in FIXUPS}
    assert not used and e['source_fixups']==R.Parent.Parent.Parent.Env.fixups(used)
    assert len(a['source_proofs'])==len(A.obligations())==a['source_queries_unsat']==83
    for q in a['source_proofs']:
        solver=z3.Solver();solver.set(timeout=30000);solver.from_string(q['query']);assert solver.check()==z3.unsat and q['premises_nonvacuous']
    assert a['permutation_certificate']==A.permutation_certificate() and len(a['permutation_certificate'])==630
    snap=json.loads(read(ROOT/'daemon_context_lock_snapshot.json'))
    for r in snap['regions']:
        raw=zlib.decompress(base64.b64decode(r['bytes_zlib_base64']));assert len(raw)==r['size_bytes'] and sha256(raw).hexdigest()==r['sha256']
    known=zlib.decompress(base64.b64decode(snap['heap_owner']['known_mask_zlib_base64']));off=R.TABLE_DATA-int(snap['arena_owner'],16)
    assert all(known[off:off+512]) and len(known[off:off+512])==512
    assert all(not x[k] for x in [e,a] for k in ['native_API_executed','native_daemon_kext_pairing_established','native_epoch_join_established','full_goal_complete'])
    report=read(BASE/'daemon_context_unseal_report.md')
    assert all(f'| CU{j} |' in report for j in range(1,7)) and all(f'| CU-A{j}:' in report for j in range(1,10)) and all(f'**QG{j}**' in report for j in range(1,8))
    assert a['all_checks_pass'];return e,a

def main():
    e,a=receipts();raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==8718 and len(after)==8724 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
    assert {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256'] and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
    assert new['validation']['daemon_context_unseal_increment_checks']==COUNTS and new['validation']['daemon_context_unseal_replay_checks']==INDEPENDENT
    assert new['validation']['daemon_context_unseal_interface_checks']==a['interfaces']['verified_counts']
    assert new['validation']['daemon_context_unseal_static_scope']==e['scope']
    assert new['validation']['daemon_context_unseal_source_queries_unsat']==83 and new['validation']['daemon_context_unseal_permutation_certificates']==630
    assert new['validation']['reports']==old['validation']['reports']+1==501 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    fields=extent=0
    for obj in [e,a]:
        path_hygiene(json.dumps(paths_in_typed_payloads(obj)).encode());n,b=decoded_hex_hygiene(obj);fields+=n;extent+=b
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
    assert delta==OWNED,delta^OWNED
    print(json.dumps({'unchanged_manifest_entries':8709,'owned_physical_files':16,'original_inputs_preserved':3,'reports':501,
        'independent_lifts':296,'source_visits':70572,'source_queries_unsat':83,'permutation_certificates':630,'producer_source_visits':43843,
        'decoded_hex_fields_path_checked':fields,'decoded_hex_bytes_path_checked':extent,
        'native_API_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':main()
