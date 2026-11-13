#!/usr/bin/env python3
"""Verify exact clock-record publication, original-source provenance and hygiene.

O(receipts+owned bytes+source+manifest+query DAG) time/space; solver work
separate, 30 s/query. No native target operations, hardware PAC or IDB mutation.
"""
import json,subprocess
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
import recover_daemon_clock_record as R
import audit_daemon_clock_record as A

ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='64d585ade9e21f73b45f404f29487870a91f1cb6'
BASELINE_SHA='15f2e4929c4c4df941341371e47dd79601cd2e7af1a06c8ed9a6c136c79864d0'
CHECKS_SHA='0636a892fbba8b6ab2bd3637b7f6049aa5127ae68b5a32d7081b3786b34e97dd'
AUDIT_SHA='b5b5c334300d8dc73a262435b5ebdc3821bd5520085320818a3a80630e08e264'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'mach_ports_report.md','interface_abi_report.md','interface_investigation_status.md',
         'obfuscated_routines_report.md','foundational_triage_report.md','corefp_client_paths_report.md',
         'daemon_context_state_publish_report.md','daemon_seed_material_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'daemon_clock_record_report.md','triage_evidence/recover_daemon_clock_record.py',
       'triage_evidence/audit_daemon_clock_record.py','triage_evidence/verify_daemon_clock_record_publication.py',
       'triage_evidence/daemon_clock_record_checks.json','triage_evidence/daemon_clock_record_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/daemon_clock_record_checks.json','triage_evidence/daemon_clock_record_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'clock_cases':40,'random_cases':64,'intervals':168,'source_visits':19392,'reads':3872,'writes':1280,'logical_edges':512,'source_calls':128}
INDEPENDENT={'register_values_checked':625920,'NZCV_values_checked':19560,'vector_register_values_checked':625920,
             'read_bytes_checked':21056,'source_visits':19392,'write_bytes_checked':6144,'original_authenticated_edges_checked':384}

def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)

def receipts():
    assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
    e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
    assert e['generator_sha256']==a['generator_sha256']==sha(R.__file__) and a['auditor_sha256']==sha(A.__file__)
    assert a['checks_sha256']==CHECKS_SHA and e['dependencies']==a['dependencies']=={n:sha(ROOT/n) for n in R.DEPS}
    assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert e['verified_counts']==a['verified_counts']==COUNTS and a['independent_totals']==INDEPENDENT
    assert len(a['independent_lifts'])==168;total=Counter();counts=Counter()
    for lift in a['independent_lifts']:assert lift['all_checks_pass'];total.update(lift['verified_counts'])
    assert dict(total)==INDEPENDENT
    for row in R.intervals(e):
        assert len(row['source_visits'])==len(row['source_frames']) and not row['native_target_executed']
        assert len(row['entry_Q_registers32'])==len(row['boundary']['Q_registers32'])==32
        counts.update(source_visits=len(row['source_visits']),reads=len(row['source_reads']),writes=len(row['source_writes']),logical_edges=len(row['logical_edges']),source_calls=len(row['source_calls']))
        for v,frame in zip(row['source_visits'],row['source_frames']):
            assert v['bytes_hex']==IMAGE.read(int(v['pc'],16),4).hex() and len(frame['Q_registers32'])==32
    assert dict(counts)=={k:COUNTS[k] for k in counts}
    assert e['source_regions']==R.source() and a['interfaces']==A.interfaces(e)
    for child in e['random_cases']:
        parent=e['clock_cases'][child['parent_clock_case_index']];out=int(parent['timeval_address'],16)
        padding=set(range(out+12,out+16))
        for row in child['intervals']:
            assert all(not padding.intersection(range(int(f['address'],16),int(f['address'],16)+len(bytes.fromhex(f['bytes_hex'])))) for f in row['initial_private_fixtures'])
            assert all(not padding.intersection(range(int(x['address'],16),int(x['address'],16)+x['size_bytes'])) for x in row['source_reads']+row['source_writes'])
    assert a['SDK_checks']==A.sdk_checks() and a['SDK_checks']['exit_code']==0
    parent=json.loads(read(ROOT/(R.Parent.P+'_checks.json')))
    assert e['pointer_origin_evidence']==R.pointer_origin(parent) and len(e['pointer_origin_evidence'])==4
    used={int(x['address'],16) for row in R.intervals(e) for x in row['source_reads'] if int(x['address'],16) in FIXUPS}
    assert e['source_fixups']==R.Parent.Parent.Parent.Parent.Parent.Parent.Env.fixups(used)
    assert len(a['source_proofs'])==len(A.obligations())==a['source_queries_unsat']==8
    for q in a['source_proofs']:
        solver=z3.Solver();solver.set(timeout=30000);solver.from_string(q['query']);assert solver.check()==z3.unsat and q['premises_nonvacuous']
    assert all(not x[k] for x in [e,a] for k in ['native_API_executed','native_daemon_kext_pairing_established','native_epoch_join_established','full_goal_complete'])
    report=read(BASE/'daemon_clock_record_report.md')
    assert all(f'| CR{j} |' in report for j in range(1,7)) and all(f'| CR-A{j}:' in report for j in range(1,10)) and all(f'**QG{j}**' in report for j in range(1,8))
    assert CHECKS_SHA in report and AUDIT_SHA in report and a['all_checks_pass'];return e,a

def main():
    e,a=receipts();raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==8736 and len(after)==8742 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
    assert {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256'] and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
    for suffix,value in [('increment_checks',COUNTS),('replay_checks',INDEPENDENT),('interface_checks',a['interfaces']['verified_counts']),
                         ('static_scope',e['scope']),('source_queries_unsat',8),('SDK_compile_exit',0)]:
        assert new['validation']['daemon_clock_record_'+suffix]==value
    assert new['validation']['reports']==old['validation']['reports']+1==504 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    fields=extent=0
    for obj in [e,a]:
        path_hygiene(json.dumps(paths_in_typed_payloads(obj)).encode());n,b=decoded_hex_hygiene(obj);fields+=n;extent+=b
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
    assert delta==OWNED,delta^OWNED
    print(json.dumps({'unchanged_manifest_entries':8727,'owned_physical_files':16,'original_inputs_preserved':3,'reports':504,
        'independent_lifts':168,'source_visits':19392,'source_queries_unsat':8,
        'decoded_hex_fields_path_checked':fields,'decoded_hex_bytes_path_checked':extent,
        'native_API_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':main()
