#!/usr/bin/env python3
"""Verify exact arena split/fill/payload publication, source provenance and path hygiene.

O(receipts+owned bytes+source+manifest+query DAG) time/space; 30 s/query.
No native target operations, concurrency, hardware PAC or IDB mutation.
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
import recover_daemon_arena_split as R
import audit_daemon_arena_split as A

ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='abf2257659361a3cd8d16642ec52d7c3d50d5ff2'
BASELINE_SHA='8d9d71af513ead919e8431b108b86fecac0b03043b4b0691ee2d7621c653f205'
CHECKS_SHA='ec60b186a8613a1c1e6844cf3a5ea88bb50c8dc272e649d39c7073cfc1ebbd48'
AUDIT_SHA='0266b5139f41536f7005b0e05d05a2e523037ccc14ee22f6426d2c3293359366'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'mach_ports_report.md','interface_abi_report.md','interface_investigation_status.md',
         'obfuscated_routines_report.md','foundational_triage_report.md','corefp_client_paths_report.md',
         'daemon_clock_record_report.md','daemon_readiness_arena_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'daemon_arena_split_report.md','triage_evidence/recover_daemon_arena_split.py',
       'triage_evidence/audit_daemon_arena_split.py','triage_evidence/verify_daemon_arena_split_publication.py',
       'triage_evidence/daemon_arena_split_checks.json','triage_evidence/daemon_arena_split_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/daemon_arena_split_checks.json','triage_evidence/daemon_arena_split_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'marker_cases':8,'seed_cases':8,'intervals':48,'source_visits':68592,'reads':5700,'writes':5208,'logical_edges':5088,'source_calls':16}
INDEPENDENT={'register_values_checked':2196480,'NZCV_values_checked':68640,'vector_register_values_checked':2196480,
             'read_bytes_checked':43816,'source_visits':68592,'original_authenticated_edges_checked':5072,
             'write_bytes_checked':21072,'retained_X8_fixup_origins_checked':4}

def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)

def receipts():
    assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
    e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
    assert e['generator_sha256']==a['generator_sha256']==sha(R.__file__) and a['auditor_sha256']==sha(A.__file__)
    assert a['checks_sha256']==CHECKS_SHA and e['dependencies']==a['dependencies']=={n:sha(ROOT/n) for n in R.DEPS}
    assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert e['verified_counts']==a['verified_counts']==COUNTS and a['independent_totals']==INDEPENDENT
    assert len(a['independent_lifts'])==48;total=Counter();counts=Counter()
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
    assert e['snapshot_fields']==R.snapshot_fields()
    assert e['fill_evidence']==R.fill_evidence(json.loads(read(ROOT/(R.Parent.P+'_checks.json'))))
    used={int(x['address'],16) for row in R.intervals(e) for x in row['source_reads'] if int(x['address'],16) in FIXUPS}
    assert e['source_fixups']==R.Parent.Parent.Parent.Parent.Parent.Parent.Parent.Env.fixups(used)
    rebuilt=A.obligations();assert len(a['source_proofs'])==len(rebuilt)==a['source_queries_unsat']==8
    for q,fresh in zip(a['source_proofs'],rebuilt):
        assert {k:v for k,v in q.items() if k!='query'}=={k:v for k,v in fresh.items() if k!='query'}
        old_ast,new_ast=z3.parse_smt2_string(q['query']),z3.parse_smt2_string(fresh['query'])
        assert len(old_ast)==len(new_ast)>0 and all(x.eq(y) for x,y in zip(old_ast,new_ast))
        solver=z3.Solver();solver.set(timeout=30000);solver.from_string(q['query']);assert solver.check()==z3.unsat and q['premises_nonvacuous']
    assert all(not x[k] for x in [e,a] for k in ['native_API_executed','native_daemon_kext_pairing_established','native_epoch_join_established','full_goal_complete'])
    report=read(BASE/'daemon_arena_split_report.md')
    assert all(f'| AS{j} |' in report for j in range(1,7)) and all(f'| AS-A{j}:' in report for j in range(1,10)) and all(f'**QG{j}**' in report for j in range(1,8))
    assert CHECKS_SHA in report and AUDIT_SHA in report and a['all_checks_pass'];return e,a

def main():
    e,a=receipts();raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==8748 and len(after)==8754 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
    assert {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256'] and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
    for suffix,value in [('increment_checks',COUNTS),('replay_checks',INDEPENDENT),('interface_checks',a['interfaces']['verified_counts']),
                         ('static_scope',e['scope']),('source_queries_unsat',8)]:
        assert new['validation']['daemon_arena_split_'+suffix]==value
    assert new['validation']['reports']==old['validation']['reports']+1==506 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    fields=extent=0
    for obj in [e,a]:
        path_hygiene(json.dumps(paths_in_typed_payloads(obj)).encode());n,b=decoded_hex_hygiene(obj);fields+=n;extent+=b
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
    assert delta==OWNED,delta^OWNED
    print(json.dumps({'unchanged_manifest_entries':8739,'owned_physical_files':16,'original_inputs_preserved':3,'reports':506,
        'independent_lifts':48,'source_visits':68592,'source_queries_unsat':8,
        'decoded_hex_fields_path_checked':fields,'decoded_hex_bytes_path_checked':extent,
        'native_API_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':main()
