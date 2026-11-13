#!/usr/bin/env python3
"""Verify SIDB path objects, source proofs and the exact publication delta.

O(receipts+visits+owned bytes+manifest+query DAG) time/storage; 30 s/query.
Native APIs/IPC/PAC and IDB mutation never execute. API effects and native caller epochs remain explicit premises.
"""
import json
from hashlib import sha256
from collections import Counter
from compression import zstd
import z3
from daemon_receive_tools import SOURCE,IMAGE,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_daemon_payload_mix_publication import ROOT,BASE,git,hygiene,path_hygiene
from verify_daemon_second_mix_publication import canonical_expression,check_query_comparison
import recover_daemon_state_path_objects as R
import audit_daemon_state_path_objects as A

PREVIOUS='eaa07368dbccfac7926bf5fd46926a2b67b95ff4'
BASELINE_SHA='70430e00e207b4a10c38310e95268f4944840929ae42e738ff561a8f7229a141'
CHECKS_SHA='07a337c86186417bf07e4aaa78565bb7a75eac938128af0e42e3a097918a458d'
AUDIT_SHA='6ec2b37431f87db9631fdfa8f6725a7128e154b2c9d8719af1ad61024a677a4c'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'mach_ports_report.md','interface_abi_report.md','interface_investigation_status.md',
         'obfuscated_routines_report.md','foundational_triage_report.md','corefp_client_paths_report.md',
         'daemon_payload_reactivation_report.md','daemon_rwlock_lifecycle_report.md',
         'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'daemon_state_path_objects_report.md','triage_evidence/recover_daemon_state_path_objects.py',
       'triage_evidence/audit_daemon_state_path_objects.py','triage_evidence/verify_daemon_state_path_objects_publication.py',
       'triage_evidence/daemon_state_path_objects_checks.json','triage_evidence/daemon_state_path_objects_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/daemon_state_path_objects_checks.json','triage_evidence/daemon_state_path_objects_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'cases': 48, 'intervals': 200, 'source_visits': 71112, 'reads': 9456, 'writes': 2568, 'logical_edges': 2608, 'source_calls': 88}
INDEPENDENT={'register_values_checked': 2281984, 'NZCV_values_checked': 71312, 'vector_register_values_checked': 2281984, 'source_visits': 71112, 'read_bytes_checked': 50088, 'original_authenticated_edges_checked': 2520, 'write_bytes_checked': 16552}
MODEL={'API_return_joins_checked': 152, 'ordinary_state_joins_checked': 48, 'constructor_status_words_checked': 48, 'failure_preserves_destination_checked': 40, 'next_path_requests_checked': 48, 'generated_stream_bytes_preserved_checked': 1536, 'initially_undefined_owner_bytes_checked': 9360, 'declared_owner_retirements_checked': 32, 'creator_record_views_checked': 40, 'opaque_lock_bytes_checked': 6400, 'preinit_lock_header_bytes_checked': 256, 'path_bytes_checked': 272, 'directory_byte_defuses_checked': 160, 'basename_source_bytes_checked': 96, 'object_defined_bytes_checked': 504, 'object_undefined_gap_bytes_checked': 88, 'pointer_publications_checked': 8}


def receipts():
    assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
    e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
    assert e['generator_sha256']==a['generator_sha256']==sha(R.__file__) and a['auditor_sha256']==sha(A.__file__) and a['checks_sha256']==CHECKS_SHA
    assert e['dependencies']==a['dependencies']=={n:sha(ROOT/n) for n in R.DEPS} and a['auditor_dependencies']=={n:sha(ROOT/n) for n in A.AD}
    assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert e['verified_counts']==a['verified_counts']==COUNTS and a['independent_totals']==INDEPENDENT and a['model_checks']==MODEL and a['all_checks_pass']
    assert e['source_regions']==R.source() and len(e['cases'])==len(a['cases'])==48
    parent=json.loads(read(ROOT/(R.Parent.P+'_checks.json')));h=Counter();counts=Counter();totals=Counter();model=Counter();used=set();keys=set()
    for c,ac in zip(e['cases'],a['cases']):
        key=(c['parent_case_index'],c['ABI_clobber_pattern'],c['scenario']);assert key not in keys;keys.add(key)
        assert tuple(ac[k] for k in ['parent_case_index','ABI_clobber_pattern','scenario'])==key and ac['all_checks_pass']
        rebuilt=json.loads(json.dumps(A.contract(c,parent['cases'][c['parent_case_index']])));assert rebuilt==ac['contract'];model.update(rebuilt['model_checks'])
        rows=[R.unpack(p) for p in c['intervals_packed']];assert len(rows)==len(ac['independent_lifts'])==len(c['API_return_premises'])
        cs=Counter();ts=Counter()
        for row,lift in zip(rows,ac['independent_lifts']):
            h.update(hygiene(row));assert not row['native_target_executed'] and lift['all_checks_pass'] and not lift['native_target_executed']
            cs.update(R.rc(row));ts.update(lift['verified_counts'])
            assert len(row['source_visits'])==len(row['source_frames'])==lift['verified_counts']['source_visits'] and row['boundary']['pc']==lift['boundary']
            for visit,frame in zip(row['source_visits'],row['source_frames']):
                assert visit['bytes_hex']==IMAGE.read(int(visit['pc'],16),4).hex() and visit['pc']==frame['pc'] and len(frame['Q_registers32'])==32
            used.update(int(x['address'],16) for x in row['source_reads'] if int(x['address'],16) in FIXUPS)
        assert dict(cs)==c['counts'] and dict(ts)==ac['independent_totals'];counts.update(cs);totals.update(ts)
        events=[x for x in c['API_return_premises'] if x];scenario=c['scenario'];expected=['libSystem/_malloc']
        if scenario!='object_NULL':expected+=['libSystem/_malloc']
        if scenario.startswith('init_'):expected+=['libSystem/_pthread_rwlock_init']
        if scenario not in ['object_NULL','init_0']:expected+=['libSystem/_free']
        assert [x['symbol'] for x in events]==expected
        assert events[0]['pointer_return64']==('0x0' if scenario=='object_NULL' else hex(R.B))
        if scenario!='object_NULL':assert events[1]['pointer_return64']==('0x0' if scenario=='lock_NULL' else hex(R.L))
        if scenario.startswith('init_'):assert int(events[2]['return32'],16)==int(scenario.split('_')[1]) and events[2]['opaque_owner_premise']=={'address':hex(R.L),'size_bytes':200,'initial_bytes_defined':False}
        if scenario=='init_0':
            body=rows[2];pub=A.select(body,0x10003a3e0);assert len(pub)==1 and pub[0]['address']==hex(R.J+0x118) and pub[0]['after_hex']==R.B.to_bytes(8,'little').hex()
            assert all(w['source_visit_index']<pub[0]['source_visit_index'] for w in body['source_writes'] if A.overlap(w,R.B,74))
            for pc,offset in [(0x10009161c,2),(0x100091630,0),(0x100091640,3),(0x100091650,1)]:
                reads=A.select(body,pc,'source_reads');assert [x['address'] for x in reads]==[hex(0x10102fa20+j+offset) for j in [0,4,8]]
        assert rows[-1]['boundary']['detail']['symbol']=='libSystem/_malloc' and rows[-1]['boundary']['detail']['modifier']=='0x6aa4' and rows[-1]['boundary']['registers31'][23]=='0x1010130e0'
    assert keys=={(j,p,s) for j in range(4) for p in [0,1] for s in R.SCENARIOS}
    assert dict(totals)==INDEPENDENT and dict(model)==MODEL and dict(counts)=={k:COUNTS[k] for k in counts} and e['source_fixups']==R.fixups(used)
    check_query_comparison();fresh=A.obligations();assert len(fresh)==len(a['source_proofs'])==a['source_queries_unsat']==11
    for old,new in zip(a['source_proofs'],fresh):
        assert {k:v for k,v in old.items() if k!='query'}=={k:v for k,v in new.items() if k!='query'}
        oa,na=z3.parse_smt2_string(old['query']),z3.parse_smt2_string(new['query']);assert len(oa)==len(na)>0
        assert all(canonical_expression(x)==canonical_expression(y) for x,y in zip(oa,na))
        solver=z3.Solver();solver.set(timeout=30000);solver.from_string(old['query']);assert solver.check()==z3.unsat and old['premises_nonvacuous']
    for obj in [e,a]:
        h.update(hygiene(obj));assert all(not obj[k] for k in ['native_API_executed','native_daemon_kext_pairing_established','native_epoch_join_established','full_goal_complete'])
    report=read(BASE/'daemon_state_path_objects_report.md');assert CHECKS_SHA in report and AUDIT_SHA in report
    assert all(f'| SO{j} |' in report for j in range(1,7)) and all(f'| SO-A{j}:' in report for j in range(1,11)) and all(f'**QG{j}**' in report for j in range(1,8))
    return e,a,h

def main():
    e,a,h=receipts();raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==8790 and len(after)==8796 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
    assert {p for p in before if before[p]!=after[p]}==CHANGED and new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256'] and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
    for suffix,value in [('increment_checks',COUNTS),('replay_checks',INDEPENDENT),('model_checks',MODEL),('static_scope',e['scope']),('source_queries_unsat',11)]:
        assert new['validation']['daemon_state_path_objects_'+suffix]==value
    assert new['validation']['reports']==old['validation']['reports']+1==513 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        path_hygiene((BASE/p).read_bytes());path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
    assert delta==OWNED,delta^OWNED
    print(json.dumps({'unchanged_manifest_entries':8781,'owned_physical_files':16,'original_inputs_preserved':3,'reports':513,
                     'independent_lifts':200,'source_visits':71112,'source_queries_unsat':11,**h,
                     'native_API_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':main()
