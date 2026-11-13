#!/usr/bin/env python3
"""Verify auxiliary initializer receipts, source equations and publication.

O(receipts+visits+owned bytes+manifest+query DAG) time/storage; 30 s/query.
Native APIs/IPC/PAC and IDB mutation never execute. Source-known local
publication does not establish ownership, native reachability or transport.
"""
import json
from hashlib import sha256
from collections import Counter
from compression import zstd
import z3
from daemon_receive_tools import SOURCE,IMAGE,FIXUPS,TABLE
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_daemon_payload_mix_publication import ROOT,BASE,git,hygiene,path_hygiene
from verify_daemon_second_mix_publication import canonical_expression,check_query_comparison
import recover_daemon_auxiliary_state as R
import audit_daemon_auxiliary_state as A

PREVIOUS='2de854f65901de1aa5111df34a4363bc03a709f3'
BASELINE_SHA='175bd6aefd3b42e837fe7aa6087daf5ca1743168c91202982c650f28a17c3a14'
CHECKS_SHA='320da14726a35e4c32f34708d03b34479923d8b0fbff7234fe9edd9069ffa2a4'
AUDIT_SHA='8092b66fffa6c6801cb43fbcbb0313a3a96fb8e9149412ca675415c3e1348a3d'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'mach_ports_report.md','interface_abi_report.md','interface_investigation_status.md',
         'obfuscated_routines_report.md','foundational_triage_report.md','corefp_client_paths_report.md',
         'daemon_generated_stream_report.md','daemon_context_state_publish_report.md',
         'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'daemon_auxiliary_state_report.md','triage_evidence/recover_daemon_auxiliary_state.py',
       'triage_evidence/audit_daemon_auxiliary_state.py','triage_evidence/verify_daemon_auxiliary_state_publication.py',
       'triage_evidence/daemon_auxiliary_state_checks.json','triage_evidence/daemon_auxiliary_state_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/daemon_auxiliary_state_checks.json','triage_evidence/daemon_auxiliary_state_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'cases':16,'main_cases':8,'table_NULL_controls':8,'intervals':16,'source_visits':2640,'reads':496,'writes':400,'logical_edges':40,'source_calls':0}
INDEPENDENT={'register_values_checked':84992,'NZCV_values_checked':2656,'vector_register_values_checked':84992,
             'source_visits':2640,'read_bytes_checked':2408,'original_authenticated_edges_checked':40,'write_bytes_checked':1464}
MODEL={'import_return_joins_checked':16,'generated_bytes_preserved_without_access_checked':512,
       'NULL_allocation_skips_publication_checked':8,'table_record_decodes_checked':8,
       'table_read_undefined_bytes_checked':64,'table_control_lookups_checked':64,'table_NULL_routes_checked':8,
       'auxiliary_bytes_initialized_checked':744,'auxiliary_gaps_undefined_checked':88,
       'raw_pointer_publications_checked':8,'cached_word_transforms_checked':16}

def receipts():
    assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
    e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
    assert e['generator_sha256']==a['generator_sha256']==sha(R.__file__) and a['auditor_sha256']==sha(A.__file__)
    assert a['checks_sha256']==CHECKS_SHA and e['dependencies']==a['dependencies']=={n:sha(ROOT/n) for n in R.DEPS}
    assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert e['verified_counts']==a['verified_counts']==COUNTS and a['independent_totals']==INDEPENDENT and a['model_checks']==MODEL and a['all_checks_pass']
    assert e['source_regions']==R.source() and len(e['cases'])==len(a['cases'])==16
    parent=json.loads(read(ROOT/(R.Parent.P+'_checks.json')));h=Counter();counts=Counter();totals=Counter();model=Counter();used=set();keys=set()
    for c,ac in zip(e['cases'],a['cases']):
        key=(c['parent_case_index'],c['ABI_clobber_pattern'],c['pointer_return64'],c['table_NULL_control']);assert key not in keys;keys.add(key)
        assert len(c['intervals_packed'])==1;row=R.unpack(c['intervals_packed'][0]);h.update(hygiene(row))
        assert not row['native_target_executed'];lift=ac['independent_lift'];assert lift['all_checks_pass'] and not lift['native_target_executed']
        rebuilt=json.loads(json.dumps(A.contract(c,parent['cases'][c['parent_case_index']])))
        assert ac['contract']==rebuilt;model.update(ac['contract']['model_checks'])
        assert c['counts']==R.rc(row);counts.update(c['counts']);totals.update(lift['verified_counts'])
        assert len(row['source_visits'])==len(row['source_frames'])==lift['verified_counts']['source_visits']
        assert lift['boundary']==row['boundary']['pc'] and len(row['entry_Q_registers32'])==len(row['boundary']['Q_registers32'])==32
        for visit,frame in zip(row['source_visits'],row['source_frames']):
            assert visit['bytes_hex']==IMAGE.read(int(visit['pc'],16),4).hex() and visit['pc']==frame['pc'] and len(frame['Q_registers32'])==32
        used.update(int(x['address'],16) for x in row['source_reads'] if int(x['address'],16) in FIXUPS)
    expected={(j,p,hex(r),zero) for j in [0,1] for p in [0,1] for r in [0,R.B] for zero in [False,True]}
    assert keys==expected and dict(totals)==INDEPENDENT and dict(model)==MODEL
    assert dict(counts)=={k:COUNTS[k] for k in counts} and e['source_fixups']==R.fixups(used)
    for index,target in [(0x4a95,0x1007fccd8),(0x4b15,0x10050e008),(0x838b,0x100865de0),(0x8371,R.SKIP)]:
        assert FIXUPS[TABLE+8*index]['target']==target
    check_query_comparison();fresh=A.obligations();assert len(fresh)==len(a['source_proofs'])==a['source_queries_unsat']==8
    for old,new in zip(a['source_proofs'],fresh):
        assert {k:v for k,v in old.items() if k!='query'}=={k:v for k,v in new.items() if k!='query'}
        oa,na=z3.parse_smt2_string(old['query']),z3.parse_smt2_string(new['query'])
        assert len(oa)==len(na)>0 and all(canonical_expression(x)==canonical_expression(y) for x,y in zip(oa,na))
        s=z3.Solver();s.set(timeout=30000);s.from_string(old['query']);assert s.check()==z3.unsat and old['premises_nonvacuous']
    for obj in [e,a]:
        h.update(hygiene(obj));assert all(not obj[k] for k in ['native_API_executed','native_daemon_kext_pairing_established','native_epoch_join_established','full_goal_complete'])
    report=read(BASE/'daemon_auxiliary_state_report.md');assert CHECKS_SHA in report and AUDIT_SHA in report
    assert all(f'| AS{j} |' in report for j in range(1,7)) and all(f'| AS-A{j}:' in report for j in range(1,9)) and all(f'**QG{j}**' in report for j in range(1,8))
    return e,a,h

def main():
    e,a,h=receipts();raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==8778 and len(after)==8784 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
    assert {p for p in before if before[p]!=after[p]}==CHANGED and new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256'] and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
    for suffix,value in [('increment_checks',COUNTS),('replay_checks',INDEPENDENT),('model_checks',MODEL),('static_scope',e['scope']),('source_queries_unsat',8)]:
        assert new['validation']['daemon_auxiliary_state_'+suffix]==value
    assert new['validation']['reports']==old['validation']['reports']+1==511 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
    assert delta==OWNED,delta^OWNED
    print(json.dumps({'unchanged_manifest_entries':8769,'owned_physical_files':16,'original_inputs_preserved':3,'reports':511,
                     'independent_lifts':16,'source_visits':2640,'source_queries_unsat':8,**h,
                     'native_API_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':main()
