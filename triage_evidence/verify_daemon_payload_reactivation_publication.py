#!/usr/bin/env python3
"""Verify payload reactivation, source proofs and the exact publication delta.

O(receipts+visits+owned bytes+manifest+query DAG) time/storage; 30 s/query.
Native APIs/IPC/PAC and IDB mutation never execute. Separate producer bytes
remain an explicit premise, not an established native epoch join.
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
import recover_daemon_payload_reactivation as R
import audit_daemon_payload_reactivation as A

PREVIOUS='c0c365d42154634c87ea4065184ae1be427d50ab'
BASELINE_SHA='4ba760ad28f36278a516686eeb5988babf1892620240b8c1bd79a565ad307b88'
CHECKS_SHA='56e853302ecd55f8663815cb15cb881b376957ba1b6b7865793540a8a6c2d7f7'
AUDIT_SHA='4d4169369c6a3fc28ae4e6ddac9c240fd8183fecb11d98ce3e6ddae54ce3393c'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'mach_ports_report.md','interface_abi_report.md','interface_investigation_status.md',
         'obfuscated_routines_report.md','foundational_triage_report.md','corefp_client_paths_report.md',
         'daemon_generated_stream_report.md','daemon_auxiliary_state_report.md',
         'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'daemon_payload_reactivation_report.md','triage_evidence/recover_daemon_payload_reactivation.py',
       'triage_evidence/audit_daemon_payload_reactivation.py','triage_evidence/verify_daemon_payload_reactivation_publication.py',
       'triage_evidence/daemon_payload_reactivation_checks.json','triage_evidence/daemon_payload_reactivation_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/daemon_payload_reactivation_checks.json','triage_evidence/daemon_payload_reactivation_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'cases':4,'intervals':28,'source_visits':141492,'reads':23080,'writes':12080,'logical_edges':2908,'source_calls':20}
INDEPENDENT={'register_values_checked': 4528640, 'NZCV_values_checked': 141520, 'vector_register_values_checked': 4528640, 'read_bytes_checked': 149676, 'source_visits': 141492, 'write_bytes_checked': 84372, 'original_authenticated_edges_checked': 2892, 'cross_interval_X8_fixup_origins_checked': 4}
MODEL={'complete_interval_joins_checked': 28, 'inverse_word_swaps_checked': 1088, 'inverse_payload_bytes_checked': 8736, 'raw_pointer_publications_checked': 4, 'four_byte_request_records_checked': 4, 'generated_bytes_copied_checked': 16, 'header_word_updates_checked': 4, 'slot_clear_fields_checked': 120, 'resealed_payload_bytes_checked': 8736, 'encoded_pointer_publications_checked': 4, 'distinct_status_and_adjustment_channels_checked': 4, 'generator_twist_words_checked': 2496, 'original_stream_bytes_preserved_checked': 128}
PRODUCER={'source_visits': 160048, 'read_bytes_checked': 87594, 'register_effects_checked': 142251, 'write_bytes_checked': 43191, 'write_effects_checked': 8566, 'unknown_copied_bytes_checked': 176, 'NZCV_effects_checked': 4691, 'producer_payload_checkpoint_bytes_checked': 4368, 'producer_pointer_publication_bytes_checked': 8}

def receipts():
    assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
    e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
    assert e['generator_sha256']==a['generator_sha256']==sha(R.__file__) and a['auditor_sha256']==sha(A.__file__)
    assert a['checks_sha256']==CHECKS_SHA and e['dependencies']==a['dependencies']=={n:sha(ROOT/n) for n in R.DEPS}
    assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert e['verified_counts']==a['verified_counts']==COUNTS and a['independent_totals']==INDEPENDENT and a['model_checks']==MODEL and a['all_checks_pass']
    assert e['source_regions']==R.source() and e['producer_evidence']==R.producer()
    slots=e['producer_evidence']['slot_initializer_writes'];assert len(slots)==120
    for j in range(30):
        for event,(pc,offset,n,value) in zip(slots[4*j:4*j+4],[(0x100293ee4,0,4,0),(0x100293ee8,8,8,0xe3b88695c0d52dbc),(0x100293eec,16,4,0x2480b3b0),(0x100293eec,20,4,0x8b3dc651)]):
            assert event['pc']==hex(pc) and event['address']==hex(R.D+24+72*j+offset) and event['size_bytes']==n and event['value']=={'hex':value.to_bytes(n,'little').hex()}
    producer=a['producer_replay'];assert producer['all_checks_pass'] and not producer['native_target_executed'] and producer['verified_counts']==PRODUCER
    assert PRODUCER['source_visits']==160048 and PRODUCER['producer_payload_checkpoint_bytes_checked']==4368 and PRODUCER['producer_pointer_publication_bytes_checked']==8
    parent=json.loads(read(ROOT/(R.Parent.P+'_checks.json')));h=Counter();counts=Counter();totals=Counter();model=Counter();used=set()
    assert [c['parent_case_index'] for c in e['cases']]==R.SELECTED==[0,2,12,14] and len(a['cases'])==4
    for c,ac in zip(e['cases'],a['cases']):
        assert ac['parent_case_index']==c['parent_case_index'] and ac['all_checks_pass']
        old=parent['cases'][c['parent_case_index']]
        assert not old['table_NULL_control'] and c['stream_parent_index']==old['parent_case_index'] and c['ABI_clobber_pattern']==old['ABI_clobber_pattern'] and c['auxiliary_pointer64']==old['pointer_return64']
        assert c['producer_state_effect']['address']==hex(R.D) and len(bytes.fromhex(c['producer_state_effect']['bytes_hex']))==2184
        rebuilt=json.loads(json.dumps(A.contract(c,old)));assert ac['contract']==rebuilt;model.update(rebuilt['model_checks'])
        rows=[R.unpack(p['packed']) for p in c['intervals']];assert len(rows)==len(ac['independent_lifts'])==7
        case_counts=Counter();case_totals=Counter()
        for row,lift in zip(rows,ac['independent_lifts']):
            h.update(hygiene(row));assert not row['native_target_executed'] and lift['all_checks_pass'] and not lift['native_target_executed']
            case_counts.update(R.rc(row));case_totals.update(lift['verified_counts'])
            assert len(row['source_visits'])==len(row['source_frames'])==lift['verified_counts']['source_visits'] and lift['boundary']==row['boundary']['pc']
            for visit,frame in zip(row['source_visits'],row['source_frames']):
                assert visit['bytes_hex']==IMAGE.read(int(visit['pc'],16),4).hex() and visit['pc']==frame['pc'] and len(frame['Q_registers32'])==32
            used.update(int(x['address'],16) for x in row['source_reads'] if int(x['address'],16) in FIXUPS)
        assert dict(case_counts)==c['counts'] and dict(case_totals)==ac['independent_totals'];counts.update(case_counts);totals.update(case_totals)
        boundary=rows[-1]['boundary'];assert boundary['registers31'][:3]==['0x4a',hex(R.J+0x118),'0x14'] and boundary['detail']['modifier']=='0x6aa4'
        record=int(rebuilt['status_record_pointer'],16)
        for pc,off,n,value in [(0x1004ceebc,0,8,R.J+0x118),(0x1004ceeb4,12,1,0xc6),(0x1004ceeac,16,8,0x6600003000),(0x1004ceea8,24,8,0x10102fa20),(0x1004ceec8,32,4,0xc03d9628)]:
            ws=A.selected(rows[-1],pc,'source_writes');assert len(ws)==1 and ws[0]['address']==hex(record+off) and ws[0]['size_bytes']==n and ws[0]['after_hex']==value.to_bytes(n,'little').hex()
        call=rebuilt['next_internal_call'];assert call['arguments8'][:2]==[hex(record),'0x2'] and call['modifier']=='0x704f'
    assert dict(totals)==INDEPENDENT and dict(model)==MODEL and dict(counts)=={k:COUNTS[k] for k in counts} and e['source_fixups']==R.fixups(used)
    check_query_comparison();fresh=A.obligations(e);assert len(fresh)==len(a['source_proofs'])==a['source_queries_unsat']==10
    for old,new in zip(a['source_proofs'],fresh):
        assert {k:v for k,v in old.items() if k!='query'}=={k:v for k,v in new.items() if k!='query'}
        oa,na=z3.parse_smt2_string(old['query']),z3.parse_smt2_string(new['query'])
        assert len(oa)==len(na)>0 and all(canonical_expression(x)==canonical_expression(y) for x,y in zip(oa,na))
        s=z3.Solver();s.set(timeout=30000);s.from_string(old['query']);assert s.check()==z3.unsat and old['premises_nonvacuous']
    for obj in [e,a]:
        h.update(hygiene(obj));assert all(not obj[k] for k in ['native_API_executed','native_daemon_kext_pairing_established','native_epoch_join_established','full_goal_complete'])
    report=read(BASE/'daemon_payload_reactivation_report.md');assert CHECKS_SHA in report and AUDIT_SHA in report
    assert all(f'| RA{j} |' in report for j in range(1,7)) and all(f'| RA-A{j}:' in report for j in range(1,11)) and all(f'**QG{j}**' in report for j in range(1,8))
    return e,a,h

def main():
    e,a,h=receipts();raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==8784 and len(after)==8790 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
    assert {p for p in before if before[p]!=after[p]}==CHANGED and new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256'] and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
    for suffix,value in [('increment_checks',COUNTS),('replay_checks',INDEPENDENT),('model_checks',MODEL),('static_scope',e['scope']),('source_queries_unsat',10)]:
        assert new['validation']['daemon_payload_reactivation_'+suffix]==value
    assert new['validation']['reports']==old['validation']['reports']+1==512 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        path_hygiene((BASE/p).read_bytes());path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
    assert delta==OWNED,delta^OWNED
    print(json.dumps({'unchanged_manifest_entries':8775,'owned_physical_files':16,'original_inputs_preserved':3,'reports':512,
                     'independent_lifts':28,'source_visits':141492,'fresh_producer_visits':160048,'source_queries_unsat':10,**h,
                     'native_API_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':main()
