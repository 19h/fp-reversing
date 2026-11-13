#!/usr/bin/env python3
"""Verify post-seed cleanup, full twist, first encoded byte and publication.

O(decoded receipts+visits+N+owned bytes+manifest+query DAG) time;
O(receipt collection+largest interval+N) space;30 s/query.
No native target/API/IPC/PAC/ownership or IDB mutation executes.
"""
import json,struct
from hashlib import sha256
from collections import Counter
from compression import zstd
import z3
from daemon_receive_tools import SOURCE,IMAGE,FIXUPS,TABLE
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_daemon_payload_mix_publication import ROOT,BASE,git,hygiene,path_hygiene
from verify_daemon_second_mix_publication import canonical_expression,check_query_comparison
from audit_daemon_network_record import state_bytes,fixture_bytes
import recover_daemon_postseed_output as R
import audit_daemon_postseed_output as A

PREVIOUS='92fbc6bc627e23c65a9c95b86b7a7aeb80af47d0'
BASELINE_SHA='e1fe874fbd42bae2cc22816ddb01295eae17c7ae7cce3ab28150cbe9957bda9b'
CHECKS_SHA='6466a4b4d732b9f65d45e419d8516a25a951390db5017a29a352e512281cea6b'
AUDIT_SHA='a0b681b43750070af2f4d76bd4c16739de3b216461eebca5db5f55749a404fde'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'mach_ports_report.md','interface_abi_report.md','interface_investigation_status.md',
         'obfuscated_routines_report.md','foundational_triage_report.md','corefp_client_paths_report.md',
         'daemon_second_mix_report.md','daemon_arena_split_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'daemon_postseed_output_report.md','triage_evidence/recover_daemon_postseed_output.py',
       'triage_evidence/audit_daemon_postseed_output.py','triage_evidence/verify_daemon_postseed_output_publication.py',
       'triage_evidence/daemon_postseed_output_checks.json','triage_evidence/daemon_postseed_output_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/daemon_postseed_output_checks.json','triage_evidence/daemon_postseed_output_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'cases':2,'intervals':28,'source_visits':31424,'reads':5750,'writes':1852,'logical_edges':1572,'source_calls':2}
INDEPENDENT={'register_values_checked':1006464,'NZCV_values_checked':31452,'vector_register_values_checked':1006464,
             'source_visits':31424,'read_bytes_checked':30614,'original_authenticated_edges_checked':1570,'write_bytes_checked':7706}
MODEL={'unchanged_cleanup_state_words_checked':7488,'twist_word_updates_checked':1248,'odd_table_choices':628,'even_table_choices':620,
       'complete_twist_boundary_words_checked':3744,'payload_overwrite_bytes_checked':108,'arena_head_overwrite_bytes_checked':172,
       'snapshot_added_bytes_checked':16,'strict_missing_field_controls_checked':2,'gate_releases_checked':2,'index_resets_checked':2,
       'selected_words_checked':2,'tempered_words_checked':2,'encoded_output_bytes_checked':2}

def receipts():
    assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
    e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
    assert e['generator_sha256']==a['generator_sha256']==sha(R.__file__) and a['auditor_sha256']==sha(A.__file__)
    assert a['checks_sha256']==CHECKS_SHA and e['dependencies']==a['dependencies']=={n:sha(ROOT/n) for n in R.DEPS}
    assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert e['verified_counts']==a['verified_counts']==COUNTS and a['independent_totals']==INDEPENDENT and a['model_checks']==MODEL
    assert e['source_regions']==R.source() and e['route_decoder']==R.route_decoder() and e['snapshot_neighbor']==R.neighbor()
    assert len(e['cases'])==len(a['cases'])==2 and a['all_checks_pass'];h=Counter();counts=Counter();totals=Counter();models=Counter();used=set()
    parent=json.loads(read(ROOT/(R.Parent.P+'_checks.json')))
    for c,ac in zip(e['cases'],a['cases']):
        assert c['parent_case_index']==ac['parent_case_index'] and ac['all_checks_pass'];before=R.Parent.Parent.unpack(parent['cases'][c['parent_case_index']]['exit_intervals_packed'][-1])
        initial=state_bytes(before);mt=list(struct.unpack('<624I',A.raw(initial,R.G,2496)));sp=int(before['boundary']['SP'],16)
        assert A.raw(initial,R.G,2496).hex()==c['entry_state2496_hex'];rows=[];cc=Counter()
        assert len(c['intervals'])==len(ac['independent_lifts'])==13
        for k,(p,lift) in enumerate(zip(c['intervals'],ac['independent_lifts'])):
            row=R.Parent.Parent.unpack(p['packed']);A.joined(before,row,[c['snapshot_neighbor_effect']] if k==4 else [])
            h.update(hygiene(row));assert lift['all_checks_pass'] and not row['native_target_executed'];rows.append(row)
            assert len(row['source_frames'])==len(row['source_visits'])
            for v,f in zip(row['source_visits'],row['source_frames']):
                assert v['bytes_hex']==IMAGE.read(int(v['pc'],16),4).hex() and v['pc']==f['pc'] and len(f['Q_registers32'])==32
            rc={key:len(row[field]) for key,field in [('source_visits','source_visits'),('reads','source_reads'),('writes','source_writes'),('logical_edges','logical_edges'),('source_calls','source_calls')]}
            assert lift['verified_counts']['source_visits']==rc['source_visits'];cc.update(rc);totals.update(lift['verified_counts'])
            used.update(int(x['address'],16) for x in row['source_reads'] if int(x['address'],16) in FIXUPS)
            actual=state_bytes(row)
            if k<6:assert A.raw(actual,R.G,2496)==struct.pack('<624I',*mt)
            if k in [6,7,8]:
                indices=range(227) if k==6 else range(227,623) if k==7 else range(623,624)
                pc=[0x100a5e93c,0x100b312a4,0x100a2f634][k-6];writes=A.selected(row,pc,'source_writes');assert len(writes)==len(indices)
                for i,w in zip(indices,writes):
                    nxt=mt[(i+1)%624];y=(mt[i]&0x80000000)|(nxt&0x7fffffff)
                    mt[i]=A.u32(mt[(i+397)%624]^(y>>1)^(0x9908b0df if nxt&1 else 0))
                    assert w['address']==hex(R.G+4*i) and w['after_hex']==struct.pack('<I',mt[i]).hex()
                assert A.raw(actual,R.G,2496)==struct.pack('<624I',*mt)
            before=row
        control=R.Parent.Parent.unpack(c['missing_neighbor_control_packed']);A.joined(rows[3],control);h.update(hygiene(control))
        assert not any(control[f] for f in ['source_visits','source_reads','source_writes','source_calls','logical_edges'])
        assert control['boundary']['kind']=='before_undefined_foreign_owner_read' and control['boundary']['detail']=={'address':e['snapshot_neighbor']['address'],'size_bytes':8}
        assert ac['missing_field_lift']['all_checks_pass'];totals.update(ac['missing_field_lift']['verified_counts'])
        assert [len(r['source_visits']) for r in rows]==[46,14,24,1048,1820,27,4540,7933,30,7,96,56,71]
        assert A.comparison(rows[10])==ac['comparison'] and A.codec(rows[12])==ac['codec']
        assert ac['raw_selected_u32']==hex(mt[0]) and c['output_first_byte_hex']==ac['codec']['stored8_hex']
        assert A.raw(state_bytes(rows[-1]),R.G,2496).hex()==c['final_state2496_hex']==struct.pack('<624I',*mt).hex()
        assert sha256(struct.pack('<624I',*mt)).hexdigest()==ac['final_state_sha256']
        assert c['final_boundary']==rows[-1]['boundary'] and c['final_NZCV']==rows[-1]['boundary_NZCV']
        assert c['final_boundary']['pc']==hex(R.NEXT) and ac['codec']['defined_output_bytes']==1 and ac['codec']['unknown_output_bytes']==31
        assert dict(cc)==c['counts'];counts.update(cc);models.update(ac['model_checks'])
    assert dict(totals)==INDEPENDENT and dict(models)==MODEL and dict(counts)=={k:COUNTS[k] for k in counts}
    assert e['source_fixups']==R.Parent.Parent.Parent.Parent.Parent.Parent.Parent.Parent.Parent.Parent.Env.fixups(used)
    # Independently resolve all reported alternatives, including unexecuted guards.
    for index,target in [(0xcbc1,R.POINTER),(0xcbb6,R.RELEASE),(0x5ae9,R.EXTENT),(0x5aeb,R.RELEASE),(0x75f8,R.RETIRE),(0x24f4,R.RELEASE),
                         (0x1782,0x100a6cd1c),(0x56c9,R.TWIST2),(0xaa52,R.TWIST_LAST),(0x6d1a,R.RESET),(0x6d0e,R.SELECT),
                         (0x16a1,R.COUNTER),(0x6058,0x100a7ccac),(0x26d1,R.BYTE),(0xbc66,R.NEXT)]:assert FIXUPS[TABLE+8*index]['target']==target
    check_query_comparison();fresh=A.obligations();assert len(fresh)==len(a['source_proofs'])==a['source_queries_unsat']==11
    for old,new in zip(a['source_proofs'],fresh):
        assert {k:v for k,v in old.items() if k!='query'}=={k:v for k,v in new.items() if k!='query'}
        oa,na=z3.parse_smt2_string(old['query']),z3.parse_smt2_string(new['query']);assert len(oa)==len(na)>0
        assert all(canonical_expression(x)==canonical_expression(y) for x,y in zip(oa,na))
        s=z3.Solver();s.set(timeout=30000);s.from_string(old['query']);assert s.check()==z3.unsat and old['premises_nonvacuous']
    for obj in [e,a]:
        h.update(hygiene(obj));assert all(not obj[k] for k in ['native_API_executed','native_daemon_kext_pairing_established','native_epoch_join_established','full_goal_complete'])
    report=read(BASE/'daemon_postseed_output_report.md');assert CHECKS_SHA in report and AUDIT_SHA in report
    assert all(f'| PO{j} |' in report for j in range(1,7)) and all(f'| PO-A{j}:' in report for j in range(1,11)) and all(f'**QG{j}**' in report for j in range(1,8))
    return e,a,h

def main():
    e,a,h=receipts();raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==8766 and len(after)==8772 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
    assert {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256'] and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
    for suffix,value in [('increment_checks',COUNTS),('replay_checks',INDEPENDENT),('model_checks',MODEL),('static_scope',e['scope']),('source_queries_unsat',11)]:
        assert new['validation']['daemon_postseed_output_'+suffix]==value
    assert new['validation']['reports']==old['validation']['reports']+1==509 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,delta^OWNED
    print(json.dumps({'unchanged_manifest_entries':8757,'owned_physical_files':16,'original_inputs_preserved':3,'reports':509,
                     'independent_lifts':28,'source_visits':31424,'source_queries_unsat':11,**h,'native_API_executed':False,
                     'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':main()
