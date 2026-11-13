#!/usr/bin/env python3
"""Verify generated-stream receipts, caller ABI boundaries and publication.

O(receipts+visits+intervals*N+owned bytes+manifest+query DAG) time;
O(receipt collection+largest interval+N) space;30 s/query. Native target
API/IPC/PAC, ownership and IDB mutation are not established or executed.
"""
import json,struct
from hashlib import sha256
from collections import Counter
from compression import zstd
import z3
from daemon_receive_tools import SOURCE,IMAGE,FIXUPS,TABLE,POOL,qword
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_daemon_payload_mix_publication import ROOT,BASE,git,hygiene,path_hygiene
from verify_daemon_second_mix_publication import canonical_expression,check_query_comparison
from audit_daemon_network_record import state_bytes,fixture_bytes
import recover_daemon_generated_stream as R
import audit_daemon_generated_stream as A

PREVIOUS='d8e8568a50cf4a4ea3ce9027024bcba6baa4be0d'
BASELINE_SHA='636636c478e306afbc6648cf70220800192ffb2ffd1a637df48a220598c5228d'
CHECKS_SHA='f926f57e47a7824e6ac4a7e7478c3edcbd8ae901cb251711fddb03b654f3f57a'
AUDIT_SHA='198480d68f27e2e2fc7c74137de448ed5c4e2250b552d2ced18796ceda57cc0e'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'mach_ports_report.md','interface_abi_report.md','interface_investigation_status.md',
         'obfuscated_routines_report.md','foundational_triage_report.md','corefp_client_paths_report.md',
         'daemon_postseed_output_report.md','daemon_payload_mix_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'daemon_generated_stream_report.md','triage_evidence/recover_daemon_generated_stream.py',
       'triage_evidence/audit_daemon_generated_stream.py','triage_evidence/verify_daemon_generated_stream_publication.py',
       'triage_evidence/daemon_generated_stream_checks.json','triage_evidence/daemon_generated_stream_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/daemon_generated_stream_checks.json','triage_evidence/daemon_generated_stream_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'cases':2,'zero_controls':2,'counter_controls':4,'intervals':226,'source_visits':190234,'reads':37970,'writes':9626,'logical_edges':9178,'source_calls':32}
INDEPENDENT={'register_values_checked': 6094720, 'NZCV_values_checked': 190460, 'vector_register_values_checked': 6094720, 'source_visits': 190234, 'read_bytes_checked': 191914, 'write_bytes_checked': 39580, 'original_authenticated_edges_checked': 9142, 'reloaded_saved_origins_checked': 4}
MODEL={'forced_zero_attempts_checked': 6, 'forced_zero_refills_checked': 2, 'separate_counter_partitions_checked': 4, 'complete_state_boundary_words_checked': 131040, 'encoded_byte_attempts_checked': 62, 'full_twist_refills_checked': 14, 'twist_word_updates_checked': 8736, 'selected_words_checked': 14, 'tempered_words_checked': 14, 'arena_copy_bytes_checked': 64, 'private_overwrite_bytes_checked': 64, 'status_pointer_mismatches_checked': 2, 'logical_caller_returns_checked': 4}

def bank_routes():
    left,right=0x100fc4130,0x101031ea0;l,r=IMAGE.read(left,256),IMAGE.read(right,256)
    values=[j^r[l[j]^0x4e] for j in range(256)];assert set(values)=={255}
    for add,bias,pointer in [(0x697,0xffffffffcf088d1a,0x1010c8268),(0x3bd,0xffffffff8fba20ba,0x1010c67d4)]:
        slot=POOL+8*(add+255);assert (qword(slot)+bias)&((1<<64)-1)==pointer
    return {'exhaustive_cached_root_bank_inputs_checked':256,'cached_root_bank_XOR_constant8':255}

def receipts():
    assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
    e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
    assert e['generator_sha256']==a['generator_sha256']==sha(R.__file__) and a['auditor_sha256']==sha(A.__file__)
    assert a['checks_sha256']==CHECKS_SHA and e['dependencies']==a['dependencies']=={n:sha(ROOT/n) for n in R.DEPS}
    assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert e['verified_counts']==a['verified_counts']==COUNTS and a['independent_totals']==INDEPENDENT and a['model_checks']==MODEL
    assert e['source_regions']==R.source() and a['all_checks_pass'];parent=json.loads(read(ROOT/(R.Parent.P+'_checks.json')))
    h=Counter();counts=Counter();totals=Counter();model=Counter();used=set();intervals=0
    def checked(row,lift):
        nonlocal intervals
        intervals+=1;assert lift['all_checks_pass'] and not row['native_target_executed'];h.update(hygiene(row));counts.update(R.rc(row));totals.update(lift['verified_counts'])
        assert len(row['source_visits'])==len(row['source_frames']) and len(row['entry_Q_registers32'])==len(row['boundary']['Q_registers32'])==32
        for v,f in zip(row['source_visits'],row['source_frames']):assert v['bytes_hex']==IMAGE.read(int(v['pc'],16),4).hex() and v['pc']==f['pc'] and len(f['Q_registers32'])==32
        assert lift['verified_counts']['source_visits']==len(row['source_visits'])
        used.update(int(x['address'],16) for x in row['source_reads'] if int(x['address'],16) in FIXUPS)
    for c,ac in zip(e['cases'],a['cases']):
        assert c['parent_case_index']==ac['parent_case_index'] and ac['all_checks_pass']
        before=R.unpack(parent['cases'][c['parent_case_index']]['intervals'][-1]['packed']);initial=state_bytes(before);mt=list(struct.unpack('<624I',A.raw(initial,R.G,2496)))
        output=int(c['output_pointer'],16);attempts=[];comparisons=[];assert len(c['intervals'])==len(ac['independent_lifts'])==105
        for p,lift in zip(c['intervals'],ac['independent_lifts']):
            row=R.unpack(p['packed']);A.joined(before,row);checked(row,lift);label=p['label'];s=state_bytes(row)
            if label.startswith('refill_first_twist') or label.startswith('refill_second_twist') or label=='refill_last_twist_and_retained_index':
                part=0 if label.startswith('refill_first') else 1 if label.startswith('refill_second') else 2
                indices=[range(227),range(227,623),range(623,624)][part];pc=[0x100a5e93c,0x100b312a4,0x100a2f634][part]
                ww=A.selected(row,pc,'source_writes');assert len(ww)==len(indices)
                for i,w in zip(indices,ww):
                    nxt=mt[(i+1)%624];y=(mt[i]&0x80000000)|(nxt&0x7fffffff);mt[i]=A.u32(mt[(i+397)%624]^(y>>1)^(0x9908b0df if nxt&1 else 0))
                    assert w['address']==hex(R.G+4*i) and w['after_hex']==struct.pack('<I',mt[i]).hex()
            if label=='encoded_byte_attempt':attempts.append(A.codec(row))
            if label in ['counter_record_refill_to_twist','refill_selection_and_counter_comparison']:comparisons.append(A.comparison(row,'refill' if label.startswith('counter_record') else 'selection'))
            if row['entry_PC']==hex(R.DONE):
                completed=A.raw(fixture_bytes(row,'private'),output,32);assert completed.hex()==c['completed_output32_hex'] and A.caller(row,completed,output)==ac['caller_contract']
            assert A.raw(s,R.G,2496)==struct.pack('<624I',*mt);before=row
        assert attempts==ac['byte_attempts'] and comparisons==ac['comparisons'] and len(attempts)==31
        assert sha256(struct.pack('<624I',*mt)).hexdigest()==ac['final_array_sha256'] and struct.pack('<624I',*mt).hex()==c['final_generated_array2496_hex']
        assert c['final_boundary']==before['boundary'] and c['final_NZCV']==before['boundary_NZCV'] and before['boundary']['pc']==hex(R.NEXT)
        model.update(ac['model_checks'])
    extra=a['controls'];assert extra['all_checks_pass'] and len(e['zero_controls'])==len(extra['zero_controls'])==2
    for c,ac in zip(e['zero_controls'],extra['zero_controls']):
        main=e['cases'][c['parent_case_index']];origin=R.unpack(main['intervals'][c['parent_main_interval_index']]['packed']);before=R.entry(origin);effect=c['entry_register_effect']
        assert before['boundary']['registers31'][9]==effect['before'];before['boundary']['registers31']=before['boundary']['registers31'].copy();before['boundary']['registers31'][9]=effect['after'];attempts=[]
        assert len(c['intervals_packed'])==len(ac['independent_lifts'])==6
        for packed,lift in zip(c['intervals_packed'],ac['independent_lifts']):
            row=R.unpack(packed);A.joined(before,row);checked(row,lift)
            if row['entry_PC']==hex(R.BYTE):attempts.append(A.codec(row))
            before=row
        assert attempts==ac['attempts'] and all(x['stored8_hex']=='00' and x['remaining_after']==31 for x in attempts)
        assert len({x['address'] for x in attempts})==1 and before['boundary']['pc']==hex(R.REFILL)
    for c,ac in zip(e['counter_controls'],extra['counter_controls']):
        origin=R.unpack(e['cases'][c['parent_case_index']]['intervals'][c['parent_main_interval_index']]['packed']);row=R.unpack(c['intervals_packed'][0])
        A.joined(R.entry(origin),row,[c['effect']]);checked(row,ac['independent_lift']);assert A.comparison(row,'refill')==ac['comparison']
        assert ac['comparison']['A64']==c['counter32'] and row['boundary']['pc']==hex(R.ADMISSION if c['counter32']==0 else R.TWIST_ENTRY)
    model.update(extra['model_checks']);assert dict(model)==MODEL and dict(totals)==INDEPENDENT and intervals==COUNTS['intervals'] and dict(counts)=={k:COUNTS[k] for k in counts}
    assert e['source_fixups']==R.fixups(used);h.update(bank_routes())
    for index,target in [(0x26d1,R.BYTE),(0x2700,R.REFILL),(0xc4da,R.DONE),(0x177c,R.ADMISSION),(0x1782,R.TWIST_ENTRY)]:assert FIXUPS[TABLE+8*index]['target']==target
    check_query_comparison();fresh=A.obligations();assert len(fresh)==len(a['source_proofs'])==a['source_queries_unsat']==7
    for old,new in zip(a['source_proofs'],fresh):
        assert {k:v for k,v in old.items() if k!='query'}=={k:v for k,v in new.items() if k!='query'}
        oa,na=z3.parse_smt2_string(old['query']),z3.parse_smt2_string(new['query']);assert len(oa)==len(na)>0 and all(canonical_expression(x)==canonical_expression(y) for x,y in zip(oa,na))
        s=z3.Solver();s.set(timeout=30000);s.from_string(old['query']);assert s.check()==z3.unsat and old['premises_nonvacuous']
    for obj in [e,a]:
        h.update(hygiene(obj));assert all(not obj[k] for k in ['native_API_executed','native_daemon_kext_pairing_established','native_epoch_join_established','full_goal_complete'])
    report=read(BASE/'daemon_generated_stream_report.md');assert CHECKS_SHA in report and AUDIT_SHA in report
    assert all(f'| GS{j} |' in report for j in range(1,7)) and all(f'| GS-A{j}:' in report for j in range(1,11)) and all(f'**QG{j}**' in report for j in range(1,8))
    return e,a,h

def main():
    e,a,h=receipts();raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==8772 and len(after)==8778 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
    assert {p for p in before if before[p]!=after[p]}==CHANGED and new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256'] and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
    for suffix,value in [('increment_checks',COUNTS),('replay_checks',INDEPENDENT),('model_checks',MODEL),('static_scope',e['scope']),('source_queries_unsat',7)]:assert new['validation']['daemon_generated_stream_'+suffix]==value
    assert new['validation']['reports']==old['validation']['reports']+1==510 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,delta^OWNED
    print(json.dumps({'unchanged_manifest_entries':8763,'owned_physical_files':16,'original_inputs_preserved':3,'reports':510,
                     'independent_lifts':226,'source_visits':190234,'source_queries_unsat':7,**h,'native_API_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':main()
