#!/usr/bin/env python3
"""Verify first-pass source receipts, compact state composition and publication.

O(decoded receipts+visits+iterations*N+owned bytes+manifest+query DAG) time;
O(receipt collection+largest interval+N) space. Solver limit30 s/query.
No native target operation, IDB mutation or Git-history rewrite executes.
"""
import json,struct,subprocess
from pathlib import Path
from hashlib import sha256
from collections import Counter
from compression import zstd
import z3
from daemon_receive_tools import SOURCE,IMAGE,FIXUPS,TABLE
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene
from verify_daemon_iokit_result_publication import decoded_hex_hygiene
from verify_corefp_late_preparation_publication import paths_in_typed_payloads
from audit_daemon_network_record import state_bytes
import recover_daemon_payload_mix as R
import audit_daemon_payload_mix as A

ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='e24a4782c68beb3579b5e26236b87dd4af051f3a'
BASELINE_SHA='d7f6c958e1fb0b173912720a8bd23d00d47b3440551f09e3907a368901fcedae'
CHECKS_SHA='28c45f52155b22f2e6e30e6864489159e0f87477543a3fe3f0c8761dc9d5b829'
AUDIT_SHA='48e9c204e37cabc3688f1450869bc1e79fc4449348f48bb20eb165bf03e826e2'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'mach_ports_report.md','interface_abi_report.md','interface_investigation_status.md',
         'obfuscated_routines_report.md','foundational_triage_report.md','corefp_client_paths_report.md',
         'daemon_clock_record_report.md','daemon_arena_split_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'daemon_payload_mix_report.md','triage_evidence/recover_daemon_payload_mix.py',
       'triage_evidence/audit_daemon_payload_mix.py','triage_evidence/verify_daemon_payload_mix_publication.py',
       'triage_evidence/daemon_payload_mix_checks.json','triage_evidence/daemon_payload_mix_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/daemon_payload_mix_checks.json','triage_evidence/daemon_payload_mix_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'cases':2,'intervals':1250,'source_visits':379704,'reads':68842,'writes':22430,'logical_edges':11214,'source_calls':2492}
INDEPENDENT={'register_values_checked': 12190528, 'NZCV_values_checked': 380954, 'vector_register_values_checked': 12190528, 'read_bytes_checked': 383760, 'source_visits': 379704, 'write_bytes_checked': 109656, 'original_authenticated_edges_checked': 8722, 'inherited_exit_origins_checked': 2}
MODEL={'complete_state_words_checked':777504,'complete_key_words_checked':4984,'exact_intermediate_joins_checked':1246,
       'state_wraps_checked':2,'key_0_mutations_checked':312,'key_1_mutations_checked':310,
       'key_2_mutations_checked':312,'key_3_mutations_checked':312}
CONTROL={'0x1009c4808_true':2,'0x1009c4808_false':1244,'0x100b6bb74_true':312,'0x100b6bb74_false':934}

def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)

def hygiene(obj):
    path_hygiene(json.dumps(obj).encode());path_hygiene(json.dumps(paths_in_typed_payloads(obj)).encode())
    n,b=decoded_hex_hygiene(obj);return Counter(decoded_hex_fields_path_checked=n,decoded_hex_bytes_path_checked=b)

def exit_origin(load,transfer):
    slot=TABLE+8*0xa559;target=0x100abba18;reads=load['source_reads'];assert len(reads)==1
    event=reads[0];assert event['pc']=='0x100aaeffc' and event['address']==hex(slot) and event['size_bytes']==8
    assert int.from_bytes(bytes.fromhex(event['bytes_hex']),'little')==FIXUPS[slot]['target']==target
    frame=load['source_frames'][event['source_visit_index']]
    assert int(frame['registers31'][26],16)==TABLE and frame['registers31'][9]=='0xa559'
    tail=load['source_visits'][event['source_visit_index']+1:]
    assert [v['pc'] for v in tail]==['0x100aaf000','0x100aaf004']
    decoded=[next(R.CS.disasm(bytes.fromhex(v['bytes_hex']),int(v['pc'],16))) for v in tail]
    assert [(x.mnemonic,x.op_str) for x in decoded]==[('mov','w25, #0x26f'),('mov','x17, #0x35e7')]
    for f in load['source_frames'][event['source_visit_index']+1:]:assert f['registers31'][9]==hex(target)
    assert load['boundary']['registers31'][9]==transfer['entry_registers31'][9]==hex(target)
    assert transfer['entry_registers31'][17]=='0x35e7' and transfer['entry_PC']=='0x100aaf008'
    assert len(transfer['source_visits'])==1 and transfer['boundary']['pc']==hex(target)

def receipts():
    assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
    e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
    assert e['generator_sha256']==a['generator_sha256']==sha(R.__file__) and a['auditor_sha256']==sha(A.__file__)
    assert a['checks_sha256']==CHECKS_SHA and e['dependencies']==a['dependencies']=={n:sha(ROOT/n) for n in R.DEPS}
    assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert e['verified_counts']==a['verified_counts']==COUNTS and a['independent_totals']==INDEPENDENT
    assert a['model_checks']==MODEL and a['control_checks']==CONTROL and a['all_checks_pass']
    assert e['source_regions']==R.source() and len(e['cases'])==len(a['cases'])==2
    parent=json.loads(read(ROOT/(R.Parent.P+'_checks.json')));counts=Counter();totals=Counter();used=set();h=Counter()
    for c,ac in zip(e['cases'],a['cases']):
        assert c['parent_seed_case_index']==ac['parent_seed_case_index'] and ac['all_checks_pass']
        assert len(c['intervals_packed'])==len(c['iteration_records'])==len(ac['comparison_records'])==623
        assert len(c['exit_intervals_packed'])==2 and len(ac['independent_lifts'])==625
        before=parent['seed_cases'][c['parent_seed_case_index']]['intervals'][-1];initial=state_bytes(before)
        q=int(before['boundary']['SP'],16)+0x220;payload=bytes(initial[R.Parent.PAYLOAD+j] for j in range(64));d=A.masks(payload)
        assert ac['mutation_masks32']==[hex(x) for x in d]==['0x11521c','0xb50bf7c4','0x7c5f740','0xa2674a96']
        mt=list(struct.unpack('<624I',bytes(initial[R.G+j] for j in range(2496))));keys=list(struct.unpack('<4I',bytes(initial[q+j] for j in range(16))))
        assert struct.pack('<624I',*mt).hex()==c['entry_state2496_hex'] and struct.pack('<4I',*keys).hex()==c['entry_key16_hex']
        i,j,remaining=2,1,623;cc=Counter();cm=Counter();ct=Counter();last_exit=[];payload_used=set();text_used=set()
        for k,(packed,lift) in enumerate(zip(c['intervals_packed']+c['exit_intervals_packed'],ac['independent_lifts'])):
            row=R.unpack(packed);A.joined(before,row);h.update(hygiene(row));assert lift['all_checks_pass'] and not row['native_target_executed']
            assert len(row['source_visits'])==len(row['source_frames']) and len(row['entry_Q_registers32'])==len(row['boundary']['Q_registers32'])==32
            for v,f in zip(row['source_visits'],row['source_frames']):
                assert v['bytes_hex']==IMAGE.read(int(v['pc'],16),4).hex() and v['pc']==f['pc'] and len(f['Q_registers32'])==32
            rc={key:len(row[field]) for key,field in [('source_visits','source_visits'),('reads','source_reads'),('writes','source_writes'),('logical_edges','logical_edges'),('source_calls','source_calls')]}
            assert lift['verified_counts']['source_visits']==rc['source_visits'];cc.update(rc);totals.update(lift['verified_counts'])
            used.update(int(x['address'],16) for x in row['source_reads'] if int(x['address'],16) in FIXUPS)
            if k<623:
                assert [int(row['entry_registers31'][r],16) for r in [19,27,24]]==[i,j,remaining]
                mt[i]=((mt[i]^((mt[i-1]^(mt[i-1]>>30))*1664525&0xffffffff))+keys[j]+j)&0xffffffff;i+=1
                if i==624:mt[0]=mt[623];i=1;cm['state_wraps_checked']+=1
                j=(j+1)%4;keys[j]^=d[j];cm['key_'+str(j)+'_mutations_checked']+=1
                if k<622:remaining-=1
                pr=[x for x in row['source_reads'] if R.Parent.PAYLOAD<=int(x['address'],16)<R.Parent.PAYLOAD+64]
                if j:
                    assert len(pr)==1 and pr[0]['address']==hex(R.Parent.PAYLOAD+4*j) and pr[0]['size_bytes']==4
                    assert pr[0]['bytes_hex']==payload[4*j:4*j+4].hex()
                    payload_used.update(range(4*j,4*j+4))
                    frame=row['source_frames'][pr[0]['source_visit_index']];gp=frame['registers31']
                    assert gp[12]=='0x3' and int(gp[13],16)&1==0
                    tr=[x for x in row['source_reads'] if int(x['address'],16) in [0x100822c80+4*j,0x100822c82+4*j]]
                    assert len(tr)==2
                    for x in tr:
                        address=int(x['address'],16);assert x['bytes_hex']==IMAGE.read(address,4).hex() and x['size_bytes']==4
                        text_used.update(range(address,address+4))
                else:assert not pr
                for w in row['source_writes']:
                    address=int(w['address'],16);end=address+len(bytes.fromhex(w['after_hex']))
                    assert not(address<R.Parent.PAYLOAD+64 and R.Parent.PAYLOAD<end)
                    assert not(address<0x100822c92 and 0x100822c84<end)
                actual=state_bytes(row);assert bytes(actual[R.G+t] for t in range(2496))==struct.pack('<624I',*mt)
                assert bytes(actual[q+t] for t in range(16))==struct.pack('<4I',*keys)
                assert [int(row['boundary']['registers31'][r],16) for r in [19,27,24]]==[i,j,remaining]
                record=c['iteration_records'][k];assert record['iteration']==k+2 and record['key16_hex']==struct.pack('<4I',*keys).hex()
                contract=A.comparisons(row);assert contract==ac['comparison_records'][k]
                for x in contract:ct[x['call_site']+('_true' if x['predicate'] else '_false')]+=1
                cm.update(complete_state_words_checked=624,complete_key_words_checked=4,exact_intermediate_joins_checked=1)
                if k==622:assert c['first_pass_boundary']==row['boundary'] and c['first_pass_NZCV']==row['boundary_NZCV']
            else:last_exit.append(row)
            before=row
        exit_origin(*last_exit)
        assert payload_used==set(range(4,16)) and text_used==set(range(0x100822c84,0x100822c92))
        assert dict(cc)==c['counts'] and dict(cm)==ac['model_checks'] and dict(ct)==ac['control_checks']
        assert keys==[0xffffffff,0,0,0] and c['final_state2496_hex']==struct.pack('<624I',*mt).hex() and c['final_key16_hex']==struct.pack('<4I',*keys).hex()
        assert c['final_boundary']==before['boundary'] and c['final_NZCV']==before['boundary_NZCV'] and before['boundary']['registers31'][24]=='0x0'
        counts.update(cc)
        print(json.dumps({'packed_case_checked':c['parent_seed_case_index'],'source_visits':counts['source_visits']}),flush=True)
    assert dict(counts)=={k:COUNTS[k] for k in counts} and dict(totals)==INDEPENDENT
    assert e['source_fixups']==R.Parent.Parent.Parent.Parent.Parent.Parent.Parent.Parent.Env.fixups(used)
    fresh=A.obligations();assert len(fresh)==len(a['source_proofs'])==a['source_queries_unsat']==8
    for old,new in zip(a['source_proofs'],fresh):
        assert {k:v for k,v in old.items() if k!='query'}=={k:v for k,v in new.items() if k!='query'}
        oa,na=z3.parse_smt2_string(old['query']),z3.parse_smt2_string(new['query']);assert len(oa)==len(na)>0 and all(x.eq(y) for x,y in zip(oa,na))
        s=z3.Solver();s.set(timeout=30000);s.from_string(old['query']);assert s.check()==z3.unsat and old['premises_nonvacuous']
    for obj in [e,a]:
        h.update(hygiene(obj));assert all(not obj[k] for k in ['native_API_executed','native_daemon_kext_pairing_established','native_epoch_join_established','full_goal_complete'])
    report=read(BASE/'daemon_payload_mix_report.md')
    assert CHECKS_SHA in report and AUDIT_SHA in report and all(f'| PM{j} |' in report for j in range(1,7))
    assert all(f'| PM-A{j}:' in report for j in range(1,10)) and all(f'**QG{j}**' in report for j in range(1,8))
    return e,a,h

def main():
    e,a,h=receipts();raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==8754 and len(after)==8760 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
    assert {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256'] and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
    for suffix,value in [('increment_checks',COUNTS),('replay_checks',INDEPENDENT),('model_checks',MODEL),('control_checks',CONTROL),('static_scope',e['scope']),('source_queries_unsat',8)]:
        assert new['validation']['daemon_payload_mix_'+suffix]==value
    assert new['validation']['reports']==old['validation']['reports']+1==507 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
    assert delta==OWNED,delta^OWNED
    print(json.dumps({'unchanged_manifest_entries':8745,'owned_physical_files':16,'original_inputs_preserved':3,'reports':507,
        'independent_lifts':1250,'source_visits':379704,'source_queries_unsat':8,**h,
        'native_API_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':main()
