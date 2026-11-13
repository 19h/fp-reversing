#!/usr/bin/env python3
"""Verify source-pinned second mixing pass, gate transition and publication.

O(decoded receipts+visits+iterations*N+owned bytes+manifest+query DAG) time;
O(receipt collection+largest interval+N) space. Solver limit30 s/query.
No native API/IPC, concurrent target operation, PAC or IDB mutation executes.
"""
import json,struct
from hashlib import sha256
from collections import Counter
from itertools import chain
from compression import zstd
import z3
from daemon_receive_tools import SOURCE,IMAGE,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_daemon_payload_mix_publication import ROOT,BASE,git,hygiene,path_hygiene
from audit_daemon_network_record import state_bytes
import recover_daemon_second_mix as R
import audit_daemon_second_mix as A

PREVIOUS='8173d1677965b3818f397688de3f33df9eb42555'
BASELINE_SHA='6ae6e57b35cdad8ed7c51ae5b2fc95088166bf06a43627e63d502a02d9273c34'
CHECKS_SHA='de0faa88143debe0cd696ebe39f86a3e82dc0875233629a4e8f4357ac7c1c69e'
AUDIT_SHA='0ca3ddf3e468e960ca30a972380591b7a488086a7d7ae7437b4b28eebb1fe575'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'mach_ports_report.md','interface_abi_report.md','interface_investigation_status.md',
         'obfuscated_routines_report.md','foundational_triage_report.md','corefp_client_paths_report.md',
         'daemon_payload_mix_report.md','daemon_readiness_arena_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'daemon_second_mix_report.md','triage_evidence/recover_daemon_second_mix.py',
       'triage_evidence/audit_daemon_second_mix.py','triage_evidence/verify_daemon_second_mix_publication.py',
       'triage_evidence/daemon_second_mix_checks.json','triage_evidence/daemon_second_mix_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/daemon_second_mix_checks.json','triage_evidence/daemon_second_mix_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'cases':2,'intervals':1252,'source_visits':181990,'reads':28672,'writes':11220,'logical_edges':6234,'source_calls':1246}
INDEPENDENT={'register_values_checked': 5863744, 'NZCV_values_checked': 183242, 'vector_register_values_checked': 5863744, 'read_bytes_checked': 157084, 'source_visits': 181990, 'write_bytes_checked': 54848, 'original_authenticated_edges_checked': 4988, 'gate_CAS_value_transitions_checked': 2}
MODEL={'complete_state_words_checked':777504,'unchanged_key_words_checked':4984,'unchanged_payload_bytes_checked':79744,
       'exact_iteration_joins_checked':1246,'state_wraps_checked':2,'final_word_forces_checked':2,'same_gate_reacquisitions_checked':2}

def canonical_expression(expr):
    """Fingerprint a query DAG, sorting only commutative operator children."""
    commutative={z3.Z3_OP_AND,z3.Z3_OP_OR,z3.Z3_OP_XOR,z3.Z3_OP_EQ,z3.Z3_OP_DISTINCT,
                 z3.Z3_OP_BADD,z3.Z3_OP_BMUL,z3.Z3_OP_BAND,z3.Z3_OP_BOR,z3.Z3_OP_BXOR}
    cache={}
    def walk(x):
        key=x.get_id()
        if key in cache:return cache[key]
        assert z3.is_app(x)
        d=x.decl();children=[walk(v) for v in x.children()]
        if d.kind() in commutative:children.sort()
        node=[d.kind(),str(d.name()),x.sort().sexpr(),[str(v) for v in d.params()],children,x.sexpr() if not children else None]
        cache[key]=sha256(json.dumps(node,separators=(',',':')).encode()).hexdigest();return cache[key]
    return walk(expr)

def check_query_comparison():
    a,b=z3.BitVecs('sx_canonical_a32 sx_canonical_b32',32)
    assert canonical_expression(z3.Or(a==1,b==2))==canonical_expression(z3.Or(b==2,a==1))
    assert canonical_expression(z3.Or(a==1,b==2))!=canonical_expression(z3.And(a==1,b==2))
    assert canonical_expression(z3.Or(a==1,b==2))!=canonical_expression(z3.Or(a==1,b==3))
    assert canonical_expression(a-b)!=canonical_expression(b-a)

def lifecycle(c,parent):
    arena=json.loads(read(ROOT/(R.Parent.Parent.P+'_checks.json')))
    seed=arena['seed_cases'][parent['parent_seed_case_index']];marker=arena['marker_cases'][seed['parent_marker_case_index']]
    release=[w for w in marker['intervals'][0]['source_writes'] if int(w['address'],16)<=R.GATE_WORD<int(w['address'],16)+w['size_bytes']]
    assert len(release)==1 and release[0]['pc']=='0x100a8c078' and release[0]['after_hex']=='965d0000'
    rows=chain(seed['intervals'],(R.Parent.unpack(x) for x in parent['intervals_packed']+parent['exit_intervals_packed']))
    intervals=writes=0
    for row in rows:
        for w in row['source_writes']:
            address=int(w['address'],16);assert not(address<R.GATE_WORD+4 and R.GATE_WORD<address+w['size_bytes']);writes+=1
        state=state_bytes(row);assert bytes(state[R.GATE_WORD+j] for j in range(4)).hex()=='965d0000';intervals+=1
    return {'release_writers_checked':1,'gate_preserving_parent_intervals_checked':intervals,'parent_write_events_censused':writes}

def receipts():
    assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
    e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
    assert e['generator_sha256']==a['generator_sha256']==sha(R.__file__) and a['auditor_sha256']==sha(A.__file__)
    assert a['checks_sha256']==CHECKS_SHA and e['dependencies']==a['dependencies']=={n:sha(ROOT/n) for n in R.DEPS}
    assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert e['verified_counts']==a['verified_counts']==COUNTS and a['independent_totals']==INDEPENDENT and a['model_checks']==MODEL
    assert e['source_regions']==R.source() and len(e['cases'])==len(a['cases'])==2 and a['all_checks_pass']
    parent=json.loads(read(ROOT/(R.Parent.P+'_checks.json')));counts=Counter();totals=Counter();used=set();h=Counter();life=Counter()
    for c,ac in zip(e['cases'],a['cases']):
        assert c['parent_case_index']==ac['parent_case_index'] and ac['all_checks_pass']
        assert len(c['intervals_packed'])==len(c['iteration_records'])==len(ac['comparison_records'])==623
        assert len(c['exit_intervals_packed'])==3 and len(ac['independent_lifts'])==626
        p=parent['cases'][c['parent_case_index']];assert c['parent_seed_case_index']==p['parent_seed_case_index']
        life.update(lifecycle(c,p))
        before=R.Parent.unpack(p['exit_intervals_packed'][-1]);initial=state_bytes(before);q=int(before['boundary']['SP'],16)+0x220
        mt=list(struct.unpack('<624I',bytes(initial[R.G+j] for j in range(2496))));key=bytes(initial[q+j] for j in range(16));payload=bytes(initial[R.Parent.Parent.PAYLOAD+j] for j in range(64))
        assert c['entry_state2496_hex']==struct.pack('<624I',*mt).hex() and c['entry_key16_hex']==key.hex()
        assert bytes(initial[R.GATE_WORD+j] for j in range(4)).hex()==c['entry_gate32_hex']=='965d0000'
        i,remaining=2,623;cc=Counter();cm=Counter();extras=[];truth=0
        for k,(packed,lift) in enumerate(zip(c['intervals_packed']+c['exit_intervals_packed'],ac['independent_lifts'])):
            row=R.Parent.unpack(packed);A.joined(before,row);h.update(hygiene(row))
            assert lift['all_checks_pass'] and not row['native_target_executed']
            assert len(row['source_visits'])==len(row['source_frames']) and len(row['entry_Q_registers32'])==len(row['boundary']['Q_registers32'])==32
            for v,f in zip(row['source_visits'],row['source_frames']):
                assert v['bytes_hex']==IMAGE.read(int(v['pc'],16),4).hex() and v['pc']==f['pc'] and len(f['Q_registers32'])==32
            rc={key:len(row[field]) for key,field in [('source_visits','source_visits'),('reads','source_reads'),('writes','source_writes'),('logical_edges','logical_edges'),('source_calls','source_calls')]}
            assert lift['verified_counts']['source_visits']==rc['source_visits'];cc.update(rc);totals.update(lift['verified_counts'])
            used.update(int(x['address'],16) for x in row['source_reads'] if int(x['address'],16) in FIXUPS)
            actual=state_bytes(row)
            if k<623:
                sp=q-0x220
                for offset,value in [(0x148,0xa73ca7a3),(0x150,0xd831fa4f),(0x1cc,0xb399)]:
                    assert int.from_bytes(bytes(actual[sp+offset+j] for j in range(4)),'little')==value
                assert [int(row['entry_registers31'][r],16) for r in [19,25]]==[i,remaining]
                mt[i]=((mt[i]^((mt[i-1]^(mt[i-1]>>30))*1566083941&0xffffffff))-i)&0xffffffff;i+=1
                if i==624:mt[0]=mt[623];i=1;cm['state_wraps_checked']+=1
                if k<622:remaining-=1
                assert [int(row['boundary']['registers31'][r],16) for r in [19,25]]==[i,remaining]
                assert bytes(actual[R.G+j] for j in range(2496))==struct.pack('<624I',*mt)
                assert bytes(actual[R.GATE_WORD+j] for j in range(4)).hex()=='965d0000'
                record=c['iteration_records'][k];assert record['iteration']==k+1 and [record['exit_i32'],record['exit_remaining32']]==[i,remaining]
                contract=A.comparison(row);assert contract==ac['comparison_records'][k];truth+=contract['predicate']
                assert not any(R.Parent.Parent.PAYLOAD<=int(x['address'],16)<R.Parent.Parent.PAYLOAD+64 for x in row['source_reads']+row['source_writes'])
                cm.update(complete_state_words_checked=624,unchanged_key_words_checked=4,unchanged_payload_bytes_checked=64,exact_iteration_joins_checked=1)
                if k==622:
                    assert c['second_pass_boundary']==row['boundary'] and c['second_pass_NZCV']==row['boundary_NZCV']
                    assert c['second_pass_state2496_hex']==struct.pack('<624I',*mt).hex()
            else:extras.append(row)
            assert bytes(actual[q+j] for j in range(16))==key and bytes(actual[R.Parent.Parent.PAYLOAD+j] for j in range(64))==payload
            before=row
        assert truth==1 and [len(x['source_visits']) for x in extras]==[17,20,10]
        counter,force,gate=extras;assert counter['boundary']['registers31'][25]=='0x0' and counter['boundary']['pc']==hex(R.FORCE)
        assert force['source_writes']==[{'pc':'0x100b2a20c','source_visit_index':3,'address':hex(R.G),'size_bytes':4,'after_hex':'00000080'}]
        assert force['boundary']['registers31'][5]==hex(R.GATE_WORD) and force['boundary']['registers31'][4]=='0x1010b5f20'
        assert gate['source_reads'][0]['pc']=='0x100b3a84c' and gate['source_reads'][0]['address']==hex(R.GATE_WORD) and gate['source_reads'][0]['bytes_hex']=='965d0000'
        assert gate['source_writes']==[{'pc':'0x100b3a84c','source_visit_index':1,'address':hex(R.GATE_WORD),'size_bytes':4,'after_hex':'ef940a00'}]
        mt[0]=0x80000000;raw=struct.pack('<624I',*mt);assert c['final_state2496_hex']==raw.hex() and sha256(raw).hexdigest()==ac['final_state_sha256']
        assert bytes(actual[R.G+j] for j in range(2496))==raw and c['final_key16_hex']==key.hex()
        assert bytes(actual[R.GATE_WORD+j] for j in range(4)).hex()==c['final_gate32_hex']=='ef940a00'
        assert c['final_boundary']==before['boundary'] and c['final_NZCV']==before['boundary_NZCV'] and before['boundary']['pc']==hex(R.NEXT)
        cm.update(final_word_forces_checked=1,same_gate_reacquisitions_checked=1);assert dict(cm)==ac['model_checks'] and dict(cc)==c['counts'];counts.update(cc)
        print(json.dumps({'packed_case_checked':c['parent_case_index'],'source_visits':counts['source_visits']}),flush=True)
    assert dict(counts)=={k:COUNTS[k] for k in counts} and dict(totals)==INDEPENDENT
    assert e['source_fixups']==R.Parent.Parent.Parent.Parent.Parent.Parent.Parent.Parent.Parent.Env.fixups(used)
    check_query_comparison();fresh=A.obligations();assert len(fresh)==len(a['source_proofs'])==a['source_queries_unsat']==8
    for old,new in zip(a['source_proofs'],fresh):
        assert {k:v for k,v in old.items() if k!='query'}=={k:v for k,v in new.items() if k!='query'}
        oa,na=z3.parse_smt2_string(old['query']),z3.parse_smt2_string(new['query'])
        assert len(oa)==len(na)>0 and all(canonical_expression(x)==canonical_expression(y) for x,y in zip(oa,na))
        s=z3.Solver();s.set(timeout=30000);s.from_string(old['query']);assert s.check()==z3.unsat and old['premises_nonvacuous']
    for obj in [e,a]:
        h.update(hygiene(obj));assert all(not obj[k] for k in ['native_API_executed','native_daemon_kext_pairing_established','native_epoch_join_established','full_goal_complete'])
    report=read(BASE/'daemon_second_mix_report.md');assert CHECKS_SHA in report and AUDIT_SHA in report
    assert all(f'| SX{j} |' in report for j in range(1,7)) and all(f'| SX-A{j}:' in report for j in range(1,10)) and all(f'**QG{j}**' in report for j in range(1,8))
    h.update(life);return e,a,h

def main():
    e,a,h=receipts();raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==8760 and len(after)==8766 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
    assert {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256'] and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
    for suffix,value in [('increment_checks',COUNTS),('replay_checks',INDEPENDENT),('model_checks',MODEL),('static_scope',e['scope']),('source_queries_unsat',8)]:
        assert new['validation']['daemon_second_mix_'+suffix]==value
    assert new['validation']['reports']==old['validation']['reports']+1==508 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
    assert delta==OWNED,delta^OWNED
    print(json.dumps({'unchanged_manifest_entries':8751,'owned_physical_files':16,'original_inputs_preserved':3,'reports':508,
        'independent_lifts':1252,'source_visits':181990,'source_queries_unsat':8,**h,
        'native_API_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':main()
