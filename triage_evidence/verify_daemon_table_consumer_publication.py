#!/usr/bin/env python3
"""Verify complete table-consumer evidence and exact publication preservation.
Pinned full replay; fresh all-parent admissions, byte/block contracts, source
queries, census, metadata, joins and decoded path hygiene. No target native
operation, IDB mutation or history rewrite. O(receipts+visits+parents*demands+
text words+owned bytes+query DAG) time/storage; 30 s/query.
"""
import json,struct,bisect
from collections import Counter
from hashlib import sha256
from compression import zstd
import z3
from daemon_receive_tools import SOURCE,IMAGE,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_daemon_payload_mix_publication import ROOT,BASE,git,hygiene,path_hygiene
from verify_daemon_second_mix_publication import canonical_expression,check_query_comparison
import recover_daemon_table_consumer as R
import replay_daemon_table_consumer as Replay
import audit_daemon_table_consumer as A

PREVIOUS='6fb9fa2bf0f871c22126b3d2e3d565ccbf1cccce'
BASELINE_SHA='d6f4981ef109100bee1866fc5b6958e852d5d71041e36cc0d6eacd7ac1a88f03'
CHECKS_SHA='5137ecaa23c9984c362309dced8482323b1aca63357dcac61d3de3090a695f14'
REPLAY_SHA='6318ee73698283ebfc4cf0534516402c471f75ae07b339feecfacdc4b433dd4c'
AUDIT_SHA='05e23d2ba79cb44cde6226bc8dcf93fc280110810a3fdae1bed49edab9f05f8a'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'mach_ports_report.md','interface_abi_report.md','interface_investigation_status.md',
         'obfuscated_routines_report.md','foundational_triage_report.md','corefp_client_paths_report.md',
         'daemon_state_table_mixing_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'daemon_table_consumer_report.md','triage_evidence/recover_daemon_table_consumer.py',
       'triage_evidence/replay_daemon_table_consumer.py','triage_evidence/audit_daemon_table_consumer.py',
       'triage_evidence/verify_daemon_table_consumer_publication.py',
       'triage_evidence/daemon_table_consumer_checks.json','triage_evidence/daemon_table_consumer_replay.json',
       'triage_evidence/daemon_table_consumer_audit.json'}
ARCHIVES={MANIFEST,*{'triage_evidence/daemon_table_consumer_'+k+'.json' for k in ['checks','replay','audit']}}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'incoming_parents':76,'representative_classes':4,'intervals':8,'source_visits':228728,
        'reads':43892,'writes':5044,'logical_edges':2284,'source_calls':4}

def function_metadata():
    from resolve_kernel_collection_interfaces import commands
    data=SOURCE.read_bytes();assert sha256(data).hexdigest()=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    cmds=list(commands(data,0));o=next(o for o,c,n in cmds if c==0x26);off,n=struct.unpack_from('<II',data,o+8);raw=data[off:off+n]
    assert (off,n,sha256(raw).hexdigest())==(17603576,1864,'ce02892286eaa20b5ad18e05d3a348a5c4b20ab49c668be14fd9e2eb119ccd54')
    starts=[];address=0x100000000;j=0;terminated=False
    while j<len(raw):
        delta=shift=0
        while True:
            assert j<len(raw);b=raw[j];j+=1;delta|=(b&127)<<shift;shift+=7;assert shift<=70
            if not b&128:break
        if not delta:terminated=True;break
        address+=delta;starts.append(address)
    assert terminated and len(starts)==1005 and all(a<b for a,b in zip(starts,starts[1:]))
    sites=[R.ENTRY,R.CALLEE,R.RETURN,R.UNKNOWN,0x100011ffc,0x1000ac768,0x1000591ac,
           0x10005b1c0,0x1000bcd5c,0x1000f7100,0x10002fcbc,0x10002fd1c,0x10057abdc,0x1004c2b98]
    brackets=[]
    for pc in sites:
        k=bisect.bisect_right(starts,pc)-1;assert 0<=k<len(starts)-1
        brackets.append({'site':hex(pc),'preceding_advertised_start':hex(starts[k]),'next_advertised_start':hex(starts[k+1]),'is_advertised_start':pc==starts[k]})
    o=next(o for o,c,n in cmds if c==2);sy,ns,st,sz=struct.unpack_from('<IIII',data,o+8);names=[]
    for j in range(ns):
        ix,ty,se,de,va=struct.unpack_from('<IBBHQ',data,sy+16*j)
        if ix and va in sites:
            assert ix<sz;end=data.index(0,st+ix,st+sz);names.append({'address':hex(va),'name':data[st+ix:end].decode()})
    assert not names
    return {'advertised_starts_checked':1005,'table_file_offset':off,'table_bytes':n,'table_sha256':sha256(raw).hexdigest(),
            'site_brackets':brackets,'exact_site_symbols':names,'scope':'Advertised brackets only; complete noncontiguous chunks, indirect callers and original semantic names remain unknown.'}

def receipts():
    for kind,want in [('checks',CHECKS_SHA),('replay',REPLAY_SHA),('audit',AUDIT_SHA)]:assert sha(ROOT/(R.P+'_'+kind+'.json'))==want
    e=json.loads(read(ROOT/(R.P+'_checks.json')));replay=json.loads(read(ROOT/(R.P+'_replay.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
    assert e['generator_sha256']==replay['generator_sha256']==a['generator_sha256']==sha(R.__file__)
    assert a['auditor_sha256']==sha(A.__file__) and a['replayer_sha256']==replay['replayer_sha256']==sha(Replay.__file__)
    assert a['checks_sha256']==replay['checks_sha256']==CHECKS_SHA and a['replay_sha256']==REPLAY_SHA
    assert e['dependencies']==a['dependencies']==replay['dependencies']=={n:sha(ROOT/n) for n in R.DEPS}
    assert a['auditor_dependencies']=={n:sha(ROOT/n) for n in A.AD} and replay['replayer_dependencies']=={n:sha(ROOT/n) for n in Replay.DEPS}
    assert e['verified_counts']==replay['verified_counts']==a['verified_counts']==COUNTS
    assert e['source_sha256']==replay['source_sha256']==a['source_sha256']==sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    p=json.loads(read(ROOT/(R.Parent.P+'_checks.json')));parents={x['parent_index']:R.unpack(x['derived_terminal_state_packed']) for x in p['coverage']}
    handoffs={x['parent_index']:R.unpack(p['handoff_classes'][x['handoff_class_index']]['interval_packed']) for x in p['coverage']}
    assert A.coverage(e,parents)==a['coverage'] and a['coverage']['all_checks_pass']
    assert A.contracts(e,parents)==a['model'] and a['model']['all_checks_pass']
    assert A.foundation()==a['foundation'] and A.address_controls()==a['address_controls']
    assert len(e['classes'])==len(replay['cases'])==4 and [len(c['member_parent_indices']) for c in e['classes']]==[34,4,34,4]
    rows=[];counts=Counter();total=Counter();h=Counter();used=set()
    for c,rc in zip(e['classes'],replay['cases']):
        rr=A.rows(c);pr=R.registers(rr);assert pr==c['register_projection'] and len(pr['required'])==15 and pr['vector_accesses']==0
        assert rc['all_checks_pass'] and len(rc['lifts'])==len(rr)==2
        assert set(rc['semantic_register_dependencies']['required'])<=set(pr['required']) and rc['semantic_register_dependencies']['written']==pr['written']
        before=parents[c['representative_parent_index']]
        for j,(row,lift) in enumerate(zip(rr,rc['lifts'])):
            A.Prior.Prior.GS.joined(before,row);h.update(hygiene(row));counts.update(R.rc(row));total.update(lift['verified_counts'])
            assert lift['all_checks_pass'] and not lift['native_target_executed'] and not row['native_target_executed']
            assert len(row['source_visits'])==len(row['source_frames'])==lift['verified_counts']['source_visits']
            assert lift['verified_counts']['register_values_checked']==lift['verified_counts']['vector_register_values_checked']==(len(row['source_visits'])+1)*32
            assert row['boundary']['pc']==lift['boundary']
            for v,f in zip(row['source_visits'],row['source_frames']):assert v['pc']==f['pc'] and v['bytes_hex']==IMAGE.read(int(v['pc'],16),4).hex() and len(f['Q_registers32'])==32
            used.update(int(x['address'],16) for x in row['source_reads'] if int(x['address'],16) in FIXUPS)
            if j==0:
                origin=handoffs[c['representative_parent_index']]
                probe=Replay.Lift(row,{'required':set(),'written':set()},origin)
                assert probe.last_authenticated_load==(0x1010a09e0,R.CALLEE) and probe.counts['cross_interval_call_target_origins_checked']==1
                del probe
            before=row;rows.append(row)
    assert e['source_regions']==R.source(rows) and e['source_fixups']==R.Parent.Parent.Parent.API.Parent.fixups(used)
    assert dict(counts)=={k:COUNTS[k] for k in counts} and dict(total)==a['independent_totals']==replay['independent_totals']
    assert total['register_values_checked']==total['vector_register_values_checked']==(228728+8)*32
    assert total['cross_interval_call_target_origins_checked']==4 and total['original_authenticated_edges_checked']==2280
    for x in e['coverage']:h.update(hygiene(R.unpack(x['derived_terminal_state_packed'])))
    check_query_comparison();fresh=A.obligations();assert len(fresh)==len(a['source_proofs'])==a['source_queries_unsat']==9
    for old,new in zip(a['source_proofs'],fresh):
        assert {k:v for k,v in old.items() if k!='query'}=={k:v for k,v in new.items() if k!='query'}
        x,y=z3.parse_smt2_string(old['query']),z3.parse_smt2_string(new['query']);assert len(x)==len(y)>0 and all(canonical_expression(p)==canonical_expression(q) for p,q in zip(x,y))
        solver=z3.Solver();solver.set(timeout=30000);solver.from_string(old['query']);assert solver.check()==z3.unsat and old['premises_nonvacuous']
    for obj in [e,a,replay]:h.update(hygiene(obj));assert not obj['native_API_executed'] and not obj['full_goal_complete']
    assert a['all_checks_pass'] and replay['all_checks_pass'] and not a['native_daemon_kext_pairing_established'] and not a['native_epoch_join_established']
    h.update(hygiene(function_metadata()));report=read(BASE/'daemon_table_consumer_report.md')
    assert all(x in report for x in [CHECKS_SHA,REPLAY_SHA,AUDIT_SHA,a['model']['cases'][0]['final256_sha256']])
    assert all(f'| TC{j} |' in report for j in range(1,7)) and all(f'| TC-A{j}:' in report for j in range(1,10)) and all(f'**QG{j}**' in report for j in range(1,8))
    return e,a,replay,h

def main():
    e,a,replay,h=receipts();raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==8863 and len(after)==8871 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
    assert {p for p in before if before[p]!=after[p]}==CHANGED and new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256'] and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
    for suffix,value in [('increment_checks',COUNTS),('replay_checks',a['independent_totals']),('model_checks',a['model']['verified_counts']),
                         ('coverage_checks',a['coverage']['verified_counts']),('static_scope',e['scope']),('source_queries_unsat',9),('function_metadata',function_metadata())]:
        assert new['validation'][R.P+'_'+suffix]==value
    assert new['validation']['reports']==old['validation']['reports']+1==524 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:path_hygiene((BASE/p).read_bytes());path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,delta^OWNED
    print(json.dumps({'unchanged_manifest_entries':8855,'owned_physical_files':17,'original_inputs_preserved':3,'reports':524,
                      'independent_lifts':8,'source_visits':228728,'admitted_parent_states':76,'source_queries_unsat':9,**h,
                      'native_API_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':main()
