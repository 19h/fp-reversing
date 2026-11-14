#!/usr/bin/env python3
"""Verify complete table mixing, all76 dependency admissions and publication.
Pinned full instruction replay plus fresh coverage, source equations, bytes,
fixups, joins, metadata and exact manifest/blob/path preservation checks.
O(receipts+visits+parents*requirements+owned bytes+query DAG) time/storage;
30 s/query. No native target operation, IDB mutation or history rewrite.
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
import recover_daemon_state_table_mixing as R
import replay_daemon_state_table_mixing as Replay
import audit_daemon_state_table_mixing as A

PREVIOUS='35d3472d5d574720d4e734af3c2b6512447eccaf'
BASELINE_SHA='af77e31bb287ff2e18d44e96482aee72d3789e4861b6f6a29140de2ec17098fe'
CHECKS_SHA='48880e37460e2a7bf8862ebb59b739357791656bcb426a4b2ecc4643a94edbe7'
REPLAY_SHA='db6afc8b68eeead78fcc0f7399ad0d8382b4bf4b964c74d52d686eea278ec0f8'
AUDIT_SHA='15c8b51ba1a781a2ee03efa37e24e14737faed37851c614a037a30aebf0dac91';MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'mach_ports_report.md','interface_abi_report.md','interface_investigation_status.md',
         'obfuscated_routines_report.md','foundational_triage_report.md','corefp_client_paths_report.md',
         'daemon_state_emitter_completion_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'daemon_state_table_mixing_report.md','triage_evidence/recover_daemon_state_table_mixing.py',
       'triage_evidence/replay_daemon_state_table_mixing.py','triage_evidence/audit_daemon_state_table_mixing.py',
       'triage_evidence/verify_daemon_state_table_mixing_publication.py',
       'triage_evidence/daemon_state_table_mixing_checks.json','triage_evidence/daemon_state_table_mixing_replay.json',
       'triage_evidence/daemon_state_table_mixing_audit.json'}
ARCHIVES={MANIFEST,*{'triage_evidence/daemon_state_table_mixing_'+k+'.json' for k in ['checks','replay','audit']}}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'incoming_parents':76,'shared_loop_executions':1,'handoff_executions':4,'intervals':46,'mix_iterations':2569,
        'source_visits':613006,'reads':42212,'writes':5284,'logical_edges':13712,'source_calls':0}

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
    sites=[R.ENTRY,R.HEAD,R.EXIT,R.NEXT_CALL,0x1004172f4,0x10059d4f0,0x10058c3fc,0x1005cffd0,
           0x100866d98,0x100779dac,0x10076276c,0x10047c518,0x10051979c,0x10080c604]
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
            'site_brackets':brackets,'exact_site_symbols':names,'scope':'Advertised brackets only; complete chunks and original semantic names remain unknown.'}

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
    assert A.coverage(e,parents)==a['coverage'] and a['coverage']['all_checks_pass']
    rows=list(R.shared_intervals(e));assert len(rows)==len(replay['shared_lifts'])==42
    assert R.registers(rows)==e['register_projection'] and replay['semantic_register_dependencies']['written']==e['register_projection']['written']
    assert set(replay['semantic_register_dependencies']['required'])<=set(e['register_projection']['required'])
    before=parents[0];counts=Counter();total=Counter();h=Counter();used=set()
    def check(row,lift):
        h.update(hygiene(row));counts.update(R.rc(row));total.update(lift['verified_counts'])
        assert lift['all_checks_pass'] and not lift['native_target_executed'] and not row['native_target_executed']
        assert len(row['source_visits'])==len(row['source_frames'])==lift['verified_counts']['source_visits']
        assert row['boundary']['pc']==lift['boundary']
        for v,f in zip(row['source_visits'],row['source_frames']):assert v['pc']==f['pc'] and v['bytes_hex']==IMAGE.read(int(v['pc'],16),4).hex() and len(f['Q_registers32'])==32
        used.update(int(x['address'],16) for x in row['source_reads'] if int(x['address'],16) in FIXUPS)
    for row,lift in zip(rows,replay['shared_lifts']):A.Prior.GS.joined(before,row);check(row,lift);before=row
    assert before['boundary']['pc']==hex(R.EXIT)
    shared_rows=rows.copy()
    assert len(e['handoff_classes'])==len(replay['handoff_lifts'])==4 and [len(c['member_parent_indices']) for c in e['handoff_classes']]==[34,4,34,4]
    for c,lift in zip(e['handoff_classes'],replay['handoff_lifts']):
        before=R.terminal(parents[c['representative_parent_index']],shared_rows,e['register_projection']);row=R.unpack(c['interval_packed'])
        A.Prior.GS.joined(before,row);check(row,lift)
        assert row['boundary']['pc']==hex(R.NEXT_CALL) and row['boundary']['registers31'][8]=='0x1004172f4'
        rows.append(row)
    # Shared rows are the first42; appended handoffs are independent continuations.
    assert e['source_regions']==R.source(rows) and e['source_fixups']==R.Parent.Parent.API.Parent.fixups(used)
    assert dict(counts)=={k:COUNTS[k] for k in counts} and dict(total)==a['independent_totals']==replay['independent_totals']
    assert total['register_values_checked']==total['vector_register_values_checked']==(613006+46)*32
    assert total['source_visits']==613006 and total['original_authenticated_edges_checked']==13712
    for x in e['coverage']:h.update(hygiene(R.unpack(x['derived_terminal_state_packed'])))
    model=a['model'];assert model['all_checks_pass'] and model['route_counts']=={'0':820,'1':528,'2':609,'3':612}
    assert model['point_programs']=={str(k):[[hex(a),hex(b)] for a,b in spans] for k,spans in A.PROGRAMS.items()}
    assert model['verified_counts']['structured_iterations_checked']==len(model['structured_iteration_records'])==2569
    array=bytes.fromhex(model['final_array256_hex']);assert len(array)==256 and sha256(array).hexdigest()==model['final_array_sha256']
    assert model['constant_table_sha256']==sha256(IMAGE.read(0x100e406a0,256)).hexdigest()
    for row in rows[-4:]:assert A.Prior.GS.raw(A.state_bytes(row),R.FIRST,256)==array
    check_query_comparison();fresh=A.obligations(e);assert len(fresh)==len(a['source_proofs'])==a['source_queries_unsat']==6
    for old,new in zip(a['source_proofs'],fresh):
        assert {k:v for k,v in old.items() if k!='query'}=={k:v for k,v in new.items() if k!='query'}
        x,y=z3.parse_smt2_string(old['query']),z3.parse_smt2_string(new['query']);assert len(x)==len(y)>0 and all(canonical_expression(p)==canonical_expression(q) for p,q in zip(x,y))
        solver=z3.Solver();solver.set(timeout=30000);solver.from_string(old['query']);assert solver.check()==z3.unsat and old['premises_nonvacuous']
    for obj in [e,a,replay]:h.update(hygiene(obj));assert not obj['native_API_executed'] and not obj['full_goal_complete']
    assert a['all_checks_pass'] and replay['all_checks_pass'] and not a['native_daemon_kext_pairing_established'] and not a['native_epoch_join_established']
    h.update(hygiene(function_metadata()));report=read(BASE/'daemon_state_table_mixing_report.md')
    assert all(x in report for x in [CHECKS_SHA,REPLAY_SHA,AUDIT_SHA,model['final_array_sha256']])
    assert all(f'| TM{j} |' in report for j in range(1,7)) and all(f'| TM-A{j}:' in report for j in range(1,10)) and all(f'**QG{j}**' in report for j in range(1,8))
    return e,a,replay,h

def main():
    e,a,replay,h=receipts();raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==8855 and len(after)==8863 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
    assert {p for p in before if before[p]!=after[p]}==CHANGED and new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256'] and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
    for suffix,value in [('increment_checks',COUNTS),('replay_checks',a['independent_totals']),('model_checks',a['model']['verified_counts']),
                         ('coverage_checks',a['coverage']['verified_counts']),('static_scope',e['scope']),('source_queries_unsat',6),('function_metadata',function_metadata())]:
        assert new['validation'][R.P+'_'+suffix]==value
    assert new['validation']['reports']==old['validation']['reports']+1==523 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:path_hygiene((BASE/p).read_bytes());path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,delta^OWNED
    print(json.dumps({'unchanged_manifest_entries':8847,'owned_physical_files':17,'original_inputs_preserved':3,'reports':523,
                      'independent_lifts':46,'source_visits':613006,'admitted_parent_states':76,'source_queries_unsat':6,**h,
                      'native_API_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':main()
