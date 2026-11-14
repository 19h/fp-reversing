#!/usr/bin/env python3
"""Verify four original-source journals, all76 admitted states and publication.

Full instruction replay is pinned in the audit receipt, not repeated here.
Fresh checks cover opcode/fixup bytes, joins, ordered byte dependencies and
effects, every terminal export, source equations and exact publication delta.
O(receipts+visits+parents*requirements+owned bytes+manifest+query DAG) time;
O(receipts+largest state+requirements+query DAG) storage;30 s/query.
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
from audit_daemon_network_record import state_bytes
import recover_daemon_state_emitter_completion as R
import audit_daemon_state_emitter_completion as A

PREVIOUS='1a45f0452b23f3912fb586ee18b1d15b22b89613'
BASELINE_SHA='2d80e50a966fc1372b675f90a9f5d5a219cb0799f32fd9c90ea12e2853979b4c'
CHECKS_SHA='7339ebf095b22c8c390b536023d1639fbd2d36295124208a1784f1737f0bd2f1';AUDIT_SHA='f94527805283b8d0c99a5fd964e914e043ba57869bd551c4864c02ceb03931ba'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'mach_ports_report.md','interface_abi_report.md','interface_investigation_status.md',
         'obfuscated_routines_report.md','foundational_triage_report.md','corefp_client_paths_report.md',
         'daemon_state_allocation_cascade_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'daemon_state_emitter_completion_report.md','triage_evidence/recover_daemon_state_emitter_completion.py',
       'triage_evidence/audit_daemon_state_emitter_completion.py','triage_evidence/verify_daemon_state_emitter_completion_publication.py',
       'triage_evidence/daemon_state_emitter_completion_checks.json','triage_evidence/daemon_state_emitter_completion_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/daemon_state_emitter_completion_checks.json','triage_evidence/daemon_state_emitter_completion_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'incoming_parents':76,'representative_classes':4,'intervals':320,'source_visits':318704,
        'reads':63740,'writes':16080,'logical_edges':15496,'source_calls':48}

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
    sites=[R.ENTRY,R.RETURN,R.COPY,R.AFTER_COPY,R.GS.DONE,R.GS.Parent.TWIST1,R.GS.Parent.TWIST2,
           R.GS.Parent.TWIST_LAST,R.GS.Parent.SELECT,R.GS.Parent.COUNTER,R.GS.BYTE,
           0x100576f28,0x1005068ac,0x1004e020c,0x1006d7ef0,0x10046f89c]
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
    assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
    e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
    assert e['generator_sha256']==a['generator_sha256']==sha(R.__file__) and a['auditor_sha256']==sha(A.__file__) and a['checks_sha256']==CHECKS_SHA
    assert e['dependencies']==a['dependencies']=={n:sha(ROOT/n) for n in R.DEPS} and a['auditor_dependencies']=={n:sha(ROOT/n) for n in A.AD}
    assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert e['verified_counts']==a['verified_counts']==COUNTS and e['source_regions']==R.source()
    parent=json.loads(read(ROOT/(R.Parent.P+'_checks.json')));counts=Counter();total=Counter();model=Counter();used=set();h=Counter();number=0;members=set()
    assert len(e['classes'])==len(a['classes'])==4 and len(e['coverage'])==len(parent['contexts'])==76
    assert [len(c['member_parent_indices']) for c in e['classes']]==[34,4,34,4]
    assert [c['representative_parent_index'] for c in e['classes']]==[0,17,38,55]
    for c,ac in zip(e['classes'],a['classes']):
        ids=set(c['member_parent_indices']);assert not members&ids;members.update(ids)
        p=R.unpack(parent['contexts'][c['representative_parent_index']]['refill_comparison']['interval_packed']);before=p
        assert all(R.key(R.unpack(parent['contexts'][i]['refill_comparison']['interval_packed']))==c['class_key'] for i in ids)
        assert R.key(p)==c['class_key'] and ac['all_checks_pass']
        rows=list(R.context_intervals(c));assert len(rows)==len(ac['independent_lifts'])==80
        ct=Counter()
        for row,lift in zip(rows,ac['independent_lifts']):
            number+=1;h.update(hygiene(row));counts.update(R.rc(row));ct.update(lift['verified_counts']);A.GS.joined(before,row);before=row
            assert not row['native_target_executed'] and not lift['native_target_executed'] and lift['all_checks_pass']
            assert len(row['source_visits'])==len(row['source_frames'])==lift['verified_counts'].get('source_visits',0) and row['boundary']['pc']==lift['boundary']
            for v,f in zip(row['source_visits'],row['source_frames']):
                assert v['pc']==f['pc'] and v['bytes_hex']==IMAGE.read(int(v['pc'],16),4).hex() and len(f['Q_registers32'])==32
            used.update(int(x['address'],16) for x in row['source_reads'] if int(x['address'],16) in FIXUPS)
        assert dict(ct)==ac['independent_totals'];total.update(ct);model.update(ac['model_checks'])
        assert c['generated21_hex']==ac['generated21_hex']=='9ed9bba4d80a2a283821340f11b1d36bcf12dcf509'
        assert ac['heap21_hex']=='0641233c4092b2b0a0b9ac9789294bf3578a446d91'
        s=state_bytes(before);raw=A.GS.raw
        assert raw(s,R.T,21).hex()==ac['heap21_hex'] and len([i for i in range(64) if R.S+i in s])==53
        assert not any(R.U+i in s for i in range(48)) and not any(0x680006c5f0+i in s for i in range(256))
        table=IMAGE.read(0x100e406a0,256);assert raw(s,0x680006c6f0,256)==table and len(set(table))==256
        assert sha256(table).hexdigest()==ac['image_table256_sha256']=='3217b5ed48b0ac4623abdd9e60de4889964d34591f450151fa180e5d7c69b266'
        assert before['boundary']==c['final_boundary'] and before['boundary']['pc']==hex(R.AFTER_COPY)
    assert members==set(range(76)) and number==320 and dict(counts)=={k:COUNTS[k] for k in counts}
    assert dict(total)==a['independent_totals'] and dict(model)==a['model_checks'] and e['source_fixups']==R.Parent.API.Parent.fixups(used)
    assert total['register_values_checked']==total['vector_register_values_checked']==(318704+320)*32
    assert total['cross_interval_copy_target_origins_checked']==4
    assert A.coverage(e,parent)==a['coverage']
    for x in e['coverage']:h.update(hygiene(R.unpack(x['derived_terminal_state_packed'])))
    check_query_comparison();fresh=A.obligations();assert len(fresh)==len(a['source_proofs'])==a['source_queries_unsat']==11
    for old,new in zip(a['source_proofs'],fresh):
        assert {k:v for k,v in old.items() if k!='query'}=={k:v for k,v in new.items() if k!='query'}
        x,y=z3.parse_smt2_string(old['query']),z3.parse_smt2_string(new['query']);assert len(x)==len(y)>0 and all(canonical_expression(p)==canonical_expression(q) for p,q in zip(x,y))
        solver=z3.Solver();solver.set(timeout=30000);solver.from_string(old['query']);assert solver.check()==z3.unsat and old['premises_nonvacuous']
    for obj in [e,a]:
        h.update(hygiene(obj));assert all(not obj[k] for k in ['native_API_executed','native_daemon_kext_pairing_established','native_epoch_join_established','full_goal_complete'])
    assert a['all_checks_pass'];h.update(hygiene(function_metadata()))
    report=read(BASE/'daemon_state_emitter_completion_report.md');assert CHECKS_SHA in report and AUDIT_SHA in report
    assert all(f'| EC{j} |' in report for j in range(1,7)) and all(f'| EC-A{j}:' in report for j in range(1,10)) and all(f'**QG{j}**' in report for j in range(1,8))
    return e,a,h

def main():
    e,a,h=receipts();raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==8849 and len(after)==8855 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
    assert {p for p in before if before[p]!=after[p]}==CHANGED and new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256'] and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
    for suffix,value in [('increment_checks',COUNTS),('replay_checks',a['independent_totals']),('model_checks',a['model_checks']),
                         ('coverage_checks',a['coverage']['verified_counts']),('static_scope',e['scope']),('source_queries_unsat',11),('function_metadata',function_metadata())]:
        assert new['validation'][R.P+'_'+suffix]==value
    assert new['validation']['reports']==old['validation']['reports']+1==522 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:path_hygiene((BASE/p).read_bytes());path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,delta^OWNED
    print(json.dumps({'unchanged_manifest_entries':8841,'owned_physical_files':15,'original_inputs_preserved':3,'reports':522,
                      'independent_lifts':320,'source_visits':318704,'admitted_parent_states':76,'source_queries_unsat':11,**h,
                      'native_API_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':main()
