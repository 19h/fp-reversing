#!/usr/bin/env python3
"""Independent SIDB descriptor, metadata-word and cleanup audit.

O(receipts+visits*(register state+effects)+query DAG) time/storage;30 s/query.
API effects, SDK layout and parent epochs remain explicit premises. No native
target API/filesystem/IPC/PAC executes and no IDB mutation occurs.
"""
import json,struct
from collections import Counter
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_daemon_readiness_arena import Lift
from audit_daemon_network_record import state_bytes
from recover_daemon_return_bank_origins import Algebra
from lskd_values_symbolic import mem,cell
import recover_daemon_state_file_metadata as R
import audit_daemon_state_file_admission as Parent

AD=['audit_daemon_readiness_arena.py','audit_daemon_network_record.py',
    'audit_daemon_state_file_admission.py','recover_daemon_return_bank_origins.py','lskd_values_symbolic.py']

def contract(c,parent):
    start=R.unpack(parent['intervals_packed'][-1]);model=Counter()
    assert [int(start['boundary']['registers31'][j],16) for j in [20,25,26]]==[0x8d4d,0x2625fdcd,0x6883]
    def returned(before,item,invalid,status=None,pointer=False):
        row=R.unpack(item['interval_packed']);event=item['API_return_premise']
        assert event['invalidated_spans']==[{'address':hex(a),'size_bytes':n} for a,n in invalid]
        if status is not None:assert int(event['return32'],16)==status
        assert ('pointer_return64' in event)==pointer
        model.update(Parent.join(before,row,event));return row
    def supplied(before,item,address,raw,kind):
        row=R.unpack(item['interval_packed']);effect=item['output_premise']
        assert effect=={'address':hex(address),'bytes_hex':raw.hex(),'size_bytes':len(raw),'kind':kind}
        model.update(Parent.join(before,row,effect=effect));return row
    def boundary(row,pc,symbol,modifier):
        b=row['boundary'];assert b['pc']==hex(pc) and b['kind']=='before_unmodeled_import_call'
        assert b['detail']['symbol']==symbol and b['detail']['modifier']==hex(modifier)
    def status_store(row,status):
        expected=[('0x100ccedd4','0x68000600d4'),('0x10043d33c','0x6800070dc8'),('0x100712c9c','0x68000659b4')]
        for pc,address in expected:
            ws=Parent.select(row,int(pc,16));assert len(ws)==1 and ws[0]['address']==address and ws[0]['size_bytes']==4 and ws[0]['after_hex']==struct.pack('<I',status).hex()
        model['raw_status_record_stores_checked']+=3
    def wrapper(row):
        boundary(row,R.WRAPPER,'libSystem/_malloc',0x6aa4);assert row['boundary']['registers31'][0]=='0x40'
        assert [(v['pc'],v['target'],v['modifier']) for v in row['source_calls']]==[('0x1007106f0','0x100436378','0x58a3')]
        model['common_wrapper_allocation_requests_checked']+=1
    assert [q['return32'] for q in c['open_cases']]==R.RETURNS
    opens=[]
    for item in c['open_cases']:
        fd=item['return32'];row=returned(start,item,[(R.E,4)],fd);opens.append(row)
        ws=Parent.select(row,R.OPEN+12);assert len(ws)==1 and ws[0]['address']=='0x680005feac' and ws[0]['after_hex']==struct.pack('<I',fd).hex()
        assert not any(R.E+j in state_bytes(row) for j in range(4))
        edge=row['logical_edges'][0];assert (edge['pc'],edge['modifier'])==('0x100d8ffa8','0xcf29')
        if fd&0x80000000:
            boundary(row,R.ERROR,'libSystem/___error',0x6e96);assert edge['target']=='0x100d9e2ec'
        else:
            boundary(row,R.FSTAT,'libSystem/_fstat',0x5e4e);assert edge['target']=='0x100c22c28'
            assert row['boundary']['registers31'][:2]==[hex(fd),hex(R.STAT)];model['descriptor_argument_forwards_checked']+=1
        model['open_signed_return_partitions_checked']+=1
    er=c['error_accessor'];unknown=returned(opens[0],er,[],pointer=True)
    assert unknown['boundary']['pc']==hex(R.ERROR_READ) and unknown['boundary']['kind']=='before_undefined_foreign_owner_read'
    assert unknown['boundary']['detail']=={'address':hex(R.E),'size_bytes':4} and not unknown['source_visits']
    assert [q['errno32'] for q in er['word_cases']]==R.ERRNOS
    for item in er['word_cases']:
        errno=item['errno32'];row=supplied(unknown,item,R.E,struct.pack('<I',errno),'open_errno32')
        rr=Parent.select(row,R.ERROR_READ,'source_reads');assert len(rr)==1 and rr[0]['address']==hex(R.E) and rr[0]['bytes_hex']==struct.pack('<I',errno).hex()
        status_store(row,0x74c29dd1 if errno==2 else 0x74c29dd3);wrapper(row);model['errno_word_partitions_checked']+=1
    assert [q['return32'] for q in c['fstat_cases']]==R.STATUSES
    assert [int(opens[3]['boundary']['registers31'][j],16) for j in [25,26]]==[0x8d4d,0x44d3]
    stats=[]
    for item in c['fstat_cases']:
        status=item['return32'];row=returned(opens[3],item,[(R.STAT,144),(R.E,4)],status);stats.append(row)
        s=state_bytes(row);assert not any(R.STAT+j in s for j in range(144)) and not any(R.E+j in s for j in range(4))
        if status==0:
            assert row['boundary']['pc']==hex(R.SIZE_READ) and row['boundary']['kind']=='before_unknown_private_read'
            assert row['boundary']['detail']['address']==hex(R.SIZE) and row['boundary']['detail']['size_bytes']==8 and row['boundary']['detail']['snapshot']['known_mask_hex']=='00'*8
            target='0x100ce1cc4'
        else:
            boundary(row,R.CLOSE,'libSystem/_close',0xee56);assert row['boundary']['registers31'][0]=='0x7';target='0x100ac8ae8'
            rr=Parent.select(row,0x100ac8b24,'source_reads');assert len(rr)==1 and rr[0]['address']=='0x680005feac' and rr[0]['bytes_hex']=='07000000'
            model['failure_close_descriptor_requests_checked']+=1
        assert row['logical_edges'][0]['target']==target;model['fstat_return_partitions_checked']+=1;model['stat_output_bytes_invalidated_checked']+=144
    assert [int(q['size64'],16) for q in c['size_cases']]==R.SIZES
    for item in c['size_cases']:
        size=int(item['size64'],16);row=supplied(stats[0],item,R.SIZE,struct.pack('<Q',size),'stat_size64')
        boundary(row,R.MALLOC,'libSystem/_malloc',0x6aa4);assert row['boundary']['registers31'][0]==hex(size) and not row['source_writes']
        rr=Parent.select(row,R.SIZE_READ,'source_reads');assert len(rr)==1 and rr[0]['address']==hex(R.SIZE) and rr[0]['size_bytes']==8 and rr[0]['bytes_hex']==struct.pack('<Q',size).hex()
        assert {k:v for k,v in state_bytes(row).items() if R.STAT<=k<R.STAT+144}=={R.SIZE+j:v for j,v in enumerate(struct.pack('<Q',size))}
        assert len(row['source_visits'])==7;model['size_word_to_allocation_requests_checked']+=1;model['supplied_size_bytes_checked']+=8
    assert [q['fstat_case_index'] for q in c['close_cases']]==[1,2]
    for group in c['close_cases']:
        assert [q['return32'] for q in group['return_cases']]==R.STATUSES
        signatures=[]
        for item in group['return_cases']:
            row=returned(stats[group['fstat_case_index']],item,[(R.E,4)],item['return32']);wrapper(row);status_store(row,0x74c29dd3)
            assert not any(Parent.overlap(r,R.E,4) for r in row['source_reads'])
            signatures.append([(r['pc'],r['address'],r['size_bytes'],r['after_hex']) for r in row['source_writes']])
            model['close_return_continuations_checked']+=1
        assert signatures[0]==signatures[1]==signatures[2]
    initial=state_bytes(start)
    for row in R.context_intervals(c):
        state=state_bytes(row)
        for owner in start['foreign_owners']:
            a=int(owner['address'],16);n=owner['size_bytes']
            if a==R.E:continue
            assert {k:v for k,v in state.items() if a<=k<a+n}=={k:v for k,v in initial.items() if a<=k<a+n}
        assert Parent.raw(state,R.J+0x34,32)==Parent.raw(initial,R.J+0x34,32)
        assert not any(Parent.overlap(r,R.Parent.ONCE_CELL,16) or Parent.overlap(r,R.Parent.L,200) for r in row['source_reads']+row['source_writes'])
        model['foreign_owner_and_generated_stream_preservation_intervals_checked']+=1
    return {'model_checks':dict(model),'all_checks_pass':True}

def obligations():
    out=[]
    def prove(label,bad):
        s=z3.Solver();s.set(timeout=30000);assert s.check()==z3.sat;s.add(z3.simplify(bad));assert s.check()==z3.unsat,label
        out.append({'label':label,'query':s.to_smt2(),'premises_nonvacuous':True,'result':'unsat'})
    status=z3.BitVec('metadata_return32',32);base=0x70000000
    v=Algebra();v.seed('sp',base);v.seed('w0',status);v.seed('w20',0x8d4d);v.seed('w25',0x2625fdcd);v.seed('w26',0x6883)
    v.run_block(R.OPEN+4,0x100d8ffa0)
    expected=z3.If(status<0,z3.BitVecVal(0x6883,32),z3.BitVecVal(0x68c1,32))
    prove('all_u32_open_signed_partition_and_saved_word',z3.Or(v.read('w8')!=expected,cell(v,base+0x5c,4)!=status))
    v=Algebra();v.seed('sp',base);v.seed('w0',status);v.seed('w25',0x8d4d);v.seed('w26',0x44d3);v.run_block(R.FSTAT+4,0x100c22ccc)
    prove('all_u32_fstat_zero_partition',z3.Or(v.read('w8')!=z3.If(status==0,z3.BitVecVal(0x44e5,32),z3.BitVecVal(0x44d3,32)),cell(v,base+0x3c,4)!=0x8d4d))
    v=Algebra();v.seed('sp',base);mem(v,base+0x5c,4,status);v.run_block(0x100c22c9c,R.FSTAT)
    prove('all_u32_fstat_descriptor_and_output_arguments',z3.Or(v.read('x0')!=z3.ZeroExt(32,status),v.read('x1')!=base+0x68,v.read('x17')!=0x5e4e))
    v=Algebra();v.seed('sp',base);mem(v,base+0x5c,4,status);v.run_block(0x100ac8b24,R.CLOSE)
    prove('all_u32_cleanup_descriptor_argument',z3.Or(v.read('x0')!=z3.ZeroExt(32,status),v.read('x17')!=0xee56))
    size=z3.BitVec('metadata_size64',64);v=Algebra();v.seed('sp',base);mem(v,base+0xc8,8,size);v.run_block(R.SIZE_READ,R.SIZE_READ+4)
    prove('all_u64_metadata_size_original_load',v.read('x0')!=size)
    v=Algebra();v.seed('x0',base);mem(v,base,4,status);v.run_block(R.ERROR_READ,0x100d9e384)
    prove('all_u32_open_errno_status_mapping',v.read('w25')!=z3.If(status==2,z3.BitVecVal(0x74c29dd1,32),z3.BitVecVal(0x74c29dd3,32)))
    pointer=z3.BitVec('metadata_record64',64);v=Algebra();v.seed('x19',pointer);v.seed('w25',status);v.run_block(0x100ccedd4,0x100ccedd8)
    prove('all_u32_adapter_record_status_store',cell(v,pointer+28,4)!=status)
    v=Algebra();v.seed('sp',base);v.seed('x19',pointer);mem(v,base+0x34,4,status);v.run_block(0x10043d338,0x10043d340)
    prove('all_u32_caller_record_status_store',cell(v,pointer+16,4)!=status)
    target=z3.BitVec('metadata_cleanup_target64',64);v=Algebra();v.seed('sp',base);v.seed('w0',status);v.seed('x24',0x71000000)
    mem(v,base+0x3c,4,0x8d4d);mem(v,0x71000000+0x8d4d*8,8,target);v.run_block(R.CLOSE+4,0x100ac8b3c)
    prove('all_u32_close_return_independent_first_dispatch',z3.Or(v.read('x8')!=target,v.read('x17')!=0xa8e0,v.read('w0')!=status))
    return out

def build():
    e=json.loads(read(ROOT/(R.P+'_checks.json')));parent=json.loads(read(ROOT/(R.Parent.P+'_checks.json')))
    assert e['generator_sha256']==sha(R.__file__) and e['dependencies']=={n:sha(ROOT/n) for n in R.DEPS}
    contexts=[];total=Counter();model=Counter()
    for j,c in enumerate(e['contexts']):
        lifts=[];counts=Counter()
        for row in R.context_intervals(c):
            lift=Lift(row).run();assert lift['all_checks_pass'];lifts.append(lift);counts.update(lift['verified_counts'])
        p=parent['contexts'][c['parent_context_index']]['open_cases'][c['parent_open_case_index']]
        ct=contract(c,p);model.update(ct['model_checks']);total.update(counts)
        contexts.append({k:c[k] for k in ['parent_context_index','parent_open_case_index','ABI_clobber_pattern']}|
                        {'independent_lifts':lifts,'independent_totals':dict(counts),'contract':ct,'all_checks_pass':True})
        if j%16==0:print(json.dumps({'context':j,'source_visits':total['source_visits']}),flush=True)
    proofs=obligations();assert e['SDK_checks']==R.sdk_checks()
    return {'scope':__doc__,'generator_sha256':sha(R.__file__),'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':sha(SOURCE),
            'dependencies':e['dependencies'],'auditor_dependencies':{n:sha(ROOT/n) for n in AD},'verified_counts':e['verified_counts'],'contexts':contexts,
            'independent_totals':dict(total),'model_checks':dict(model),'source_proofs':proofs,'source_queries_unsat':len(proofs),'all_checks_pass':True,
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'native_epoch_join_established':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps({'independent':e['independent_totals'],'model':e['model_checks'],'source_queries_unsat':e['source_queries_unsat']}),flush=True)
