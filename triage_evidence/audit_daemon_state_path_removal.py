#!/usr/bin/env python3
"""Independent SIDB removal, raw status and SIDN handoff replay.

O(receipts+visits*(register state+effects)+owner joins+query DAG) time/storage;
30 s/query. Conditional imported returns, scalar outputs and current SDK
extents remain premises. No native API/IPC/filesystem/PAC or IDB mutation.
"""
import json,struct
from collections import Counter
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_daemon_state_word_routing import Lift
from audit_daemon_network_record import state_bytes
from recover_daemon_return_bank_origins import Algebra
from lskd_values_symbolic import mem,cell
import audit_daemon_state_file_admission as Common
import recover_daemon_state_path_removal as R

AD=['audit_daemon_state_word_routing.py','audit_daemon_readiness_arena.py','audit_daemon_state_file_admission.py',
    'audit_daemon_network_record.py','recover_daemon_return_bank_origins.py','lskd_values_symbolic.py']

def contract(c,parent):
    start=R.unpack(parent['errno_accessor']['interval_packed']);initial=state_bytes(start);model=Counter();terminal={}
    assert c['parent_case_index'] in R.PARENTS and c['prior_ABI_clobber_pattern']==parent['ABI_clobber_pattern']
    assert c['ABI_clobber_pattern']==1-parent['ABI_clobber_pattern'] and c['raw_parent_word32']==parent['raw_big_endian_word32']
    assert start['boundary']['pc']==hex(R.LSTAT) and start['boundary']['registers31'][:2]==[hex(R.B+32),hex(R.STAT)]
    def ret(before,item):
        row=R.unpack(item['interval_packed']);model.update(Common.join(before,row,event=item['API_return_premise']))
        assert item['API_return_premise']['return_NZCV']==hex(0x50000000 if c['ABI_clobber_pattern'] else 0xa0000000)
        return row
    def put(before,item,address,value,width,kind):
        assert item['output_premise']=={'address':hex(address),'bytes_hex':value.to_bytes(width,'little').hex(),'size_bytes':width,'kind':kind}
        row=R.unpack(item['interval_packed']);model.update(Common.join(before,row,effect=item['output_premise']));return row
    def pending(row,pc,symbol,modifier,sp=None,args=None):
        b=row['boundary'];assert b['kind']=='before_unmodeled_import_call' and b['pc']==hex(pc)
        assert b['detail']['symbol']==symbol and b['detail']['modifier']==hex(modifier)
        if sp is not None:assert b['SP']==hex(sp)
        if args is not None:assert b['registers31'][:len(args)]==[hex(x) for x in args]
    def seeds(row,pc,values):
        frames=[f for f in row['source_frames'] if f['pc']==hex(pc)];assert len(frames)==1
        for register,value in values.items():assert int(frames[0]['registers31'][register],16)&0xffffffff==value
        model['proof_phase_seed_registers_checked']+=len(values)
    def handoff(row,status):
        pending(row,R.ERROR,'libSystem/___error',0x6e96,0x680005fef0)
        for pc,address in [(0x1004af644,0x68000600d0),(0x10041ac4c,0x6800070dc8)]:
            ws=Common.select(row,pc);assert len(ws)==1 and (ws[0]['address'],ws[0]['size_bytes'],ws[0]['after_hex'])==(hex(address),4,struct.pack('<I',status).hex())
        ws=Common.select(row,0x100863f38);assert len(ws)==1 and (ws[0]['address'],ws[0]['after_hex'])==('0x6800070db8','96a5818e')
        ws=Common.select(row,0x100863f3c);assert len(ws)==1 and (ws[0]['address'],ws[0]['size_bytes'],ws[0]['after_hex'])==('0x6800070dc0',8,struct.pack('<Q',R.D).hex())
        assert [(x['pc'],x['target'],x['modifier']) for x in row['source_calls']]==[
            ('0x100863fa4','0x10041a980','0xb69a'),('0x10041ac34','0x1004946d8','0xf248'),('0x100494920','0x100493f38','0x4e06')]
        assert row['source_calls'][0]['arguments8'][0]=='0x6800070db8' and row['source_calls'][0]['SP']=='0x6800060100'
        model.update(raw_status_stores_checked=2,SIDN_record_handoffs_checked=1)
    stats=[]
    assert [x['return32'] for x in c['stat_cases']]==R.STATUSES
    for item in c['stat_cases']:
        status=item['return32'];assert int(item['API_return_premise']['return32'],16)==status
        assert item['API_return_premise']['invalidated_spans']==[{'address':hex(R.STAT),'size_bytes':144},{'address':hex(R.E),'size_bytes':4}]
        row=ret(start,item);stats.append(row);s=state_bytes(row)
        seeds(row,R.LSTAT+4,{20:0x5f61,24:0x1d47})
        assert not any(R.STAT+j in s for j in range(144)) and not any(R.E+j in s for j in range(4)) and not row['source_writes']
        if status==0:
            assert row['boundary']['kind']=='before_unknown_private_read' and row['boundary']['pc']==hex(R.MODE)
            assert row['boundary']['detail']['address']==hex(R.STAT+4) and row['boundary']['detail']['snapshot']['known_mask_hex']=='0000'
        else:pending(row,R.ERRNO,'libSystem/___error',0x6e96,0x680005ff10)
        model.update(lstat_return_partitions_checked=1,stat_output_bytes_invalidated_checked=144)
    modes=[];assert [x['mode16'] for x in c['mode_cases']]==R.MODES
    for j,item in enumerate(c['mode_cases']):
        mode=item['mode16'];row=put(stats[0],item,R.STAT+4,mode,2,'mode16');modes.append(row)
        seeds(row,R.MODE,{9:0x3203})
        reads=Common.select(row,R.MODE,'source_reads');assert len(reads)==1 and (reads[0]['address'],reads[0]['size_bytes'],reads[0]['bytes_hex'])==(hex(R.STAT+4),2,struct.pack('<H',mode).hex())
        if mode&0xf000==0xa000:handoff(row,0x74c29dd3);terminal['mode',j]=row
        else:
            pending(row,R.UNLINK,'libSystem/_unlink',0x566a,0x680005ff10,[R.B+32]);assert not row['source_calls'] and not row['source_writes']
        model['mode_word_partitions_checked']+=1
    assert [x['stat_case_index'] for x in c['error_accessors']]==[1,2,3]
    for ai,accessor in enumerate(c['error_accessors']):
        row=ret(stats[accessor['stat_case_index']],accessor)
        assert row['boundary']['pc']==hex(R.ERRNO+4) and row['boundary']['kind']=='before_undefined_foreign_owner_read'
        assert row['boundary']['detail']=={'address':hex(R.E),'size_bytes':4} and not row['source_visits']
        assert [x['errno32'] for x in accessor['word_cases']]==R.ERRNOS
        for wi,item in enumerate(accessor['word_cases']):
            errno=item['errno32'];out=put(row,item,R.E,errno,4,'errno32');handoff(out,0x74c29dd1 if errno==2 else 0x74c29dd3)
            seeds(out,R.ERRNO+4,{20:0xc69c})
            rr=Common.select(out,R.ERRNO+4,'source_reads');assert len(rr)==1 and (rr[0]['address'],rr[0]['size_bytes'],rr[0]['bytes_hex'])==(hex(R.E),4,struct.pack('<I',errno).hex())
            terminal['errno',ai*4+wi]=out;model['errno_word_partitions_checked']+=1
    unlinks=[];assert [x['return32'] for x in c['unlink_cases']]==R.STATUSES
    for j,item in enumerate(c['unlink_cases']):
        status=item['return32'];assert int(item['API_return_premise']['return32'],16)==status
        assert item['API_return_premise']['invalidated_spans']==[{'address':hex(R.E),'size_bytes':4}]
        row=ret(modes[1],item);unlinks.append(row)
        seeds(row,R.UNLINK+4,{25:0xc4b7502a,27:0xc69c,24:0x1d41})
        if status:handoff(row,0x74c29dd3);terminal['unlink',j]=row
        else:
            pending(row,R.ONCE,'libSystem/_pthread_once',0x8489,0x680005fea0,[R.API.ONCE_CELL,R.API.CALLBACK])
            assert [(x['pc'],x['target'],x['modifier'],x['arguments8'][0]) for x in row['source_calls']]==[('0x100628a24','0x10043e280','0x6aa4','0x680005ffd0')]
            assert not any(Common.overlap(w,R.B,74) for w in row['source_writes'])
        model['unlink_return_partitions_checked']+=1
    assert [x['synchronization_return32'] for x in c['synchronization_cases']]==[0,35]
    for si,sync in enumerate(c['synchronization_cases']):
        before=unlinks[0];rows=[];assert len(sync['returns'])==4
        for j,(pc,item) in enumerate(zip([R.ONCE,R.WRLOCK,R.ONCE2,R.UNLOCK],sync['returns'])):
            ev=item['API_return_premise'];assert ev['call_site']==hex(pc) and ev['effect_kind']=='sync'
            assert int(ev['return32'],16)==sync['synchronization_return32']
            assert ev['invalidated_spans']==[{'address':hex(R.API.ONCE_CELL if j%2==0 else R.L),'size_bytes':16 if j%2==0 else 200}]
            assert ev['once_completion_without_additional_callback_effects_premise']==(j%2==0)
            before=ret(before,item);rows.append(before)
        pending(rows[0],R.WRLOCK,'libSystem/_pthread_rwlock_wrlock',0x4c4d,0x680005fea0,[R.L])
        pending(rows[1],R.ONCE2,'libSystem/_pthread_once',0x8489,0x680005fea0,[R.API.ONCE_CELL,R.API.CALLBACK])
        pending(rows[2],R.UNLOCK,'libSystem/_pthread_rwlock_unlock',0x5431,0x680005fea0,[R.L])
        handoff(rows[3],0x8b3dc651);terminal['sync',si]=rows[3]
        writes=[w for row in rows for w in row['source_writes'] if Common.overlap(w,R.B,74)]
        assert [(w['pc'],w['address'],w['size_bytes'],w['after_hex']) for w in writes]==[('0x100628a28',hex(R.B+8),8,'00'*8),('0x100628a28',hex(R.B+16),8,'00'*8)]
        assert [(x['pc'],x['target'],x['modifier'],x['arguments8'][0]) for x in rows[1]['source_calls']]==[('0x100628acc','0x1004423f8','0x6aa4','0x680005ffd0')]
        # The invalidated synchronization objects are opaque, not source data.
        for row in rows:
            assert not any(Common.overlap(x,R.L,200) or Common.overlap(x,R.API.ONCE_CELL,16) for x in row['source_reads']+row['source_writes'])
        model.update(lock_and_unlock_pointer_pairs_checked=1,object_reset_bytes_checked=16)
    assert len(terminal)==len(c['SIDN_queries'])==19
    assert {(x['origin_kind'],x['origin_index']) for x in c['SIDN_queries']}==set(terminal)
    for item in c['SIDN_queries']:
        key=item['origin_kind'],item['origin_index'];before=terminal[key];row=ret(before,item)
        assert item['API_return_premise']['invalidated_spans']==[]
        pending(row,R.LSTAT,'libSystem/_lstat',0xf401,0x680005fef0,[R.D+32,0x680005ff18])
        assert [(w['pc'],w['address'],w['size_bytes'],w['after_hex']) for w in row['source_writes']]==[
            ('0x1004cd120',hex(R.E),4,'00'*4),('0x1004cd124','0x680005ff00',8,struct.pack('<Q',R.D).hex())]
        assert not row['source_calls'];s=state_bytes(row)
        for obj,suffix in [(R.B,b'sidb'),(R.D,b'sidn')]:
            path=b'/var/db/fpsd/SC Info/SC Info.'+suffix+b'\0';assert Common.raw(s,obj+32,len(path))==path
            expected={a:v for a,v in initial.items() if obj<=a<obj+74}
            if obj==R.B and key[0]=='sync':expected.update({R.B+j:0 for j in range(8,24)})
            assert {a:v for a,v in s.items() if obj<=a<obj+74}==expected
        model['SIDN_pending_queries_checked']+=1
    for row in R.context_intervals(c):
        assert row['foreign_owners']==start['foreign_owners'];s=state_bytes(row)
        assert {a:v for a,v in s.items() if R.A<=a<R.A+R.N}=={a:v for a,v in initial.items() if R.A<=a<R.A+R.N}
        assert len([a for a in s if R.A<=a<R.A+R.N])==4
        assert not any(Common.overlap(x,R.A,R.N) for x in row['source_reads']+row['source_writes'])
        assert Common.raw(s,R.J+0x34,32)==Common.raw(initial,R.J+0x34,32)
        model.update(owner_and_payload_preservation_intervals_checked=1,undefined_payload_bytes_preserved_checked=R.N-4)
    for left,right in zip(c['synchronization_cases'][0]['returns'],c['synchronization_cases'][1]['returns']):
        assert R.unpack(left['interval_packed'])['source_visits']==R.unpack(right['interval_packed'])['source_visits']
    model['paired_sync_status_source_sequences_checked']+=4
    return {'model_checks':dict(model),'all_checks_pass':True}

def obligations():
    out=[]
    def prove(label,bad):
        s=z3.Solver();s.set(timeout=30000);assert s.check()==z3.sat;s.add(z3.simplify(bad));assert s.check()==z3.unsat,label
        out.append({'label':label,'query':s.to_smt2(),'premises_nonvacuous':True,'result':'unsat'})
    status=z3.BitVec('removal_return32',32);v=Algebra();v.seed('w0',status);v.seed('w24',0x1d47);v.seed('w20',0x5f61)
    v.run_block(R.LSTAT+4,0x1004cd1b4)
    prove('all_u32_lstat_result_original_dispatch_index',v.read('w8')!=z3.If(status==0,z3.BitVecVal(0x5fdd,32),z3.BitVecVal(0x5f61,32)))
    mode=z3.BitVec('removal_mode16',16);base=0x70000000;v=Algebra();v.seed('sp',base);v.seed('w9',0x3203);mem(v,base+44,2,mode)
    v.run_block(R.MODE,0x1003795fc)
    prove('all_u16_original_link_type_dispatch_index',v.read('w8')!=z3.If(mode&0xf000==0xa000,z3.BitVecVal(0x322c,32),z3.BitVecVal(0x3203,32)))
    errno=z3.BitVec('removal_errno32',32);v=Algebra();v.seed('x0',base);v.seed('w20',0xc69c);mem(v,base,4,errno)
    v.run_block(R.ERRNO+4,0x1005797ec)
    prove('all_u32_original_errno_raw_status',v.read('w8')!=z3.If(errno==2,z3.BitVecVal(0x74c29dd1,32),z3.BitVecVal(0x74c29dd3,32)))
    v=Algebra();v.seed('sp',base);mem(v,base+16,8,R.B);v.seed('w0',status);v.seed('w25',0xc4b7502a);v.seed('w27',0xc69c);v.seed('w24',0x1d41)
    v.run_block(R.UNLINK+4,0x10062817c)
    prove('all_u32_original_unlink_result_dispatch_index',v.read('w8')!=z3.If(status==0,z3.BitVecVal(0x1d41,32),z3.BitVecVal(0x1d47,32)))
    obj,rec,sp=z3.BitVecs('removal_object64 removal_record64 removal_SP64',64)
    v=Algebra();v.seed('x19',obj);v.run_block(0x100628a28,0x100628a2c)
    prove('all_pointer_bits_original_two_u64_reset',z3.Or(cell(v,obj+8,8)!=0,cell(v,obj+16,8)!=0))
    v=Algebra();v.seed('x19',rec);v.seed('w8',status);v.run_block(0x1004af644,0x1004af648)
    prove('all_status_bits_original_adapter_store',cell(v,rec+8,4)!=status)
    v=Algebra();v.seed('sp',base);v.seed('x19',rec);mem(v,base+32,4,status);v.run_block(0x10041ac48,0x10041ac50)
    prove('all_status_bits_original_caller_store',cell(v,rec+16,4)!=status)
    v=Algebra();v.seed('sp',sp);v.seed('w10',status);v.seed('x20',obj);v.run_block(0x100863f34,0x100863f40)
    prove('all_pointer_status_bits_original_next_object_record',z3.Or(cell(v,sp+0x10cb8,4)!=status,cell(v,sp+0x10cc0,8)!=obj))
    v=Algebra();v.seed('sp',base);v.seed('x0',R.E);v.seed('x19',obj);v.run_block(R.ERROR+4,0x1004cd12c)
    prove('all_object_bits_original_next_errno_clear_and_inline_path',z3.Or(cell(v,R.E,4)!=0,cell(v,base+16,8)!=obj,v.read('x19')!=obj+32))
    v.run_block(0x1004cd188,R.LSTAT)
    prove('all_object_bits_original_next_lstat_arguments',z3.Or(v.read('x0')!=obj+32,v.read('x1')!=base+40,v.read('x17')!=0xf401))
    return out

def build():
    e=json.loads(read(ROOT/(R.P+'_checks.json')));p=json.loads(read(ROOT/(R.Parent.P+'_checks.json')))
    assert e['generator_sha256']==sha(R.__file__) and e['dependencies']=={n:sha(ROOT/n) for n in R.DEPS}
    contexts=[];total=Counter();model=Counter()
    for j,c in enumerate(e['contexts']):
        lifts=[]
        for row in R.context_intervals(c):
            lift=Lift(row).run();assert lift['all_checks_pass'];lifts.append(lift);total.update(lift['verified_counts'])
        ct=contract(c,p['cases'][c['parent_case_index']]);model.update(ct['model_checks'])
        contexts.append({'independent_lifts':lifts,'contract':ct,'all_checks_pass':True})
        print(json.dumps({'context':j,'source_visits':total['source_visits']}),flush=True)
    qs=obligations();assert e['SDK_checks']==R.sdk_checks()
    return {'scope':__doc__,'generator_sha256':sha(R.__file__),'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),
            'source_sha256':sha(SOURCE),'dependencies':e['dependencies'],'auditor_dependencies':{n:sha(ROOT/n) for n in AD},
            'verified_counts':e['verified_counts'],'contexts':contexts,'independent_totals':dict(total),'model_checks':dict(model),
            'source_proofs':qs,'source_queries_unsat':len(qs),'all_checks_pass':True,
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'native_epoch_join_established':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps({'independent':e['independent_totals'],'model':e['model_checks'],'queries':e['source_queries_unsat']}),flush=True)
