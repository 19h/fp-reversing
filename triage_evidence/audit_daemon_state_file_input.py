#!/usr/bin/env python3
"""Independent SIDB read, lifetime, timestamp and first-word contract audit.

O(receipts+visits*(register state+effects)+owner/state joins+query DAG)
time/storage;30 s/query. ABI returns, bounded owners, opaque outputs and SDK
layouts are premises. No native target API/filesystem/IPC/PAC or IDB mutation.
"""
import json,struct
from collections import Counter
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_daemon_readiness_arena import Lift
from audit_daemon_network_record import fixture_bytes,state_bytes
from recover_daemon_return_bank_origins import Algebra
from lskd_values_symbolic import mem,cell
import recover_daemon_state_file_input as R
import audit_daemon_state_file_admission as Common
import audit_daemon_state_file_metadata as Previous

AD=['audit_daemon_readiness_arena.py','audit_daemon_network_record.py','audit_daemon_state_file_admission.py',
    'audit_daemon_state_path_objects.py','audit_daemon_state_file_metadata.py','recover_daemon_return_bank_origins.py','lskd_values_symbolic.py']
HEADER_SEEDS={1:0x475f,2:0x61c3dc69,3:0xfe53bc46,4:0xfe53bc47,5:0x9e3c2396,
              6:0x29a8f200,7:0x94d479dc,8:0x1ac43bb,10:0,20:0xf3d7f17c,23:0xd2,30:0xfe53bc48}

def joined(before,item):
    after=R.unpack(item['interval_packed']);event=item.get('API_return_premise');effect=item.get('output_premise')
    expected=state_bytes(before);owners=before['foreign_owners'].copy();model=Counter()
    assert before['boundary']['SP']==after['caller_SP']
    if event:
        assert event['call_site']==before['boundary']['pc'] and event['symbol']==before['boundary']['detail']['symbol']
        assert event['continuation_PC']==after['entry_PC']==hex(int(event['call_site'],16)+4)
        assert after['entry_registers31']==event['return_registers31'] and after['entry_Q_registers32']==event['return_Q_registers32'] and after['entry_NZCV']==event['return_NZCV']
        assert after['entry_registers31'][18:30]==before['boundary']['registers31'][18:30] and after['entry_registers31'][30]==event['continuation_PC']
        for j in range(8,16):assert int(after['entry_Q_registers32'][j],16)&((1<<64)-1)==int(before['boundary']['Q_registers32'][j],16)&((1<<64)-1)
        assert event['ABI_return_and_output_premise'] and not event['native_API_executed'];model['API_return_joins_checked']+=1
        allocation=event.get('allocated_owner_premise')
        if allocation:
            a=int(allocation['address'],16);n=allocation['size_bytes'];assert a==R.A and n in [0,1,R.N] and not allocation['initial_bytes_defined']
            assert all(not(int(o['address'],16)<a+n and a<int(o['address'],16)+o['size_bytes']) for o in owners)
            assert all(a+j not in expected for j in range(n));owners.append({'address':hex(a),'size_bytes':n})
            model['initially_undefined_owner_bytes_checked']+=n;model['fresh_owner_records_checked']+=1
        retirement=event.get('retired_owner_premise')
        if retirement:
            assert retirement=={'address':hex(R.A),'size_bytes':R.N} and retirement in owners and event['void_return_premise']
            owners.remove(retirement);assert not any(Common.overlap(x,R.A,R.N) for x in after['source_reads']+after['source_writes'])
            model['declared_owner_retirements_checked']+=1
        for span in event['invalidated_spans']:
            a=int(span['address'],16);n=span['size_bytes'];expected={k:v for k,v in expected.items() if not a<=k<a+n};model['opaque_output_span_bytes_checked']+=n
        if event['effect_kind'] in ['allocation','read','free']:
            assert 'return32' not in event and 'int_return_upper32_unspecified_fixture' not in event
        if event['effect_kind']=='read':assert after['entry_registers31'][0]==event['ssize_return64_bits'];model['full64_read_return_joins_checked']+=1
    else:
        assert effect;model.update(Common.join(before,after,effect=effect));return after,model
    assert expected==fixture_bytes(after,'private')|fixture_bytes(after,'image') and owners==after['foreign_owners']
    return after,model

def contract(c,parent):
    model=Counter();pattern=1-parent['ABI_clobber_pattern'];assert c['ABI_clobber_pattern']==pattern
    status=35 if pattern else 0;assert c['synchronization_return32']==status
    anchor=R.unpack(parent['size_cases'][2]['interval_packed']);initial=state_bytes(anchor)
    def join(before,item,kind=None,invalid=None):
        row,m=joined(before,item);model.update(m)
        if kind:
            event=item['API_return_premise'];assert event['effect_kind']==kind
            assert event['invalidated_spans']==[{'address':hex(a),'size_bytes':n} for a,n in invalid]
        return row
    def boundary(row,pc,symbol,modifier):
        assert row['boundary']['pc']==hex(pc) and row['boundary']['kind']=='before_unmodeled_import_call'
        assert row['boundary']['detail']['symbol']==symbol and row['boundary']['detail']['modifier']==hex(modifier)
    def saved_descriptor(row):assert row['boundary']['registers31'][0]=='0x7'
    def statuses(row,word,outer=True):
        pairs=[(0x100ccedd4,0x68000600d4),(0x10043d33c,0x6800070dc8)]+([(0x100712c9c,0x68000659b4)] if outer else [])
        for pc,a in pairs:
            ws=Common.select(row,pc);assert len(ws)==1 and ws[0]['address']==hex(a) and ws[0]['size_bytes']==4 and ws[0]['after_hex']==struct.pack('<I',word).hex()
        model['raw_status_record_stores_checked']+=len(pairs)
    def wrapper(row,word):
        boundary(row,R.Parent.WRAPPER,'libSystem/_malloc',0x6aa4);assert row['boundary']['registers31'][0]=='0x40';statuses(row,word)
        assert [(v['pc'],v['target'],v['modifier']) for v in row['source_calls']]==[('0x1007106f0','0x100436378','0x58a3')]
        model['common_wrapper_requests_checked']+=1
    assert [q['parent_size_case_index'] for q in c['NULL_allocations']]==list(range(6))
    nulls=[]
    for item in c['NULL_allocations']:
        before=R.unpack(parent['size_cases'][item['parent_size_case_index']]['interval_packed']);row=join(before,item,'allocation',[(R.E,4)]);nulls.append(row)
        assert [int(before['boundary']['registers31'][j],16) for j in [21,26]]==[0xb25cf4d,0x7af0]
        assert item['API_return_premise']['pointer_return64']=='0x0' and item['API_return_premise']['allocated_owner_premise'] is None
        boundary(row,R.CLOSE,'libSystem/_close',0xee56);saved_descriptor(row);assert not row['source_writes'];model['NULL_allocation_partitions_checked']+=1
    assert [q['parent_size_case_index'] for q in c['nonnull_allocations']]==[0,1,2]
    nonnull=[]
    for item in c['nonnull_allocations']:
        j=item['parent_size_case_index'];before=R.unpack(parent['size_cases'][j]['interval_packed']);row=join(before,item,'allocation',[(R.E,4)]);nonnull.append(row)
        size=int(parent['size_cases'][j]['size64'],16);assert item['API_return_premise']['pointer_return64']==hex(R.A) and item['API_return_premise']['allocated_owner_premise']['size_bytes']==size
        boundary(row,R.READ,'libSystem/_read',0xee56);assert row['boundary']['registers31'][:3]==['0x7',hex(R.A),hex(size)] and not row['source_writes']
        assert not any(R.A<=k<R.A+max(size,1) for k in state_bytes(row));model['nonnull_read_requests_checked']+=1
    assert [int(q['return64_bits'],16) for q in c['read_cases']]==R.READ_RETURNS
    reads=[]
    for item in c['read_cases']:
        bits=int(item['return64_bits'],16);row=join(nonnull[2],item,'read',[(R.E,4),(R.A,R.N)]);reads.append(row)
        event=item['API_return_premise'];assert event['ssize_return64_bits']==hex(bits) and event['count_exceeds_request_synthetic_control']==(0<=bits<0x8000000000000000 and bits>R.N)
        assert [int(nonnull[2]['boundary']['registers31'][j],16) for j in [21,25]]==[0x7af0,0x5493]
        assert not any(R.A<=k<R.A+R.N for k in state_bytes(row)) and not any(Common.overlap(x,R.A,R.N) for x in row['source_reads']+row['source_writes'])
        if bits==R.N:
            boundary(row,R.ONCE,'libSystem/_pthread_once',0x8489)
            ws=Common.select(row,0x100be5e10);assert len(ws)==1 and ws[0]['address']=='0x6800062008' and ws[0]['after_hex']==struct.pack('<Q',R.A).hex()
            assert [(v['pc'],v['target'],v['modifier']) for v in row['source_calls']]==[('0x100be5f14','0x10043e280','0x6aa4')]
            model['exact_read_private_pointer_publications_checked']+=1
        else:
            boundary(row,R.FREE,'libSystem/_free',0x46a2);assert row['boundary']['registers31'][0]==hex(R.A)
        model['read_exact_count_partitions_checked']+=1
    assert [q['return32'] for q in c['NULL_close_cases']]==[0,0xffffffff]
    for item in c['NULL_close_cases']:
        row=join(nulls[2],item,'close',[(R.E,4)]);assert int(item['API_return_premise']['return32'],16)==item['return32'];wrapper(row,0x74c29d85)
    freed=join(reads[0],c['mismatch_free'],'free',[(R.E,4),(R.A,R.N)]);boundary(freed,R.CLOSE,'libSystem/_close',0xee56);saved_descriptor(freed)
    assert [q['return32'] for q in c['mismatch_close_cases']]==[0,0xffffffff]
    for item in c['mismatch_close_cases']:
        row=join(freed,item,'close',[(R.E,4)]);assert int(item['API_return_premise']['return32'],16)==item['return32'];wrapper(row,0x74c29dd3)
    def sync(before,item,pc,symbol,nextpc):
        boundary(before,pc,symbol,0x8489 if pc in [R.ONCE,R.ONCE2] else 0x4c4d if pc==R.WRLOCK else 0x5431)
        once=pc in [R.ONCE,R.ONCE2];span=(R.Parent.Parent.ONCE_CELL,16) if once else (R.Parent.Parent.L,200)
        row=join(before,item,'sync',[span]);event=item['API_return_premise']
        assert int(event['return32'],16)==status and event['once_completion_without_additional_callback_effects_premise']==once
        assert before['boundary']['registers31'][0]==hex(span[0])
        if once:assert before['boundary']['registers31'][1]==hex(R.Parent.Parent.CALLBACK)
        assert row['boundary']['pc']==hex(nextpc);model['source_paired_synchronization_requests_checked']+=1;return row
    before=reads[4];assert len(c['success_lock_cases'])==2
    before=sync(before,c['success_lock_cases'][0],R.ONCE,'libSystem/_pthread_once',R.WRLOCK)
    before=sync(before,c['success_lock_cases'][1],R.WRLOCK,'libSystem/_pthread_rwlock_wrlock',R.MTIME)
    assert before['boundary']['kind']=='before_unknown_private_read' and before['boundary']['detail']['address']==hex(R.SEC_ADDRESS) and before['boundary']['detail']['size_bytes']==8
    assert before['boundary']['detail']['snapshot']['known_mask_hex']=='00'*8
    assert [(int(t['seconds64_bits'],16),int(t['nanoseconds64_bits'],16)) for t in c['timestamp_cases']]==R.TIMES
    for t in c['timestamp_cases']:
        sec=int(t['seconds64_bits'],16);ns=int(t['nanoseconds64_bits'],16)
        second=join(before,t['seconds']);assert t['seconds']['output_premise']=={'address':hex(R.SEC_ADDRESS),'bytes_hex':struct.pack('<Q',sec).hex(),'size_bytes':8,'kind':'mtime_seconds64'}
        assert second['boundary']['pc']==hex(R.NSEC) and second['boundary']['kind']=='before_unknown_private_read' and second['boundary']['detail']['snapshot']['known_mask_hex']=='00'*8
        ws=Common.select(second,R.MTIME+4);assert len(ws)==1 and ws[0]['address']==hex(R.B+8) and ws[0]['after_hex']==struct.pack('<Q',sec).hex()
        third=join(second,t['nanoseconds']);assert t['nanoseconds']['output_premise']=={'address':hex(R.NSEC_ADDRESS),'bytes_hex':struct.pack('<Q',ns).hex(),'size_bytes':8,'kind':'mtime_nanoseconds64'}
        ws=Common.select(third,R.NSEC+4);assert len(ws)==1 and ws[0]['address']==hex(R.B+16) and ws[0]['after_hex']==struct.pack('<Q',ns).hex()
        assert [(v['pc'],v['target'],v['modifier']) for v in third['source_calls']]==[('0x100be5fc0','0x1004423f8','0x6aa4')]
        assert len(t['completion'])==3
        row=sync(third,t['completion'][0],R.ONCE2,'libSystem/_pthread_once',R.UNLOCK)
        row=sync(row,t['completion'][1],R.UNLOCK,'libSystem/_pthread_rwlock_unlock',R.CLOSE);saved_descriptor(row)
        row=join(row,t['completion'][2],'close',[(R.E,4)]);assert int(t['completion'][2]['API_return_premise']['return32'],16)==0
        assert row['boundary']['pc']==hex(R.BYTE) and row['boundary']['kind']=='before_undefined_foreign_owner_read' and row['boundary']['detail']=={'address':hex(R.A),'size_bytes':1}
        assert {'address':hex(R.A),'size_bytes':R.N} in row['foreign_owners'] and not any(R.A<=k<R.A+R.N for k in state_bytes(row))
        regs=[int(x,16) for x in row['boundary']['registers31']];assert regs[28]==R.A and all(regs[k]==v for k,v in HEADER_SEEDS.items())
        statuses(row,0x8b3dc651,outer=False)
        expected={k:v for k,v in initial.items() if R.B<=k<R.B+74};expected.update({R.B+8+j:v for j,v in enumerate(struct.pack('<QQ',sec,ns))})
        actual={k:v for k,v in state_bytes(row).items() if R.B<=k<R.B+74};assert actual==expected
        model['timestamp_pair_publications_checked']+=1;model['first_file_byte_demands_checked']+=1;model['unknown_payload_bytes_preserved_checked']+=R.N
    for row in R.context_intervals(c):
        s=state_bytes(row)
        for o in anchor['foreign_owners']:
            a=int(o['address'],16);n=o['size_bytes']
            if a in [R.B,R.E]:continue
            assert {k:v for k,v in s.items() if a<=k<a+n}=={k:v for k,v in initial.items() if a<=k<a+n}
        assert Common.raw(s,R.J+0x34,32)==Common.raw(initial,R.J+0x34,32)
        assert not any(Common.overlap(x,R.Parent.Parent.ONCE_CELL,16) or Common.overlap(x,R.Parent.Parent.L,200) for x in row['source_reads']+row['source_writes'])
        assert not any(Common.overlap(x,R.A,R.N) for x in row['source_reads']+row['source_writes'])
        for w in row['source_writes']:
            if Common.overlap(w,R.B,74):assert (w['pc'],w['address'],w['size_bytes']) in [('0x100be5f1c',hex(R.B+8),8),('0x100be5f24',hex(R.B+16),8)]
        model['owner_and_generated_stream_preservation_intervals_checked']+=1
    return {'model_checks':dict(model),'all_checks_pass':True}

def header_source():
    a=R.BYTE;b=0x1005b9550
    return {'start':hex(a),'end':hex(b),'bytes_hex':IMAGE.read(a,b-a).hex(),
            'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(IMAGE.read(a,b-a),a)]}

def obligations():
    out=[]
    def prove(label,bad):
        s=z3.Solver();s.set(timeout=30000);assert s.check()==z3.sat;s.add(z3.simplify(bad));assert s.check()==z3.unsat,label
        out.append({'label':label,'query':s.to_smt2(),'premises_nonvacuous':True,'result':'unsat'})
    ptr,buf,word,returned=z3.BitVecs('input_pointer64 input_buffer64 input_size64 input_read_return64',64)
    base=0x70000000;fd=z3.BitVec('input_descriptor32',32)
    v=Algebra();v.seed('sp',base);v.seed('x0',ptr);v.seed('x25',buf);v.seed('w21',0xb25cf4d);v.seed('w26',0x7af0);mem(v,base+0x10,8,word);v.run_block(R.ALLOC+4,0x100ce1d6c)
    prove('all_pointer_bits_original_NULL_allocation_partition',v.read('w8')!=z3.If(ptr==0,z3.BitVecVal(0x7af0,32),z3.BitVecVal(0x7b1a,32)))
    v=Algebra();v.seed('sp',base);mem(v,base+0xc8,8,word);v.run_block(0x100d69f9c,0x100d69fa0)
    prove('all_u64_original_read_size_argument',v.read('x2')!=word)
    v=Algebra();v.seed('sp',base);v.seed('x22',buf);v.seed('x11',word);mem(v,base+0x5c,4,fd);v.run_block(0x100d69fb0,R.READ)
    prove('all_descriptor_and_buffer_bits_original_read_arguments',z3.Or(v.read('x0')!=z3.ZeroExt(32,fd),v.read('x1')!=buf,v.read('x17')!=0xee56))
    v=Algebra();v.seed('sp',base);v.seed('x0',returned);v.seed('w21',0x7af0);v.seed('w25',0x5493);mem(v,base+0xc8,8,word);v.run_block(R.READ+4,0x100d69fe0)
    prove('all_u64_read_return_and_size_exact_equality_dispatch',v.read('w8')!=z3.If(returned==word,z3.BitVecVal(0x54ae,32),z3.BitVecVal(0x5493,32)))
    v=Algebra();v.seed('x22',buf);v.run_block(0x100cf92e0,R.FREE)
    prove('all_pointer_bits_original_unequal_read_free_argument',z3.Or(v.read('x0')!=buf,v.read('x17')!=0x46a2))
    v=Algebra();v.seed('sp',base);v.seed('x22',buf);mem(v,base+0x28,8,ptr);v.run_block(0x100be5e0c,0x100be5e14)
    prove('all_pointer_bits_original_exact_read_private_publication',cell(v,ptr,8)!=buf)
    seconds,nanoseconds=z3.BitVecs('input_seconds64 input_nanoseconds64',64)
    v=Algebra();v.seed('sp',base);v.seed('x26',ptr);mem(v,base+0x98,8,seconds);v.run_block(R.MTIME,R.NSEC)
    prove('all_u64_original_timestamp_seconds_publication',cell(v,ptr+8,8)!=seconds)
    v=Algebra();v.seed('sp',base);v.seed('x26',ptr);mem(v,base+0xa0,8,nanoseconds);v.run_block(R.NSEC,0x100be5f28)
    prove('all_u64_original_timestamp_nanoseconds_publication',cell(v,ptr+16,8)!=nanoseconds)
    v=Algebra()
    for k,value in HEADER_SEEDS.items():v.seed('w'+str(k),value)
    v.seed('x28',base);bytes4=z3.BitVecs('input_file_byte0 input_file_byte1 input_file_byte2 input_file_byte3',8)
    for j,value in enumerate(bytes4):mem(v,base+j,1,value)
    v.run_block(R.BYTE,0x1005b9550)
    prove('all_four_byte_values_original_first_word_big_endian_XOR_codec',v.read('w19')!=(z3.Concat(*bytes4)^0x6703cce9))
    labels={'all_u32_adapter_record_status_store','all_u32_caller_record_status_store','all_u32_close_return_independent_first_dispatch'}
    out.extend(p for p in Previous.obligations() if p['label'] in labels);assert len(out)==12
    return out

def build():
    e=json.loads(read(ROOT/(R.P+'_checks.json')));parent=json.loads(read(ROOT/(R.Parent.P+'_checks.json')))
    assert e['generator_sha256']==sha(R.__file__) and e['dependencies']=={n:sha(ROOT/n) for n in R.DEPS}
    contexts=[];total=Counter();model=Counter()
    for j,c in enumerate(e['contexts']):
        lifts=[];counts=Counter()
        for row in R.context_intervals(c):
            lift=Lift(row).run();assert lift['all_checks_pass'];lifts.append(lift);counts.update(lift['verified_counts'])
        ct=contract(c,parent['contexts'][c['parent_context_index']]);model.update(ct['model_checks']);total.update(counts)
        contexts.append({k:c[k] for k in ['parent_context_index','ABI_clobber_pattern']}|
                        {'independent_lifts':lifts,'independent_totals':dict(counts),'contract':ct,'all_checks_pass':True})
        if j%16==0:print(json.dumps({'context':j,'source_visits':total['source_visits']}),flush=True)
    proofs=obligations();assert e['SDK_checks']==R.sdk_checks()
    return {'scope':__doc__,'generator_sha256':sha(R.__file__),'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':sha(SOURCE),
            'dependencies':e['dependencies'],'auditor_dependencies':{n:sha(ROOT/n) for n in AD},'verified_counts':e['verified_counts'],'contexts':contexts,
            'independent_totals':dict(total),'model_checks':dict(model),'source_proofs':proofs,'source_queries_unsat':len(proofs),'symbolic_header_source':header_source(),'all_checks_pass':True,
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'native_epoch_join_established':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps({'independent':e['independent_totals'],'model':e['model_checks'],'source_queries_unsat':e['source_queries_unsat']}),flush=True)
