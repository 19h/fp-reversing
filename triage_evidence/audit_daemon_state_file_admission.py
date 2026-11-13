#!/usr/bin/env python3
"""Independent SIDB metadata/output-mask, synchronization and open audit.

O(receipts+visits*(register state+effects)+query DAG) time/storage;30 s/query.
SDK layout, API effects, callback invocation and native caller epochs remain
separate premises. No native target API/IPC/filesystem/PAC or IDB mutation.
"""
import json,struct
from collections import Counter
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,TABLE,qword
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_daemon_readiness_arena import Lift
from audit_daemon_network_record import state_bytes,fixture_bytes
from recover_daemon_return_bank_origins import Algebra
from lskd_values_symbolic import mem,cell
import recover_daemon_state_file_admission as R
import audit_daemon_state_path_objects as Common
import recover_daemon_network_gate as NG

raw=Common.raw;select=Common.select;overlap=Common.overlap
AD=['audit_daemon_readiness_arena.py','audit_daemon_network_record.py','audit_daemon_state_path_objects.py','recover_daemon_network_gate.py']

def join(before,after,event=None,effect=None,memory=None):
    expected=state_bytes(before) if memory is None else memory.copy();model=Counter()
    assert before['foreign_owners']==after['foreign_owners'] and before['boundary']['SP']==after['caller_SP']
    if event:
        assert event['call_site']==before['boundary']['pc'] and event['symbol']==before['boundary']['detail']['symbol']
        assert after['entry_PC']==event['continuation_PC']==hex(int(event['call_site'],16)+4)
        assert after['entry_registers31']==event['return_registers31'] and after['entry_Q_registers32']==event['return_Q_registers32'] and after['entry_NZCV']==event['return_NZCV']
        assert after['entry_registers31'][18:30]==before['boundary']['registers31'][18:30] and after['entry_registers31'][30]==event['continuation_PC']
        for j in range(8,16):assert int(after['entry_Q_registers32'][j],16)&((1<<64)-1)==int(before['boundary']['Q_registers32'][j],16)&((1<<64)-1)
        assert event['ABI_return_and_output_premise'] and not event['native_API_executed']
        for f in event['invalidated_spans']:
            a=int(f['address'],16);n=f['size_bytes'];expected={k:v for k,v in expected.items() if not a<=k<a+n};model['opaque_output_span_bytes_checked']+=n
        if 'pointer_return64' in event:
            assert event['pointer_return64']==hex(R.E) and event['existing_borrowed_owner_premise']=={'address':hex(R.E),'size_bytes':4}
            assert {'address':hex(R.E),'size_bytes':4} in before['foreign_owners'] and 'return32' not in event
            model['existing_borrowed_errno_pointer_returns_checked']+=1
        model['API_return_joins_checked']+=1
    else:
        assert before['boundary']['pc']==after['entry_PC'] and before['boundary']['registers31']==after['entry_registers31'] and before['boundary']['Q_registers32']==after['entry_Q_registers32'] and before['boundary_NZCV']==after['entry_NZCV']
        assert effect;data=bytes.fromhex(effect['bytes_hex']);a=int(effect['address'],16)
        assert len(data)==effect['size_bytes'] and all(a+j not in expected for j in range(len(data)))
        expected.update({a+j:b for j,b in enumerate(data)});model['supplied_output_word_bytes_checked']+=len(data);model['output_word_state_joins_checked']+=1
    assert expected==fixture_bytes(after,'private')|fixture_bytes(after,'image')
    return model

def callback(before,row,premise):
    assert premise=={'callback':hex(R.CALLBACK),'SP_gap_bytes':256,'return_token':hex(R.TOKEN),'native_pthread_stack_layout_claimed':False}
    assert row['entry_PC']==hex(R.CALLBACK) and row['entry_registers31'][:30]==before['boundary']['registers31'][:30] and row['entry_registers31'][30]==hex(R.TOKEN)
    assert row['entry_Q_registers32']==before['boundary']['Q_registers32'] and row['entry_NZCV']==before['boundary_NZCV']
    assert int(row['caller_SP'],16)==int(before['boundary']['SP'],16)-256 and row['boundary']['SP']==row['caller_SP'] and row['boundary']['pc']==hex(R.TOKEN)
    assert row['boundary']['registers31'][18:30]==before['boundary']['registers31'][18:30] and row['boundary']['Q_registers32']==before['boundary']['Q_registers32']
    assert state_bytes(before)==fixture_bytes(row,'private')|fixture_bytes(row,'image') and row['foreign_owners']==before['foreign_owners']
    ws=[w for w in row['source_writes'] if int(w['address'],16)<0x6000000000]
    assert [(w['pc'],w['address'],w['size_bytes']) for w in ws]==[('0x10040ecfc','0x1010c5088',8),('0x10040ed00','0x1010c4670',8)]
    assert [(c['pc'],c['target']) for c in row['source_calls']]==[('0x10040ee2c','0x10044fc34')] and IMAGE.read(0x10044fc34,4).hex()=='c0035fd6'
    return Counter(original_callback_invocation_joins_checked=1,callback_controller_store_bytes_checked=16)

def contract(c,parent):
    start=R.unpack(parent['intervals_packed'][-1]);model=Counter();stats=[];modes=[];errors=[]
    def returned(before,item):
        row=R.unpack(item['interval_packed']);model.update(join(before,row,item['API_return_premise']));return row
    def supplied(before,item):
        row=R.unpack(item['interval_packed']);model.update(join(before,row,effect=item['output_premise']));return row
    def stat_mask(row,expected):assert {k-R.STAT:v for k,v in state_bytes(row).items() if R.STAT<=k<R.STAT+R.SN}==expected
    assert len(c['stat_cases'])==3 and [x['return32'] for x in c['stat_cases']]==[0,0xffffffff,1]
    for item in c['stat_cases']:
        assert int(item['API_return_premise']['return32'],16)==item['return32']
        assert item['API_return_premise']['invalidated_spans']==[{'address':hex(R.STAT),'size_bytes':144},{'address':hex(R.E),'size_bytes':4}]
        row=returned(start,item);stats.append(row);stat_mask(row,{})
        assert all(R.E+j not in state_bytes(row) for j in range(4)) and not row['source_writes']
        if item['return32']==0:
            assert row['boundary']['pc']==hex(R.MODE) and row['boundary']['kind']=='before_unknown_private_read' and row['boundary']['detail']['snapshot']['known_mask_hex']=='0000'
        else:assert row['boundary']['pc']==hex(R.ERRNO) and row['boundary']['detail']['symbol']=='libSystem/___error'
        model['lstat_return_partitions_checked']+=1;model['stat_output_bytes_invalidated_checked']+=144
    assert [x['mode16'] for x in c['mode_cases']]==R.MODES
    for item in c['mode_cases']:
        mode=item['mode16'];row=supplied(stats[0],item);modes.append(row)
        assert item['output_premise']=={'address':hex(R.STAT+4),'bytes_hex':struct.pack('<H',mode).hex(),'size_bytes':2,'kind':'mode16'}
        stat_mask(row,{4:mode&255,5:mode>>8});r=select(row,R.MODE,'source_reads');assert len(r)==1 and r[0]['address']==hex(R.STAT+4) and r[0]['size_bytes']==2 and r[0]['bytes_hex']==struct.pack('<H',mode).hex()
        link=mode&0xf000==0xa000
        if link:
            assert row['boundary']['pc']==hex(R.MALLOC) and row['boundary']['registers31'][0]=='0x40'
            ws=select(row,0x10042f4d0);assert len(ws)==1 and ws[0]['address']==hex(R.Parent.Parent.R+8) and ws[0]['after_hex']=='d39dc274'
        else:assert row['boundary']['pc']==hex(R.ONCE) and row['boundary']['registers31'][:2]==[hex(R.ONCE_CELL),hex(R.CALLBACK)]
        model['mode_word_partitions_checked']+=1
    assert [a['stat_case_index'] for a in c['error_accessors']]==[1,2]
    for accessor in c['error_accessors']:
        row=returned(stats[accessor['stat_case_index']],accessor);errors.append(row)
        assert row['boundary']['pc']==hex(R.ERR_READ) and row['boundary']['kind']=='before_undefined_foreign_owner_read' and row['boundary']['detail']=={'address':hex(R.E),'size_bytes':4} and not row['source_visits']
        assert [x['errno32'] for x in accessor['word_cases']]==R.ERRNOS
        for item in accessor['word_cases']:
            errno=item['errno32'];out=supplied(row,item);assert out['boundary']['pc']==hex(R.MALLOC) and out['boundary']['registers31'][0]=='0x40'
            assert item['output_premise']=={'address':hex(R.E),'bytes_hex':struct.pack('<I',errno).hex(),'size_bytes':4,'kind':'errno32'}
            rr=select(out,R.ERR_READ,'source_reads');assert len(rr)==1 and rr[0]['address']==hex(R.E) and rr[0]['bytes_hex']==struct.pack('<I',errno).hex()
            ws=select(out,0x10042f4d0);status=0x74c29dd1 if errno==2 else 0x74c29dd3
            assert len(ws)==1 and ws[0]['address']==hex(R.Parent.Parent.R+8) and ws[0]['after_hex']==struct.pack('<I',status).hex();stat_mask(out,{})
            model['errno_word_partitions_checked']+=1;model['raw_caller_status_words_checked']+=1
    assert {(o['invoke_callback'],o['synchronization_return32']) for o in c['open_cases']}=={(i,s) for i in [False,True] for s in [0,35]}
    for op in c['open_cases']:
        before=modes[1];memory=None
        if op['invoke_callback']:
            cb=R.unpack(op['callback_interval_packed']);model.update(callback(before,cb,op['callback_invocation_premise']));memory=state_bytes(cb)
        else:assert op['callback_interval_packed'] is None and op['callback_invocation_premise'] is None
        rows=[R.unpack(p) for p in op['intervals_packed']];assert len(rows)==len(op['API_return_premises'])==5
        for j,(row,ev) in enumerate(zip(rows,op['API_return_premises'])):
            model.update(join(before,row,ev,memory=memory));memory=None
            if j<4:assert int(ev['return32'],16)==op['synchronization_return32']
            before=row
        assert [x['symbol'] for x in op['API_return_premises']]==['libSystem/_pthread_once','libSystem/_pthread_rwlock_rdlock','libSystem/_pthread_once','libSystem/_pthread_rwlock_unlock','libSystem/___error']
        assert [x['invalidated_spans'] for x in op['API_return_premises']]==[[{'address':hex(R.ONCE_CELL),'size_bytes':16}],[{'address':hex(R.L),'size_bytes':200}],[{'address':hex(R.ONCE_CELL),'size_bytes':16}],[{'address':hex(R.L),'size_bytes':200}],[]]
        assert rows[0]['boundary']['pc']==hex(R.RDLOCK) and rows[0]['boundary']['registers31'][0]==hex(R.L) and rows[0]['boundary']['detail']['modifier']=='0x57'
        assert rows[1]['boundary']['pc']==hex(R.ONCE2) and rows[1]['boundary']['registers31'][:2]==[hex(R.ONCE_CELL),hex(R.CALLBACK)]
        assert rows[2]['boundary']['pc']==hex(R.UNLOCK) and rows[2]['boundary']['registers31'][0]==hex(R.L) and rows[2]['boundary']['detail']['modifier']=='0x5431'
        assert rows[3]['boundary']['pc']==hex(R.OPEN_ERRNO)
        field=select(rows[1],0x1004d0098,'source_reads');assert len(field)==1 and field[0]['address']==hex(R.B+8) and field[0]['bytes_hex']=='00'*8
        writes=[w for row in rows for w in row['source_writes'] if overlap(w,R.B,74)]
        assert len(writes)==1 and (writes[0]['pc'],writes[0]['address'],writes[0]['size_bytes'],writes[0]['after_hex'])==('0x100514218',hex(R.B+28),4,'815bffff')
        last=rows[-1];b=last['boundary'];assert b['pc']==hex(R.OPEN) and b['detail']['symbol']=='libSystem/_open' and b['detail']['modifier']=='0x4a94' and b['registers31'][:2]==[hex(R.B+32),'0x110']
        sp=int(b['SP'],16);assert len(last['source_writes'])==2
        assert [(w['pc'],w['address'],w['size_bytes'],w['after_hex']) for w in last['source_writes']]==[('0x100d8ff00',hex(R.E),4,'00'*4),('0x100d8ff68',hex(sp),8,'00'*8)]
        s=state_bytes(last);assert raw(s,R.B+32,34)==Common.PATH and raw(s,sp,8)==bytes(8)
        initial=state_bytes(start);expected={k:v for k,v in initial.items() if R.B<=k<R.B+74};expected.update({R.B+28+j:b for j,b in enumerate(bytes.fromhex('815bffff'))})
        assert {k:v for k,v in s.items() if R.B<=k<R.B+74}==expected
        for o,off,source,_,n,_ in R.Parent.FAMILY[1:]:
            a=R.Parent.address(o);assert {k:v for k,v in s.items() if a<=k<a+62+n}=={k:v for k,v in initial.items() if a<=k<a+62+n}
        assert raw(s,R.J+0x34,32)==raw(initial,R.J+0x34,32)
        model.update(paired_lock_pointer_requests_checked=1,open_requests_checked=1,variadic_stack_zero_bytes_checked=8,preopen_object_field_writes_checked=1,generated_stream_bytes_preserved_checked=32)
    return {'model_checks':dict(model),'all_checks_pass':True}

def obligations():
    out=[]
    def prove(label,bad):
        s=z3.Solver();s.set(timeout=30000);assert s.check()==z3.sat;s.add(z3.simplify(bad));assert s.check()==z3.unsat,label
        out.append({'label':label,'query':s.to_smt2(),'premises_nonvacuous':True,'result':'unsat'})
    status=z3.BitVec('file_lstat_status32',32);v=Algebra();v.seed('w0',status);v.seed('w28',0x28ef);v.seed('w23',0xb2de);v.run_block(R.LSTAT+4,0x10063c384)
    prove('all_u32_lstat_zero_versus_nonzero_original_dispatch',v.read('w8')!=z3.If(status==0,z3.BitVecVal(0xb2de,32),z3.BitVecVal(0xb30c,32)))
    mode=z3.BitVec('file_mode16',16);base=0x70000000;v=Algebra();v.seed('sp',base);v.seed('w26',0xab1b);v.seed('w8',0x80a7);mem(v,base+28,2,mode);v.run_block(R.MODE,0x100617370)
    prove('all_u16_mode_original_symlink_partition',v.read('w8')!=z3.If(mode&0xf000==0xa000,z3.BitVecVal(0x8105,32),z3.BitVecVal(0x80a7,32)))
    errno=z3.BitVec('file_errno32',32);v=Algebra();v.seed('x0',base);v.seed('w23',0x857e);v.seed('w24',0x28f2);v.seed('w26',0x1d);v.seed('w28',0x28ef);mem(v,base,4,errno);v.run_block(R.ERR_READ,0x1006222fc)
    prove('all_u32_errno_original_missing_path_partition',v.read('w8')!=z3.If(errno==2,z3.BitVecVal(0x28ef,32),z3.BitVecVal(0x28f2,32)))
    rec,ptr,sp=z3.BitVecs('file_record64 file_object64 file_SP64',64);v=Algebra();v.seed('sp',base);v.seed('x19',rec);mem(v,base+32,4,status);v.run_block(0x10042f4cc,0x10042f4d4)
    prove('all_u32_caller_status_original_store',cell(v,rec+8,4)!=status)
    v=Algebra();v.seed('sp',base);mem(v,base+80,8,ptr);v.run_block(0x100d8ff50,0x100d8ff58)
    prove('all_pointer_bits_original_open_inline_path',v.read('x0')!=ptr+32)
    v=Algebra();v.seed('sp',sp);v.run_block(0x100d8ff68,R.OPEN)
    prove('all_SP_bits_original_open_stack_argument_and_flags',z3.Or(cell(v,sp,8)!=0,v.read('w1')!=0x110,v.read('x17')!=0x4a94))
    v=Algebra();v.seed('x0',ptr);v.run_block(0x100d8ff00,0x100d8ff04)
    prove('all_pointer_bits_original_preopen_errno_zero',cell(v,ptr,4)!=0)
    old=NG.obligations();callback=[x for x in old if x['label']=='callback_two_controller_updates_exact_u64'];assert len(callback)==1;out.extend(callback)
    assert len(out)==8
    return out

def build():
    e=json.loads(read(ROOT/(R.P+'_checks.json')));parent=json.loads(read(ROOT/(R.Parent.P+'_checks.json')))
    assert e['generator_sha256']==sha(R.__file__) and e['dependencies']=={n:sha(ROOT/n) for n in R.DEPS}
    contexts=[];total=Counter();model=Counter()
    for j,c in enumerate(e['contexts']):
        lifts=[];counts=Counter()
        for row in R.context_intervals(c):
            lift=Lift(row).run();assert lift['all_checks_pass'];lifts.append(lift);counts.update(lift['verified_counts'])
        ct=contract(c,parent['cases'][c['parent_case_index']]);model.update(ct['model_checks']);total.update(counts)
        contexts.append({'parent_case_index':c['parent_case_index'],'ABI_clobber_pattern':c['ABI_clobber_pattern'],'independent_lifts':lifts,'independent_totals':dict(counts),'contract':ct,'all_checks_pass':True})
        print(json.dumps({'context':j,'source_visits':total['source_visits']}),flush=True)
    proofs=obligations();assert e['SDK_checks']==R.sdk_checks()
    return {'scope':__doc__,'generator_sha256':sha(R.__file__),'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),'source_sha256':sha(SOURCE),
            'dependencies':e['dependencies'],'auditor_dependencies':{n:sha(ROOT/n) for n in AD},'verified_counts':e['verified_counts'],'contexts':contexts,
            'independent_totals':dict(total),'model_checks':dict(model),'source_proofs':proofs,'source_queries_unsat':len(proofs),'all_checks_pass':True,
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'native_epoch_join_established':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps({'replay':e['independent_totals'],'model':e['model_checks'],'source_queries_unsat':e['source_queries_unsat']}),flush=True)
