#!/usr/bin/env python3
"""Independent SIDB object/lock/cleanup replay and source-local equations.

O(receipts+visits*(state+effects)+query DAG) time/storage;30 s/query.
Native APIs/IPC/PAC and IDB mutation never execute. Allocation, opacity,
retirement and separate producer/caller epochs remain explicit premises.
"""
import json,struct
from collections import Counter
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_daemon_readiness_arena import Lift
from audit_daemon_environment_outputs import DEC
from audit_daemon_network_record import fixture_bytes,state_bytes,join
from recover_daemon_return_bank_origins import Algebra
from lskd_values_symbolic import mem,cell
import daemon_rwlock_lifecycle_symbolic as RW
import recover_daemon_state_path_objects as R

PATH=b'/var/db/fpsd/SC Info/SC Info.sidb\0'
AD=['daemon_rwlock_lifecycle_contracts.json','daemon_rwlock_lifecycle_symbolic.py']
def raw(s,a,n):return bytes(s[a+j] for j in range(n))
def select(row,pc,kind='source_writes'):return [x for x in row[kind] if x['pc']==hex(pc)]
def overlap(x,a,n):return int(x['address'],16)<a+n and a<int(x['address'],16)+x['size_bytes']

def joined(before,event,after):
    expected=state_bytes(before);owners=before['foreign_owners'].copy();model=Counter()
    assert before['boundary']['SP']==after['caller_SP']
    if event:
        assert event['call_site']==before['boundary']['pc'] and event['symbol']==before['boundary']['detail']['symbol']
        assert event['continuation_PC']==after['entry_PC']==hex(int(event['call_site'],16)+4)
        assert after['entry_registers31']==event['return_registers31'] and after['entry_Q_registers32']==event['return_Q_registers32'] and after['entry_NZCV']==event['return_NZCV']
        assert after['entry_registers31'][18:30]==before['boundary']['registers31'][18:30] and int(after['entry_registers31'][30],16)==int(event['call_site'],16)+4
        for j in range(8,16):assert int(after['entry_Q_registers32'][j],16)&((1<<64)-1)==int(before['boundary']['Q_registers32'][j],16)&((1<<64)-1)
        assert event['ABI_return_and_output_premise'] and not event['native_API_executed'];model['API_return_joins_checked']+=1
        alloc=event.get('allocated_owner_premise')
        if alloc:
            a=int(alloc['address'],16);n=alloc['size_bytes'];assert not alloc['initial_bytes_defined'] and all(a+j not in expected for j in range(n))
            assert all(not(int(o['address'],16)<a+n and a<int(o['address'],16)+o['size_bytes']) for o in owners)
            owners.append({'address':hex(a),'size_bytes':n});model['initially_undefined_owner_bytes_checked']+=n
        for key in ['opaque_owner_premise','retired_owner_premise']:
            effect=event.get(key)
            if not effect:continue
            a=int(effect['address'],16);n=effect['size_bytes'];assert {'address':hex(a),'size_bytes':n} in owners
            expected={k:v for k,v in expected.items() if not a<=k<a+n}
            if key=='opaque_owner_premise':assert (a,n)==(R.L,200);model['opaque_lock_bytes_checked']+=n
            else:
                assert (a,n)==(R.B,74) and event['void_return_premise'] and 'return32' not in event
                owners.remove({'address':hex(a),'size_bytes':n});assert not any(overlap(x,a,n) for x in after['source_reads']+after['source_writes']);model['declared_owner_retirements_checked']+=1
    else:
        assert before['boundary']['pc']==after['entry_PC'] and before['boundary']['registers31']==after['entry_registers31'] and before['boundary']['Q_registers32']==after['entry_Q_registers32'] and before['boundary_NZCV']==after['entry_NZCV'];model['ordinary_state_joins_checked']+=1
    assert expected==fixture_bytes(after,'private')|fixture_bytes(after,'image') and owners==after['foreign_owners']
    return model

def contract(c,parent):
    before=R.unpack(parent['intervals'][-1]['packed']);initial=state_bytes(before);rows=[R.unpack(p) for p in c['intervals_packed']]
    assert len(rows)==len(c['API_return_premises']);model=Counter();scenario=c['scenario'];success=scenario=='init_0'
    for row,event in zip(rows,c['API_return_premises']):model.update(joined(before,event,row));assert not row['native_target_executed'];before=row
    result=rows[-2];s=state_bytes(result);status={'object_NULL':0x74c29d85,'lock_NULL':0x74c29d85,'init_0':0x8b3dc651,'init_12':0x74c29d85,'init_16':0x74c29d82,'init_22':0x74c29d83}[scenario]
    assert result['boundary']==c['constructor_return'] and result['boundary_NZCV']==c['constructor_return_NZCV'] and result['boundary']['pc']==hex(R.RETURN)
    stores=[x for r in rows[:-1] for x in select(r,0x1000354d4)];assert len(stores)==1 and stores[0]['address']==hex(R.R+8) and stores[0]['after_hex']==struct.pack('<I',status).hex()
    model['constructor_status_words_checked']+=1
    events=[e for e in c['API_return_premises'] if e];assert events[0]['pointer_return64']==('0x0' if scenario=='object_NULL' else hex(R.B))
    calls=[x for r in rows for x in r['source_calls']]
    if scenario!='object_NULL':
        creator=[x for x in calls if x['target']=='0x10043a240'];assert len(creator)==1 and creator[0]['pc']=='0x10006ec54' and creator[0]['modifier']=='0x8c6d'
        record=int(creator[0]['arguments8'][0],16);sp=int(creator[0]['SP'],16);assert record==sp+0x40
        writes=rows[0]['source_writes'];ctl=next(w for w in writes if w['pc']=='0x10006ebd0');ptr=next(w for w in writes if w['pc']=='0x10006ebd8')
        k=((record&0xffffffff)^0xdc40790b)*0x5973a279&0xffffffff
        assert ctl['address']==hex(record) and (int.from_bytes(bytes.fromhex(ctl['after_hex']),'little')+k)&0xffffffff==0xaed7
        assert ptr['address']==hex(record+8) and ptr['after_hex']==struct.pack('<Q',sp+0x30).hex();model['creator_record_views_checked']+=1
        if scenario!='lock_NULL':
            zero=rows[1];ws=[w for w in zero['source_writes'] if overlap(w,R.L,200)]
            assert len(ws)==4 and [(w['address'],w['size_bytes'],w['after_hex']) for w in ws]==[(hex(R.L+2*j),2,'0000') for j in range(4)]
            assert zero['boundary']['pc']==hex(R.INIT) and zero['boundary']['registers31'][:2]==[hex(R.L),'0x0'];model['preinit_lock_header_bytes_checked']+=8
            assert all(R.L+j not in fixture_bytes(rows[2],'image') for j in range(200))
            assert not any(overlap(x,R.L,200) for r in rows[2:] for x in r['source_reads']+r['source_writes'])
    heap_writes=[w for r in rows[:-1] for w in r['source_writes'] if overlap(w,R.B,74)]
    if success:
        expected={j:b for j,b in enumerate(struct.pack('<Q',R.L)+bytes(16))};expected[24]=1;expected.update({j:0 for j in range(28,32)});expected.update({32+j:b for j,b in enumerate(PATH)})
        actual={int(w['address'],16)-R.B+j:b for w in heap_writes for j,b in enumerate(bytes.fromhex(w['after_hex']))}
        assert len(expected)==63 and actual==expected and all(s[R.B+j]==b for j,b in expected.items())
        gaps=list(range(25,28))+list(range(66,74));assert all(R.B+j not in s for j in gaps)
        assert raw(s,R.J+0x118,8)==struct.pack('<Q',R.B)
        body=rows[2];directory=select(body,0x1000879cc,'source_reads');dw=select(body,0x1000879d8)
        assert len(directory)==len(dw)==20 and [x['address'] for x in directory]==[hex(0x6600003000+j) for j in range(19,-1,-1)]
        assert [x['address'] for x in dw]==[hex(R.B+32+j) for j in range(19,-1,-1)]
        assert all(bytes.fromhex(w['after_hex'])[0]==bytes.fromhex(x['bytes_hex'])[0]^0x98 for x,w in zip(directory,dw))
        assert raw(initial,0x6600003000,21)==bytes(b^0x98 for b in b'/var/db/fpsd/SC Info\0')
        encoded=IMAGE.read(0x10102fa20,12);name=b''.join(bytes([encoded[j+2]^0x52,encoded[j]^0x3e,encoded[j+3]^0x99,encoded[j+1]^0x22]) for j in range(0,12,4));assert name==b'SC Info.sidb'
        model.update(path_bytes_checked=34,directory_byte_defuses_checked=20,basename_source_bytes_checked=12,object_defined_bytes_checked=63,object_undefined_gap_bytes_checked=11,pointer_publications_checked=1)
    else:
        assert not heap_writes and raw(s,R.J+0x118,8)==raw(initial,R.J+0x118,8);model['failure_preserves_destination_checked']+=1
    assert not any(overlap(x,R.B,74) for row in rows for x in row['source_reads'])
    last=rows[-1];assert not any(overlap(x,R.R+8,4) for x in last['source_reads'])
    assert last['boundary']==c['final_boundary'] and last['boundary']['pc']==hex(R.MALLOC) and last['boundary']['registers31'][:3]==['0x4a',hex(R.J+0x120),'0x14']
    assert len([x for x in calls if x['target']=='0x100410c4c'])==1
    end=state_bytes(last);assert raw(end,R.J+0x34,32)==raw(initial,R.J+0x34,32)
    assert not any(overlap(x,R.J+0x34,32) for row in rows for x in row['source_reads']+row['source_writes'])
    model.update(next_path_requests_checked=1,generated_stream_bytes_preserved_checked=32)
    return {'scenario':scenario,'status32':hex(status),'success':success,'path_ascii':PATH[:-1].decode() if success else None,'model_checks':dict(model),'all_checks_pass':True}

def obligations():
    qs=[]
    def prove(label,bad,premise=z3.BoolVal(True)):
        s=z3.Solver();s.set(timeout=30000);s.add(premise);assert s.check()==z3.sat;s.add(z3.simplify(bad));assert s.check()==z3.unsat,label
        qs.append({'label':label,'query':s.to_smt2(),'premises_nonvacuous':True,'result':'unsat'})
    ptr,lock,rec=z3.BitVecs('path_object64 path_lock64 path_record64',64);v=Algebra();v.seed('x0',ptr);v.seed('w22',0x9168);v.seed('w20',0x9c0d);v.run_block(R.ENTRY,0x10018ed50)
    prove('all_pointer_bits_original_allocation_partition',v.read('w8')!=z3.If(ptr==0,z3.BitVecVal(0x9c48,32),z3.BitVecVal(0x9c0d,32)))
    v=Algebra();v.seed('sp',rec-0x40);v.seed('w22',0x9168);v.run_block(0x10006eb8c,0x10006ebdc)
    k=(z3.Extract(31,0,rec)^0xdc40790b)*0x5973a279
    prove('all_aligned_records_original_creator_pack',z3.Or(cell(v,rec,4)!=0xaed7-k,cell(v,rec+8,8)!=rec-16),rec&7==0)
    base=0x70000000;v=Algebra();v.seed('sp',base);v.seed('w9',0x3fc2f8c0);mem(v,base,8,ptr);mem(v,base+0x30,8,lock);v.run_block(0x1000fc56c,0x1000fc588)
    prove('all_object_lock_pointers_original_header',z3.Or(cell(v,ptr,8)!=lock,cell(v,ptr+8,8)!=0,cell(v,ptr+16,8)!=0,cell(v,ptr+24,1)!=1))
    b=z3.BitVec('path_directory_byte8',8);v=Algebra();v.seed('x24',base);v.seed('x10',1);v.seed('x12',base+0x100);v.seed('w11',0xb0cfbf69);v.seed('w13',0x4f306bf6);mem(v,base,1,b);v.run_block(0x1000879c4,0x1000879dc)
    prove('all_directory_byte_bits_original_XOR98',z3.Or(cell(v,base+0x100,1)!=b^0x98,v.read('x10')!=0))
    data=z3.BitVec('path_basename_quad32',32)
    for j in [0,4,8]:
        v=Algebra();v.seed('x23',base);v.seed('x9',base+0x100);v.seed('x10',j);v.seed('w11',j);v.seed('w8',0x2b60);v.seed('x13',0x33eb9b6)
        for k in range(4):mem(v,base+j+k,1,z3.Extract(8*k+7,8*k,data))
        v.run_block(0x1000915ec,0x10009165c)
        encoded=[z3.Extract(8*i+7,8*i,data) for i in range(4)];expected=z3.Concat(encoded[1]^0x22,encoded[3]^0x99,encoded[0]^0x3e,encoded[2]^0x52)
        actual=z3.Concat(*[cell(v,base+0x100+k,1) for k in range(3,-1,-1)])
        prove('all_basename_data_bits_original_quad_'+str(j),actual!=expected)
    v=Algebra();v.seed('x9',base+0x200);v.seed('x1',ptr);v.seed('x0',base);v.run_block(0x10003a3d8,0x10003a3e4)
    prove('all_pointer_bits_original_object_publication',cell(v,base,8)!=ptr)
    status=z3.BitVec('path_status32',32);v=Algebra();v.seed('x19',rec);v.seed('w28',status);v.run_block(0x1000354d4,0x1000354d8)
    prove('all_record_status_bits_original_status_store',cell(v,rec+8,4)!=status)
    old=json.loads(read(ROOT/'daemon_rwlock_lifecycle_contracts.json'));assert old['source_sha256']==sha(SOURCE)
    for span in old['spans']:assert IMAGE.read(int(span['start'],16),len(bytes.fromhex(span['bytes_hex']))).hex()==span['bytes_hex']
    prior,_=RW.queries(old)
    for label,bad in prior:
        if label in ['all_u32_initializer_status','initializer_publication_predicate']:prove('reused_source_'+label,bad)
    assert len(qs)==11
    return qs

def build():
    e=json.loads(read(ROOT/(R.P+'_checks.json')));p=json.loads(read(ROOT/(R.Parent.P+'_checks.json')))
    assert e['generator_sha256']==sha(R.__file__) and e['dependencies']=={n:sha(ROOT/n) for n in R.DEPS}
    cases=[];total=Counter();model=Counter()
    for j,c in enumerate(e['cases']):
        lifts=[];counts=Counter()
        for packed in c['intervals_packed']:
            a=Lift(R.unpack(packed)).run();assert a['all_checks_pass'];lifts.append(a);counts.update(a['verified_counts'])
        ct=contract(c,p['cases'][c['parent_case_index']]);model.update(ct['model_checks']);total.update(counts)
        cases.append({'parent_case_index':c['parent_case_index'],'ABI_clobber_pattern':c['ABI_clobber_pattern'],'scenario':c['scenario'],'independent_lifts':lifts,'independent_totals':dict(counts),'contract':ct,'all_checks_pass':True})
        print(json.dumps({'case':j,'source_visits':total['source_visits']}),flush=True)
    proofs=obligations()
    return {'scope':__doc__,'generator_sha256':sha(R.__file__),'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),
            'source_sha256':sha(SOURCE),'dependencies':e['dependencies'],'auditor_dependencies':{n:sha(ROOT/n) for n in AD},'verified_counts':e['verified_counts'],
            'cases':cases,'independent_totals':dict(total),'model_checks':dict(model),'source_proofs':proofs,'source_queries_unsat':len(proofs),'all_checks_pass':True,
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'native_epoch_join_established':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps({'replay':e['independent_totals'],'model':e['model_checks'],'source_queries_unsat':e['source_queries_unsat']}),flush=True)
