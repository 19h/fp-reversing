#!/usr/bin/env python3
"""Independent allocator cascade, undefinedness and21B emitter-request audit.

O(receipts+visits*(register state+effects)+owner joins+query DAG) time/storage;
30 s/query. Original saved-pointer provenance crosses exact parent/return joins.
No native target API/IPC/filesystem/allocation/free/PAC or IDB mutation runs.
"""
import json,struct
from collections import Counter
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,TABLE
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_daemon_network_record import state_bytes,fixture_bytes
from recover_daemon_return_bank_origins import Algebra
from lskd_values_symbolic import mem,cell
from audit_daemon_state_container_construction import Lift as ParentLift,pending
import audit_daemon_state_file_admission as Common
import recover_daemon_state_allocation_cascade as R

AD=['audit_daemon_state_container_construction.py','audit_daemon_state_word_routing.py',
    'audit_daemon_readiness_arena.py','audit_daemon_state_file_admission.py',
    'audit_daemon_network_record.py','recover_daemon_return_bank_origins.py','lskd_values_symbolic.py']

class Lift(ParentLift):
    def __init__(self,row,previous):
        super().__init__(row);self.previous=previous

    def integer(self,x):
        value=super().integer(x)
        if self.pc==0x10068ae84 and value==0x1007812e8:
            slot=0x10103ea90;target=value;address=0x6800068da8;parent=self.previous[0]
            load=Common.select(parent,0x10083c8b0,'source_reads');save=Common.select(parent,0x10083c8b8)
            reload=Common.select(self.c,0x10068ae7c,'source_reads');assert len(load)==len(save)==len(reload)==1
            expected=struct.pack('<Q',target).hex();load,save,reload=load[0],save[0],reload[0]
            assert (load['address'],load['size_bytes'],load['bytes_hex'])==(hex(slot),8,expected)
            assert (save['address'],save['size_bytes'],save['after_hex'])==(hex(address),8,expected)
            assert (reload['address'],reload['size_bytes'],reload['bytes_hex'])==(hex(address),8,expected)
            assert load['source_visit_index']<save['source_visit_index']
            assert not any(Common.overlap(w,address,8) and w['source_visit_index']>save['source_visit_index'] for w in parent['source_writes'])
            for row in self.previous[1:]:assert not any(Common.overlap(w,address,8) for w in row['source_writes'])
            assert not any(Common.overlap(w,address,8) and w['source_visit_index']<=reload['source_visit_index'] for w in self.c['source_writes'])
            assert self.projected(z3.Concat(*[self.bytes[address+j] for j in range(7,-1,-1)]))==target and FIXUPS[slot]['target']==target
            self.last_authenticated_load=(slot,target);self.counts['parent_saved_continuation_origins_checked']+=1
        return value

def external_join(before,after,event,kind,pattern):
    expected=state_bytes(before);owners=before['foreign_owners'].copy();model=Counter()
    assert event['effect_kind']==kind and event['call_site']==before['boundary']['pc'] and event['symbol']==before['boundary']['detail']['symbol']
    assert after['entry_PC']==event['continuation_PC']==hex(int(event['call_site'],16)+4)
    assert after['entry_registers31']==event['return_registers31'] and after['entry_Q_registers32']==event['return_Q_registers32'] and after['entry_NZCV']==event['return_NZCV']
    assert event['return_NZCV']==hex(0x50000000 if pattern else 0xa0000000)
    assert after['caller_SP']==before['boundary']['SP'] and after['entry_registers31'][18:30]==before['boundary']['registers31'][18:30] and after['entry_registers31'][30]==event['continuation_PC']
    for j in range(8,16):assert int(after['entry_Q_registers32'][j],16)&((1<<64)-1)==int(before['boundary']['Q_registers32'][j],16)&((1<<64)-1)
    assert event['ABI_return_and_output_premise'] and not event['native_API_executed'] and 'return32' not in event
    if kind=='free_21':
        assert event['call_site']==hex(R.FREE21) and before['boundary']['registers31'][0]==hex(R.T) and event['void_return_premise']
        assert event['retired_owner_premise']=={'address':hex(R.T),'size_bytes':21} and 'pointer_return64' not in event
        assert event['invalidated_spans']==[{'address':hex(R.T),'size_bytes':21},{'address':hex(R.E),'size_bytes':4}]
        owners.remove({'address':hex(R.T),'size_bytes':21});model['retired_21B_owner_joins_checked']+=1
    else:
        n=21 if kind=='allocation_21' else 48;ptr=int(event['pointer_return64'],16);address=R.T if n==21 else R.U
        assert kind=='allocation_'+str(n) and event['call_site']==hex(R.MALLOC21 if n==21 else R.MALLOC48)
        assert before['boundary']['registers31'][0]==hex(n) and ptr in [0,address] and event['return_registers31'][0]==hex(ptr)
        assert event['invalidated_spans']==[{'address':hex(R.E),'size_bytes':4}]
        assert all(not(int(o['address'],16)<address+n and address<int(o['address'],16)+o['size_bytes']) for o in owners)
        if ptr:
            assert event['allocated_owner_premise']=={'address':hex(address),'size_bytes':n,'initial_bytes_defined':False}
            owners.append({'address':hex(address),'size_bytes':n});assert all(address+j not in expected for j in range(n))
        else:assert event['allocated_owner_premise'] is None
        model['allocator_'+str(n)+'B_joins_checked']+=1
    assert after['foreign_owners']==owners
    for span in event['invalidated_spans']:
        a=int(span['address'],16);n=span['size_bytes'];expected={k:v for k,v in expected.items() if not a<=k<a+n}
    assert fixture_bytes(after,'private')|fixture_bytes(after,'image')==expected
    return model

def raw(s,a,n):return bytes(s[a+j] for j in range(n))
def word(s,a,n=8):return int.from_bytes(raw(s,a,n),'little')

def predecessors(c,parent):
    start=R.unpack(parent['allocation_cases'][1]['interval_packed'])
    a21=[R.unpack(x['interval_packed']) for x in c['allocation21_cases']]
    a48=[R.unpack(x['interval_packed']) for x in c['allocation48_cases']]
    return [[start],[start],[start,a21[1]],[start,a21[1]],[start,a21[1],a48[0]],[start,a21[1],a48[1]]]

def contract(c,parent):
    start=R.unpack(parent['allocation_cases'][1]['interval_packed']);initial=state_bytes(start);model=Counter()
    assert c['ABI_clobber_pattern']==1-parent['ABI_clobber_pattern']
    assert (c['parent_SIDB_context_index'],c['parent_SIDN_query_index'])==(parent['parent_context_index'],parent['parent_SIDN_query_index'])
    pending(start,R.MALLOC21,'libSystem/_malloc',0x6aa4,[21],0x6800060100)
    assert word(initial,0x6800062438)==0 and word(initial,0x68000617d0)==0x480
    assert word(initial,0x6800061c50)==0x680006c5d0
    assert [(w['address'],w['after_hex']) for w in Common.select(start,0x10083c8f0)]==[('0x6800062438','00'*8)]
    assert [(w['address'],w['after_hex']) for w in Common.select(start,0x10083c8dc)]==[('0x6800061c50','d0c5060068000000')]
    assert [x['pointer_return64'] for x in c['allocation21_cases']]==['0x0',hex(R.T)]
    assert [x['pointer_return64'] for x in c['allocation48_cases']]==['0x0',hex(R.U)]
    a21=[R.unpack(x['interval_packed']) for x in c['allocation21_cases']];a48=[R.unpack(x['interval_packed']) for x in c['allocation48_cases']]
    fr=R.unpack(c['free21_return']['interval_packed'])
    comparison=R.unpack(c['refill_comparison']['interval_packed'])
    for item,row in zip(c['allocation21_cases'],a21):model.update(external_join(start,row,item['API_return_premise'],'allocation_21',c['ABI_clobber_pattern']))
    for item,row in zip(c['allocation48_cases'],a48):model.update(external_join(a21[1],row,item['API_return_premise'],'allocation_48',c['ABI_clobber_pattern']))
    model.update(external_join(a48[0],fr,c['free21_return']['API_return_premise'],'free_21',c['ABI_clobber_pattern']))
    pending(a21[1],R.MALLOC48,'libSystem/_malloc',0x6aa4,[48],0x6800060100)
    pending(a48[0],R.FREE21,'libSystem/_free',0x46a2,[R.T],0x6800060100)
    for row in [a21[0],fr]:
        b=row['boundary'];assert b['pc']==hex(R.UNKNOWN) and b['kind']=='before_undefined_foreign_owner_read' and b['detail']=={'address':hex(R.S+48),'size_bytes':8}
        s=state_bytes(row);assert all(R.S+48+j not in s for j in range(8))
        assert not any(Common.overlap(x,R.S+48,8) for x in row['source_reads']+row['source_writes'])
        assert word(s,0x68000617d0)==0x460 and word(s,0x6800062c54,4)==0x74c29d85
        assert not any(R.T+j in s for j in range(21)) and {'address':hex(R.T),'size_bytes':21} not in row['foreign_owners']
        assert not row['source_calls'];model.update(undefined_container_field_demands_checked=1,cleanup_cursor_and_status_stores_checked=2)
    for row,ptr,pc,address in [(a21[0],0,0x100934300,0x6800063f00),(a21[1],R.T,0x100934300,0x6800063f00),
                               (a48[0],0,0x1008a103c,0x68000677e0),(a48[1],R.U,0x1008a103c,0x68000677e0)]:
        ws=Common.select(row,pc);assert len(ws)==1 and (ws[0]['address'],ws[0]['size_bytes'],ws[0]['after_hex'])==(hex(address),8,struct.pack('<Q',ptr).hex())
        model['private_allocator_result_stores_checked']+=1
    row=a48[1];s=state_bytes(row);b=row['boundary']
    assert b['pc']==hex(R.COMPARE) and b['kind']=='before_explicit_source_cut' and b['SP']=='0x680005fd40'
    assert b['registers31'][:3]==['0x680005ffd0','0x0','0x15']
    calls=row['source_calls'];assert [(x['pc'],x['target'],x['modifier']) for x in calls]==[
        ('0x10093ca80',hex(R.ADAPTER),'0x22a0'),('0x100add7d4',hex(R.EMITTER),'0x7c25'),('0x100b33030',hex(R.COMPARE),'0xec9d')]
    record=0x6800070db8;output=0x680006c5d0;k=(((record&0xffffffff)^0xeaae0ac9)*0x7398180b)&0xffffffff
    assert calls[0]['arguments8'][:2]==[hex(record),'0x680006bda0']
    assert word(s,record+8)==output and (word(s,record+16,2)-k-0x153b)&65535==21 and (word(s,record+20,4)+k)&0xffffffff==0xb399
    assert not any(Common.overlap(w,output,21) for w in row['source_writes'])
    model.update(emitter_21B_request_records_checked=1,emitter_private_output_bytes_unwritten_checked=21)
    seed=word(initial,0x1010b8d78);updated=(seed*0x2ec5+1)&((1<<64)-1);reserve=16*((updated>>60)+1)
    assert word(s,0x1010b8d78)==updated and reserve==80 and calls[1]['SP']==hex(0x6800060100-64-reserve)
    temp=int(calls[1]['arguments8'][1],16);assert temp==0x6800060070 and word(s,temp)==seed
    for pc,address,n,value in [(0x10093ca10,0x680006bda0,8,seed),(0x100add728,0x1010b8d78,8,updated),
                               (0x100add74c,temp,8,(seed-0xb0)&((1<<64)-1)),(0x100acdb1c,temp,8,seed)]:
        ws=Common.select(row,pc);assert len(ws)==1 and (ws[0]['address'],ws[0]['size_bytes'],ws[0]['after_hex'])==(hex(address),n,value.to_bytes(n,'little').hex())
    model.update(adapter_seed_updates_checked=1,adjustment_temporary_write_pairs_checked=1)
    q=0x680005ffd0;key=(((q^0xee9763edb3ce6674)^0xa374c17f4a1aff00)*0xda51a827)&((1<<64)-1)
    assert (word(s,q,4)-(key&0xffffffff))&0xffffffff==0
    assert (word(s,q+8)-key)&((1<<64)-1)==word(s,0x1010c8258,4)==9
    assert word(s,q+32)^key==0
    model['pending_equality_record_counter9_checked']+=1
    assert comparison['entry_PC']==b['pc'] and comparison['caller_SP']==b['SP'] and comparison['entry_registers31']==b['registers31']
    assert comparison['entry_Q_registers32']==b['Q_registers32'] and comparison['entry_NZCV']==row['boundary_NZCV'] and comparison['foreign_owners']==row['foreign_owners']
    assert fixture_bytes(comparison,'private')|fixture_bytes(comparison,'image')==s
    assert comparison['boundary']['pc']==hex(R.TWIST) and comparison['boundary']['kind']=='before_explicit_source_cut'
    assert [(w['address'],w['size_bytes'],w['after_hex']) for w in Common.select(comparison,0x10041a668)]==[(hex(q+16),4,'82170000')]
    assert comparison['logical_edges'][-1]['pc']=='0x100b330b8' and comparison['logical_edges'][-1]['target']==hex(R.TWIST) and comparison['logical_edges'][-1]['modifier']=='0x504c'
    assert not comparison['source_calls'];model.update(complete_source_state_joins_checked=1,equality_leaf_and_nonzero_refill_routes_checked=1)
    for rr,pc,values in [(a21[0],0x100934a2c,{19:0x76bf,21:0}),(a21[1],0x100934a2c,{19:0x76bf,21:0}),
                         (a48[0],0x1008a103c,{19:0xb9dcdf6b,23:0x5fc1,24:0x6802}),
                         (a48[1],0x1008a103c,{19:0xb9dcdf6b,23:0x5fc1,24:0x6802}),
                         (a48[1],0x10093c934,{22:0x76d8ea81,24:0x1282})]:
        fs=[f for f in rr['source_frames'] if f['pc']==hex(pc)];assert len(fs)==1
        for reg,value in values.items():assert int(fs[0]['registers31'][reg],16)==value
        model['source_equation_phase_registers_checked']+=len(values)
    for row in [*a21,*a48,fr,comparison]:
        s=state_bytes(row)
        assert {a:v for a,v in s.items() if R.S<=a<R.S+64}=={a:v for a,v in initial.items() if R.S<=a<R.S+64}
        assert len([a for a in s if R.S<=a<R.S+64])==53
        for address,n in [(R.T,21),(R.U,48)]:
            assert not any(address+j in s for j in range(n))
            assert not any(Common.overlap(x,address,n) for x in row['source_reads']+row['source_writes'])
        assert not any(Common.overlap(w,R.J+0x68,8) for w in row['source_writes'])
        assert raw(s,R.J+0x34,32)==raw(initial,R.J+0x34,32)
        model.update(container_mask_preservation_intervals_checked=1,heap_payload_bytes_undefined_checked=69,
                     generated_stream_bytes_preserved_checked=32,context_publication_absence_intervals_checked=1)
    return {'decoded_output_pointer':hex(output),'decoded_length_bytes':21,'decoded_control32':'0xb399',
            'seed64':hex(seed),'updated_seed64':hex(updated),'fixed_adapter_reserve_bytes':64,'dynamic_reserve_bytes':reserve,
            'adjustment_temporary_pointer':hex(temp),'pending_generation_counter32':9,'model_checks':dict(model),'all_checks_pass':True}

def obligations():
    out=[]
    def prove(label,bad,premise=z3.BoolVal(True)):
        s=z3.Solver();s.set(timeout=30000);s.add(premise);assert s.check()==z3.sat;s.add(z3.simplify(bad));assert s.check()==z3.unsat,label
        out.append({'label':label,'query':s.to_smt2(),'premises_nonvacuous':True,'result':'unsat'})
    p,q,sp,d,cursor=z3.BitVecs('cascade_pointer64 cascade_companion64 cascade_SP64 cascade_output64 cascade_cursor64',64)
    class Select(Algebra):
        def load(self,a,n):
            if self.pc in [0x100934a4c,0x1008a1060]:assert n==8;self.slot=a;return z3.BitVecVal(0,64)
            return super().load(a,n)
    v=Select();v.seed('sp',sp);v.seed('x0',p);v.seed('x21',q);v.seed('w19',0x76bf);mem(v,sp+0x9d8,8,TABLE)
    v.run_block(0x100934a2c,0x100934a60)
    prove('all_pointer_bits_original21_allocator_partition',v.slot!=TABLE+8*z3.If((p|q)==0,z3.BitVecVal(0x76bf,64),z3.BitVecVal(0x76d3,64)))
    v=Select();v.seed('sp',sp);v.seed('x0',p);v.seed('w19',0xb9dcdf6b);v.seed('w23',0x5fc1);v.seed('w24',0x6802);v.seed('x25',TABLE)
    v.run_block(0x1008a103c,0x1008a1068)
    prove('all_pointer_bits_original48_allocator_partition',v.slot!=TABLE+8*z3.If(p==0,z3.BitVecVal(0x6802,64),z3.BitVecVal(0x6819,64)))
    v=Algebra();v.seed('x20',p+R.Parent.BIAS);v.seed('w21',0x6f81);v.run_block(0x10074aba8,R.UNKNOWN)
    prove('all_container_pointer_bits_original_cleanup_field_address',v.read('x9')!=p+48)
    v=Algebra();v.seed('sp',sp);v.seed('x0',p);v.run_block(0x100934300,0x100934304)
    prove('all_pointer_bits_original21_result_store',cell(v,sp+0x3e00,8)!=p)
    v=Algebra();v.seed('sp',sp);v.seed('x0',p);v.run_block(0x1008a103c,0x1008a1040)
    prove('all_pointer_bits_original48_result_store',cell(v,sp+0x76e0,8)!=p)
    v=Algebra();v.seed('sp',sp);mem(v,sp+0x16d0,8,cursor);v.run_block(0x10068ae70,0x10068ae7c)
    prove('all_cursor_bits_original_failure_rewind32',cell(v,sp+0x16d0,8)!=cursor-32)
    v=Algebra();v.seed('sp',sp);v.run_block(0x10083c8f0,0x10083c8f8)
    prove('original_companion_and_allocator_result_initially_zero',z3.Or(cell(v,sp+0x2338,8)!=0,cell(v,sp+0x3e00,8)!=0))
    v=Algebra();v.seed('sp',sp);v.seed('w24',0x1282);v.seed('w22',0x76d8ea81);mem(v,sp+0x1b50,8,d)
    v.run_block(0x10093c934,0x10093ca04);record=sp+0x10cb8;k=(z3.Extract(31,0,record)^0xeaae0ac9)*0x7398180b
    prove('all_aligned_SP_bits_original_emitter21_request',z3.Or(cell(v,record+8,8)!=d,
          cell(v,record+16,2)-z3.Extract(15,0,k)-0x153b!=21,cell(v,record+20,4)+k!=0xb399),(sp&15)==0)
    v=Algebra();v.seed('sp',sp);mem(v,sp+0x16d0,8,cursor);v.seed('x10',0xc388)
    v.run_block(0x10083c8cc,0x10083c8f0)
    prove('all_cursor_bits_original_private_output_reservation',z3.Or(cell(v,sp+0x1b50,8)!=sp+0xc070+cursor,cell(v,sp+0x16d0,8)!=cursor+32))
    record,left,right=z3.BitVecs('cascade_compare_record64 cascade_left64 cascade_right64',64)
    mode,mask,yes,no=z3.BitVecs('cascade_compare_mode32 cascade_mask32 cascade_yes32 cascade_no32',32)
    v=Algebra();v.seed('x0',record);v.run_block(R.COMPARE,0x10041a61c);key=v.read('x8');lo=z3.Extract(31,0,key)
    for off,n,value in [(0,4,mode+lo),(8,8,left+key),(20,4,mask+lo),(32,8,right^key),(40,4,no-lo),(44,4,yes^lo)]:mem(v,record+off,n,value)
    v.run_block(0x10041a61c,0x10041a66c);predicate=z3.If(mode&1!=0,z3.UGT(left,right),left==right)
    prove('all_records_original_equality_or_unsigned_greater_leaf',z3.Or(cell(v,record+16,4)!=(mask^z3.If(predicate,yes,no)),v.read('x0')!=record,v.stores[-1]['address']!=record+16))
    counter=z3.BitVec('cascade_generation_counter32',32);at=0x680005ffd0;key=((at^0xee9763edb3ce6674^0xa374c17f4a1aff00)*0xda51a827)&((1<<64)-1)
    v=Algebra();v.seed('sp',0x680005fd40);v.seed('x29',0x6800060060);v.seed('w12',0xb399);v.seed('x13',z3.ZeroExt(32,counter));mem(v,0x680005fd40+0x98,8,key)
    v.run_block(0x100b32f60,0x100b32fb4);v.seed('x0',at);v.run_block(R.COMPARE,0x10041a66c)
    prove('all_counter32_original_current_refill_record_partition',z3.Or(cell(v,at+16,4)!=z3.If(counter==0,z3.BitVecVal(0x177c,32),z3.BitVecVal(0x1782,32)),cell(v,0x680005fd40+0xc8,8)!=z3.ZeroExt(32,counter)))
    return out

def build():
    e=json.loads(read(ROOT/(R.P+'_checks.json')));p=json.loads(read(ROOT/(R.Parent.P+'_checks.json')))
    assert e['generator_sha256']==sha(R.__file__) and e['dependencies']=={n:sha(ROOT/n) for n in R.DEPS}
    contexts=[];total=Counter();model=Counter()
    for j,c in enumerate(e['contexts']):
        parent=p['contexts'][c['parent_context_index']];lifts=[]
        for row,previous in zip(R.context_intervals(c),predecessors(c,parent)):
            lift=Lift(row,previous).run();assert lift['all_checks_pass'];lifts.append(lift);total.update(lift['verified_counts'])
        ct=contract(c,parent);model.update(ct['model_checks']);contexts.append({'independent_lifts':lifts,'contract':ct,'all_checks_pass':True})
        if j%8==0:print(json.dumps({'context':j,'source_visits':total['source_visits']}),flush=True)
    qs=obligations();assert e['SDK_checks']==R.Parent.sdk_checks()
    return {'scope':__doc__,'generator_sha256':sha(R.__file__),'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),
            'source_sha256':sha(SOURCE),'dependencies':e['dependencies'],'auditor_dependencies':{n:sha(ROOT/n) for n in AD},
            'verified_counts':e['verified_counts'],'contexts':contexts,'independent_totals':dict(total),'model_checks':dict(model),
            'source_proofs':qs,'source_queries_unsat':len(qs),'all_checks_pass':True,
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'native_epoch_join_established':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps({'independent':e['independent_totals'],'model':e['model_checks'],'queries':e['source_queries_unsat']}),flush=True)
