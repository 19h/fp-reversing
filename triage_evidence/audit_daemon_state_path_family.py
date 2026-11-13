#!/usr/bin/env python3
"""Independent family/gate/errno replay and nonvacuous source equations.

O(receipts+visits*(state+effects)+query DAG) time/storage;30 s/query.
Native APIs/IPC/PAC/filesystem and IDB mutation never execute. New object
allocations, initializer returns, borrowed errno and caller epochs are premises.
"""
import json,struct
from collections import Counter
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_daemon_readiness_arena import Lift
from audit_daemon_network_record import fixture_bytes,state_bytes
from recover_daemon_return_bank_origins import Algebra
from lskd_values_symbolic import mem,cell
import recover_daemon_state_path_family as R
import audit_daemon_state_path_objects as Prior

raw=Prior.raw;select=Prior.select;overlap=Prior.overlap
AD=['audit_daemon_state_path_objects.py','recover_daemon_return_bank_origins.py','lskd_values_symbolic.py']

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
        for key in ['allocated_owner_premise','borrowed_owner_premise']:
            alloc=event.get(key)
            if not alloc:continue
            a=int(alloc['address'],16);n=alloc['size_bytes'];assert not alloc['initial_bytes_defined'] and all(a+j not in expected for j in range(n))
            assert all(not(int(o['address'],16)<a+n and a<int(o['address'],16)+o['size_bytes']) for o in owners)
            owners.append({'address':hex(a),'size_bytes':n});model['initially_undefined_'+('borrowed' if key.startswith('borrowed') else 'allocated')+'_bytes_checked']+=n
        opaque=event.get('opaque_owner_premise')
        if opaque:
            a=int(opaque['address'],16);n=opaque['size_bytes'];assert {'address':hex(a),'size_bytes':n} in owners and n==200 and not opaque['initial_bytes_defined']
            expected={k:v for k,v in expected.items() if not a<=k<a+n};model['opaque_lock_bytes_checked']+=n
    else:
        assert before['boundary']['pc']==after['entry_PC'] and before['boundary']['registers31']==after['entry_registers31'] and before['boundary']['Q_registers32']==after['entry_Q_registers32'] and before['boundary_NZCV']==after['entry_NZCV'];model['ordinary_state_joins_checked']+=1
    assert expected==fixture_bytes(after,'private')|fixture_bytes(after,'image') and owners==after['foreign_owners']
    return model

def expected_object(ordinal,source,n):
    lock=R.address(ordinal)+0x1000;payload=R.path_payload(source,n)
    path=b'/var/db/fpsd/SC Info/'+payload+b'\0'
    out={j:b for j,b in enumerate(struct.pack('<Q',lock)+bytes(16))};out[24]=1
    out.update({j:0 for j in range(28,32)});out.update({32+j:b for j,b in enumerate(path)})
    return out,path

def contract(c,parent):
    before=R.unpack(parent['intervals_packed'][-1]);initial=state_bytes(before);rows=[R.unpack(p) for p in c['intervals_packed']]
    assert len(rows)==len(c['API_return_premises'])==29;model=Counter();objects=[]
    for row,event in zip(rows,c['API_return_premises']):
        model.update(joined(before,event,row));assert not row['native_target_executed'];before=row
    for j,(ordinal,offset,source,call,n,name) in enumerate(R.FAMILY[1:]):
        a=R.address(ordinal);lock=a+0x1000;size=62+n;part=rows[3*j:3*j+3]
        prior=R.unpack(parent['intervals_packed'][-1]) if j==0 else rows[3*j-1]
        assert prior['boundary']['pc']==hex(R.Parent.MALLOC) and prior['boundary']['registers31'][:3]==[hex(size),hex(R.J+offset),'0x14'] and prior['boundary']['registers31'][23]==hex(source)
        assert prior['source_calls'][-1]['pc']==hex(call) and prior['source_calls'][-1]['target']=='0x100410c4c' and prior['source_calls'][-1]['modifier']=='0x704f'
        ev=c['API_return_premises'][3*j:3*j+3]
        assert [x['symbol'] for x in ev]==['libSystem/_malloc','libSystem/_malloc','libSystem/_pthread_rwlock_init']
        assert ev[0]['pointer_return64']==hex(a) and ev[0]['allocated_owner_premise']['size_bytes']==size
        assert ev[1]['pointer_return64']==hex(lock) and ev[1]['allocated_owner_premise']['size_bytes']==200
        assert int(ev[2]['return32'],16)==0 and ev[2]['opaque_owner_premise']['address']==hex(lock)
        assert part[1]['boundary']['pc']==hex(R.Parent.INIT) and part[1]['boundary']['registers31'][:2]==[hex(lock),'0x0']
        zero=[w for w in part[1]['source_writes'] if overlap(w,lock,200)]
        assert [(w['address'],w['size_bytes'],w['after_hex']) for w in zero]==[(hex(lock+2*k),2,'0000') for k in range(4)]
        assert not any(overlap(x,lock,200) for row in rows[3*j+2:] for x in row['source_reads']+row['source_writes'])
        actual={int(w['address'],16)-a+k:b for row in part for w in row['source_writes'] if overlap(w,a,size) for k,b in enumerate(bytes.fromhex(w['after_hex']))}
        expected,path=expected_object(ordinal,source,n);assert actual==expected
        s=state_bytes(part[-1]);assert {k-a:v for k,v in s.items() if a<=k<a+size}==expected
        assert raw(s,R.J+offset,8)==struct.pack('<Q',a)
        pubs=select(part[-1],0x10003a3e0);assert len(pubs)==1 and pubs[0]['address']==hex(R.J+offset) and pubs[0]['after_hex']==struct.pack('<Q',a).hex()
        assert all(w['source_visit_index']<pubs[0]['source_visit_index'] for w in part[-1]['source_writes'] if overlap(w,a,size))
        st=select(part[-1],0x1000354d4);assert len(st)==1 and st[0]['address']==hex(R.Parent.R+8) and st[0]['after_hex']==struct.pack('<I',0x8b3dc651).hex()
        directory=select(part[-1],0x1000879cc,'source_reads');dw=select(part[-1],0x1000879d8)
        assert [x['address'] for x in directory]==[hex(0x6600003000+k) for k in range(19,-1,-1)]
        assert [x['address'] for x in dw]==[hex(a+32+k) for k in range(19,-1,-1)]
        assert all(bytes.fromhex(w['after_hex'])[0]==bytes.fromhex(r['bytes_hex'])[0]^0x98 for r,w in zip(directory,dw))
        for pc,off in [(0x10009161c,2),(0x100091630,0),(0x100091640,3),(0x100091650,1)]:
            reads=select(part[-1],pc,'source_reads');assert [x['address'] for x in reads]==[hex(source+k+off) for k in range(0,n,4)]
            assert all(x['bytes_hex']==IMAGE.read(int(x['address'],16),1).hex() for x in reads)
        assert path.split(b'\0')[0].decode()=='/var/db/fpsd/SC Info/'+name
        assert len(expected)==n+51 and size-len(expected)==11
        objects.append({'ordinal':ordinal,'context_offset':hex(offset),'owner':hex(a),'requested_size_bytes':size,'path_payload_hex':path.hex(),'defined_bytes':len(expected),'undefined_bytes':11})
        model.update(object_publications_checked=1,constructor_status_words_checked=1,object_defined_bytes_checked=len(expected),object_undefined_gap_bytes_checked=11,
                     directory_byte_defuses_checked=20,basename_source_bytes_checked=n,path_payload_bytes_checked=len(path),preinit_lock_header_bytes_checked=8)
    gate,caller,last=rows[26:29];assert gate['boundary']['pc']==caller['entry_PC']==hex(R.GATE)
    reads=[(int(x['pc'],16),int(x['address'],16)) for x in caller['source_reads'] if R.J+0x108<=int(x['address'],16)<R.J+0x158]
    expected_reads=[(pc,R.J+off) for off,pc,_,_ in R.GATES]+[(0x1006d9aac,R.J+0x118),(0x10083947c,R.J+0x120)]
    assert reads==expected_reads
    calls=caller['source_calls'];assert [(x['pc'],x['target'],x['modifier']) for x in calls]==[
        ('0x10083955c','0x10042f208','0x6aa4'),('0x10042f4b8','0x100618fdc','0xe200'),('0x100619234','0x1006176f8','0x11d8')]
    rec=int(calls[1]['arguments8'][0],16);assert calls[2]['arguments8'][0]==hex(rec)
    packed=select(caller,0x10042f3b4);assert len(packed)==1 and packed[0]['address']==hex(rec) and packed[0]['after_hex']==struct.pack('<Q',R.Parent.B).hex()
    loaded=select(caller,0x10061788c,'source_reads');assert len(loaded)==1 and loaded[0]['address']==hex(rec) and loaded[0]['bytes_hex']==packed[0]['after_hex']
    control=select(caller,0x10042f3c8);loaded_control=select(caller,0x100617884,'source_reads')
    assert len(control)==len(loaded_control)==1 and control[0]['address']==loaded_control[0]['address']==hex(rec+12) and control[0]['after_hex']==loaded_control[0]['bytes_hex']
    assert caller['boundary']['pc']==hex(R.ERRNO) and caller['boundary']['detail']['symbol']=='libSystem/___error' and caller['boundary']['detail']['modifier']=='0x6e96'
    errno=c['API_return_premises'][-1];assert errno['borrowed_owner_premise']=={'address':hex(R.E),'size_bytes':4,'initial_bytes_defined':False}
    assert errno['pointer_return64']==hex(R.E) and len(last['source_writes'])==1
    w=last['source_writes'][0];assert (w['pc'],w['address'],w['size_bytes'],w['after_hex'])==('0x10063c2fc',hex(R.E),4,'00000000')
    assert last['boundary']==c['final_boundary'] and last['boundary_NZCV']==c['final_NZCV']
    b=last['boundary'];assert b['pc']==hex(R.LSTAT) and b['detail']['symbol']=='libSystem/_lstat' and b['detail']['modifier']=='0xf401'
    assert b['registers31'][:2]==[hex(R.Parent.B+32),hex(int(b['SP'],16)+24)]
    assert raw(state_bytes(last),R.Parent.B+32,34)==Prior.PATH
    for ordinal,_,source,_,n,_ in R.FAMILY:
        a=R.address(ordinal);expect,_=expected_object(ordinal,source,n)
        assert {k-a:v for k,v in state_bytes(last).items() if a<=k<a+62+n}==expect
    assert raw(initial,R.J+0x34,32)==raw(state_bytes(last),R.J+0x34,32)
    assert not any(overlap(x,R.J+0x34,32) for row in rows for x in row['source_reads']+row['source_writes'])
    model.update(caller_nonnull_field_checks=9,consumer_record_object_defuses_checked=1,errno_source_zero_bytes_checked=4,lstat_requests_checked=1,generated_stream_bytes_preserved_checked=32,complete_family_object_masks_checked=10)
    return {'objects':objects,'filesystem_record':hex(rec),'lstat_boundary':b,'model_checks':dict(model),'all_checks_pass':True}

def control_contract(control,c):
    before=R.unpack(c['intervals_packed'][26]);after=R.unpack(control['interval_packed']);off=int(control['zero_context_offset'],16);a=R.J+off
    assert control['premise']=={'address':hex(a),'size_bytes':8,'bytes_hex':'00'*8,'native_allocation_failure_observed':False}
    assert before['boundary']['pc']==after['entry_PC']==hex(R.GATE) and before['boundary']['registers31']==after['entry_registers31'] and before['boundary']['Q_registers32']==after['entry_Q_registers32'] and before['boundary_NZCV']==after['entry_NZCV'] and before['boundary']['SP']==after['caller_SP']
    expected=state_bytes(before);expected.update({a+k:0 for k in range(8)})
    assert expected==fixture_bytes(after,'private')|fixture_bytes(after,'image') and before['foreign_owners']==after['foreign_owners']
    b=after['boundary'];model=Counter(single_field_zero_state_joins_checked=1,zero_control_bytes_checked=8)
    if off==0x138:
        assert b['pc']==hex(R.ERRNO) and b['detail']['symbol']=='libSystem/___error'
        assert not any(overlap(r,a,8) for r in after['source_reads']);model['optional_field_controls_reach_errno_checked']+=1
    else:
        lock=R.address(2)+0x1000 if off==0x118 else R.Parent.L
        assert b['pc']==hex(R.DESTROY) and b['detail']['symbol']=='libSystem/_pthread_rwlock_destroy' and b['detail']['modifier']=='0xfe1e' and b['registers31'][0]==hex(lock)
        reads=select(after,0x1004272f8,'source_reads');assert len(reads)==1 and reads[0]['address']==hex(lock-0x1000) and reads[0]['bytes_hex']==struct.pack('<Q',lock).hex()
        assert not any(x['target']=='0x100618fdc' for x in after['source_calls']);model['required_field_controls_reach_destroy_checked']+=1
    return {'zero_context_offset':hex(off),'boundary':b,'model_checks':dict(model),'all_checks_pass':True}

def obligations(e):
    qs=Prior.obligations()
    def prove(label,bad,premise=z3.BoolVal(True)):
        s=z3.Solver();s.set(timeout=30000);s.add(premise);assert s.check()==z3.sat;s.add(z3.simplify(bad));assert s.check()==z3.unsat,label
        qs.append({'label':label,'query':s.to_smt2(),'premises_nonvacuous':True,'result':'unsat'})
    base=0x70000000;data=z3.BitVec('family_basename_quad32',32)
    for j in [12,16]:
        v=Algebra();v.seed('x23',base);v.seed('x9',base+0x100);v.seed('x10',j);v.seed('w11',j);v.seed('w8',0x2b60);v.seed('x13',0x33eb9b6)
        for k in range(4):mem(v,base+j+k,1,z3.Extract(8*k+7,8*k,data))
        v.run_block(0x1000915ec,0x10009165c);b=[z3.Extract(8*i+7,8*i,data) for i in range(4)]
        expected=z3.Concat(b[1]^0x22,b[3]^0x99,b[0]^0x3e,b[2]^0x52)
        prove('all_family_basename_data_bits_original_quad_'+str(j),z3.Concat(*[cell(v,base+0x100+k,1) for k in range(3,-1,-1)])!=expected)
    row=R.unpack(e['cases'][0]['intervals_packed'][27]);frames={int(f['pc'],16):f for f in row['source_frames']}
    ptr=z3.BitVec('family_gate_pointer64',64)
    for off,start,end,index in R.GATES:
        def run(value):
            v=Algebra();f=frames[start]
            for j,x in enumerate(f['registers31']):v.seed('x'+str(j),int(x,16))
            v.seed('sp',int(f['SP'],16));mem(v,R.J+off,8,value);v.run_block(start,end);return v.read(index)
        nonnull=run(z3.BitVecVal(R.Parent.B,64));null=run(z3.BitVecVal(0,64));actual=run(ptr)
        assert z3.is_true(z3.simplify(nonnull!=null))
        prove('all_pointer_bits_original_caller_gate_'+hex(off),actual!=z3.If(ptr==0,null,nonnull))
    err,obj=z3.BitVecs('family_errno_pointer64 family_path_object64',64)
    v=Algebra();v.seed('x0',err);v.seed('x20',obj);v.run_block(0x10063c2fc,0x10063c304)
    prove('all_pointer_bits_original_errno_zero_and_path_argument',z3.Or(cell(v,err,4)!=0,v.read('x0')!=obj+32))
    assert len(qs)==23
    return qs

def build():
    e=json.loads(read(ROOT/(R.P+'_checks.json')));p=json.loads(read(ROOT/(R.Parent.P+'_checks.json')))
    assert e['generator_sha256']==sha(R.__file__) and e['dependencies']=={n:sha(ROOT/n) for n in R.DEPS}
    cases=[];controls=[];total=Counter();model=Counter()
    for j,c in enumerate(e['cases']):
        lifts=[];counts=Counter()
        for packed in c['intervals_packed']:
            lift=Lift(R.unpack(packed)).run();assert lift['all_checks_pass'];lifts.append(lift);counts.update(lift['verified_counts'])
        ct=contract(c,p['cases'][c['parent_case_index']]);model.update(ct['model_checks']);total.update(counts)
        cases.append({'parent_case_index':c['parent_case_index'],'ABI_clobber_pattern':c['ABI_clobber_pattern'],'independent_lifts':lifts,'independent_totals':dict(counts),'contract':ct,'all_checks_pass':True})
        print(json.dumps({'family_case':j,'source_visits':total['source_visits']}),flush=True)
    for j,c in enumerate(e['gate_controls']):
        lift=Lift(R.unpack(c['interval_packed'])).run();assert lift['all_checks_pass'];total.update(lift['verified_counts'])
        ct=control_contract(c,e['cases'][c['family_case_index']]);model.update(ct['model_checks'])
        controls.append({'family_case_index':c['family_case_index'],'zero_context_offset':c['zero_context_offset'],'independent_lift':lift,'contract':ct,'all_checks_pass':True})
    proofs=obligations(e)
    return {'scope':__doc__,'generator_sha256':sha(R.__file__),'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),
            'source_sha256':sha(SOURCE),'dependencies':e['dependencies'],'auditor_dependencies':{n:sha(ROOT/n) for n in AD},'verified_counts':e['verified_counts'],
            'cases':cases,'gate_controls':controls,'independent_totals':dict(total),'model_checks':dict(model),'source_proofs':proofs,'source_queries_unsat':len(proofs),'all_checks_pass':True,
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'native_epoch_join_established':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps({'replay':e['independent_totals'],'model':e['model_checks'],'source_queries_unsat':e['source_queries_unsat']}),flush=True)
