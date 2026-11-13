#!/usr/bin/env python3
"""Independent SIDN cleanup, owner transitions and64B construction audit.

O(receipts+visits*(register state+effects)+owner joins+query DAG) time/storage;
30 s/query. Imported effects are conditional premises, not native lifetimes.
Original pointer loads, private saves and reloads are joined before matching
authenticated fixup words. No native API/IPC/PAC or IDB mutation executes.
"""
import json,struct
from collections import Counter
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_daemon_state_word_routing import Lift as ParentLift
from audit_daemon_network_record import state_bytes,fixture_bytes
from recover_daemon_return_bank_origins import Algebra
from lskd_values_symbolic import mem,cell
import audit_daemon_state_path_removal as Local
import audit_daemon_state_file_admission as Common
import recover_daemon_state_container_construction as R

AD=['audit_daemon_state_word_routing.py','audit_daemon_readiness_arena.py','audit_daemon_state_path_removal.py',
    'audit_daemon_state_file_admission.py','audit_daemon_network_record.py','recover_daemon_return_bank_origins.py','lskd_values_symbolic.py']
COPIES={0x1006902ec:(0x1008b394c,0x101040278,0x1006c3e6c,0x1006c3e70,0x1006902e4,0x3aa8),
        0x1006b7728:(0x1006991ac,0x101044d98,0x10087768c,0x100877690,0x1006b7710,0x4e20),
        0x100939c84:(0x10070a2e4,0x101045180,0x10084a76c,0x10084a774,0x100947068,0x9c18),
        0x100831198:(0x100595ec0,0x10103e1c8,0x100665680,0x100665684,0x100670198,0x9110)}
ADC={0x100946fd4:('w13','wzr','w12'),0x100946ff0:('w11','wzr','w12'),
     0x100947024:('w10','wzr','w12'),0x100947058:('w9','w10','w9')}

class Lift(ParentLift):
    def one(self,i):
        if i.mnemonic=='adc':
            adc32(self,i);self.counts['ADC32_value_transitions_checked']+=1;return
        return super().one(i)

    def integer(self,x):
        value=super().integer(x)
        if self.pc in COPIES and value==COPIES[self.pc][0]:
            target,slot,loadpc,savepc,reloadpc,offset=COPIES[self.pc];sp=int(self.c['caller_SP'],16);address=sp+offset
            assert FIXUPS[slot]['target']==target
            assert self.projected(z3.Concat(*[self.bytes[address+j] for j in range(7,-1,-1)]))==target
            loads=Common.select(self.c,loadpc,'source_reads');saves=Common.select(self.c,savepc);reloads=Common.select(self.c,reloadpc,'source_reads')
            assert len(loads)==len(saves)==len(reloads)==1;load,save,reload=loads[0],saves[0],reloads[0]
            expected=target.to_bytes(8,'little').hex()
            assert (load['address'],load['size_bytes'],load['bytes_hex'])==(hex(slot),8,expected)
            assert (save['address'],save['size_bytes'],save['after_hex'])==(hex(address),8,expected)
            assert (reload['address'],reload['size_bytes'],reload['bytes_hex'])==(hex(address),8,expected)
            assert load['source_visit_index']<save['source_visit_index']<reload['source_visit_index']
            assert not any(Common.overlap(w,address,8) and save['source_visit_index']<w['source_visit_index']<=reload['source_visit_index'] for w in self.c['source_writes'])
            self.last_authenticated_load=(slot,target);self.counts['original_pointer_load_save_reload_chains_checked']+=1
        return value

def adc32(v,i):
    assert i.mnemonic=='adc' and i.address in ADC and i.op_str==', '.join(ADC[i.address])
    dest,left,right=ADC[i.address]
    v.write(dest,v.read(left)+v.read(right)+z3.If(v.carry,z3.BitVecVal(1,32),z3.BitVecVal(0,32)))

def external_join(before,after,event,kind):
    expected=state_bytes(before);owners=before['foreign_owners'].copy();model=Counter()
    assert event['effect_kind']==kind and event['call_site']==before['boundary']['pc'] and event['symbol']==before['boundary']['detail']['symbol']
    assert after['entry_PC']==event['continuation_PC']==hex(int(event['call_site'],16)+4)
    assert after['entry_registers31']==event['return_registers31'] and after['entry_Q_registers32']==event['return_Q_registers32'] and after['entry_NZCV']==event['return_NZCV']
    assert after['caller_SP']==before['boundary']['SP'] and after['entry_registers31'][18:30]==before['boundary']['registers31'][18:30] and after['entry_registers31'][30]==event['continuation_PC']
    for j in range(8,16):assert int(after['entry_Q_registers32'][j],16)&((1<<64)-1)==int(before['boundary']['Q_registers32'][j],16)&((1<<64)-1)
    assert event['ABI_return_and_output_premise'] and not event['native_API_executed'] and 'return32' not in event
    if kind=='buffer_free':
        assert event['call_site']==hex(R.FREE) and before['boundary']['registers31'][0]==hex(R.A) and event['void_return_premise']
        assert 'pointer_return64' not in event and event['retired_owner_premise']=={'address':hex(R.A),'size_bytes':R.N}
        assert event['invalidated_spans']==[{'address':hex(R.A),'size_bytes':R.N},{'address':hex(R.E),'size_bytes':4}]
        owners.remove({'address':hex(R.A),'size_bytes':R.N});model['buffer_owner_retirement_joins_checked']+=1
    else:
        assert kind=='container_allocation' and event['call_site']==hex(R.MALLOC) and before['boundary']['registers31'][0]=='0x40'
        pointer=int(event['pointer_return64'],16);assert pointer in [0,R.S] and event['return_registers31'][0]==hex(pointer)
        assert event['invalidated_spans']==[{'address':hex(R.E),'size_bytes':4}]
        assert all(not(int(o['address'],16)<R.S+64 and R.S<int(o['address'],16)+o['size_bytes']) for o in owners)
        if pointer:
            assert event['allocated_owner_premise']=={'address':hex(R.S),'size_bytes':64,'initial_bytes_defined':False}
            owners.append({'address':hex(R.S),'size_bytes':64});assert all(R.S+j not in expected for j in range(64))
        else:assert event['allocated_owner_premise'] is None
        model['container_allocation_joins_checked']+=1
    assert after['foreign_owners']==owners
    for span in event['invalidated_spans']:
        a=int(span['address'],16);n=span['size_bytes'];expected={k:v for k,v in expected.items() if not a<=k<a+n}
    assert fixture_bytes(after,'private')|fixture_bytes(after,'image')==expected
    return model

def pending(row,pc,symbol,modifier,args=None,sp=None):
    b=row['boundary'];assert b['pc']==hex(pc) and b['kind']=='before_unmodeled_import_call' and b['detail']['symbol']==symbol and b['detail']['modifier']==hex(modifier)
    if args is not None:assert b['registers31'][:len(args)]==[hex(x) for x in args]
    if sp is not None:assert b['SP']==hex(sp)

def contract(c,parent,item):
    start=R.unpack(item['interval_packed']);initial=state_bytes(start);model=Counter();terminal={}
    assert (c['parent_origin_kind'],c['parent_origin_index'])==(item['origin_kind'],item['origin_index']) and c['ABI_clobber_pattern']==1-parent['ABI_clobber_pattern']
    pending(start,R.LSTAT,'libSystem/_lstat',0xf401,[R.B+32,0x680005ff18],0x680005fef0);stat=0x680005ff18
    def ret(before,item):
        row=R.unpack(item['interval_packed']);ev=item['API_return_premise'];model.update(Common.join(before,row,event=ev))
        assert ev['return_NZCV']==hex(0x50000000 if c['ABI_clobber_pattern'] else 0xa0000000);return row
    def put(before,item,address,value,width,kind):
        assert item['output_premise']=={'address':hex(address),'bytes_hex':value.to_bytes(width,'little').hex(),'size_bytes':width,'kind':kind}
        row=R.unpack(item['interval_packed']);model.update(Common.join(before,row,effect=item['output_premise']));return row
    def seeds(row,pc,values):
        frames=[f for f in row['source_frames'] if f['pc']==hex(pc)];assert len(frames)==1
        for register,value in values.items():assert int(frames[0]['registers31'][register],16)&0xffffffff==value
        model['proof_phase_seed_registers_checked']+=len(values)
    def terminal_status(row,status):
        pending(row,R.FREE,'libSystem/_free',0x46a2,[R.A],0x6800060100)
        for pc,address in [(0x1004af644,0x68000600d0),(0x10041ac4c,0x6800070dc8)]:
            ws=Common.select(row,pc);assert len(ws)==1 and (ws[0]['address'],ws[0]['size_bytes'],ws[0]['after_hex'])==(hex(address),4,struct.pack('<I',status).hex())
        store=Common.select(row,0x10041ac4c)[0]
        assert not any(Common.overlap(x,0x6800070dc8,4) and x['source_visit_index']>store['source_visit_index'] for x in row['source_reads'])
        assert not row['source_calls'] and row['boundary']['registers31'][22]=='0x74c29dbe'
        reads=Common.select(row,0x10074aa04,'source_reads');assert len(reads)==1 and (reads[0]['address'],reads[0]['size_bytes'],reads[0]['bytes_hex'])==('0x6800062008',8,struct.pack('<Q',R.A).hex())
        assert row['foreign_owners']==start['foreign_owners'];model.update(raw_SIDN_status_stores_checked=2,ignored_outer_status_windows_checked=1,buffer_free_requests_checked=1)
    assert [x['return32'] for x in c['stat_cases']]==R.STATUSES;stats=[]
    for x in c['stat_cases']:
        assert int(x['API_return_premise']['return32'],16)==x['return32'] and x['API_return_premise']['invalidated_spans']==[{'address':hex(stat),'size_bytes':144},{'address':hex(R.E),'size_bytes':4}]
        row=ret(start,x);stats.append(row);s=state_bytes(row);assert not any(stat+j in s for j in range(144)) and not any(R.E+j in s for j in range(4)) and not row['source_writes']
        seeds(row,R.LSTAT+4,{20:0x5f61,24:0x1d47})
        if x['return32']==0:
            assert row['boundary']['pc']==hex(R.MODE) and row['boundary']['kind']=='before_unknown_private_read' and row['boundary']['detail']['address']==hex(stat+4) and row['boundary']['detail']['snapshot']['known_mask_hex']=='0000'
        else:pending(row,R.ERRNO,'libSystem/___error',0x6e96,sp=0x680005fef0)
        model['lstat_return_partitions_checked']+=1
    assert [x['mode16'] for x in c['mode_cases']]==R.MODES;modes=[]
    for j,x in enumerate(c['mode_cases']):
        row=put(stats[0],x,stat+4,x['mode16'],2,'mode16');modes.append(row);seeds(row,R.MODE,{9:0x3203})
        rr=Common.select(row,R.MODE,'source_reads');assert len(rr)==1 and (rr[0]['address'],rr[0]['size_bytes'],rr[0]['bytes_hex'])==(hex(stat+4),2,struct.pack('<H',x['mode16']).hex())
        if j==0:terminal_status(row,0x74c29dd3);terminal['mode',j]=row
        else:pending(row,R.UNLINK,'libSystem/_unlink',0x566a,[R.B+32],0x680005fef0);assert not row['source_writes']
        model['mode_word_partitions_checked']+=1
    assert [x['stat_case_index'] for x in c['error_accessors']]==[1,2,3]
    for ai,a in enumerate(c['error_accessors']):
        row=ret(stats[a['stat_case_index']],a);assert row['boundary']['pc']==hex(R.ERRNO+4) and row['boundary']['kind']=='before_undefined_foreign_owner_read' and row['boundary']['detail']=={'address':hex(R.E),'size_bytes':4} and not row['source_visits']
        assert [x['errno32'] for x in a['word_cases']]==R.ERRNOS
        for wi,x in enumerate(a['word_cases']):
            out=put(row,x,R.E,x['errno32'],4,'errno32');seeds(out,R.ERRNO+4,{20:0xc69c});terminal_status(out,0x74c29dd1 if x['errno32']==2 else 0x74c29dd3)
            terminal['errno',ai*2+wi]=out;model['errno_word_partitions_checked']+=1
    assert [x['return32'] for x in c['unlink_cases']]==R.STATUSES;unlinks=[]
    for j,x in enumerate(c['unlink_cases']):
        assert int(x['API_return_premise']['return32'],16)==x['return32'] and x['API_return_premise']['invalidated_spans']==[{'address':hex(R.E),'size_bytes':4}]
        row=ret(modes[1],x);unlinks.append(row);seeds(row,R.UNLINK+4,{25:0xc4b7502a,27:0xc69c,24:0x1d41})
        if j:terminal_status(row,0x74c29dd3);terminal['unlink',j]=row
        else:pending(row,R.ONCE,'libSystem/_pthread_once',0x8489,[R.API.ONCE_CELL,R.API.CALLBACK],0x680005fe80)
        model['unlink_return_partitions_checked']+=1
    assert [x['synchronization_return32'] for x in c['synchronization_cases']]==[0,35]
    for si,sync in enumerate(c['synchronization_cases']):
        before=unlinks[0];rows=[];assert len(sync['returns'])==4
        for j,(pc,x) in enumerate(zip([R.ONCE,R.WRLOCK,R.ONCE2,R.UNLOCK],sync['returns'])):
            ev=x['API_return_premise'];assert ev['call_site']==hex(pc) and ev['effect_kind']=='sync' and int(ev['return32'],16)==sync['synchronization_return32']
            assert ev['invalidated_spans']==[{'address':hex(R.API.ONCE_CELL if j%2==0 else R.L),'size_bytes':16 if j%2==0 else 200}]
            assert ev['once_completion_without_additional_callback_effects_premise']==(j%2==0)
            before=ret(before,x);rows.append(before)
        pending(rows[0],R.WRLOCK,'libSystem/_pthread_rwlock_wrlock',0x4c4d,[R.L],0x680005fe80)
        pending(rows[1],R.ONCE2,'libSystem/_pthread_once',0x8489,[R.API.ONCE_CELL,R.API.CALLBACK],0x680005fe80)
        pending(rows[2],R.UNLOCK,'libSystem/_pthread_rwlock_unlock',0x5431,[R.L],0x680005fe80)
        terminal_status(rows[3],0x8b3dc651);terminal['sync',si]=rows[3]
        writes=[w for row in rows for w in row['source_writes'] if Common.overlap(w,R.B,74)]
        assert [(w['pc'],w['address'],w['size_bytes'],w['after_hex']) for w in writes]==[('0x100628a28',hex(R.B+8),8,'00'*8),('0x100628a28',hex(R.B+16),8,'00'*8)]
        for row in rows:assert not any(Common.overlap(x,R.L,200) or Common.overlap(x,R.API.ONCE_CELL,16) for x in row['source_reads']+row['source_writes'])
        model.update(SIDN_lock_pointer_pairs_checked=1,SIDN_zero_store_bytes_checked=16)
    assert len(terminal)==len(c['buffer_frees'])==12 and {(x['origin_kind'],x['origin_index']) for x in c['buffer_frees']}==set(terminal)
    frees=[]
    for x in c['buffer_frees']:
        before=terminal[x['origin_kind'],x['origin_index']];row=R.unpack(x['interval_packed']);model.update(external_join(before,row,x['API_return_premise'],'buffer_free'));frees.append(row)
        pending(row,R.MALLOC,'libSystem/_malloc',0x6aa4,[64],0x6800060100)
        assert [(w['address'],w['after_hex']) for w in Common.select(row,0x100689e0c)]==[('0x68000659b4','be9dc274')]
        assert not any(Common.overlap(r,0x6800070dc8,4) for r in row['source_reads'])
        assert [(x['pc'],x['target'],x['modifier']) for x in row['source_calls']]==[('0x1007106f0','0x100436378','0x58a3')]
        model.update(carried_status_stores_checked=1,common_64B_allocation_requests_checked=1)
    assert c['buffer_frees'][0]['origin_kind']=='mode' and c['buffer_frees'][0]['origin_index']==0
    assert [x['pointer_return64'] for x in c['allocation_cases']]==['0x0',hex(R.S)]
    for x in c['allocation_cases']:
        row=R.unpack(x['interval_packed']);model.update(external_join(frees[0],row,x['API_return_premise'],'container_allocation'));s=state_bytes(row);ptr=int(x['pointer_return64'],16)
        stored=Common.select(row,0x100710770);assert len(stored)==1 and (stored[0]['address'],stored[0]['after_hex'])==('0x68000627e0',struct.pack('<Q',(ptr+R.BIAS)&((1<<64)-1)).hex())
        if ptr:
            pending(row,R.NEXT_MALLOC,'libSystem/_malloc',0x6aa4,[21],0x6800060100)
            expected={R.S+j:b for j,b in enumerate(bytes(8)+struct.pack('<QQ',0x8b3cc6508b3ac658,0xda660f258b3dc650)+Common.raw(initial,R.J+0x1c,24))}
            expected.update({R.S+0x38+j:b for j,b in enumerate(bytes.fromhex('7f7db92100'))})
            assert {a:v for a,v in s.items() if R.S<=a<R.S+64}==expected and len(expected)==53
            assert [(v['pc'],v['target'],v['modifier']) for v in row['source_calls']]==[('0x1006c23b0','0x100413164','0x6240'),('0x100595f84','0x10046f89c','0x34a1')]
            assert row['source_calls'][1]['arguments8'][:3]==[hex(R.J+0x1c),hex(R.S+24),'0x18']
            copies=[w for w in row['source_writes'] if 0x10046f89c<=int(w['pc'],16)<0x10046fa90]
            assert len(copies)==24 and [int(w['address'],16) for w in copies]==list(range(R.S+24,R.S+48))
            assert bytes.fromhex(''.join(w['after_hex'] for w in copies))==Common.raw(initial,R.J+0x1c,24)
            assert not any(Common.overlap(w,R.J+0x68,8) for w in row['source_writes'])
            model.update(container_defined_bytes_checked=53,container_undefined_bytes_checked=11,context_to_container_copy_bytes_checked=24,pending_21B_allocation_requests_checked=1)
        else:
            pending(row,R.NEXT_ERROR,'libSystem/___error',0x6e96,sp=0x680005feb0)
            writes=[w for w in row['source_writes'] if Common.overlap(w,R.J+0x68,8)]
            assert len(writes)==1 and (writes[0]['pc'],writes[0]['address'],writes[0]['size_bytes'],writes[0]['after_hex'])==('0x100901498',hex(R.J+0x68),8,struct.pack('<Q',R.BIAS).hex())
            assert [(v['pc'],v['target'],v['modifier']) for v in row['source_calls']]==[('0x1006965b0','0x10042f208','0x6aa4'),('0x10042f4b8','0x100618fdc','0xe200'),('0x100619234','0x1006176f8','0x11d8')]
            assert row['boundary']['registers31'][20]==hex(R.B) and not any(R.S+j in s for j in range(64))
            model['encoded_NULL_context_publications_checked']+=1
    for row in R.context_intervals(c):
        s=state_bytes(row)
        assert not any(Common.overlap(x,R.A,R.N) for x in row['source_reads']+row['source_writes'])
        if {'address':hex(R.A),'size_bytes':R.N} not in row['foreign_owners']:assert not any(R.A+j in s for j in range(R.N))
        assert Common.raw(s,R.J+0x34,32)==Common.raw(initial,R.J+0x34,32)
        model['generated_stream_and_no_buffer_dereference_intervals_checked']+=1
    return {'model_checks':dict(model),'all_checks_pass':True}

def obligations():
    out=Local.obligations()
    def prove(label,bad):
        s=z3.Solver();s.set(timeout=30000);assert s.check()==z3.sat;s.add(z3.simplify(bad));assert s.check()==z3.unsat,label
        out.append({'label':label,'query':s.to_smt2(),'premises_nonvacuous':True,'result':'unsat'})
    ptr,sp,ctx,src=z3.BitVecs('container_pointer64 container_SP64 container_context64 container_source64',64)
    status=z3.BitVec('container_carried_status32',32);base=0x70000000
    v=Algebra();v.seed('x0',ptr);v.seed('sp',sp);v.run_block(R.MALLOC+4,0x100710774)
    prove('all_pointer_bits_original_allocator_encoding',cell(v,sp+0x26e0,8)!=ptr+R.BIAS)
    v=Algebra();v.seed('x0',base);mem(v,base+8,8,ptr+R.BIAS);v.run_block(0x100413164,0x1004131f8)
    prove('all_pointer_bits_original_initializer_decode_and_scalar_prefix',z3.Or(cell(v,ptr,8)!=0,cell(v,ptr+8,8)!=0x8b3dc6518b3dc651,
          cell(v,ptr+16,4)!=0x8b3dc651,cell(v,ptr+20,8)!=0x08d8a8d9))
    v=Algebra();v.seed('x8',ptr+R.BIAS);v.run_block(0x100413200,0x100413250)
    prove('all_pointer_bits_original_initializer_scalar_suffix',z3.Or(cell(v,ptr+44,4)!=0,cell(v,ptr+56,4)!=0x21b97d7f,cell(v,ptr+60,1)!=0))
    v=Algebra();v.seed('x20',ptr);v.run_block(0x1006c23b4,0x1006c23bc)
    prove('all_pointer_bits_original_post_initializer_zero_stores',z3.Or(cell(v,ptr,8)!=0,cell(v,ptr+24,4)!=0))
    v=Algebra();v.seed('sp',base);mem(v,base+0x26e0,8,ptr+R.BIAS);v.run_block(0x100595edc,0x100595f08)
    prove('all_pointer_bits_original_nonnull_field16',cell(v,ptr+16,8)!=0xda660f258b3dc650)
    v=Algebra();v.seed('x22',ptr+R.BIAS);v.run_block(0x100595fac,0x100595fec)
    prove('all_pointer_bits_original_nonnull_field8_and_byte60',z3.Or(cell(v,ptr+8,8)!=0x8b3cc6508b3ac658,cell(v,ptr+60,1)!=0))
    v=Algebra();v.seed('x20',ptr+R.BIAS);v.seed('x11',ctx+0x68);v.run_block(0x100901498,0x10090149c)
    prove('all_pointer_bits_original_context_slot_store',cell(v,ctx+0x68,8)!=ptr+R.BIAS)
    v=Algebra();v.seed('sp',sp);v.seed('w22',status);v.run_block(0x100689e08,0x100689e10)
    prove('all_status_bits_original_carried_status_store',cell(v,sp+0x58b4,4)!=status)
    v=Algebra();v.seed('sp',base);mem(v,base+0x1f08,8,ptr);v.run_block(0x10074aa04,0x10074aa08)
    prove('all_pointer_bits_original_free_argument',v.read('x0')!=ptr)
    v=Algebra();v.run_block(0x100595f08,0x100595f18);v.seed('x22',ptr+R.BIAS);v.seed('x20',src);v.run_block(0x100595f74,0x100595f84)
    prove('all_pointer_bits_original_24B_copy_request',z3.Or(v.read('x0')!=src,v.read('x1')!=ptr+24,v.read('w2')!=24,v.read('x17')!=0x34a1))
    from audit_daemon_environment_outputs import DEC
    left,right=z3.BitVecs('container_ADC_left32 container_ADC_right32',32);carry=z3.Bool('container_ADC_carry')
    for pc,(dest,lhs,rhs) in ADC.items():
        v=Algebra();v.seed(lhs,left);v.seed(rhs,right);v.carry=carry
        a=z3.BitVecVal(0,32) if lhs=='wzr' else left
        adc32(v,next(DEC.disasm(IMAGE.read(pc,4),pc)))
        expected=z3.Extract(31,0,z3.ZeroExt(32,a)+z3.ZeroExt(32,right)+z3.If(carry,z3.BitVecVal(1,64),z3.BitVecVal(0,64)))
        prove('all_u32_carry_bits_original_ADC_'+hex(pc),z3.Or(v.read(dest)!=expected,v.carry!=carry))
    return out

def build():
    e=json.loads(read(ROOT/(R.P+'_checks.json')));p=json.loads(read(ROOT/(R.Parent.P+'_checks.json')))
    assert e['generator_sha256']==sha(R.__file__) and e['dependencies']=={n:sha(ROOT/n) for n in R.DEPS}
    contexts=[];total=Counter();model=Counter()
    for j,c in enumerate(e['contexts']):
        parent=p['contexts'][c['parent_context_index']];item=parent['SIDN_queries'][c['parent_SIDN_query_index']];lifts=[]
        for row in R.context_intervals(c):
            lift=Lift(row).run();assert lift['all_checks_pass'];lifts.append(lift);total.update(lift['verified_counts'])
        ct=contract(c,parent,item);model.update(ct['model_checks']);contexts.append({'independent_lifts':lifts,'contract':ct,'all_checks_pass':True})
        if j%4==0:print(json.dumps({'context':j,'source_visits':total['source_visits']}),flush=True)
    qs=obligations();assert e['SDK_checks']==R.sdk_checks()
    return {'scope':__doc__,'generator_sha256':sha(R.__file__),'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),
            'source_sha256':sha(SOURCE),'dependencies':e['dependencies'],'auditor_dependencies':{n:sha(ROOT/n) for n in AD},
            'verified_counts':e['verified_counts'],'contexts':contexts,'independent_totals':dict(total),'model_checks':dict(model),
            'source_proofs':qs,'source_queries_unsat':len(qs),'all_checks_pass':True,
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'native_epoch_join_established':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps({'independent':e['independent_totals'],'model':e['model_checks'],'queries':e['source_queries_unsat']}),flush=True)
