#!/usr/bin/env python3
"""Independent cold-client replay, certificate/transport and branch oracles.

Does not import the new producer. Reconstructs initial RAM and independently
checks every client CPU/data/API/PAC transition. Frozen daemon replay checks
original metadata rejection, not full daemon RAM or native message delivery.
O(C*(B+F+V+J+R)) time/space; 30000 client visits and 30 s per SMT query.
"""
import copy,json,struct,subprocess
from pathlib import Path
from hashlib import sha256
from collections import Counter
import z3
from unicorn import arm64_const as A
from audit_corefp_lookup_release import Replay as Frozen,parent_inputs,ENTRY,PARENT,CURSOR,DONE,HEAP,M64
from audit_corefp_lookup_initialization import initial_page,declared_inputs,frame,restore,ret,unpack,CS
from corefp_fixups_reader import Pointers,ROOT,THIN_SHA
from probe_corefp_exports import BASE,BIND
from daemon_receive_tools import SOURCE,IMAGE,verify_original_fixups
from verify_daemon_reader_record_payloads_publication import read

SHA=lambda b:sha256(b).hexdigest();CERT=HEAP+0x400


def extra_inputs():return [(BIND+175*16,bytes.fromhex('0000000001000000')),(BIND+82*16,(0x1717).to_bytes(4,'little'))]


class Replay(Frozen):
    def __init__(self,p,spans,s):
        super().__init__(p,spans,s);self.ce=self.tx=0;self.cert_live=False
    def code(self,u,pc,n,d):
        self.flush();cfg=self.p['configuration'];name=self.imports.get(pc);call=u.reg_read(A.UC_ARM64_REG_LR)-4-BASE
        if pc==BASE+0x8ea868:
            assert cfg.get('continue_atomic_to_entropy')and self.tx==0
            raw=self.ram(pc,4);assert raw.hex()=='8bfde888'
            assert self.p['visits'][self.v]=={'pc':'0x8ea868','bytes_hex':raw.hex(),'instruction':'casal w8, w11, [x12]'};self.v+=1
            pointer=u.reg_read(A.UC_ARM64_REG_X12);old=int.from_bytes(self.ram(pointer,4),'little');compare=u.reg_read(A.UC_ARM64_REG_W8);new=u.reg_read(A.UC_ARM64_REG_W11)
            assert pointer==BASE+0x1d33108 and old==compare==0x5d96 and new==0xa94ef
            e=self.event();assert {k:e[k]for k in ['kind','visit','pointer','old_u32','compare_u32','replacement_u32','concurrent_ordering_validated']}=={
              'kind':'declared_sequential_CASAL','visit':self.v-1,'pointer':hex(pointer),'old_u32':old,'compare_u32':compare,'replacement_u32':new,'concurrent_ordering_validated':False}
            self.effects(e,[(pointer,new.to_bytes(4,'little'))]);f=copy.deepcopy(e['before']);f['X31'][8]=hex(old);f['PC']=hex(pc+4);assert e['after']==f;restore(u,f);return
        if name=='_arc4random':
            assert cfg.get('continue_atomic_to_entropy')and self.tx==0 and not self.cert_live
            assert self.p['frontier']=={'reason':'before_fallback_entropy','CPU':frame(u),'callsite':'0x8eb800','name':name,
              'token4_hex':self.ram(BASE+0x1d33108,4).hex(),'held_lock_model':hex(self.held)}
            assert call==0x8eb800 and self.p['parent_return']is None;self.done=True;u.emu_stop();return
        own=(name=='_malloc'and call==0x249368)or name=='_free'or(name=='_mach_msg'and u.reg_read(A.UC_ARM64_REG_X2)==64)
        builder=name in ['_mig_get_reply_port','_voucher_mach_msg_set','_mig_put_reply_port','_mig_dealloc_reply_port']and call in [0x8b50,0x8b80,0x8bdc,0x8c2c]
        if own or builder:
            args=[u.reg_read(getattr(A,'UC_ARM64_REG_X'+str(j)))for j in range(8)];e=self.event();writes=[];value=0
            assert e['kind']=='declared_API'and e['name']==name and e['callsite']==hex(call)and e['args_x0_x7']==list(map(hex,args))
            if name=='_malloc':
                assert args[0]==760 and self.cert==0;self.cert+=1;self.cert_live=True;value=CERT;writes=[(CERT,b'\xa5'*760)]
                want={'kind':'declared_allocate','CPU':frame(u),'pointer':hex(CERT),'size_B':760,'callsite':hex(call)}
                assert want==self.p['certificate_events'][self.ce];self.ce+=1
            elif name=='_free':
                assert self.cert_live and args[0]==CERT and call==0x8e9fa8;self.cert_live=False
                want={'kind':'declared_free','CPU':frame(u),'pointer':hex(CERT),'size_B':760,'callsite':hex(call),'allocation760_hex_at_free':self.ram(CERT,760).hex(),
                  'model':'mark private allocation inactive; retain mapped bytes for evidence; no native free'}
                assert want==self.p['certificate_events'][self.ce];self.ce+=1
            elif name=='_mach_msg':
                assert args[1:7]==[3,64,220,0x5173,0,0]and call==0x8ba8 and self.tx==0 and not self.cert_live
                wire=self.ram(args[0],64);pointer=struct.unpack_from('<Q',wire,28)[0];size=struct.unpack_from('<I',wire,40)[0];assert size==756
                value=cfg['request1200_status_u32'];assert value!=0 and e['transaction_index']==0
                want={'CPU':frame(u),'message_address':hex(args[0]),'request64_hex':wire.hex(),'OOL_address':hex(pointer),'OOL_size_B':size,
                  'OOL756_hex':self.ram(pointer,size).hex(),'callsite':hex(call),'status_u32':value,'held_lock_model':hex(self.held),'native_message_emitted':False}
                assert want==self.p['transactions'][self.tx];self.tx+=1
            elif name=='_mig_get_reply_port':assert call==0x8b50;value=0x5173
            elif name=='_voucher_mach_msg_set':assert call==0x8b80
            elif name=='_mig_put_reply_port':assert call==0x8bdc and args[0]==0x5173
            else:assert name=='_mig_dealloc_reply_port'and call==0x8c2c and args[0]==0x5173
            self.effects(e,writes);assert e['return_u64']==hex(value);f=ret(e['before'],value,cfg.get('clobber_callers',False));assert e['after']==f;restore(u,f);return
        return super().code(u,pc,n,d)
    def run(self):
        result=super().run();assert self.ce==len(self.p['certificate_events'])==2 and self.tx==len(self.p['transactions'])and not self.cert_live
        result['parent_returns_checked']=int(self.p['parent_return']is not None)
        return {**result,'transactions_checked':self.tx,'certificate_events_checked':self.ce,'fallback_entropy_frontiers_checked':int(self.p['parent_return']is None)}


def oracle(p,s):
    c=p['configuration'];label=c['label'];fallback=label=='fallback_entropy_frontier';other=label=='primary_other_error';static=label=='static_invalid_dest'
    expected={'label':label,'allocation_success':[not static,True],'lock_init_status_u32':[0,0],'continue_to_bootstrap':True,
      'bootstrap_results':[{'status_u32':1102},{'status_u32':0,'write_port_u32':0x5034}]if fallback else [{'status_u32':0,'write_port_u32':0x5017}],
      'unlock_status_u32':5 if label=='unlock_error'else 0,**({'continue_atomic_to_entropy':True}if fallback else {'request1200_status_u32':0x10000004 if other else 0x10000003}),
      **({'clobber_callers':True}if label=='clobber_invalid_dest'else {})};assert c==expected
    entry,lookup=p['handoffs'][:2];assert [v['label']for v in p['handoffs'][:2]]==['source_lookup_entry','source_lookup_return']
    raw=bytes.fromhex(entry['lookup_record32_hex']);r=int(entry['lookup_record'],16);key=((r&0xffffffff)^0x8b4ea7c9)*0x0bcb7857&0xffffffff
    assert (int.from_bytes(raw[28:],'little')-key)&0xffffffff==0xba27 and (raw[24]-key)&255==9
    assert lookup['lookup_output_words']==([0x5034,0]if fallback else [0x5017,10])and lookup['lookup_record32_hex'][:8]=='dbf91dba'
    rows=[x for x in p['reads']if p['visits'][x['visit']]['pc']=='0x8ea058'];assert len(rows)==1
    assert rows[0]['address']=='0x62016628'and rows[0]['size_B']==4 and int.from_bytes(bytes.fromhex(rows[0]['bytes_hex']),'little')==(0 if fallback else 10)
    branch=[x for x in p['PAC_models']if x['pc']=='0x8ea0b0'];assert len(branch)==1;branch=branch[0]
    assert int(branch['CPU']['X31'][27],16)&0xffffffff==0xc1f7 and branch['target']==hex(BASE+(0x8ea19c if fallback else 0x8ea0b4))
    assert p['reads'][branch['load_index']]['address']==hex(BASE+(0x1cc99f0 if fallback else 0x1cc99c8))
    container=bytes(b^0xba for b in s.read(0x185c226,760));assert container[:4].hex()=='01000007'
    der=(ROOT/'corefp_fppineboard_certificate.der').read_bytes();assert container[4:]==der and SHA(der)=='a0caace76b0db1214f92e89225458e5040d3b92837c03270274ea1a1b359e2de'
    assert bytes.fromhex(p['certificate_events'][1]['allocation760_hex_at_free'])==container[4:]+container[-4:]
    models=p['models'];names=[x.get('name')for x in models];pointer=BASE+0x1d27bf0 if static else HEAP
    assert p['final_state']['primary_u32']==(0x5034 if fallback else 0x5017)and p['final_state']['secondary_u32']==0
    assert '_mach_port_deallocate'not in names and names.count('_free')==1 and p['certificate_allocation_attempts']==1
    task_cell=BIND+82*16;assert not any(int(x['address'],16)<task_cell+4 and task_cell<int(x['address'],16)+x['size_B']for x in p['reads']+p['writes'])
    advances=[x for x in p['writes']if int(x['address'],16)<=CURSOR<int(x['address'],16)+x['size_B']]
    assert len(advances)==1 and advances[0]['address']==hex(CURSOR)and advances[0]['size_B']==8 and advances[0]['before_hex']=='00'*8 and advances[0]['after_hex']=='0001000000000000'
    assert p['visits'][advances[0]['visit']]['pc']=='0x8e830c'and advances[0]['visit']<entry['visits_so_far']
    assert names.count('_pthread_once')==(2 if fallback else 3)and names.count('_pthread_rwlock_wrlock')==1
    assert len(p['lock_events'])==(1 if fallback else 2)and all(x['pointer']==hex(pointer)for x in p['lock_events'])
    if fallback:
        assert len(p['handoffs'])==2 and len(p['transactions'])==len(p['metadata_returns'])==len(p['daemon_children'])==0 and p['parent_return']is None
        assert not any(0x8ae0<=int(v['pc'],16)<0x8d40 for v in p['visits'])and names.count('_pthread_rwlock_unlock')==0
        assert sum(x['kind']=='declared_sequential_CASAL'for x in models)==1 and '_arc4random'not in names
        assert p['frontier']['token4_hex']=='965d0000'and p['frontier']['held_lock_model']==hex(HEAP)
        stores=[x for x in p['writes']if int(x['address'],16)==BASE+0x1d33108]
        assert len(stores)==1 and p['visits'][stores[0]['visit']]['pc']=='0x8eb7a8'and stores[0]['before_hex']=='ef940a00'and stores[0]['after_hex']=='965d0000'
        marker=None;cleanup=None
    else:
        assert len(p['transactions'])==len(p['metadata_returns'])==len(p['daemon_children'])==1 and len(p['handoffs'])==4
        tx=p['transactions'][0];wire=bytes.fromhex(tx['request64_hex']);assert len(wire)==64
        expected_words={0:0x80001513,8:0x5017,12:0x5173,16:0,20:1200,24:1,36:0x01000100,40:756,52:2,56:2,60:756}
        for off,value in expected_words.items():assert struct.unpack_from('<I',wire,off)[0]==value
        assert wire[44:52]==bytes.fromhex('0000000001000000')and tx['OOL_address']=='0x62016b50'and struct.unpack_from('<Q',wire,28)[0]==0x62016b50
        assert tx['OOL_address']!=hex(CERT)and bytes.fromhex(tx['OOL756_hex'])==der and not tx['native_message_emitted']
        marker=0x45e2a043 if other else 0x45e2a2e3;before=parent_inputs()[0][1]
        assert p['parent_return']['parent_record48_hex']==(marker.to_bytes(4,'little')+before[4:]).hex()and p['parent_return']['cursor_u64']=='0x100'
        assert p['parent_return']['CPU']['X31'][0]==hex(c['unlock_status_u32'])and p['parent_return']['CPU']['SP']==p['initial_CPU']['SP']
        assert p['parent_return']['CPU']['X31'][19:31]==p['initial_CPU']['X31'][19:31]
        assert p['parent_return']['held_lock_model']==(hex(pointer)if c['unlock_status_u32']else None)
        assert names.count('_pthread_rwlock_unlock')==1
        cleanup=[x for x in models if x.get('callsite')in ['0x8bdc','0x8c2c']];assert len(cleanup)==1 and cleanup[0]['name']==('_mig_dealloc_reply_port'if other else '_mig_put_reply_port')
        cleanup=cleanup[0]['name'];assert not any(x['kind']=='declared_sequential_CASAL'for x in models)
    return {'label':label,'lookup_flags_u32':0 if fallback else 10,'request1200_transactions':len(p['transactions']),'certificate_container_B':760,
      'certificate_DER_B':756,'DER_sha256':SHA(der),'raw_parent_record_result_u32':None if marker is None else hex(marker),
      'reply_port_cleanup':cleanup,'cached_name_retained_u32':hex(p['final_state']['primary_u32']),'parent_returned':not fallback,
      'lock_released_by_model':not fallback and c['unlock_status_u32']==0,'native_transport_or_ownership_established':False}


def source_checks(s):
    exact={0x8ea020:('mov','w8, #0x51e6'),0x8ea024:('eor','w8, w27, w8'),0x8ea028:('mov','w9, #0x37ee'),0x8ea02c:('movk','w9, #0x562a, lsl #16'),
      0x8ea030:('add','w9, w8, w9'),0x8ea034:('mov','w10, #0xf9f7'),0x8ea038:('movk','w10, #0xa9d5, lsl #16'),0x8ea03c:('and','w9, w9, w10'),
      0x8ea040:('mov','w10, #0xd5de'),0x8ea044:('movk','w10, #0x94b9, lsl #16'),0x8ea048:('add','w10, w8, w10'),0x8ea04c:('mov','w11, #0xdb73'),
      0x8ea050:('movk','w11, #0x6b45, lsl #16'),0x8ea054:('and','w12, w10, w11'),0x8ea064:('add','w9, w12, w9'),0x8ea068:('mov','w11, #0xfcad'),
      0x8ea06c:('movk','w11, #0xfffe, lsl #16'),0x8ea070:('add','w9, w9, w11'),0x8bb0:('mov','w8, #0xfffe'),0x8bc4:('mov','w9, #1'),
      0x8ea058:('ldr','w10, [sp, #0x498]'),0x8ea05c:('tst','w10, #2'),0x8ea060:('cset','w10, eq'),0x8ea074:('mul','w9, w9, w10'),
      0x8ea078:('eor','w8, w9, w8'),0x8ea094:('ldr','x8, [x19, w8, sxtw #3]'),0x8ea0b0:('braa','x8, x17'),
      0x8bb4:('movk','w8, #0xefff, lsl #16'),0x8bb8:('add','w8, w0, w8'),0x8bbc:('cmp','w8, #0xe'),0x8bc0:('b.hi','#0x8be4'),
      0x8bc8:('lsl','w8, w9, w8'),0x8bcc:('mov','w9, #0x4003'),0x8bd0:('tst','w8, w9'),0x8bd4:('b.eq','#0x8be4'),
      0x8be4:('cbnz','w22, #0x8c28'),0x8ea868:('casal','w8, w11, [x12]')}
    for a,want in exact.items():i=next(CS.disasm(s.read(a,4),a));assert(i.mnemonic,i.op_str)==want,(hex(a),i.mnemonic,i.op_str,want)
    flags=z3.BitVec('lookup_flags32',32);u=0xc1f7^0x51e6;mix=(((u+0x562a37ee)&0xa9d5f9f7)+((u+0x94b9d5de)&0x6b45db73)+0xfffefcad)&0xffffffff
    index=z3.BitVecVal(u,32)^(z3.BitVecVal(mix,32)*z3.If(flags&2==0,z3.BitVecVal(1,32),z3.BitVecVal(0,32)))
    status=z3.BitVec('mach_msg_status32',32);delta=status+0xeffffffe
    put=z3.And(z3.ULE(delta,14),((z3.BitVecVal(1,32)<<(delta&31))&0x4003)!=0)
    queries=[('flags_bit1_dispatch',index,z3.If(flags&2!=0,z3.BitVecVal(u,32),z3.BitVecVal(u^mix,32))),
      ('reply_port_put_selector',put,z3.Or(*[status==v for v in [0x10000002,0x10000003,0x10000010]]))]
    proofs=[]
    for label,left,right in queries:
        sol=z3.Solver();sol.set(timeout=30000);sol.add(left!=right);assert sol.check()==z3.unsat;proofs.append({'label':label,'query':sol.to_smt2(),'result':'unsat'})
    references=[]
    for idx,slot,target in [(u,0x1cc99c8,0x8ea0b4),(u^mix,0x1cc99f0,0x8ea19c)]:
        signed=idx if idx<1<<31 else idx-(1<<32);assert 0x1c81940+signed*8==slot
        row=s.decoded[slot];assert not row['bind']and row['authenticated']and row['target']==hex(target)and row['key']=='IA'and int(row['diversity'],16)==0x89ab
        references.append({'index_u32':hex(idx),'slot':hex(slot),'row':row})
    code='#include <mach/mach.h>\n_Static_assert(MACH_SEND_INVALID_DEST==0x10000003,"invalid_destination");\n_Static_assert(MACH_SEND_TIMED_OUT==0x10000004,"send_timeout");\n_Static_assert(sizeof(mach_msg_header_t)==24,"header24");\n_Static_assert(sizeof(mach_msg_ool_descriptor_t)==16,"OOL16");\n'
    command=['xcrun','clang','-target','arm64e-apple-macos14','-fsyntax-only','-x','c','-'];r=subprocess.run(command,input=code,text=True,capture_output=True,timeout=30);assert r.returncode==0,r.stderr
    sdk=Path(subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip());raw=(sdk/'usr/include/mach/message.h').read_bytes()
    header=IMAGE.read(0x101038040,32);assert struct.unpack_from('<3I',header,8)==(1200,1205,212)
    fixups=verify_original_fixups([0x101038040,0x101038068]);assert [v['decoded_target']for v in fixups['records']]==['0x1000044fc','0x100004530']
    return {'proofs':proofs,'exact_instructions_checked':len(exact),'dispatch_reference_rows':references,'ABI_compile':{'command':command,'source':code,'exit_code':0,
      'stderr':r.stderr,'emitted_artifact':False,'header':{'SDK_relative_header':'usr/include/mach/message.h','size_B':len(raw),'sha256':SHA(raw)}},
      'daemon_catalog':{'address':'0x101038040','header32_hex':header.hex(),'start_id':1200,'end_id_exclusive':1205,'declared_max_reply_B':212,
        'client_receive_capacity_B':220,'capacity_difference_B':8,'difference_semantics':'unknown','used_fixups':fixups,'request1200_delivered':False}}


def main():
    e=json.loads(read(ROOT/'corefp_request1200_failure_checks.json'));s=Pointers();assert e['thin_sha256']==THIN_SHA and e['daemon_thin_sha256']==SHA(SOURCE.read_bytes())
    assert e['generator_sha256']==SHA((ROOT/'recover_corefp_request1200_failure.py').read_bytes())
    for n,h in e['dependencies'].items():assert SHA(read(ROOT/n).encode())==h
    assert e['declared_inputs']==[{'address':hex(a),'bytes_hex':b.hex()}for a,b in declared_inputs()+parent_inputs()+extra_inputs()]
    auth=next(r for r in s.meta['sections']if r['section']=='__auth_stubs')
    for f in e['source_spans']:
        a,b=int(f['start'],16),int(f['end'],16)
        if 'kind'in f:assert f['kind']=='complete_import_stub_16B'and b-a==16 and(a-auth['address'])%16==0 and auth['address']<=a<b<=auth['address']+auth['size']and f['bytes']==s.read(a,16).hex()and f['sha256']==SHA(s.read(a,16))
        else:assert f==s.function(a)
    totals=Counter();oracles=[];assert [p['configuration']['label']for p in e['profiles']]==['primary_invalid_dest','primary_other_error','fallback_entropy_frontier','static_invalid_dest','clobber_invalid_dest','unlock_error']
    for p in e['profiles']:
        cpu={'X31':[hex(((j+1)*0x123456789abcdef)&M64)for j in range(31)],'Q32':[hex(int.from_bytes(bytes([j])*16,'little'))for j in range(32)],
          'SP':'0x62018000','PC':hex(BASE+ENTRY),'NZCV':'0x60000000','FPCR':'0x0','FPSR':'0x0','CPACR_EL1':'0x300000'}
        cpu['X31'][0]=hex(PARENT);cpu['X31'][1]=hex(CURSOR);cpu['X31'][30]=hex(DONE);assert p['initial_CPU']==cpu;totals['initial_CPU_frames_checked']+=1
        for row in p['initial_RAM']:
            a=int(row['address'],16);b=bytearray(initial_page(s,a))
            for addr,raw in parent_inputs()+extra_inputs():
                if a<=addr<addr+len(raw)<=a+4096:b[addr-a:addr-a+len(raw)]=raw
            assert unpack(row['payload'])==bytes(b);totals['initial_RAM_B_checked']+=4096
        replay=Replay(p,e['source_spans'],s);totals.update(replay.run());oracles.append(oracle(p,s))
    counts={'profiles':len(e['profiles']),**{k:sum(len(p[k])for p in e['profiles'])for k in ['visits','reads','writes','PAC_models','models','points','metadata_returns','daemon_children','handoffs','lock_events','transactions','certificate_events']},
      'bootstrap_calls':sum(p['bootstrap_calls']for p in e['profiles']),'certificate_allocation_attempts':sum(p['certificate_allocation_attempts']for p in e['profiles'])};assert counts==e['verified_counts']
    source=source_checks(s);d=json.loads(read(ROOT/'corefp_request1200_failure_ida.json'));live=[]
    assert not d['IDB_mutated']and not d['native_target_executed']and d['CoreFP_recall']['count']==0 and d['daemon_recall']['count']==2
    assert d['requests']=={'bytes':{'target':'c3d025e56a86','addresses':['0x8ae0','0x8ea830','0x249334'],'size':608},
      'CoreFP_recall':{'target':'c3d025e56a86','query':'1200','scope':'all','limit':12},'daemon_recall':{'target':'70f8437872ac','query':'1200','scope':'all','limit':12}}
    assert not d['CoreFP_recall']['truncated']and not d['daemon_recall']['truncated']
    for row in d['bytes']['results']:
        raw=bytes.fromhex(row['bytes']);assert raw==s.read(int(row['address'],16),len(raw))and len(raw)==row['size_read']==row['size_requested'];live.append({'address':row['address'],'size_B':len(raw),'sha256':SHA(raw)})
    result={'verified_counts':counts,'independent_client_replay':dict(totals),'compact_oracle_profiles':len(oracles),'client_source_spans':len(e['source_spans']),
      'client_source_B_checked':sum(len(bytes.fromhex(v['bytes']))for v in e['source_spans']),'live_B_checked':sum(v['size_B']for v in live),
      'daemon_source_visits_fresh_checked':sum(len(c['visited_original_instructions'])for p in e['profiles']for c in p['daemon_children']),
      'daemon_steps_including_return':sum(c['steps']for p in e['profiles']for c in p['daemon_children']),'queries_unsat':2,'exact_instructions_checked':source['exact_instructions_checked'],
      'ABI_compile_exit':0,'native_target_executed':False,'all_checks_pass':True}
    out={'result':result,'checks_sha256':SHA(read(ROOT/'corefp_request1200_failure_checks.json').encode()),'auditor_sha256':SHA(Path(__file__).read_bytes()),
      'IDA_readback_sha256':SHA(read(ROOT/'corefp_request1200_failure_ida.json').encode()),'dependencies':e['dependencies'],'oracles':oracles,'source_checks':source,
      'live_byte_ranges':live,'foreign_IDA_memories_used_as_leads_only':True,'semantic_annotations_used_as_proof':False,'full_daemon_CPU_RAM_replayed':False,
      'fresh_replay_completed':True,'process_exit_code':0}
    (ROOT/'corefp_request1200_failure_audit.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(result),flush=True)


if __name__=='__main__':main()
