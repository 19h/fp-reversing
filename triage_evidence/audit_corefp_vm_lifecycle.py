#!/usr/bin/env python3
"""Independent whole-caller VM/ingress/cleanup replay and byte oracles.

No import of the new producer. Initial CPU/RAM, every retained original
transition/access/API/PAC effect and final RAM are checked. Backing retention
and API statuses remain explicit private models, not native lifetime evidence.
Replay/enumeration O(C*(B+P*F+V*L+R+N)) time/space upper bound; SMT cost
separate, 30 s/query. 100000 visits/profile, N=4096 B.
"""
import json,struct
from pathlib import Path
from hashlib import sha256
from collections import Counter
import z3
from unicorn import arm64_const as A
from audit_corefp_ingress_callers import Replay as Frozen,caller_inputs,CS
from audit_corefp_lookup_release import parent_inputs,frame,restore,ret,unpack
from audit_corefp_lookup_initialization import initial_page,declared_inputs
from recover_fpsd1201_predicates import pack
from corefp_fixups_reader import Pointers,ROOT,THIN_SHA
from probe_corefp_exports import BASE
from daemon_receive_tools import SOURCE
from verify_daemon_reader_record_payloads_publication import read

SHA=lambda b:sha256(b).hexdigest();M32=(1<<32)-1;M64=(1<<64)-1
ENTRY=0x2e4280;META=0x64000800;VM=0x66000000;N=4096;DONE=0x65000000


class Replay(Frozen):
    def __init__(self,p,spans,s):
        super().__init__(p,spans,s);self.vi=self.vac=self.vdc=self.fc=self.biter=self.miter=0;self.ingress=self.root_record=None
    def vm_point(self,label):
        row={'label':label,'CPU':frame(self.u),'visits_so_far':self.v,'models_so_far':self.mi,'metadata32_hex':self.ram(META,32).hex()}
        if self.ingress is not None:
            row.update({'ingress_address':hex(self.ingress),'ingress48_hex':self.ram(self.ingress,48).hex()})
            holder=int.from_bytes(self.ram(self.ingress+24,8),'little');row['ingress_pointer24_holder_word']=hex(int.from_bytes(self.ram(holder,8),'little'))
        if self.root_record is not None:row.update({'root_record_address':hex(self.root_record),'root_record40_hex':self.ram(self.root_record,40).hex()})
        if self.vac and not self.p['configuration']['vm_status_u32']:row['VM4096']=pack(self.ram(VM,N))
        assert row==self.p['vm_points'][self.vi],(label,self.vi);self.vi+=1
    def code(self,u,pc,n,d):
        self.flush();at=pc-BASE;name=self.imports.get(pc);cfg=self.p['configuration']
        if at==0x2e490c:self.ingress=u.reg_read(A.UC_ARM64_REG_X0);self.vm_point('before_ingress_call')
        if at==0x5f48c0:self.root_record=u.reg_read(A.UC_ARM64_REG_X0);self.vm_point('before_root_adapter')
        points={0x8e81c8:'root_entry',0x5f48d8:'before_ingress_result_store',0x2e4910:'ingress_return',0x653c70:'cleanup_entry',
          0x1ca59c:'VM_allocator_return',0x1ca8bc:'before_VM_metadata_publish',0x1ca8d0:'VM_metadata_published',
          0x653edc:'before_buffer_overwrite',0x654024:'before_VM_deallocate',0x654034:'before_metadata_overwrite',0x6540ec:'before_free'}
        if at in points:self.vm_point(points[at])
        if at==0x653f0c:
            self.biter+=1
            if self.biter==1:self.vm_point('first_buffer_iteration')
        if at==0x654060:
            self.miter+=1
            if self.miter==1:self.vm_point('first_metadata_iteration')
        if name in ['_vm_allocate','_vm_deallocate','_free']:
            args=[u.reg_read(getattr(A,'UC_ARM64_REG_X'+str(j)))for j in range(8)];call=u.reg_read(A.UC_ARM64_REG_LR)-4-BASE;e=self.event();writes=[]
            assert e['kind']=='declared_API'and e['name']==name and e['callsite']==hex(call)and e['args_x0_x7']==list(map(hex,args))
            if name=='_vm_allocate':
                assert self.vac==0 and call==0x1ca598 and args[:4]==[cfg['task_port_u32'],0x62017d70,N,1];self.vac+=1;value=cfg['vm_status_u32']
                if value==0:writes=[(args[1],VM.to_bytes(8,'little'))]
            elif name=='_vm_deallocate':
                assert self.vdc==0 and call==0x654024 and args[:3]==[cfg['task_port_u32'],0 if cfg['vm_status_u32']else VM,0 if cfg['vm_status_u32']else N]
                self.vdc+=1;value=cfg['deallocate_status_u32']
            else:assert self.fc==0 and call==0x6540ec and args[0]==META;self.fc+=1;value=cfg['free_residual_X0_u64']
            self.effects(e,writes);assert e['return_u64']==hex(value);f=ret(e['before'],value,cfg.get('clobber_callers',False));assert e['after']==f;restore(u,f);return
        if pc==DONE:self.vm_point('outer_return')
        return super().code(u,pc,n,d)
    def run(self):
        self.u.emu_start(BASE+ENTRY,0,count=100001);self.flush();assert self.done and not self.once
        assert [self.v,self.r,self.w,self.pac,self.mi,self.pi,self.hi,self.li,self.mri,self.di,self.ci,self.mai,self.vi]==[
          len(self.p[k])for k in ['visits','reads','writes','PAC_models','models','points','handoffs','lock_events','metadata_returns','daemon_children','caller_points']]+[
          self.p['metadata_allocation_attempts'],len(self.p['vm_points'])]
        assert [self.vac,self.vdc,self.fc,self.biter,self.miter]==[self.p[k]for k in ['vm_allocate_calls','vm_deallocate_calls','free_calls','buffer_iterations','metadata_iterations']]
        assert self.vac==self.vdc==self.fc==1 and self.miter==32 and self.biter==(0 if self.p['configuration']['vm_status_u32']else N)
        assert self.allocs==self.p['allocations_attempted']==(0 if self.p['configuration']['vm_status_u32']else 2)
        assert self.bi==self.p['bootstrap_calls']and self.cert==self.p['certificate_allocation_attempts']and self.snapshot('frontier')==self.p['final_state']
        for row in self.p['final_RAM']:assert self.ram(int(row['address'],16),4096)==unpack(row['payload'])
        return {'visits_checked':self.v,'reads_checked':self.r,'writes_checked':self.w,'PAC_models_checked':self.pac,'models_checked':self.mi,
          'caller_points_checked':self.ci,'vm_points_checked':self.vi,'metadata_allocation_attempts_checked':self.mai,
          'buffer_iterations_checked':self.biter,'metadata_iterations_checked':self.miter,'final_RAM_B_checked':4096*len(self.p['final_RAM'])}


def patterned(seed,n):
    return bytes((((seed+n-1-i)^0xba)*(seed+n-1-i+17))&255 for i in range(n))


def oracle(p,r,s):
    c=p['configuration'];failed=bool(c['vm_status_u32']);lookup_error=c['label']=='lookup_error';pts={x['label']:x for x in p['vm_points']}
    status=0x45e2a2e3 if lookup_error else 0x45e2a20f
    final=p['frontier']['CPU'];assert p['frontier']['reason']=='parent_return'and final['SP']==p['initial_CPU']['SP']and final['X31'][19:31]==p['initial_CPU']['X31'][19:31]
    assert final['X31'][0]==hex(c['free_residual_X0_u64'])and r.ram(0x63000818,4)==status.to_bytes(4,'little')
    apis=[x for x in p['models']if x.get('name')in ['_vm_allocate','_vm_deallocate','_free']]
    assert [x['name']for x in apis]==['_vm_allocate','_vm_deallocate','_free']and p['metadata_allocation_attempts']==1
    # Allocator model writes only the output address on success; releases do not
    # unmap retained private backing or manufacture source stores.
    assert len(apis[0]['memory'])==int(not failed)and not apis[1]['memory']and not apis[2]['memory']
    cleanup=bytes.fromhex(pts['cleanup_entry']['metadata32_hex']);wipe_n=(int.from_bytes(cleanup[12:16],'little')-0x49741372)&M32
    release_n=(int.from_bytes(cleanup[8:12],'little')-0x49741372)&M32
    assert wipe_n==release_n==(0 if failed else N)and int.from_bytes(cleanup[:8],'little')==(0 if failed else VM)
    vmwrites=[x for x in p['writes']if p['visits'][x['visit']]['pc']=='0x653f1c'];assert len(vmwrites)==wipe_n
    if failed:assert not any(x['label']in ['root_entry','before_ingress_call','first_buffer_iteration']for x in p['vm_points'])
    else:
        point=pts['first_buffer_iteration'];seed=int(point['CPU']['X31'][11],16);assert seed==int(point['CPU']['SP'],16)+8
        assert int(point['CPU']['X31'][13],16)==seed+17 and point['CPU']['X31'][10]=='0x42a1'and point['CPU']['X31'][14]=='0xfff'
        want=patterned(seed,N);assert unpack(pts['before_VM_deallocate']['VM4096'])==r.ram(VM,N)==want
        assert [(int(x['address'],16),x['size_B'],x['after_hex'])for x in vmwrites]==[(VM+i,1,want[i:i+1].hex())for i in range(N-1,-1,-1)]
        ing=pts['before_ingress_call'];i=int(ing['ingress_address'],16);ib=bytes.fromhex(ing['ingress48_hex']);ki=(((i|0xfd215347)+0x02deacb8-(i|0x02deacb8))^0x2435fd1a)*0x08c5d407&M32
        assert i==0x62017f68 and (int.from_bytes(ib[:4],'little')+ki+0x513c5990)&M32==0xc1f7
        assert (int.from_bytes(ib[16:20],'little')-ki)&M32==0x2d2a8321 and (int.from_bytes(ib[20:24],'little')+ki)&M32==0x1f03fdec
        assert int.from_bytes(ib[8:16],'little')==META and int.from_bytes(ib[24:32],'little')==0x62017f58 and ing['ingress_pointer24_holder_word']=='0x0'
        root=pts['root_entry'];rr=int(root['root_record_address'],16);b=bytes.fromhex(root['root_record40_hex']);kr=((rr^0x84b771aed97ffe38)*0xfcf33521)&M32
        assert rr==0x62017ea0 and int.from_bytes(b[8:16],'little')==0x62017f58 and int.from_bytes(b[32:40],'little')==META
        assert (int.from_bytes(b[16:20],'little')+kr)&M32==0x0484c46a and (int.from_bytes(b[20:24],'little')-kr)&M32==0xc1f7
        assert int.from_bytes(b[24:28],'little')^kr==0x114e4318
        staged=unpack(ing['VM4096']);prefix=bytearray.fromhex('9ae57a32bababab600a74361babababad9bab6ba')
        assert c['entry_scalar_u32']in [0,16]
        if c['entry_scalar_u32']==16:prefix[11]=0x71
        prefix=bytes(prefix)
        assert staged==prefix+bytes(N-20)
        initial_writes=[x for x in p['writes']if VM<=int(x['address'],16)<VM+N and x['visit']<ing['visits_so_far']]
        assert [(int(x['address'],16)-VM,x['size_B'],x['after_hex'])for x in initial_writes]==[(j,1,prefix[j:j+1].hex())for j in range(20)]
        if c.get('payload_pattern'):assert not any(0x63000c00<=int(x['address'],16)<0x63000c80 for x in p['reads'])
        returned=bytes.fromhex(pts['ingress_return']['ingress48_hex']);assert int.from_bytes(returned[32:36],'little')==status
        assert pts['before_ingress_result_store']['CPU']['X31'][8]==hex(status)
        assert [x['pointer_row']['address']for x in p['PAC_models']if x['pc']in ['0x2e490c','0x5f48c0','0x8fd1b8']]==['0x1d03c60','0x1d04e20','0x1d05150']
    m=pts['first_metadata_iteration'];mseed=int(m['CPU']['X31'][9],16);assert mseed==int(m['CPU']['SP'],16)+16
    mwant=patterned(mseed,32);assert bytes.fromhex(pts['before_free']['metadata32_hex'])==r.ram(META,32)==mwant
    mwrites=[x for x in p['writes']if p['visits'][x['visit']]['pc']=='0x654070'];assert len(mwrites)==32
    assert [(int(x['address'],16),x['size_B'],x['after_hex'])for x in mwrites]==[(META+i,1,mwant[i:i+1].hex())for i in range(31,-1,-1)]
    assert max(x['visit']for x in mwrites)<next(x['visit']for x in p['PAC_models']if x['pc']=='0x6540ec')
    assert p['bootstrap_calls']==int(not failed)and len(p['daemon_children'])==int(not failed and not lookup_error)
    assert p['certificate_allocation_attempts']==int(not failed and not lookup_error)and len(p['lock_events'])==2*int(not failed)
    result={'label':c['label'],'VM_status_u32':hex(c['vm_status_u32']),'VM_deallocate_status_u32':hex(c['deallocate_status_u32']),
      'VM_overwrite_B':wipe_n,'VM_deallocate_requested_B':release_n,'metadata_overwrite_B':32,'metadata_seed_u64':hex(mseed),
      'metadata_pattern_sha256':SHA(mwant),'caller_result_u32':hex(status),'residual_X0_u64':hex(c['free_residual_X0_u64']),
      'coherent_ingress_reached':not failed,'root_record_patched':False,'native_lifetime_established':False,'retained_private_backing':True}
    if not failed:result.update({'root_record':'0x62017ea0','root_mode_u32':'0x114e4318','root_field16_u32':'0x484c46a','root_operation_u32':'0xc1f7',
      'VM_pattern_sha256':SHA(want),'VM_pattern_seed_u64':hex(seed),'metadata_span_word_minus_bias_u32':hex((int.from_bytes(cleanup[16:20],'little')-0x574de777)&M32)})
    if not failed:result.update({'source_staged_VM_prefix20_hex':prefix.hex(),'staged_VM_prefix_B':20,'AUX_pattern_reads':0 if c.get('payload_pattern')else None})
    return result


def source_checks(s):
    proofs=[]
    def prove(label,left,right):
        sol=z3.Solver();sol.set(timeout=30000);sol.add(left!=right);res=sol.check();assert res==z3.unsat,(label,res)
        proofs.append({'label':label,'query':sol.to_smt2(),'result':'unsat'})
    q=z3.BitVec('loop_seed64',64);i=z3.BitVec('iteration64',64);low=lambda v:z3.Extract(31,0,v)
    vm_byte=z3.Extract(7,0,low(q+i+17)*(low(q+i)^0xba));meta_byte=z3.Extract(7,0,(low(q+i)^0xba)*low(q+i+17))
    g=lambda v:(z3.Extract(7,0,v)^0xba)*(z3.Extract(7,0,v)+17)
    prove('VM_loop_byte_all_seed_iteration',vm_byte,g(q+i));prove('metadata_loop_byte_all_seed_iteration',meta_byte,g(q+i))
    prove('both_loops_same_byte_function',vm_byte,meta_byte);prove('pattern_period_256',g(q+256),g(q))
    word=z3.BitVec('descriptor_word32',32)
    prove('overwrite_extent_decode_all32',word+0xb68bec8e,word-0x49741372)
    prove('release_extent_at_phase37da_all32',word+0xb68bb4b4+0x37da,word-0x49741372)
    count,index,base=z3.BitVecs('count64 index64 buffer_base64',64)
    prove('descending_store_address',base+(count-1-index),(base+count)-1-index)
    prove('loop_seed_increment',q+(i+1),(q+i)+1)
    exact={0x653ea0:('ldr','x1, [x20]'),0x653ea4:('ldr','w13, [x20, #0xc]'),0x653eac:('movk','w14, #0xb68b, lsl #16'),
      0x653eb0:('adds','w14, w13, w14'),0x653edc:('add','x11, sp, #8'),0x653ee4:('add','x12, x11, w10, uxtw'),
      0x653ee8:('mov','x13, #-0x4290'),0x653eec:('add','x13, x12, x13'),0x653ef0:('sub','x14, x14, #1'),
      0x653efc:('mov','w15, #0xba'),0x653f0c:('str','x14, [sp, #8]'),0x653f10:('eor','w17, w11, w15'),
      0x653f14:('mul','w17, w13, w17'),0x653f18:('add','x0, x1, x14'),0x653f1c:('strb','w17, [x0]'),
      0x653f20:('add','x11, x11, #1'),0x653f24:('cmp','x14, #0'),0x653f38:('add','x13, x13, #1'),0x653f3c:('sub','x14, x14, #1'),
      0x653fc0:('ldr','w0, [x9]'),0x653fc4:('ldr','w9, [x20, #8]'),0x653fc8:('mov','w11, #0xb4b4'),
      0x653fcc:('movk','w11, #0xb68b, lsl #16'),0x653fd0:('add','w9, w9, w11'),0x653fd4:('add','w2, w27, w9'),
      0x654020:('mov','x17, #0x7bce'),0x654024:('blraa','x8, x17'),0x654028:('ldr','x8, [x25, w28, sxtw #3]'),
      0x654030:('braa','x8, x17'),0x654038:('add','x9, sp, #0x10'),0x654040:('mov','w10, #0x1f'),0x654048:('mov','w11, #0xba'),
      0x654060:('eor','w13, w9, w11'),0x654064:('add','w14, w9, #0x11'),0x654068:('mul','w13, w13, w14'),
      0x65406c:('add','x14, x20, x10'),0x654070:('strb','w13, [x14]'),0x654074:('add','x9, x9, #1'),
      0x654078:('cmp','x10, #0'),0x65408c:('sub','x10, x10, #1'),0x6540e4:('mov','x0, x20'),0x6540e8:('mov','x17, #0x7c9f'),
      0x6540ec:('blraa','x8, x17'),0x6540f0:('ldr','x8, [x25, w27, sxtw #3]'),0x654100:('braa','x8, x17'),
      0x1ca8bc:('str','x27, [x19]'),0x1ca8c0:('stp','w28, w28, [x19, #8]'),0x2e4ed0:('str','w28, [x8, #0x18]')}
    rows=[]
    for at,want in exact.items():
        ins=next(CS.disasm(s.read(at,4),at));assert (ins.mnemonic,ins.op_str)==want
        rows.append({'address':hex(at),'bytes_hex':s.read(at,4).hex(),'instruction':ins.mnemonic+' '+ins.op_str})
    # API results are not read between these calls and their source-selected
    # indirect branches; complete return-value controls corroborate this scope.
    return {'proofs':proofs,'exact_original_instructions':rows,'exact_instructions_checked':len(rows),
      'release_extent_phase_assumption_u32':'0x37da','equation_proofs_are_original_instruction_lifts':False,
      'loop_count_coverage':'Finite complete 4096-byte buffer and 32-byte metadata loops in coherent caller runs; no native concurrency or lifetime proof.'}


def main():
    e=json.loads(read(ROOT/'corefp_vm_lifecycle_checks.json'));s=Pointers();assert e['thin_sha256']==THIN_SHA and e['daemon_thin_sha256']==SHA(SOURCE.read_bytes())
    assert e['generator_sha256']==SHA((ROOT/'recover_corefp_vm_lifecycle.py').read_bytes())
    for n,h in e['dependencies'].items():assert SHA(read(ROOT/n).encode())==h
    assert e['declared_base_inputs']==[{'address':hex(a),'bytes_hex':b.hex()}for a,b in declared_inputs()+parent_inputs()]
    for f in e['source_spans']:
        a,b=int(f['start'],16),int(f['end'],16)
        if 'kind'in f:assert f['kind']=='complete_import_stub_16B'and b-a==16 and f['bytes']==s.read(a,16).hex()and f['sha256']==SHA(s.read(a,16))
        else:assert f==s.function(a)
    assert e['declared_VM_backing']=={'address':hex(VM),'size_B':N,'initial_fill_u8':0,'native_allocation':False,'retained_after_declared_deallocation':True}
    totals=Counter();oracles=[]
    for ix,p in enumerate(e['profiles']):
        c=p['configuration'];cpu={'X31':[hex(((j+1)*0x123456789abcdef)&M64)for j in range(31)],'Q32':[hex(int.from_bytes(bytes([j])*16,'little'))for j in range(32)],
          'SP':'0x62018000','PC':hex(BASE+ENTRY),'NZCV':'0x60000000','FPCR':'0x0','FPSR':'0x0','CPACR_EL1':'0x300000'}
        cpu['X31'][0]='0x63000800';cpu['X31'][1]='0x63000e00';cpu['X31'][30]=hex(DONE);assert p['initial_CPU']==cpu;totals['initial_CPU_frames_checked']+=1
        assert e['profile_caller_inputs'][ix]==[{'address':hex(a),'bytes_hex':b.hex()}for a,b in caller_inputs(s,c)]
        payload=[(0x63000c00,bytes((37*j+11)&255 for j in range(128)))]if c.get('payload_pattern')else []
        assert e['profile_payload_inputs'][ix]==[{'address':hex(a),'bytes_hex':b.hex()}for a,b in payload]
        for row in p['initial_RAM']:
            a=int(row['address'],16);b=bytearray(bytes(N)if a==VM else initial_page(s,a))
            for address,raw in parent_inputs()+caller_inputs(s,c)+payload:
                if a<=address<address+len(raw)<=a+4096:b[address-a:address-a+len(raw)]=raw
            assert unpack(row['payload'])==bytes(b),(c['label'],hex(a));totals['initial_RAM_B_checked']+=4096
        replay=Replay(p,e['source_spans'],s);totals.update(replay.run());oracles.append(oracle(p,replay,s))
    assert [p['configuration']['label']for p in e['profiles']]==['vm_failure','vm_failure_release_error','primary_null','lookup_error','clobber_primary','payload_16']
    counts={'profiles':len(e['profiles']),'complete_outer_returns':len(e['profiles']),'coherent_ingress_calls':sum(not p['configuration']['vm_status_u32']for p in e['profiles']),
      **{k:sum(len(p[k])for p in e['profiles'])for k in ['visits','reads','writes','PAC_models','models','points','metadata_returns','daemon_children','handoffs','lock_events','caller_points','vm_points']},
      **{k:sum(p[k]for p in e['profiles'])for k in ['metadata_allocation_attempts','vm_allocate_calls','vm_deallocate_calls','free_calls','buffer_iterations','metadata_iterations','bootstrap_calls','certificate_allocation_attempts']}}
    assert counts==e['verified_counts'];source=source_checks(s)
    result={'verified_counts':counts,'independent_client_replay':dict(totals),'compact_oracle_profiles':len(oracles),
      'client_source_spans':len(e['source_spans']),'client_source_B_checked':sum(len(bytes.fromhex(f['bytes']))for f in e['source_spans']),
      'source_queries_unsat':len(source['proofs']),'exact_instructions_checked':source['exact_instructions_checked'],
      'buffer_oracle_bytes_checked':sum(o['VM_overwrite_B']for o in oracles),'metadata_oracle_bytes_checked':32*len(oracles),
      'daemon_source_visits_fresh_checked':sum(len(x['visited_original_instructions'])for p in e['profiles']for x in p['daemon_children']),
      'native_target_executed':False,'all_checks_pass':True}
    out={'result':result,'checks_sha256':SHA(read(ROOT/'corefp_vm_lifecycle_checks.json').encode()),'auditor_sha256':SHA(Path(__file__).read_bytes()),
      'dependencies':e['dependencies'],'frozen_contract_modules':{n:SHA(read(ROOT/n).encode())for n in ['audit_corefp_ingress_callers.py','audit_corefp_lookup_release.py',
        'audit_corefp_cold_metadata.py','audit_corefp_lookup_initialization.py','audit_fpsd1201_predicates.py']},
      'oracles':oracles,'source_contracts':source,'semantic_annotations_used_as_proof':False,'full_daemon_CPU_RAM_replayed':False,
      'fresh_replay_completed':True,'process_exit_code':0,'full_goal_complete':False}
    (ROOT/'corefp_vm_lifecycle_audit.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(result),flush=True)


if __name__=='__main__':main()
