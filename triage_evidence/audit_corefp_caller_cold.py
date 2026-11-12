#!/usr/bin/env python3
"""Independent coherent caller-to-cold replay and compact data-flow oracles.

Does not import this increment's producer. Reconstructs initial CPU/RAM and
checks all original source/API/PAC transitions and final touched pages. Frozen
seed/route source contracts are freshly rechecked. No native API, target, IPC
or IDB mutation occurs. O(C*(B+P*F+V*J+R+624)) time/space upper bound,
including frozen reaching-load/page scans; 100000 visits, 30 s/SMT query.
"""
import json,struct
from pathlib import Path
from hashlib import sha256
from collections import Counter
from unicorn import arm64_const as A
from audit_corefp_vm_lifecycle import Replay as VMReplay,caller_inputs,CS
from audit_corefp_cold_seed import Replay as ColdReplay,extra_inputs,state,source_proofs,source_contracts,contract,leaf_contract,sdk_checks
from audit_corefp_lookup_release import parent_inputs,frame,unpack
from audit_corefp_lookup_initialization import initial_page,declared_inputs
from corefp_fixups_reader import Pointers,ROOT,THIN_SHA
from probe_corefp_exports import BASE
from daemon_receive_tools import SOURCE
from verify_daemon_reader_record_payloads_publication import read

SHA=lambda b:sha256(b).hexdigest();M32=(1<<32)-1;M64=(1<<64)-1
ENTRY=0x2e4280;META=0x64000800;VM=0x66000000;N=4096;STATE=0x1d4551c
FLOW=[0x8ea890,0x8ea894,0x8ea8ac,0x8eb7a4,0x8eba0c,0x8eba3c,0x8eba40,0x8eba44]
LIST_FIELDS=['visits','reads','writes','PAC_models','models','points','metadata_returns','daemon_children',
 'handoffs','lock_events','transactions','certificate_events','constructor_points','caller_points','vm_points','flow_points']
SCALAR_FIELDS=['metadata_allocation_attempts','vm_allocate_calls','vm_deallocate_calls','free_calls','buffer_iterations',
 'metadata_iterations','bootstrap_calls','certificate_allocation_attempts','entropy_calls','clock_calls','seed_iterations']


class Replay(VMReplay,ColdReplay):
    def __init__(self,*args):super().__init__(*args);self.fi=0
    def code(self,u,pc,n,d):
        if self.imports.get(pc)=='_free'and u.reg_read(A.UC_ARM64_REG_LR)-4-BASE==0x8e9fa8:
            return ColdReplay.code(self,u,pc,n,d)
        if pc-BASE in FLOW:
            self.flush();e={'CPU':frame(u),'visits_so_far':self.v,'models_so_far':self.mi}
            assert e==self.p['flow_points'][self.fi];self.fi+=1
        return super().code(u,pc,n,d)
    def run(self):
        self.u.emu_start(BASE+ENTRY,0,count=100001);self.flush();assert self.done and not self.once and not self.cert_live
        assert [self.v,self.r,self.w,self.pac,self.mi,self.pi,self.hi,self.li,self.mri,self.di,self.ci,self.vi,self.fi,self.ce,self.tx,self.cpi]==[
          len(self.p[k])for k in ['visits','reads','writes','PAC_models','models','points','handoffs','lock_events',
          'metadata_returns','daemon_children','caller_points','vm_points','flow_points','certificate_events','transactions','constructor_points']]
        assert [self.mai,self.vac,self.vdc,self.fc,self.biter,self.miter,self.bi,self.cert,self.ei,self.ti,self.si]==[
          self.p[k]for k in SCALAR_FIELDS]==[1,1,0,0,0,0,2,1,3,1,623]
        assert self.allocs==self.p['allocations_attempted']==2 and self.snapshot('frontier')==self.p['final_state']
        for row in self.p['final_RAM']:assert self.ram(int(row['address'],16),4096)==unpack(row['payload'])
        return {'visits_checked':self.v,'reads_checked':self.r,'writes_checked':self.w,'PAC_models_checked':self.pac,'models_checked':self.mi,
          'caller_points_checked':self.ci,'vm_points_checked':self.vi,'flow_points_checked':self.fi,'constructor_points_checked':self.cpi,
          'certificate_events_checked':self.ce,'entropy_returns_checked':self.ei,'clock_returns_checked':self.ti,'seed_iterations_checked':self.si,
          'final_RAM_B_checked':4096*len(self.p['final_RAM'])}


def expected_config(label):
    extra={'caller_cold':{},'caller_cold_clobber':{'clobber_callers':True},'caller_clock_error':{'time_status_u32':0xffffffff},
      'caller_payload_16':{'entry_scalar_u32':16,'payload_pattern':True},
      'caller_stack_5a_clock_error':{'stack_fill_u8':0x5a,'time_status_u32':0xffffffff}}[label]
    return {'label':label,'allocation_success':[True,True],'lock_init_status_u32':[0,0],'continue_to_bootstrap':True,
      'bootstrap_results':[{'status_u32':1102},{'status_u32':0,'write_port_u32':0x5034}],'unlock_status_u32':0,
      'entry_tag_u32':0x9744,'entry_scalar_u32':0,'first_pointer':0x63000900,'second_pointer':0x63000c00,
      'metadata_success':True,'metadata_fill_u8':0,'task_port_u32':0x4201,'vm_status_u32':0,'deallocate_status_u32':0,
      'free_residual_X0_u64':0,'continue_atomic_to_entropy':True,'random_u32':[0x12345678,0x9abcdef0,0x0fedcba9],
      'seconds_i64':0x123456789abcdef,'microseconds_i32':654321,'time_status_u32':0,**extra}


def oracle(p,r,s):
    cfg=p['configuration'];assert cfg==expected_config(cfg['label'])
    vm={x['label']:x for x in p['vm_points']};pts={x['label']:x for x in p['constructor_points']}
    assert list(vm)==['VM_allocator_return','before_VM_metadata_publish','VM_metadata_published','before_ingress_call','before_root_adapter','root_entry']
    ing=vm['before_ingress_call'];i=int(ing['ingress_address'],16);ib=bytes.fromhex(ing['ingress48_hex']);ki=((i^0xd914ae5d)*0x08c5d407)&M32
    assert i==0x62017f68 and (int.from_bytes(ib[:4],'little')+ki+0x513c5990)&M32==0xc1f7
    assert (int.from_bytes(ib[16:20],'little')-ki)&M32==0x2d2a8321 and (int.from_bytes(ib[20:24],'little')+ki)&M32==0x1f03fdec
    assert int.from_bytes(ib[8:16],'little')==META and int.from_bytes(ib[24:32],'little')==0x62017f58
    root=vm['root_entry'];rr=int(root['root_record_address'],16);raw=bytes.fromhex(root['root_record40_hex']);kr=((rr^0x84b771aed97ffe38)*0xfcf33521)&M32
    assert rr==0x62017ea0 and (int.from_bytes(raw[16:20],'little')+kr)&M32==0x0484c46a
    assert (int.from_bytes(raw[20:24],'little')-kr)&M32==0xc1f7 and int.from_bytes(raw[24:28],'little')^kr==0x114e4318
    assert int.from_bytes(raw[8:16],'little')==0x62017f58 and int.from_bytes(raw[32:40],'little')==META
    metadata=struct.pack('<QIIIIII',VM,0x49742372,0x49742372,0x574de78b,0x71349589,0xba1df9db,0)
    assert bytes.fromhex(root['metadata32_hex'])==r.ram(META,32)==metadata
    prefix=bytes.fromhex('9ae57a32bababab600a74371babababad9bab6ba'if cfg['entry_scalar_u32']==16 else '9ae57a32bababab600a74361babababad9bab6ba')
    assert unpack(ing['VM4096'])==prefix+bytes(N-20)
    before=[w for w in p['writes']if VM<=int(w['address'],16)<VM+N and w['visit']<ing['visits_so_far']]
    assert [(int(w['address'],16)-VM,w['size_B'],w['after_hex'])for w in before]==[(j,1,prefix[j:j+1].hex())for j in range(20)]
    pattern_reads=sum(0x63000c00<=int(x['address'],16)<0x63000c80 for x in p['reads']);assert pattern_reads==0
    sp=int(pts['tuple_complete']['CPU']['SP'],16);C=sp+0x1340;T=sp+0x1a30;fill=cfg.get('stack_fill_u8',0xa5)
    assert sp==0x62015f50 and pts['tuple_complete']['context_pointer']==hex(C)and pts['tuple_complete']['tuple_pointer']==hex(T)
    context=bytes.fromhex('006664706300000001')+bytes([fill])*119
    assert pts['tuple_complete']['context128_hex']==context.hex()and r.ram(C,128)==context
    assert not any(int(w['address'],16)<C+128 and C+9<int(w['address'],16)+w['size_B']for w in p['writes'])
    clock=next(v for v in p['models']if v.get('name')=='_gettimeofday')
    assert clock['scratch16_before_hex']==(bytes([fill])*16).hex()
    scratch=bytes.fromhex(clock['scratch16_after_hex']);tuple4=[cfg['random_u32'][2],int.from_bytes(scratch[8:12],'little'),int.from_bytes(scratch[:4],'little'),cfg['random_u32'][1]]
    assert r.ram(T,16)==struct.pack('<4I',*tuple4)and pts['tuple_complete']['tuple32_hex']==r.ram(T,32).hex()
    seed=cfg['random_u32'][0];want=state(seed);stores=[w for w in p['writes']if BASE+STATE<=int(w['address'],16)<BASE+STATE+2496];assert len(stores)==625
    for j,w in enumerate(stores[:624]):assert (w['address'],w['size_B'],w['after_hex'])==(hex(BASE+STATE+4*j),4,want[4*j:4*j+4].hex())
    mixed=((int.from_bytes(want[4:8],'little')^((seed^(seed>>30))*1664525))+tuple4[0])&M32
    assert (stores[-1]['address'],stores[-1]['size_B'],stores[-1]['after_hex'])==(hex(BASE+STATE+4),4,mixed.to_bytes(4,'little').hex())
    assert p['visits'][stores[-1]['visit']]['pc']=='0x8ebbd4';final=bytearray(want);struct.pack_into('<I',final,4,mixed);assert r.ram(BASE+STATE,2496)==bytes(final)
    leaves=[]
    for before,after,entry in [('first_predicate_entry','first_predicate_return',0x1abbe0),('second_predicate_entry','second_predicate_return',0x439734)]:
        a,b=pts[before],pts[after];raw=bytes.fromhex(a['record44_hex']);ptr=int(a['record_pointer'],16)
        if entry==0x1abbe0:out,off=leaf_contract(entry,ptr,raw);decoded={'result_u32':out,'output_offset_B':off}
        else:decoded=contract(ptr,raw);out,off=decoded['result_u32'],0
        desired=bytearray(raw);struct.pack_into('<I',desired,off,out)
        assert bytes.fromhex(b['record44_hex'])==desired and a['record_pointer']==b['record_pointer']==hex(sp+0x1da8)
        assert out==(0x245a if entry==0x1abbe0 else 0x252a);leaves.append({'entry':hex(entry),'record':hex(ptr),'decoded':decoded,'output_offset_B':off})
    flow={int(x['CPU']['PC'],16)-BASE:x for x in p['flow_points']};assert list(flow)==FLOW
    start,end=flow[0x8ea890],flow[0x8eb7a4];lo,hi=start['visits_so_far'],end['visits_so_far']
    # Exact original MOV supplies zero; no intervening source or API writes X13.
    ins=next(CS.disasm(s.read(0x8ea890,4),0x8ea890));assert (ins.mnemonic,ins.op_str)==('mov','x13, #0')
    assert flow[0x8ea894]['CPU']['X31'][13]==end['CPU']['X31'][13]=='0x0'and start['models_so_far']==end['models_so_far']
    for v in p['visits'][lo+1:hi]:
        a=int(v['pc'],16);ins=next(CS.disasm(s.read(a,4),a));assert not {'x13','w13'}&{CS.reg_name(x)for x in ins.regs_access()[1]}
    readby=lambda pc:[x for x in p['reads']if p['visits'][x['visit']]['pc']==hex(pc)]
    selector=readby(0x8ea8b0);assert len(selector)==1 and selector[0]['address']==hex(BASE+0x1d44409)and selector[0]['bytes_hex']=='00'
    assert s.read(0x1d44409,1)==b'\0'and not any(int(w['address'],16)<=BASE+0x1d44409<int(w['address'],16)+w['size_B']for w in p['writes'])
    edge=[e for e in p['PAC_models']if e['pc']=='0x8ea8e8'];assert len(edge)==1 and edge[0]['target']==hex(BASE+0x8eb7a4)and edge[0]['pointer_row']==s.decoded[0x1cc62a0]
    inp=[w for w in p['writes']if w['address']==hex(sp+0x438)];assert len(inp)==1 and inp[0]['size_B']==8 and inp[0]['after_hex']=='00'*8 and p['visits'][inp[0]['visit']]['pc']=='0x8eb7a4'
    assert r.ram(sp+0x438,8)==bytes(8)and r.ram(sp+0x428,4)==bytes(4)and r.ram(sp+0x418,4).hex()=='cc6bd4f1'
    assert flow[0x8eba3c]['CPU']['X31'][11]=='0x4'and flow[0x8eba40]['CPU']['X31'][13]=='0x0'
    f=p['frontier'];assert f['address']=='0x4'and f['CPU']['PC']==hex(BASE+0x8eba44)and f['CPU']['X31'][12]=='0x4'
    assert f['held_lock_model']=='0x64000000'and f['token4_hex']=='965d0000'and p['parent_return']is None
    assert not any(int(v['address'],16)<8 for v in p['reads'])and not any(0x8ae0<=int(v['pc'],16)<0x8d40 for v in p['visits'])
    assert not any(p[k]for k in ['transactions','metadata_returns','daemon_children'])and len(p['lock_events'])==1
    assert p['final_state']['primary_u32']==0x5034 and p['final_state']['secondary_u32']==0 and p['handoffs'][1]['lookup_output_words']==[0x5034,0]
    names=[v.get('name')for v in p['models']];assert not any(x in names for x in ['_mach_msg','_mach_port_deallocate','_pthread_rwlock_unlock','_vm_deallocate'])
    assert names.count('_free')==1 and next(v for v in p['models']if v.get('name')=='_free')['callsite']=='0x8e9fa8'
    container=bytes(x^0xba for x in s.read(0x185c226,760));assert bytes.fromhex(p['certificate_events'][1]['allocation760_hex_at_free'])==container[4:]+container[-4:]
    assert container[4:]==(ROOT/'corefp_fppineboard_certificate.der').read_bytes()
    return {'label':cfg['label'],'root_record':hex(rr),'root_mode_u32':'0x114e4318','root_operation_u32':'0xc1f7','root_field16_u32':'0x484c46a',
      'metadata_pointer':hex(META),'VM_pointer':hex(VM),'source_staged_VM_prefix20_hex':prefix.hex(),'AUX_reads':pattern_reads,
      'root_SP':hex(sp),'context_pointer':hex(C),'source_context_prefix_B':9,'context_suffix_without_source_store_B':119,'initial_stack_fill_u8':hex(fill),
      'tuple_pointer':hex(T),'tuple_u32':tuple4,'oracle_seed_words_checked':624,'state1_after_u32':mixed,'predicate_calls':leaves,
      'selector_byte_address':'0x1d44409','selector_byte_u8':0,'optional_zero_definition':'0x8ea890','zero_definition_to_store_source_visits':hi-lo,
      'optional_input_store':'0x8eb7a4','optional_input_pointer':'0x0','next_read_address':'0x4','next_read_executed':False,
      'certificate_DER_B':756,'certificate_DER_sha256':SHA(container[4:]),'source_PC_gap':False,'root_record_patched':False,
      'VM_metadata_cleanup_reached':False,'native_lifetime_established':False,'native_target_executed':False}


def main():
    e=json.loads(read(ROOT/'corefp_caller_cold_checks.json'));s=Pointers();CS.detail=True
    assert e['thin_sha256']==THIN_SHA and e['daemon_thin_sha256']==SHA(SOURCE.read_bytes())
    assert e['generator_sha256']==SHA((ROOT/'recover_corefp_caller_cold.py').read_bytes())
    for n,h in e['dependencies'].items():assert SHA(read(ROOT/n).encode())==h
    assert e['declared_base_inputs']==[{'address':hex(a),'bytes_hex':b.hex()}for a,b in declared_inputs()+parent_inputs()+extra_inputs()]
    assert e['initialization_order']==['base','parent','certificate_extra','optional_stack_fill','caller','VM_zero_page','payload']
    for f in e['source_spans']:
        a,b=int(f['start'],16),int(f['end'],16)
        if 'kind'in f:assert f['kind']=='complete_import_stub_16B'and b-a==16 and f['bytes']==s.read(a,16).hex()and f['sha256']==SHA(s.read(a,16))
        else:assert f==s.function(a)
    assert [p['configuration']['label']for p in e['profiles']]==['caller_cold','caller_cold_clobber','caller_clock_error','caller_payload_16','caller_stack_5a_clock_error']
    totals=Counter();oracles=[]
    for ix,p in enumerate(e['profiles']):
        c=p['configuration'];assert c==expected_config(c['label'])
        cpu={'X31':[hex(((j+1)*0x123456789abcdef)&M64)for j in range(31)],'Q32':[hex(int.from_bytes(bytes([j])*16,'little'))for j in range(32)],
          'SP':'0x62018000','PC':hex(BASE+ENTRY),'NZCV':'0x60000000','FPCR':'0x0','FPSR':'0x0','CPACR_EL1':'0x300000'}
        cpu['X31'][0]='0x63000800';cpu['X31'][1]='0x63000e00';cpu['X31'][30]='0x65000000';assert p['initial_CPU']==cpu;totals['initial_CPU_frames_checked']+=1
        payload=[(0x63000c00,bytes((37*j+11)&255 for j in range(128)))]if c.get('payload_pattern')else []
        assert e['profile_caller_inputs'][ix]==[{'address':hex(a),'bytes_hex':b.hex()}for a,b in caller_inputs(s,c)]
        assert e['profile_payload_inputs'][ix]==[{'address':hex(a),'bytes_hex':b.hex()}for a,b in payload]
        for row in p['initial_RAM']:
            a=int(row['address'],16);b=bytearray(bytes(N)if a==VM else initial_page(s,a))
            if 0x62000000<=a<a+4096<=0x62020000 and 'stack_fill_u8'in c:b[:]=bytes([c['stack_fill_u8']])*4096
            for address,raw in parent_inputs()+extra_inputs()+caller_inputs(s,c)+payload:
                if a<=address<address+len(raw)<=a+4096:b[address-a:address-a+len(raw)]=raw
            assert unpack(row['payload'])==bytes(b),(c['label'],hex(a));totals['initial_RAM_B_checked']+=4096
        r=Replay(p,e['source_spans'],s);totals.update(r.run());oracles.append(oracle(p,r,s))
    counts={'profiles':len(e['profiles']),**{k:sum(len(p[k])for p in e['profiles'])for k in LIST_FIELDS},**{k:sum(p[k]for p in e['profiles'])for k in SCALAR_FIELDS}}
    assert counts==e['verified_counts']
    seed_source=source_proofs({'source_spans':[s.function(0x8e81c8)]},s)
    route_source=source_contracts({},s,{'prefix':{'result':{'visited_original_instructions':[v['pc']for v in e['profiles'][0]['visits']]}}})
    sdk=sdk_checks();contracts={}
    for name in ['audit_corefp_vm_lifecycle.py','audit_corefp_ingress_callers.py','audit_corefp_cold_seed.py','audit_corefp_request1200_failure.py',
      'audit_corefp_lookup_release.py','audit_corefp_lookup_initialization.py','audit_fpsd1201_seed.py','audit_fpsd1201_key_routes.py','audit_fpsd1201_predicates.py']:
        contracts[name]=SHA(read(ROOT/name).encode())
    prior=json.loads(read(ROOT/'corefp_cold_seed_checks.json'));old=prior['profiles'][0]
    old_r=int(old['initial_CPU']['X31'][0],16);old_raw=bytes.fromhex(old['caller_record48_hex']);old_k=((old_r^0x84b771aed97ffe38)*0xfcf33521)&M32
    assert int.from_bytes(old_raw[24:28],'little')^old_k==0
    assert len(prior['profiles'])==9 and all(len(p['certificate_events'])==2 for p in prior['profiles'])
    old_tuple=next(x for x in old['constructor_points']if x['label']=='tuple_complete')
    assert old_tuple['CPU']['SP']=='0x62016190'and old_tuple['context_pointer']=='0x620174d0'and old_tuple['tuple_pointer']=='0x62017bc0'
    comparison={'prior_profiles_receipt_pinned_not_replayed':9,'prior_mode_u32':'0x0','new_mode_u32':'0x114e4318',
      'certificate_allocate_free_already_present_in_all_prior_profiles':True,'constructor_SP_change_B':-576,
      'prior_root_SP':'0x62016190','new_root_SP':'0x62015f50','single_mode_field_causal_experiment':False}
    result={'verified_counts':counts,'independent_client_replay':dict(totals),'compact_oracle_profiles':len(oracles),
      'client_source_spans':len(e['source_spans']),'client_source_B_checked':sum(len(bytes.fromhex(v['bytes']))for v in e['source_spans']),
      'oracle_seed_words_checked':624*len(oracles),'source_queries_unsat':len(seed_source['proofs'])+len(route_source['proofs']),
      'exact_instructions_checked':seed_source['exact_instructions_checked']+route_source['exact_instructions_checked']+1,
      'SDK_compile_exit':0,'native_target_executed':False,'all_checks_pass':True}
    out={'result':result,'checks_sha256':SHA(read(ROOT/'corefp_caller_cold_checks.json').encode()),'auditor_sha256':SHA(Path(__file__).read_bytes()),
      'dependencies':e['dependencies'],'frozen_contract_modules':contracts,'oracles':oracles,'seed_source_contracts':seed_source,'route_source_contracts':route_source,
      'SDK_assertions':sdk,'prior_fixture_comparison':comparison,
      'zero_definition_original':{'address':'0x8ea890','bytes_hex':s.read(0x8ea890,4).hex(),'instruction':'mov x13, #0'},
      'semantic_annotations_used_as_proof':False,'full_daemon_CPU_RAM_replayed':False,'new_live_IDA_claim':False,
      'fresh_replay_completed':True,'process_exit_code':0,'full_goal_complete':False}
    (ROOT/'corefp_caller_cold_audit.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(result),flush=True)


if __name__=='__main__':main()
