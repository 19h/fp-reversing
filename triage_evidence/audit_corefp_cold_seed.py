#!/usr/bin/env python3
"""Independently replay complete cold constructor paths and environmental ABI.

No import of this increment's producer. Initial CPU/RAM are reconstructed;
all client source/API/PAC effects and final touched pages are checked. Frozen
source contracts are rechecked, with independent complete seed/mix/leaf oracles.
Conservative O(C*(B+P*F+V*J+R+624)) time/space, including reaching-load
scans and per-page fixup reconstruction; 100000 visits, 30 s per SMT query.
"""
import copy,json,struct,subprocess
from pathlib import Path
from hashlib import sha256
from collections import Counter
from unicorn import arm64_const as A
from audit_corefp_request1200_failure import Replay as Frozen,extra_inputs
from audit_corefp_lookup_release import parent_inputs,ENTRY,PARENT,CURSOR,DONE,HEAP,M64
from audit_corefp_lookup_initialization import initial_page,declared_inputs,frame,restore,ret,unpack
from audit_fpsd1201_seed import state,source_proofs
from audit_fpsd1201_key_routes import contract,source_contracts
from audit_fpsd1201_predicates import leaf_contract
from recover_fpsd1201_predicates import pack
from corefp_fixups_reader import Pointers,ROOT,THIN_SHA
from probe_corefp_exports import BASE
from daemon_receive_tools import SOURCE
from verify_daemon_reader_record_payloads_publication import read

SHA=lambda b:sha256(b).hexdigest();STATE=0x1d4551c;TOKEN=0x1d33108


class Replay(Frozen):
    def __init__(self,p,spans,s):
        super().__init__(p,spans,s);self.ei=self.ti=self.si=self.cpi=0
    def constructor_point(self,label,record=False):
        sp=self.u.reg_read(A.UC_ARM64_REG_SP);r=self.u.reg_read(A.UC_ARM64_REG_X0)
        e={'label':label,'CPU':frame(self.u),'visits_so_far':self.v,'models_so_far':self.mi}
        if label=='before_first_entropy':e.update({'token4_hex':self.ram(BASE+TOKEN,4).hex(),'held_lock_model':hex(self.held)})
        if label=='seed_complete':e['state624']=pack(self.ram(BASE+STATE,2496))
        if label=='tuple_complete':
            p=int.from_bytes(self.ram(sp+0x498,8),'little');e.update({'context_pointer':hex(sp+0x1340),'context128_hex':self.ram(sp+0x1340,128).hex(),
              'tuple_pointer':hex(p),'tuple32_hex':self.ram(p,32).hex()})
        if record:e.update({'record_pointer':hex(r),'record44_hex':self.ram(r,44).hex()})
        assert e==self.p['constructor_points'][self.cpi];self.cpi+=1
    def code(self,u,pc,n,d):
        self.flush();name=self.imports.get(pc);cfg=self.p['configuration']
        if name in ['_arc4random','_gettimeofday']:
            if name=='_arc4random'and self.ei==0:self.constructor_point('before_first_entropy')
            args=[u.reg_read(getattr(A,'UC_ARM64_REG_X'+str(j)))for j in range(8)];e=self.event();call=u.reg_read(A.UC_ARM64_REG_LR)-4-BASE;writes=[]
            assert e['kind']=='declared_API'and e['name']==name and e['args_x0_x7']==list(map(hex,args))and e['callsite']==hex(call)
            if name=='_arc4random':
                assert call==[0x8eb800,0x8eb94c,0x8eb9a4][self.ei]and e['entropy_index']==self.ei
                value=cfg['random_u32'][self.ei];self.ei+=1
            else:
                assert self.ti==0 and call==0x8eb8e0 and args[1]==0 and args[0]==u.reg_read(A.UC_ARM64_REG_SP)+0x1a40;self.ti+=1
                assert self.ram(args[0],16).hex()==e['scratch16_before_hex'];value=cfg['time_status_u32']
                if value==0:writes=[(args[0],struct.pack('<qi',cfg['seconds_i64'],cfg['microseconds_i32']))]
            self.effects(e,writes)
            if name=='_gettimeofday':assert self.ram(args[0],16).hex()==e['scratch16_after_hex']and e['scratch16_after_hex'][24:]==e['scratch16_before_hex'][24:]
            assert e['return_u64']==hex(value);f=ret(e['before'],value,cfg.get('clobber_callers',False));assert e['after']==f;restore(u,f);return
        if pc==BASE+0x8eb824:
            self.si+=1
            if self.si==1:self.constructor_point('seed_loop_entry')
        if pc==BASE+0x8eb85c:
            assert self.si==623 and self.ram(BASE+STATE,2496)==state(cfg['random_u32'][0]);self.constructor_point('seed_complete')
        if pc==BASE+0x8eb9b4:self.constructor_point('tuple_complete')
        for at,label in [(0x1abbe0,'first_predicate_entry'),(0x8ebca4,'first_predicate_return'),(0x439734,'second_predicate_entry'),(0x8ebe38,'second_predicate_return')]:
            if pc==BASE+at:self.constructor_point(label,True)
        if pc==BASE+0x8eba44:
            assert self.p['frontier']=={'reason':'before_optional_input_word_read','CPU':frame(u),'address':hex(u.reg_read(A.UC_ARM64_REG_X12)),
              'held_lock_model':hex(self.held),'token4_hex':self.ram(BASE+TOKEN,4).hex()}
            self.done=True;u.emu_stop();return
        return super().code(u,pc,n,d)
    def run(self):
        self.u.emu_start(BASE+ENTRY,0,count=100001);self.flush();assert self.done and not self.once and not self.cert_live
        assert [self.v,self.r,self.w,self.pac,self.mi,self.pi,self.hi,self.li,self.mri,self.di,self.bi,self.cert,self.ce,self.tx,self.cpi]==[
          len(self.p[k])for k in ['visits','reads','writes','PAC_models','models','points','handoffs','lock_events','metadata_returns','daemon_children']]+[
          self.p['bootstrap_calls'],self.p['certificate_allocation_attempts'],len(self.p['certificate_events']),len(self.p['transactions']),len(self.p['constructor_points'])]
        assert [self.ei,self.ti,self.si]==[self.p['entropy_calls'],self.p['clock_calls'],self.p['seed_iterations']]==[3,1,623]
        assert self.allocs==self.p['allocations_attempted']==2 and self.snapshot('frontier')==self.p['final_state']
        assert self.ram(PARENT,48).hex()==self.p['caller_record48_hex']and hex(int.from_bytes(self.ram(CURSOR,8),'little'))==self.p['caller_word_u64']
        for row in self.p['final_RAM']:assert self.ram(int(row['address'],16),4096)==unpack(row['payload'])
        return {'visits_checked':self.v,'reads_checked':self.r,'writes_checked':self.w,'PAC_models_checked':self.pac,'models_checked':self.mi,'points_checked':self.pi,
          'handoffs_checked':self.hi,'lock_events_checked':self.li,'constructor_points_checked':self.cpi,'certificate_events_checked':self.ce,'entropy_returns_checked':self.ei,
          'clock_returns_checked':self.ti,'seed_iterations_checked':self.si,'final_RAM_B_checked':4096*len(self.p['final_RAM'])}


def oracle(p,r,s,prior):
    cfg=p['configuration'];label=cfg['label'];seed={'zero_seed':0,'one_seed':1,'max_seed':0xffffffff}.get(label,0x12345678)
    expected={'label':label,'allocation_success':[label!='static_lock',True],'lock_init_status_u32':[0,0],'continue_to_bootstrap':True,
      'bootstrap_results':[{'status_u32':1102},{'status_u32':0,'write_port_u32':0x5034}],'unlock_status_u32':0,'continue_atomic_to_entropy':True,
      'random_u32':[seed,0x9abcdef0,0x0fedcba9],'seconds_i64':0 if label=='zero_seed'else -1 if label=='one_seed'else 0x7fffffffffffffff if label=='max_seed'else 0x123456789abcdef,
      'microseconds_i32':0 if label=='zero_seed'else 999999 if label in ['one_seed','max_seed']else 654321,
      'time_status_u32':0xffffffff if label in ['clock_error_no_write','zero_stack_clock_error','alternate_stack_clock_error']else 0,
      **({'clobber_callers':True}if label=='clock_A_clobber'else {}),**({'stack_fill_u8':0 if label=='zero_stack_clock_error'else 0x5a}if 'stack_fill_u8'in cfg else {})};assert cfg==expected
    fill=cfg.get('stack_fill_u8',0xa5);pts={v['label']:v for v in p['constructor_points']};sp=int(pts['tuple_complete']['CPU']['SP'],16);C=sp+0x1340;T=sp+0x1a30
    assert sp==0x62016190 and pts['tuple_complete']['context_pointer']==hex(C)and pts['tuple_complete']['tuple_pointer']==hex(T)
    context=bytes.fromhex('006664706300000001')+bytes([fill])*119
    assert pts['tuple_complete']['context128_hex']==context.hex()and r.ram(C,128)==context
    # The 119-byte suffix has no source store before this frontier. Its value
    # comes from the declared initial stack, not an initialized native context.
    assert not any(int(w['address'],16)<C+128 and C+9<int(w['address'],16)+w['size_B']for w in p['writes'])
    clock=next(v for v in p['models']if v.get('name')=='_gettimeofday');assert clock['scratch16_before_hex']==bytes([fill]*16).hex()
    b=bytes.fromhex(clock['scratch16_after_hex']);tuple4=[cfg['random_u32'][2],int.from_bytes(b[8:12],'little'),int.from_bytes(b[:4],'little'),cfg['random_u32'][1]]
    assert r.ram(T,16)==struct.pack('<4I',*tuple4)and pts['tuple_complete']['tuple32_hex']==r.ram(T,32).hex()
    expected_state=state(seed);stores=[v for v in p['writes']if BASE+STATE<=int(v['address'],16)<BASE+STATE+2496];assert len(stores)==625
    for j,w in enumerate(stores[:624]):assert w['address']==hex(BASE+STATE+4*j)and w['size_B']==4 and w['after_hex']==expected_state[4*j:4*j+4].hex()
    before1=int.from_bytes(expected_state[4:8],'little');mixed=((before1^((seed^(seed>>30))*1664525))+tuple4[0])&0xffffffff
    assert stores[-1]['address']==hex(BASE+STATE+4)and stores[-1]['size_B']==4 and stores[-1]['after_hex']==mixed.to_bytes(4,'little').hex()and p['visits'][stores[-1]['visit']]['pc']=='0x8ebbd4'
    wanted=bytearray(expected_state);struct.pack_into('<I',wanted,4,mixed);assert r.ram(BASE+STATE,2496)==bytes(wanted)
    leaves=[]
    for before,after,entry in [('first_predicate_entry','first_predicate_return',0x1abbe0),('second_predicate_entry','second_predicate_return',0x439734)]:
        a,b=pts[before],pts[after];raw=bytes.fromhex(a['record44_hex']);ptr=int(a['record_pointer'],16)
        if entry==0x1abbe0:out,off=leaf_contract(entry,ptr,raw);decoded={'result_u32':out,'output_offset_B':off}
        else:decoded=contract(ptr,raw);out,off=decoded['result_u32'],0
        want=bytearray(raw);struct.pack_into('<I',want,off,out);assert bytes.fromhex(b['record44_hex'])==want and a['record_pointer']==b['record_pointer']==hex(0x62017f38)
        assert out==(0x245a if entry==0x1abbe0 else 0x252a);leaves.append({'entry':hex(entry),'decoded':decoded,'output_offset_B':off})
    assert r.ram(sp+0x418,4).hex()=='cc6bd4f1'and r.ram(sp+0x438,8)==b'\0'*8 and r.ram(sp+0x428,4)==b'\0'*4
    inputstores=[w for w in p['writes']if w['address']==hex(sp+0x438)];assert len(inputstores)==1 and inputstores[0]['after_hex']=='00'*8 and p['visits'][inputstores[0]['visit']]['pc']=='0x8eb7a4'
    assert p['frontier']['address']=='0x4'and p['frontier']['CPU']['PC']==hex(BASE+0x8eba44)and p['frontier']['token4_hex']=='965d0000'
    assert not any(int(v['address'],16)<8 for v in p['reads'])and not any(0x8ae0<=int(v['pc'],16)<0x8d40 for v in p['visits'])
    pointer=BASE+0x1d27bf0 if label=='static_lock'else HEAP;assert p['frontier']['held_lock_model']==hex(pointer)
    assert len(p['lock_events'])==1 and p['lock_events'][0]['pointer']==hex(pointer)and p['parent_return']is None and p['caller_word_u64']=='0x100'and p['caller_record48_hex']==parent_inputs()[0][1].hex()
    assert p['final_state']['primary_u32']==0x5034 and p['final_state']['secondary_u32']==0 and len(p['handoffs'])==2 and p['handoffs'][1]['lookup_output_words']==[0x5034,0]
    assert not p['transactions']and not p['metadata_returns']and not p['daemon_children']
    names=[v.get('name')for v in p['models']];assert not any(v in names for v in ['_mach_msg','_mach_port_deallocate','_pthread_rwlock_unlock'])
    container=bytes(v^0xba for v in s.read(0x185c226,760));assert bytes.fromhex(p['certificate_events'][1]['allocation760_hex_at_free'])==container[4:]+container[-4:]
    assert container[4:]==(ROOT/'corefp_fppineboard_certificate.der').read_bytes()
    first=pts['before_first_entropy'];prefix_equal=label not in ['clock_A_clobber','static_lock','zero_stack_clock_error','alternate_stack_clock_error']
    if prefix_equal:
        assert first['CPU']==prior['frontier']['CPU']and first['token4_hex']==prior['frontier']['token4_hex']and first['held_lock_model']==prior['frontier']['held_lock_model']
        assert p['visits'][:first['visits_so_far']]==prior['visits']and p['models'][:first['models_so_far']]==prior['models']
        for key in ['reads','writes','PAC_models']:assert [v for v in p[key]if v['visit']<first['visits_so_far']]==prior[key]
    return {'label':label,'seed_u32':hex(seed),'initial_stack_fill_u8':hex(fill),'source_context_prefix_B':9,'context_suffix_without_source_store_B':119,
      'tuple_pointer':hex(T),'tuple_u32':tuple4,'state1_before_u32':before1,'state1_after_u32':mixed,'oracle_seed_words_checked':624,
      'predicate_calls':leaves,'same_epoch_optional_input_pointer':'0x0','next_read_address':'0x4','next_read_executed':False,
      'exact_prior_cold_prefix_compared':prefix_equal,'native_target_executed':False}


def sdk_checks():
    code='#include <sys/time.h>\n#include <stdlib.h>\n#include <stdint.h>\n#include <stddef.h>\n_Static_assert(sizeof(struct timeval)==16,"timeval16");\n_Static_assert(offsetof(struct timeval,tv_sec)==0,"seconds_offset0");\n_Static_assert(offsetof(struct timeval,tv_usec)==8,"microseconds_offset8");\n_Static_assert(sizeof(((struct timeval*)0)->tv_sec)==8,"seconds8");\n_Static_assert(sizeof(((struct timeval*)0)->tv_usec)==4,"microseconds4");\n_Static_assert(__builtin_types_compatible_p(__typeof__(&arc4random),uint32_t(*)(void)),"arc4random_prototype");\n'
    cmd=['xcrun','clang','-target','arm64e-apple-macos14','-fsyntax-only','-x','c','-'];r=subprocess.run(cmd,input=code,text=True,capture_output=True,timeout=30);assert r.returncode==0,r.stderr
    sdk=Path(subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip());headers=[]
    for name in ['usr/include/sys/time.h','usr/include/stdlib.h']:
        raw=(sdk/name).read_bytes();headers.append({'SDK_relative_header':name,'size_B':len(raw),'sha256':SHA(raw)})
    return {'command':cmd,'source':code,'exit_code':0,'stderr':r.stderr,'headers':headers,'emitted_artifact':False}


def main():
    e=json.loads(read(ROOT/'corefp_cold_seed_checks.json'));s=Pointers();assert e['thin_sha256']==THIN_SHA and e['daemon_thin_sha256']==SHA(SOURCE.read_bytes())
    assert e['generator_sha256']==SHA((ROOT/'recover_corefp_cold_seed.py').read_bytes())
    for n,h in e['dependencies'].items():assert SHA(read(ROOT/n).encode())==h
    assert e['declared_inputs']==[{'address':hex(a),'bytes_hex':b.hex()}for a,b in declared_inputs()+parent_inputs()+extra_inputs()]
    for span in e['source_spans']:assert span==s.function(int(span['start'],16))
    prior=json.loads(read(ROOT/'corefp_request1200_failure_checks.json'))['profiles'][2];totals=Counter();oracles=[]
    assert [p['configuration']['label']for p in e['profiles']]==['clock_A','zero_seed','one_seed','max_seed','clock_error_no_write','clock_A_clobber','static_lock','zero_stack_clock_error','alternate_stack_clock_error']
    for p in e['profiles']:
        cpu={'X31':[hex(((j+1)*0x123456789abcdef)&M64)for j in range(31)],'Q32':[hex(int.from_bytes(bytes([j])*16,'little'))for j in range(32)],
          'SP':'0x62018000','PC':hex(BASE+ENTRY),'NZCV':'0x60000000','FPCR':'0x0','FPSR':'0x0','CPACR_EL1':'0x300000'}
        cpu['X31'][0]=hex(PARENT);cpu['X31'][1]=hex(CURSOR);cpu['X31'][30]=hex(DONE);assert p['initial_CPU']==cpu;totals['initial_CPU_frames_checked']+=1
        for row in p['initial_RAM']:
            a=int(row['address'],16);b=bytearray(initial_page(s,a))
            if 0x62000000<=a<a+4096<=0x62020000 and 'stack_fill_u8'in p['configuration']:b[:]=bytes([p['configuration']['stack_fill_u8']])*4096
            for addr,raw in parent_inputs()+extra_inputs():
                if a<=addr<addr+len(raw)<=a+4096:b[addr-a:addr-a+len(raw)]=raw
            assert unpack(row['payload'])==bytes(b);totals['initial_RAM_B_checked']+=4096
        r=Replay(p,e['source_spans'],s);totals.update(r.run());o=oracle(p,r,s,prior);oracles.append(o);totals['oracle_seed_words_checked']+=o['oracle_seed_words_checked']
    counts={'profiles':len(e['profiles']),**{k:sum(len(p[k])for p in e['profiles'])for k in ['visits','reads','writes','PAC_models','models','points','metadata_returns','daemon_children',
      'handoffs','lock_events','transactions','certificate_events','constructor_points']},**{k:sum(p[k]for p in e['profiles'])for k in ['bootstrap_calls','certificate_allocation_attempts','entropy_calls','clock_calls','seed_iterations']}};assert counts==e['verified_counts']
    src=source_proofs({'source_spans':[s.function(ENTRY)]},s)
    routes=source_contracts({},s,{'prefix':{'result':{'visited_original_instructions':[v['pc']for v in e['profiles'][0]['visits']]}}})
    sdk=sdk_checks();d=json.loads(read(ROOT/'corefp_cold_seed_ida.json'));live=[];unavailable=[]
    assert not d['IDB_mutated']and not d['native_target_executed']and all(d[k]['count']==0 and not d[k]['truncated']for k in ['CoreFP_recall','daemon_recall'])
    for row in d['bytes']['results']:
        raw=bytes.fromhex(row['bytes'])
        if row['address']=='0x1d44409':
            assert len(raw)==row['size_read']==0 and row['size_requested']==1;unavailable.append({'address':row['address'],'size_requested_B':1,'size_read_B':0,'original_image_byte_hex':s.read(0x1d44409,1).hex()});continue
        assert raw==s.read(int(row['address'],16),len(raw))and len(raw)==row['size_read']==row['size_requested'];live.append({'address':row['address'],'size_B':len(raw),'sha256':SHA(raw)})
    contracts={}
    for name,receipt_name in [('audit_fpsd1201_seed.py','fpsd1201_seed_audit.json'),('audit_fpsd1201_key_routes.py','fpsd1201_key_routes_audit.json')]:
        h=SHA(read(ROOT/name).encode());assert h==json.loads(read(ROOT/receipt_name))['auditor_sha256'];contracts[name]=h
    result={'verified_counts':counts,'independent_client_replay':dict(totals),'compact_oracle_profiles':len(oracles),'client_source_spans':len(e['source_spans']),
      'client_source_B_checked':sum(len(bytes.fromhex(v['bytes']))for v in e['source_spans']),'live_B_checked':sum(v['size_B']for v in live),
      'source_queries_unsat':len(src['proofs'])+len(routes['proofs']),'exact_instructions_checked':src['exact_instructions_checked']+routes['exact_instructions_checked'],'SDK_compile_exit':0,'native_target_executed':False,'all_checks_pass':True}
    out={'result':result,'checks_sha256':SHA(read(ROOT/'corefp_cold_seed_checks.json').encode()),'auditor_sha256':SHA(Path(__file__).read_bytes()),
      'IDA_readback_sha256':SHA(read(ROOT/'corefp_cold_seed_ida.json').encode()),'dependencies':e['dependencies'],'frozen_contract_modules':contracts,'oracles':oracles,
      'source_contracts':src,'source_route_contracts':routes,'SDK_assertions':sdk,'live_byte_ranges':live,'IDA_reads_without_backing_bytes':unavailable,'semantic_annotations_used_as_proof':False,'source_PC_gap':False,
      'restored_parent_frame':False,'fresh_replay_completed':True,'process_exit_code':0}
    (ROOT/'corefp_cold_seed_audit.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(result),flush=True)


if __name__=='__main__':main()
