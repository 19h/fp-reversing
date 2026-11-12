#!/usr/bin/env python3
"""Independent cold parent replay, cleanup-record oracle and source contracts.

Does not import the new producer. Reconstructs complete initial touched RAM,
checks every retained client transition/access and independently repeats the
daemon rejection through the frozen driver. Native ownership remains unknown.
O(C*(B+F+V+J+R)) time/space; 30000 client visits, 30 s per SMT query.
"""
import json,struct,copy,subprocess
from pathlib import Path
from hashlib import sha256
from collections import Counter
import z3
from unicorn import arm64_const as A
from audit_corefp_cold_metadata import Replay as Frozen,CS,frame,restore,ret,unpack
from audit_corefp_lookup_initialization import initial_page,declared_inputs
from corefp_fixups_reader import Pointers,ROOT,THIN_SHA
from probe_corefp_exports import BASE
from daemon_receive_tools import SOURCE
from verify_daemon_reader_record_payloads_publication import read

SHA=lambda b:sha256(b).hexdigest();M64=(1<<64)-1
ENTRY=0x8e81c8;PARENT=0x63000800;DATA=0x63000900;AUX=0x63000c00;CURSOR=0x63000e00;DONE=0x65000000;HEAP=0x64000000


def parent_inputs():
    p=PARENT;c=0x08ae71402ff5057c;mix=(((p|c)-p+(p&0xf7518ebfd00afa83))&M64)^0x8c1900eef68afb44;k=mix*0xfcf33521&M64
    b=bytearray(b'\xa5'*48);b[8:16]=DATA.to_bytes(8,'little');b[20:24]=((k+0xc1f7)&0xffffffff).to_bytes(4,'little')
    b[24:28]=(k&0xffffffff).to_bytes(4,'little');b[32:40]=AUX.to_bytes(8,'little')
    return [(PARENT,bytes(b)),(DATA,b'\0'*128),(AUX,b'\0'*128),(CURSOR,b'\0'*8)]


class Replay(Frozen):
    def __init__(self,p,spans,s):
        super().__init__(p,spans,s);self.hi=self.li=self.cert=0;self.held=None;self.lookup_pointer=None
    def handoff(self,want):assert want==self.p['handoffs'][self.hi];self.hi+=1
    def checkpoint(self,label):
        row={**self.snapshot(label),'parent_record48_hex':self.ram(PARENT,48).hex(),'cursor_u64':hex(int.from_bytes(self.ram(CURSOR,8),'little')),
          'held_lock_model':None if self.held is None else hex(self.held),'visits_so_far':self.v,'models_so_far':self.mi}
        if self.lookup_pointer:
            raw=self.ram(self.lookup_pointer,32);a,b=struct.unpack_from('<QQ',raw,8)
            row.update({'lookup_record':hex(self.lookup_pointer),'lookup_record32_hex':raw.hex(),'lookup_output_addresses':[hex(a),hex(b)],
              'lookup_output_words':[int.from_bytes(self.ram(a,4),'little'),int.from_bytes(self.ram(b,4),'little')]})
        return row
    def ledger(self,kind,status):
        pointer=self.u.reg_read(A.UC_ARM64_REG_X0);want={'kind':kind,'CPU':frame(self.u),'pointer':hex(pointer),'callsite':hex(self.u.reg_read(A.UC_ARM64_REG_LR)-4-BASE),'status_u32':status}
        assert want==self.p['lock_events'][self.li];self.li+=1
    def code(self,u,pc,n,d):
        self.flush();cfg=self.p['configuration']
        if pc==DONE:
            assert self.p['frontier']=={'reason':'parent_return','CPU':frame(u)}
            want={**self.snapshot('parent_return'),'parent_record48_hex':self.ram(PARENT,48).hex(),'cursor_u64':hex(int.from_bytes(self.ram(CURSOR,8),'little')),
              'held_lock_model':None if self.held is None else hex(self.held)};assert self.p['parent_return']==want;self.done=True;u.emu_stop();return
        if pc==BASE+0x1cdb24:
            assert self.lookup_pointer is None;self.lookup_pointer=u.reg_read(A.UC_ARM64_REG_X0);self.handoff(self.checkpoint('source_lookup_entry'))
        if pc==BASE+0x8e8520:self.handoff(self.checkpoint('source_lookup_return'))
        if pc in [BASE+0x457838,BASE+0x1be978]:
            r=u.reg_read(A.UC_ARM64_REG_X0);self.handoff({'label':'cleanup_wrapper_entry'if pc==BASE+0x457838 else 'unlock_helper_entry',
              'CPU':frame(u),'record':hex(r),'record16_hex':self.ram(r,16).hex(),'caller_callsite':hex(u.reg_read(A.UC_ARM64_REG_LR)-4-BASE)})
        name=self.imports.get(pc)
        if name=='_pthread_rwlock_wrlock':assert self.held is None;self.held=u.reg_read(A.UC_ARM64_REG_X0);self.ledger('declared_acquire',0)
        if name=='_pthread_rwlock_unlock'or name=='_malloc'and u.reg_read(A.UC_ARM64_REG_LR)-4-BASE==0x249368:
            args=[u.reg_read(getattr(A,'UC_ARM64_REG_X'+str(j)))for j in range(8)];e=self.event()
            assert e['kind']=='declared_API'and e['name']==name and e['args_x0_x7']==list(map(hex,args))and e['callsite']==hex(u.reg_read(A.UC_ARM64_REG_LR)-4-BASE)
            if name=='_malloc':assert args[0]==760;self.cert+=1;value=0
            else:
                assert args[0]==self.held and e['callsite']=='0x1becc8';value=cfg['unlock_status_u32'];self.ledger('declared_release',value)
                if value==0:self.held=None
            self.effects(e,[]);assert e['return_u64']==hex(value);f=ret(e['before'],value,cfg.get('clobber_callers',False));assert e['after']==f;restore(u,f);return
        return super().code(u,pc,n,d)
    def run(self):
        self.u.emu_start(BASE+ENTRY,0,count=30001);self.flush();assert self.done and not self.once
        assert [self.v,self.r,self.w,self.pac,self.mi,self.pi,self.hi,self.li,self.mri,self.di,self.bi,self.cert]==[len(self.p[k])for k in ['visits','reads','writes','PAC_models','models','points','handoffs','lock_events','metadata_returns','daemon_children']]+[self.p['bootstrap_calls'],self.p['certificate_allocation_attempts']]
        assert self.allocs==self.p['allocations_attempted']==2 and self.snapshot('frontier')==self.p['final_state']
        for row in self.p['final_RAM']:assert self.ram(int(row['address'],16),4096)==unpack(row['payload'])
        return {'visits_checked':self.v,'reads_checked':self.r,'writes_checked':self.w,'PAC_models_checked':self.pac,'models_checked':self.mi,'points_checked':self.pi,
          'handoffs_checked':self.hi,'lock_events_checked':self.li,'metadata_returns_checked':self.mri,'daemon_children_fresh_checked':self.di,'bootstrap_calls_checked':self.bi,
          'certificate_allocation_attempts_checked':self.cert,'parent_returns_checked':1,'final_RAM_B_checked':4096*len(self.p['final_RAM'])}


def oracle(p):
    c=p['configuration'];label=c['label'];failed=label in ['lookup_error','fallback_error'];primary=label not in ['fallback_null','lookup_error','fallback_error']
    sequence=[(5,None)]if label=='lookup_error'else [(1102,None),(5,None)]if label=='fallback_error'else [(1102,None),(0,0x5034)]if label=='fallback_null'else [(0,0x5017)]
    assert c=={'label':label,'allocation_success':[label!='static_null',True],'lock_init_status_u32':[0,0],'continue_to_bootstrap':True,
      'bootstrap_results':[{'status_u32':s,**({'write_port_u32':v}if v is not None else {})}for s,v in sequence],'unlock_status_u32':5 if label=='unlock_error'else 0,
      **({'clobber_callers':True}if label=='clobber_null'else {})}
    entry,lookup,wrapper,helper=p['handoffs'];assert [v['label']for v in p['handoffs']]==['source_lookup_entry','source_lookup_return','cleanup_wrapper_entry','unlock_helper_entry']
    r=int(entry['lookup_record'],16);raw=bytes.fromhex(entry['lookup_record32_hex']);key=((r&0xffffffff)^0x8b4ea7c9)*0x0bcb7857&0xffffffff
    assert (int.from_bytes(raw[28:],'little')-key)&0xffffffff==0xba27 and (raw[24]-key)&255==9
    expected_outputs=[0xa5a5a5a5]*2 if failed else [0x5017,10]if primary else [0x5034,0]
    assert lookup['lookup_output_words']==expected_outputs and lookup['lookup_record32_hex'][:8]==(0x45e2a2e3 if failed else 0xba1df9db).to_bytes(4,'little').hex()
    assert wrapper['caller_callsite']=='0x8fc3f0'and helper['caller_callsite']=='0x457aa0'
    w=int(wrapper['record'],16);wb=bytes.fromhex(wrapper['record16_hex']);wkey=((w&0xffffffff)^0x8b4ea7c9)*0x0bcb7857&0xffffffff;control=(int.from_bytes(wb[:4],'little')-wkey)&0xffffffff;assert control==0x97413dbe
    q=int(helper['record'],16);b=bytes.fromhex(helper['record16_hex']);assert q%8==0
    h=((((~((q&0xffffffff)^0xff481ff8))&0xffffffff)^0x17d12dda)*0xb7a7bfff)&0xffffffff
    assert int.from_bytes(b[8:12],'little')^h==0x4cfa and (control+0x68bf0f3c)&0xffffffff==0x4cfa
    supplied=0 if label=='static_null'else HEAP;assert int.from_bytes(b[:8],'little')==supplied
    pointer=BASE+0x1d27bf0 if not supplied else supplied;assert [v['pointer']for v in p['lock_events']]==[hex(pointer)]*2
    target_reads=[x for x in p['reads']if p['visits'][x['visit']]['pc']=='0x4579ac'];assert len(target_reads)==1 and target_reads[0]['address']==hex(BASE+0x1d444a8)and int.from_bytes(bytes.fromhex(target_reads[0]['bytes_hex']),'little')==supplied
    helper_access=[x for x in p['reads']if 0x1be978<=int(p['visits'][x['visit']]['pc'],16)<0x1becf8 and q<=int(x['address'],16)<q+16]
    assert [(int(x['address'],16)-q,x['size_B'])for x in helper_access]==[(8,4),(0,8)]
    status=0x45e2a2e3 if failed else 0x45e2a20f;before=parent_inputs()[0][1];assert p['parent_return']['parent_record48_hex']==(status.to_bytes(4,'little')+before[4:]).hex()
    assert p['parent_return']['CPU']['X31'][0]==hex(c['unlock_status_u32'])and p['parent_return']['cursor_u64']=='0x100'
    advances=[x for x in p['writes']if int(x['address'],16)<=CURSOR<int(x['address'],16)+x['size_B']]
    assert len(advances)==1 and advances[0]['address']==hex(CURSOR)and advances[0]['size_B']==8 and advances[0]['before_hex']=='00'*8 and advances[0]['after_hex']=='0001000000000000'
    assert p['visits'][advances[0]['visit']]['pc']=='0x8e830c'and advances[0]['visit']<entry['visits_so_far']
    assert p['parent_return']['held_lock_model']==(hex(pointer)if c['unlock_status_u32']else None)
    assert p['parent_return']['CPU']['SP']==p['initial_CPU']['SP']and p['parent_return']['CPU']['X31'][19:31]==p['initial_CPU']['X31'][19:31]
    assert p['certificate_allocation_attempts']==int(not failed)and len(p['daemon_children'])==int(primary)
    names=[x.get('name')for x in p['models']];assert names.count('_pthread_rwlock_wrlock')==names.count('_pthread_rwlock_unlock')==1 and names.count('_pthread_once')==3
    assert '_mach_port_deallocate'not in names and '_free'not in names
    return {'label':label,'decoded_lookup_tag_u32':'0xba27','decoded_lookup_flag_u8':9,'decoded_cleanup_wrapper_control_u32':hex(control),
      'decoded_unlock_control_u32':'0x4cfa','unlock_record_accessed_extent_B':12,'supplied_lock_pointer':hex(supplied),'acquired_released_pointer':hex(pointer),
      'raw_parent_result_u32':hex(status),'final_X0':hex(c['unlock_status_u32']),'caller_u64_word_after':'0x100','caller_word_restored_on_failure':False,'native_unlock_success_established':False}


def source_checks(s):
    p=z3.BitVec('unlock_record_low32',32);helper=((~(p^0xff481ff8))^0x17d12dda)*0xb7a7bfff
    wrapper=(((p|0x0a90cea5)+(0xf56f315a|~p))^0x1df60379)*0xb7a7bfff;simple=(p^0x1766cddd)*0xb7a7bfff
    proofs=[]
    for label,domain,left,right in [('helper_key_all32',True,helper,simple),('aligned_wrapper_helper_key',p&7==0,wrapper,helper)]:
        sol=z3.Solver();sol.set(timeout=30000);sol.add(domain,left!=right);assert sol.check()==z3.unsat;proofs.append({'label':label,'query':sol.to_smt2(),'result':'unsat'})
    sol=z3.Solver();sol.set(timeout=30000);sol.add(wrapper!=helper);assert sol.check()==z3.sat;v=sol.model().eval(p,model_completion=True)
    counterexample={'query':sol.to_smt2(),'result':'sat','unaligned_low32':hex(v.as_long()),'wrapper_key_u32':hex(z3.simplify(z3.substitute(wrapper,(p,v))).as_long()),'helper_key_u32':hex(z3.simplify(z3.substitute(helper,(p,v))).as_long())}
    assert v.as_long()%2==1
    exact={0x457968:('ldr','w0, [x0]'),0x4579ac:('ldur','x16, [x16, #-4]'),0x4579f4:('str','x16, [sp, #8]'),0x457a00:('str','w16, [sp, #0x10]'),
      0x457aa0:('blraa','x8, x17'),0x1beab8:('ldr','w12, [x0, #8]'),0x1beac0:('ldr','x19, [x0]'),0x1becc0:('mov','x0, x19'),0x1becc8:('blraa','x8, x17'),
      0x8fc3f0:('blraa','x8, x17'),0x8fc404:('str','w8, [x24]'),0x8e8304:('ldr','x9, [x1]'),0x8e8308:('add','x9, x9, #0x100'),0x8e830c:('str','x9, [x1]')}
    for a,want in exact.items():i=next(CS.disasm(s.read(a,4),a));assert (i.mnemonic,i.op_str)==want
    # On the normal epilogues the unlock result survives in X0, while W8
    # supplies the separate parent record result. Stack-check failure excluded.
    for a,b in [(0x1beccc,0x1becf8),(0x457aa4,0x457ac8),(0x8fc3f4,0x8fc444)]:
        for i in CS.disasm(s.read(a,b-a),a):assert not any(x in i.op_str.replace(',',' ').replace('[',' ').replace(']',' ').split()for x in ['x0','w0'])
    refs={name:[{'slot':hex(a),'row':r}for a,r in s.decoded.items()if not r['bind']and int(r['target'],16)==target]for name,target in [('unlock_helper',0x1be978),('cleanup_wrapper',0x457838),('lock_helper',0x20f37c)]}
    assert [v['slot']for v in refs['unlock_helper']]==['0x1d03798']and [v['slot']for v in refs['cleanup_wrapper']]==['0x1d04f38']
    code='#include <pthread.h>\n_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_rwlock_unlock),int(*)(pthread_rwlock_t*)),"unlock_prototype");\n'
    command=['xcrun','clang','-target','arm64e-apple-macos14','-fsyntax-only','-x','c','-'];r=subprocess.run(command,input=code,text=True,capture_output=True,timeout=30);assert r.returncode==0,r.stderr
    sdk=Path(subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip());header=(sdk/'usr/include/pthread.h').read_bytes()
    return {'proofs':proofs,'outside_alignment_counterexample':counterexample,'exact_instructions_checked':len(exact),'reference_rows':refs,
      'ABI_compile':{'command':command,'source':code,'exit_code':r.returncode,'stderr':r.stderr,'emitted_artifact':False,
        'header':{'SDK_relative_header':'usr/include/pthread.h','size_B':len(header),'sha256':SHA(header)}}}


def main():
    e=json.loads(read(ROOT/'corefp_lookup_release_checks.json'));s=Pointers();assert e['thin_sha256']==THIN_SHA and e['daemon_thin_sha256']==SHA(SOURCE.read_bytes())
    assert e['generator_sha256']==SHA((ROOT/'recover_corefp_lookup_release.py').read_bytes())
    for n,h in e['dependencies'].items():assert SHA(read(ROOT/n).encode())==h
    assert e['declared_inputs']==[{'address':hex(a),'bytes_hex':b.hex()}for a,b in declared_inputs()+parent_inputs()]
    auth=next(r for r in s.meta['sections']if r['section']=='__auth_stubs')
    for f in e['source_spans']:
        a,b=int(f['start'],16),int(f['end'],16)
        if 'kind'in f:assert f['kind']=='complete_import_stub_16B'and b-a==16 and (a-auth['address'])%16==0 and f['bytes']==s.read(a,16).hex()and f['sha256']==SHA(s.read(a,16))
        else:assert f==s.function(a)
    totals=Counter();oracles=[]
    assert [p['configuration']['label']for p in e['profiles']]==['primary_null','fallback_null','static_null','clobber_null','unlock_error','lookup_error','fallback_error']
    for p in e['profiles']:
        cpu={'X31':[hex(((j+1)*0x123456789abcdef)&M64)for j in range(31)],'Q32':[hex(int.from_bytes(bytes([j])*16,'little'))for j in range(32)],
          'SP':'0x62018000','PC':hex(BASE+ENTRY),'NZCV':'0x60000000','FPCR':'0x0','FPSR':'0x0','CPACR_EL1':'0x300000'}
        cpu['X31'][0]=hex(PARENT);cpu['X31'][1]=hex(CURSOR);cpu['X31'][30]=hex(DONE);assert p['initial_CPU']==cpu;totals['initial_CPU_frames_checked']+=1
        for row in p['initial_RAM']:
            a=int(row['address'],16);b=bytearray(initial_page(s,a))
            for addr,raw in parent_inputs():
                if a<=addr<addr+len(raw)<=a+4096:b[addr-a:addr-a+len(raw)]=raw
            assert unpack(row['payload'])==bytes(b);totals['initial_RAM_B_checked']+=4096
        replay=Replay(p,e['source_spans'],s);totals.update(replay.run());oracles.append(oracle(p))
    counts={'profiles':len(e['profiles']),**{k:sum(len(p[k])for p in e['profiles'])for k in ['visits','reads','writes','PAC_models','models','points','metadata_returns','daemon_children','handoffs','lock_events']},
      'bootstrap_calls':sum(p['bootstrap_calls']for p in e['profiles']),'certificate_allocation_attempts':sum(p['certificate_allocation_attempts']for p in e['profiles'])};assert counts==e['verified_counts']
    source=source_checks(s);d=json.loads(read(ROOT/'corefp_lookup_release_ida.json'));live=[]
    assert d['target']=='c3d025e56a86'and not d['IDB_mutated']and not d['native_target_executed']and d['recall']['count']==0 and not d['recall']['truncated']
    for v in d['bytes']['results']:
        raw=bytes.fromhex(v['bytes']);assert raw==s.read(int(v['address'],16),len(raw))and len(raw)==v['size_read']==v['size_requested'];live.append({'address':v['address'],'size_B':len(raw),'sha256':SHA(raw)})
    xrefs={v['address']:v['xrefs_to']for v in d['xrefs']['results']};assert [v['from']for v in xrefs['0x1be978']]==['0x1d03798']and [v['from']for v in xrefs['0x457838']]==['0x1d04f38']
    assert xrefs['0x1d444a8']==[]and [v['from']for v in xrefs['0x1d27bf0']]==['0x1d383d8']
    result={'verified_counts':counts,'independent_client_replay':dict(totals),'compact_oracle_profiles':len(oracles),'client_source_spans':len(e['source_spans']),
      'client_source_B_checked':sum(len(bytes.fromhex(v['bytes']))for v in e['source_spans']),'live_B_checked':sum(v['size_B']for v in live),
      'daemon_source_visits_fresh_checked':sum(len(c['visited_original_instructions'])for p in e['profiles']for c in p['daemon_children']),
      'daemon_steps_including_return':sum(c['steps']for p in e['profiles']for c in p['daemon_children']),
      'queries_unsat':2,'unaligned_counterexamples_sat':1,'exact_instructions_checked':source['exact_instructions_checked'],'ABI_compile_exit':0,'native_target_executed':False,'all_checks_pass':True}
    out={'result':result,'checks_sha256':SHA(read(ROOT/'corefp_lookup_release_checks.json').encode()),'auditor_sha256':SHA(Path(__file__).read_bytes()),
      'IDA_readback_sha256':SHA(read(ROOT/'corefp_lookup_release_ida.json').encode()),'dependencies':e['dependencies'],'oracles':oracles,'source_checks':source,
      'live_byte_ranges':live,'semantic_annotations_used_as_proof':False,'full_daemon_CPU_RAM_replayed':False,'fresh_replay_completed':True,'process_exit_code':0}
    (ROOT/'corefp_lookup_release_audit.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(result),flush=True)


if __name__=='__main__':main()
