#!/usr/bin/env python3
"""Read-only cache/daemon/KC trap-boundary contracts; no target host execution.

O(B+E+H) extraction/validation time, O(B+E) retained space, streamed O(1)
auxiliary hash storage; B selected bytes, E finite evidence, H source hash bytes.
Solver cost and native callback/kernel execution costs are separate/unknown.
"""
import hashlib
import json
import struct
import subprocess
from pathlib import Path
from bootpolicy_cache_reader import Cache,Dylib,CS,ROOT,CACHE
from daemon_receive_tools import SOURCE,IMAGE
from daemon_import_bindings import binding
from kernel_native_reader import Kernel
from resolve_kernel_collection_interfaces import commands,string


def sha(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        while b:=f.read(1<<20):h.update(b)
    return h.hexdigest()


def builds(data,at=0):
    return [{'platform':struct.unpack_from('<I',data,o+8)[0],
             'minimum_os_raw':hex(struct.unpack_from('<I',data,o+12)[0]),
             'sdk_raw':hex(struct.unpack_from('<I',data,o+16)[0]),'bytes':data[o:o+n].hex()}
            for o,c,n in commands(data,at) if c==0x32]


def main():
    c=Cache();assert c.uuid=='2bd06591-e751-3e84-963f-b08dab6af23a'
    kernel=Dylib(c,'/usr/lib/system/libsystem_kernel.dylib')
    umbrella=Dylib(c,'/usr/lib/libSystem.B.dylib')
    assert kernel.uuid=='f2bceb9a-0fec-3c92-b6ea-8e37157050a8'
    dependencies=[]
    for cmd,raw in umbrella.commands:
        if cmd in [0xc,0x80000018,0x8000001f,0x80000023]:
            off=struct.unpack_from('<I',raw,8)[0]
            dependencies.append({'ordinal':len(dependencies)+1,'command':hex(cmd),
                                 'path':raw[off:].split(b'\0')[0].decode()})
    reexport=next(x for x in dependencies if x['path']==kernel.path)
    assert reexport['command']=='0x8000001f'
    names=['_mmap','_munmap','_open','_close','_fstat','_mach_msg','_mach_msg_overwrite',
           '_mach_msg2_internal','_mach_msg2_trap','_mach_msg_trap','_mach_msg_overwrite_trap',
           '_close$NOCANCEL','_open$NOCANCEL','___libkernel_voucher_init','___libkernel_init']
    extra=[0x180548a08,0x18054b724,0x180548678,0x180548934,0x1805485e0,0x1805495cc,
           0x18054dc3c,0x180547b28,0x180547b40]
    addresses=sorted({kernel.exports[n]['address'] for n in names}|set(extra))
    functions=[]
    for a in addresses:
        r=kernel.function(a);r['original_nlist']=kernel.symbols_at(a)
        r['original_exports']=[n for n,e in kernel.exports.items() if e['address']==a]
        m=c.mapping(a);r['source_file']=m['path'];r['source_offset']=hex(m['off']+a-m['va'])
        functions.append(r)
    raw_entries=[('open',0x180548678,5),('close',kernel.exports['_close']['address'],6),
      ('mmap',0x180548a08,197),('munmap',0x18054b724,73),('fstat64',kernel.exports['_fstat']['address'],339),
      ('open_nocancel',0x180548934,398),('close_nocancel',kernel.exports['_close$NOCANCEL']['address'],399),
      ('mach_msg2',kernel.exports['_mach_msg2_trap']['address'],-47),
      ('mach_msg_legacy',kernel.exports['_mach_msg_trap']['address'],-31),
      ('mach_msg_overwrite_legacy',kernel.exports['_mach_msg_overwrite_trap']['address'],-32),
      ('task_self',0x180547b40,-28),('mach_reply_port',0x180547b28,-26)]
    traps=[]
    for label,a,want in raw_entries:
        ins=list(CS.disasm(c.read(a,8),a))
        assert [i.mnemonic for i in ins]==['mov','svc'] and ins[1].op_str=='#0x80'
        assert ins[0].op_str.startswith('x16, #')
        value=int(ins[0].op_str.split('#')[1],0);assert value==want
        traps.append({'label':label,'entry':hex(a),'svc':hex(a+4),'x16_signed':value,
                      'original_bytes':c.read(a,8).hex(),'native_target_executed':False})
    globals=[]
    for a,n in [(0x1ed83e8d8,8),(0x1ed83e8f8,8),(0x1ed83e960,4),(0x1ed83e8f4,4),(0x1ed83efa8,4),
                (0x1eb065e48,8),(0x1eb065e58,8),(0x18057d1a0,48)]:
        rec={'address':hex(a),'size_bytes':n,'original_bytes':c.read(a,n).hex(),
             'original_nlist':kernel.symbols_at(a),'runtime_value':'unknown'}
        if a==0x1ed83e8d8:
            rec['original_chain_pointer']=c.pointer(a)
            assert int(rec['original_chain_pointer']['target'],16)==0x18057d1a0
        globals.append(rec)
    queries={
      'complex_descriptor_presence':'''(declare-fun bits () (_ BitVec 32))
(declare-fun send () Bool)
(define-fun sum () (_ BitVec 32) (bvadd bits #x00000001))
(define-fun n () Bool (= ((_ extract 31 31) sum) #b1))
(define-fun overflow () Bool (= bits #x7fffffff))
(define-fun gt () Bool (and (not (= sum #x00000000)) (= n overflow)))
(define-fun needs_count () Bool (not (ite send gt true)))
(assert (not (= needs_count (and send (= ((_ extract 31 31) bits) #b1)))))''',
      'packed_header_pairs':'''(declare-fun bits () (_ BitVec 32))
(declare-fun size () (_ BitVec 32))
(declare-fun remote () (_ BitVec 32))
(declare-fun local () (_ BitVec 32))
(declare-fun voucher () (_ BitVec 32))
(declare-fun id () (_ BitVec 32))
(define-fun a2 () (_ BitVec 64) (bvor ((_ zero_extend 32) bits) (bvshl ((_ zero_extend 32) size) #x0000000000000020)))
(define-fun a3 () (_ BitVec 64) (bvor ((_ zero_extend 32) remote) (bvshl ((_ zero_extend 32) local) #x0000000000000020)))
(define-fun a4 () (_ BitVec 64) (bvor ((_ zero_extend 32) voucher) (bvshl ((_ sign_extend 32) id) #x0000000000000020)))
(assert (not (and (= a2 (concat size bits)) (= a3 (concat local remote)) (= a4 (concat id voucher)))))''',
      'receive_retry_options':'''(declare-fun o () (_ BitVec 64))
(define-fun both () Bool (= (bvand o #x0000000000000003) #x0000000000000003))
(define-fun mask () (_ BitVec 64) (ite both #xffffffffffffbbbe #xfffffffffffffbbe))
(define-fun result () (_ BitVec 64) (bvand o mask))
(assert (not (and (= (bvand result #x0000000000000441) #x0000000000000000)
 (= (bvand result #x0000000000004000) (ite both #x0000000000000000 (bvand o #x0000000000004000)))
 (= (bvand result #xffffffffffffbbbe) (bvand o #xffffffffffffbbbe)))))''',
      'initial_interrupt_mask':'''(declare-fun o () (_ BitVec 64))
(define-fun result () (_ BitVec 64) (bvand o #xfffffffffffffbbf))
(assert (not (and (= (bvand result #x0000000000000440) #x0000000000000000)
 (= (bvor result (bvand o #x0000000000000440)) o))))''',
      'mmap_wrapper_gate':'''(declare-fun n () (_ BitVec 64))
(declare-fun f () (_ BitVec 32))
(define-fun native () Bool
 (ite (not (= (bvand f #x00000002) #x00000000))
      (not (= n #x0000000000000000))
      (and (not (= n #x0000000000000000)) (not (= (bvand f #x00000001) #x00000000)))))
(assert (not (= native (and (not (= n #x0000000000000000)) (not (= (bvand f #x00000003) #x00000000))))))'''}
    proofs=[]
    for name,body in queries.items():
        p=ROOT/f'user_trap_{name}.smt2';p.write_text('(set-logic QF_BV)\n'+body+'\n(check-sat)\n')
        answer=subprocess.run(['z3','-smt2',str(p)],check=True,capture_output=True,text=True).stdout.strip()
        assert answer=='unsat',(name,answer)
        proofs.append({'name':name,'path':p.name,'result':answer,'scope':'arithmetic and branch predicates only'})
    fixtures=json.loads((ROOT/'user_trap_profiles.json').read_text())
    assert fixtures['generator_sha256']==sha(ROOT/'probe_user_trap_interfaces.py')
    assert fixtures['cache_reader_sha256']==sha(ROOT/'bootpolicy_cache_reader.py')
    assert fixtures['cache_uuid']==c.uuid and fixtures['library_uuid']==kernel.uuid
    rows={r['label']:r for r in fixtures['profiles']};assert len(rows)==32
    svc=lambda label:[e for e in rows[label]['events'] if e['kind']=='intercepted_svc']
    args=lambda label,index=0:[int(a,16) for a in svc(label)[index]['args']]
    for r in rows.values():
        code_hash=hashlib.sha256()
        for page in r['source_code_pages']:
            a=int(page,16);code_hash.update(struct.pack('<Q',a));code_hash.update(c.read(a,4096))
        assert code_hash.hexdigest()==r['source_code_pages_sha256']
        assert not r['native_target_executed'] and not r['target_host_operations_executed']
        assert r['stop_reason'] not in ['unicorn_error','instruction_budget','unmodeled_code','unmodeled_next_svc_result','unmodeled_pac']
        assert r['entry']==hex(kernel.exports[r['entry_symbol']]['address'])
    for label in ['mmap_0','mmap_no_map_kind']:
        assert not svc(label) and rows[label]['tls_errno_bits']=='0x16'
        assert rows[label]['events'][-1]['x0']=='0xffffffffffffffff'
    for label in ['mmap_1','mmap_64','mmap_18446744073709551615']:
        assert svc(label)[0]['x16_signed']==197 and args(label)[3]==0x40002
        assert args(label)[1]==int(rows[label]['initial_args'][1],16)
    assert rows['mmap_error_return']['tls_errno_bits']=='0xc' and rows['fstat_error_return']['tls_errno_bits']=='0x9'
    assert rows['mmap_success_return']['events'][-1]['x0']=='0x6500000000'
    assert rows['close_error_runtime_unknown']['stop_reason']=='unknown_runtime_data'
    assert args('open_readonly')[2]==0 and args('open_create_mode_stack')[2]==0x81a4
    assert svc('fstat_boundary')[0]['x16_signed']==339 and svc('close_boundary')[0]['x16_signed']==6
    assert svc('munmap_boundary')[0]['x16_signed']==73 and svc('open_readonly')[0]['x16_signed']==5
    assert not svc('munmap_logger_boundary') and len(svc('mmap_logger_boundary'))==1
    assert [int(x,16) for x in rows['mmap_logger_boundary']['events'][-1]['args'][:6]]==[0x90,0,64,0,0x6500000000,0]
    assert [int(x,16) for x in rows['munmap_logger_boundary']['events'][-1]['args'][:6]]==[0x20,0,0x6500000000,64,0,0]
    packet_checks=[]
    for label in ['reply_simple_once','reply_simple_send','reply_complex_once','reply_voucher_v3_null',
                  'reply_voucher_callback_zero','reply_voucher_callback_nonzero','reply_complex_voucher_nonzero',
                  'send_receive_packed','receive_only_packed']:
        r=rows[label];a=args(label);bits,n,remote,local,voucher,mid=struct.unpack_from('<6I',bytes.fromhex(r['header_seed_hex']))
        original=[int(x,16) for x in r['initial_args']];desc=3 if bits&0x80000000 and original[1]&1 else 0
        vector=bool(a[1]&(1<<32));cfi=4 if r['input_seeds']['callback_result'] is not None else 8
        assert a[1]==(cfi<<32)|(original[1])|((1<<32) if vector else 0)
        assert a[2]==bits|((2 if vector else original[2])<<32)
        assert a[3]==remote|(local<<32) and a[4]==voucher|(mid<<32)
        assert a[5]==desc|(original[4]<<32)
        assert a[6]==(2 if vector else original[3])|((original[6] if original[1]&1 else 0)<<32)
        assert a[7]==original[5] and svc(label)[0]['x16_signed']==-47
        if vector:
            raw=bytes.fromhex(svc(label)[0]['private_vector_bytes_hex'])
            v0=struct.unpack_from('<QQII',raw,0);v1=struct.unpack_from('<QQII',raw,24)
            assert v0==(0x6100000000,0,80,0) and v1[1:]==(0,5,128)
        packet_checks.append({'label':label,'packet':svc(label)[0],'descriptor_count':desc,'vector':vector})
    for label,count in [('send_retry',2),('send_interrupt',1),('receive_retry',2),('receive_interrupt',1),('both_retries',3),
                        ('receive_sync_wait_both',2),('receive_sync_wait_only',2)]:
        assert len(svc(label))==count
        for ev in svc(label):assert int(ev['args'][1],16)&0x440==0
        if label in ['receive_retry','both_retries','receive_sync_wait_both','receive_sync_wait_only']:
            last=args(label,-1);first=args(label)
            assert last[1]&1==0 and last[2]==first[2]&0xffffffff and last[3:]==first[3:]
    assert args('receive_sync_wait_both',-1)[1]&0x4000==0
    assert args('receive_sync_wait_only',-1)[1]&0x4000==0x4000
    subprocess.run(['/Users/___/Downloads/zut/.venv/bin/python',str(ROOT/'audit_zut_trap_arguments.py')],check=True,capture_output=True,text=True)
    trace_audit=json.loads((ROOT/'zut_trap_argument_audit.json').read_text())
    assert trace_audit['raw_svc_records']==27 and trace_audit['matched_sends']==22
    assert len(trace_audit['identical_packet_resume_pairs'])==5
    assert trace_audit['recorded_pc_counts']=={'0x180547c20':27}
    assert c.read(0x180547c20,4).hex()=='c0035fd6'
    daemon_bindings=[binding(a) for a in [0x1010a1288,0x1010a0da8,0x1010a0f78,0x1010a06d8,0x1010a09f0]]
    assert daemon_bindings[0]['symbol']=='_mach_msg'
    pinned=json.loads((ROOT/'daemon_receive_public_sources.json').read_text())[0]
    assert pinned['path']=='xnu_osfmk_mach_message.h' and sha(ROOT/pinned['path'])==pinned['sha256']
    bp=json.loads((ROOT/'bootpolicy_backend_contracts.json').read_text())
    task_import=next(p for p in bp['port_globals'] if p['exact_original_export']=='_mach_task_self_')
    assert int(task_import['target'],16)==0x1ed83e960
    k=Kernel();v=k.read(0xfffffe0007045493,160).split(b'\0')[0].decode()
    assert v.startswith('Darwin Kernel Version 27.2.0:') and 'xnu-13432.41.4~3' in v
    so,count,st,ss=k.kernel['symtab'];wanted={'_sysent','_nsysent','_mach_trap_table','_mach_msg2_trap','_unix_syscall'}
    found=[]
    for j in range(count):
        sx,ty,se,ds,val=struct.unpack_from('<IBBHQ',k.data,so+j*16)
        if sx and sx<ss and string(k.data,st+sx) in wanted:found.append({'name':string(k.data,st+sx),'address':hex(val)})
    sdk=Path('/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk')
    command=['clang','-target','arm64e-apple-macos13.0','-isysroot',str(sdk),'-std=c11','-fsyntax-only',str(ROOT/'user_trap_layouts.c')]
    subprocess.run(command,check=True,capture_output=True,text=True)
    out={'scope':__doc__,'cache_uuid':c.uuid,'kernel_library_path':kernel.path,'kernel_library_uuid':kernel.uuid,
      'umbrella_path':umbrella.path,'umbrella_uuid':umbrella.uuid,'reexport_path':reexport,
      'static_reexport_is_runtime_binding_attestation':False,'functions':functions,'traps':traps,'globals':globals,
      'cache_source_files':[{**c.files[p],'sha256':sha(Path(p))} for p in sorted(c.used)],
      'proofs':proofs,'profiles_path':'user_trap_profiles.json','profile_count':len(rows),'packet_checks':packet_checks,
      'trace_audit':{'path':'zut_trap_argument_audit.json','raw_trap_records':27,'matching_printed_sends':22,
          'identical_packet_resume_pairs':5,'recorded_pc_is_current_ret_after_svc':True,
          'historical_library_or_producer_attested':False},
      'port_global_publication':{'initializer':'0x18054dc3c','exact_nlist':'_mach_init_doit',
          'task_self':{'call':'0x18054dc48','trap_svc':'0x180547b44','store':'0x18054dc50','cell':'0x1ed83e960','width_bytes':4},
          'reply_port':{'call':'0x18054dc54','trap_svc':'0x180547b2c','store':'0x18054dc5c','cell':'0x1ed83e8f4','width_bytes':4},
          'runtime_names_and_ownership':'unknown'},
      'daemon_original_bindings':daemon_bindings,'daemon_build_versions':builds(SOURCE.read_bytes()),
      'iokit_task_name_import':task_import,
      'cache_library_build_versions':[raw.hex() for cmd,raw in kernel.commands if cmd==0x32],
      'kernel_identity':{'sha256':k.sha256,'uuid':k.kernel['uuid'],'version_address':'0xfffffe0007045493','version':v,
         'nlist_count':count,'selected_dispatch_names_found':found,'exact_kernel_dispatch_targets_recovered':False},
      'pinned_header_reference':{**pinned,'exact_target_revision':False},
      'sdk_compile':{'command':command,'exit_code':0,'headers':[{'path':str(sdk/p),'sha256':sha(sdk/p)}
          for p in ['usr/include/sys/syscall.h','usr/include/sys/mman.h','usr/include/mach/message.h',
                    'usr/include/mach/arm/syscall_sw.h','usr/include/mach/arm/vm_param.h']]},
      'generator_sha256':sha(Path(__file__)),'native_target_executed':False,'target_host_operations_executed':False,
      'runtime_library_selection_attested':False,'full_goal_complete':False}
    (ROOT/'user_trap_contracts.json').write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'cache_functions':len(functions),'raw_traps':len(traps),'proofs_unsat':len(proofs),
       'profiles':len(rows),'source_files_hashed':len(c.used),'packet_cases':len(packet_checks),'sdk_compile':0}))


if __name__=='__main__':main()
