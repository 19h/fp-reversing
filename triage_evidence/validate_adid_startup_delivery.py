#!/usr/bin/env python3
"""Verify original startup/lifecycle evidence and checkpoint equivalence.

Fresh files, static tools, clang, local SMT and explicit private Unicorn models
only. No target/native API/IPC/file/environment/signal operation executes.
O(B+F+R+V) readback time/space; replay has its declared source hook cap and
SMT queries have independent 30 s caps.
"""
import base64
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import zlib
from adid_reader import Adid,ROOT,CS,sha,SOURCE,FIXUPS,THIN_SHA
from probe_adid_startup import Startup,unpack_records


def read(name):return json.loads((ROOT/name).read_text())
def visits(row):
    if 'visited_original_instructions' in row:return [int(a,16) for a in row['visited_original_instructions']]
    raw=zlib.decompress(base64.b64decode(row['visited_original_instructions_zlib_base64']));assert len(raw)==row['visited_original_instruction_count']*8
    return [a[0] for a in struct.iter_unpack('<Q',raw)]


def main():
    checks=[]
    def check(condition,description):
        assert condition,description
        checks.append(description)
    s=Adid();p=read('adid_startup_profiles.json');c=read('adid_startup_contracts.json');rows={r['fixture']['label']:r for r in p['profiles']};events={k:unpack_records(v) for k,v in rows.items()}
    check(p['thin_sha256']==c['thin_sha256']==THIN_SHA,'fresh original provider identity')
    check(p['generator_sha256']==sha((ROOT/'probe_adid_startup.py').read_bytes()) and c['generator_sha256']==sha((ROOT/'recover_adid_startup.py').read_bytes()),'producer/static source pins')
    for source in (p,c):
        for name,digest in source['dependencies'].items():check(sha((ROOT/name).read_bytes())==digest,'dependency '+name)
    run=subprocess.run(['/usr/bin/dyld_info','-arch','arm64e','-fixups',str(SOURCE)],capture_output=True,check=True);check(run.stdout==FIXUPS.read_bytes(),'fresh independent pointer-tool output')
    for name,digest in p['checkpoint_sha256s'].items():
        check(sha((ROOT/name).read_bytes())==digest,'checkpoint pin '+name);ck=read(name)
        check(ck['source_thin_sha256']==THIN_SHA and not ck['native_state'],'private source checkpoint scope '+name)
        for region in ck['regions']:
            raw=zlib.decompress(base64.b64decode(region['bytes_zlib_base64']));check(len(raw)==region['size_bytes'] and sha(raw)==region['sha256'],'checkpoint mutable region '+name+':'+region['address'])
        check(set(ck['registers'])=={f'X{i}' for i in range(31)}|{f'Q{i}' for i in range(32)}|{'SP','PC','NZCV','FPCR','FPSR','CPACR_EL1'},'explicit checkpoint register set '+name)
        check(ck['source_ordered_instruction_sha256']==rows[ck['source_profile']]['ordered_original_instruction_sha256'],'checkpoint source trace '+name)
    instruction_bytes={}
    for i in p['original_instruction_records']:
        pc=int(i['ea'],16);raw=s.read(pc,4);d=next(CS.disasm(raw,pc));check(raw.hex()==i['bytes'] and d.mnemonic==i['mnemonic'] and d.op_str==i['operands'],'original instruction '+i['ea']);instruction_bytes[pc]=raw
    for f in p['original_functions']:
        a,z=int(f['start'],16),int(f['end'],16);check(s.bounds(a)==(a,z) and sha(s.read(a,z-a))==f['sha256'],'original compiler bounds/hash '+f['start'])
    total=0
    for label,row in rows.items():
        vv=visits(row);total+=len(vv);h=hashlib.sha256()
        for pc in vv:h.update(struct.pack('<Q',pc));h.update(instruction_bytes[pc])
        check(h.hexdigest()==row['ordered_original_instruction_sha256'],'ordered original-byte visits '+label)
        check(row['steps']<=row['fixture'].get('instruction_budget',100000)+1,'finite hook bound '+label)
        for e in events[label]:
            if e['kind'] in ('modeled_API','startup_modeled_API'):check(e['name'] in row['fixture']['model_APIs'] and not e['native_API_executed'],'declared private API '+label+':'+e['name'])
            if e['kind']=='original_private_global_write':
                a=int(e['address'],16);check(any(seg['name']=='__DATA' and seg['address']<=a and a+e['size_bytes']<=seg['address']+seg['vm_size'] for seg in s.meta['segments']),'owned source-global write '+label)
            if e['kind']=='modeled_vector_XOR3':
                a,b,d=[int(v,16) for v in e['input_u128']];check(int(e['output_u128'],16)==a^b^d and not e['native_instruction_executed'],'private source XOR3 '+label)
    for f in ('VMM_original_function','signal_original_function'):check(s.function(int(c[f]['start'],16))==c[f],'complete original function '+f)
    for w in c['original_windows']:
        a,z=int(w['start'],16),int(w['end'],16);raw=s.read(a,z-a)
        check(raw.hex()==w['bytes'] and sha(raw)==w['sha256'],'original window '+w['role'])
        check([{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(raw,a)]==w['instructions'],'fresh window decode '+w['role'])
    for ptr in c['source_import_pointers']+[r['pointer'] for r in c['write_branch_pointers']]:check(s.decoded[int(ptr['address'],16)]==ptr,'original chain member '+ptr['address'])
    for proof in c['proofs']:
        path=ROOT/proof['path'];check(sha(path.read_bytes())==proof['sha256'],'SMT source pin '+path.name)
        run=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);check(run.stdout.strip()=='unsat' and not run.stderr,'fresh full-domain local proof '+path.name)
    def ev(label,name=None,kind=None):return [e for e in events[label] if (name is None or e.get('name')==name) and (kind is None or e['kind']==kind)]
    account=c['provider_account_declaration'];raw=Path(account['path']).read_bytes()
    check(sha(raw)==account['sha256'] and account['literal_record'] in raw.decode().splitlines() and account['uid']==account['gid']==265 and account['home']=='/var/db/fpsd','installed account declaration independent of native credentials')
    for label in ('provider_uid_0','provider_uid_265','provider_uid_501'):check(ev(label,'_lstat')[0]['path']=='/Users/Shared/adi','controlled UID reaches first directory '+label)
    for row in rows.values():
        label=row['fixture']['label']
        for e in ev(label,kind='original_open_predicate'):check(e['threshold_u32']==0,'source signed32 open threshold '+label)
    for fd in (0,73):check(ev('record_open_'+str(fd),'_fstat')[0]['fd_signed32']==fd,'read-open descriptor accepted through fstat '+str(fd))
    check(rows['record_open_-1']['stop_reason']=='opaque_API_boundary:_os_log_type_enabled' and not ev('record_open_-1','_fstat'),'negative read-open result avoids fstat')
    for size in (0,16,31,257):
        label='migrate_record_'+str(size);raw=bytes.fromhex(rows[label]['fixture']['record_bytes_hex']);write=ev(label,'_write')[0];opens=ev(label,'_open')
        check(write['bytes']==raw.hex() and write['size_bytes']==size and ev(label,'_read')[0]['requested_bytes']==size,'exact opaque byte transfer '+str(size))
        check([e['path'] for e in opens]==['/Users/Shared/adi/adi.pb','/var/db/fpsd/adi/adi.pb'] and [e['flags_u32'] for e in opens]==[0x110,0x321] and int(opens[1]['first_variadic_stack_u64'],16)&0xffffffff==0o666,'source/destination open ABI '+str(size))
        check([e['callsite'] for e in ev(label,'_close')]==['0x100015d24','0x1000174fc'] and ev(label,'_ftruncate')[0]['size_u64']==size and len(ev(label,'_unlink'))==1,'observed transfer close/truncate/unlink order '+str(size))
        check(rows[label]['filesystem_model_final']['/var/db/fpsd/adi/adi.pb']['contents_hex']==raw.hex() and rows[label]['filesystem_model_final']['/Users/Shared/adi/adi.pb']['path_unlinked'],'private filesystem transfer model consistent '+str(size))
    for label in ('migration_short_write','migration_write_error','migration_truncate_error'):
        check(not ev(label,'_unlink') and not rows[label]['filesystem_model_final']['/Users/Shared/adi/adi.pb'].get('path_unlinked',False),'failure prefix retains source namespace '+label)
    check(ev('migration_unlink_error','_unlink')[0]['result']=='-0x1' and not rows['migration_unlink_error']['filesystem_model_final']['/Users/Shared/adi/adi.pb'].get('path_unlinked',False),'unlink failure remains distinct')
    check(rows['listener_after_short_write']['stop_reason']=='returned_to_private_fixture' and rows['listener_after_short_write']['result_u32']==0xffffffff and not ev('listener_after_short_write','_xpc_connection_create_mach_service'),'continued short-write failure returns before listener publication')
    for label in rows:
        for e in ev(label,kind='original_write_count_predicate'):
            check(e['w26']==0x24fe and e['w24']==0x2447 and e['table']=='0x1002c40c0','source write-edge prefix constants '+label)
            wr=ev(label,'_write')[0];check(e['expected_u64']==wr['size_bytes'] and e['result_u64']==int(wr['result'],16)&((1<<64)-1),'full64 write result/count operands '+label)
    for label,value in [('postinit_VMM_0',9),('postinit_VMM_1',10),('postinit_VMM_2',9),('postinit_VMM_error',9)]:
        check(ev(label,kind='original_VMM_result_byte')[0]['value_u8']==value and rows[label]['stop_reason']=='startup_opaque_API_boundary:_kqueue','VMM output byte and event-loop continuation '+label)
    label='listener_setup';signal=ev(label,'_signal')[0];kevent=ev(label,'_kevent')[0];fd=ev(label,'_CFFileDescriptorCreate')[0];listener=ev(label,'_xpc_connection_create_mach_service')[0]
    check(signal['signal_u32']==15 and signal['handler']=='0x1','SIGTERM BSD handler request is SIG_IGN')
    check(struct.unpack('<QhHIqQ',bytes.fromhex(kevent['changes_bytes']))==(15,-6,5,0,0,0) and kevent['change_count']==1 and kevent['event_capacity']==0,'original SIGTERM EVFILT_SIGNAL registration ABI')
    check(fd['callback']=='0x100045bdc' and fd['close_on_invalidate_boolean']==1 and fd['context40_bytes'] is None,'original CF descriptor callback/close/context contract')
    check(listener['name_string']=='com.apple.adid' and listener['args_x0_x7'][1:3]==['0x7c007c00','0x1'],'main dispatch queue and listener-flag endpoint')
    handler=ev(label,'_xpc_connection_set_event_handler')[0];block=bytes.fromhex(handler['block48_bytes']);descriptor=struct.unpack_from('<Q',block,24)[0]
    check(struct.unpack_from('<Q',block,16)[0]==0x1000009f8 and struct.unpack_from('<Q',block,32)[0]==0x7c007c00 and s.qword(descriptor+8)==40,'source-created main listener block invokes peer setup and captures queue')
    check(ev(label,'_xpc_connection_activate')[0]['callsite']=='0x10001a980' and rows[label]['stop_reason']=='startup_opaque_API_boundary:_CFRunLoopRun','source activation reaches CFRunLoopRun')
    for label in ('signal_SIGTERM_VMM_0','signal_SIGTERM_VMM_1'):
        check(rows[label]['stop_reason']=='returned_to_private_fixture' and ev(label,'_CFFileDescriptorInvalidate')[0]['callsite']=='0x100048dd8' and ev(label,'_CFRunLoopStop')[0]['callsite']=='0x100048e68','SIGTERM consumer invalidates and stops under query fixture '+label)
    for label in ('signal_no_events','signal_kevent_error','signal_other_ident'):check(rows[label]['stop_reason']=='returned_to_private_fixture' and not ev(label,'_CFRunLoopStop'),'non-SIGTERM/empty/error local behavior '+label)
    unmaps=ev('loop_return_unmap','_munmap');check([e['args_x0_x7'][:2] for e in unmaps]==[['0x7e000000','0x10000'],['0x7e010000','0x10000']] and rows['loop_return_unmap']['private_mappings_final']==[] and rows['loop_return_unmap']['stop_reason']=='returned_to_private_fixture','normal private loop return retires both owned pools')
    check(rows['receiver_before_getuid_same_models']['stop_reason']=='unresolved_private_memory_boundary' and rows['receiver_after_listener_setup']['stop_reason']=='startup_opaque_API_boundary:_lstat' and ev('receiver_after_listener_setup','_lstat')[0]['path']=='/var/db/fpsd/adi','matched entry/models distinguish incomplete and later initialization states')
    peer=ev('linked_peer_setup','_xpc_connection_set_event_handler')[0];b=bytes.fromhex(peer['block48_bytes']);capture=struct.unpack_from('<Q',b,32)[0]
    check(rows['linked_peer_setup']['stop_reason']=='returned_to_private_fixture' and ev('linked_peer_setup','_xpc_connection_set_target_queue')[0]['args_x0_x7'][:2]==['0x7b00d000','0x7c007c00'] and capture==0x7b00d000 and struct.unpack_from('<Q',b,16)[0]==0x100029fc8,'original main block -> peer target queue -> original request block')
    check(rows['linked_peer_setup']['fixture_events'][0]['size_bytes']==40 and not rows['linked_peer_setup']['fixture_events'][0]['native_block_lifetime_inferred'],'explicit private block-copy boundary')
    peer_ck=read('adid_peer_checkpoint.json');heap_region=next(r for r in peer_ck['regions'] if r['address']=='0x7b000000');heap_bytes=zlib.decompress(base64.b64decode(heap_region['bytes_zlib_base64']))
    check(heap_bytes[0x300:0x328]==b[:40] and rows['linked_peer_request']['fixture']['new_args']==[0x7b000300,0x7b00d100],'captured original peer block bytes feed the linked handler entry')
    check(rows['linked_peer_request']['stop_reason']=='returned_to_private_fixture' and ev('linked_peer_request','_xpc_dictionary_set_data')[0]['payload_bytes']=='ffff4ff2' and ev('linked_peer_request','_xpc_dictionary_send_reply')[0]['callsite']=='0x1000aaa70','source-created callback chain reaches original denial reply')
    # Independent execution shape: one uninterrupted private source run must
    # equal the serialized prefix+continuation instruction stream and final RAM.
    fixture=rows['listener_setup']['fixture'];direct=Startup(s,{**fixture,'label':'independent_uninterrupted_listener_replay'});direct_row=direct.run()
    combined=visits(rows['original_main_prefix_to_getuid'])+visits(rows['listener_setup']);h=hashlib.sha256()
    for pc in combined:h.update(struct.pack('<Q',pc));h.update(instruction_bytes[pc])
    check(direct_row['ordered_original_instruction_sha256']==h.hexdigest() and direct_row['stop_reason']=='startup_opaque_API_boundary:_CFRunLoopRun','uninterrupted source replay equals serialized join')
    loop_ck=read('adid_listener_checkpoint.json')
    for region in loop_ck['regions']:
        a=int(region['address'],16);check(sha(bytes(direct.u.mem_read(a,region['size_bytes'])))==region['sha256'],'uninterrupted replay final mutable memory '+region['address'])
    for name,value in loop_ck['registers'].items():
        from unicorn import arm64_const as A
        check(direct.u.reg_read(getattr(A,'UC_ARM64_REG_'+name))==int(value,16),'uninterrupted replay final register '+name)
    layout=c['SDK_compile'];check(sha((ROOT/'adid_startup_layouts.c').read_bytes())==layout['source_sha256'] and sha((ROOT/'adid_startup_layouts.s').read_bytes())==layout['assembly_sha256'],'SDK C/assembly pins')
    with tempfile.TemporaryDirectory() as directory:
        out=Path(directory)/'layout.s';cmd=layout['command'][:-1]+[str(out)];run=subprocess.run(cmd,capture_output=True,text=True)
        check(run.returncode==0 and not run.stderr and out.read_bytes()==(ROOT/'adid_startup_layouts.s').read_bytes(),'fresh arm64e SDK flags/layout/variadic/backup compile')
    for header in c['SDK_headers']:check(sha(Path(header['path']).read_bytes())==header['sha256'],'SDK primary source '+header['path'])
    for row in read('interface_manifest.json')['inputs_preserved']:
        path=ROOT.parent/row['path'];check(path.stat().st_size==row['size_bytes'] and sha(path.read_bytes())==row['sha256'],'original supplied input preserved '+row['path'])
    counts={'private_cases':len(rows),'original_instruction_records':len(instruction_bytes),'original_compiler_ranges':len(p['original_functions']),'retained_original_visits':total,
        'full_uninterrupted_replay_steps':direct_row['steps'],'checkpoints':len(p['checkpoint_sha256s']),'SMT_unsat':len(c['proofs']),'selected_import_pointers':len(c['source_import_pointers']),
        'opaque_record_lengths_bytes':[0,16,31,257],'SDK_compile_exit':run.returncode,'assertions':len(checks)}
    (ROOT/'adid_startup_checks.json').write_text(json.dumps({'scope':__doc__,'verified_counts':counts,'all_checks_pass':True,'checks':checks,'native_target_executed':False,'full_goal_complete':False},indent=2)+'\n')
    quality={'scope':'Original startup,record transfer,VMM byte,listener/callback chain,SIGTERM and modeled return/teardown only. Broad goal active.',
        'verified_counts':counts,'native_target_executed':False,'full_goal_complete':False}
    for n,evidence in [(1,'Descriptive technical findings.'),(2,'Report S1-S8 retain assumptions,dependent results and falsification probes.'),(3,'Concrete startup/IPC/lifecycle/dataflow progress;full goal remains incomplete.'),
        (4,'Byte widths,32/64-bit predicates,three bounded SMT obligations and arm64e SDK layout/variadic contracts explicit.'),(5,'Metadata/API models,error paths,block-copy/native lifetime,query branch,partial initialization and shutdown boundaries separated.'),
        (6,'Original source/chain/instruction/SDK/account readback and independent uninterrupted-vs-checkpoint execution agree.'),(7,'Impact-labeled native pairing,record schema,remaining field semantics,error/ownership/concurrency and deeper IOKit continuation.')]:quality['QG'+str(n)]={'status':'pass_for_stated_increment','evidence':evidence}
    (ROOT/'adid_startup_quality_gates.json').write_text(json.dumps(quality,indent=2)+'\n');print(json.dumps(counts))


if __name__=='__main__':main()
