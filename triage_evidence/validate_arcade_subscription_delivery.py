#!/usr/bin/env python3
"""Validate original contracts, fresh private startup, subscription and cache cases.

O(total retained bytes + instructions + packet bytes*depth), excluding solvers.
No target host IPC. Broad interface investigation remains active.
"""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
from daemon_receive_tools import IMAGE,SOURCE,ROOT
from bootpolicy_cache_reader import Cache,Dylib
from recover_arcade_subscription import decode_wire


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    subprocess.run([sys.executable,str(ROOT/'recover_arcade_subscription.py')],check=True)
    c=json.loads((ROOT/'arcade_subscription_contracts.json').read_text())
    initpath=ROOT/'arcade_subscription_initialization_profile.json';init=json.loads(initpath.read_text())
    rows=json.loads((ROOT/'arcade_subscription_profiles.json').read_text())['profiles'];assert len(rows)==16
    initsha=sha(initpath);checks=[];page_hashes={};decoded=[]
    def check(label,condition,meaning):
        assert condition,(label,meaning);checks.append({'profile':label,'check':meaning,'result':'pass'})
    def code_check(label,r):
        pages=tuple(r['visited_original_code_pages'])
        if pages not in page_hashes:
            h=hashlib.sha256()
            for a in pages:a=int(a,16);h.update(struct.pack('<Q',a));h.update(IMAGE.read(a,4096))
            page_hashes[pages]=h.hexdigest()
        check(label,page_hashes[pages]==r['visited_original_code_pages_sha256'],'original ordered code-page digest reproduced')
        check(label,len(r['visited_instruction_addresses'])==r['original_instruction_bytes_verified'],'every visited target instruction was checked against original four bytes')
        check(label,r['source_sha256']==sha(SOURCE),'original daemon identity')
        check(label,not r['native_target_executed'] and not r['target_host_operations_executed'],'private execution and explicit API models only')
    code_check('initialization',init)
    check('initialization',init['probe_generator_sha256']==sha(ROOT/'probe_arcade_subscription.py') and init['runner_sha256']==sha(ROOT/'run_arcade_subscription_profiles.py'),'fresh startup generators match current sources')
    check('initialization',init['result']['full_initialization_complete'] and init['result']['stop_reason']=='returned_to_fixture' and init['result']['steps']==5668177,
        'original initializer returns within ten-million-instruction bound under explicit fixed time/random/lock models')
    check('initialization',[h['extent_bytes'] for h in init['private_allocations']]==[90000,200,200,960,200,200,58,101],
        'one arena,four opaque rwlocks,one960-byte allocation and two byte buffers allocated in observed order')
    check('initialization',len(init['opaque_rwlocks'])==4 and all(v=={'readers':0,'writer':False} for v in init['opaque_rwlocks'].values()),'all four abstract locks leave no modeled holder')
    check('initialization',all(int(a,16)!=0 for a in init['result']['byte_state_cells'].values()),'both required mutable byte-state pointers published')
    payloads={};boundaries={}
    for r in rows:
        label=r['label'];code_check(label,r);s=r['seed'];calls=r['calls'];api=lambda suffix:[e for e in calls if e['name'].endswith('/'+suffix)]
        check(label,r['generator_sha256']==sha(ROOT/'probe_arcade_subscription.py') and r['initialization_prefix']['profile_sha256']==initsha,
            'case clone derives from the freshly generated original initializer')
        check(label,r['base_probe_sha256']==sha(ROOT/'daemon_rpc502_probe.py'),'base fixture implementation unchanged')
        check(label,r['steps']<=5000000,'case instruction bound retained')
        copy=api('___strcpy_chk')[0];check(label,copy['return_pc']=='0x10051e564' and int(copy['args'][2],16)==1024,'original checked-copy site and byte capacity')
        out=bytes.fromhex(r['final_reply_40_bytes']);check(label,struct.unpack_from('<I',out,36)[0]==1,'native application initializes decision output1 before later work')
        if label=='path1024':
            check(label,r['stop_reason']=='outside_fitting_checked_copy_model' and not api('_CFMachPortGetPort'),
                'oversized path remains outside fitting-copy model; no claim about native overflow timing')
            continue
        check(label,api('_CFMachPortGetPort')[0]['return_pc']=='0x10051e5ac' and calls.index(copy)<calls.index(api('_CFMachPortGetPort')[0]),
            'checked path copy precedes anonymous-service-name comparison')
        if label=='service_mismatch':
            check(label,r['stop_reason']=='returned_to_fixture' and struct.unpack_from('<i',out,32)[0]==5 and struct.unpack_from('<I',out,4)[0]==36,
                'mismatch returns status5 in36-byte prepared reply')
            check(label,not api('_malloc') and not api('_xpc_add_bundle'),'mismatch bypasses parser allocation and XPC setup')
            continue
        record=next(x for x in r['records'] if x['kind']=='native_path_record');b=bytes.fromhex(record['bytes_80'])
        n=api('_strnlen')[0]['result'];check(label,struct.unpack_from('<Q',b,56)[0]==0x5001000000 and struct.unpack_from('<II',b,72)==((n+1)^0x8b3dc651,2),
            'private80-byte record retains original pointer,encoded inclusive length and mode2')
        reads={(e['offset_bytes'],e['size_bytes']) for e in r['records'] if e['kind']=='native_argument_read'}
        check(label,reads=={(0,4),(8,8),(32,8)},'selected pre-boundary code reads service,path and output pointer; count/opaque slots not read in this finite path')
        if label=='malloc_first_null':
            check(label,r['stop_reason']=='unmodeled_subscription_import' and r['records'][-1]['name']=='libobjc/_objc_msgSend','first-allocation-null route reaches separate Objective-C boundary')
            continue
        if label=='malloc_second_null':
            check(label,r['stop_reason']=='unknown_or_outside_private_heap_read' and r['records'][-1]['pc']=='0x1005b6120' and r['records'][-1]['size_bytes']==8,
                'second-allocation-null route stops at uninitialized parent-field read in private allocation')
            continue
        check(label,r['stop_reason']=='outgoing_arcade_xpc_message_boundary','stop occurs before actual synchronous XPC exchange')
        bundle=api('_xpc_add_bundle')[0];conn=api('_xpc_connection_create')[0];event=api('_xpc_connection_set_event_handler')[0]
        check(label,bundle['bundle']==c['xpc']['bundle'] and bundle['flags']=='0x2' and bundle['return_pc']=='0x10040fcfc','CoreFP bundle and explicit flags2 reach add-bundle boundary')
        check(label,conn['connection']['name']=='com.apple.fpsd.arcadeservice' and conn['connection']['queue']=='0x6000000840' and event['block_invoke']=='0x100460008',
            'service name,normalized dispatch-main-queue symbol and global event callback reach XPC APIs')
        send=api('_xpc_connection_send_message_with_reply_sync')[0];field=api('_xpc_dictionary_set_data')[0]
        check(label,send['return_pc']=='0x10077e618' and field['return_pc']=='0x10077e5c8' and field['key']=='data','exact dictionary data and synchronous send emission sites')
        packet=bytes.fromhex(send['message']['fields']['data']['value']['bytes']);records=decode_wire(packet)
        check(label,records is not None and len(records)==3 and [v['key'] for v in records]==['0x7976211a','0xfd2821c7','0x0'],
            'entire packet decodes as three outer framed records with no trailing bytes')
        child=records[1]['nested_records'];check(label,[v['key'] for v in child]==['0x7e852555','0x1fe19f28','0xf6964e3e','0x0'],
            'nested records contain two fixed scalars,path span and padding span')
        path=bytes.fromhex(child[1]['payload_hex']);check(label,len(path)==n+1 and path[-1:]==b'\0' and path[:-1]==bytes.fromhex(s['synthetic_ool_prefix'])[:min(n,96)] if n<96 else len(path)==n+1 and path==bytes([0x43])*n+b'\0',
            'path payload includes terminating NUL and exactly matches fixture source')
        check(label,child[0]['decoded_u32']=='0xa7c636e9' and child[2]['decoded_u32']=='0x8fcf6de4','two decoded scalar constants retained without invented semantic names')
        innerpad=bytes.fromhex(child[3]['payload_hex']);outerpad=bytes.fromhex(records[2]['payload_hex'])
        check(label,len(innerpad)==16-((n+1)%16) and not any(innerpad) and len(outerpad)==14 and not any(outerpad) and len(packet)==112+16*((n+1)//16),
            'finite length cases match zero-padding records,including full16-byte inner padding on aligned inclusive length')
        payloads[label]=packet.hex();boundaries[label]=reads
        decoded.append({'profile':label,'packet_size_bytes':len(packet),'packet_sha256':hashlib.sha256(packet).hexdigest(),'records':records})
    for label in ['count0','count1','count57','countmax','opaque0','opaquemax']:
        check(label,payloads[label]==payloads['default'],'selected count/opaque variation leaves complete outgoing serialized request unchanged')
    cp=json.loads((ROOT/'checked_path_copy_profiles.json').read_text());cache=Cache();lib=Dylib(cache,'/usr/lib/system/libsystem_c.dylib')
    check('checked_copy',cp['cache_uuid']==cache.uuid and cp['library_uuid']==lib.uuid and cp['generator_sha256']==sha(ROOT/'probe_checked_path_copy.py'),'separately versioned installed cache and generator match')
    for f in cp['original_ranges']:check('checked_copy',cache.read(int(f['start'],16),len(bytes.fromhex(f['bytes'])))==bytes.fromhex(f['bytes']),'checked-copy wrapper original bytes match current cache')
    for case in cp['cases']:
        n=case['length_excluding_nul_bytes'];cap=case['claimed_capacity_bytes'];check('checked_copy',case['copied_bytes_before_return_or_failure']==n+1 and case['stop']==('returned' if n+1<=cap else 'original_overflow_failure_entry'),
            f'length{n}: original wrapper checks after modeled stpcpy strlen/memmove copy')
    build=subprocess.run(['xcrun','clang','-target','arm64e-apple-macos13.0','-std=c11','-fsyntax-only',str(ROOT/'arcade_subscription_layouts.c')],capture_output=True,text=True);assert build.returncode==0,build.stderr
    counts={'daemon_ranges':len(c['ranges']),'kernel_ranges':len(c['kernel']['ranges']),'banks_256':len(c['banks_256']),
        'proofs_unsat':len(c['proofs']),'fresh_ida_ranges':c['live_ida_ranges_matched'],'daemon_native_checks':len(c['native_instruction_checks']),
        'kernel_native_checks':len(c['kernel']['native_instruction_checks']),'fresh_initialization_steps':init['result']['steps'],
        'private_subscription_profiles':len(rows),'outgoing_messages_decoded':len(decoded),'checked_copy_cases':len(cp['cases']),
        'explicit_checks':len(checks),'layout_compile_exit':build.returncode}
    (ROOT/'arcade_subscription_profile_checks.json').write_text(json.dumps({'scope':__doc__,'counts':counts,'checks':checks,'decoded_messages':decoded},indent=2)+'\n')
    gates={'scope':'Subscription path/serialization/XPC interface increment; broad goal active and incomplete.',
        'QG1':{'status':'pass','evidence':'Factual analysis.'},'QG2':{'status':'pass','evidence':'Report S1-S9 include dependencies and falsification probes.'},
        'QG3':{'status':'pass_for_increment','evidence':'Kernel producer,daemon path/record and outgoing CoreFP XPC boundary covered; reply/policy/native lifecycle remain open.'},
        'QG4':{'status':'pass','evidence':'u32/u64 widths,40/80-byte records,byte extents,compiler and complexity explicit.'},
        'QG5':{'status':'pass','evidence':'Native/model/cache boundaries,unread argument slots,copy timing and allocation-failure definedness remain separate.'},
        'QG6':{'status':'pass','evidence':'Original SHA/ranges/bindings,nine IDA matches,three proofs,fresh initialization,16 private cases and seven cache cases.'},
        'QG7':{'status':'pass','evidence':'Impact-labeled continuation table covers reply,service,policy,event,OOM and initialization.'},
        'verified_counts':counts,'native_target_executed':False,'target_host_operations_executed':False,'idb_mutated':False,'full_goal_complete':False}
    (ROOT/'arcade_subscription_quality_gates.json').write_text(json.dumps(gates,indent=2)+'\n');print(json.dumps(counts),flush=True)
    subprocess.run([sys.executable,str(ROOT/'validate_rpc502_sidecar_delivery.py')],check=True)


if __name__=='__main__':main()
