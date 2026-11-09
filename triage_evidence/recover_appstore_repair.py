#!/usr/bin/env python3
"""Original daemon repair adapter and reference AppStoreDaemon interfaces.

Read-only original bytes/cache metadata. No repair, notification, sleep, vproc,
framework or IPC call executes. O(B+I+F+S) extraction time/space for retained bytes,
instructions, fixups and symbol records. Runtime pairing remains unknown.
"""
import bisect
import json
from pathlib import Path
import struct
import subprocess
from daemon_receive_tools import IMAGE,SOURCE,CS,qword,FIXUPS
from daemon_import_bindings import binding
from arcade_service_reader import ROOT,sha
from bootpolicy_cache_reader import Cache,Dylib


def symbol_rows(lib):
    raw=next(r for c,r in lib.commands if c==2);off,n,st,sz=struct.unpack_from('<4I',raw,8)
    rows=lib.read_offset(off,n*16);strings=lib.read_offset(st,sz);out=[]
    for j in range(n):
        ix,t,se,de,a=struct.unpack_from('<IBBHQ',rows,j*16)
        if ix:out.append({'name':strings[ix:strings.index(0,ix)].decode(errors='replace'),'address':a,'n_type':t,'n_sect':se})
    return out


def main():
    cache=Cache();app=Dylib(cache,'/System/Library/PrivateFrameworks/AppStoreDaemon.framework/Versions/A/AppStoreDaemon')
    symbols=symbol_rows(app);selected=set()
    for r in symbols:
        name=r['name'];a=r['address']
        if a not in app.functions:continue
        if ('ASDRepairService' in name or ('ASDServiceBroker' in name and any(k in name for k in ['defaultBroker','initWithMachServiceName:','getRepairServiceWithError:']))
            or name in ['-[ASDRepairOptions fairplayStatus]','-[ASDRepairOptions setFairplayStatus:]','-[ASDRepairOptions setExitReason:]']):selected.add(a)
    selected.update((0x1be1442c8,0x1be15beec))
    app_ranges=[]
    for a in sorted(selected):
        r=app.function(a);r['original_names']=[n for n in symbols if n['address']==a];app_ranges.append(r)
    images=sorted((r['address'],r['path']) for r in cache.images);starts=[a for a,p in images];libraries={app.path:app};stubs={}
    def cache_stub(a):
        if a in stubs:return stubs[a]
        raw=cache.read(a,16);ins=list(CS.disasm(raw,a));kind=[i.mnemonic for i in ins]
        out={'address':hex(a),'bytes':raw.hex()}
        if kind[:3]==['adrp','add','b'] and ins[0].op_str.startswith('x1,'):
            p=int(ins[0].op_str.split('#')[1],0)+int(ins[1].op_str.split('#')[1],0)
            out.update({'kind':'objc_selector','selector_address':hex(p),'selector':cache.cstring(p)})
        elif kind==['adrp','add','ldr','braa'] and ins[0].op_str.startswith('x17,'):
            slot=int(ins[0].op_str.split('#')[1],0)+int(ins[1].op_str.split('#')[1],0);p=cache.pointer(slot);target=int(p['target'],16)
            owner=images[bisect.bisect_right(starts,target)-1][1]
            if owner not in libraries:libraries[owner]=Dylib(cache,owner)
            lib=libraries[owner];exports=[n for n,r in lib.exports.items() if r['address']==target]
            out.update({'kind':'cached_import','pointer':p,'target':hex(target),'library':owner,'library_uuid':lib.uuid,'exact_exports':exports})
        else:out['kind']='direct_code_or_unresolved_stub'
        stubs[a]=out;return out
    edges=[]
    for r in app_ranges:
        a=int(r['start'],16);z=int(r['end'],16)
        for i in r['instructions']:
            if i['mnemonic'] not in ('bl','b') or not i['operands'].startswith('#'):continue
            target=int(i['operands'][1:],0)
            if a<=target<z:continue
            st=cache_stub(target);edges.append({'source_function':r['start'],'callsite':i['ea'],'instruction':i['mnemonic'],'target':hex(target),'stub_kind':st['kind']})
    daemon=[]
    for a,z in [(0x100002134,0x1000021bc),(0x1000021bc,0x1000021c0),(0x1005acad8,0x1005acb90)]:
        raw=IMAGE.read(a,z-a);ins=list(CS.disasm(raw,a));assert len(ins)*4==z-a
        daemon.append({'start':hex(a),'end':hex(z),'bytes':raw.hex(),'sha256':sha(raw),
            'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ins]})
    daemon_stubs=[]
    for a in (0x100e2b300,0x100e2ab80,0x100e2b020,0x100e2b280,0x100e2b2a0,0x100e2af40,0x100e2b240):
        ins=list(CS.disasm(IMAGE.read(a,24),a));selector=None;selector_slot=None
        if ins[0].op_str.startswith('x1,'):
            slot=int(ins[0].op_str.split('#')[1],0)+int(ins[1].op_str.split('#')[1].split(']')[0],0)
            ptr=qword(slot);selector_slot=slot;selector=IMAGE.read(ptr,150).split(b'\0')[0].decode();ins=ins[2:]
        target_slot=int(ins[0].op_str.split('#')[1],0)+int(ins[1].op_str.split('#')[1],0)
        daemon_stubs.append({'address':hex(a),'bytes':IMAGE.read(a,24 if selector else 16).hex(),'selector':selector,
            'selector_slot':None if selector_slot is None else hex(selector_slot),'binding':binding(target_slot)})
    cls=app.exports['_OBJC_CLASS_$_ASDRepairOptions']['address'];class_chain=cache.pointer(cls+32);ro=int(class_chain['target'],16)&~7
    property_chain=cache.pointer(ro+64);p=int(property_chain['target'],16);stride,count=struct.unpack('<II',cache.read(p,8));assert stride==16 and count==10
    props=[]
    for j in range(count):
        q=p+8+j*stride;nc,ac=cache.pointer(q),cache.pointer(q+8)
        props.append({'entry':hex(q),'name':cache.cstring(int(nc['target'],16)),'attributes':cache.cstring(int(ac['target'],16)),
            'name_chain':nc,'attribute_chain':ac})
    assert next(r['attributes'] for r in props if r['name']=='fairplayStatus')=='Ti,N,V_fairplayStatus'
    assert next(r['attributes'] for r in props if r['name']=='exitReason')=='TQ,N,V_exitReason'
    cf=0x1e6c48a58;cp=cache.pointer(cf+16);n=struct.unpack('<Q',cache.read(cf+24,8))[0];notification=cache.read(int(cp['target'],16),n).decode()
    assert notification=='com.apple.appstored.ASDRepairBundleID'
    mach_obj=0x1e6c48118;mach_chain=cache.pointer(mach_obj+16);mn=struct.unpack('<Q',cache.read(mach_obj+24,8))[0]
    mach_name=cache.read(int(mach_chain['target'],16),mn).decode();assert mach_name=='com.apple.appstoreagent.xpc'
    foundation=Dylib(cache,'/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation')
    constants=[]
    for slot,name in [(0x1e016dba8,'_OBJC_CLASS_$_NSDistributedNotificationCenter'),(0x1e016df68,'_OBJC_CLASS_$_NSThread'),
            (0x1e016e188,'_OBJC_CLASS_$_NSXPCConnection')]:
        p=cache.pointer(slot);assert int(p['target'],16)==foundation.exports[name]['address']
        constants.append({'slot':hex(slot),'pointer':p,'exact_export':name,'library':foundation.path,'library_uuid':foundation.uuid})
    strcmp=cache_stub(0x1c00f3ff0);assert '__platform_strcmp' in strcmp['exact_exports']
    vproc=cache_stub(0x1c0100b90);assert '_vproc_swap_string' in vproc['exact_exports']
    sdk=Path('/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk')
    cfile=ROOT/'appstore_repair_layouts.c';cmd=['/usr/bin/clang','-x','objective-c','-target','arm64e-apple-macos','-isysroot',str(sdk),'-fblocks','-fsyntax-only','-Wall','-Wextra','-Werror',str(cfile)]
    run=subprocess.run(cmd,capture_output=True,text=True);assert run.returncode==0,(run.stdout,run.stderr)
    out={'scope':__doc__,'daemon_sha256':sha(SOURCE.read_bytes()),'daemon_ranges':daemon,'daemon_stubs':daemon_stubs,
        'repair_block':{'address':'0x101038020','original_bytes':IMAGE.read(0x101038020,32).hex(),
            'isa_fixup':FIXUPS[0x101038020],'invoke_fixup':FIXUPS[0x101038030],'descriptor_fixup':FIXUPS[0x101038038],
            'invoke':'0x1000021bc','invoke_instruction':'ret'},
        'cache_uuid':cache.uuid,'appstore_path':app.path,'appstore_uuid':app.uuid,'appstore_ranges':app_ranges,
        'cache_call_edges':edges,'cache_stubs':list(stubs.values()),
        'repair_options_properties':{'class_address':hex(cls),'class_chain':class_chain,'class_ro':hex(ro),
            'property_chain':property_chain,'properties':props},
        'environment_branch':{'query_call':'0x1be164238','query_import_stub':vproc,'key_u32':6,
            'key_enum_name':'unknown','comparison_call':'0x1be1642a0','comparison_stub':strcmp,
            'literal_address':'0x1be1ba589','literal':cache.cstring(0x1be1ba589),
            'equal_path':'remote object proxy','non_equal_or_query_error_path':'distributed notification'},
        'notification':{'constant_object':hex(cf),'string_chain':cp,'name':notification,'length_bytes':n,
            'post_call':'0x1be1645a8','options_u64':2,'following_sleep_call':'0x1be1645c0','sleep_seconds':1.0,
            'callback_call':'0x1be16462c','callback_args':['1','NULL','NULL'],'class_bindings':constants},
        'broker_connection':{'mach_service_object':hex(mach_obj),'name_chain':mach_chain,'mach_service_name':mach_name,
            'factory_block':'0x1be1440f0','init_call':'0x1be144118','connection_init_call':'0x1be144304',
            'connection_options_u64':0,'connection_cell_offset_bytes':8,'service_name_offset_bytes':32,
            'resume_call':'0x1be14440c','native_connection_created':False},
        'sdk_compile':{'command':cmd,'exit_code':0,'source_sha256':sha(cfile.read_bytes())},
        'sdk_notification_header':{'path':str(sdk/'System/Library/Frameworks/Foundation.framework/Headers/NSDistributedNotificationCenter.h'),
            'sha256':sha((sdk/'System/Library/Frameworks/Foundation.framework/Headers/NSDistributedNotificationCenter.h').read_bytes())},
        'native_appstore_operations_executed':False,'runtime_cache_pairing':'unknown','full_goal_complete':False,
        'cache_files_used':[cache.files[p] for p in sorted(cache.used)],'generator_sha256':sha(Path(__file__).read_bytes())}
    (ROOT/'appstore_repair_contracts.json').write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'daemon_ranges':len(daemon),'daemon_stubs':len(daemon_stubs),'appstore_functions':len(app_ranges),
        'cache_call_edges':len(edges),'cache_stubs':len(stubs),'repair_properties':len(props),'sdk_compile_exit':0}))


if __name__=='__main__':main()
