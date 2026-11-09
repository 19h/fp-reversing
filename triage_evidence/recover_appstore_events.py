#!/usr/bin/env python3
"""Original appstoreagent event relays, notification reconstruction and keybag path.

Source/cache read only. No framework, notification, account, network, FairPlay
or Mach operation runs. O(B+I+F+S) extraction, O(V+E) local CFG checks.
"""
import bisect
import json
from pathlib import Path
import re
import struct
from appstore_agent_reader import Agent,ROOT,THIN_SHA,CS,sha
from bootpolicy_cache_reader import Cache,Dylib
from recover_appstore_repair import symbol_rows


def stub(s,a):
    ins=list(CS.disasm(s.read(a,24),a));selector=None;sel_slot=None
    if ins[0].mnemonic=='adrp' and ins[0].op_str.startswith('x1,') and ins[1].mnemonic=='ldr':
        m=re.fullmatch(r'x1, \[x1(?:, #(0x[0-9a-f]+|[0-9]+))?\]',ins[1].op_str);assert m,ins[1].op_str
        sel_slot=int(ins[0].op_str.split('#')[1],0)+(int(m[1],0) if m[1] else 0)
        selector=s.cstring(s.qword(sel_slot));ins=ins[2:]
    if [i.mnemonic for i in ins[:4]]!=['adrp','add','ldr','braa']:
        return {'address':hex(a),'bytes':s.read(a,16).hex(),'kind':'unresolved_original_stub'}
    slot=int(ins[0].op_str.split('#')[1],0)+int(ins[1].op_str.split('#')[1],0)
    return {'address':hex(a),'bytes':s.read(a,24 if selector else 16).hex(),'kind':'original_bound_stub',
        'selector':selector,'selector_slot':None if sel_slot is None else hex(sel_slot),'binding':s.decoded_fixups[slot]}


def main():
    s=Agent();seeds={0x10004d520:'ArcadeManager init and notification observer registration',
        0x100058718:'ArcadeManager repair notification observer',0x1000587c4:'queued repair notification reconstruction',
        0x100140c10:'install three event-stream handlers',0x100140dfc:'plain distributed notification event relay',
        0x1001410d4:'trusted distributed notification event relay',0x1001415a4:'notifyd event relay',
        0x10012367c:'startup catalog and direct keybag notification registration',
        0x100124ce0:'keybag notify dispatch callback',0x100124e24:'keybag notify completion',
        0x1000f1610:'repair service refresh keybag public method',0x1000f1708:'repair service queued refresh block',
        0x1000f18a8:'repair service refresh result callback',0x1000faed4:'RefetchKeybag log-key constructor',
        0x1000fb004:'RefetchKeybag account and interactive policy',0x1000fb70c:'RefetchKeybag recent bag request',
        0x1000fc214:'RefetchKeybag creates AuthorizeMachine operation',
        0x10018e2b4:'AuthorizeMachine constructor',0x10018e3c4:'AuthorizeMachine request and promises',
        0x10018f100:'AuthorizeMachine request parameters'}
    # Follow only literal x16 block targets in these compiler ranges, two layers.
    depth={a:0 for a in seeds};todo=list(seeds);ranges=[]
    while todo:
        a=todo.pop(0);ix=s.starts.index(a);z=s.starts[ix+1];raw=s.read(a,z-a);ins=list(CS.disasm(raw,a));assert len(ins)*4==len(raw)
        ranges.append({'label':seeds[a],'start':hex(a),'end':hex(z),'complete_compiler_range':True,'bytes':raw.hex(),'sha256':sha(raw),
            'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ins]})
        if depth[a]>=2:continue
        for first,second in zip(ins,ins[1:]):
            if first.mnemonic=='adrp' and first.op_str.startswith('x16,') and second.mnemonic=='add' and second.op_str.startswith('x16, x16, #'):
                target=int(first.op_str.split('#')[1],0)+int(second.op_str.split('#')[1],0)
                if target in s.starts and target not in seeds:
                    seeds[target]='literal original block target from '+hex(first.address);depth[target]=depth[a]+1;todo.append(target)
    stubs={};edges=[];stubsecs=[x for x in s.sections if x['section'] in ('__auth_stubs','__stubs','__objc_stubs')]
    for r in ranges:
        a=int(r['start'],16);z=int(r['end'],16)
        for i in r['instructions']:
            if i['mnemonic'] not in ('bl','b') or not i['operands'].startswith('#'):continue
            t=int(i['operands'][1:],0)
            if a<=t<z:continue
            e={'source':r['start'],'callsite':i['ea'],'instruction':i['mnemonic'],'target':hex(t),'kind':'direct_original_internal'}
            if any(x['address']<=t<x['address']+x['size'] for x in stubsecs):
                if t not in stubs:stubs[t]=stub(s,t)
                st=stubs[t];e.update({'kind':st['kind'],'selector':st.get('selector'),'symbol':st.get('binding',{}).get('target')})
            edges.append(e)
    literals=[]
    for a,role in [(0x100591278,'repair notification name'),(0x10058d758,'bundle identifier field'),(0x1005917d8,'bundle path field'),
        (0x10058e0f8,'status field'),(0x1005917f8,'exit reason field'),(0x100591818,'internal force upsell field'),(0x100591838,'internal force revoke field')]:
        p=s.qword(a+16);n=s.qword(a+24);literals.append({'role':role,'cfstring':hex(a),'bytes':s.read(a,32).hex(),
            'string_address':hex(p),'length_bytes':n,'text':s.read(p,n).decode(),'chain':s.decoded_fixups[a+16]})
    strings=[{'address':hex(a),'text':s.cstring(a)} for a in [0x100547ce7,0x100547cf0,0x100547d0d,0x100547d32,0x100546e82]]
    blocks=[]
    for a,role in [(0x10058cc10,'plain distributed'),(0x100572640,'trusted distributed'),(0x10058cc30,'notifyd'),(0x1005720a8,'direct keybag notify')]:
        blocks.append({'address':hex(a),'role':role,'bytes':s.read(a,32).hex(),'flags_u32':struct.unpack('<I',s.read(a+8,4))[0],
            'invoke':hex(s.qword(a+16)),'invoke_chain':s.decoded_fixups[a+16]})
    cache=Cache();app=Dylib(cache,'/System/Library/PrivateFrameworks/AppStoreDaemon.framework/Versions/A/AppStoreDaemon');syms=symbol_rows(app)
    cache_ranges=[]
    for x in syms:
        if x['name'] in ['-[ASDRepairOptions initWithBundleID:]','-[ASDRepairOptions initWithBundlePath:]',
            '-[ASDRepairOptions copyUserInfoDictionary]','-[ASDRepairOptions supportsSecureCoding]',
            '+[ASDRepairOptions supportsSecureCoding]','-[ASDRepairOptions initWithCoder:]','-[ASDRepairOptions encodeWithCoder:]']:
            r=app.function(x['address']);r['original_name']=x;cache_ranges.append(r)
    cstubs={};cedges=[]
    for r in cache_ranges:
        for i in r['instructions']:
            if i['mnemonic'] not in ('bl','b') or not i['operands'].startswith('#'):continue
            t=int(i['operands'][1:],0)
            if int(r['start'],16)<=t<int(r['end'],16):continue
            if t not in cstubs:
                raw=cache.read(t,16);ins=list(CS.disasm(raw,t));out={'address':hex(t),'bytes':raw.hex(),'kind':'direct_or_unresolved'}
                if [k.mnemonic for k in ins[:3]]==['adrp','add','b'] and ins[0].op_str.startswith('x1,'):
                    p=int(ins[0].op_str.split('#')[1],0)+int(ins[1].op_str.split('#')[1],0)
                    out.update({'kind':'original_selector','selector_address':hex(p),'selector':cache.cstring(p)})
                elif [k.mnemonic for k in ins]==['adrp','add','ldr','braa']:
                    slot=int(ins[0].op_str.split('#')[1],0)+int(ins[1].op_str.split('#')[1],0)
                    out.update({'kind':'original_chained_import','pointer':cache.pointer(slot)})
                cstubs[t]=out
            cedges.append({'source':r['start'],'callsite':i['ea'],'target':hex(t),'instruction':i['mnemonic'],
                'selector':cstubs[t].get('selector'),'kind':cstubs[t]['kind']})
    cache_keys=[]
    for a in [0x1e6c47a78,0x1e6c48cd8,0x1e6c48cf8,0x1e6c48d18,0x1e6c48d38,0x1e6c48d58,0x1e6c48d78]:
        ptr=cache.pointer(a+16);n=struct.unpack('<Q',cache.read(a+24,8))[0]
        cache_keys.append({'cfstring':hex(a),'chain':ptr,'length_bytes':n,'text':cache.read(int(ptr['target'],16),n).decode()})
    xpc=Dylib(cache,'/usr/lib/system/libxpc.dylib');key=xpc.exports['__xpc_event_key_name']['address'];key_chain=cache.pointer(key)
    event_key={'library':xpc.path,'uuid':xpc.uuid,'export':'__xpc_event_key_name','address':hex(key),'chain':key_chain,
        'text':cache.cstring(int(key_chain['target'],16))}
    ams=Dylib(cache,'/System/Library/PrivateFrameworks/AppleMediaServices.framework/Versions/A/AppleMediaServices')
    ams_ranges=[]
    for a in [0x19c1ed14c,0x19c648678,0x19c648880,0x19c648a4c,0x19c9ec168,0x19ca1dd68,0x19c1e8be8,
        0x19c5ffe7c,0x19c5fffc4,0x19c60000c,0x19c6000e4,0x19c6003a0,0x19c6006fc,0x19c600704,
        0x19ca0d0e4,0x19c9e12a0,0x19c602914,0x19c602970,0x19c602bc4]:
        r=ams.function(a);r['original_names']=ams.symbols_at(a);ams_ranges.append(r)
    images=sorted((x['address'],x['path']) for x in cache.images);image_starts=[x[0] for x in images];libs={app.path:app,ams.path:ams,xpc.path:xpc}
    ams_stubs={};ams_edges=[]
    for r in ams_ranges:
        for i in r['instructions']:
            if i['mnemonic'] not in ('bl','b') or not i['operands'].startswith('#'):continue
            t=int(i['operands'][1:],0)
            if int(r['start'],16)<=t<int(r['end'],16):continue
            if t not in ams_stubs:
                raw=cache.read(t,16);ins=list(CS.disasm(raw,t));out={'address':hex(t),'bytes':raw.hex(),'kind':'direct_or_unresolved'}
                if [k.mnemonic for k in ins[:3]]==['adrp','add','b'] and ins[0].op_str.startswith('x1,'):
                    p=int(ins[0].op_str.split('#')[1],0)+int(ins[1].op_str.split('#')[1],0)
                    out.update({'kind':'original_selector','selector_address':hex(p),'selector':cache.cstring(p)})
                elif [k.mnemonic for k in ins]==['adrp','add','ldr','braa']:
                    slot=int(ins[0].op_str.split('#')[1],0)+int(ins[1].op_str.split('#')[1],0);ptr=cache.pointer(slot);target=int(ptr['target'],16)
                    path=images[bisect.bisect_right(image_starts,target)-1][1]
                    if path not in libs:libs[path]=Dylib(cache,path)
                    lib=libs[path]
                    out.update({'kind':'original_chained_import','pointer':ptr,'library':path,'library_uuid':lib.uuid,
                        'exact_exports':[n for n,x in lib.exports.items() if x['address']==target]})
                ams_stubs[t]=out
            st=ams_stubs[t];ams_edges.append({'source':r['start'],'callsite':i['ea'],'target':hex(t),'instruction':i['mnemonic'],
                'kind':st['kind'],'selector':st.get('selector'),'exact_exports':st.get('exact_exports',[])})
    out={'scope':__doc__,'source_sha256':THIN_SHA,'source_uuid':s.meta['uuid'],'ranges':sorted(ranges,key=lambda x:int(x['start'],16)),
        'call_edges':edges,'stubs':list(stubs.values()),'literals':literals,'strings':strings,'global_blocks':blocks,
        'event_name_key_binding':s.decoded_fixups[0x1005a9a00],'dictionary_type_binding':s.decoded_fixups[0x1005a9a10],
        'local_notification_center_binding':s.decoded_fixups[0x1005a9888],
        'observer_selector_slot':'0x1005d4c00','observer_selector':s.cstring(s.qword(0x1005d4c00)),
        'queue_ivar_cell':'0x1005dbd4c','queue_ivar_original_u32':struct.unpack('<I',s.read(0x1005dbd4c,4))[0],
        'reference_cache_uuid':cache.uuid,'reference_appstore_uuid':app.uuid,'reference_appstore_path':app.path,
        'reference_option_ranges':cache_ranges,'reference_call_edges':cedges,'reference_stubs':list(cstubs.values()),'reference_user_info_keys':cache_keys,
        'reference_event_name_key':event_key,'reference_ams_path':ams.path,'reference_ams_uuid':ams.uuid,'reference_ams_ranges':ams_ranges,
        'reference_ams_edges':ams_edges,'reference_ams_stubs':list(ams_stubs.values()),
        'ams_keybag_class_binding':s.decoded_fixups[0x1005a8f20],
        'keybag_response_fields':[{'cfstring':hex(a),'bytes':s.read(a,32).hex(),'text':s.cstring(s.qword(a+16)),
            'chain':s.decoded_fixups[a+16]} for a in [0x1005a0318,0x1005a0f38]],
        'authorization_url_key':{'slot':'0x100573c00','pointer_chain':s.decoded_fixups[0x100573c00],
            'cfstring':hex(s.qword(0x100573c00)),'text':s.cstring(s.qword(s.qword(0x100573c00)+16))},
        'reference_context_literals':[{'address':hex(a),'text':cache.cstring(a)} for a in [0x19cbd3cdc,0x19cbd3d27]],
        'reference_family_notification':{'post_call':'0x19c60294c','center_call':'0x19c602934',
            'constants':[{'cfstring':hex(a),'chain':cache.pointer(a+16),
                'text':cache.cstring(int(cache.pointer(a+16)['target'],16))} for a in [0x1e44be440,0x1e44be460,0x1e44be480,0x1e44be4a0,0x1e44be4c0]],
            'class_chains':[cache.pointer(a) for a in [0x1e0f897c8,0x1e0f897d0]],
            'object_argument':'NULL','deliver_immediately_boolean':False},
        'keybag_import_private_abi':{'caller':'0x19c64891c','callee':'0x19c9ec168','original_name':'_ha0dkchaters6',
            'inputs':['W0=context ID u32','X1=NSData bytes','X2=NSData length u64','X3=output pointer cell64','X4=output count cell32'],
            'output_record_stride_bytes':32,'record_fields':{'purchaser_account_id_u64':0,'downloader_account_id_u64':8,'family_id_u64':16,'unknown':24},
            'dispose_call':'0x19c648a18','dispose_callee':'0x19ca1dd68','dispose_original_name':'_jEHf8Xzsv8K',
            'count_guard':'0x19c6489a8','loop_backedge':'0x19c6489f4','native_reachability':'unknown'},
        'generator_sha256':sha(Path(__file__).read_bytes()),'native_target_executed':False,'full_goal_complete':False}
    (ROOT/'appstore_events_contracts.json').write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({k:len(out[k]) for k in ['ranges','call_edges','stubs','reference_option_ranges','reference_call_edges','reference_stubs']}))


if __name__=='__main__':main()
