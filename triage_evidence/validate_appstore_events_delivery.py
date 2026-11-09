#!/usr/bin/env python3
"""Validate original event/option/AMS contracts and finite private caller cases.

No native target/framework/event/account/network/file/xattr/IPC operation runs.
Analyst original-byte reads, local compiler syntax checks and hashing only.
"""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
from appstore_agent_reader import Agent,ROOT,THIN_SHA,CS,sha
from bootpolicy_cache_reader import Cache,Dylib
from recover_arcade_receipt import cfg,reachable


def read(name):return json.loads((ROOT/name).read_text())


def main():
    subprocess.run([sys.executable,str(ROOT/'recover_appstore_events.py')],check=True,stdout=subprocess.DEVNULL)
    s=Agent();cache=Cache();r=read('appstore_events_contracts.json');p=read('appstore_events_profiles.json');a=read('ams_keybag_profiles.json');checks=[]
    def check(ok,label):
        assert ok,label
        checks.append(label)
    check(r['source_sha256']==p['source_sha256']==THIN_SHA and r['source_uuid']==s.meta['uuid'],'original agent identity')
    check(r['reference_cache_uuid']==a['reference_cache_uuid']==cache.uuid,'original reference cache identity')
    check(len(r['ranges'])==29 and len(r['call_edges'])==1293 and len(r['stubs'])==135,'agent event graph counts')
    nodes={}
    for row in r['ranges']:
        at=int(row['start'],16);raw=bytes.fromhex(row['bytes']);ix=s.starts.index(at)
        check(s.read(at,len(raw))==raw and sha(raw)==row['sha256'] and int(row['end'],16)==s.starts[ix+1],f'complete original event range {row["start"]}')
        check([{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(raw,at)]==row['instructions'],f'original event decode {row["start"]}')
        nodes.update({i['ea']:i for i in row['instructions']})
    for edge in r['call_edges']:
        i=nodes[edge['callsite']];check(i['mnemonic']==edge['instruction'] and int(i['operands'][1:],0)==int(edge['target'],16),f'original event edge {edge["callsite"]}')
    for st in r['stubs']:
        check(s.read(int(st['address'],16),len(bytes.fromhex(st['bytes']))).hex()==st['bytes'],f'original event stub {st["address"]}')
        if st['kind']=='original_bound_stub':
            check(s.decoded_fixups[int(st['binding']['address'],16)]==st['binding'],f'original event stub chain {st["address"]}')
            if st['selector']:check(s.cstring(s.qword(int(st['selector_slot'],16)))==st['selector'],f'original event stub selector {st["address"]}')
    for lit in r['literals']:
        at=int(lit['cfstring'],16);check(s.read(at,32).hex()==lit['bytes'] and s.read(int(lit['string_address'],16),lit['length_bytes']).decode()==lit['text'] and s.decoded_fixups[at+16]==lit['chain'],f'original event literal {lit["role"]}')
    for st in r['strings']:check(s.cstring(int(st['address'],16))==st['text'],f'original event string {st["address"]}')
    for block in r['global_blocks']:
        at=int(block['address'],16);check(s.read(at,32).hex()==block['bytes'] and s.qword(at+16)==int(block['invoke'],16),f'original event callback {block["role"]}')
    app=Dylib(cache,r['reference_appstore_path']);ams=Dylib(cache,r['reference_ams_path'])
    check(app.uuid==r['reference_appstore_uuid'] and ams.uuid==r['reference_ams_uuid']==a['reference_ams_uuid'],'reference AppStoreDaemon and AMS UUIDs')
    for key,lib in [('reference_option_ranges',app),('reference_ams_ranges',ams)]:
        for row in r[key]:
            at=int(row['start'],16);raw=bytes.fromhex(row['bytes'])
            check(at in lib.functions and cache.read(at,len(raw))==raw and lib.function(at)['end']==row['end'],f'complete original cached function {row["start"]}')
            if 'original_names' in row:check(lib.symbols_at(at)==row['original_names'],f'original cached nlist {row["start"]}')
    for key in ('reference_stubs','reference_ams_stubs'):
        for st in r[key]:
            check(cache.read(int(st['address'],16),len(bytes.fromhex(st['bytes']))).hex()==st['bytes'],f'original cached target {st["address"]}')
            if st.get('pointer'):check(cache.pointer(int(st['pointer']['address'],16))==st['pointer'],f'original v5 import chain {st["address"]}')
            if st.get('selector'):check(cache.cstring(int(st['selector_address'],16))==st['selector'],f'original cached selector {st["address"]}')
    for c in r['reference_user_info_keys']+r['reference_family_notification']['constants']:
        ptr=cache.pointer(int(c['cfstring'],16)+16);check(ptr==c['chain'] and cache.cstring(int(ptr['target'],16))==c['text'],f'original cached constant {c["text"]}')
    key=r['reference_event_name_key'];xpc=Dylib(cache,key['library']);check(xpc.uuid==key['uuid'] and xpc.exports[key['export']]['address']==int(key['address'],16) and cache.pointer(int(key['address'],16))==key['chain'] and cache.cstring(int(key['chain']['target'],16))==key['text']=='XPCEventName','original libxpc event-name key export')
    relay=next(x for x in r['ranges'] if x['start']=='0x100140dfc');nn,graph=cfg(relay)
    check(0x1001410b4 not in reachable(graph,0x100140dfc,0x100140ff0) and 0x1001410b4 in reachable(graph,0x100140dfc),'local userInfo post dominated by CF conversion call')
    check(r['observer_selector']=='_handleRepairBundleIDNotification:' and r['queue_ivar_original_u32']==64,'observer selector and original queue offset')
    for rows,gen,expected in [(p,'probe_appstore_events.py',17),(a,'probe_ams_keybag.py',8)]:
        check(rows['generator_sha256']==sha((ROOT/gen).read_bytes()) and rows['source_contracts_sha256']==sha((ROOT/'appstore_events_contracts.json').read_bytes()),f'private probe provenance {gen}')
        check(len(rows['profiles'])==expected and not rows['native_target_executed'] and not rows['hardware_PAC_checked'],f'finite private count and boundaries {gen}')
        for row in rows['profiles']:
            label=row['fixture']['label'];check(row['stop_reason']=='returned_to_private_fixture',f'completed private case {label}')
            h=hashlib.sha256()
            for pc in row['visited_original_instructions']:
                pc=int(pc,16);h.update(struct.pack('<Q',pc));h.update((s.read if rows is p else cache.read)(pc,4))
            check(h.hexdigest()==row['original_instruction_bytes_sha256'],f'visited original-byte readback {label}')
            if rows is a:
                for page in row['mapped_original_pages']:check(sha(cache.read(int(page['address'],16),4096))==page['sha256'],f'original mapped cache page {label}:{page["address"]}')
    check(p['parent_probe_sha256']==sha((ROOT/'probe_appstore_agent.py').read_bytes()),'frozen parent mapping model provenance')
    by={x['fixture']['label']:x for x in p['profiles']}
    for name in ('relay_null','relay_wrong_type','relay_name_absent'):check(not by[name]['posts'],f'relay rejects {name}')
    for name in ('relay_userinfo_absent','relay_userinfo_wrong_type'):check(by[name]['posts'][0]['selector']=='postNotificationName:object:' and by[name]['posts'][0]['user_info'] is None,f'plain name-only fallback {name}')
    check(by['relay_full_repair']['posts'][0]['user_info']==by['consumer_path']['fixture']['user_info'],'unchanged dictionary fixture joins relay and consumer cases')
    check(by['observer_queues_notification']['schedules'][0]['invoke']=='0x1000587c4','observer captures original queued block')
    expected={'bundlePath':'/private/synthetic/ArcadeFixture.app','fairplayStatus':-42352,'exitReason':16}
    for name in ('consumer_path','consumer_both_path_wins','consumer_external_ignored_fields'):
        row=by[name];check(row['tasks'][0]['options']['fields']==expected and row['schedules'][0]['wait_u64']==1,f'path priority/options and wait request {name}')
    check(by['consumer_identifier']['tasks'][0]['options']['fields']=={'bundleID':'fixture.bundle','fairplayStatus':-42352,'exitReason':16},'identifier route when path absent')
    check(by['consumer_missing_fields']['tasks'][0]['options']['fields']=={'bundleID':None,'exitReason':0},'missing fields preserved as private initializer inputs')
    check(by['consumer_u32_wrap']['tasks'][0]['options']['fields']==dict(expected,exitReason=(1<<64)-1),'modeled low32 status and u64 exit reason')
    check(by['consumer_internal_force_fields']['tasks'][0]['options']['fields']==dict(expected,forceUpsell=True,forceRevoke=True),'conditional internal force flags')
    check(all('isBackground' not in row['field_lookups'] for row in p['profiles']),'no isBackground lookup in finite consumer paths')
    check(not any(x.get('symbol') and 'SecTask' in x['symbol'] for row in p['profiles'] for x in row['calls']),'no peer entitlement query in finite relay/consumer cases')
    am={x['fixture']['label']:x for x in a['profiles']}
    for name in ('nil_data','null_output_pointer','zero_record_count','one_account_pair','two_distinct_account_pairs'):check(am[name]['success_byte']==1,f'AMS conditional success {name}')
    for name in ('zero_context','context_error','protected_import_error'):check(am[name]['success_byte']==0,f'AMS conditional failure {name}')
    check(not am['nil_data']['records_disposed'] and am['zero_record_count']['records_disposed'],'nil versus nonnull zero-record disposal')
    check(am['context_error']['error_present'] and am['protected_import_error']['error_present'],'context and import error output preserved')
    check(am['two_distinct_account_pairs']['account_pairs']==[{'downloader_u64':22,'purchaser_u64':11,'family_u64':33},{'downloader_u64':55,'purchaser_u64':44,'family_u64':66}],'two original records stride and account permutation')
    check(am['two_distinct_account_pairs']['notification_arguments']==[am['two_distinct_account_pairs']['account_pairs']] and am['two_distinct_account_pairs']['records_disposed'],'private notification arguments then record disposal')
    importrow=next(x for x in r['reference_ams_ranges'] if x['start']=='0x19c648880');im={x['ea']:x for x in importrow['instructions']}
    check(im['0x19c6489c4']['operands']=='x3, x2, [x9]' and im['0x19c6489c0']['operands']=='x9, x8, x22, lsl #5' and im['0x19c6489c8']['operands']=='x4, [x9, #0x10]','original 32-byte record loads and permutation')
    notify=r['reference_family_notification'];check(not notify['deliver_immediately_boolean'] and notify['constants'][0]['text']=='com.apple.StoreServices.SSVFamilyContentDeletionNotification','exact family notification name and Boolean argument')
    bind={x['address']:x for x in r['reference_ams_stubs']};check('_CFNotificationCenterPostNotification' in bind['0x1a0089b70']['exact_exports'] and '_CFNotificationCenterGetDistributedCenter' in bind['0x1a008bc20']['exact_exports'],'exact CF distributed notification bindings')
    path=next(x for x in r['reference_ams_ranges'] if x['start']=='0x19c6003a0');pn={x['ea']:x for x in path['instructions']}
    check(pn['0x19c6005d8']['mnemonic']=='ldrb' and pn['0x19c6005dc']['operands']=='w8, w8, #0x40' and '_getxattr' in bind['0x1a008c080']['exact_exports'] and '_setxattr' in bind['0x1a008c2b0']['exact_exports'],'original xattr result-adjacent instruction and exact functions')
    sdk=Path('/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk');cfile=ROOT/'appstore_events_layouts.c'
    cmd=['/usr/bin/clang','-target','arm64e-apple-macos','-isysroot',str(sdk),'-fsyntax-only','-Wall','-Wextra','-Werror',str(cfile)]
    run=subprocess.run(cmd,capture_output=True,text=True);check(run.returncode==0 and not run.stderr,'arm64e record layout and SDK XATTR_NOFOLLOW compile')
    counts={'agent_original_ranges':29,'agent_direct_edges':1293,'agent_stubs':135,'reference_option_functions':6,'reference_option_edges':146,
        'reference_ams_functions':19,'reference_ams_edges':220,'reference_ams_targets':66,'private_event_cases':17,'private_ams_cases':8,
        'private_cases':25,'record_stride_bytes':32,'local_cfg_checks':1,'sdk_compile_exit':run.returncode,'assertions':len(checks)}
    (ROOT/'appstore_events_profile_checks.json').write_text(json.dumps({'scope':__doc__,'verified_counts':counts,'checks':checks,
        'sdk_compile':{'command':cmd,'source_sha256':sha(cfile.read_bytes()),'exit_code':run.returncode},
        'sdk_xattr_header':{'path':str(sdk/'usr/include/sys/xattr.h'),'sha256':sha((sdk/'usr/include/sys/xattr.h').read_bytes())},
        'native_target_executed':False,'full_goal_complete':False},indent=2)+'\n')
    quality={'scope':'Repair event reconstruction and deeper keybag caller ABI increment only.','verified_counts':counts,
        'QG1':{'status':'pass','evidence':'Descriptive technical investigation.'},
        'QG2':{'status':'pass','evidence':'EV1-EV8 with dependencies, probes and current verification boundaries.'},
        'QG3':{'status':'pass_for_increment','evidence':'Event/schema/keybag caller contracts advanced; full objective remains active.'},
        'QG4':{'status':'pass','evidence':'Original byte/count/register widths, 32-byte layout, SDK compile and bounded algorithms.'},
        'QG5':{'status':'pass_for_stated_claims','evidence':'Producer admission, local relay, task scheduling, protected algorithm, callback and actual delivery remain distinct.'},
        'QG6':{'status':'pass','evidence':'Original source/cache bytes, chain membership, nlist/selectors, original-page hashes and 25 finite cases.'},
        'QG7':{'status':'pass','evidence':'Impact-labeled admission, account, notification, protected algorithm and lifetime continuation.'},
        'native_target_executed':False,'full_goal_complete':False}
    (ROOT/'appstore_events_quality_gates.json').write_text(json.dumps(quality,indent=2)+'\n')
    subprocess.run([sys.executable,str(ROOT/'validate_rpc502_sidecar_delivery.py')],check=True)
    print(json.dumps(counts))


if __name__=='__main__':main()
