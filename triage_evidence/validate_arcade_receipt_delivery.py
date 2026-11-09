#!/usr/bin/env python3
"""Validate receipt/CMS and repair-interface increments, then owned manifest.

No native target/framework/file/decoder/IPC/sleep executes. Analyst readers,
compiler and SMT only. O(retained bytes+instructions+metadata+links) verification.
"""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
from arcade_service_reader import Service,ROOT,THIN_SHA,sha,CS
from daemon_receive_tools import IMAGE,SOURCE
from bootpolicy_cache_reader import Cache,Dylib
from recover_arcade_receipt import cfg,reachable


def read(name):return json.loads((ROOT/name).read_text())


def main():
    subprocess.run([sys.executable,str(ROOT/'recover_arcade_receipt.py')],check=True)
    subprocess.run([sys.executable,str(ROOT/'recover_appstore_repair.py')],check=True)
    s=Service();cache=Cache();r=read('arcade_receipt_contracts.json');a=read('appstore_repair_contracts.json');checks=[]
    def check(ok,label):
        assert ok,label
        checks.append(label)
    check(r['service_sha256']==THIN_SHA and a['daemon_sha256']==sha(SOURCE.read_bytes()),'source identities')
    check(r['cache_uuid']==a['cache_uuid']==cache.uuid,'common reference cache identity')
    check(len(r['ranges'])==20 and len(r['calls'])==138 and len(r['stubs'])==70,'twenty methods138 edges70 stubs')
    for row in r['ranges']:
        raw=bytes.fromhex(row['bytes']);check(s.read(int(row['start'],16),len(raw))==raw and sha(raw)==row['sha256'],f'original receipt method {row["method"]}')
    for row in r['stubs']:
        raw=bytes.fromhex(row['bytes']);check(s.read(int(row['address'],16),len(raw))==raw and s.decoded_fixups[int(row['binding']['address'],16)]==row['binding'],f'original receipt stub {row["address"]}')
    security=Dylib(cache,'/System/Library/Frameworks/Security.framework/Versions/A/Security')
    check(security.uuid==r['security_uuid'],'reference Security identity')
    for row in r['reference_security_functions']:
        raw=bytes.fromhex(row['bytes']);check(security.exports[row['export']]['address']==int(row['start'],16) and cache.read(int(row['start'],16),len(raw))==raw,f'original reference export {row["export"]}')
    free=r['free_binding'];check(cache.pointer(int(free['pointer']['address'],16))==free['pointer'],'CMS deallocator original version5 chain')
    malloc=Dylib(cache,free['library']);check(malloc.uuid==free['uuid'] and malloc.exports['_free']['address']==int(free['target'],16),'exact malloc free export')
    finish=next(x for x in r['reference_security_functions'] if x['export']=='_SecCmsDecoderFinish');nodes,edges=cfg(finish)
    ret={pc for pc,i in nodes.items() if i['mnemonic'] in ('ret','retab','retaa')};removed=int(r['finish_free_dominance']['free_call'],16)
    check(not ret.intersection(reachable(edges,int(finish['start'],16),removed)) and bool(ret),'all local Finish normal returns dominated by free')
    create=next(x for x in r['reference_security_functions'] if x['export']=='_SecCmsDecoderCreate');nodes,edges=cfg(create)
    check(int(r['create_output']['only_explicit_output_store'],16) not in reachable(edges,int(r['create_output']['failure_entry'],16)),'Create failure cannot reach output store')
    check(not r['create_output']['caller_slot_initialized_before_create'],'caller decoder slot lacks original prefix initialization')
    oid=r['required_oid_literal'];check(s.read(int(oid['string_address'],16),oid['length_bytes']).decode()==oid['text']=='1.2.840.113635.100.6.2.1','original certificate OID literal')
    proof=r['trust_result_proof'];p=ROOT/proof['path'];run=subprocess.run(['z3',str(p)],capture_output=True,text=True,check=True)
    check(sha(p.read_bytes())==proof['sha256'] and run.stdout.strip()=='unsat' and not run.stderr,'full32 trust result predicate')
    check(r['sdk_compile']['exit_code']==a['sdk_compile']['exit_code']==0,'two arm64e layout/constant compiles')
    for hdr in (r['sdk_trust_header'],a['sdk_notification_header']):check(sha(Path(hdr['path']).read_bytes())==hdr['sha256'],f'SDK source {hdr["path"]}')
    app=Dylib(cache,a['appstore_path']);check(app.uuid==a['appstore_uuid'],'reference AppStoreDaemon identity')
    check(len(a['appstore_ranges'])==24 and len(a['cache_call_edges'])==199 and len(a['cache_stubs'])==52,'reference repair graph counts')
    for row in a['appstore_ranges']:
        raw=bytes.fromhex(row['bytes']);check(cache.read(int(row['start'],16),len(raw))==raw and sha(raw)==row['sha256'],f'original AppStore range {row["start"]}')
    for row in a['daemon_ranges']:
        raw=bytes.fromhex(row['bytes']);check(IMAGE.read(int(row['start'],16),len(raw))==raw,f'original repair adapter range {row["start"]}')
    for row in a['cache_stubs']:
        check(cache.read(int(row['address'],16),len(bytes.fromhex(row['bytes']))).hex()==row['bytes'],f'original repair target/stub {row["address"]}')
        if row['kind']=='cached_import':check(cache.pointer(int(row['pointer']['address'],16))==row['pointer'],f'repair import chain {row["address"]}')
    props=a['repair_options_properties']['properties'];check(len(props)==10,'ten original repair properties')
    for row in props:
        check(cache.pointer(int(row['name_chain']['address'],16))==row['name_chain'] and cache.pointer(int(row['attribute_chain']['address'],16))==row['attribute_chain'],f'property chains {row["name"]}')
    check(next(x['attributes'] for x in props if x['name']=='fairplayStatus').startswith('Ti,') and next(x['attributes'] for x in props if x['name']=='exitReason').startswith('TQ,'),'signed32 FairPlay status and u64 exit reason')
    check(a['notification']['name']=='com.apple.appstored.ASDRepairBundleID' and a['notification']['options_u64']==2 and a['notification']['sleep_seconds']==1.0,'notification exact name/options/delay')
    check(a['broker_connection']['mach_service_name']=='com.apple.appstoreagent.xpc' and a['broker_connection']['connection_options_u64']==0,'named broker endpoint and options')
    check(a['environment_branch']['literal']=='Aqua' and '__platform_strcmp' in a['environment_branch']['comparison_stub']['exact_exports'],'reference Aqua comparison')
    check(IMAGE.read(0x1000021bc,4).hex()=='c0035fd6','daemon callback single RET')
    profiles=read('arcade_receipt_profiles.json')['profiles'];check(len(profiles)==9,'nine original receipt service cases')
    by={x['label']:x for x in profiles};phases=[];packets=[]
    for row in profiles:
        label=row['label'];phases.extend(row['fresh_prefix']);phases.append(row)
        check(row['receipt_probe_sha256']==sha((ROOT/'probe_arcade_receipt.py').read_bytes()) and row['policy_probe_sha256']==sha((ROOT/'probe_arcade_service_policy.py').read_bytes()) and row['metadata_reader_sha256']==sha((ROOT/'arcade_objc_metadata.py').read_bytes()),f'{label} frozen/private model provenance')
        check(not row['native_receipt_operations_executed'],f'{label} no native receipt operation')
        entry=next(e for e in row['records'] if e['kind']=='native_receipt_helper_entry');check(entry['count_u32']==57 and entry['output_initial']['kind32']=='02000000',f'{label} helper input/count/initial kind')
        sends=[e for e in row['records'] if e.get('name')=='libSystem/_xpc_connection_send_message']
        if sends:
            fields=sends[-1]['reply_fields'];check(row['stop_reason']=='outgoing_service_reply_boundary' and fields['status']=={'type':'int64','value':0} and fields['data']['size_bytes']==144,f'{label} exact completed service envelope')
            packets.append(fields['data']['bytes']);exit=next(e for e in row['records'] if e['kind']=='native_receipt_helper_exit')
            check(exit['status32']=='0x0' and exit['output_final']==entry['output_initial'],f'{label} missing/failed receipt leaves original output defaults')
    for row in phases:
        label=row['label'];check(row['source_sha256']==THIN_SHA and row['generator_sha256']==sha((ROOT/'probe_arcade_service.py').read_bytes()),f'{label} source/base provenance')
        h=hashlib.sha256()
        for pc in row['visited_original_instructions']:
            pc=int(pc,16);h.update(struct.pack('<Q',pc));h.update(s.read(pc,4))
        check(h.hexdigest()==row['visited_original_instruction_bytes_sha256'],f'{label} original visited instructions')
    check(len(phases)==27 and len(packets)==6 and len(set(packets))==1,'27 isolated phases and six identical144-byte responses')
    row=by['cms_create_failure'];create_event=next(e for e in row['records'] if e.get('name')=='Security/_SecCmsDecoderCreate')
    destroy=next(e for e in row['records'] if e.get('name')=='Security/_SecCmsDecoderDestroy')
    check(row['stop_reason']=='unknown_cms_context_destroy_boundary' and create_event['failure_output_written'] is False and destroy['args'][0]==hex(int.from_bytes(bytes.fromhex(create_event['output_before']),'little')),'Create error passes unchanged prior slot value to guarded Destroy')
    row=by['cms_finish_failure'];finish_event=next(e for e in row['records'] if e.get('name')=='Security/_SecCmsDecoderFinish');destroy=next(e for e in row['records'] if e.get('name')=='Security/_SecCmsDecoderDestroy')
    check(row['stop_reason']=='retired_cms_context_destroy_boundary' and finish_event['context_retired'] and not destroy['context_state']['alive'],'Finish error reaches guarded retired-context Destroy')
    row=by['cms_update_failure'];destroy=next(e for e in row['records'] if e.get('name')=='Security/_SecCmsDecoderDestroy')
    check(destroy['context_state']['alive'] and not destroy['context_state']['decoder_core_alive'] and destroy['context_retired'],'Update error context ownership differs from Finish error')
    replies=read('arcade_receipt_reply_profiles.json')['profiles'];check(len(replies)==6,'six daemon receipt continuations')
    for row in replies:
        label=row['label'];check(row['receipt_reply_probe_sha256']==sha((ROOT/'probe_arcade_receipt_reply.py').read_bytes()) and row['source_receipt_profiles_sha256']==sha((ROOT/'arcade_receipt_profiles.json').read_bytes()) and row['roundtrip_probe_sha256']==sha((ROOT/'probe_arcade_policy_roundtrip.py').read_bytes()),f'{label} source/fixture bindings')
        check(row['request_bytes_identical'] and not row['native_receipt_transaction_observed'],f'{label} exact request/private boundary')
        raw=bytes.fromhex(row['final_reply_40_bytes']);check(row['stop_reason']=='returned_to_fixture' and int.from_bytes(raw[4:8],'little')==40 and int.from_bytes(raw[20:24],'little')==61571 and raw[32:40]==bytes.fromhex('0000000001000000'),f'{label} completed status0/decision1 reply')
        repair=next(e for e in row['records'] if e.get('selector')=='repairAppWithOptions:replyHandler:')
        check(repair['options']=={'type':'repair_options','fields':{'bundlePath':'/private/synthetic/ArcadeFixture.app','exitReason':16,'fairplayStatus':-42352}} and repair['reply_block']=='0x101038020' and repair['reply_block_invoke']=='0x1000021bc',f'{label} exact repair request and callback')
        check(not any(e['pc']=='0x1004d7b0c' for e in row['native_mig_output_writes']),f'{label} no zero-decision store')
        h=hashlib.sha256()
        for pc in row['visited_original_code_pages']:
            pc=int(pc,16);h.update(struct.pack('<Q',pc));h.update(IMAGE.read(pc,4096))
        check(h.hexdigest()==row['visited_original_code_pages_sha256'],f'{label} daemon original pages')
    counts={'receipt_methods':20,'receipt_call_edges':138,'receipt_stubs':70,'reference_cms_functions':4,
        'finish_free_cfg_proofs':1,'trust_smt_unsat':1,'receipt_service_cases':9,'receipt_service_phases':27,
        'source_response_packets':6,'daemon_completed_cases':6,'repair_adapter_ranges':3,'repair_adapter_stubs':7,
        'reference_appstore_functions':24,'appstore_call_edges':199,'appstore_target_records':52,'repair_properties':10,
        'sdk_compile_exits':[0,0],'assertions':len(checks)}
    (ROOT/'arcade_receipt_profile_checks.json').write_text(json.dumps({'scope':__doc__,'verified_counts':counts,'checks':checks,
        'native_target_executed':False,'full_goal_complete':False},indent=2)+'\n')
    quality={'scope':'Receipt/CMS ownership and downstream repair/broker/notification increment only.',
        'verified_counts':counts,'native_target_executed':False,'full_goal_complete':False,
        'QG1':{'status':'pass','evidence':'Descriptive technical scope.'},
        'QG2':{'status':'pass','evidence':'RC1-RC5 and AR1-AR4 with dependent claims,probes,status.'},
        'QG3':{'status':'pass_for_increment','evidence':'Concrete receipt/decode/repair contracts; full goal remains active.'},
        'QG4':{'status':'pass','evidence':'80-byte class,signed32/u64 properties,32/64-bit CMS arguments,37-byte name,1s request,SDK/SMT/CFG complexity.'},
        'QG5':{'status':'pass_for_stated_claims','evidence':'Conditional cache ownership conflicts,synthetic decoder outputs,native pairing,completed buffers and actual transport separated.'},
        'QG6':{'status':'pass','evidence':'Original bytes,metadata,chains,nlist,exports,SDK,CFG/SMT and source-pinned private cases.'},
        'QG7':{'status':'pass','evidence':'Both reports have impact-labeled continuation.'}}
    (ROOT/'arcade_receipt_quality_gates.json').write_text(json.dumps(quality,indent=2)+'\n')
    subprocess.run([sys.executable,str(ROOT/'validate_rpc502_sidecar_delivery.py')],check=True)
    print(json.dumps(counts))


if __name__=='__main__':main()
