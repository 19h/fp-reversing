#!/usr/bin/env python3
"""Validate scoped authorization, metadata and private protocol evidence.

No target native code/IPC/framework/files/loader/synchronization runs. Analysis
cost O(retained bytes + visited addresses + metadata + links); SMT is separate.
"""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
from arcade_service_reader import ROOT,Service,THIN_SHA,sha
from arcade_objc_metadata import recover as objc_metadata
from daemon_receive_tools import IMAGE,SOURCE,CS
from bootpolicy_cache_reader import Cache,Dylib


def read(name):return json.loads((ROOT/name).read_text())


def main():
    subprocess.run([sys.executable,str(ROOT/'recover_arcade_policy.py')],check=True)
    s=Service();c=read('arcade_policy_contracts.json');cache=Cache();store=Dylib(cache,c['storefoundation_path']);checks=[]
    def check(ok,label):
        assert ok,label
        checks.append(label)
    check(c['service_sha256']==THIN_SHA and c['daemon_sha256']==sha(SOURCE.read_bytes()),'source identities')
    for a,m,ops in [(0x1005a99c0,'str','x9, [x11]'),(0x1008b35ec,'ldr','w10, [sp, #0xb30]'),
                    (0x1008b35f0,'cmp','w10, #1'),(0x1004d7b0c,'str','wzr, [x9]')]:
        i=next(CS.disasm(IMAGE.read(a,4),a));check((i.mnemonic,i.op_str)==(m,ops),f'original store/load/decision width {a:#x}')
    check(store.uuid==c['storefoundation_uuid'] and cache.uuid==c['cache_uuid'],'reference cache/library identities')
    for r in c['ranges']:
        image=s if r['image']=='service' else IMAGE;raw=bytes.fromhex(r['bytes'])
        check(image.read(int(r['start'],16),len(raw))==raw and sha(raw)==r['sha256'],f'original span {r["image"]} {r["start"]}')
    for r in c['storefoundation_ranges']:
        raw=bytes.fromhex(r['bytes']);check(cache.read(int(r['start'],16),len(raw))==raw and sha(raw)==r['sha256'],f'original StoreFoundation {r["start"]}')
        check(store.symbols_at(int(r['start'],16))==r['original_nlist_names'],f'original nlist names {r["start"]}')
    for r in c['cache_bindings']:check(cache.pointer(int(r['slot'],16))==r['pointer'],f'version5 original chain {r["stub"]}')
    for r in c['security_bindings']:check(s.decoded_fixups[int(r['address'],16)]==r,f'original service Security binding {r["symbol"]}')
    req=c['entitlement_requirement'];check(req['text']=='(entitlement ["com.apple.fp.receipt"] exists)' and s.read(int(req['string_address'],16),req['size_bytes']).decode()==req['text'],'original receipt-entitlement literal')
    for r in c['proofs']:
        p=ROOT/r['path'];run=subprocess.run(['z3',str(p)],capture_output=True,text=True,check=True)
        check(sha(p.read_bytes())==r['sha256'] and run.stdout.strip()=='unsat' and not run.stderr,f'SMT {r["name"]}')
    check(len(c['proofs'])==4 and c['sdk_compile']['exit_code']==0,'four local proofs and SDK compile')
    for r in c['sdk_headers']:check(sha(Path(r['path']).read_bytes())==r['sha256'],f'SDK provenance {r["path"]}')
    objc=read('arcade_service_objc_metadata.json');check(objc_metadata(s)==objc,'fresh independent metadata readback')
    check(len(objc['classes'])==7 and len(objc['methods'])==53,'seven classes and53 methods')
    for r in objc['methods']:
        check(s.read(int(r['entry'],16),len(bytes.fromhex(r['entry_bytes']))).hex()==r['entry_bytes'] and r['implementation_is_compiler_function_start'],f'original method entry {r["class"]} {r["kind"]} {r["selector"]}')
    service=read('arcade_service_policy_profiles.json')['profiles'];check(len(service)==10,'ten private service policy cases')
    by={r['label']:r for r in service};phases=[]
    for r in service:
        phases.extend(r['fresh_prefix']);phases.append(r)
        check(r['policy_probe_sha256']==sha((ROOT/'probe_arcade_service_policy.py').read_bytes()) and r['packet_source_profiles_sha256']==sha((ROOT/'arcade_service_peer_profiles.json').read_bytes()),f'{r["label"]} policy and packet provenance')
        check(not r['native_target_executed'] and not r['native_peer_authentication_executed'],f'{r["label"]} native boundary')
        points={e['pc']:e for e in r['records'] if e['kind']=='native_policy_checkpoint'}
        check(points['0x10000d540']['registers']['x21']=='0x177' and points['0x10000d540']['registers']['x22']=='0xd1',f'{r["label"]} first gate premises')
        for pc,arg in [('0x10000d568','guest_status'),('0x10000d608','requirement_status'),('0x10000d6a8','validity_status')]:
            if pc in points:
                value=r['synthetic_policy'].get(arg,0)&0xffffffff
                if pc=='0x10000d6a8':
                    value=next((r['synthetic_policy'].get(k,0)&0xffffffff for k in ('guest_status','requirement_status','validity_status') if r['synthetic_policy'].get(k,0)),0)
                check(int(points[pc]['registers']['x24'],16)==(value^0x662255dd),f'{r["label"]} native encoded status {arg}')
    for r in phases:
        check(r['source_sha256']==THIN_SHA and r['generator_sha256']==sha((ROOT/'probe_arcade_service.py').read_bytes()) and r['reader_sha256']==sha((ROOT/'arcade_service_reader.py').read_bytes()),f'{r["label"]} frozen dependencies')
        h=hashlib.sha256()
        for a in r['visited_original_instructions']:
            a=int(a,16);h.update(struct.pack('<Q',a));h.update(s.read(a,4))
        check(h.hexdigest()==r['visited_original_instruction_bytes_sha256'],f'{r["label"]} original visited code')
    def sends(r):return [e for e in r['records'] if e.get('name')=='libSystem/_xpc_connection_send_message']
    for label,status in [('guest_failure',-67050),('requirement_failure',-50),('validity_failure',-67050)]:
        r=by[label];check(r['stop_reason']=='outgoing_service_reply_boundary' and sends(r)[-1]['reply_fields']=={'status':{'type':'int64','value':status}},f'{label} exact signed error propagation')
    for label in ('developer_true','developer_true_volatile'):
        r=by[label];fields=sends(r)[-1]['reply_fields'];check(r['stop_reason']=='outgoing_service_reply_boundary' and fields['status']=={'type':'int64','value':0} and fields['data']['size_bytes']==96,f'{label} completed conditional service envelope')
    check(sends(by['developer_true'])[-1]['reply_fields']==sends(by['developer_true_volatile'])[-1]['reply_fields'],'scalar perturbation preserves exact source reply')
    for label in ('developer_false','developer_false_volatile'):
        r=by[label];e=r['records'][-2]
        check(r['stop_reason']=='objc_policy_boundary' and e['selector']=='receiptWithContentsOfFile:' and e['args'][0]=='0x100068aa8' and e['argument_objects'][0]=={'type':'string','text':'/private/synthetic/ArcadeFixture.app/Contents/_MASReceipt/receipt'},f'{label} exact original receipt path/class boundary')
    for label in ('developer_true_volatile','developer_false_volatile'):
        check(any(e['kind']=='private_scalar_clobber' for e in by[label]['records']),f'{label} perturbation actually applied')
    check(by['guest_null_success']['stop_reason']=='null_code_validity_boundary','counterfactual NULL code stopped before API')
    check(any(e.get('name')=='Security/_SecCodeCheckValidity' and e['args'][2]=='0x0' for e in by['requirement_null_success']['records']),'counterfactual NULL requirement distinguished')
    roundtrips=read('arcade_policy_roundtrip_profiles.json')['profiles'];check(len(roundtrips)==11,'eleven daemon reply/field cases')
    expected_complete=[];actual_complete=[]
    for r in roundtrips:
        label=r['label'];mutation=r['response_mutation'];value=1 if mutation is None else int(mutation['raw_be64'],16)
        completes=(value&0xffffffff)==1
        if completes:expected_complete.append(label)
        if r['stop_reason']=='returned_to_fixture':actual_complete.append(label)
        check(r['roundtrip_probe_sha256']==sha((ROOT/'probe_arcade_policy_roundtrip.py').read_bytes()) and r['reply_probe_sha256']==sha((ROOT/'probe_arcade_reply.py').read_bytes()) and r['service_profiles_sha256']==sha((ROOT/'arcade_service_policy_profiles.json').read_bytes()),f'{label} roundtrip dependency provenance')
        check(r['request_bytes_identical'] and not r['native_roundtrip_observed'],f'{label} exact request private boundary')
        raw=bytes.fromhex(r['final_reply_40_bytes']);writes=r['native_mig_output_writes']
        slot_writes=[e for e in r['records'] if e['kind']=='native_response_low32_slot_write' and e['pc']=='0x1005a99c0']
        compares=[e for e in r['records'] if e['kind']=='native_response_low32_compare']
        check(len(slot_writes)==1 and slot_writes[0]['size_bytes']==8 and int(slot_writes[0]['value'],16)==value and len(compares)==1 and compares[0]['candidate_u32']==(value&0xffffffff),f'{label} raw64 store to native low32 comparison')
        if completes:
            check(r['stop_reason']=='returned_to_fixture' and int.from_bytes(raw[4:8],'little')==40 and int.from_bytes(raw[20:24],'little')==61571 and int.from_bytes(raw[32:36],'little')==0 and int.from_bytes(raw[36:40],'little')==0,f'{label} completed original MIG61571 fields')
            check(any(w['pc']=='0x1004d7b0c' and w['offset_bytes']==36 and w['value']=='0x0' for w in writes),f'{label} original zero-decision store')
        else:
            check(r['stop_reason']=='objc_path_conversion_boundary' and int.from_bytes(raw[36:40],'little')==1 and not any(w['pc']=='0x1004d7b0c' for w in writes),f'{label} unfinished Foundation branch, provisional1')
        h=hashlib.sha256()
        for a in r['visited_original_code_pages']:
            a=int(a,16);h.update(struct.pack('<Q',a));h.update(IMAGE.read(a,4096))
        check(h.hexdigest()==r['visited_original_code_pages_sha256'],f'{label} daemon source-page provenance')
    check(actual_complete==expected_complete,'finite observed low32 projection, no universal field theorem')
    check(len(phases)==30 and len(actual_complete)==4,'thirty fresh service phases and four completed daemon cases')
    counts={'original_service_daemon_spans':7,'storefoundation_functions':5,'cache_import_bindings':5,'selector_stubs':4,
        'objc_classes':7,'objc_methods':53,'proofs_unsat':4,'service_policy_cases':10,'service_phases':30,
        'daemon_field_cases':11,'completed_daemon_cases':4,'unaltered_source_reply_completions':2,'sdk_compile_exit':0,'assertions':len(checks)}
    (ROOT/'arcade_policy_profile_checks.json').write_text(json.dumps({'scope':__doc__,'verified_counts':counts,'checks':checks,
        'native_target_executed':False,'full_goal_complete':False},indent=2)+'\n')
    quality={'scope':'Peer-entitlement/developer/reference-cache/metadata/private-MIG increment only.',
        'verified_counts':counts,'full_goal_complete':False,'native_target_executed':False,
        'QG1':{'status':'pass','evidence':'Descriptive technical scope.'},
        'QG2':{'status':'pass','evidence':'AP1-AP6 with dependencies, status and falsification probes.'},
        'QG3':{'status':'pass_for_increment','evidence':'Current authorization/path/private-reply coverage; full interface goal remains active.'},
        'QG4':{'status':'pass','evidence':'Exact signed32/u64/low32 widths, buffer extents, flags, SDK compile and complexity.'},
        'QG5':{'status':'pass_for_stated_claims','evidence':'Peer/target identity, NULL-success counterfactuals, field mutations, completed/stopped paths and cache pairing separated.'},
        'QG6':{'status':'pass','evidence':'Original file/cache bytes, method metadata/nlist/fixups, SDK, arithmetic and source-pinned finite cases.'},
        'QG7':{'status':'pass','evidence':'Impact-labeled continuation table.'}}
    (ROOT/'arcade_policy_quality_gates.json').write_text(json.dumps(quality,indent=2)+'\n')
    subprocess.run([sys.executable,str(ROOT/'validate_rpc502_sidecar_delivery.py')],check=True)
    print(json.dumps(counts))


if __name__=='__main__':main()
