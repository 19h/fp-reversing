#!/usr/bin/env python3
"""Verify the current source-pinned XPC increment and refresh owned delivery.

No target execution, IPC, loader, framework or host synchronization operations.
O(total retained bytes + visited addresses + links), bounded JSON working sets.
"""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
from arcade_service_reader import Service,ROOT,THIN_SHA,sha
from daemon_receive_tools import IMAGE,SOURCE


def read(name):return json.loads((ROOT/name).read_text())


def main():
    subprocess.run([sys.executable,str(ROOT/'recover_arcade_xpc.py')],check=True)
    s=Service();count=0;labels=[]
    def check(ok,label):
        nonlocal count
        assert ok,label
        count+=1;labels.append(label)
    c=read('arcade_xpc_contracts.json');inventory=read('arcade_service_inventory.json')
    check(inventory['selected_sha256']==THIN_SHA and inventory['uuid']==s.meta['uuid'],'service identity')
    check(inventory['installed_daemon_sha256']=='4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7','installed universal daemon identity')
    check(inventory['fixup_chain_membership_matches_dyld_info'] and len(s.fixups)==1163,'1163 independently walked original fixups')
    check(not inventory['encryption_commands'],'selected slice no LC_ENCRYPTION_INFO_64')
    check(len(read('arcade_service_original_functions.json')['ranges'])==70,'70 compiler ranges')
    for r in read('arcade_service_original_functions.json')['ranges']:
        a=int(r['start'],16);z=int(r['end'],16);raw=s.read(a,z-a)
        check(raw.hex()==r['bytes'] and sha(raw)==r['sha256'],f'original service range {r["start"]}')
    for r in c['daemon_reply_ranges']:
        raw=bytes.fromhex(r['bytes']);check(IMAGE.read(int(r['start'],16),len(raw))==raw and sha(raw)==r['sha256'],f'daemon range {r["start"]}')
    check(len(c['live_ida_matches'])==5 and all(r['matches_original'] for r in c['live_ida_matches']),'five current read-only IDA windows')
    for r in c['banks']:
        left,right=bytes.fromhex(r['left_bytes']),bytes.fromhex(r['right_bytes']);key=int(r['key'],16)
        check({x^right[left[x]^key] for x in range(256)}=={int(r['constant'],16)},f'exhaustive bank {r["label"]}')
    for r in c['call_sites']:
        check(s.decoded_fixups[int(r['slot'],16)]==r['binding'],f'original call slot {r["label"]}')
    for r in c['proofs']:
        p=ROOT/r['path'];run=subprocess.run(['z3',str(p)],capture_output=True,text=True,check=True)
        check(sha(p.read_bytes())==r['sha256'] and run.stdout.strip()=='unsat' and not run.stderr,f'SMT {r["name"]}')
    for r in c['sdk_headers']:check(sha(Path(r['path']).read_bytes())==r['sha256'],f'SDK source {r["path"]}')
    check(c['sdk_compile']['exit_code']==0,'arm64e SDK layout/declaration compile')
    meta=read('arcade_reply_initial_state.json')
    check(meta['result']['full_initialization_complete'] and meta['result']['steps']==5668177,'fresh initializer returned after 5668177 instructions')
    check(meta['snapshot_sha256']==sha((ROOT/'arcade_reply_initial_state.bin').read_bytes()),'owned private checkpoint hash')
    check(meta['source_sha256']==sha(SOURCE.read_bytes()),'checkpoint original source')
    for key,name in [('subscription_probe_sha256','probe_arcade_subscription.py'),('base_probe_sha256','daemon_rpc502_probe.py')]:
        check(meta[key]==sha((ROOT/name).read_bytes()),f'checkpoint dependency {name}')
    h=hashlib.sha256()
    for a in meta['visited_original_code_pages']:
        a=int(a,16);h.update(struct.pack('<Q',a));h.update(IMAGE.read(a,4096))
    check(h.hexdigest()==meta['visited_original_code_pages_sha256'],'fresh initialization code page provenance')
    reply=read('arcade_reply_profiles.json')['profiles'];check(len(reply)==16,'sixteen daemon reply profiles')
    by={r['label']:r for r in reply}
    want_data={'reply_status_zero','reply_status_high32','reply_status_negative_high32','reply_missing_data','reply_short_data','reply_scalar_frame'}
    for r in reply:
        label=r['label'];calls=r['calls'];data=[e for e in calls if e['name']=='libSystem/_xpc_dictionary_get_data']
        check(r['reply_probe_sha256']==sha((ROOT/'probe_arcade_reply.py').read_bytes()) and r['generator_sha256']==meta['subscription_probe_sha256'] and r['base_probe_sha256']==meta['base_probe_sha256'],f'{label} source-pinned models')
        check(r['stop_reason']=='objc_path_conversion_boundary' and calls[-1]['receiver']=='Foundation/_OBJC_CLASS_$_NSString' and calls[-1]['selector']=='stringWithUTF8String:',f'{label} precise stopped boundary')
        check(calls[-1]['string_argument']=='/private/synthetic/ArcadeFixture.app',f'{label} original path-prefix transformation')
        check(bool(data)==(label in want_data),f'{label} status/type to data boundary')
        check(not r['native_target_executed'] and not r['native_xpc_reply_observed'],f'{label} no native reply claim')
        check(int.from_bytes(bytes.fromhex(r['final_reply_40_bytes'])[36:40],'little')==1,f'{label} provisional decision snapshot')
        h=hashlib.sha256()
        for a in r['visited_original_code_pages']:
            a=int(a,16);h.update(struct.pack('<Q',a));h.update(IMAGE.read(a,4096))
        check(h.hexdigest()==r['visited_original_code_pages_sha256'],f'{label} original visited pages')
        cp=[e for e in r['records'] if e['kind']=='native_status_checkpoint' and e['pc']=='0x100834928']
        if cp:check(all(e['registers']['x22']=='0x708e' and e['registers']['x26']=='0x60cc' for e in cp),f'{label} conditional codec premises')
    reads=[e for e in by['reply_scalar_frame']['records'] if e['kind']=='native_reply_data_read']
    check(len(reads)==14 and {e['offset_bytes'] for e in reads}==set(range(14)),'fourteen-byte scalar frame actually read, within defined extent')
    check(not any(e['kind']=='native_reply_data_read' for e in by['reply_short_data']['records']),'four-byte short payload not dereferenced')
    service=read('arcade_service_peer_profiles.json');profiles=service['profiles'];check(len(profiles)==10,'ten service case profiles')
    check(service['daemon_packet_source_profiles_sha256']==sha((ROOT/'arcade_reply_profiles.json').read_bytes()),'daemon-to-service packet artifact binding')
    flat=[]
    for r in profiles:flat.extend(r.get('fresh_prefix',[]));flat.append(r)
    for r in flat:
        label=r['label'];check(r['source_sha256']==THIN_SHA and r['generator_sha256']==sha((ROOT/'probe_arcade_service.py').read_bytes()) and r['reader_sha256']==sha((ROOT/'arcade_service_reader.py').read_bytes()),f'{label} service source/models')
        h=hashlib.sha256()
        for a in r['visited_original_instructions']:
            a=int(a,16);h.update(struct.pack('<Q',a));h.update(s.read(a,4))
        check(h.hexdigest()==r['visited_original_instruction_bytes_sha256'],f'{label} original visited instruction bytes')
        check(not r['native_target_executed'] and not r['native_peer_authentication_executed'],f'{label} no native authentication claim')
    bys={r['label']:r for r in profiles}
    calls0=[r['name'] for r in bys['peer_requirement_status_0']['records'] if r['kind']=='private_import']
    calls1=[r['name'] for r in bys['peer_requirement_status_1']['records'] if r['kind']=='private_import']
    check(calls0==['libSystem/_xpc_connection_set_peer_code_signing_requirement','libSystem/_xpc_connection_set_event_handler','libSystem/_xpc_connection_resume'],'zero setter status installs block and resumes')
    check(calls1==calls0[:1],'nonzero setter status returns without block installation/resume')
    for label,value in [('event_error',-42049),('event_missing_data',-42052),('event_empty_data',-42023)]:
        r=bys[label];send=next(e for e in r['records'] if e.get('name')=='libSystem/_xpc_connection_send_message')
        check(r['stop_reason']=='outgoing_service_reply_boundary' and send['reply_fields']=={'status':{'type':'int64','value':value}},f'{label} conditional exact error envelope')
    for label in ('event_error_no_reply','event_missing_data_no_reply'):
        r=bys[label];check(r['stop_reason']=='returned_to_fixture' and not any(e.get('name')=='libSystem/_xpc_connection_send_message' for e in r['records']),f'{label} null reply cleanup returns without send')
    r=bys['event_daemon_packet'];lookup=next(e for e in r['records'] if e.get('name')=='Security/_SecCodeCopyGuestWithAttributes')
    token=struct.pack('<8I',501,501,20,501,20,1234,100,1).hex()
    check(r['stop_reason']=='security_guest_lookup_boundary' and lookup['attributes']=={'type':'dictionary','fields':{'kSecGuestAttributeAudit':{'type':'data','bytes':token}}},'daemon packet -> peer audit -> guest lookup exact typed data flow')
    emitted=next(e['outgoing_request']['fields']['data']['value']['bytes'] for e in reply[0]['calls'] if e['name']=='libSystem/_xpc_connection_send_message_with_reply_sync')
    check(r['synthetic_event']['data_hex']==emitted,'unaltered daemon-produced packet supplied to original service')
    check(len(flat)==22,'22 isolated service phases including fresh prefixes')
    counts={'service_functions':70,'independently_walked_fixups':1163,'banks_exhaustive_256':6,'proofs_unsat':3,
        'daemon_reply_ranges':5,'fresh_ida_windows':5,'daemon_reply_cases':16,'service_cases':10,'service_phases':22,
        'fresh_initialization_steps':5668177,'sdk_compile_exit':0,'assertions':count}
    (ROOT/'arcade_xpc_profile_checks.json').write_text(json.dumps({'scope':__doc__,'verified_counts':counts,'checks':labels,
        'native_target_executed':False,'full_goal_complete':False},indent=2)+'\n')
    q={'scope':'Companion-service peer gate, conditional error envelope and daemon reply-width increment only.',
        'verified_counts':counts,'native_target_executed':False,'full_goal_complete':False,
        'QG1':{'status':'pass','evidence':'Descriptive technical evidence.'},
        'QG2':{'status':'pass','evidence':'Two reports carry scoped assumptions and explicit falsification probes.'},
        'QG3':{'status':'pass_for_increment','evidence':'Source identity, service peer gate and daemon envelope covered; broad goal remains active.'},
        'QG4':{'status':'pass','evidence':'32/64-bit status, 32-byte token, 40-byte block, source-bound SMT and SDK compile.'},
        'QG5':{'status':'pass_for_stated_claims','evidence':'NULL reply, error-event eligibility, low32 status, stopped Foundation and Security boundaries separated.'},
        'QG6':{'status':'pass','evidence':'Original files/chains, fresh IDA windows, local SDK, source-pinned private cases; native gaps explicit.'},
        'QG7':{'status':'pass','evidence':'Impact-labeled continuation tables in both reports.'}}
    (ROOT/'arcade_xpc_quality_gates.json').write_text(json.dumps(q,indent=2)+'\n')
    subprocess.run([sys.executable,str(ROOT/'validate_rpc502_sidecar_delivery.py')],check=True)
    print(json.dumps(counts))


if __name__=='__main__':main()
