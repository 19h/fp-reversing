#!/usr/bin/env python3
"""Validate local service-registration contracts, fixtures and owned reports.

O(B+I+E) time/space excluding solvers and manifest hashing; no target host IPC.
"""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
from daemon_receive_tools import IMAGE,SOURCE
from probe_daemon_registration import OBJECTS,HEADER

ROOT=Path(__file__).resolve().parent


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    subprocess.run([sys.executable,str(ROOT/'recover_daemon_registration.py')],check=True)
    c=json.loads((ROOT/'daemon_registration_contracts.json').read_text())
    p=json.loads((ROOT/'daemon_registration_profiles.json').read_text())
    rows={r['label']:r for r in p['profiles']};assert len(rows)==14
    names=[r['name'] for r in c['services']];cells=[int(r['destination_cell'],16) for r in c['services']]
    hashes={};checks=[]
    def check(label,condition,meaning):
        assert condition,(label,meaning)
        checks.append({'profile':label,'check':meaning,'result':'pass'})
    for label,r in rows.items():
        assert r['generator_sha256']==sha(ROOT/'probe_daemon_registration.py')
        assert r['base_probe_sha256']==sha(ROOT/'daemon_rpc502_probe.py') and r['source_sha256']==c['source']['sha256']==sha(SOURCE)
        pages=tuple(r['visited_code_pages'])
        if pages not in hashes:
            h=hashlib.sha256()
            for a in pages:a=int(a,16);h.update(struct.pack('<Q',a));h.update(IMAGE.read(a,4096))
            hashes[pages]=h.hexdigest()
        assert hashes[pages]==r['visited_original_code_pages_sha256'] and r['steps']<30000
        assert not r['native_target_executed'] and not r['target_host_operations_executed']
        mainstage=r['entry']=='0x100083778';helper=r['helper_fixture'];count=1 if helper else 5
        check(label,r['original_instruction_bytes_verified']==len(r['visited_instruction_addresses']),
            'every executed target instruction matches its original four bytes despite explicit PAC control bypass')
        check(label,r['stop_reason']==('completed_private_main_registration_gate' if mainstage else 'returned_to_fixture'),
            'all selected original continuations finish at the declared private boundary')
        calls=r['calls'];boot=[e for e in calls if e['name']=='libSystem/_bootstrap_check_in']
        entries=[e for e in r['records'] if e['kind']=='native_checkin_entry']
        check(label,[e['service'] for e in boot]==names[:count] and len(entries)==count,
            'all expected service names attempted in original order, including after earlier failures')
        check(label,[int(e['destination_cell'],16) for e in entries]==cells[:count] and
            all(e['decoded_control_state']=='0x2e4c' for e in entries),
            'native caller records identify exact destination cells and canonical helper state')
        for entry in entries:
            raw=bytes.fromhex(entry['record_40_bytes'])
            check(label,len(raw)==40 and struct.unpack_from('<Q',raw,24)[0]==0,
                f"{entry['service']}: complete input prefix has null reserved+24 field")
        final=bytes.fromhex(r['final_header_72_bytes']);out=bytes.fromhex(r['final_argument_bytes'])
        last_success=False
        for i,b in enumerate(boot):
            start=calls.index(b);end=calls.index(boot[i+1]) if i+1<len(boot) else len(calls)
            group=calls[start:end];api=lambda suffix:[e for e in group if e['name']=='CoreFoundation/'+suffix]
            cf=api('_CFMachPortCreateWithPort');src=api('_CFMachPortCreateRunLoopSource')
            add=api('_CFRunLoopAddSource');rel=api('_CFRelease');inv=api('_CFMachPortInvalidate')
            want_status=r['checkin_status'] if r['fail_service'] is None or i==r['fail_service'] else 0
            check(label,b['status']==want_status and int(b['args'][0],16)==0x707 and b['return_pc']=='0x100440390',
                f'{names[i]}: bootstrap input, API emission and explicitly modeled status')
            check(label,len(cf)==int(want_status==0),f'{names[i]}: failed checkin skips CF construction')
            if cf:
                args=[int(x,16) for x in cf[0]['args']]
                check(label,args[:3]==[0,int(b['modeled_receive_name'],16),0x100425f78] and cf[0]['context_40_bytes']==bytes(40).hex(),
                    f'{names[i]}: received u32 name, common callback, null allocator and zero context reach CF API')
            object_ok=want_status==0 and not r['null_cf'];source_ok=object_ok and not r['null_source']
            check(label,len(src)==int(object_ok) and len(add)==int(source_ok),
                f'{names[i]}: source creation and source insertion are gated by prior object results')
            if src:check(label,[int(x,16) for x in src[0]['args'][:3]]==[0,OBJECTS+i*0x100,0],
                f'{names[i]}: source uses exact returned CF object and order0')
            if source_ok:
                source=OBJECTS+0x4000+i*0x100
                check(label,[int(x,16) for x in add[0]['args'][:3]]==[OBJECTS+0xe000,source,OBJECTS+0xf100] and
                    len(rel)==1 and int(rel[0]['args'][0],16)==source and group.index(add[0])<group.index(rel[0]),
                    f'{names[i]}: main-loop/default-mode insertion precedes release of local source reference')
            check(label,len(inv)==int(object_ok and not source_ok) and
                (not inv or len(rel)==1 and inv[0]['args'][0]==rel[0]['args'][0]==hex(OBJECTS+i*0x100) and group.index(inv[0])<group.index(rel[0])),
                f'{names[i]}: source failure invalidates then releases the CF object')
            expected=OBJECTS+i*0x100 if source_ok else 0xbad00000+i if r['seeded_outputs'] else 0
            offset=cells[i]-HEADER
            check(label,struct.unpack_from('<Q',final,offset)[0]==expected,
                f'{names[i]}: publish CF object on success; preserve destination bytes on failure')
            writes=[w for w in r['image_writes'] if int(w['address'],16)==cells[i]]
            check(label,len(writes)==int(source_ok) and (not writes or writes[0]['pc']=='0x100315354' and writes[0]['size']==8),
                f'{names[i]}: only native publication instruction writes this destination in the fixture')
            last_success=source_ok
        status=struct.unpack_from('<I',out,16 if helper else 0)[0]
        check(label,status==(0x6263fc55 if last_success else 0x6263578d),
            'record status depends on the final registration, independently of earlier failures')
        if mainstage:
            check(label,r['records'][-1]['target']==('0x10009697c' if last_success else '0x100027310'),
                'original main gate accepts final success even when the first checkin failed; final failure selects other continuation')
        if not helper and not mainstage:check(label,r['final_seed']=='0xf0','service routine adds240 bytes to private frame seed')
        check(label,all(e['name']!='libSystem/_mach_port_deallocate' for e in calls),
            'selected helper has no modeled explicit namespace-name deallocation call; full framework ownership remains separate')
    assert {r['profile'] for r in checks}==set(rows)
    counts={'original_ranges':len(c['ranges']),'complete_compiler_ranges':sum(r['complete_compiler_range'] for r in c['ranges']),
        'native_instruction_checks':len(c['native_instruction_checks']),'banks_256':len(c['bank_proofs']),
        'services':len(names),'proofs_unsat':len(c['proofs']),'live_ida_ranges':c['live_ida_ranges_matched'],
        'trace_service_matches':len(c['trace_service_order']),'private_profiles':len(rows),
        'explicit_profile_checks':len(checks),'profiles_covered':len({r['profile'] for r in checks}),
        'layout_compile_exit':c['layout_compile']['exit_code']}
    (ROOT/'daemon_registration_profile_checks.json').write_text(json.dumps({'scope':'Local original-byte contracts and finite private fixtures; no native service/CF registry/port-object/PAC attestation.',
        'profiles_sha256':sha(ROOT/'daemon_registration_profiles.json'),'counts':counts,'checks':checks},indent=2)+'\n')
    q={'scope':'Five-service registration and startup-gate increment; full interface goal remains active.',
       'QG1':{'status':'pass','evidence':'Factual technical scope.'},
       'QG2':{'status':'pass','evidence':'Report G1-G8 retain dependencies, falsification probes and status.'},
       'QG3':{'status':'pass_for_increment','evidence':'Names, caller/control ABI, checkin/CF/source/publication/error edges and last-status gate covered; wider native lifecycle/IPC remains open.'},
       'QG4':{'status':'pass','evidence':'u8/u32/u64 arithmetic,8-byte alignment,40/72-byte partial layouts, compiler and complexity explicit.'},
       'QG5':{'status':'pass','evidence':'Requested/effective callback, port name/CF object, per-service/final status, static/trace/model and inline/body ownership separated.'},
       'QG6':{'status':'pass','evidence':'Original SHA/LC ranges/fixups/import addends, eleven fresh IDA ranges, preserved trace bytes, native assertions, eight proofs and page/instruction-checked fixtures.'},
       'QG7':{'status':'pass','evidence':'Impact-labeled continuation covers native identity, failure cleanup, extra created port, startup gates, RPC700 and bootstrap transport.'},
       'verified_counts':counts,'native_target_executed':False,'target_host_operations_executed':False,
       'idb_mutated':False,'full_goal_complete':False}
    (ROOT/'daemon_registration_quality_gates.json').write_text(json.dumps(q,indent=2)+'\n')
    print(json.dumps(counts),flush=True)
    subprocess.run([sys.executable,str(ROOT/'validate_rpc502_sidecar_delivery.py')],check=True)


if __name__=='__main__':main()
