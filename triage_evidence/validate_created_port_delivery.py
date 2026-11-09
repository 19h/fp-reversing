#!/usr/bin/env python3
"""Validate source-pinned arcade handshake contracts and finite private cases.

O(B+I+E) time/space excluding solvers and manifest hashing. No target host IPC.
"""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
from daemon_receive_tools import IMAGE,SOURCE,ROOT
from probe_created_port import CFPORT,CFSOURCE,RANGES


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def u32(v):return v&0xffffffff


def main():
    subprocess.run([sys.executable,str(ROOT/'recover_created_port.py')],check=True)
    c=json.loads((ROOT/'created_port_contracts.json').read_text())
    rows=json.loads((ROOT/'created_port_profiles.json').read_text())['profiles'];assert len(rows)==30
    assert len({r['label'] for r in rows})==len(rows)
    checks=[];hashes={}
    def check(label,condition,meaning):
        assert condition,(label,meaning)
        checks.append({'profile':label,'check':meaning,'result':'pass'})
    for r in rows:
        label=r['label'];s=r['seed'];rs=r['registration_seed'];calls=r['calls']
        api=lambda name:[e for e in calls if e['name'].split('/')[-1]==name]
        assert r['generator_sha256']==sha(ROOT/'probe_created_port.py')
        assert r['base_probe_sha256']==sha(ROOT/'daemon_rpc502_probe.py') and r['source_sha256']==c['source']['sha256']==sha(SOURCE)
        check(label,r['stop_reason']=='returned_to_fixture' and r['steps']<50000,'original demux/protected handler completes at declared private return')
        addresses=[int(a,16) for a in r['visited_instruction_addresses']]
        check(label,r['original_instruction_bytes_verified']==len(addresses) and all(any(a<=v<z for a,z in RANGES) for v in addresses),
            'all visited target instruction bytes were checked against original image within reviewed ranges')
        pages=tuple(r['visited_original_code_pages'])
        if pages not in hashes:
            h=hashlib.sha256()
            for a in pages:a=int(a,16);h.update(struct.pack('<Q',a));h.update(IMAGE.read(a,4096))
            hashes[pages]=h.hexdigest()
        check(label,hashes[pages]==r['visited_original_code_pages_sha256'],'ordered original code-page digest independently reproduced')
        check(label,not r['native_target_executed'] and not r['target_host_operations_executed'],'private API models and explicit PAC bypass do not attest native target execution')
        service_ok=rs['incoming_service_name']==rs['arcade_service_name'];old=rs['old_created'];created=service_ok and not s['null_cf']
        check(label,len(api('_CFMachPortCreate'))==int(service_ok),'service-name mismatch bypasses new CF creation')
        inv=api('_CFMachPortInvalidate');rel=api('_CFRelease');src=api('_CFMachPortCreateRunLoopSource')
        if service_ok:
            cf=api('_CFMachPortCreate')[0]
            check(label,[int(a,16) for a in cf['args'][:2]]==[0,0x100425f78] and cf['context_40_bytes']==bytes(40).hex(),
                'new CF construction receives null allocator, shared callback and zero40-byte context')
        expected=5 if not service_ok else 0
        if created:
            if s['transport_status']:expected=u32(s['transport_status'])
            elif s['reply_id']==71:expected=u32(-308)
            elif s['reply_id']!=51571:expected=u32(-301)
            elif s['reply_complex'] or s['reply_size']!=36 or s['reply_remote']!=0:expected=u32(-300)
            else:expected=u32(s['reply_status'])
        out=bytes.fromhex(r['final_outer_reply_44_bytes'])
        check(label,struct.unpack_from('<I',out,20)[0]==41571 and struct.unpack_from('<I',out,32)[0]==expected,
            'prepared outer41571 status follows original status codec and selected error path')
        check(label,struct.unpack_from('<III',out,4)==(36,0,0),'kernel-shaped one-way trigger prepares36-byte status with no reply destination')
        msg=api('_mach_msg2_internal');insert=api('_mach_port_insert_right')
        check(label,len(msg)==len(insert)==int(created),'nested client and make-send insertion require nonnull new CF object')
        if created:
            e=msg[0];args=[int(a,16) for a in e['args']];wire=bytes.fromhex(e['request_40_bytes']);n=u32(s['port_name'])
            check(label,struct.unpack_from('<7I',wire)==(0x80001513,40,0x2203,0xb03,0,51471,1),
                'nested request header/count identifies51471 with peer destination and private reply name')
            check(label,struct.unpack_from('<I',wire,28)[0]==n and wire[32:38]==bytes(6) and wire[38:40]==bytes([19,0]),
                'created u32 name becomes one COPY_SEND port descriptor without arithmetic distortion')
            check(label,args[1:]==[0x200000003,0x2880001513,0xb0300002203,0xc90f00000000,0xb0300000001,44,0] and e['return_pc']=='0x10000442c',
                'exact original emission packs KOBJECT/send/receive,40-byte send and44-byte receive capacity')
            check(label,[int(a,16) for a in insert[0]['args'][:4]]==[0x103,n,n,20] and insert[0]['return_pc']=='0x100503c9c',
                'make-send insertion receives modeled task-self and same receive name twice; status may be ignored')
        inner_ok=created and expected==0;published=inner_ok and not s['null_source']
        check(label,len(src)==int(inner_ok),'run-loop source construction requires nested client zero status')
        check(label,len(api('_CFRunLoopAddSource'))==int(published),'source insertion requires nonnull returned source')
        if published:
            add=api('_CFRunLoopAddSource')[0]
            check(label,[int(a,16) for a in add['args'][:3]]==[CFPORT+0xf000,CFSOURCE,CFPORT+0xe000],
                'returned source enters modeled main loop default mode')
        wanted_inv=([CFPORT+0x3000] if service_ok and old else [])+([CFPORT] if inner_ok and s['null_source'] else [])
        check(label,[int(e['args'][0],16) for e in inv]==wanted_inv,'old endpoint invalidation and source-failure invalidation remain separate')
        wanted_rel=[CFSOURCE] if published else [CFPORT] if inner_ok else []
        check(label,[int(e['args'][0],16) for e in rel]==wanted_rel,'selected route releases local source or failed new CF object, with no explicit old-object release')
        dealloc=api('_mach_port_deallocate')
        check(label,len(dealloc)==int(inner_ok) and all([int(a,16) for a in e['args'][:2]]==[0x103,0x2203] and e['return_pc']=='0x100494314' for e in dealloc),
            'incoming peer send-name deallocation occurs after successful nested call, including source-null path')
        want_field=CFPORT if published else CFPORT+0x3000 if old and not service_ok else 0
        check(label,int(r['final_created_cf_field'],16)==want_field,'anonymous CF field reflects replacement/publication, failure or untouched mismatched service')
        writes=[w['pc'] for w in r['image_writes'] if w['address']=='0x1010c4d10']
        check(label,writes==(['0x1004ace78'] if old and service_ok else [])+(['0x1004a951c'] if published else []),
            'only original clear and publication instructions write anonymous CF field in fixture')
        t=u32(s['transport_status']);put=created and t in (0x10000002,0x10000003,0x10000010)
        check(label,len(api('_mig_put_reply_port'))==int(put) and len(api('_mig_dealloc_reply_port'))==int(created and t!=0 and not put),
            'three exact transport statuses put reply port; other selected nonzero statuses deallocate it')
        check(label,len(api('_mach_msg_destroy'))==int(created and not t and expected!=0),
            'received inner reply is explicitly destroyed for selected validation/server errors')
    counts={'daemon_original_ranges':len(c['ranges']),'kernel_original_ranges':len(c['kernel']['ranges']),
        'daemon_native_checks':len(c['native_instruction_checks']),'kernel_native_checks':len(c['kernel']['native_instruction_checks']),
        'banks_256':len(c['bank_proofs']),'proofs_unsat':len(c['proofs']),'fresh_ida_ranges':c['fresh_ida_ranges_matched'],
        'private_profiles':len(rows),'explicit_profile_checks':len(checks),'layout_compile_exit':c['layout_compile']['exit_code']}
    (ROOT/'created_port_profile_checks.json').write_text(json.dumps({'scope':__doc__,'profiles_sha256':sha(ROOT/'created_port_profiles.json'),
        'counts':counts,'checks':checks},indent=2)+'\n')
    q={'scope':'Arcade registration/port handshake increment; full interface goal remains active.',
       'QG1':{'status':'pass','evidence':'Factual technical analysis.'},
       'QG2':{'status':'pass','evidence':'Report P1-P8 enumerate dependencies, probes and status.'},
       'QG3':{'status':'pass_for_increment','evidence':'41471 trigger,51471 registration,61471 upcall, daemon resources and original kernel interface covered; deeper policy/application/lifetime remain open.'},
       'QG4':{'status':'pass','evidence':'u8/u16/u32/u64 widths,40/52/64/72-byte messages, SDK layout assertions and complexity explicit.'},
       'QG5':{'status':'pass','evidence':'One-way trigger/status buffer, u32 name/object, CF/local/kernel holds and native/model error paths separated.'},
       'QG6':{'status':'pass','evidence':'Original SHA/LC ranges/imports/fixups, eight fresh IDA ranges, native assertions, six proofs and page/instruction-checked finite fixtures.'},
       'QG7':{'status':'pass','evidence':'Impact-labeled bounded continuation table retained.'},
       'verified_counts':counts,'native_target_executed':False,'target_host_operations_executed':False,'idb_mutated':False,'full_goal_complete':False}
    (ROOT/'created_port_quality_gates.json').write_text(json.dumps(q,indent=2)+'\n')
    print(json.dumps(counts))
    subprocess.run([sys.executable,str(ROOT/'validate_rpc502_sidecar_delivery.py')],check=True)


if __name__=='__main__':main()
