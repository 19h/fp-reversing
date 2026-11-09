#!/usr/bin/env python3
"""Original libnotify/notifyd IPC,metadata,MIG and source interface catalog.

Original code/fixups/SDK layout compilation; four bounded local QF_BV proofs.
No native target/loader/service/IPC. O(B+F+I+E+C) time/space plus solver bounds.
Static inventories do not establish whole-path or native feasibility.
"""
import json
from pathlib import Path
import struct
import subprocess
from notify_ipc_reader import Notify,ROOT,sha,CS
from notifyd_ipc_reader import Notifyd,THIN_SHA


def main():
    s=Notify();d=Notifyd();ci=json.loads((ROOT/'notify_ipc_inventory.json').read_text());di=json.loads((ROOT/'notifyd_ipc_inventory.json').read_text());cp=json.loads((ROOT/'notify_ipc_profiles.json').read_text());dp=json.loads((ROOT/'notifyd_ipc_profiles.json').read_text())
    table=[]
    for j in range(33):
        a=0x1000104f0+j*40;raw=d.read(a,40);target=d.qword(a+8);argc,descs,args,maxreply=struct.unpack_from('<IIQI',raw,16);table.append({'message_id':1000+j,'record_address':hex(a),'record_bytes':raw.hex(),'stub_slot':hex(a+8),'stub_fixup':d.decoded.get(a+8),'resolved_stub':hex(target),'argument_count':argc,'descriptor_count':descs,'argument_descriptor_pointer':args,'max_reply_size_bytes':maxreply,'whole_worker_or_native_feasibility_established':False})
    notification_table=[]
    for j in range(9):
        a=0x100010368+j*40;raw=d.read(a,40);target=d.qword(a+8);argc,descs,args,maxreply=struct.unpack_from('<IIQI',raw,16);notification_table.append({'message_id':64+j,'record_address':hex(a),'record_bytes':raw.hex(),'stub_fixup':d.decoded.get(a+8),'resolved_stub':hex(target),'argument_count':argc,'descriptor_count':descs,'argument_descriptor_pointer':args,'max_reply_size_bytes':maxreply})
    demux_pointers=[d.decoded[a] for a in [0x100010280,0x100014000,0x100010348,0x1000104d0]]
    sec=next(x for x in d.sections if x['section']=='__auth_stubs');stubs={}
    for a in range(sec['address'],sec['address']+sec['size'],16):
        ins=list(CS.disasm(d.read(a,16),a));assert [i.mnemonic for i in ins]==['adrp','add','ldr','braa'];slot=int(ins[0].op_str.split('#')[1],16)+int(ins[1].op_str.split('#')[1],0);pointer=d.decoded[slot];assert pointer['bind'];stubs[a]={'address':hex(a),'bytes':d.read(a,16).hex(),'slot':hex(slot),'original_fixup':pointer,'symbol':pointer['import']['name']}
    edges=[]
    for a in d.starts:
        for ins in d.function(a)['instructions']:
            if ins['mnemonic'] in ['b','bl'] and ins['operands'].startswith('#'):
                target=int(ins['operands'][1:],16)
                if target in stubs:edges.append({'compiler_function_start':hex(a),**ins,'stub':stubs[target]})
    client_sends=[r for r in ci['original_direct_edges'] if r.get('external_target',{}).get('exact_exports') and '_mach_msg' in r['external_target']['exact_exports']]
    # Inventory schema retains resolved veneer, not inferred linkage.
    if not client_sends:
        for r in ci['original_direct_edges']:
            target=r.get('veneer',{}).get('resolved_target',{})
            if '_mach_msg' in target.get('exact_exports',[]):client_sends.append(r)
    observed=[]
    for case in cp['cases']:
        for ordinal,r in enumerate(case['calls']):
            for e in r['records']:
                if 'message_id_u32' in e:observed.append({'client_case':case['case']['label'],'call_ordinal':ordinal,**e})
    windows=[]
    for image,reader,a,z,role in [
      ('client',s,0x180593b38,0x180594370,'public check-registration,inline request1012 and reply1112 parser'),
      ('client',s,0x180594370,0x18059499c,'token checks,shared counters and RPC1002 fallback'),
      ('client',s,0x180596ad8,0x180597700,'posting,cached nameID1009 and uncached name1010'),
      ('client',s,0x18059a6c8,0x18059a7b0,'shared-memory mapping helper prefix'),
      ('client',s,0x1805494d4,0x180549548,'original kernel-library bounded zerofill MIG name copy'),
      ('provider',d,0x100001c7c,0x100001ef0,'registration worker,slot assignment,fresh counter1,output publication'),
      ('provider',d,0x1000097b8,0x100009a3c,'ID1009 name-ID lookup,audit/permission predicates,counter increment and delivery'),
      ('provider',d,0x100008dfc,0x100008e34,'MIG selector full32 range and40-byte rows'),
      ('provider',d,0x100009c3c,0x100009d64,'ID1012 variable-name validation,audit trailer,worker ABI'),
      ('provider',d,0x10000a8e4,0x10000a994,'ID1023 fixed24-byte checkin and audit trailer'),
      ('provider',d,0x100002f94,0x100003040,'checkin worker version3,pid,status0'),
      ('provider',d,0x1000012a4,0x100001400,'active-delivery direct Mach sender,token ID,queue/timeout flags'),
      ('provider',d,0x100001534,0x100001690,'port construction,MAKE_SEND insertion,SEND_POSSIBLE registration'),
      ('provider',d,0x100006034,0x100006104,'dispatch Mach event wrappers and selector demultiplexing'),
      ('provider',d,0x1000052b8,0x100006034,'main initialization,bootstrap,shared memory and Mach channels')]:
        raw=reader.read(a,z-a);windows.append({'image':image,'start':hex(a),'end':hex(z),'role':role,'bytes':raw.hex(),'sha256':sha(raw),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(raw,a)]})
    # Original NDR bytes are compared against the explicit external-data fixture.
    ndr={'original_pointer_member':s.pointer(0x1e01c8ab0),'cache_address':'0x1eb065de0','bytes':s.read(0x1eb065de0,8).hex(),'scope':'original pointer-derived NDR bytes; provider imported-data binding remains an explicit guest fixture'}
    queries={
      'notify_ipc_selector32.smt2':'''(set-logic QF_BV)
(declare-fun id () (_ BitVec 32))
(define-fun source () Bool (bvuge (bvsub id #x00000409) #xffffffdf))
(define-fun compact () Bool (and (bvuge id #x000003e8) (bvult id #x00000409)))
(assert (distinct source compact))''',
      'notify_ipc_registration_extent32.smt2':'''(set-logic QF_BV)
(declare-fun size () (_ BitVec 32))
(declare-fun count () (_ BitVec 32))
(define-fun aligned () (_ BitVec 32) (bvand (bvadd count #x00000003) #xfffffffc))
(define-fun range () Bool (bvuge (bvsub size #x0000022d) #xfffffdff))
(define-fun source () Bool (and range (bvule count #x00000200) (bvuge (bvsub size #x0000002c) count) (= size (bvadd aligned #x0000002c))))
(define-fun compact () Bool (and (bvule count #x00000200) (= size (bvadd aligned #x0000002c))))
(assert (distinct source compact))''',
      'notify_ipc_counter32.smt2':'''(set-logic QF_BV)
(declare-fun old () (_ BitVec 32))
(declare-fun first () (_ BitVec 32))
(declare-fun second () (_ BitVec 32))
(define-fun changed () (_ BitVec 32) (ite (= old first) #x00000000 #x00000001))
(define-fun next () (_ BitVec 32) (ite (= old first) old second))
(assert (or (distinct (= changed #x00000001) (distinct old first)) (and (= old first) (distinct next old)) (and (distinct old first) (distinct next second))))''',
      'notify_ipc_post_wrap32.smt2':'''(set-logic QF_BV)
(declare-fun counter () (_ BitVec 32))
(define-fun after_full_wrap () (_ BitVec 32) ((_ extract 31 0) (bvadd ((_ zero_extend 32) counter) #x0000000100000000)))
(assert (distinct counter after_full_wrap))'''}
    proofs=[]
    for name,body in queries.items():
        body='(set-option :timeout 30000)\n'+body+'\n(check-sat)\n';(ROOT/name).write_text(body);run=subprocess.run(['z3',str(ROOT/name)],capture_output=True,text=True,check=True);result=run.stdout.strip();assert result=='unsat' and not run.stderr,(name,result,run.stderr);proofs.append({'path':name,'sha256':sha(body.encode()),'result':result,'timeout_ms':30000,'scope':'only encoded arithmetic/source predicates; no native/path feasibility proof'})
    sdk=subprocess.check_output(['/usr/bin/xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip();cmd=['/usr/bin/xcrun','clang','-target','arm64e-apple-macos15.0','-isysroot',sdk,'-std=c11','-Wall','-Wextra','-Werror','-S','-O2',str(ROOT/'notify_ipc_layouts.c'),'-o',str(ROOT/'notify_ipc_layouts.s')];compile=subprocess.run(cmd,capture_output=True,text=True);assert compile.returncode==0,compile.stderr
    headers=[]
    for name in ['mach/message.h','mach/mig.h','mach/ndr.h','mach/notify.h','mach/port.h','notify.h']:
        p=Path(sdk)/'usr/include'/name;headers.append({'path':str(p),'sha256':sha(p.read_bytes())})
    out={'scope':__doc__,'cache_uuid':s.cache.uuid,'client_uuid':s.lib.uuid,'provider_thin_sha256':THIN_SHA,'generator_sha256':sha(Path(__file__).read_bytes()),'dependencies':{n:sha((ROOT/n).read_bytes()) for n in ['notify_ipc_reader.py','notifyd_ipc_reader.py','notify_ipc_inventory.json','notifyd_ipc_inventory.json','notify_ipc_profiles.json','notifyd_ipc_profiles.json']},'subsystem_header_address':'0x1000104d0','subsystem_header_original_bytes':d.read(0x1000104d0,32).hex(),'subsystem_header_server_pointer':d.decoded[0x1000104d0],'mig_rows':table,'mach_notification_rows':notification_table,'original_demux_table_pointers':demux_pointers,'mach_notification_header_bytes':d.read(0x100010348,32).hex(),'provider_import_stubs':list(stubs.values()),'provider_external_direct_edges':edges,'client_mach_msg_emission_sites':client_sends,'observed_client_messages':observed,'original_windows':windows,'original_NDR_record':ndr,'proofs':proofs,'sdk_compile':{'command':cmd,'exit_code':compile.returncode,'stderr':compile.stderr,'source_sha256':sha((ROOT/'notify_ipc_layouts.c').read_bytes()),'assembly_sha256':sha((ROOT/'notify_ipc_layouts.s').read_bytes()),'headers':headers,'target_execution':False},'native_target_executed':False,'full_goal_complete':False};(ROOT/'notify_ipc_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'mig_rows':len(table),'non_null_stubs':sum(r['resolved_stub']!='0x0' for r in table),'provider_stubs':len(stubs),'provider_external_edges':len(edges),'client_mach_msg_emission_sites':len(client_sends),'observed_messages':len(observed),'proofs':len(proofs),'ndr':ndr}),flush=True)

if __name__=='__main__':main()
