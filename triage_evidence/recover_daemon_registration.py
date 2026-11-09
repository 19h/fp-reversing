#!/usr/bin/env python3
"""Original-image service names, registration ABI and local startup linkage.

O(B+F+I+T) extraction time/space for image bytes B, fixups/starts F, retained
instructions I and trace bytes T; nine fixed-pattern searches are O(B).
SMT cost is separate. No target, host IPC, loader or IDB mutation executes.
"""
import bisect
import hashlib
import json
from pathlib import Path
import struct
import subprocess
from daemon_receive_tools import IMAGE,SOURCE,FIXUPS,CS,ROOT,TABLE,POOL,selected,qword,verify_original_fixups
from daemon_import_bindings import binding
from bootpolicy_cache_reader import uleb
from resolve_kernel_collection_interfaces import commands
from probe_daemon_registration import RANGES


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    starts=[];entry=None
    for at,cmd,n in commands(IMAGE.data,0):
        if cmd==0x26:
            off,size=struct.unpack_from('<II',IMAGE.data,at+8);buf=IMAGE.data[off:off+size];cur=0;address=0x100000000
            while cur<len(buf):
                delta,cur=uleb(buf,cur)
                if not delta:break
                address+=delta;starts.append(address)
        elif cmd==0x80000028:entry=0x100000000+struct.unpack_from('<Q',IMAGE.data,at+8)[0]
    assert entry==0x100413bb4
    spans=RANGES+[(0x100413bb4,0x100413fc0),(0x1000a352c,0x1000a3638),
        (0x1004412b4,0x100441580),(0x10045053c,0x100450788),(0x100437c18,0x100437f90),
        (0x1005757cc,0x100575870),(0x100001f50,0x100001f9c),(0x100e2a8e0,0x100e2a8f0)]
    ranges=[]
    for a,z in spans:
        raw=IMAGE.read(a,z-a);ins=list(CS.disasm(raw,a));assert len(ins)*4==z-a
        ix=bisect.bisect_right(starts,a)-1;assert ix>=0
        end=starts[ix+1] if ix+1<len(starts) else None
        ranges.append({'start':hex(a),'end':hex(z),'bytes':raw.hex(),'sha256':hashlib.sha256(raw).hexdigest(),
            'compiler_start':hex(starts[ix]),'next_compiler_start':None if end is None else hex(end),
            'complete_compiler_range':a==starts[ix] and z==end,
            'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ins]})
    # Every bank is exhaustive over all 256 possible live selector-byte values.
    A=(0x100fc4230,0x101031fa0);B=(0x100fc4130,0x101031ea0)
    C=(0x101031da0,0x100e99900);D=(0x100e99a00,0x100f4e390)
    E=(0x100e99700,0x100f4e190);F=(0x100e99800,0x100f4e290)
    cases=[
      ('bootstrap checkin',D,0x54,0xce65,TABLE,0,'libSystem/_bootstrap_check_in'),
      ('bootstrap data',A,0x6c,0x29c,POOL,0,'libSystem/_bootstrap_port'),
      ('CF existing name wrapper',C,0x86,0xcc8d,TABLE,0,0x100001f9c),
      ('CF source',B,0xbb,0xcc78,TABLE,0,'CoreFoundation/_CFMachPortCreateRunLoopSource'),
      ('CF main run loop',E,0x56,0xcd2d,TABLE,0,'CoreFoundation/_CFRunLoopGetMain'),
      ('CF default mode data',B,0xbb,0xc05,POOL,0,'CoreFoundation/_kCFRunLoopDefaultMode'),
      ('CF add source',B,0x4e,0xcca4,TABLE,0,'CoreFoundation/_CFRunLoopAddSource'),
      ('CF source release',B,0x4e,0xcb7f,TABLE,0,'CoreFoundation/_CFRelease'),
      ('CF invalidate',B,0xa3,0xcbe1,TABLE,0,'CoreFoundation/_CFMachPortInvalidate'),
      ('service helper call1',A,0xf3,0xcbfc,TABLE,0,0x10044011c),
      ('service helper call2',A,0xe4,0xcbe2,TABLE,0,0x10044011c),
      ('service helper call3-4',B,0xa3,0xcbcd,TABLE,0,0x10044011c),
      ('service helper call5',E,0x56,0xcc2b,TABLE,0,0x10044011c),
      ('service header',B,0xa3,0xafb,POOL,0xffffffffc53e9a7d,0x1010c4cd8),
      ('unfreed bytes cell',D,0x6d,0x302,POOL,0xffffffff8e054906,0x1010b8c48),
      ('fairplayd bytes cell',C,0xa,0xa74,POOL,0xffffffffbcee1682,0x1010b5dd8),
      ('fpsd bytes cell',E,0x81,0x706,POOL,0xffffffffa71fad32,0x1010b5d68),
      ('arcade bytes cell',D,0x6d,0x6e9,POOL,0xffffffffb7c46bb9,0x1010b70c0),
      ('sim bytes cell',B,0xbb,0x11ba,POOL,0xffffffffaafc7825,0x1010b5dc0),
      ('service stack adapter body',A,0x6c,0xce28,TABLE,0,0x100537b90),
      ('main registration stack adapter',A,0xe4,0xce30,TABLE,0,0x100539234),
      ('main pre-registration helper',B,0xbb,0xcd60,TABLE,0,0x100437c18),
      ('main bootstrap wrapper',B,0x4e,0xcdad,TABLE,0,0x1004412b4),
      ('once API',D,0xd7,0xcb66,TABLE,0,'libSystem/_pthread_once'),
      ('once control',A,0xe4,0x101,POOL,0xffffffff8740c482,0x1010b70c8),
      ('initialization status',C,0xa,0xff4,POOL,0xfffffffff40d6a02,0x1010b6360),
      ('independent new-port wrapper call',E,0x56,0xccdb,TABLE,0,0x100001f50),
    ]
    banks=[]
    for label,pair,key,add,base,bias,want in cases:
        r=selected(*pair,key,add,base,bias);assert r['target']==(hex(want) if isinstance(want,int) else want),(label,r)
        r['label']=label;banks.append(r)
    names=[]
    for cell,n,m,k,name,off,call in [
      (0x1010b8c48,18,-5,0x6c,'com.apple.unfreed',0x18,0x100538040),
      (0x1010b5dd8,20,0x35,0x32,'com.apple.fairplayd',0x20,0x10053823c),
      (0x1010b5d68,15,0xf1,-0x4f,'com.apple.fpsd',0x28,0x100538444),
      (0x1010b70c0,22,0xd3,-4,'com.apple.arcade.fpsd',0x30,0x10053865c),
      (0x1010b5dc0,19,None,0xfc,'com.apple.fpsd.sim',0x40,0x10053882c)]:
        a=qword(cell);raw=IMAGE.read(a,n)
        decoded=bytes((b^k) if m is None else ((m*b+k)&255) for b in raw)
        assert decoded==name.encode()+b'\0'
        names.append({'name':name,'source_cell':hex(cell),'source_address':hex(a),'source_bytes':raw.hex(),
            'source_sha256':hashlib.sha256(raw).hexdigest(),'decoded_hex':decoded.hex(),
            'decoder':{'multiply':m,'add_or_xor':k,'width_bits':8},'helper_call':hex(call),
            'destination_cell':hex(0x1010c4cd8+off),'header_offset_bytes':off})
    # Inspect the complete service routine, not only modeled executions, for
    # the unchecked sequence and the single final status load.
    service=next(r for r in ranges if r['start']=='0x100537b90')
    callsites=[int(i['ea'],16) for i in service['instructions'] if i['mnemonic']=='blraa']
    assert callsites==[int(r['helper_call'],16) for r in names]
    loads=[i['ea'] for i in service['instructions'] if i['mnemonic'].startswith('ld') and '[x29, #-0x78]' in i['operands']]
    assert loads==['0x100538830']
    checks=[]
    for a,m,o,label in [
      (0x10044026c,'ldr','x1, [x0, #8]','service name is record+8'),
      (0x100440270,'str','wzr, [sp, #0x24]','receive-name output starts zero'),
      (0x100440384,'add','x2, sp, #0x24','checkin out receive-name pointer'),
      (0x10044038c,'blraa','x8, x17','bootstrap checkin API call'),
      (0x1003ad1c8,'ldr','w0, [sp, #0x24]','received name forwarded to CF wrapper'),
      (0x1003ad234,'blraa','x8, x17','existing-name wrapper call'),
      (0x10031733c,'blraa','x8, x17','source creation API call'),
      (0x100315264,'blraa','x8, x17','get main loop API call'),
      (0x100315300,'blraa','x8, x17','add source API call'),
      (0x10031534c,'blraa','x8, x17','release local source reference'),
      (0x100315354,'str','x20, [x8]','publish CF object after source add/release'),
      (0x1001ce8cc,'blraa','x8, x17','failed source: invalidate CF object'),
      (0x1001ce910,'blraa','x8, x17','failed source: release CF object'),
      (0x1001f531c,'str','w8, [x19, #0x10]','helper status only, destination unchanged on failure'),
      (0x100538830,'ldur','w8, [x29, #-0x78]','only final helper status is read'),
      (0x100538838,'str','w8, [x9]','last helper status becomes service-routine result word'),
      (0x1000a35c8,'add','w23, w24, w8','main local scalar 26de+6b67=9245'),
      (0x1000837cc,'str','w9, [x20, #0x10c]','main encodes service input word'),
      (0x1000838ac,'blraa','x8, x17','main calls stack adapter'),
      (0x100539464,'blraa','x8, x17','adapter calls five-service routine'),
      (0x1005393ac,'sub','x16, x21, #0xf0','adapter subtracts240 from temporary seed'),
      (0x100537cf4,'add','x10, x10, #0xf0','service restores240 to temporary seed'),
      (0x100539470,'ubfiz','x8, x8, #4, #0x10','adapter publishes aligned low16-bit frame delta'),
      (0x1004414e8,'blraa','x8, x17','once initializer call'),
      (0x1004414d8,'paciza','x16','sign initializer literal 10045053c'),
      (0x100575840,'blraa','x8, x17','independent new-port wrapper call; owner route unresolved'),
      (0x100001f8c,'bl','#0x100e2a8e0','new-port wrapper reaches CF create stub'),
    ]:
        raw=IMAGE.read(a,4);i=next(CS.disasm(raw,a));assert (i.mnemonic,i.op_str)==(m,o),(hex(a),i.mnemonic,i.op_str)
        checks.append({'address':hex(a),'bytes':raw.hex(),'mnemonic':m,'operands':o,'meaning':label})
    queries={
      'main_control_encoding':'''(declare-fun p () (_ BitVec 32))
(assert (= (bvand p #x00000007) #x00000000))
(define-fun x () (_ BitVec 32) (bvxor (bvadd (bvsub (bvshl (bvand p #x672f8260) #x00000001) p) #x98d07d9b) #xe422f67b))
(define-fun enc () (_ BitVec 32) (bvadd (bvmul x #x83918153) #x00009245 #xf449e622))
(assert (not (= (bvsub enc (bvmul #x83918153 (bvxor p #x7cf28be0))) #xf44a7867)))''',
      'first_record_control':'''(declare-fun p () (_ BitVec 32))
(assert (= (bvand p #x00000007) #x00000000))
(define-fun x () (_ BitVec 32) (bvxor (bvsub (bvor p #xecc7b172) (bvand p #xecc7b170)) #x74b91df8))
(define-fun enc () (_ BitVec 32) (bvsub #x00002e4c (bvmul x #x316f29c1)))
(assert (not (= (bvadd enc (bvmul #x316f29c1 (bvxor p #x987eac8a))) #x00002e4c)))''',
      'checkin_status_edge':'''(declare-fun status () (_ BitVec 32))
(define-fun idx () (_ BitVec 32) (bvxor #x00002e4c (bvmul (ite (= status #x00000000) #x00000001 #x00000000)
 (bvxor (bvand (bvsub #x00002e4c #x20542f0e) #x20542ef7) #x0000c520))))
(assert (not (= idx (ite (= status #x00000000) #x0000c55a #x00002e4c))))''',
      'cf_object_edge':'''(declare-fun object () (_ BitVec 64))
(define-fun state () (_ BitVec 32) (bvor (bvsub #x00002e36 #x00002a36) #x00008991))
(define-fun idx () (_ BitVec 32) (bvxor #x00002e36 (bvmul (ite (= object #x0000000000000000) #x00000001 #x00000000)
 (bvxor (bvsub state #x00005f45) #x00002e36))))
(assert (not (= idx (ite (= object #x0000000000000000) #x00002e4c #x00002e36))))''',
      'source_object_edge':'''(declare-fun object () (_ BitVec 64))
(define-fun state () (_ BitVec 32) #x00008d91)
(define-fun a () (_ BitVec 32) (bvmul (bvxor state #x00008d93) #x00001726))
(define-fun b () (_ BitVec 32) (bvor (bvsub state #x00006d8d) #x00000e48))
(define-fun idx () (_ BitVec 32) (bvxor state (bvmul (ite (= object #x0000000000000000) #x00000001 #x00000000) (bvxor (bvadd a #x0000002a) b))))
(assert (not (= idx (ite (= object #x0000000000000000) #x00008dab #x00008d91))))''',
      'mode_import_addend':'''(declare-fun symbol () (_ BitVec 64))
(assert (not (and (= (bvadd symbol #x000000007ed8f1f2 #xffffffff81270e0e) symbol)
 (= (bvadd symbol #x000000007da61013 #xffffffff8259efed) symbol))))'''}
    queries['main_last_status_gate']='''(declare-fun status () (_ BitVec 32))
(define-fun expected () (_ BitVec 32) (bvxor (bvadd #x00009245 #x626313dc) (bvxor #x00009245 #x0000c831)))
(define-fun idx () (_ BitVec 32) (bvxor #x00009245 (bvmul #x00003f6d (ite (= status expected) #x00000001 #x00000000))))
(assert (not (and (= expected #x6263fc55) (= idx (ite (= status #x6263fc55) #x0000ad28 #x00009245)))))'''
    queries['adapter_frame_delta']='''(declare-fun seed () (_ BitVec 64))
(define-fun returned () (_ BitVec 64) (bvadd (bvsub seed #x00000000000000f0) #x00000000000000f0))
(define-fun delta32 () (_ BitVec 32) (bvsub ((_ extract 31 0) returned) ((_ extract 31 0) seed)))
(define-fun published () (_ BitVec 64) (bvshl ((_ zero_extend 48) ((_ extract 15 0) delta32)) #x0000000000000004))
(assert (not (= published #x0000000000000000)))'''
    proofs=[]
    for name,body in queries.items():
        p=ROOT/f'daemon_registration_{name}.smt2';p.write_text('(set-logic QF_BV)\n'+body+'\n(check-sat)\n')
        answer=subprocess.run(['z3','-smt2',str(p)],check=True,capture_output=True,text=True,timeout=30).stdout.strip()
        assert answer=='unsat',(name,answer);proofs.append({'name':name,'file':p.name,'result':answer,'scope':'lifted local arithmetic, not native reachability/PAC'})
    branches=[]
    for ix,want in [(0xc55a,0x1003ad1a8),(0x2e4c,0x1001f531c),(0x2e36,0x1003172bc),
                    (0x8d91,0x1003151e8),(0x8dab,0x1001ce87c),(0x26de,0x100083778),
                    (0xad28,0x10009697c),(0x9245,0x100027310)]:
        a=TABLE+8*ix;assert qword(a)==want
        branches.append({'index':hex(ix),'slot':hex(a),'target':hex(want),'original_fixup':FIXUPS[a]})
    used=[int(r['slot'],16) for r in banks]+[int(r['slot'],16) for r in branches]
    used += [int(r['source_cell'],16) for r in names]+[0x1010b1c48,0x1010b1c40]
    # The earlier generic checker deliberately accepts only zero-addend binds.
    # Use the dedicated original import/addend decoder for these data imports.
    original=verify_original_fixups([a for a in used if not FIXUPS[a]['kind'].endswith('bind')])
    imports=[binding(int(r['slot'],16)) for r in banks if isinstance(FIXUPS[int(r['slot'],16)]['target'],str)]
    imports += [binding(0x1010b1c48),binding(0x1010b1c40)]
    live=json.loads((ROOT/'daemon_registration_live_ranges.json').read_text())
    for r in live['results']:assert IMAGE.read(int(r['address'],16),len(bytes.fromhex(r['bytes']))).hex()==r['bytes'].lower()
    trace=json.loads((ROOT/'zut_trace_decoded.json').read_text());trace_path=Path(trace['trace_path'])
    assert sha(trace_path)==trace['trace_sha256']=='78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e'
    seen=[]
    for e in trace['events']:
        if e['direction']!='send' or e['id']!=0x400000ce:continue
        raw=bytes.fromhex(e['message_hex']);found=[r['name'] for r in names if r['name'].encode()+b'\0' in raw]
        assert len(found)==1;seen.append({'name':found[0],'line':e['line'],'message_id':e['id']})
    assert [r['name'] for r in names]==[r['name'] for r in seen]
    sdk=subprocess.run(['xcrun','--show-sdk-path'],check=True,capture_output=True,text=True).stdout.strip()
    header=Path(sdk)/'usr/include/servers/bootstrap.h';copy=ROOT/'daemon_registration_sdk_bootstrap.h.txt';copy.write_bytes(header.read_bytes())
    cmd=['xcrun','clang','-target','arm64e-apple-macos13.0','-isysroot',sdk,'-std=c11','-Wall','-Werror','-fsyntax-only',str(ROOT/'daemon_registration_layouts.c')]
    comp=subprocess.run(cmd,capture_output=True,text=True);assert comp.returncode==0,comp.stderr
    result={'scope':__doc__,'source':{'path':str(SOURCE),'sha256':sha(SOURCE),'entrypoint':hex(entry)},
        'generator_sha256':sha(Path(__file__)),'compiler_starts_count':len(starts),'ranges':ranges,
        'bank_proofs':banks,'services':names,'branch_slots':branches,'native_instruction_checks':checks,
        'unchecked_sequence':{'native_call_sites':[hex(a) for a in callsites],'status_loads':loads,
            'last_status_only':True,'assumption':'each helper and imported API returns normally'},
        'original_fixup_checks':original,'imports':imports,'proofs':proofs,'live_ida_ranges_matched':live['count'],
        'trace_service_order':seen,'trace_sha256':trace['trace_sha256'],
        'layout_compile':{'command':cmd,'exit_code':comp.returncode,'stderr':comp.stderr,
            'source_sha256':sha(ROOT/'daemon_registration_layouts.c'),'sdk_header':str(header),'sdk_header_sha256':sha(copy)},
        'native_target_executed':False,'target_host_operations_executed':False,'idb_mutated':False,
        'full_goal_complete':False}
    (ROOT/'daemon_registration_contracts.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'ranges':len(ranges),'complete_compiler_ranges':sum(r['complete_compiler_range'] for r in ranges),
        'banks_256':len(banks),'services':len(names),'proofs_unsat':len(proofs),'native_instruction_checks':len(checks),
        'live_ida_ranges':live['count'],'trace_service_matches':len(seen),'layout_compile_exit':comp.returncode}))


if __name__=='__main__':main()
