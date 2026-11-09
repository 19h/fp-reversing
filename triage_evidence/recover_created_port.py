#!/usr/bin/env python3
"""Original daemon/kernel arcade registration and subscription ABI evidence.

O(B+F+I) extraction time/space for bytes, fixups and retained instructions.
The fixed-pattern kernel search is O(B). Solver cost is separate. Read-only
target inputs; no target process, host IPC/framework or IDB mutation.
"""
import bisect
import hashlib
import json
from pathlib import Path
import struct
import subprocess
from daemon_receive_tools import IMAGE,SOURCE,ROOT,CS,TABLE,POOL,FIXUPS,selected,qword,verify_original_fixups
from daemon_import_bindings import binding
from bootpolicy_cache_reader import uleb
from resolve_kernel_collection_interfaces import commands,chained_rebases
from kernel_native_reader import Kernel
from probe_created_port import RANGES


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    starts=[]
    for at,cmd,n in commands(IMAGE.data,0):
        if cmd!=0x26:continue
        off,n=struct.unpack_from('<II',IMAGE.data,at+8);raw=IMAGE.data[off:off+n];p=0;a=0x100000000
        while p<len(raw):
            d,p=uleb(raw,p)
            if not d:break
            a+=d;starts.append(a)
    ranges=[]
    for a,z in RANGES+[(0x1000054d8,0x10000559c)]:
        raw=IMAGE.read(a,z-a);ins=list(CS.disasm(raw,a));assert len(ins)*4==z-a
        ix=bisect.bisect_right(starts,a)-1;end=starts[ix+1] if ix+1<len(starts) else None
        ranges.append({'start':hex(a),'end':hex(z),'bytes':raw.hex(),'sha256':hashlib.sha256(raw).hexdigest(),
            'compiler_start':hex(starts[ix]),'next_compiler_start':None if end is None else hex(end),'complete_compiler_range':a==starts[ix] and z==end,
            'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ins]})
    A=(0x100fc4230,0x101031fa0);B=(0x100fc4130,0x101031ea0)
    D=(0x100e99a00,0x100f4e390);E=(0x100e99700,0x100f4e190)
    specs=[('protected wrapper',B,0x4e,0xcbea,TABLE,0x10065ffd8),
      ('logging predicate',E,0x81,0xcc69,TABLE,'libSystem/_os_log_type_enabled'),
      ('registered arcade name',A,0xf3,0xccc0,TABLE,'CoreFoundation/_CFMachPortGetPort'),
      ('new CF wrapper',E,0x56,0xccdb,TABLE,0x100001f50),
      ('created name',D,0xd7,0xcc77,TABLE,'CoreFoundation/_CFMachPortGetPort'),
      ('make send',D,0x54,0xcbd5,TABLE,'libSystem/_mach_port_insert_right'),
      ('registration client',D,0x6d,0xcdcd,TABLE,0x1000043b4),
      ('source',B,0x4e,0xcc34,TABLE,'CoreFoundation/_CFMachPortCreateRunLoopSource'),
      ('main loop',D,0x54,0xcc8b,TABLE,'CoreFoundation/_CFRunLoopGetMain'),
      ('default mode',D,0x6d,0xbf0,POOL,'CoreFoundation/_kCFRunLoopDefaultMode'),
      ('add source',D,0x54,0xcced,TABLE,'CoreFoundation/_CFRunLoopAddSource'),
      ('release source',D,0x78,0xcbdd,TABLE,'CoreFoundation/_CFRelease'),
      ('invalidate old or source failure',A,0xe4,0xcbf6,TABLE,'CoreFoundation/_CFMachPortInvalidate'),
      ('source failure release',A,0xe4,0xcc21,TABLE,'CoreFoundation/_CFRelease'),
      ('release incoming peer name',A,0x6c,0xcdd7,TABLE,'libSystem/_mach_port_deallocate')]
    banks=[]
    for label,pair,key,add,base,want in specs:
        r=selected(*pair,key,add,base);assert r['target']==(hex(want) if isinstance(want,int) else want),(label,r)
        r['label']=label;banks.append(r)
    branches=[]
    for ix,want in [(0x4c31,0x1005757cc),(0x401c,0x1005757cc),(0x23ae,0x100503b90),
        (0x23b4,0x100547800),(0xc901,0x10050a6a0),(0xc2fc,0x1004a93d0),
        (0xc302,0x100800aa8),(0x8871,0x1004942a8),(0x19a3,0x100528dd8)]:
        slot=TABLE+8*ix;assert qword(slot)==want,(hex(ix),qword(slot))
        branches.append({'index':hex(ix),'slot':hex(slot),'target':hex(want),'fixup':FIXUPS[slot]})
    checks=[]
    for a,m,o,meaning in [
      (0x100005450,'bl','#0x100006944','incoming41471 application call'),
      (0x100006ad0,'mov','w17, #0x6cf4','original protected control tag'),
      (0x100006c20,'blraa','x8, x17','application wrapper protected call'),
      (0x100526018,'blraa','x8, x17','registered arcade CF name query'),
      (0x100525ffc,'ldr','x0, [x10, #0x30]','registered arcade CF field'),
      (0x100546214,'ldr','x0, [x9, #0x38]','load prior anonymous CF object'),
      (0x1004ace70,'blraa','x8, x17','invalidate prior anonymous CF object'),
      (0x1004ace78,'str','xzr, [x8, #0x38]','clear prior anonymous CF field'),
      (0x100575840,'blraa','x8, x17','CF create wrapper call'),
      (0x100503c04,'blraa','x8, x17','query created receive name'),
      (0x100503c98,'blraa','x8, x17','make-send insertion call'),
      (0x100503cec,'blraa','x8, x17','MIG51471 client call'),
      (0x100004428,'bl','#0x100e2ab00','MIG51471 packet emission to libSystem'),
      (0x10050a710,'blraa','x8, x17','created source call after inner zero status'),
      (0x1004a94d0,'blraa','x8, x17','main/default add source'),
      (0x1004a9510,'blraa','x8, x17','release local source reference'),
      (0x1004a951c,'str','x9, [x8, #0x38]','publish new CF object'),
      (0x100800b0c,'blraa','x8, x17','source-null invalidate'),
      (0x100800b50,'blraa','x8, x17','source-null CF release'),
      (0x100494310,'blraa','x8, x17','peer send name deallocation'),
      (0x100528ddc,'str','w6, [x8, #0x18]','publish encoded status'),
      (0x100005540,'bl','#0x1000057c0','subscription61471 application call')]:
        raw=IMAGE.read(a,4);i=next(CS.disasm(raw,a));assert (i.mnemonic,i.op_str)==(m,o),(hex(a),i.mnemonic,i.op_str)
        checks.append({'address':hex(a),'bytes':raw.hex(),'mnemonic':m,'operands':o,'meaning':meaning})
    used=[int(r['slot'],16) for r in banks+branches]+[0x1010b1d18,0x1010b1d20,0x1010b1d30,0x1010b1d40,0x1010b1d48]
    original=verify_original_fixups([a for a in used if not FIXUPS[a]['kind'].endswith('bind')])
    imports=[binding(a) for a in sorted(set(used)) if FIXUPS[a]['kind'].endswith('bind')]
    live=json.loads((ROOT/'created_port_live_ida_bytes.json').read_text())
    for r in live['results']:
        assert bytes.fromhex(r['bytes'])==IMAGE.read(int(r['address'],16),r['size_read'])
    queries={
      'created_name_identity':'''(declare-fun n () (_ BitVec 32))
(define-fun enc () (_ BitVec 32) (bvadd (bvxor n #xcdfd77f7) #x0000c2fc (bvand (bvshl n #x00000001) #x9bfaefee)))
(assert (not (= (bvadd enc #x3201c50d) n)))''',
      'status_roundtrip':'''(declare-fun s () (_ BitVec 32))
(define-fun enc () (_ BitVec 32) (bvadd (bvsub s (bvand (bvshl s #x00000001) #x167b8ca2)) #x8b3dc651))
(assert (not (= (bvxor enc #x8b3dc651) s)))''',
      'transport_reply_cache_partition':'''(declare-fun s () (_ BitVec 32))
(define-fun k () (_ BitVec 32) (bvsub s #x10000002))
(define-fun put () Bool (and (bvule k #x0000000e) (not (= (bvand (bvshl #x00000001 k) #x00004003) #x00000000))))
(assert (not (= put (or (= s #x10000002) (= s #x10000003) (= s #x10000010)))))''',
      'default_mode_addend':'''(declare-fun p () (_ BitVec 64))
(assert (not (= (bvadd p #x000000007ed8f1f2 #xffffffff81270e0e) p)))''',
      'created_cf_edges':'''(declare-fun p () (_ BitVec 64))
(define-fun a () (_ BitVec 32) (bvor (bvsub #x00006cf4 #x00004c64) #x00000324))
(define-fun b () (_ BitVec 32) (bvsub #x00006cf4 #x00004946))
(define-fun ix () (_ BitVec 32) (bvxor b (bvmul (ite (= p #x0000000000000000) #x00000001 #x00000000) (bvsub a #x0000239a))))
(assert (not (= ix (ite (= p #x0000000000000000) #x000023b4 #x000023ae))))''',
      'source_edges':'''(declare-fun p () (_ BitVec 64))
(define-fun ix () (_ BitVec 32) (bvxor #x0000c2fc (bvmul (ite (= p #x0000000000000000) #x00000001 #x00000000) (bvxor #x21a0e21f #x21a0e3e1))))
(assert (not (= ix (ite (= p #x0000000000000000) #x0000c302 #x0000c2fc))))'''}
    proofs=[]
    for name,body in queries.items():
        p=ROOT/f'created_port_{name}.smt2';p.write_text('(set-logic QF_BV)\n'+body+'\n(check-sat)\n')
        result=subprocess.run(['z3','-smt2',str(p)],capture_output=True,text=True,check=True,timeout=30).stdout.strip()
        assert result=='unsat',(name,result);proofs.append({'name':name,'file':p.name,'result':result,'scope':'lifted arithmetic, not reachability or PAC'})
    k=Kernel();base,rebases,metadata=chained_rebases(k.data)
    kranges=[k.function(a) for a in [0xfffffe000bd92600,0xfffffe000bd92510,0xfffffe000bce1864,
        0xfffffe000bce1a64,0xfffffe000bd923a4,0xfffffe000c629780,0xfffffe000bcf4a5c,0xfffffe000bce1f8c]]
    table=0xfffffe0007e688d8;raw=k.read(table,64)
    assert struct.unpack_from('<III',raw,8)==(51471,51472,44)
    selected_fixups=[]
    for off,want in [(0xe648d8,0xfffffe000bd92600),(0xe64900,0xfffffe000bd92510)]:
        assert rebases[off]==want;selected_fixups.append({'file_offset':hex(off),**metadata[off]})
    needle=struct.pack('<II',51471,51472);hits=[];p=0
    while (p:=k.data.find(needle,p))>=0:
        if p%4==0:hits.append(p)
        p+=1
    assert hits==[0xe648e0]
    strings=[]
    for a,want in [(0xfffffe000704a880,b'com.apple.arcade.fpsd'),
        (0xfffffe00070ed93f,b'arcade: received register request'),
        (0xfffffe000704a896,b'arcade_upcall_refresh(get fairplayd) @%s:%d'),
        (0xfffffe000704a8c2,b'arcade.c'),
        (0xfffffe00070ed961,b'arcade: subscription validation upcall returned %#x')]:
        actual=k.read(a,len(want)+1);assert actual==want+b'\0'
        strings.append({'address':hex(a),'bytes':actual.hex(),'text':want.decode()})
    assert struct.unpack('<II',k.read(0xfffffe000700db70,8))==(0x80001513,0)
    assert struct.unpack('<II',k.read(0xfffffe000700de50,8))==(0,61471)
    kc_checks=[]
    for a,m,o,meaning in [
      (0xfffffe000bd92608,'mov','w9, #0xc90f','subsystem accepts51471'),
      (0xfffffe000bd9252c,'cmp','w8, #0x34','internal registration request52 bytes'),
      (0xfffffe000bd92534,'ldrh','w8, [x0, #0x2e]','internal port disposition/type16-bit field'),
      (0xfffffe000bd925e4,'cmp','w8, #0x2b','registration kobject type43'),
      (0xfffffe000bd925ec,'ldr','x16, [x17, #0x50]!','registration kobject payload'),
      (0xfffffe000bd925b0,'bl','#0xfffffe000bce1864','registration application call'),
      (0xfffffe000bce18a4,'cbz','x19, #0xfffffe000bce18f4','null registration object rejected'),
      (0xfffffe000bce18e4,'blraa','x8, x17','runtime policy callback'),
      (0xfffffe000bce1934,'ldr','w8, [x8, #0xe10]','registration-pending gate'),
      (0xfffffe000bce1950,'bl','#0xfffffe000bcd0448','release previous stored send right'),
      (0xfffffe000bce1954,'str','x20, [x23, #0xe18]','publish new kernel-held send right'),
      (0xfffffe000bce1a1c,'mov','w0, #5','no pending registration returns5'),
      (0xfffffe000bce1bdc,'mov','w2, #0x1f','host special slot31'),
      (0xfffffe000bce1be0,'bl','#0xfffffe000bcf258c','host special-port lookup'),
      (0xfffffe000bce1c04,'ldr','x17, [x8, #0x540]','registration kobject port from global'),
      (0xfffffe000bce1c48,'mov','w8, #0xa1ff','trigger message41471'),
      (0xfffffe000bce1c54,'mov','w1, #0x34','internal trigger52 bytes'),
      (0xfffffe000bce1c68,'bl','#0xfffffe000bcf55dc','kernel one-way trigger send call'),
      (0xfffffe000bce1dbc,'bl','#0xfffffe000bd923a4','subscription client call'),
      (0xfffffe000bd92434,'mov','w1, #0x48','internal subscription request72 bytes'),
      (0xfffffe000bd92438,'mov','w2, #0x38','kernel transport receive capacity56 bytes'),
      (0xfffffe000bd92448,'bl','#0xfffffe000bcf59e0','common kernel RPC helper'),
      (0xfffffe000bd9245c,'mov','w9, #0xf083','expected subscription reply61571'),
      (0xfffffe000c629838,'mov','w1, #0x12b','allocator combined kind/flag word'),
      (0xfffffe000c629844,'bl','#0xfffffe000bcf4a5c','registration kobject allocation'),
      (0xfffffe000c629848,'stlr','x0, [x19]','publish registration kobject port'),
      (0xfffffe000bcf4ad0,'and','x8, x20, #0xff','allocator payload discriminator uses low8-bit kind'),
      (0xfffffe000bce2090,'bl','#0xfffffe000bce1a64','thread-flag0x800 consumer calls subscription upcall')]:
        b=k.read(a,4);i=next(k.cs.disasm(b,a));assert (i.mnemonic,i.op_str)==(m,o),(hex(a),i.mnemonic,i.op_str)
        kc_checks.append({'address':hex(a),'bytes':b.hex(),'mnemonic':m,'operands':o,'meaning':meaning})
    build=subprocess.run(['xcrun','clang','-target','arm64e-apple-macos13.0','-std=c11','-fsyntax-only',str(ROOT/'created_port_layouts.c')],capture_output=True,text=True)
    assert build.returncode==0,build.stderr
    symbols=k.symbols({0xfffffe000bcf258c,0xfffffe000bcd0448,0xfffffe000bd7deec,0xfffffe0007f8b0a0,0xfffffe000bdc6308})
    out={'scope':__doc__,'source':{'path':str(SOURCE),'sha256':sha(SOURCE)},'ranges':ranges,
        'bank_proofs':banks,'branch_targets':branches,'native_instruction_checks':checks,
        'original_rebases':original,'original_import_bindings':imports,'proofs':proofs,
        'fresh_ida_ranges_matched':len(live['results']),
        'layout_compile':{'command':build.args,'exit_code':build.returncode,'stderr':build.stderr},
        'kernel':{'sha256':k.sha256,'uuid':k.kernel['uuid'],'ranges':kranges,'exact_symbols':symbols,'native_instruction_checks':kc_checks,
            'subsystem_address':hex(table),'subsystem_original_bytes':raw.hex(),'subsystem_range_pattern_file_hits':[hex(x) for x in hits],
            'selected_original_format8_fixups':selected_fixups,'strings':strings,
            'registration_kobject_cell':'0xfffffe0007e5c540','accepted_kobject_type':43,
            'published_daemon_send_cell':'0xfffffe000cb5fe18','registration_pending_word':'0xfffffe000cb5fe10',
            'refresh_host_special_slot':31,'subscription_id':61471,'subscription_reply_id':61571,
            'subscription_internal_bytes':72,'subscription_user_bytes':64,'subscription_ool_bytes':4096,
            'subscription_result_word_user_offset':36,'native_control_and_lifecycle_not_executed':True},
        'native_target_executed':False,'target_host_operations_executed':False,'idb_mutated':False,'full_goal_complete':False}
    (ROOT/'created_port_contracts.json').write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'daemon_ranges':len(ranges),'banks_256':len(banks),'instruction_checks':len(checks),
        'proofs_unsat':len(proofs),'fresh_ida_matches':len(live['results']),'kernel_ranges':len(kranges)}))


if __name__=='__main__':main()
