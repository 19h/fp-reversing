#!/usr/bin/env python3
"""Recover source-backed companion identity, peer gate and daemon reply widths.

O(B+F+I+S) time/space, bounded retained bytes/fixups/instructions/SDK metadata.
SMT solving is separate. No target host operations or native authentication.
"""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
from arcade_service_reader import Service,ROOT,THIN_SHA,CS,sha
from daemon_receive_tools import IMAGE,SOURCE,block


def main():
    s=Service();pool=0x100065830;banks=[]
    for label,left,right,key in [
        ('entry and event-target selector',0x100061940,0x100061e50,0x56),
        ('entry method selector',0x100061d50,0x100062d40,0xf9),
        ('entry table selector',0x100060e50,0x100061a40,2),
        ('requirement method and literal selector',0x100061d50,0x100062d40,0xf6),
        ('peer table selector',0x100060f50,0x100061b40,0xed),
        ('resume method selector',0x100061840,0x100061c50,0x3a)]:
        b=s.bank(left,right,key);b['label']=label;b['left_bytes']=s.read(left,256).hex();b['right_bytes']=s.read(right,256).hex();banks.append(b)
    assert [int(b['constant'],16) for b in banks]==[0x15,0x68,0x13,0x6d,0x6c,0xbe]
    base=s.qword(pool+(0x6c-0x4f)*8)-12;assert base==0x100064070
    sites=[]
    for label,pc,index,want in [('main',0x1000034f8,0x13+0x2b9,'libSystem/_xpc_main'),
        ('peer requirement',0x10000369c,0x6d+0x272,'libSystem/_xpc_connection_set_peer_code_signing_requirement'),
        ('set event handler',0x1000037c4,0x15+0x2c4,'libSystem/_xpc_connection_set_event_handler'),
        ('resume',0x100003814,0xbe+0x225,'libSystem/_xpc_connection_resume')]:
        slot=base+index*8;r=s.decoded_fixups[slot];assert r['target']==want and r['total_addend']==0
        sites.append({'label':label,'call_pc':hex(pc),'index':hex(index),'table_base':hex(base),'slot':hex(slot),'binding':r})
    literal=s.qword(pool+(0x6d-0x61)*8)-8;assert literal==0x100060df0
    requirement=s.cstring(literal);assert requirement=='(anchor apple) and (identifier "com.apple.fairplayd" or identifier "com.apple.lskdd")'
    gate=[]
    for status,index,want in [('zero',0xfa,0x1000036c4),('nonzero',0x10c,0x100003818)]:
        a=base+index*8;assert s.qword(a)==want
        gate.append({'status32':status,'index':hex(index),'slot':hex(a),'target':hex(want),'fixup':s.decoded_fixups[a]})
    queries={
      'requirement_status_gate':'''(declare-fun status () (_ BitVec 32))
(define-fun ix () (_ BitVec 32) (bvxor (bvmul (ite (= status #x00000000) #x00000000 #x00000001) #x000001f6) #x000000fa))
(assert (not (= ix (ite (= status #x00000000) #x000000fa #x0000010c))))''',
      'daemon_status32_codec':'''(declare-fun status () (_ BitVec 64))
(define-fun s () (_ BitVec 32) ((_ extract 31 0) status))
(define-fun encoded () (_ BitVec 32) (bvadd (bvsub (bvadd #x000060cc s) (bvand (bvshl s #x00000001) #x167b8ca2)) #x8b3d6585))
(assert (not (= encoded (bvxor s #x8b3dc651))))''',
      'daemon_status32_zero':'''(declare-fun s () (_ BitVec 32))
(assert (not (= (= (bvxor s #x8b3dc651) #x8b3dc651) (= s #x00000000))))'''}
    proofs=[]
    for name,q in queries.items():
        p=ROOT/f'arcade_xpc_{name}.smt2';p.write_text('(set-logic QF_BV)\n'+q+'\n(check-sat)\n')
        run=subprocess.run(['z3',str(p)],capture_output=True,text=True,check=True);assert run.stdout.strip()=='unsat' and not run.stderr
        proofs.append({'name':name,'path':p.name,'sha256':sha(p.read_bytes()),'solver_result':'unsat',
            'scope':'Instruction arithmetic; daemon codec depends on entry W22=0x708e,W26=0x60cc; no native policy theorem.'})
    ranges=[]
    for a,z in [(0x10074e158,0x10074e2b0),(0x100755b58,0x100755c20),(0x10072a148,0x10072a204),
                (0x1008348f8,0x100834984),(0x1008ed718,0x1008ed7b8)]:
        raw=IMAGE.read(a,z-a);ins=list(CS.disasm(raw,a));assert len(ins)*4==z-a
        ranges.append({'start':hex(a),'end':hex(z),'sha256':sha(raw),'bytes':raw.hex(),
            'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ins]})
    live=json.loads((ROOT/'arcade_reply_live_ida.json').read_text());matches=[]
    for r in live['tool_output']['results']:
        raw=bytes.fromhex(r['bytes']);a=int(r['address'],16);assert IMAGE.read(a,len(raw))==raw
        matches.append({'address':r['address'],'size_bytes':len(raw),'matches_original':True})
    sdk=Path('/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk')
    source=ROOT/'arcade_xpc_layouts.c'
    cmd=['/usr/bin/clang','-target','arm64e-apple-macos','-isysroot',str(sdk),'-fblocks','-fsyntax-only','-Wall','-Wextra','-Werror',str(source)]
    run=subprocess.run(cmd,capture_output=True,text=True);assert run.returncode==0,(run.stdout,run.stderr)
    headers=[]
    for rel in ['usr/include/xpc/connection.h','usr/include/xpc/xpc.h',
        'System/Library/Frameworks/Security.framework/Headers/SecCode.h',
        'System/Library/Frameworks/CoreFoundation.framework/Headers/CFData.h',
        'System/Library/Frameworks/CoreFoundation.framework/Headers/CFBase.h']:
        p=sdk/rel;headers.append({'path':str(p),'sha256':sha(p.read_bytes())})
    strings=[]
    for sec in s.sections:
        if sec['section'] not in ('__cstring','__objc_methname'):continue
        data=s.read(sec['address'],sec['size']);at=0
        while at<len(data):
            end=data.index(0,at);raw=data[at:end]
            if raw:
                try:text=raw.decode()
                except UnicodeDecodeError:text=None
                if text:strings.append({'address':hex(sec['address']+at),'section':sec['section'],'text':text})
            at=end+1
    r={'scope':__doc__,'service_sha256':THIN_SHA,'daemon_sha256':sha(SOURCE.read_bytes()),
        'service_functions_path':'arcade_service_original_functions.json','banks':banks,'call_sites':sites,
        'requirement':{'literal_address':hex(literal),'text':requirement},'status_gate':gate,
        'daemon_reply_ranges':ranges,'proofs':proofs,'live_ida_matches':matches,'service_strings':strings,
        'sdk_headers':headers,'sdk_compile':{'command':cmd,'source_sha256':sha(source.read_bytes()),'exit_code':run.returncode,
            'scope':'Layout and declaration checks only; no target linking or execution'},
        'native_target_executed':False,'full_goal_complete':False,
        'generator_sha256':sha(Path(__file__).read_bytes())}
    (ROOT/'arcade_xpc_contracts.json').write_text(json.dumps(r,indent=2)+'\n')
    print(json.dumps({'service_functions':len(s.starts),'fixups':len(s.fixups),'banks':len(banks),'proofs':len(proofs),
        'daemon_reply_ranges':len(ranges),'fresh_ida_windows':len(matches),'sdk_compile_exit':run.returncode}))


if __name__=='__main__':main()
