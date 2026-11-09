#!/usr/bin/env python3
"""Original companion authorization/path and reference StoreFoundation contracts.

No native target code/framework/files/IPC runs. Readers, compiler and SMT only.
O(B+F+I+M) extraction time/space for retained bytes, fixups, instructions, metadata.
SMT solving is a separate bounded invocation.
"""
import bisect
import hashlib
import json
from pathlib import Path
import struct
import subprocess
from arcade_service_reader import Service,ROOT,THIN_SHA,CS,sha
from arcade_objc_metadata import recover as objc_metadata
from daemon_receive_tools import IMAGE,SOURCE
from bootpolicy_cache_reader import Cache,Dylib


def main():
    s=Service();objc=objc_metadata(s)
    (ROOT/'arcade_service_objc_metadata.json').write_text(json.dumps(objc,indent=2)+'\n')
    ranges=[]
    for image,a,z in [(s,0x100000dc8,0x100000f9c),(s,0x1000011e8,0x100001320),
        (s,0x10000d4e4,0x10000d884),(IMAGE,0x1004d795c,0x1004d7b80),
        (IMAGE,0x1005a9950,0x1005a99e0),(IMAGE,0x1008b35dc,0x1008b3628),
        (IMAGE,0x100580958,0x1005809a0)]:
        raw=image.read(a,z-a);ins=list(CS.disasm(raw,a));assert len(ins)*4==z-a
        ranges.append({'image':'service' if image is s else 'daemon','start':hex(a),'end':hex(z),'bytes':raw.hex(),'sha256':sha(raw),
            'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ins]})
    cf=0x100065b80;literal=s.qword(cf+16);n=s.qword(cf+24);text=s.read(literal,n).decode()
    assert text=='(entitlement ["com.apple.fp.receipt"] exists)'
    calls=[]
    for name in ('_SecCodeCopyGuestWithAttributes','_SecRequirementCreateWithString','_SecCodeCheckValidity'):
        matches=[r for r in s.decoded_fixups.values() if r.get('symbol')==name]
        assert len(matches)==1 and matches[0]['total_addend']==0
        calls.append(matches[0])
    cache=Cache();store=Dylib(cache,'/System/Library/PrivateFrameworks/StoreFoundation.framework/Versions/A/StoreFoundation')
    sf=[]
    for a in (0x1c6fd6648,0x1c6fd6924,0x1c6fd6b74,0x1c6fd6ce8,0x1c6fd6d8c):
        r=store.function(a);r['original_nlist_names']=store.symbols_at(a);sf.append(r)
    objc_stubs=[]
    for a in (0x1c80d5c60,0x1c8002480,0x1c80d4e20,0x1c80d4e30):
        raw=cache.read(a,12);ins=list(CS.disasm(raw,a));assert [i.mnemonic for i in ins]==['adrp','add','b']
        ptr=int(ins[0].op_str.split('#')[1],0)+int(ins[1].op_str.split('#')[1],0)
        objc_stubs.append({'address':hex(a),'bytes':raw.hex(),'selector_address':hex(ptr),'selector':cache.cstring(ptr),
            'shared_objc_branch':ins[-1].op_str})
    image_starts=sorted((r['address'],r['path']) for r in cache.images);starts=[a for a,p in image_starts];libraries={}
    bindings=[]
    for a in (0x1c80fab10,0x1c8121140,0x1c80fb040,0x1c810ffc0,0x1c811acb0):
        raw=cache.read(a,16);ins=list(CS.disasm(raw,a));assert [i.mnemonic for i in ins]==['adrp','add','ldr','braa']
        slot=int(ins[0].op_str.split('#')[1],0)+int(ins[1].op_str.split('#')[1],0)
        pointer=cache.pointer(slot);target=int(pointer['target'],16)
        owner=image_starts[bisect.bisect_right(starts,target)-1][1]
        if owner not in libraries:libraries[owner]=Dylib(cache,owner)
        lib=libraries[owner];assert any(r['name']=='__TEXT' and r['address']<=target<r['address']+r['size'] for r in lib.segments)
        exports=[name for name,r in lib.exports.items() if r['address']==target]
        assert exports,(hex(a),hex(target),owner)
        bindings.append({'stub':hex(a),'bytes':raw.hex(),'slot':hex(slot),'pointer':pointer,'target':hex(target),
            'library':owner,'library_uuid':lib.uuid,'exact_exports':exports})
    expected=['_CFDataCreateWithBytesNoCopy','_SecRequirementCreateWithData','_CFURLCreateWithFileSystemPath',
        '_SecStaticCodeCreateWithPath','_SecStaticCodeCheckValidity']
    assert all(name in r['exact_exports'] for name,r in zip(expected,bindings))
    requirement=cache.read(0x1c6ff7320,80)
    queries={
        'security_status_codec':'''(declare-fun s () (_ BitVec 32))
(define-fun encoded () (_ BitVec 32) (bvsub (bvadd s #x662255dd) (bvand (bvshl s #x00000001) #xcc44abba)))
(assert (not (= encoded (bvxor s #x662255dd))))''',
        'security_status_zero':'''(declare-fun s () (_ BitVec 32))
(assert (not (= (= (bvxor s #x662255dd) #x662255dd) (= s #x00000000))))''',
        'static_validation_flags':'''(declare-fun basic () (_ BitVec 32))
(define-fun flags () (_ BitVec 32) (ite (not (= basic #x00000000)) #x00000007 (bvadd #x00000000 #x00000001)))
(assert (not (= flags (ite (= basic #x00000000) #x00000001 #x00000007))))''',
        'response_store64_load32':'''(declare-fun raw () (_ BitVec 64))
(define-fun loaded () (_ BitVec 32)
 (concat ((_ extract 31 24) raw) (concat ((_ extract 23 16) raw) (concat ((_ extract 15 8) raw) ((_ extract 7 0) raw)))))
(assert (not (= (= loaded #x00000001) (= ((_ extract 31 0) raw) #x00000001))))'''}
    proofs=[]
    for name,q in queries.items():
        path=ROOT/f'arcade_policy_{name}.smt2';path.write_text('(set-logic QF_BV)\n'+q+'\n(check-sat)\n')
        run=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);assert run.stdout.strip()=='unsat' and not run.stderr
        proofs.append({'name':name,'path':path.name,'sha256':sha(path.read_bytes()),'result':'unsat',
            'scope':'Local arithmetic only; status codec uses displayed entry constants, u64 equality assumes decoded candidate=raw XOR codec constant.'})
    sdk=Path('/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk')
    path=ROOT/'arcade_policy_layouts.c';cmd=['/usr/bin/clang','-target','arm64e-apple-macos','-isysroot',str(sdk),'-fblocks','-fsyntax-only','-Wall','-Wextra','-Werror',str(path)]
    run=subprocess.run(cmd,capture_output=True,text=True);assert run.returncode==0,(run.stdout,run.stderr)
    headers=[]
    for rel in ('SecCode.h','SecRequirement.h','SecStaticCode.h'):
        p=sdk/'System/Library/Frameworks/Security.framework/Headers'/rel;headers.append({'path':str(p),'sha256':sha(p.read_bytes())})
    out={'scope':__doc__,'service_sha256':THIN_SHA,'daemon_sha256':sha(SOURCE.read_bytes()),'ranges':ranges,
        'entitlement_requirement':{'object':hex(cf),'object_original_bytes':s.read(cf,32).hex(),'class_fixup':s.decoded_fixups[cf],
            'string_fixup':s.decoded_fixups[cf+16],'string_address':hex(literal),'size_bytes':n,'text':text},
        'security_bindings':calls,'cache_uuid':cache.uuid,'storefoundation_path':store.path,'storefoundation_uuid':store.uuid,
        'storefoundation_ranges':sf,'cache_objc_selector_stubs':objc_stubs,'cache_bindings':bindings,
        'developer_requirement_data':{'address':'0x1c6ff7320','bytes':requirement.hex(),'size_bytes':80,'sha256':sha(requirement),
            'human_requirement_expression':'unknown','native_requirement_parser_executed':False},
        'cache_files_used':[cache.files[p] for p in sorted(cache.used)],'runtime_cache_pairing':'unknown',
        'proofs':proofs,'objc_classes':len(objc['classes']),'objc_methods':len(objc['methods']),
        'sdk_headers':headers,'sdk_compile':{'command':cmd,'exit_code':run.returncode,'source_sha256':sha(path.read_bytes())},
        'native_target_executed':False,'full_goal_complete':False,'generator_sha256':sha(Path(__file__).read_bytes())}
    (ROOT/'arcade_policy_contracts.json').write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'service_daemon_ranges':len(ranges),'storefoundation_functions':len(sf),'resolved_cache_bindings':len(bindings),
        'selector_stubs':len(objc_stubs),'objc_classes':len(objc['classes']),'objc_methods':len(objc['methods']),'proofs_unsat':len(proofs),'sdk_compile_exit':run.returncode}))


if __name__=='__main__':main()
