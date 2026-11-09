#!/usr/bin/env python3
"""Original ADID header, selector, status, context-record and setup ABI.

Read original files, compile analyst declarations and solve five local BV
obligations. No native target/API/IPC/persistence operation. O(B+F+R+E)
time/space, with a separate 30 s timeout per local SMT obligation.
"""
import json
from pathlib import Path
import subprocess
from adid_reader import Adid,ROOT,CS,sha,THIN_SHA
from probe_adid_startup import unpack_records


def main():
    s=Adid();p=json.loads((ROOT/'adid_context_profiles.json').read_text());rows={r['fixture']['label']:r for r in p['profiles']};events=unpack_records(rows['context_error_producer'])
    def boundary(pc):return next(e for e in events if e['kind']=='original_context_boundary' and e['pc']==hex(pc))
    header=boundary(0x10016a800);hr=header['registers'];assert [int(hr[k],16) for k in ('x7','x19','x20')]==[0xf577f73e,0xeaefee7c,0xacedfe8]
    serializer=boundary(0x10021b8d0);assert int(serializer['registers']['x9'],16)==0x767
    selector=boundary(0x1001ca3fc);assert int(selector['registers']['x23'],16)==(0xfffffffffffffff8^0xda8ca8cae5dfbd2d)
    queries={
      'adid_context_header32.smt2':'''(set-logic QF_BV)
(set-option :timeout 30000)
(declare-fun n () (_ BitVec 32))
(define-fun t () (_ BitVec 32) (bvadd (bvadd (bvxor n #xf577f73e) #x0acedfe8) (bvand (bvshl n #x00000001) #xeaefee7c)))
(assert (distinct t (bvadd n #x0046d726)))
(check-sat)
''',
      'adid_context_argument64.smt2':'''(set-logic QF_BV)
(set-option :timeout 30000)
(declare-fun n () (_ BitVec 64))
(define-fun t () (_ BitVec 64) (bvsub (bvadd n #xda8ca8cae5dfbd2d) (bvand (bvshl n #x0000000000000001) #xb5195195cbbf7a5a)))
(assert (distinct t (bvxor n #xda8ca8cae5dfbd2d)))
(check-sat)
''',
      'adid_context_selector64.smt2':'''(set-logic QF_BV)
(set-option :timeout 30000)
(declare-fun s () (_ BitVec 64))
(define-fun j () (_ BitVec 64) (bvadd (bvxor s #xda8ca8cae5dfbd2d) #xda8ca8cae5dfbd30))
(define-fun selected () Bool (and (bvule j #x0000000000000007) (distinct (bvand (bvshl #x0000000000000001 j) #x00000000000000eb) #x0000000000000000)))
(assert (distinct selected (or (= s #xfffffffffffffff8) (= s #xfffffffffffffffa) (= s #xfffffffffffffffb) (= s #xfffffffffffffffc) (= s #xfffffffffffffffd) (= s #xfffffffffffffffe))))
(check-sat)
''',
      'adid_context_status32.smt2':'''(set-logic QF_BV)
(set-option :timeout 30000)
(declare-fun n () (_ BitVec 32))
(define-fun t () (_ BitVec 32) (bvsub (bvadd n #x99556a80) (bvand (bvadd #x3f4db6e2 (bvshl n #x00000001)) #x335d1e1e)))
(assert (distinct (bvxor t #x99ae8f0f) (bvsub n #x0059248f)))
(check-sat)
''',
      'adid_context_record_key32.smt2':'''(set-logic QF_BV)
(set-option :timeout 30000)
(declare-fun a () (_ BitVec 32))
(define-fun m () (_ BitVec 32) (bvsub (bvor a #x5562e9a6) (bvand a #x5562e9a6)))
(define-fun k () (_ BitVec 32) (bvmul (bvxor m #x523f78ab) #xd756578d))
(assert (distinct k (bvmul (bvxor a #x075d910d) #xd756578d)))
(check-sat)
'''}
    proofs=[]
    for name,text in queries.items():
        path=ROOT/name;path.write_text(text);run=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);assert run.stdout.strip()=='unsat' and not run.stderr
        proofs.append({'path':name,'sha256':sha(path.read_bytes()),'result':'unsat','scope':'Full declared BV domains, under retained local source prefix. No whole-program/native admission claim.'})
    windows=[]
    for a,z,role in [(0x10016a7f8,0x10016a81c,'BE32 header fold'),(0x1001af140,0x1001af178,'BE64 argument fold'),(0x1001bfc54,0x1001bfdc4,'context-record construction and return gate'),
        (0x1001bfe3c,0x1001bfea4,'alternate record-key expression'),(0x1001247d8,0x100124800,'context status store'),(0x1001ca3ac,0x1001ca464,'cleanup byte and six-selector membership'),
        (0x10019bdd0,0x10019be18,'final encoded error selection'),(0x10019c098,0x10019c0c8,'error cell store'),(0x10019cfbc,0x10019cfe4,'final encoded status load'),
        (0x10021ab90,0x10021ac74,'earlier status and cleanup selection'),(0x10021b8cc,0x10021b938,'encoded status fold'),(0x100202898,0x1002028dc,'BE32 byte stores'),
        (0x1001fcc70,0x1001fccf0,'reply buffer copy'),(0x100106150,0x10010652c,'CF data/property-list/key/type/number interfaces')]:
        raw=s.read(a,z-a);windows.append({'start':hex(a),'end':hex(z),'role':role,'bytes':raw.hex(),'sha256':sha(raw),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(raw,a)]})
    cleanup=boundary(0x10021abe8);r=cleanup['registers'];branches=[]
    for unequal in (False,True):
        index=((int(r['x19'],16)-0x27c)^(0x3d*int(unequal)))&0xffffffff;slot=int(r['x27'],16)+index*8
        branches.append({'byte_unequal':unequal,'index_u32':index,'slot':hex(slot),'pointer':s.decoded[slot]})
    key_event=next(e for e in unpack_records(rows['nonroot_setup_parent_db_empty_dictionary']) if e.get('name')=='_CFDictionaryGetValue');key=int(key_event['args_x0_x7'][1],16);chars=s.qword(key+16);literal=s.cstring(chars);assert literal=='kBuddingRunningForUID'
    selected={'_CFDataCreateWithBytesNoCopy','_CFPropertyListCreateWithData','_CFDictionaryGetTypeID','_CFDictionaryGetValue','_CFGetTypeID','_CFNumberGetTypeID','_CFNumberGetValue','_kCFAllocatorNull','_kCFAllocatorDefault'}
    imports=[v for v in s.decoded.values() if v['bind'] and v['import']['name'] in selected]
    sdk=Path('/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk');cmd=['/usr/bin/clang','-target','arm64e-apple-macos','-isysroot',str(sdk),'-Wall','-Wextra','-Werror','-O2','-S',str(ROOT/'adid_context_layouts.c'),'-o',str(ROOT/'adid_context_layouts.s')]
    run=subprocess.run(cmd,capture_output=True,text=True);assert run.returncode==0 and not run.stderr
    headers=['CFData.h','CFPropertyList.h','CFDictionary.h','CFNumber.h','CFBase.h'];directory=sdk/'System/Library/Frameworks/CoreFoundation.framework/Headers'
    out={'scope':__doc__,'thin_sha256':THIN_SHA,'uuid':s.meta['uuid'],'original_windows':windows,'source_import_pointers':imports,'proofs':proofs,'header_prefix':header,'serializer_prefix':serializer,'selector_prefix':selector,'cleanup_prefix':cleanup,'cleanup_branch_pointers':branches,
        'literal_setup_key':{'object_address':hex(key),'object32_bytes':s.read(key,32).hex(),'characters_address':hex(chars),'characters':literal,'characters_bytes':s.read(chars,len(literal)+1).hex()},
        'setup_account_declaration':json.loads((ROOT/'adid_setup_account.json').read_text()),'SDK_compile':{'command':cmd,'source_sha256':sha((ROOT/'adid_context_layouts.c').read_bytes()),'assembly_sha256':sha((ROOT/'adid_context_layouts.s').read_bytes()),'exit_code':run.returncode},
        'SDK_headers':[{'path':str(directory/name),'sha256':sha((directory/name).read_bytes())} for name in headers],'generator_sha256':sha(Path(__file__).read_bytes()),
        'dependencies':{n:sha((ROOT/n).read_bytes()) for n in ['adid_reader.py','probe_adid_context.py','adid_context_profiles.json','adid_setup_account.json','adid_receiver_contracts.json','adid_peer_checkpoint.json']},'native_target_executed':False,'full_goal_complete':False}
    (ROOT/'adid_context_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'proofs':len(proofs),'windows':len(windows),'imports':len(imports),'setup_key':literal,'cleanup_branches':branches}))


if __name__=='__main__':main()
