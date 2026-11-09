#!/usr/bin/env python3
"""Recover original ADID request persistence predicates and SDK contracts.

Read-only original bytes, analyst compilation and four local SMT queries.
No target/IPC/persistent-file operation executes. O(B+F+R+E) time/space;
each SMT query has a separate 30 s cap and only its stated prefix scope.
"""
import json
from pathlib import Path
import subprocess
from adid_reader import Adid,ROOT,CS,sha,THIN_SHA
from probe_adid_startup import unpack_records


def main():
    s=Adid();p=json.loads((ROOT/'adid_request_profiles.json').read_text());rows={r['fixture']['label']:r for r in p['profiles']}
    proofs=[]
    queries={
      'adid_request_mode_mask.smt2':'''(set-logic QF_BV)
(set-option :timeout 30000)
(declare-fun mode () (_ BitVec 16))
(define-fun missing () (_ BitVec 32) (bvand #x000001b6 (bvnot ((_ zero_extend 16) mode))))
(assert (distinct (= missing #x00000000) (= (bvand mode #x01b6) #x01b6)))
(check-sat)
''',
      'adid_request_type_fold.smt2':'''(set-logic QF_BV)
(set-option :timeout 30000)
(declare-fun diff () (_ BitVec 32))
(define-fun result () (_ BitVec 32) (bvadd (bvxor diff #xfbf9d5cf) (bvand (bvshl diff #x00000001) #xf7f3ab9e)))
(assert (distinct (= result #xfbf9d5cf) (= diff #x00000000)))
(check-sat)
''',
      'adid_request_signed_byte_match.smt2':'''(set-logic QF_BV)
(set-option :timeout 30000)
(declare-fun reference () (_ BitVec 8))
(declare-fun input () (_ BitVec 8))
(define-fun decoded () (_ BitVec 32) (bvxor ((_ sign_extend 24) reference) #x00000004))
(define-fun diff () (_ BitVec 32) (bvsub decoded ((_ sign_extend 24) input)))
(assert (distinct (= diff #x00000000) (= (bvxor reference #x04) input)))
(check-sat)
''',
      'adid_request_nfs_string.smt2':'''(set-logic QF_BV)
(set-option :timeout 30000)
(declare-fun input () (_ BitVec 32))
(define-fun matched () Bool (and (= ((_ extract 7 0) input) (bvxor #x6a #x04)) (= ((_ extract 15 8) input) (bvxor #x62 #x04)) (= ((_ extract 23 16) input) (bvxor #x77 #x04)) (= ((_ extract 31 24) input) (bvxor #x04 #x04))))
(assert (distinct matched (= input #x0073666e)))
(check-sat)
'''}
    for name,text in queries.items():
        path=ROOT/name;path.write_text(text);run=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True)
        assert run.stdout.strip()=='unsat' and not run.stderr
        proofs.append({'path':name,'sha256':sha(path.read_bytes()),'result':'unsat','scope':'Local original predicates under captured operands/reference/shift; no native or whole-request proof.'})
    windows=[]
    for a,z,role in [(0x100110474,0x10011055c,'lstat status, errno and type predicates'),(0x10010adc8,0x10010aed0,'umask and variadic lock-file open'),
        (0x10010cd5c,0x10010cd9c,'fstat status'),(0x10010cdb4,0x10010cde0,'mode mask and encoded branch'),
        (0x10010ce38,0x10010cf08,'mode normalization with umask preservation'),(0x10010d0e0,0x10010d1c4,'F_GETPATH,stack output pointer and statfs'),
        (0x10010d1c4,0x10010d318,'encoded NFS string comparison'),(0x10010d318,0x10010d440,'errno reset and lockf boundary')]:
        raw=s.read(a,z-a);windows.append({'start':hex(a),'end':hex(z),'role':role,'bytes':raw.hex(),'sha256':sha(raw),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(raw,a)]})
    events=unpack_records(rows['statfs_selector_-8']);pred=next(e for e in events if e['kind']=='original_persistence_predicate' and e['pc']=='0x10010cdbc');r=pred['registers'];table=int(r['x30'],16)
    assert int(r['w9'],16)==0x1b6
    fold=next(e for e in events if e['kind']=='original_persistence_predicate' and e['pc']=='0x10010d2f8');fr=fold['registers'];shift=(int(fr['w22'],16)-0x1ac9)&31
    assert shift==1 and int(fr['w9'],16)==0xfbf9d5cf and int(fr['w11'],16)==0xf7f3ab9e
    branches=[]
    for missing in (False,True):
        idx=(int(r['w20'],16)^((int(r['w23'],16)^0x69c)*int(missing)))&0xffffffff;ix=idx-(1<<32) if idx>>31 else idx;slot=table+ix*8
        branches.append({'missing_requested_mode_bits':missing,'index_u32':idx,'slot':hex(slot),'pointer':s.decoded[slot]})
    refs=[e for e in unpack_records(rows['statfs_type_nfs']) if e['kind']=='original_filesystem_reference'];assert refs and len({v['reference_address'] for v in refs})==1
    reference=refs[0];a=int(reference['reference_address'],16);assert s.read(a,16).hex()==reference['source_bytes']
    selected={'_lstat','_fstat','_open','_fchmod','_umask','___error','_fcntl','_statfs','_lockf','_close','_IOServiceMatching','_IOServiceGetMatchingServices','_IOServiceOpen','_IOConnectCallStructMethod','_notify_post'}
    imports=[v for v in s.decoded.values() if v['bind'] and v['import']['name'] in selected]
    sdk=Path('/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk')
    cmd=['/usr/bin/clang','-target','arm64e-apple-macos','-isysroot',str(sdk),'-Wall','-Wextra','-Werror','-O2','-S',str(ROOT/'adid_request_layouts.c'),'-o',str(ROOT/'adid_request_layouts.s')]
    run=subprocess.run(cmd,capture_output=True,text=True);assert run.returncode==0 and not run.stderr
    headers=['usr/include/sys/stat.h','usr/include/sys/fcntl.h','usr/include/sys/mount.h','usr/include/unistd.h','usr/include/sys/param.h']
    out={'scope':__doc__,'thin_sha256':THIN_SHA,'uuid':s.meta['uuid'],'original_windows':windows,'mode_branch_pointers':branches,'filesystem_reference':reference,
        'mode_prefix':pred,'type_fold_prefix':fold,'type_fold_shift_low5':shift,
        'filesystem_reference_decoded_prefix_hex':bytes(v^4 for v in s.read(a,4)).hex(),'proofs':proofs,'source_import_pointers':imports,
        'SDK_compile':{'command':cmd,'exit_code':run.returncode,'source_sha256':sha((ROOT/'adid_request_layouts.c').read_bytes()),'assembly_sha256':sha((ROOT/'adid_request_layouts.s').read_bytes())},
        'SDK_headers':[{'path':str(sdk/name),'sha256':sha((sdk/name).read_bytes())} for name in headers],
        'generator_sha256':sha(Path(__file__).read_bytes()),'dependencies':{n:sha((ROOT/n).read_bytes()) for n in ['adid_reader.py','probe_adid_requests.py','adid_request_profiles.json','adid_peer_checkpoint.json']},
        'native_target_executed':False,'full_goal_complete':False}
    (ROOT/'adid_request_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'proofs':len(proofs),'source_import_pointers':len(imports),'mode_branches':branches,'reference':reference}))


if __name__=='__main__':main()
