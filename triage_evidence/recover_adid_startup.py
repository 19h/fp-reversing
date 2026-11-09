#!/usr/bin/env python3
"""Original adid startup/lifecycle contracts and local branch proofs.

No target/loader/host API runs. Static tools read files; clang compiles an
analyst ABI model only. O(B+F+R+P) static time/space; three local SMT queries
have separate 30 s caps. No whole-program or native authorization claim.
"""
import json
from pathlib import Path
import struct
import subprocess
from adid_reader import Adid,ROOT,CS,sha,THIN_SHA
from probe_adid_startup import unpack_records


def main():
    s=Adid();p=json.loads((ROOT/'adid_startup_profiles.json').read_text());rows={r['fixture']['label']:r for r in p['profiles']}
    predicate=next(e for e in unpack_records(rows['migration_cleanup']) if e['kind']=='original_write_count_predicate')
    assert predicate['w26']==0x24fe and predicate['w24']==0x2447
    pointers=[]
    for truth in (False,True):
        idx=(predicate['w24']^((predicate['w26']^0x278d)*int(truth)))&0xffffffff;ix=idx-(1<<32) if idx>>31 else idx
        slot=int(predicate['table'],16)+ix*8;pointers.append({'comparison_equal':truth,'index_u32':idx,'slot':hex(slot),'pointer':s.decoded[slot]})
    queries={
      'adid_startup_VMM_byte.smt2':'''(set-logic QF_BV)
(set-option :timeout 30000)
(declare-fun status () (_ BitVec 32))
(declare-fun value () (_ BitVec 32))
(define-fun cmp_Z () Bool (= value #x00000001))
(define-fun ccmp_Z () Bool (ite cmp_Z (= status #x00000000) false))
(define-fun byte () (_ BitVec 8) (ite ccmp_Z #x0a #x09))
(assert (distinct (= byte #x0a) (and (= value #x00000001) (= status #x00000000))))
(check-sat)
''',
      'adid_startup_open_signed32.smt2':'''(set-logic QF_BV)
(set-option :timeout 30000)
(declare-fun descriptor () (_ BitVec 32))
(assert (distinct (bvslt descriptor #x00000000) (= ((_ extract 31 31) descriptor) #b1)))
(check-sat)
''',
      'adid_startup_write_edge.smt2':'''(set-logic QF_BV)
(set-option :timeout 30000)
(declare-fun result () (_ BitVec 64))
(declare-fun count () (_ BitVec 64))
(define-fun eq () (_ BitVec 32) (ite (= result count) #x00000001 #x00000000))
(define-fun index () (_ BitVec 32) (bvxor (bvmul eq (bvxor #x000024fe #x0000278d)) #x00002447))
(assert (distinct (= index #x00002734) (= result count)))
(check-sat)
'''}
    proofs=[]
    for name,text in queries.items():
        path=ROOT/name;path.write_text(text);run=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);assert run.stdout.strip()=='unsat' and not run.stderr
        proofs.append({'path':name,'sha256':sha(path.read_bytes()),'result':'unsat','scope':'Local source predicate under stated prefix constants;not a full startup/native transaction proof.'})
    windows=[]
    for a,z,role in [(0x100014df0,0x100014e38,'source open and signed32 predicate'),(0x100016b98,0x100016c24,'destination open variadic mode'),
        (0x100016cf0,0x100016d10,'truncate boundary'),(0x100016d70,0x100016dbc,'64-bit write count and encoded edge'),
        (0x10001a0a0,0x10001a2c0,'kqueue and SIGTERM registration'),(0x10001a438,0x10001a688,'CF descriptor source setup'),
        (0x10001a780,0x10001a9d4,'XPC listener/block/activation'),(0x10001c4a0,0x10001c598,'private arena teardown')]:
        raw=s.read(a,z-a);windows.append({'start':hex(a),'end':hex(z),'role':role,'bytes':raw.hex(),'sha256':sha(raw),
            'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(raw,a)]})
    selected={'_open','_lstat','_fstat','_read','_write','_ftruncate','_close','_unlink','_sysctlbyname','_signal','_kqueue','_kevent',
        '_CFFileDescriptorCreate','_CFFileDescriptorGetNativeDescriptor','_CFRunLoopStop','_CFRunLoopRun','_xpc_connection_create_mach_service',
        '_xpc_connection_set_event_handler','_xpc_connection_activate','__dispatch_main_q'}
    imports=[v for v in s.decoded.values() if v['bind'] and v['import']['name'] in selected]
    sdk=Path('/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk')
    cmd=['/usr/bin/clang','-target','arm64e-apple-macos','-fblocks','-isysroot',str(sdk),'-Wall','-Wextra','-Werror','-O2','-S',str(ROOT/'adid_startup_layouts.c'),'-o',str(ROOT/'adid_startup_layouts.s')]
    run=subprocess.run(cmd,capture_output=True,text=True);assert run.returncode==0 and not run.stderr
    headers=['usr/include/sys/stat.h','usr/include/sys/fcntl.h','usr/include/sys/signal.h','usr/include/sys/event.h','usr/include/xpc/connection.h',
        'System/Library/Frameworks/CoreFoundation.framework/Headers/CFFileDescriptor.h',
        'System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/CarbonCore.framework/Versions/A/Headers/BackupCore.h']
    account=json.loads((ROOT/'adid_provider_account.json').read_text())
    assert sha(Path(account['path']).read_bytes())==account['sha256'] and account['uid']==account['gid']==265
    out={'scope':__doc__,'thin_sha256':THIN_SHA,'uuid':s.meta['uuid'],'original_windows':windows,'VMM_original_function':s.function(0x10002ba5c),
        'signal_original_function':s.function(0x100045bdc),'source_import_pointers':imports,'write_branch_pointers':pointers,'proofs':proofs,
        'write_count_width_example':{'requested_bytes':(1<<32)+31,'returned_bytes':31,'low32_equal':True,'source64_equal':False,'native_observed':False},
        'SDK_compile':{'command':cmd,'exit_code':run.returncode,'source_sha256':sha((ROOT/'adid_startup_layouts.c').read_bytes()),'assembly_sha256':sha((ROOT/'adid_startup_layouts.s').read_bytes())},
        'SDK_headers':[{'path':str(sdk/name),'sha256':sha((sdk/name).read_bytes())} for name in headers],
        'provider_account_declaration':account,'dependencies':{n:sha((ROOT/n).read_bytes()) for n in ['adid_reader.py','probe_adid_receiver.py','probe_adid_startup.py','adid_startup_profiles.json',
            'adid_startup_checkpoint.json','adid_listener_checkpoint.json','adid_peer_checkpoint.json','adid_provider_account.json','adid_receiver_quality_gates.json']},
        'generator_sha256':sha(Path(__file__).read_bytes()),'native_target_executed':False,'full_goal_complete':False}
    (ROOT/'adid_startup_contracts.json').write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'source_windows':len(windows),'original_complete_functions':2,'selected_import_pointers':len(imports),'SMT_unsat':len(proofs)}))


if __name__=='__main__':main()
