#!/usr/bin/env python3
"""Original monitor source,all direct callers,imports,Block descriptors and ABI.

Read original executable/cache bytes; compile-only source-shape/SDK assertions
and four local SMT formulas. O(B+F+I+V+E) time/space plus bounded formulas.
No native filesystem watch,credential,dispatch,daemon or IPC operation.
"""
import json,re,subprocess
from pathlib import Path
from notifyd_ipc_reader import Notifyd,ROOT,THIN_SHA,sha
from notify_ipc_reader import Notify,CS
from bootpolicy_cache_reader import Dylib
from recover_notifyd_admission import events

ROLES={0x10000712c:'deferred configuration monitor Block',0x1000070d0:'token-vector disposal',0x1000072f0:'monitor release',0x1000073bc:'112-byte monitor construction',0x100007690:'once timezone realpath capture',0x100007724:'metadata/access rebuild and event coalescing',0x100007c94:'monitor detachment from watcher lists',0x100007cf8:'watcher compaction/cancel/disposal scheduling',0x100007f98:'watcher async disposer Block',0x100007ff0:'per-client credential stat helper',0x100008148:'delayed DataOR resume/release Block',0x100008194:'72-byte watcher lookup/construction',0x1000084f0:'watcher monitor-reference append',0x1000085c4:'VNODE event and metadata-pair callback',0x1000086e4:'VNODE cancel FD-close Block',0x1000086ec:'configuration named-post Block',0x100008700:'per-client monitor installation',0x100008990:'PID/token client publication Block',0x100008a24:'automatic service.path registration parser',0x1000051dc:'internal named shared-counter post',0x100000cf4:'name generation and client delivery',0x100003548:'client cancellation',0x100000d58:'client unlink and release'}


def main():
    d=Notifyd();cache=Notify();profiles=json.loads((ROOT/'notifyd_monitor_profiles.json').read_text());functions=[{'role':v,**d.function(a)}for a,v in ROLES.items()];sec=next(s for s in d.sections if s['section']=='__auth_stubs');stubs={}
    for a in range(sec['address'],sec['address']+sec['size'],16):
        ins=list(CS.disasm(d.read(a,16),a));assert [i.mnemonic for i in ins]==['adrp','add','ldr','braa'];slot=int(ins[0].op_str.split('#')[1],16)+int(ins[1].op_str.split('#')[1],16);bind=d.decoded[slot];assert bind['bind'];stubs[a]={'stub':hex(a),'bytes':d.read(a,16).hex(),'slot':hex(slot),'original_format12_bind':bind,'symbol':bind['symbol']}
    edges=[];incoming=[]
    for a in d.starts:
        fun=d.function(a)
        for i in fun['instructions']:
            if i['mnemonic'] not in ['b','bl'] or not i['operands'].startswith('#0x'):continue
            target=int(i['operands'][1:],16);row={'caller':hex(a),'site':i['ea'],'mnemonic':i['mnemonic'],'target':hex(target)}
            if target in ROLES:incoming.append(row)
            if a in ROLES:
                if target in stubs:row['import']=stubs[target]
                edges.append(row)
    bindings=[]
    for libpath,sym in [('/usr/lib/system/libsystem_sandbox.dylib','_SANDBOX_CHECK_NO_REPORT'),('/usr/lib/system/libsystem_info.dylib','_gL1CacheEnabled')]:
        lib=Dylib(cache.cache,libpath);address=lib.exports[sym]['address'];bindings.append({'library':libpath,'uuid':lib.uuid,'symbol':sym,'address':hex(address),'bytes4':cache.read(address,4).hex(),'bind_slots':[x for x in d.decoded.values()if x.get('symbol')==sym],'native_runtime_value_established':False})
    descriptors={};api_sites={};strings=[]
    for case in profiles['cases']:
        for r in case['provider_journal']:
            for b in r['explicit_copied_blocks_after']:
                a=int(b['descriptor_pointer'],16)
                if a not in descriptors:descriptors[a]={'address':hex(a),'original_bytes16':d.read(a,16).hex(),'declared_block_size_bytes':int.from_bytes(d.read(a+8,8),'little')}
            for e in events(r):
                if 'name'in e and 'callsite'in e:
                    key=(e['name'],e['callsite']);api_sites[key]={'name':key[0],'site':key[1],'records':api_sites.get(key,{}).get('records',0)+1,'kind':e['kind']}
    for a in [0x10000d969,0x10000d9d9,0x10000db6a,0x10000db8b]:
        raw=d.read(a,128).split(b'\0')[0]+b'\0';strings.append({'address':hex(a),'bytes':raw.hex(),'text':raw[:-1].decode()})
    queries={
      'mask32':'''(declare-fun flags () (_ BitVec 32))
(declare-fun event () (_ BitVec 32))
(define-fun source () (_ BitVec 64) (bvand ((_ zero_extend 32) (bvand flags event)) #x00000000000003ff))
(define-fun compact () (_ BitVec 64) ((_ zero_extend 54) ((_ extract 9 0) (bvand flags event))))
(assert (distinct source compact))''',
      'metadata32':'''(declare-fun event () (_ BitVec 32))
(declare-fun mtime_equal () Bool)
(declare-fun ctime_equal () Bool)
(define-fun first () (_ BitVec 32) (ite mtime_equal event (bvor event #x00000100)))
(define-fun source () (_ BitVec 32) (ite ctime_equal first (bvor first #x00000200)))
(define-fun compact () (_ BitVec 32) (bvor event (ite mtime_equal #x00000000 #x00000100) (ite ctime_equal #x00000000 #x00000200)))
(assert (distinct source compact))''',
      'release32':'''(declare-fun refs () (_ BitVec 32))
(define-fun release_zero () Bool (ite (= refs #x00000000) true (= (bvsub refs #x00000001) #x00000000)))
(assert (distinct release_zero (or (= refs #x00000000) (= refs #x00000001))))''',
      'coalesce32':'''(declare-fun flags () (_ BitVec 32))
(define-fun pending () Bool (= ((_ extract 28 28) flags) #b1))
(define-fun set () (_ BitVec 32) (bvor flags #x10000000))
(define-fun clear () (_ BitVec 32) (bvand set #xefffffff))
(assert (or (distinct (= ((_ extract 28 28) set) #b1) true) (distinct clear (bvand flags #xefffffff)) (distinct pending (distinct (bvand flags #x10000000) #x00000000))))'''}
    proofs=[]
    for name,body in queries.items():
        path=ROOT/('notifyd_monitor_'+name+'.smt2');path.write_text('(set-option :timeout 30000)\n(set-logic QF_BV)\n'+body+'\n(check-sat)\n');run=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);assert run.stdout.strip()=='unsat' and not run.stderr;proofs.append({'path':path.name,'sha256':sha(path.read_bytes()),'result':'unsat','scope':'encoded local bitvector predicates only;not callback scheduling or native feasibility'})
    sdk=Path('/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk');cmd=['/usr/bin/clang','-target','arm64e-apple-macos','-isysroot',str(sdk),'-Wall','-Wextra','-Werror','-O2','-S',str(ROOT/'notifyd_monitor_layouts.c'),'-o',str(ROOT/'notifyd_monitor_layouts.s')];run=subprocess.run(cmd,capture_output=True,text=True);assert run.returncode==0 and not run.stderr,(run.stdout,run.stderr)
    out={'scope':__doc__,'generator_sha256':sha(Path(__file__).read_bytes()),'dependencies':{n:sha((ROOT/n).read_bytes())for n in ['notifyd_monitor_profiles.json','probe_notifyd_monitor.py','probe_notifyd_monitor_cases.py','notifyd_ipc_reader.py','notify_ipc_reader.py']},'provider_thin_sha256':THIN_SHA,'cache_uuid':cache.cache.uuid,'client_uuid':cache.lib.uuid,'original_functions':functions,'complete_direct_callers_of_selected_functions':incoming,'selected_direct_outgoing_edges':edges,'original_data_bindings':bindings,'source_Block_descriptors':list(descriptors.values()),'original_strings':strings,'observed_API_sites':list(api_sites.values()),'proofs':proofs,'sdk_compile':{'command':cmd,'exit_code':run.returncode,'source_sha256':sha((ROOT/'notifyd_monitor_layouts.c').read_bytes()),'assembly_sha256':sha((ROOT/'notifyd_monitor_layouts.s').read_bytes()),'headers':[{'path':str(sdk/'usr/include'/n),'sha256':sha((sdk/'usr/include'/n).read_bytes())}for n in ['sys/stat.h','sys/event.h','sys/fcntl.h','sys/syscall.h','dispatch/time.h','bsm/audit.h']],'native_target_executed':False},'native_target_executed':False,'full_goal_complete':False};(ROOT/'notifyd_monitor_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(functions),'incoming_edges':len(incoming),'outgoing_edges':len(edges),'descriptors':len(descriptors),'API_sites':len(api_sites),'proofs':len(proofs)}),flush=True)

if __name__=='__main__':main()
