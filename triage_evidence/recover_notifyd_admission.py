#!/usr/bin/env python3
"""Pin original startup/admission/record interfaces and four local formulas.

Read original universal/cache bytes and retained pair profiles;compile arm64e
source-shape layout assertions;run bounded Z3 queries. No native target/API.
O(B+F+I+V+E) time/space plus four30 s-bounded local arithmetic queries.
"""
import base64
import json
from pathlib import Path
import subprocess
import zlib
from notifyd_ipc_reader import Notifyd,ROOT,THIN_SHA,sha
from notify_ipc_reader import Notify


def events(row):return row['records'] if 'records' in row else json.loads(zlib.decompress(base64.b64decode(row['records_zlib_base64'])))


def main():
    s=Notifyd();cache=Notify();p=json.loads((ROOT/'notifyd_admission_profiles.json').read_text());ep=json.loads((ROOT/'notifyd_event_profiles.json').read_text());functions=[]
    for a,role in [(0x1000052b8,'main startup and CLI options'),(0x100001c7c,'check registration slots and app-status outputs'),(0x1000010b4,'73+strlen name allocation,ID assignment,generation1'),(0x100000ed8,'name lookup/create,88-byte client allocation and composite key'),(0x100001024,'registration flavor and shared-slot publication'),(0x100001b48,'plain registration fallback'),(0x1000097b8,'cached-ID posting and shared counter increment'),(0x100009a3c,'name posting MIG stub'),(0x100000cf4,'per-name generation increment and client delivery loop'),(0x100000890,'UID namespace and configured controlled-name access'),(0x100001818,'restricted-post name prefix and entitlement key'),(0x100005124,'root entitlement Boolean'),(0x100008e34,'RPC token check and per-name generation comparison'),(0x10000a0d0,'PID-scoped token cancellation'),(0x100003548,'client cancellation and shared-slot reference decrement'),(0x100000d58,'client unlink,record release and name retirement'),(0x100003138,'process monitor construction and callbacks'),(0x100006104,'publisher reason dispatch and two Mach channel connections'),(0x100006554,'scheduled collection iteration and timestamp block')]:functions.append({'role':role,**s.function(a)})
    strings=[]
    for a in [0x10000be00,0x10000c6fc,0x10000bf9a,0x10000cc7d,0x10000cddd,0x10000cd7f]:
        raw=s.read(a,512).split(b'\0')[0];strings.append({'address':hex(a),'bytes':(raw+b'\0').hex(),'text':raw.decode()})
    api_catalog={}
    for case in p['cases']:
        for row in [case['startup']]+case['provider_calls']:
            for e in events(row):
                if 'name' in e and 'callsite' in e:
                    k=(e['name'],e['callsite']);api_catalog[k]={'name':k[0],'site':k[1],'profiles':api_catalog.get(k,{}).get('profiles',0)+1,'kind':e['kind']}
    queries={
      'notifyd_admission_pid_token64.smt2':'''(set-logic QF_BV)
(declare-fun pid () (_ BitVec 32))
(declare-fun token () (_ BitVec 32))
(define-fun source () (_ BitVec 64) (bvor ((_ zero_extend 32) token) (bvshl ((_ zero_extend 32) pid) #x0000000000000020)))
(assert (distinct source (concat pid token)))''',
      'notifyd_admission_key_extent64.smt2':'''(set-logic QF_BV)
(declare-fun suffix () (_ BitVec 64))
(assert (bvule suffix #x00000000000001df))
(define-fun result () (_ BitVec 64) (bvadd suffix #x0000000000000034))
(assert (distinct (bvule result #x0000000000000100) (bvule suffix #x00000000000000cc)))''',
      'notifyd_admission_slot_next32.smt2':'''(set-logic QF_BV)
(declare-fun count () (_ BitVec 32))
(declare-fun old () (_ BitVec 32))
(assert (and (bvuge count #x00000002) (bvult old count)))
(define-fun sum () (_ BitVec 32) (bvadd old #x00000001))
(define-fun next () (_ BitVec 32) (ite (bvuge sum count) #x00000001 sum))
(assert (or (bvult next #x00000001) (bvuge next count)))''',
      'notifyd_admission_pages32.smt2':'''(set-logic QF_BV)
(declare-fun pages () (_ BitVec 32))
(define-fun source () (_ BitVec 32) (bvshl (bvmul pages #x00001000) #x00000002))
(assert (distinct source (bvmul pages #x00004000)))'''}
    proofs=[]
    for name,body in queries.items():
        body='(set-option :timeout 30000)\n'+body+'\n(check-sat)\n';path=ROOT/name;path.write_text(body);run=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);assert run.stdout.strip()=='unsat' and not run.stderr;proofs.append({'path':name,'sha256':sha(path.read_bytes()),'result':'unsat','scope':'encoded local arithmetic only;no native/path feasibility proof'})
    sdk='/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk';cmd=['/usr/bin/clang','-target','arm64e-apple-macos','-isysroot',sdk,'-Wall','-Wextra','-Werror','-O2','-S',str(ROOT/'notifyd_admission_layouts.c'),'-o',str(ROOT/'notifyd_admission_layouts.s')];run=subprocess.run(cmd,capture_output=True,text=True);assert run.returncode==0 and not run.stderr
    out={'scope':__doc__,'provider_thin_sha256':THIN_SHA,'cache_uuid':cache.cache.uuid,'client_uuid':cache.lib.uuid,'generator_sha256':sha(Path(__file__).read_bytes()),'dependencies':{n:sha((ROOT/n).read_bytes()) for n in ['notifyd_admission_profiles.json','notifyd_event_profiles.json','probe_notifyd_events.py','probe_notifyd_admission.py','probe_notifyd_pairs.py','notifyd_ipc_reader.py','notify_ipc_reader.py']},'original_functions':functions,'captured_handler_and_channel_records':[e for e in events(ep['cases'][2]['startup'])+events(ep['cases'][2]['handler']) if e.get('name') in ['_dispatch_mach_create_f','_xpc_event_publisher_set_handler','_dispatch_mach_connect']],'original_strings':strings,'source_literals':{'name_default_access_and_slot64':s.read(0x10000bdb0,8).hex(),'constructor_allocation_base_bytes':73,'name_inline_offset':72,'client_allocation_bytes':88,'restricted_name_prefix_length_bytes':32,'restricted_entitlement_prefix_length_bytes':52,'entitlement_buffer_bytes':257,'maximum_entitlement_length_bytes_excluding_NUL':256},'observed_provider_API_sites':list(api_catalog.values()),'proofs':proofs,'sdk_compile':{'command':cmd,'exit_code':run.returncode,'source_sha256':sha((ROOT/'notifyd_admission_layouts.c').read_bytes()),'assembly_sha256':sha((ROOT/'notifyd_admission_layouts.s').read_bytes()),'native_execution':False},'native_target_executed':False,'full_goal_complete':False};(ROOT/'notifyd_admission_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(functions),'strings':len(strings),'API_sites':len(api_catalog),'proofs':len(proofs),'source_literal':out['source_literals']}),flush=True)

if __name__=='__main__':main()
