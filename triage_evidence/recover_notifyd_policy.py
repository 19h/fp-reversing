#!/usr/bin/env python3
"""Source-pinned configuration grammar,policy guards and ABI formulas.

Original binary/captured-file reads,compile-only stat layout and four bounded
local formulas. No native target/file/policy API. O(B+F+I+V) time/space.
"""
import base64,json,subprocess,zlib,bisect
from pathlib import Path
from notifyd_ipc_reader import Notifyd,ROOT,THIN_SHA,sha
from recover_notifyd_admission import events
from notify_ipc_reader import Notify,CS
from bootpolicy_cache_reader import Dylib


def main():
    d=Notifyd();profiles=json.loads((ROOT/'notifyd_policy_profiles.json').read_text());functions=[{'role':role,**d.function(a)} for a,role in [(0x1000052b8,'main/stat/configuration parser'),(0x10000723c,'token-vector append and allocation'),(0x1000070d0,'token-vector disposal'),(0x100001184,'descending controlled-name insertion and deduplication'),(0x100000890,'namespace/controlled-name first-prefix permission'),(0x100000e48,'64-bit initial state setter and timestamp'),(0x10000712c,'deferred monitor declaration block'),(0x10000a1dc,'state get by nameID,RPC1017 and48-byte reply'),(0x10000a4d8,'one-way state setter1019 and52-byte request'),(0x1000027c8,'state setter audit/entitlement/access and optional sandbox gate')]]
    cache=Notify();audit=Dylib(cache.cache,'/usr/lib/libbsm.0.dylib');audit_helpers=[]
    for name,item in audit.exports.items():
        if not name.startswith('_audit_token_to_'):continue
        a=item['address'];ix=bisect.bisect_right(audit.functions,a)-1;z=audit.functions[ix+1] if ix+1<len(audit.functions) else next(s['address']+s['size'] for s in audit.sections if s['name']=='__text');raw=cache.read(a,z-a);audit_helpers.append({'symbol':name,'library':audit.path,'uuid':audit.uuid,'start':hex(a),'end':hex(z),'bytes':raw.hex(),'sha256':sha(raw),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(raw,a)]})
    state_messages=[]
    for case in profiles['cases']:
        for row in case['client_calls']:
            for e in events(row):
                if e.get('message_id_u32') in [1017,1019]:state_messages.append({'case':case['case']['label'],**e})
    strings=[]
    for a in [0x10000d876,0x10000d8dd,0x10000d8e5,0x10000d8e9,0x10000d8f1,0x10000d8f6]:
        raw=d.read(a,128).split(b'\0')[0]+b'\0';strings.append({'address':hex(a),'bytes':raw.hex(),'text':raw[:-1].decode()})
    queries={
      'notifyd_policy_permissions32.smt2':'''(set-logic QF_BV)
(declare-fun uid () (_ BitVec 32))
(declare-fun gid () (_ BitVec 32))
(declare-fun owner () (_ BitVec 32))
(declare-fun group () (_ BitVec 32))
(declare-fun mask () (_ BitVec 32))
(declare-fun op () (_ BitVec 32))
(assert (or (= op #x00000001) (= op #x00000002)))
(define-fun owner_Z () Bool (ite (= uid owner) (= (bvand mask op) #x00000000) true))
(define-fun group_Z () Bool (ite (= gid group) (= (bvand mask (bvshl op #x00000004)) #x00000000) true))
(define-fun final_Z () Bool (ite group_Z (= (bvand mask (bvshl op #x00000008)) #x00000000) false))
(define-fun source () Bool (or (not owner_Z) (not final_Z)))
(define-fun compact () Bool (or (and (= uid owner) (distinct (bvand mask op) #x00000000)) (and (= gid group) (distinct (bvand mask (bvshl op #x00000004)) #x00000000)) (distinct (bvand mask (bvshl op #x00000008)) #x00000000)))
(assert (distinct source compact))''',
      'notifyd_policy_file_gate16.smt2':'''(set-logic QF_BV)
(declare-fun mode () (_ BitVec 16))
(declare-fun uid () (_ BitVec 32))
(define-fun source () Bool (and (= uid #x00000000) (= ((_ extract 1 1) mode) #b0)))
(define-fun compact () Bool (and (= uid #x00000000) (= (bvand mode #x0002) #x0000)))
(define-fun toggle_group () Bool (and (= uid #x00000000) (= (bvand (bvxor mode #x0010) #x0002) #x0000)))
(assert (or (distinct source compact) (distinct source toggle_group)))''',
      'notifyd_policy_whitespace8.smt2':'''(set-logic QF_BV)
(declare-fun char () (_ BitVec 8))
(define-fun shifted () (_ BitVec 64) (bvshl #x0000000000000001 ((_ zero_extend 56) (bvand char #x3f))))
(define-fun source () Bool (and (bvule char #x20) (distinct (bvand shifted #x0000000100000201) #x0000000000000000)))
(define-fun compact () Bool (or (= char #x00) (= char #x09) (= char #x20)))
(assert (distinct source compact))''',
      'notifyd_policy_access48.smt2':'''(set-logic QF_BV)
(declare-fun chars () (_ BitVec 48))
(define-fun r0 () Bool (= ((_ extract 7 0) chars) #x72))
(define-fun w1 () Bool (= ((_ extract 15 8) chars) #x77))
(define-fun r2 () Bool (= ((_ extract 23 16) chars) #x72))
(define-fun w3 () Bool (= ((_ extract 31 24) chars) #x77))
(define-fun r4 () Bool (= ((_ extract 39 32) chars) #x72))
(define-fun w5 () Bool (= ((_ extract 47 40) chars) #x77))
(define-fun first () (_ BitVec 32) (ite w1 (ite r0 #x00000003 #x00000002) (ite r0 #x00000001 #x00000000)))
(define-fun second () (_ BitVec 32) (ite r2 (bvor first #x00000010) first))
(define-fun third () (_ BitVec 32) (ite w3 (bvor second #x00000020) second))
(define-fun fourth () (_ BitVec 32) (ite r4 (bvor third #x00000100) third))
(define-fun source () (_ BitVec 32) (ite w5 (bvor fourth #x00000200) fourth))
(define-fun compact () (_ BitVec 32) (bvor (ite r0 #x00000001 #x00000000) (ite w1 #x00000002 #x00000000) (ite r2 #x00000010 #x00000000) (ite w3 #x00000020 #x00000000) (ite r4 #x00000100 #x00000000) (ite w5 #x00000200 #x00000000)))
(assert (distinct source compact))'''}
    proofs=[]
    for name,body in queries.items():
        raw='(set-option :timeout 30000)\n'+body+'\n(check-sat)\n';path=ROOT/name;path.write_text(raw);run=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);assert run.stdout.strip()=='unsat' and not run.stderr;proofs.append({'path':name,'sha256':sha(path.read_bytes()),'result':'unsat','scope':'encoded local source predicates only;no native path proof'})
    sdk=Path('/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk');cmd=['/usr/bin/clang','-target','arm64e-apple-macos','-isysroot',str(sdk),'-Wall','-Wextra','-Werror','-O2','-S',str(ROOT/'notifyd_policy_layouts.c'),'-o',str(ROOT/'notifyd_policy_layouts.s')];run=subprocess.run(cmd,capture_output=True,text=True);assert run.returncode==0 and not run.stderr
    out={'scope':__doc__,'provider_thin_sha256':THIN_SHA,'generator_sha256':sha(Path(__file__).read_bytes()),'dependencies':{n:sha((ROOT/n).read_bytes()) for n in ['notifyd_policy_profiles.json','probe_notifyd_policy.py','probe_notifyd_policy_pairs.py','notifyd_policy_reference.conf','notifyd_policy_reference.json','notifyd_ipc_reader.py']},'original_functions':functions,'original_audit_helpers':audit_helpers,'observed_state_messages':state_messages,'cache_uuid':cache.cache.uuid,'original_strings':strings,'stat_gate_source_fields':{'size_bytes':144,'mode_offset':4,'uid_offset':16,'gid_offset':20,'size_offset':96,'tested_mode_mask':2},'source_controlled_array_pointer':'0x100014210','source_controlled_count':'0x100014224','proofs':proofs,'sdk_compile':{'command':cmd,'exit_code':run.returncode,'source_sha256':sha((ROOT/'notifyd_policy_layouts.c').read_bytes()),'assembly_sha256':sha((ROOT/'notifyd_policy_layouts.s').read_bytes()),'stat_header':{'path':str(sdk/'usr/include/sys/stat.h'),'sha256':sha((sdk/'usr/include/sys/stat.h').read_bytes())},'target_execution':False},'additional_SDK_headers':[{'path':str(sdk/'usr/include'/n),'sha256':sha((sdk/'usr/include'/n).read_bytes())} for n in ['bsm/libbsm.h','mach/message.h','mach/ndr.h']],'native_target_executed':False,'full_goal_complete':False};(ROOT/'notifyd_policy_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(functions),'strings':len(strings),'proofs':len(proofs),'SDK_compile_exit':run.returncode}),flush=True)

if __name__=='__main__':main()
