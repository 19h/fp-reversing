#!/usr/bin/env python3
"""Original frame/bank/caller evidence and bounded kernel-corpus search.

Read original provider,collection,SDK and retained private artifacts. No native
target/API operation. O(B+F+C*256+R) time/space; local SMT timeout30s each.
"""
import json
from pathlib import Path
import struct
import subprocess
from adid_reader import Adid,ROOT,CS,sha,THIN_SHA
from resolve_kernel_collection_interfaces import CACHE,commands,string
from probe_adid_startup import unpack_records

BANKS=[('query_A',0x1001f4d88,0x1001f4d28,0x1002add60,0x1002c1d90,0x66,0x2825,'x27',0x15a0,0x1598),
 ('query_B',0x1001f55d8,0x1001f557c,0x1002c1f90,0x10027f330,0xff,0x28bc,'x27',0x1688,0x1680),
 ('query_C',0x1001f5990,0x1001f5930,0x1002add60,0x1002c1d90,0x9d,0x285e,'x27',0x15a0,0x1598),
 ('record_helper',0x100263a00,0x10026399c,0x1002add60,0x1002c1d90,0x9d,0x2873,'x27',0x15a0,0x1598),
 ('host_uuid_A',0x1001d45a0,0x1001d4548,0x10027f230,0x100294230,0x6a,0x278f,'x27',0x15a8,0x15b0),
 ('host_uuid_B_conditional',0x1001fb804,0x1001fb7ac,0x10027f430,0x100294330,0x3b,0x2826,'x27',0x1628,None),
 ('truncate',0x10025d12c,0x10025d0c8,0x1002ade60,0x1002c1e90,0x37,0x27e1,'x24',0x1670,0x1678)]


def main():
    s=Adid();p=json.loads((ROOT/'adid_driver_dispatch_profiles.json').read_text());ck=json.loads((ROOT/'adid_driver_dispatch_frame.json').read_text());sp=int(ck['registers']['SP'],16)
    first=next(r for r in p['profiles'] if r['fixture']['label']=='original_request_frame');frame=unpack_records(first)[-1];table=0x1002c40c0
    banks=[];bindings=[]
    for label,site,start,a,b,key,base,reg,sa,sb in BANKS:
        aa=s.read(a,256);bb=s.read(b,256);values=[n^bb[aa[n]^key] for n in range(256)];assert len(set(values))==1
        row={'label':label,'first_address':hex(a),'second_address':hex(b),'first_bytes':aa.hex(),'second_bytes':bb.hex(),'key_u8':key,'constant_u8':values[0],'results_256':values};banks.append(row)
        index=base+values[0];slot=table+index*8;raw=s.read(start,site+4-start)
        bindings.append({'label':label,'callsite':hex(site),'window_start':hex(start),'window_end':hex(site+4),'window_bytes':raw.hex(),'window_sha256':sha(raw),
            'table_register':reg,'table_base_assumption':hex(table),'base_index_u32':base,'first_frame_slot_offset':sa,'second_frame_slot_offset':sb,
            'second_register_assumption':{'register':'x15','value':hex(b),'writer_or_reaching_binding_proven':False} if sb is None else None,
            'constant_byte_u8':values[0],'index_u32':index,'source_pointer':s.decoded[slot],
            'scope':'Local original lookup under stated table/frame bindings;whole-request/native reachability unproved.'})
        assert int(frame['stack_slots'][hex(sa)],16)==a
        if sb is not None:assert int(frame['stack_slots'][hex(sb)],16)==b
    queries={
 'adid_driver_dispatch_index32.smt2':'''(declare-fun n () (_ BitVec 32))
(declare-fun c () (_ BitVec 8))
(declare-fun base () (_ BitVec 32))
(define-fun bank_result () (_ BitVec 8) (bvxor ((_ extract 7 0) n) c))
(define-fun original () (_ BitVec 32) (bvadd base ((_ zero_extend 24) ((_ extract 7 0) (bvxor n ((_ zero_extend 24) bank_result))))))
(assert (distinct original (bvadd base ((_ zero_extend 24) c))))''',
 'adid_driver_dispatch_record_keys32.smt2':'''(declare-fun a () (_ BitVec 32))
(define-fun k () (_ BitVec 32) (bvmul (bvxor a #x834674ac) #x0a42990d))
(define-fun first () (_ BitVec 32) (bvmul (bvxor (bvsub (bvadd a #x4eb93c51) (bvshl (bvand a #x4eb93c51) #x00000001)) #xcdff48fd) #x0a42990d))
(define-fun second () (_ BitVec 32) (bvmul (bvxor (bvsub (bvor a #xa26d2245) (bvand a #xa26d2245)) #x212b56e9) #x0a42990d))
(define-fun third () (_ BitVec 32) (bvmul (bvxor (bvadd (bvsub (bvshl (bvand a #x1a827310) #x00000001) a) #xe57d8ced) #x663bf841) #x0a42990d))
(assert (or (distinct first k) (distinct second k) (and (= (bvand a #x00000002) #x00000000) (distinct third k))))''',
 'adid_driver_dispatch_alias64.smt2':'''(declare-fun sp () (_ BitVec 64))
(define-fun fp () (_ BitVec 64) (bvadd sp #x0000000000009ff0))
(define-fun rec () (_ BitVec 64) (bvsub fp #x00000000000000a8))
(define-fun pa () (_ BitVec 64) (bvadd sp #x00000000000028e3))
(define-fun pb () (_ BitVec 64) (bvadd sp #x00000000000016db))
(define-fun pc () (_ BitVec 64) (bvadd sp #x0000000000002ede))
(define-fun bias () (_ BitVec 64) #x7e1f59740c8f6451)
(define-fun inv () (_ BitVec 64) #x81e0a68bf3709baf)
(assert (or (distinct (bvadd (bvadd pa bias) inv) (bvadd (bvadd sp #x0000000000002728) #x00000000000001bb)) (distinct (bvadd (bvadd pb bias) inv) (bvadd (bvadd sp #x00000000000006dc) #x0000000000000fff)) (distinct (bvadd (bvadd pc bias) inv) (bvadd (bvadd sp #x0000000000002728) #x00000000000007b6)) (and (= (bvand sp #x000000000000000f) #x0000000000000000) (distinct (bvand rec #x000000000000000f) #x0000000000000008))))''',
 'adid_driver_dispatch_predicate8.smt2':'''(declare-fun value () (_ BitVec 8))
(define-fun a () (_ BitVec 8) ((_ extract 7 0) (bvsub #x00001106 #x000003e7)))
(define-fun b () (_ BitVec 8) ((_ extract 7 0) (bvsub (bvor (bvadd #x000008f6 #x0000030d) #x00000158) #x0000003c)))
(define-fun c () (_ BitVec 8) ((_ extract 7 0) (bvadd (bvxor (bvshl #x00000583 #x00000001) #x000003dc) #x00000045)))
(assert (or (distinct a #x1f) (distinct b #x1f) (distinct c #x1f) (distinct (= value a) (= value b)) (distinct (distinct value c) (not (= value a)))))'''}
    proofs=[]
    for name,body in queries.items():
        path=ROOT/name;path.write_text('(set-logic QF_BV)\n(set-option :timeout 30000)\n'+body+'\n(check-sat)\n');run=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True)
        assert run.stdout.strip()=='unsat' and not run.stderr;proofs.append({'path':name,'sha256':sha(path.read_bytes()),'result':'unsat','scope':'Full stated local BV domains under declared frame/state/alignment prefixes only.'})
    windows=[]
    for a,z,role in [(0x1001664c0,0x10016653c,'original encoded output-slot producers'),(0x1001f4c24,0x1001f4c34,'query A output initialization'),(0x1001f4cc4,0x1001f4d9c,'query A constructor/call/consumer'),
        (0x1001f5478,0x1001f5484,'query B output initialization'),(0x1001f550c,0x1001f55f0,'query B constructor/call/consumer'),(0x1001f583c,0x1001f584c,'query C output initialization'),(0x1001f58c0,0x1001f59a4,'query C constructor/call/consumer'),
        (0x1001d452c,0x1001d4548,'host UUID argument/zero-timeout preparation A'),(0x1001fb798,0x1001fb7ac,'conditional host UUID argument/zero-timeout preparation B')]:
        raw=s.read(a,z-a);windows.append({'start':hex(a),'end':hex(z),'role':role,'bytes':raw.hex(),'sha256':sha(raw),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(raw,a)]})
    raw=CACHE.read_bytes();assert sha(raw)=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe';filesets=[]
    for at,cmd,size in commands(raw,0):
        if cmd==0x80000035:filesets.append(string(raw,at+struct.unpack_from('<I',raw,at+24)[0]))
    literals={word:raw.count(word.encode()) for word in ['AvpFairPlayDriver','AvpFairPlayUserClient','AvpFairPlayUserClient.access','com_apple_driver_FairPlayIOKit']}
    corpus={'path':str(CACHE),'sha256':sha(raw),'size_bytes':len(raw),'fileset_names':filesets,'literal_counts':literals,'name_filter_matches':[x for x in filesets if any(k in x.lower() for k in ('avp','fairplay','virt'))],
        'scope':'Exact plaintext literals and module-name filter in one pinned collection;not proof of absence from runtime or other images/encodings.'}
    sdk=Path('/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk');cmd=['/usr/bin/clang','-target','arm64e-apple-macos','-isysroot',str(sdk),'-Wall','-Wextra','-Werror','-O2','-S',str(ROOT/'adid_driver_dispatch_layouts.c'),'-o',str(ROOT/'adid_driver_dispatch_layouts.s')];run=subprocess.run(cmd,capture_output=True,text=True);assert run.returncode==0 and not run.stderr
    headers=[sdk/'usr/include/unistd.h',sdk/'usr/include/gethostuuid.h',sdk/'usr/include/sys/_types/_timespec.h']
    out={'scope':__doc__,'thin_sha256':THIN_SHA,'uuid':s.meta['uuid'],'banks':banks,'local_bindings':bindings,'proofs':proofs,'original_windows':windows,'kernel_corpus_search':corpus,
        'frame_provenance':{'source_row':'original_request_frame','stop_pc':'0x10019bb18','SP':hex(sp),'FP':ck['registers']['X29'],'table_base':hex(table),'source_before_any_fragment_override':True},
        'SDK_compile':{'command':cmd,'source_sha256':sha((ROOT/'adid_driver_dispatch_layouts.c').read_bytes()),'assembly_sha256':sha((ROOT/'adid_driver_dispatch_layouts.s').read_bytes()),'exit_code':run.returncode},'SDK_headers':[{'path':str(h),'sha256':sha(h.read_bytes())} for h in headers],
        'generator_sha256':sha(Path(__file__).read_bytes()),'dependencies':{n:sha((ROOT/n).read_bytes()) for n in ['adid_reader.py','probe_adid_driver_dispatch.py','adid_driver_dispatch_profiles.json','adid_driver_dispatch_frame.json','adid_context_profiles.json','adid_iokit_caller_contracts.json']},'native_target_executed':False,'full_goal_complete':False}
    (ROOT/'adid_driver_dispatch_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'banks':len(banks),'byte_domain_checks':len(banks)*256,'local_bindings':len(bindings),'proofs':len(proofs),'windows':len(windows),'collection_filesets':len(filesets),'literal_counts':literals,'SDK_compile_exit':run.returncode}))


if __name__=='__main__':main()
