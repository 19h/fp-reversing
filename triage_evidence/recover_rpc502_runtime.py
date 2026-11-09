#!/usr/bin/env python3
"""Original-byte runtime/CoreKE interface recovery plus bounded fixture readback.

No native target/library/IPC/file operation is executed. O(B+F+D+P) extraction
time/space plus streamed source hashing and solver-dependent proof cost.
"""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import uuid
from daemon_receive_tools import IMAGE,SOURCE,ROOT,CS,FIXUPS,TABLE,qword,selected
from daemon_import_bindings import binding
from resolve_kernel_collection_interfaces import commands
from bootpolicy_cache_reader import uleb
from run_rpc502_context_profiles import PROFILES

P2=0x1010ab960
T2=0x1010ab1a0


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def native(a,end):
    raw=IMAGE.read(a,end-a)
    ins=list(CS.disasm(raw,a));assert len(ins)*4==len(raw)
    return {'start':hex(a),'end':hex(end),'bytes':raw.hex(),'sha256':hashlib.sha256(raw).hexdigest(),
        'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ins]}


def core_image(data):
    seg=[];exports=None;starts=[];ident=None;libs=[]
    for at,cmd,n in commands(data,0):
        if cmd==0x19:
            name=data[at+8:at+24].split(b'\0')[0].decode()
            va,size,off,length=struct.unpack_from('<4Q',data,at+24)
            seg.append((name,va,size,off,length))
        elif cmd==0x1b:ident=str(uuid.UUID(bytes=data[at+8:at+24]))
        elif cmd==0x80000033:exports=struct.unpack_from('<II',data,at+8)
        elif cmd==0x26:starts_info=struct.unpack_from('<II',data,at+8)
        elif cmd in (0xc,0x80000018,0x8000001f,0x80000023,0x20):
            d=struct.unpack_from('<I',data,at+8)[0];s=at+d
            libs.append(data[s:data.index(0,s)].decode())
    base=next(s[1] for s in seg if s[0]=='__TEXT')
    assert exports
    off,n=exports;buf=data[off:off+n];names={}
    def visit(at,prefix,ancestors):
        assert at not in ancestors
        n,cur=uleb(buf,at);end=cur+n
        if n:
            flags,loc=uleb(buf,cur);assert not flags&8
            value,_=uleb(buf,loc);names[prefix]=base+value
        count=buf[end];cur=end+1
        for _ in range(count):
            endstr=buf.index(0,cur);suffix=buf[cur:endstr].decode()
            child,cur=uleb(buf,endstr+1);visit(child,prefix+suffix,ancestors|{at})
    visit(0,'',set())
    off,n=starts_info;buf=data[off:off+n];at=0;a=base
    while at<len(buf):
        d,at=uleb(buf,at)
        if not d:break
        a+=d;starts.append(a)
    def read(a,n):
        s=next(s for s in seg if s[1]<=a and a+n<=s[1]+s[4])
        return data[s[3]+a-s[1]:s[3]+a-s[1]+n]
    funcs=[]
    for name,a in names.items():
        ix=starts.index(a);end=starts[ix+1];raw=read(a,end-a)
        funcs.append({'name':name,'start':hex(a),'end':hex(end),'bytes':raw.hex(),
            'sha256':hashlib.sha256(raw).hexdigest(),
            'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(raw,a)]})
    return {'uuid':ident,'exports':{k:hex(v) for k,v in names.items()},'load_dylibs':libs,
            'function_starts_count':len(starts),'exported_functions':funcs}


def main():
    ranges=[native(a,b) for a,b in [
        (0x1005bbb20,0x1005bbbfc),(0x10051e790,0x10051e7c0),(0x1004d4b18,0x1004d4bd0),
        (0x100de50f4,0x100de55e8),(0x100ddb5d4,0x100ddb7f8),(0x100de3608,0x100de3834),
        (0x100de6860,0x100de6a94),(0x100ddff88,0x100de0170),
        (0x100de1430,0x100de1e3c),(0x100ddc63c,0x100ddc710),
        (0x100de9bf0,0x100de9cd8),(0x100d943d0,0x100d944d0),
        (0x100de83f0,0x100de8630)]]
    cases=[
      ('once',0x101032970,0x101032a70,0xb9,0x8a,T2,0,'libSystem/_pthread_once'),
      ('malloc',0x101032b70,0x101032c70,0x27,0x26,T2,0,'libSystem/_malloc_type_malloc'),
      ('rwlock init',0x101032570,0x101032670,0xd0,0x24,T2,0,'libSystem/_pthread_rwlock_init'),
      ('dispatch pointer',0x101032b70,0x101032c70,0x2b,-0x72,P2,-12,hex(T2)),
      ('CoreKE path',0x101032170,0x101032270,0xf3,-0x1f,P2,-8,'0x1010320e9'),
      ('message',0x101032770,0x101032870,0x2b,-0xd9,P2,-8,'0x1010320a0'),
      ('dlopen',0x101032b70,0x101032c70,0x2b,0x56,T2,0,'libSystem/_dlopen'),
      ('dlsym A',0x101032b70,0x101032c70,0x2b,0x67,T2,0,'libSystem/_dlsym'),
      ('dlsym B',0x101032570,0x101032670,0xb7,0xb1,T2,0,'libSystem/_dlsym'),
      ('export name A',0x101032770,0x101032870,0x6a,0x1f,P2,-12,'0x101032137'),
      ('export name B',0x101032570,0x101032670,0xd,-0x9e,P2,-12,'0x10103214e'),
      ('publish export A',0x101032170,0x101032270,0xf3,-0x2e,P2,-4,'0x1010c5738'),
      ('publish export B',0x101032b70,0x101032c70,0x27,-0x9c,P2,-4,'0x1010c5718'),
      ('loader ready byte',0x101032570,0x101032670,0xd,-0x77,P2,0,'0x1010c5728')]
    banks=[]
    for label,l,r,k,add,base,bias,want in cases:
        rec=selected(l,r,k,add,base,bias);assert rec['target']==want,(label,rec['target'],want)
        rec['label']=label;banks.append(rec)
    encoded=IMAGE.read(0x101032123,20);decoded=bytes((b*27-17)&255 for b in encoded)
    assert decoded==b'kern.hv_vmm_present\0'
    assert qword(0x1010c5360)==0x101032123
    assert all((((x*27-17)+17)*19)&255==x for x in range(256))
    branches={0x4c:0x100de6960,0x5d:0x100de6990,0xd:0x100de18b4,
              0x1f:0x100de18e0,0x1b:0x100de1a44,0x1d:0x100de1ac0}
    for ix,a in branches.items():assert qword(T2+8*ix)==a
    mask=0xffffffff
    z10=(0x0a8d938a+0xf5726cc2)&mask
    z9=((z10+0x7e9e7cf3)&mask)&0xdd7fbfee
    assert (z9^0x5c1e3d2f)==1 and z10==0x4c
    for a in [0x1010c5340,0x1010c5350]:assert IMAGE.read(a,16)==bytes.fromhex('babcb130000000000000000000000000')
    queries={
      'comparison_mask':'''(declare-fun p () (_ BitVec 64))
(define-fun callee () (_ BitVec 64)
 (bvmul (bvxor (bvadd (bvsub (bvor p #x5df58a7def5ba5e7) p)
 (bvand p #xa20a758210a45a18)) #xf3c6b5a52cf276c6) #x0000000044a8b7e9))
(assert (not (= callee (bvmul (bvxor p #xae333fd8c3a9d321) #x0000000044a8b7e9))))''',
      'status_frame_mask':'''(declare-fun p () (_ BitVec 64))
(define-fun caller () (_ BitVec 64)
 (bvmul (bvxor (bvsub #xfffffffffffffffe
 (bvadd (bvor p #x7ff9dd26253164cc) (bvor (bvnot p) #x800622d9dace9b33)))
 #x2e351d0119674812) #x0000000044a8b7e9))
(assert (not (= caller (bvmul (bvxor p #xae333fd8c3a9d321) #x0000000044a8b7e9))))''',
      'predicate_frame_mask':'''(declare-fun p () (_ BitVec 64))
(assert (= (bvand p #x0000000000000007) #x0000000000000000))
(define-fun caller () (_ BitVec 64)
 (bvmul (bvxor (bvadd (bvsub (bvshl (bvand p #x2368d6bcd1b79518) #x0000000000000001) p)
 #x5c9729432e486ae1) #xf2a4169bede1b9c0) #x0000000044a8b7e9))
(assert (not (= caller (bvmul (bvxor p #xae333fd8c3a9d321) #x0000000044a8b7e9))))''',
      'vmm_gate':'''(declare-fun s () (_ BitVec 32))
(declare-fun v () (_ BitVec 32))
(define-fun nz () (_ BitVec 32) (bvlshr (bvor s (bvneg s)) #x0000001f))
(define-fun first () (_ BitVec 32)
 (bvxor (ite (= s #x00000000) #x8601b00b #x8601b019) #x8601b006))
(define-fun a () (_ BitVec 32)
 (ite (= first #x0000000d) (ite (= v #x00000001) #x00000001 #x00000000) #x00000000))
(define-fun b () (_ BitVec 32) (ite (= first #x0000000d) nz #x00000000))
(define-fun c () (_ BitVec 32) (ite (= first #x0000000d) #x00000001 nz))
(define-fun mixed () (_ BitVec 32)
 (bvadd #xd719acda (bvxor #xd719acda #x28e65324) c #x00000003))
(define-fun result () (_ BitVec 32)
 (bvxor (ite (not (= a #x00000000)) #xd719acda mixed)
   (bvxor #xd719acda b #x0000001b)))
(assert (not (= result (ite (and (= s #x00000000) (= v #x00000001)) #x0000001b #x0000001d))))'''}
    proofs=[]
    for name,body in queries.items():
        p=ROOT/f'rpc502_runtime_{name}.smt2';p.write_text('(set-logic QF_BV)\n'+body+'\n(check-sat)\n')
        answer=subprocess.run(['z3','-smt2',str(p)],check=True,capture_output=True,text=True).stdout.strip()
        assert answer=='unsat',(name,answer)
        proofs.append({'name':name,'path':p.name,'result':answer})
    profiles=[];reads={}
    for name,args in PROFILES:
        p=ROOT/f'rpc502_context_{name}.json';r=json.loads(p.read_text())
        assert r['generator_sha256']==sha(ROOT/'daemon_rpc502_context_probe.py')
        assert r['base_generator_sha256']==sha(ROOT/'daemon_rpc502_probe.py')
        assert r['source_sha256']==sha(SOURCE)
        assert not r['native_target_executed'] and r['synthetic_target_instructions_executed']
        assert not r['target_host_ipc_files_or_system_calls_executed'] and not r['coreke_code_executed']
        assert r['stop_reason'] in ['unmodeled_pointer_auth_instruction','unmodeled_import','unmodeled_coreke_export']
        for rec in r['bound_import_reads']:reads[rec['slot']]=rec
        profiles.append({'file':p.name,'sha256':sha(p),'arguments':args,'steps':r['steps'],
             'stop_reason':r['stop_reason'],'last_record':r['records'][-1],
             'once_completed':r['serial_once_completed_controls'],'lock_states':r['serial_lock_states'],
             'open_boundary':[a for a in r['records'] if a['kind']=='unmodeled_open_boundary']})
    bindings=[binding(int(a,16)) for a in sorted(reads)]
    sid=json.loads((ROOT/'coreke_source_identity.json').read_text())
    original=Path(sid['original_path']);fat=original.read_bytes()
    assert sha(original)==sid['original_sha256']
    thin=(ROOT/sid['output']).read_bytes();s=sid['selected_slice']
    assert thin==fat[s['offset']:s['offset']+s['size']] and hashlib.sha256(thin).hexdigest()==sid['sha256']
    assert Path('/System/Library/PrivateFrameworks/CoreKE.framework/CoreKE').resolve()==original
    core=core_image(thin)
    assert core['exports']=={'_IWvA5fm4IwMS88oQXDANCS':'0x11b4','_JY0DfiUyFiVcNw89R4t':'0x1418'}
    variants=[]
    for row in sid['slices']:
        if row['cpu']!='0x100000c':continue
        im=core_image(fat[row['offset']:row['offset']+row['size']])
        variants.append({'cpu':row['cpu'],'subtype':row['subtype'],'uuid':im['uuid'],'exports':im['exports']})
    headers=[]
    sdk=Path('/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include')
    for name in ['pthread/pthread.h','pthread/pthread_impl.h','sys/_pthread/_pthread_types.h','dlfcn.h','fcntl.h']:
        p=sdk/name;headers.append({'path':str(p),'resolved_path':str(p.resolve()),'sha256':sha(p),'exact_runtime_source':False})
    out={'source_sha256':sha(SOURCE),'native_ranges':ranges,'banks':banks,
        'branch_slots':[{'index':hex(i),'target':hex(a)} for i,a in branches.items()],
        'original_import_bindings':bindings,'name_decoder':{'source':'0x101032123','encoded_hex':encoded.hex(),
            'formula':'(27*byte-17) modulo256','decoded_hex':decoded.hex(),'decoded_ascii':decoded[:-1].decode(),
            'inverse_inputs_checked':256},'proofs':proofs,'profiles':profiles,
        'coreke_source_identity':sid,'coreke_image':core,'coreke_arm_variants':variants,'headers':headers,
        'native_target_executed':False,'synthetic_target_instructions_executed':True,'coreke_code_executed':False,
        'idb_mutated':False,'unknowns':['runtime library/slice selection, PAC and concurrency',
            'CoreKE operation semantics, complete record schema and returned status',
            'unexpected synthetic sidecar prefix and complete path construction',
            'actual sysctl state and native transaction/output lifetimes']}
    (ROOT/'rpc502_runtime_contracts.json').write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'native_ranges':len(ranges),'bank_checks':len(banks),'import_bindings':len(bindings),
        'proofs_unsat':len(proofs),'profiles':len(profiles),'coreke_exports':len(core['exports']),
        'coreke_variants':len(variants),'header_hashes':len(headers)}))


if __name__=='__main__':main()
