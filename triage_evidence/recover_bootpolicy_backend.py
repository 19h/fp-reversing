#!/usr/bin/env python3
"""Original cache/KC BootPolicy interface recovery; no target execution.

O(B+F+S+D+H) extraction time/space for KC bytes B, fixups F, symbols S,
retained instructions D and hashed source bytes H (hashing streams O(1) space).
SMT cost is solver-dependent. Runtime object/PAC/environment identity unknown.
"""
import bisect
import hashlib
import json
from pathlib import Path
import plistlib
import struct
import subprocess
from bootpolicy_cache_reader import Cache,Dylib,CS,ROOT,CACHE,uleb
from verify_interface_contracts import Image
from kernel_native_reader import Kernel
from resolve_kernel_collection_interfaces import commands,chained_rebases,string
from daemon_receive_tools import block,qword,TABLE,SOURCE


def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for buf in iter(lambda:f.read(4*1024*1024),b''):h.update(buf)
    return h.hexdigest()


def main():
    c=Cache();d=Dylib(c,'/usr/lib/libbootpolicy.dylib')
    assert c.uuid=='2bd06591-e751-3e84-963f-b08dab6af23a'
    assert d.uuid=='c7262dd7-f07d-35f3-a130-3cfa5a10289a'
    cached={d.path:d}
    original_functions=[]
    for a in [0x1b7e48f44,0x1b7e49170,0x1b7e3b118,0x1b7e39350,
              0x1b7e38808,0x1b7e38c24,0x1b7e3a968,0x1b7e470b4,
              0x1b7e3a374,0x1b7e3a41c,0x1b7e614c4,0x1b7e614d8]:
        r=d.function(a);r['original_nlist']=d.symbols_at(a);original_functions.append(r)
    text=next(s for s in d.sections if s['name']=='__text')
    original_text=c.read(text['address'],text['size'])
    extracted_path=ROOT/'libbootpolicy.arm64e.macho'
    extracted=Image(extracted_path)
    assert original_text==extracted.read(text['address'],text['size'])
    extraction={'path':extracted_path.name,'sha256':digest(extracted_path),
        'command':'/Users/___/dev/dylex/target/release/dylex extract '+str(CACHE)+
          ' -i /usr/lib/libbootpolicy.dylib -o triage_evidence/libbootpolicy.arm64e.macho -v 2',
        'extractor_sha256':digest(Path('/Users/___/dev/dylex/target/release/dylex')),
        'original_text_address':hex(text['address']),'original_text_size':text['size'],
        'original_text_sha256':hashlib.sha256(original_text).hexdigest(),'entire_text_equal':True,
        'note':'Extracted headers/support/pointers modified by extractor; all native claims use original cache ranges.'}
    imports=[]
    def resolve_stub(a):
        raw=c.read(a,16);ins=list(CS.disasm(raw,a))
        assert [i.mnemonic for i in ins]==['adrp','add','ldr','braa'],hex(a)
        cell=int(ins[0].op_str.split('#')[1],16)+int(ins[1].op_str.split('#')[1],16)
        p=c.pointer(cell);target=int(p['target'],16)
        image=max((r for r in c.images if r['address']<=target),key=lambda r:r['address'])
        if image['path'] not in cached:cached[image['path']]=Dylib(c,image['path'])
        lib=cached[image['path']]
        assert any(s['name']=='__TEXT' and s['address']<=target<s['address']+s['size'] for s in lib.segments)
        names=[n for n,r in lib.exports.items() if r['address']==target]
        assert names,(hex(a),image['path'],hex(target))
        rec={'stub':hex(a),'bytes':raw.hex(),'pointer':p,'target_image':image['path'],
             'target_uuid':lib.uuid,'exact_original_exports':names}
        imports.append(rec);return rec
    for a in [0x1b812f7f0,0x1b812bf80,0x1b812f010,0x1b812fd00,
              0x1b8130230,0x1b8130980,0x1b8130120,0x1b81300e0,
              0x1b812f450,0x1b81313b0,0x1b812f460,0x1b812ef80,
              0x1b812bed0,0x1b812f380,0x1b81318e0,
              0x1b8147de0,0x1b812ef90,0x1b8147f00]:resolve_stub(a)
    io=cached['/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit']
    io_functions=[]
    for a in [0x184e77b74,0x184e77bc0,0x184e78db0,0x184e77d74,0x184e77e8c]:
        r=io.function(a);r['original_nlist']=io.symbols_at(a);io_functions.append(r)
    resolve_stub(0x188088a80)
    assert imports[-1]['exact_original_exports']==['_mach_msg2_internal']
    port_globals=[]
    for address,libname,want in [
        (0x1e01c8b30,'/usr/lib/system/libsystem_kernel.dylib','_mach_task_self_'),
        (0x1e016e6d0,io.path,'_kIOMainPortDefault')]:
        p=c.pointer(address)
        target=int(p['target'],16)
        lib=cached.get(libname) or Dylib(c,libname)
        assert lib.exports[want]['address']==target
        port_globals.append({**p,'exact_original_export':want,'library':libname,
            'runtime_value':'unknown'})
    cells=[]
    for a in [0x1e1770ab0,0x1e1770ac0,0x1e66a88f0,0x1e66a8c20]:
        p=c.pointer(a);p['target_prefix_hex']=c.read(int(p['target'],16),32).hex();cells.append(p)
    assert int(cells[0]['target'],16)==0x1b7e77819
    assert c.cstring(0x1b7e77819,128)=='/System/Volumes/iSCPreboot'
    assert int(cells[1]['target'],16)==0x1ee340af0
    assert c.read(0x1ee340af0,16)==bytes(16)
    strings={hex(a):c.cstring(a,128) for a in [0x1b7e77819,0x1b7e777f1,
        0x1b7e7a0a1,0x1b7e7a0c9,0x1b7e77429,0x1b7e77443,0x1b7e7a192]}
    assert strings['0x1b7e777f1']=='BootPolicy'
    # Original LC_CODE_SIGNATURE XML entitlement blob; no trust/signature verification.
    data=SOURCE.read_bytes();lc=next(at for at,cmd,n in commands(data,0) if cmd==0x1d)
    off,size=struct.unpack_from('<II',data,lc+8)
    magic,length,count=struct.unpack_from('>3I',data,off)
    assert magic==0xfade0cc0 and length<=size
    ents=None;entblob=None
    for i in range(count):
        typ,rel=struct.unpack_from('>2I',data,off+12+8*i)
        bm,blen=struct.unpack_from('>2I',data,off+rel)
        if typ==5:
            assert bm==0xfade7171 and rel+blen<=length
            entblob=data[off+rel+8:off+rel+blen];ents=plistlib.loads(entblob)
    assert ents and ents['com.apple.private.security.bootpolicy'] is True
    (ROOT/'bootpolicy_daemon_entitlements.plist').write_bytes(entblob)
    # Matching original kernel collection, with independent format8 chain membership.
    k=Kernel();entry=next(e for e in k.entries if e['name']=='com.apple.security.BootPolicy')
    assert entry['uuid']=='cd49af0a-e1ab-3506-98e6-9f04b09314dd'
    starts=[]
    base=next(s['address'] for s in entry['segments'] if s['name']=='__TEXT')
    for at,cmd,n in commands(k.data,entry['header_offset']):
        if cmd==0x26:
            off,size=struct.unpack_from('<II',k.data,at+8);buf=k.data[off:off+size]
            at=0;a=base
            while at<len(buf):
                delta,at=uleb(buf,at)
                if not delta:break
                a+=delta;starts.append(a)
    all_symbols=[]
    so,count,st,ss=entry['symtab']
    for i in range(count):
        sx,ty,se,ds,value=struct.unpack_from('<IBBHQ',k.data,so+i*16)
        if value and sx and sx<ss:
            all_symbols.append({'address':hex(value),'name':string(k.data,st+sx),
                                'n_type':ty,'n_sect':se})
    kernel_functions=[]
    for a in [0xfffffe000a337f80,0xfffffe000a33809c,0xfffffe000a3382d8,
              0xfffffe000a3386d0,0xfffffe000a338734,0xfffffe000a338e60,
              0xfffffe000a338ebc,0xfffffe000a339278,0xfffffe000a3397b0,
              0xfffffe000a339910,0xfffffe000a339a68,0xfffffe000a339bc0,
              0xfffffe000a339c68]:
        assert a in starts,hex(a)
        ix=starts.index(a);end=starts[ix+1];raw=k.read(a,end-a)
        kernel_functions.append({'start':hex(a),'end':hex(end),'bytes':raw.hex(),
            'sha256':hashlib.sha256(raw).hexdigest(),
            'original_nlist':[r for r in all_symbols if r['address']==hex(a)],
            'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}
                for i in k.cs.disasm(raw,a)]})
    _,rebases,metadata=chained_rebases(k.data)
    kernel_pointers=[]
    def kernel_pointer(a):
        s=next(s for s in k.root['segments'] if s['address']<=a<a+8<=s['address']+s['file_size'])
        off=s['file_offset']+a-s['address'];assert off in rebases
        p={'address':hex(a),'file_offset':hex(off),**metadata[off]}
        kernel_pointers.append(p);return int(p['target'],16)
    kernel_stubs=[]
    for a in [0xfffffe000a33a374,0xfffffe000a33a404,0xfffffe000a33a494,
              0xfffffe000a33a4a4,0xfffffe000a33a434,0xfffffe000a33a444,
              0xfffffe000a33a454,0xfffffe000a33a464,0xfffffe000a33a474]:
        raw=k.read(a,16);ins=list(k.cs.disasm(raw,a))
        assert [i.mnemonic for i in ins]==['adrp','add','ldr','braa']
        cell=int(ins[0].op_str.split('#')[1],16)+int(ins[1].op_str.split('#')[1],16)
        target=kernel_pointer(cell)
        kernel_stubs.append({'stub':hex(a),'bytes':raw.hex(),'cell':hex(cell),'target':hex(target)})
    names=k.symbols([int(r['target'],16) for r in kernel_stubs])
    for r in kernel_stubs:r['exact_symbols']=names[r['target']]
    endpoint_slots=[]
    for offset in [0x170,0x180,0x1e8,0x200,0x208]:
        a=0xfffffe0008316408+16+offset
        target=kernel_pointer(a)
        endpoint_slots.append({'vtable':'0xfffffe0008316408','address_point':'0xfffffe0008316418',
            'offset':hex(offset),'cell':hex(a),'target':hex(target)})
    endpoint_names=k.symbols([int(r['target'],16) for r in endpoint_slots])
    for r in endpoint_slots:r['exact_symbols']=endpoint_names[r['target']]
    assert next(r for r in endpoint_slots if r['offset']=='0x1e8')['target']=='0xfffffe0009de8d18'
    kernel_pointer(0xfffffe0008429f58)
    dispatch={'address':'0xfffffe0008429f58','bytes':k.read(0xfffffe0008429f58,40).hex(),
        'function':'0xfffffe000a33809c','scalar_input_count':0,'structure_input_size':0xffffffff,
        'scalar_output_count':0,'structure_output_size':0xffffffff,
        'allowAsync':0,'checkEntitlement':0,'size_bytes':40}
    assert kernel_pointers[-1]['target']==dispatch['function']
    assert struct.unpack('<4I',k.read(0xfffffe0008429f60,16))==(0,0xffffffff,0,0xffffffff)
    assert k.read(0xfffffe0008429f70,16)==bytes(16)
    kstrings={hex(a):k.read(a,128).split(b'\0')[0].decode() for a in [
        0xfffffe00078d3976,0xfffffe00078d399c,0xfffffe00078d3e34]}
    # Native daemon result classification after BootPolicy success.
    daemon_native=[block(a,0x1800) for a in [0x100592a00,0x100461da8,0x1005750d4,
        0x1004cdba4,0x1003c33f8,0x10051e440,0x1005bbb20]]
    branches={0x946e:0x100461da8,0x226d:0x1005750d4,0x2263:0x1004cdba4,
        0x3826:0x1003c33f8,0x3833:0x10051e440,0x6140:0x1005bbb20,0x2b0b:0x1005bbb20}
    for ix,a in branches.items():assert qword(TABLE+ix*8)==a
    allowed=[n for n in range(0x100) if n in (0x4c,0x5a) or
             (0<=(n-11)<=60 and (0x1b1f88048800207f>>(n-11))&1)]
    assert 0x11 in allowed
    queries={
     'readonly_commands':'''(declare-fun c () (_ BitVec 32))
(define-fun delta () (_ BitVec 32) (bvsub c #x0000000b))
(define-fun shifted () (_ BitVec 64) (bvshl #x0000000000000001
 ((_ zero_extend 32) (bvand delta #x0000003f))))
(define-fun native () Bool (or (= c #x0000004c) (= c #x0000005a)
 (and (bvule delta #x0000003c) (not (= (bvand shifted #x1b1f88048800207f) #x0000000000000000)))))
(assert (not (= native (or '''+' '.join('(= c #x%08x)'%a for a in allowed)+'''))))''',
     'daemon_mode_partition':'''(declare-fun m () (_ BitVec 32))
(define-fun native () (_ BitVec 32)
 (ite (bvslt m #x00000003)
  (ite (bvsgt m #x00000000) #x693d4f62 #x693d4f68)
  (ite (= m #x00000003) #x693d4f65 #x693d4f68)))
(define-fun reduced () (_ BitVec 32)
 (ite (or (= m #x00000001) (= m #x00000002)) #x693d4f62
  (ite (= m #x00000003) #x693d4f65 #x693d4f68)))
(assert (not (= native reduced)))'''}
    proofs=[]
    for name,body in queries.items():
        p=ROOT/f'bootpolicy_{name}.smt2';p.write_text('(set-logic QF_BV)\n'+body+'\n(check-sat)\n')
        answer=subprocess.run(['z3','-smt2',str(p)],check=True,capture_output=True,text=True).stdout.strip()
        assert answer=='unsat',(name,answer)
        proofs.append({'name':name,'path':p.name,'result':answer})
    sources=[]
    c.used.add(str(CACHE))
    for name in sorted(c.used):
        sources.append({**c.files[name],'sha256':digest(Path(name))})
    out={'cache_uuid':c.uuid,'cache_images':len(c.images),'cache_mappings':len(c.maps),
        'source_files':sources,'library_uuid':d.uuid,'library_path':d.path,
        'library_exports':{n:{'address':hex(r['address']),'flags':r['flags']} for n,r in d.exports.items()
            if n in ['_bootpolicy_get_security_mode','_bootpolicy_get_security_mode_ex',
              '_bootpolicy_default_policy_volume_path_value','_bootpolicy_root_volume_uuid_value']},
        'extraction_check':extraction,'library_functions':original_functions,
        'shared_cache_call_stubs':imports,'data_cells':cells,'strings':strings,
        'port_globals':port_globals,
        'iokit_functions':io_functions,'daemon_entitlements':ents,
        'entitlement_blob_sha256':hashlib.sha256(entblob).hexdigest(),
        'entitlement_signature_trust_verified':False,
        'kernel_collection_sha256':k.sha256,'kernel_entry':entry,
        'kernel_function_starts_count':len(starts),'kernel_functions':kernel_functions,
        'kernel_stubs':kernel_stubs,'kernel_pointer_chains':kernel_pointers,
        'endpoint_virtual_slots':endpoint_slots,
        'kernel_strings':kstrings,'kernel_dispatch':dispatch,
        'readonly_command_ids':allowed,'daemon_mode_ranges':daemon_native,
        'daemon_branch_slots':[{'index':hex(ix),'target':hex(a)} for ix,a in branches.items()],
        'smt_proofs':proofs,'native_target_executed':False,
        'synthetic_target_instructions_executed':False,'idb_mutated':False,
        'runtime_library_selection_attested':False,
        'unknowns':['actual runtime cache/library selection and PAC state',
          'SEP firmware command semantics/security-mode enum and final FairPlay policy',
          'native request success, port object identity and complete endpoint lifecycle',
          'complete input_local_policy filesystem/metadata derivation and output semantics']}
    (ROOT/'bootpolicy_backend_contracts.json').write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'cache_uuid':c.uuid,'library_functions':len(original_functions),
        'iokit_functions':len(io_functions),'exact_shared_stubs':len(imports),
        'kernel_functions':len(kernel_functions),'kernel_stubs':len(kernel_stubs),
        'source_file_hashes':len(sources),'readonly_ids':len(allowed),
        'daemon_ranges':len(daemon_native),'smt_unsat':len(proofs),
        'entitlement_present':True,'original_text_equal':True}))


if __name__=='__main__':main()
