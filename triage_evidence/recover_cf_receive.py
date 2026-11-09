#!/usr/bin/env python3
"""Original cache/daemon CF receive contracts. No target host execution.

O(B+S+I+H) time and O(B+S+I) space for selected bytes B, original symbols S,
instructions I and streamed source-hash bytes H. Solver cost is separate.
"""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
from bootpolicy_cache_reader import Cache,Dylib,CS,ROOT
from daemon_receive_tools import IMAGE,SOURCE
from daemon_import_bindings import binding
from kernel_native_reader import Kernel

CF_PATH='/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation'
SERVICE=0x184758a28
DO_SOURCE=0x184758bc8
SOURCE_CALL=0x184758ec0
PERFORM=0x184784050
CREATE_SOURCE=0x18472d178
WITH_PORT=0x1848121b0
REALLOC=0x1847f38b0
RUN=0x184756e7c
CF_UUID='7fe5392e-ff16-31e1-8552-3a45c6b68224'
FUNCTIONS=[0x184752484,0x18472cfe8,0x184812774,WITH_PORT,CREATE_SOURCE,
    0x1847e8924,PERFORM,0x1847841ec,SERVICE,DO_SOURCE,SOURCE_CALL,RUN,
    0x1847cf374,0x18472d31c,0x18472d934,REALLOC,0x1847f37ec,
    0x1848cd9d8,0x1848d4550,0x18472cff0,0x1846ddb6c,0x1846ddde4,0x1846dbbb8]


def sha(p):
    h=hashlib.sha256()
    with p.open('rb') as stream:
        while b:=stream.read(4<<20):h.update(b)
    return h.hexdigest()


def main():
    c=Cache();assert c.uuid=='2bd06591-e751-3e84-963f-b08dab6af23a'
    cf=Dylib(c,CF_PATH);assert cf.uuid==CF_UUID
    funcs=[]
    for a in FUNCTIONS:
        r=cf.function(a);assert len(r['instructions'])*4==len(bytes.fromhex(r['bytes']))
        r['original_nlist']=cf.symbols_at(a);r['original_exports']=[n for n,v in cf.exports.items() if v['address']==a]
        m=c.mapping(a);r['source_file']=m['path'];r['source_offset']=hex(m['off']+a-m['va']);funcs.append(r)
    libs={CF_PATH:cf};imports=[]
    def stub(a):
        raw=c.read(a,16);ins=list(CS.disasm(raw,a));assert [i.mnemonic for i in ins]==['adrp','add','ldr','braa']
        cell=int(ins[0].op_str.split('#')[1],16)+int(ins[1].op_str.split('#')[1],16)
        ptr=c.pointer(cell);target=int(ptr['target'],16)
        path=max((i for i in c.images if i['address']<=target),key=lambda i:i['address'])['path']
        if path not in libs:libs[path]=Dylib(c,path)
        lib=libs[path];names=[n for n,v in lib.exports.items() if v['address']==target];assert names,hex(a)
        r={'stub':hex(a),'bytes':raw.hex(),'pointer':ptr,'target':hex(target),
           'library':path,'uuid':lib.uuid,'original_exports':names}
        imports.append(r);return r
    for a in [0x188076b60,0x18806c3d0,0x188081380,0x188081360,0x188078e40,
              0x18806ead0,0x188076bc0,0x18806ebf0,0x18806c600,0x18806c510,
              0x1880846e0]:stub(a)
    assert imports[0]['original_exports']==['_mach_msg']
    voucher_hooks=[]
    libkernel=libs['/usr/lib/system/libsystem_kernel.dylib']
    for a in (0x18054b344,0x18054b32c):
        r=libkernel.function(a);assert len(r['instructions'])*4==len(bytes.fromhex(r['bytes']))
        r['original_nlist']=libkernel.symbols_at(a);m=c.mapping(a)
        r['source_file']=m['path'];r['source_offset']=hex(m['off']+a-m['va']);voucher_hooks.append(r)
    voucher_table=c.pointer(0x1ed83e8d8)
    voucher_table['original_target_bytes_48']=c.read(int(voucher_table['target'],16),48).hex()
    voucher_table['runtime_value']='unknown; ___libkernel_voucher_init can replace this table'
    # Assertions tie the lifted widths, ABI positions, PAC contracts and
    # ownership branches to exact original instructions, separately from models.
    checks=[]
    def check(a,mnemonic,operands,meaning):
        raw=c.read(a,4);i=next(CS.disasm(raw,a))
        assert (i.mnemonic,i.op_str)==(mnemonic,operands),(hex(a),i.mnemonic,i.op_str)
        checks.append({'address':hex(a),'bytes':raw.hex(),'mnemonic':mnemonic,
            'operands':operands,'meaning':meaning})
    for a,m,o,n in [
      (0x184752484,'mov','w4, #1','public create hidden monitor flag'),
      (0x18472cfe8,'mov','w5, #1','public create-with-port hidden monitor flag'),
      (0x184758a70,'mov','w26, #0xc00','fixed initial receive capacity'),
      (0x184758ac4,'bl','#0x188076b60','receive reaches resolved mach_msg'),
      (0x184758ad0,'bl','#0x188081380','revert previous voucher state after receive'),
      (0x184758ad8,'bl','#0x188081360','adopt current receive voucher'),
      (0x184758aec,'bl','#0x188078e40','optional voucher copy'),
      (0x184758b24,'add','w8, w8, #0x44','u32 trailer addition'),
      (0x184758b28,'add','x8, x8, #3','u64 rounding addition'),
      (0x184758b2c,'and','x26, x8, #0x1fffffffc','u64 rounded capacity mask'),
      (0x184758b3c,'mov','x3, #0','no reallocation recovery context'),
      (0x184758b40,'bl','#0x1847f38b0','private safe reallocation entry'),
      (0x184758b58,'bl','#0x18806ead0','release copied voucher before retry'),
      (0x184758b74,'ldr','w8, [x25, #0xc]','successful live receive name'),
      (0x184758b88,'bl','#0x18806c3d0','timeout releases grown receive buffer'),
      (0x184758b94,'str','xzr, [x20]','timeout clears buffer output'),
      (0x184758bc4,'bl','#0x1848d4550','other receive statuses enter cold failure'),
      (0x184758d98,'ldr','x16, [x17, #0xa8]!','source callback field'),
      (0x184758da0,'movk','x17, #0xc0b6, lsl #48','version1 perform discriminator'),
      (0x184758e20,'bl','#0x184758ec0','source1 perform bridge'),
      (0x184758ef8,'blraaz','x8','perform callback authenticated call'),
      (0x184758efc,'str','x0, [x19]','perform return becomes framework reply pointer'),
      (0x1847840bc,'ccmp','x0, #0, #4, eq','boost only if old null and new nonnull'),
      (0x184784124,'bl','#0x1846ddde4','install boost in TSD12 before callback'),
      (0x18478413c,'blraaz','x8','CFMachPort callback with temporary boost'),
      (0x18478414c,'bl','#0x1846ddde4','clear TSD12 after callback'),
      (0x18478416c,'blraaz','x8','CFMachPort callback without temporary boost'),
      (0x1847841b4,'str','xzr, [x19, #0x60]','clear temporary cached boost'),
      (0x1847841d0,'mov','x0, #0','CFMachPort performs no framework-generated reply'),
      (0x184784200,'mov','w0, #0xd','boost reads TSD13'),
      (0x184784230,'bl','#0x1880846e0','retain voucher inside boost'),
      (0x18472d598,'ldr','x16, [x19, #0x40]','version1 context perform offset64'),
      (0x18472d5bc,'movk','x17, #0xc0b6, lsl #48','version1 perform signing discriminator'),
      (0x18472d738,'str','x16, [x8]','version1 stores signed perform at source+a8'),
      (0x1847576c0,'bl','#0x1846ddde4','run loop installs voucher in TSD13'),
      (0x184757708,'ldr','w4, [x3, #4]','source size is header inline size, excluding trailer'),
      (0x184757718,'bl','#0x184758bc8','run loop source1 dispatch'),
      (0x184757744,'bl','#0x188076b60','optional generic source reply send'),
      (0x184757788,'bl','#0x1846ddde4','restore prior TSD13'),
      (0x1847577b4,'cmp','x0, x24','compare receive buffer with original stack buffer'),
      (0x1847577c4,'bl','#0x18806c3d0','free grown receive storage after dispatch'),
      (0x1847f380c,'bl','#0x18806c510','original typed realloc target'),
      (0x1848cda04,'cbz','x2, #0x1848cda54','null recovery context enters failure'),
      (0x1848cdacc,'brk','#1','reallocation fail-stop'),
      (0x18054b34c,'ldr','x1, [x8, #0x18]','adopt runtime voucher table callback+24'),
      (0x18054b354,'braaz','x1','adopt tail-calls authenticated runtime callback'),
      (0x18054b358,'mov','x0, #-1','empty adopt hook returns sentinel -1'),
      (0x18054b334,'ldr','x1, [x8, #0x20]','revert runtime voucher table callback+32'),
      (0x18054b33c,'braaz','x1','revert tail-calls authenticated runtime callback'),
    ]:check(a,m,o,n)
    globals=[]
    for a,n in [(0x1ed891742,1),(0x1ed890e90,8),(0x1ed890e08,8),(0x1ed890e10,8)]:
        globals.append({'address':hex(a),'original_bytes':c.read(a,n).hex(),'runtime_value':'unknown'})
    for a in [0x1e01c88a8,0x1e01c8b30,0x1e0261ea0,0x1e01c8830]:
        globals.append({**c.pointer(a),'runtime_value':'unknown'})
    # Original daemon wrapper code, imports and current live-IDB readback.
    wrappers=[]
    for a,n in [(0x100001f50,76),(0x100001f9c,80)]:
        raw=IMAGE.read(a,n);wrappers.append({'start':hex(a),'size_bytes':n,'bytes':raw.hex(),
            'sha256':hashlib.sha256(raw).hexdigest(),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(raw,a)]})
    live=json.loads((ROOT/'cf_receive_live_wrappers.json').read_text())
    for r in wrappers:
        got=next(x for x in live['result']['results'] if x['address'].lower()==r['start'])
        assert got['bytes'].lower()==r['bytes']
    binds=[binding(a) for a in [0x1010b1c40,0x1010b1c48,0x1010a0888,0x1010a0c08,0x1010a0270]]
    request_guards=[]
    for mid,start,size,cmp in [
        (1200,0x100004530,64,0x100004548),(1201,0x100004720,164,0x10000472c),
        (1202,0x1000047a4,84,0x1000047bc),(1203,0x100004918,100,0x100004930),
        (1204,0x100004ae4,24,0x100004af0),(1000,0x100004c44,60,0x100004c5c),
        (1001,0x100004e1c,160,0x100004e28),(1002,0x100004e98,80,0x100004eb0),
        (502,0x1000050c8,80,0x1000050e0),(41471,0x100005324,40,0x10000533c),
        (61471,0x1000054d8,64,0x1000054f0)]:
        raw=IMAGE.read(cmp-4,12);ins=list(CS.disasm(raw,cmp-4))
        assert (ins[0].mnemonic,ins[0].op_str)==('ldr','w8, [x0, #4]')
        assert (ins[1].mnemonic,ins[1].op_str)==('cmp',f'w8, #{hex(size)}')
        assert ins[2].mnemonic=='b.ne'
        assert size%4==0 and size+68<=3072
        request_guards.append({'message_id':mid,'stub_start':hex(start),'size_bytes':size,
            'guard_address':hex(cmp-4),'guard_bytes':raw.hex(),'guard_sha256':hashlib.sha256(raw).hexdigest(),
            'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ins],
            'inline_plus_av_trailer_bytes':size+68})
    # The same original kernel's packer and audit template remain a separate image.
    k=Kernel();packer=k.function(0xfffffe000bcc62d0);template=k.read(0xfffffe0007010a68,68)
    assert template[20:52]==bytes(32)
    queries={
      'growth_normal_bounds':'''(declare-fun size () (_ BitVec 32))
(assert (bvule size #x02ffffbc))
(define-fun sum32 () (_ BitVec 32) (bvadd size #x00000044))
(define-fun cap () (_ BitVec 64) (bvand (bvadd ((_ zero_extend 32) sum32) #x0000000000000003) #x00000001fffffffc))
(define-fun need () (_ BitVec 64) (bvadd ((_ zero_extend 32) size) #x0000000000000044))
(assert (not (and (bvuge cap need) (bvule (bvsub cap need) #x0000000000000003)
 (bvult cap #x0000000100000000) (= (bvand cap #x0000000000000003) #x0000000000000000))))''',
      'growth_fullwidth_bound':'''(declare-fun size () (_ BitVec 32))
(define-fun sum32 () (_ BitVec 32) (bvadd size #x00000044))
(define-fun cap () (_ BitVec 64) (bvand (bvadd ((_ zero_extend 32) sum32) #x0000000000000003) #x00000001fffffffc))
(assert (not (and (bvule cap #x0000000100000000) (= (bvand cap #x0000000000000003) #x0000000000000000))))''',
      'receive_options':'''(declare-fun timeout () (_ BitVec 32))
(define-fun options () (_ BitVec 32) (ite (= timeout #xffffffff) #x07000806 #x07000906))
(assert (not (and (= (bvand options #x0f000806) #x07000806)
 (= (bvand options #x00000001) #x00000000)
 (= (bvand options #x00000100) (ite (= timeout #xffffffff) #x00000000 #x00000100)))))''',
      'constructor_admission':'''(declare-fun status () (_ BitVec 32))
(declare-fun types () (_ BitVec 32))
(define-fun z () Bool (ite (= status #x00000000) (= (bvand types #x00070000) #x00000000) true))
(assert (not (= (not z) (and (= status #x00000000) (not (= (bvand types #x00070000) #x00000000))))))''',
      'audit_prefix_coverage':'''(declare-fun inline () (_ BitVec 32))
(assert (and (bvuge inline #x00000018) (bvule inline #x00000bbc) (= (bvand inline #x00000003) #x00000000)))
(define-fun delivered () (_ BitVec 32) (bvadd inline #x00000044))
(define-fun audit_end () (_ BitVec 32) (bvadd inline #x00000034))
(assert (not (and (bvule delivered #x00000c00) (bvule audit_end delivered))))''',
      'boost_field_gate':'''(declare-fun old () (_ BitVec 64))
(declare-fun new () (_ BitVec 64))
(define-fun z () Bool (ite (= old #x0000000000000000) (= new #x0000000000000000) true))
(assert (not (= (not z) (and (= old #x0000000000000000) (not (= new #x0000000000000000))))))'''}
    proofs=[]
    for name,body in queries.items():
        p=ROOT/f'cf_receive_{name}.smt2';p.write_text('(set-logic QF_BV)\n'+body+'\n(check-sat)\n')
        answer=subprocess.run(['z3','-smt2',str(p)],check=True,capture_output=True,text=True,timeout=30).stdout.strip()
        assert answer=='unsat',(name,answer);proofs.append({'name':name,'file':p.name,'result':answer,'scope':'lifted branch/width arithmetic, not native reachability'})
    sdk=json.loads((ROOT/'cf_receive_references.json').read_text())
    for s in sdk['sources']:assert sha(ROOT/s['file'])==s['sha256']
    layout=ROOT/'cf_receive_layouts.c';compiler=subprocess.run(['xcrun','--find','clang'],check=True,capture_output=True,text=True).stdout.strip()
    command=[compiler,'-target','arm64e-apple-macos13.0','-isysroot',sdk['sdk'],'-std=c11','-fsyntax-only',str(layout)]
    comp=subprocess.run(command,capture_output=True,text=True);assert comp.returncode==0,comp.stderr
    files=[]
    for path in sorted(c.used):files.append({**c.files[path],'sha256':sha(Path(path))})
    result={'scope':__doc__,'cache_uuid':c.uuid,'library':CF_PATH,'library_uuid':cf.uuid,
        'generator_sha256':sha(Path(__file__)),'cache_reader_sha256':sha(ROOT/'bootpolicy_cache_reader.py'),
        'functions':funcs,'voucher_hook_ranges':voucher_hooks,'voucher_hook_table':voucher_table,
        'imports':imports,'globals':globals,'native_instruction_checks':checks,
        'daemon_source_sha256':sha(SOURCE),
        'daemon_wrappers':wrappers,'daemon_imports':binds,'daemon_request_size_guards':request_guards,
        'live_wrapper_ranges_matched':len(wrappers),
        'kernel':{'sha256':k.sha256,'uuid':k.kernel['uuid'],'packer':packer,
            'audit_template_address':'0xfffffe0007010a68','audit_template':template.hex()},
        'proofs':proofs,'references':sdk,'layout_compile':{'command':command,'exit_code':comp.returncode,
            'stderr':comp.stderr,'source_sha256':sha(layout)},'cache_source_files':files,
        'native_target_executed':False,'target_host_operations_executed':False,
        'runtime_module_or_port_identity_attested':False,'full_goal_complete':False}
    (ROOT/'cf_receive_contracts.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'cache_ranges':len(funcs),'native_instruction_checks':len(checks),'resolved_stubs':len(imports),'proofs_unsat':len(proofs),
        'live_wrappers':len(wrappers),'request_size_guards':len(request_guards),
        'cache_files_hashed':len(files),'layout_compile':comp.returncode}))


if __name__=='__main__':main()
