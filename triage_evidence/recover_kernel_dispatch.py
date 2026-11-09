#!/usr/bin/env python3
"""Original KC dispatch-table and handler contracts; static reads only.

O(B+F+T+I) time/space for image bytes B, validated fixups F, table rows T,
and retained instructions I. Solver complexity is separate. Names come from
the original collection's parallel tables; pinned source is a comparison.
"""
import bisect
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
from kernel_native_reader import Kernel
from resolve_kernel_collection_interfaces import chained_rebases

ROOT=Path(__file__).resolve().parent
MACH=0xfffffe0007efb010
MACH_NAMES=0xfffffe0007efbc10
BSD=0xfffffe0007f2ca58
BSD_NAMES=0xfffffe000caa30c8
MACH_DISPATCH=0xfffffe000be76b10
BSD_DISPATCH=0xfffffe000c43ba9c
MACH2=0xfffffe000bcdd73c
SEND=0xfffffe000bcdd350
RECEIVE=0xfffffe000bcdd4e4
RETURN=0xfffffe000c43be88


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    k=Kernel();base,rebases,metadata=chained_rebases(k.data)
    def offset(a,n=1):
        s=next(s for s in k.root['segments'] if s['address']<=a and a+n<=s['address']+s['file_size'])
        return s['file_offset']+a-s['address']
    def pointer(a,nullable=False):
        off=offset(a,8)
        if nullable and k.read(a,8)==bytes(8):return None
        assert off in rebases,hex(a)
        return {'slot':hex(a),'file_offset':hex(off),**metadata[off]}
    def cstring(a):
        off=offset(a);end=k.data.index(0,off)
        return k.data[off:end].decode()
    def region(a,n):
        raw=k.read(a,n)
        return {'address':hex(a),'file_offset':hex(offset(a,n)),
                'size_bytes':n,'sha256':hashlib.sha256(raw).hexdigest(),'bytes':raw.hex()}
    rows=[]
    for i in range(128):
        a=MACH+24*i;n,w,p,pad=struct.unpack('<4B',k.read(a,4))
        assert pad==0 and k.read(a+4,4)==bytes(4) and p in (0,1) and n<=9 and w<=16
        call=pointer(a+8);munge=pointer(a+16,True);namep=pointer(MACH_NAMES+8*i)
        assert int(call['target'],16) in k.starts
        if munge:assert int(munge['target'],16) in k.starts
        rows.append({'index':i,'signed_selector':-i,'name':cstring(int(namep['target'],16)),
            'argument_count':n,'u32_words':w,'returns_port':bool(p),
            'handler_pointer':call,'munger_pointer':munge,'name_pointer':namep})
    bsd=[]
    for i in range(558):
        a=BSD+24*i;call=pointer(a);munge=pointer(a+8,True)
        rt,n,nb=struct.unpack('<IhH',k.read(a+16,8));namep=pointer(BSD_NAMES+8*i)
        assert rt<=7 and 0<=n<=8 and 0<=nb<=64 and int(call['target'],16) in k.starts
        if munge:assert int(munge['target'],16) in k.starts
        bsd.append({'index':i,'name':cstring(int(namep['target'],16)),
            'return_type':rt,'argument_count':n,'u32_argument_bytes':nb,
            'handler_pointer':call,'munger_pointer':munge,'name_pointer':namep})
    assert [bsd[i]['name'] for i in (5,6,73,197,339,398,399)]==[
        'open','close','munmap','mmap','fstat64','open_nocancel','close_nocancel']
    assert k.read(BSD+558*24,8)==bytes(8)
    # Source comparison explicitly preserves target/reference differences.
    src=(ROOT/'xnu_dispatch_reference_osfmk_kern_syscall_sw.c.txt').read_text().split('const char * const mach_syscall_name_table')[0]
    refs={}
    for ix,name,n,w in re.findall(r'/\*\s*(\d+)\s*\*/\s*MACH_TRAP\(\s*(\w+)\s*,\s*(\d+)\s*,\s*(\d+)',src):
        refs.setdefault(int(ix),(name,int(n),int(w)))
    assert len(refs)==128
    differences=[]
    for r in rows:
        value=(r['name'],r['argument_count'],r['u32_words'])
        if value!=refs[r['index']]:differences.append({'index':r['index'],'original':value,'reference':refs[r['index']]})
    assert [r['index'] for r in differences]==[63,108]
    selected_mach=[26,27,28,29,31,32,47,50,63,100,108]
    selected_bsd=[0,5,6,63,73,197,339,398,399,557]
    addresses={MACH_DISPATCH,BSD_DISPATCH,RETURN,MACH2,SEND,RECEIVE,
        0xfffffe000bcdd148,0xfffffe000c43c058,0xfffffe000bd7e9c4,0xfffffe000bd41068,
        0xfffffe000bf55720,0xfffffe000c289b50,0xfffffe000c289dbc,
        0xfffffe000bdc1ec0,0xfffffe000bcc8cf4,0xfffffe000bccd000,
        0xfffffe000bcc9c1c,0xfffffe000bd4401c,0xfffffe000c2bd008,
        0xfffffe000c5f2534,0xfffffe000bf08c94}
    addresses|={int(rows[i]['handler_pointer']['target'],16) for i in selected_mach}
    addresses|={int(bsd[i]['handler_pointer']['target'],16) for i in selected_bsd}
    functions={hex(a):k.function(a) for a in sorted(addresses)}
    # Compiler-bounded exception handler includes words not decoded by Capstone.
    # Preserve these as .byte rather than inventing instructions.
    svc=0xfffffe000be7c764;ix=k.starts.index(svc);end=k.starts[ix+1]
    raw=k.read(svc,end-svc);k.cs.skipdata=True;ins=list(k.cs.disasm(raw,svc));k.cs.skipdata=False
    assert sum(i.size for i in ins)==len(raw)
    functions[hex(svc)]={'start':hex(svc),'end':hex(end),'bytes':raw.hex(),
        'sha256':hashlib.sha256(raw).hexdigest(),'instructions':[{'ea':hex(i.address),
        'mnemonic':i.mnemonic,'operands':i.op_str} for i in ins],
        'undecoded_words':[hex(i.address) for i in ins if i.mnemonic=='.byte']}
    names=set(addresses)
    for r in functions.values():
        for i in r['instructions']:
            if i['mnemonic'] in ('b','bl') and i['operands'].startswith('#0x'):
                names.add(int(i['operands'][1:],16))
    symbols=k.symbols(names)
    for a,r in functions.items():r['exact_nlist']=symbols.get(a,[])
    # Check native dispatch sites and fixed strides, not just recognizable data.
    checks={
      '0xfffffe000be76b78':('adrp','x9, #0xfffffe0007efb000'),
      '0xfffffe000be76b7c':('add','x9, x9, #0x10'),
      '0xfffffe000be76c88':('blraa','x22, x17'),
      '0xfffffe000c43bbac':('cmp','w21, #0x22e'),
      '0xfffffe000c43bbc0':('add','x9, x9, #0xa58'),
      '0xfffffe000c43bd60':('blraa','x8, x17'),
      '0xfffffe000be7cb68':('tbnz','w27, #0x1f, #0xfffffe000be7cfb8'),
      '0xfffffe000be7cb8c':('bl','#0xfffffe000c43ba9c'),
      '0xfffffe000be7d02c':('bl','#0xfffffe000be76b10')}
    instructions={i['ea']:i for r in functions.values() for i in r['instructions']}
    for a,pair in checks.items():assert (instructions[a]['mnemonic'],instructions[a]['operands'])==pair
    # Arithmetic/protocol predicate proofs are distinct from instruction execution.
    queries={
      'bsd_low16_selection':'''(declare-fun code () (_ BitVec 64))
(define-fun low () (_ BitVec 64) (bvand code #x000000000000ffff))
(define-fun idx () (_ BitVec 64) (ite (bvult low #x000000000000022e) low #x000000000000003f))
(define-fun offset () (_ BitVec 64) (bvshl (bvadd idx (bvshl idx #x0000000000000001)) #x0000000000000003))
(assert (not (and (bvult idx #x000000000000022e) (= offset (bvmul idx #x0000000000000018)))) )''',
      'descriptor_minimum_extent':'''(declare-fun size () Int)
(assert (and (<= 28 size) (<= size 4294967295)))
(define-fun n () Int (- size 28))
; UMULH by 0xaaaaaaaaaaaaaaab followed by LSR 3 is integer division by 2^67.
; n is nonnegative and 32-bit, so the original 128-bit product cannot overflow.
(define-fun native () Int (div (* n 12297829382473034411) 147573952589676412928))
(assert (not (= native (div n 12))))''',
      'mach2_class_gate':'''(declare-fun o () (_ BitVec 64))
(define-fun cl () (_ BitVec 64) (bvand o #x0000001e00000000))
(define-fun dec () (_ BitVec 64) (bvsub cl #x0000000000000001))
(define-fun vec () (_ BitVec 64) (bvand o #x0000000d00000000))
(define-fun isvec () Bool (= vec #x0000000100000000))
(define-fun native_invalid () Bool (or isvec (bvule (bvxor cl dec) dec)))
(define-fun onehot () Bool (and (not (= cl #x0000000000000000)) (= (bvand cl dec) #x0000000000000000)))
(define-fun vector_compatible () Bool (or (= (bvand o #x0000000100000000) #x0000000000000000)
 (not (= (bvand o #x0000000c00000000) #x0000000000000000))))
(assert (not (= native_invalid (not (and vector_compatible onehot)))))''',
      'option_policy_mask':'''(declare-fun o () (_ BitVec 64))
(define-fun native () (_ BitVec 64)
 (ite (= (bvand o #x0000000000010000) #x0000000000000000)
  (bvand o #x0000001f0fb7dbbf)
  (bvor (bvand o #x0000001f0fb6dbbf) #x0000004000000000)))
(assert (not (and (= (bvand native #x0000000000000440) #x0000000000000000)
 (= (bvand native #x0000004000000000) (ite (= (bvand o #x0000000000010000) #x0000000000000000) #x0000000000000000 #x0000004000000000)))))'''}
    proofs=[]
    for name,body in queries.items():
        logic='QF_LIA' if name=='descriptor_minimum_extent' else 'QF_BV'
        p=ROOT/f'kernel_dispatch_{name}.smt2';p.write_text(f'(set-logic {logic})\n'+body+'\n(check-sat)\n')
        done=subprocess.run(['z3','-smt2',str(p)],capture_output=True,text=True,check=True,timeout=60)
        assert done.stdout.strip()=='unsat',(name,done.stdout,done.stderr)
        proofs.append({'name':name,'file':p.name,'result':'unsat','logic':logic,'scope':'bounded integer or bitvector formula, not runtime reachability'})
    # All reference files are preserved with URLs and hashes; exact revision unknown.
    refs=json.loads((ROOT/'kernel_dispatch_references.json').read_text())
    for r in refs['sources']:assert sha(ROOT/r['file'])==r['sha256']
    refs['existing_message_reference']={'path':'xnu_osfmk_ipc_mach_msg.c',
        'sha256':sha(ROOT/'xnu_osfmk_ipc_mach_msg.c'),
        'url':'https://raw.githubusercontent.com/apple-oss-distributions/xnu/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/ipc/mach_msg.c'}
    result={'source':{'path':str(__import__('resolve_kernel_collection_interfaces').CACHE),
        'sha256':k.sha256,'kernel_uuid':k.kernel['uuid'],'function_starts':len(k.starts)},
        'scope':__doc__,'generator_sha256':sha(Path(__file__)),
        'reader_sha256':sha(ROOT/'kernel_native_reader.py'),
        'fixup_decoder_sha256':sha(ROOT/'resolve_kernel_collection_interfaces.py'),
        'all_chained_fixups':len(rebases),
        'mach_table':region(MACH,128*24),'mach_name_table':region(MACH_NAMES,128*8),
        'bsd_table':region(BSD,558*24),'bsd_name_table':region(BSD_NAMES,558*8),
        'mach_entries':rows,'bsd_entries':bsd,'functions':functions,
        'exact_symbol_bindings':{a:b for a,b in symbols.items() if b},
        'native_dispatch_checks':checks,'reference_comparison':refs,
        'mach_reference_differences':differences,'proofs':proofs,
        'native_target_executed':False,'target_host_operations_executed':False,
        'runtime_pac_or_table_contents_attested':False,'full_goal_complete':False}
    p=ROOT/'kernel_dispatch_contracts.json';p.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'mach_entries':len(rows),'bsd_entries':len(bsd),'functions':len(functions),
        'reference_differences':differences,'proofs_unsat':len(proofs),
        'exception_handler_undecoded_words':len(functions[hex(svc)]['undecoded_words'])}))


if __name__=='__main__':main()
