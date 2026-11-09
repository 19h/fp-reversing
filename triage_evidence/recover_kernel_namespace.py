#!/usr/bin/env python3
"""Read-only original KC namespace, reference, and reply-link contracts.

O(B+I+N) time/space for original image B, selected instructions I, and nlists N.
Arithmetic proof complexity is separate; no native target execution occurs.
"""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
from kernel_native_reader import Kernel

ROOT=Path(__file__).resolve().parent
LOOKUP=0xfffffe000bcd2cc0
MQUEUE=0xfffffe000bcc8cf4
TRANSLATE=0xfffffe000bcc92e4
TRYLOCK=0xfffffe000bcca438
LINK=0xfffffe000bccef30
PREPARE=0xfffffe000bcced98
COMPLETE=0xfffffe000bcceadc
ADJUST=0xfffffe000bcce5b8
USER_REPLY=0xfffffe000bcf8ca0
KERNEL_REPLY=0xfffffe000bcf8e14
KERNEL_UNBIND=0xfffffe000bcf837c
ALLOC=0xfffffe000bccd000
LOCK=0xfffffe000bccc128
UNLOCK=0xfffffe000bd0ab18
RELEASE_SAFE=0xfffffe000bcc927c


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    k=Kernel();addresses=[LOOKUP,MQUEUE,TRANSLATE,TRYLOCK,LINK,PREPARE,COMPLETE,ADJUST,
        USER_REPLY,KERNEL_REPLY,KERNEL_UNBIND,ALLOC,LOCK,RELEASE_SAFE,
        0xfffffe000bcc9240,0xfffffe000bcc922c,0xfffffe000bccdbb4,
        0xfffffe000bccd170,0xfffffe000bcbc250,0xfffffe000bccb548,
        0xfffffe000bcdd4e4,0xfffffe000bd0b274,0xfffffe000bcdcc7c]
    ranges={hex(a):k.function(a) for a in addresses}
    wanted=set(addresses)
    for r in ranges.values():
        for i in r['instructions']:
            if i['mnemonic'] in ('bl','b') and i['operands'].startswith('#0x'):wanted.add(int(i['operands'][1:],16))
    symbols=k.symbols(wanted)
    for a,r in ranges.items():r['exact_nlist']=symbols.get(a,[])
    checks={
      '0xfffffe000bcd2cdc':('cmp','w1, #0xff'),
      '0xfffffe000bcd2d18':('ldr','x16, [x20, #0x48]!'),
      '0xfffffe000bcd2d34':('lsr','w9, w1, #8'),
      '0xfffffe000bcd2d38':('mov','w8, #0x18'),
      '0xfffffe000bcd2d74':('cmp','x10, x12'),
      '0xfffffe000bcd2dac':('bl','#0xfffffe000bcca438'),
      '0xfffffe000bcd2dfc':('cmp','x16, x19'),
      '0xfffffe000bcd2e0c':('tst','w20, #0x1f0000'),
      '0xfffffe000bcd2e14':('and','w11, w20, #0xfc000000'),
      '0xfffffe000bcd2e18':('orr','w11, w11, #0x3000000'),
      '0xfffffe000bcd2e1c':('lsl','w12, w26, #0x18'),
      '0xfffffe000bcc8d3c':('mov','w8, #0xa0000'),
      '0xfffffe000bcc8d54':('ldadd','w8, w8, [x0]'),
      '0xfffffe000bcc8d94':('tbz','w23, #0x15, #0xfffffe000bcc8db4'),
      '0xfffffe000bcc92f8':('cmp','w2, #4'),
      '0xfffffe000bcc932c':('tbz','w9, #0x10, #0xfffffe000bcc933c'),
      '0xfffffe000bcf8cec':('str','xzr, [x20]'),
      '0xfffffe000bcf8d58':('mov','w1, #0x10b'),
      '0xfffffe000bcf8db4':('str','x9, [x19, #0x450]'),
      '0xfffffe000bcf8dc4':('str','x17, [x8, #0x40]'),
      '0xfffffe000bccf0c4':('str','x17, [x20, #0x58]'),
      '0xfffffe000bccf0d0':('orr','w8, w8, #0x1000'),
      '0xfffffe000bcce79c':('cbz','x16, #0xfffffe000bcce7fc'),
      '0xfffffe000bcdce04':('ldaddl','w9, w9, [x8]')}
    ins={i['ea']:i for r in ranges.values() for i in r['instructions']}
    for a,pair in checks.items():assert (ins[a]['mnemonic'],ins[a]['operands'])==pair,(a,ins[a])
    queries={
      'name_generation':'''(declare-fun name () (_ BitVec 32))
(declare-fun bits () (_ BitVec 32))
(define-fun actual () Bool (= (bvor (bvand bits #xfc000000) #x03000000) (bvshl name #x00000018)))
(define-fun low () (_ BitVec 32) (bvand name #x000000ff))
(define-fun gen () (_ BitVec 32) (bvor (bvlshr (bvand bits #xfc000000) #x00000018) #x00000003))
(assert (not (= actual (= low gen))))''',
      'entry_stride_bound':'''(declare-fun name () (_ BitVec 32))
(define-fun idx () (_ BitVec 64) ((_ zero_extend 32) (bvlshr name #x00000008)))
(define-fun off () (_ BitVec 64) (bvshl (bvadd idx (bvshl idx #x0000000000000001)) #x0000000000000003))
(assert (not (and (= off (bvmul idx #x0000000000000018))
 (bvule (bvadd off #x0000000000000018) #x0000000018000000))))''',
      'array_decode_alignment':'''(declare-fun token () (_ BitVec 64))
(define-fun small () Bool (= (bvand token #x0000400000000000) #x0000000000000000))
(define-fun addr () (_ BitVec 64) (ite small
 (bvor (bvand token #xffffffffffffc000) #x0000400000000000)
 (bvand token #xffffffffffffffe0)))
(define-fun size () (_ BitVec 64) (ite small
 (bvshl (bvand token #x0000000000003fff) #x000000000000000e)
 (bvshl (bvor (bvand token #x0000000000000010) #x0000000000000020) (bvand token #x000000000000000f))))
(assert (not (and (= (bvand addr #x000000000000001f) #x0000000000000000)
 (bvule size #x000000000fffc000))))''',
      'translate_right_bit':'''(declare-fun bits () (_ BitVec 32))
(declare-fun right () (_ BitVec 32))
(assert (bvule right #x00000004))
(define-fun native () Bool (not (= (bvand (bvlshr bits right) #x00010000) #x00000000)))
(define-fun expected () Bool (not (= (bvand bits (bvshl #x00010000 right)) #x00000000)))
(assert (not (= native expected)))''',
      'link_state_update':'''(declare-fun flags () (_ BitVec 32))
(define-fun native () (_ BitVec 32) (bvor (bvand flags #xffff8fff) #x00001000))
(assert (not (and (= (bvand native #x00007000) #x00001000)
 (= (bvand native #xffff8fff) (bvand flags #xffff8fff)))))''',
      'reference_increment_guard':'''(declare-fun old () (_ BitVec 32))
(define-fun actual_ok () Bool (bvugt (bvadd old #xf0000001) #xf0000001))
(assert (not (= actual_ok (and (bvugt old #x00000000) (bvult old #x0fffffff)))))'''}
    proofs=[]
    for name,body in queries.items():
        p=ROOT/f'kernel_namespace_{name}.smt2';p.write_text('(set-logic QF_BV)\n'+body+'\n(check-sat)\n')
        done=subprocess.run(['z3','-smt2',str(p)],check=True,text=True,capture_output=True,timeout=30)
        assert done.stdout.strip()=='unsat',(name,done.stdout)
        proofs.append({'name':name,'file':p.name,'result':'unsat','scope':'all-domain formula; runtime object provenance and concurrency unproved'})
    refs=json.loads((ROOT/'kernel_namespace_references.json').read_text())
    for r in refs['sources']:assert sha(ROOT/r['file'])==r['sha256']
    layout=ROOT/'kernel_namespace_layouts.c'
    compiler=subprocess.run(['xcrun','--find','clang'],capture_output=True,text=True,check=True).stdout.strip()
    command=[compiler,'-target','arm64e-apple-macos13.0','-std=c11','-fsyntax-only',str(layout)]
    comp=subprocess.run(command,capture_output=True,text=True);assert comp.returncode==0,comp.stderr
    result={'source':{'sha256':k.sha256,'kernel_uuid':k.kernel['uuid'],'function_starts':len(k.starts)},
        'scope':__doc__,'generator_sha256':sha(Path(__file__)),
        'reader_sha256':sha(ROOT/'kernel_native_reader.py'),'functions':ranges,
        'exact_symbol_bindings':{a:b for a,b in symbols.items() if b},
        'native_instruction_checks':checks,'proofs':proofs,'references':refs,
        'layout_compile':{'command':command,'exit_code':comp.returncode,'stderr':comp.stderr,
            'source_sha256':sha(layout),'scope':'partial field offsets, widths and stride only'},
        'native_target_executed':False,'target_host_operations_executed':False,'runtime_pac_attested':False,
        'full_goal_complete':False}
    (ROOT/'kernel_namespace_contracts.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'ranges':len(ranges),'instruction_checks':len(checks),'proofs_unsat':len(proofs),'layout_compile':comp.returncode}))


if __name__=='__main__':main()
