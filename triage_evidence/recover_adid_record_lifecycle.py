#!/usr/bin/env python3
"""Whole-text literal-family inventory and source-pinned local record proofs.

Literal scan completeness is limited to consecutive MOV-wide construction;
matching bias does not prove native object aliasing. O(B+F+R) time/space;
each local SMT query has a 30 s timeout. No native target/API.
"""
import json
from pathlib import Path
import struct
import subprocess
from adid_reader import Adid,ROOT,CS,sha,THIN_SHA


def scan(s):
    sec=next(x for x in s.meta['sections'] if x['section']=='__text');raw=s.read(sec['address'],sec['size']);regs={};hits=[]
    for j,(w,) in enumerate(struct.iter_unpack('<I',raw)):
        pc=sec['address']+j*4;op=w&0xff800000;reg=w&31
        if op not in (0xd2800000,0x92800000,0xf2800000):regs={};continue
        imm=(w>>5)&65535;shift=((w>>21)&3)*16
        if op==0xd2800000:regs[reg]=(imm<<shift,[pc])
        elif op==0x92800000:regs[reg]=((~(imm<<shift))&((1<<64)-1),[pc])
        elif reg in regs:
            value,pcs=regs[reg];regs[reg]=((value&~(65535<<shift))|(imm<<shift),pcs+[pc])
        if reg not in regs:continue
        value,pcs=regs[reg]
        if len(pcs)==4 and value>>32 in [0x9053e834,0xd2e521bd,0xa731fc27,0x6fac17cb,0x2d1ade42,0x58ce03d8]:hits.append({'start':hex(pcs[0]),'end':hex(pc+4),'register':'x'+str(reg),'value_u64':hex(value),'member_pcs':[hex(x) for x in pcs],'member_bytes':[s.read(x,4).hex() for x in pcs]})
    return {'start':hex(sec['address']),'size_bytes':len(raw),'sha256':sha(raw),'four_byte_units':len(raw)//4,'literal_hits':hits}


def main():
    s=Adid();inventory=scan(s)
    queries={
      'adid_record_constructor_state32.smt2':'''(declare-fun status () (_ BitVec 32))
(define-fun state () (_ BitVec 32) (bvmul (bvxor #x00000d5b #x00000d6e) #x00000095))
(define-fun mask () (_ BitVec 32) (bvor (bvsub state #x00000ed8) #x000004c8))
(define-fun want () (_ BitVec 32) (bvxor (bvadd #x00592ea1 #x000001a5) mask))
(define-fun index () (_ BitVec 32) (bvxor (bvadd #x00000d5b #x00000593) (ite (= status want) #x00000f93 #x00000000)))
(assert (or (distinct state #x00001ed9) (distinct want #x0059248f)
 (distinct (= index #x00001d7d) (= status #x0059248f))))''',
      'adid_record_constructor_tag64.smt2':'''(declare-fun key () (_ BitVec 64))
(define-fun e () (_ BitVec 64) (bvxor key #xda8ca8cae5dfbd2d))
(define-fun a () (_ BitVec 64) (bvxor (bvadd #x0000000000000d5b #x2513463d122640c7) e))
(define-fun b () (_ BitVec 64) (bvxor (bvand (bvshl e #x0000000000000001) #xff3fddefeff3e61e) #xb5195185cbb3621a))
(define-fun t () (_ BitVec 64) (bvadd a b))
(define-fun decoded () (_ BitVec 64) (bvadd t #x0060110808060cf1))
(define-fun tag () (_ BitVec 32) (ite (bvult decoded #xfffffffffffffff0) #x61aec520 (ite (= t #xff9feef7f7f9f30e) #x61aec521 #x61aec522)))
(define-fun compact () (_ BitVec 32) (ite (= key #xffffffffffffffff) #x61aec521 (ite (bvuge key #xfffffffffffffff0) #x61aec522 #x61aec520)))
(assert (or (distinct decoded key) (distinct tag compact)))''',
      'adid_record_allocation_normalize64.smt2':'''(declare-fun n () (_ BitVec 64))
(define-fun accepted () Bool (bvule n #xffffffffffffff7f))
(define-fun source () (_ BitVec 64) (ite (bvule n #x00000000000000e0)
 (ite (bvult n #x000000000000000f) #x0000000000000020 (bvand (bvadd n #x000000000000001f) #x00000000000001f0))
 (ite accepted (bvand (bvadd n #x000000000000001f) #xfffffffffffffff0) #xffffffffffffffff)))
(define-fun rounded () (_ BitVec 64) (bvand (bvadd n #x000000000000001f) #xfffffffffffffff0))
(define-fun compact () (_ BitVec 64) (ite accepted (ite (bvult rounded #x0000000000000020) #x0000000000000020 rounded) #xffffffffffffffff))
(assert (or (distinct source compact) (and accepted (or (distinct (bvand source #x000000000000000f) #x0000000000000000) (bvult source (bvadd n #x0000000000000010))))))''',
      'adid_record_mapping_roundup64.smt2':'''(declare-fun n () (_ BitVec 64))
(declare-fun p () (_ BitVec 64))
(assert (and (distinct p #x0000000000000000) (= (bvand p (bvsub p #x0000000000000001)) #x0000000000000000)))
(assert (bvule p #x7fffffffffffffff))
(assert (bvule n (bvsub (bvsub #xffffffffffffffff p) #x000000000000005f)))
(define-fun first () (_ BitVec 64) (bvand (bvadd n p #x000000000000003e) (bvneg p)))
(define-fun second () (_ BitVec 64) (bvand (bvadd n p #x000000000000005f) (bvneg p)))
(assert (or (bvult first (bvadd n #x000000000000003f)) (bvuge (bvsub first (bvadd n #x000000000000003f)) p)
 (bvult second (bvadd n #x0000000000000060)) (bvuge (bvsub second (bvadd n #x0000000000000060)) p)
 (distinct (bvand first (bvsub p #x0000000000000001)) #x0000000000000000)
 (distinct (bvand second (bvsub p #x0000000000000001)) #x0000000000000000)))'''}
    # Faithful byte-width reductions of all eight stores in the original encoder.
    body=['(declare-fun value () (_ BitVec 64))','(define-fun stored () (_ BitVec 64) (bvxor value #xda8ca8cae5dfbd2d))']
    for i in range(8):body.append(f'(define-fun b{i} () (_ BitVec 32) ((_ zero_extend 24) ((_ extract {63-8*i} {56-8*i}) stored)))')
    t={0:'(bvxor b0 #x000018da)',1:'(bvxor b1 #x0000008c)',2:'(bvxor b2 #xffffffa8)',3:'(bvxor b3 #xffffffca)',4:'(bvxor b4 #xffffffe5)',5:'(bvxor b5 #xffffffdf)',6:'(bvxor b6 #xffffffbd)'}
    expected=[]
    for i in range(8):
        if i==7:expression='(bvxor b7 #x0000005e)'
        elif i==1:expression=f'(bvadd (bvsub {t[i]} (bvand (bvshl b1 #x00000001) #xffffffe7)) #x00000073)'
        elif i==2:expression=f'(bvadd (bvsub {t[i]} (bvshl (bvxor (bvand {t[i]} #xfffffff7) (bvand b2 #x00000004)) #x00000001)) #x00000073)'
        else:expression=f'(bvadd (bvsub {t[i]} (bvand (bvshl {t[i]} #x00000001) #xffffffe7)) #x00000073)'
        body.append(f'(define-fun out{i} () (_ BitVec 8) ((_ extract 7 0) {expression}))');expected.append(f'(distinct out{i} (bvxor ((_ extract {63-8*i} {56-8*i}) value) #x73))')
    queries['adid_record_field_encode64.smt2']='\n'.join(body)+'\n(assert (or '+' '.join(expected)+'))'
    body=[];terms=[];clean=[]
    for i in range(8):
        body.append(f'(declare-fun b{i} () (_ BitVec 8))');sub=f'(bvsub ((_ zero_extend 56) b{i}) #x0000000000000019)';v=sub if i==0 else f'(bvand {sub} #x00000000000000ff)';terms.append(f'(bvshl {v} #x{56-8*i:016x})');clean.append(f'(bvsub b{i} #x19)')
    assembled=terms[0]
    for t in terms[1:]:assembled=f'(bvadd {assembled} {t})'
    concatenated=clean[0]
    for t in clean[1:]:concatenated=f'(concat {concatenated} {t})'
    fold=f'(bvsub (bvadd {assembled} #xda8ca8cae5dfbd2d) (bvand (bvshl {assembled} #x0000000000000001) #xb5195195cbbf7a5a))'
    queries['adid_record_field_decode64.smt2']='\n'.join(body)+f'\n(assert (distinct {fold} (bvxor {concatenated} #xda8ca8cae5dfbd2d)))'
    proofs=[]
    for name,body in queries.items():
        path=ROOT/name;path.write_text('(set-logic QF_BV)\n(set-option :timeout 30000)\n'+body+'\n(check-sat)\n');run=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);assert run.stdout.strip()=='unsat' and not run.stderr,(name,run.stdout,run.stderr)
        proofs.append({'path':name,'sha256':sha(path.read_bytes()),'result':'unsat','scope':'Full declared local BV domains, fixed source constants; mapping proof requires positive power-of-two alignment and explicit non-overflow bound.'})
    windows=[]
    for a,z,role in [(0x10019c578,0x10019cb24,'constructor gate, allocation requests, complete initialized fields'),(0x10012004c,0x1001201b4,'local field serializer and presence branch'),(0x10013f86c,0x10013f99c,'local field parser and presence branch'),(0x10019f634,0x10019f678,'additional protected value read/copy'),(0x10019fa9c,0x10019fae4,'additional protected value write'),(0x1002674a0,0x10026757c,'allocation request normalization'),(0x100267a60,0x100267b20,'direct-map sizing and mmap'),(0x100267c0c,0x100267cbc,'arena-map sizing and mmap')]:
        raw=s.read(a,z-a);windows.append({'start':hex(a),'end':hex(z),'role':role,'bytes':raw.hex(),'sha256':sha(raw),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(raw,a)]})
    functions=[s.function(a) for a in [0x1000621d4,0x1002698cc,0x100267044]]
    field_sites=[{'literal_start':h['start'],'member_pcs':h['member_pcs']} for h in inventory['literal_hits'] if h['value_u64']=='0x9053e8349e1cb22f']
    out={'scope':__doc__,'thin_sha256':THIN_SHA,'uuid':s.meta['uuid'],'whole_text_literal_inventory':inventory,'direct_field98_literal_sites':field_sites,'original_windows':windows,'allocation_functions':functions,'proofs':proofs,
        'generator_sha256':sha(Path(__file__).read_bytes()),'dependencies':{n:sha((ROOT/n).read_bytes()) for n in ['adid_reader.py','probe_adid_record_lifecycle.py','adid_record_lifecycle_profiles.json','adid_driver_dispatch_frame.json']},'native_target_executed':False,'full_goal_complete':False}
    (ROOT/'adid_record_lifecycle_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'literal_hits':len(inventory['literal_hits']),'field98_sites':len(field_sites),'proofs':len(proofs),'windows':len(windows),'allocation_functions':len(functions)}))


if __name__=='__main__':main()
