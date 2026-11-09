#!/usr/bin/env python3
"""Recover original context guard and local reversible byte-transform contracts.

Original bytes/fixups and local SMT only; no native target/loader/API operation.
O(B+F+R) time/space;each SMT obligation has a30s timeout.
"""
import json
from pathlib import Path
import struct
import subprocess
from adid_reader import Adid,ROOT,CS,sha,THIN_SHA
from probe_adid_startup import unpack_records
from probe_adid_context_gates import BLOCK


def main():
    s=Adid();p=json.loads((ROOT/'adid_context_gate_profiles.json').read_text());baseline=p['profiles'][0];events=unpack_records(baseline)
    queries={
    'adid_context_gate_transform32.smt2':'''(declare-fun i () (_ BitVec 32))
(declare-fun k () (_ BitVec 32))
(declare-fun x () (_ BitVec 8))
(define-fun raw () (_ BitVec 32) (bvxor (bvmul ((_ zero_extend 24) x) #x0000009b) (bvmul (bvadd i k) (bvsub i k)) k))
(define-fun ib () (_ BitVec 8) ((_ extract 7 0) i))
(define-fun kb () (_ BitVec 8) ((_ extract 7 0) k))
(define-fun reduced () (_ BitVec 8) (bvxor (bvmul x #x9b) (bvsub (bvmul ib ib) (bvmul kb kb)) kb))
(assert (distinct ((_ extract 7 0) raw) reduced))''',
    'adid_context_gate_inverse8.smt2':'''(declare-fun x () (_ BitVec 8))
(declare-fun i () (_ BitVec 8))
(declare-fun k () (_ BitVec 8))
(define-fun term () (_ BitVec 8) (bvxor (bvsub (bvmul i i) (bvmul k k)) k))
(define-fun y () (_ BitVec 8) (bvxor (bvmul x #x9b) term))
(define-fun decoded () (_ BitVec 8) (bvmul (bvxor y term) #x93))
(assert (distinct decoded x))''',
    'adid_context_gate_branches.smt2':'''(declare-fun tag () (_ BitVec 32))
(declare-fun ptr () (_ BitVec 64))
(define-fun state () (_ BitVec 32) #x00000d5b)
(define-fun v6 () (_ BitVec 32) (bvsub state #x0000075a))
(define-fun v1 () (_ BitVec 32) (bvor (bvsub state #x00000afa) #x00001018))
(define-fun expected () (_ BitVec 32) (bvadd #x16e4d129 v6 #x00000da9))
(define-fun tagindex () (_ BitVec 32) (bvxor (bvadd state #x0000167f) (bvmul (ite (= tag expected) #x00000001 #x00000000) (bvxor v1 #x0000125b))))
(define-fun p9 () (_ BitVec 32) (bvsub state #x00000453))
(define-fun p10 () (_ BitVec 32) (bvsub state #x000004a7))
(define-fun pindex () (_ BitVec 32) (bvxor p10 (bvmul (bvand #x00000001 (bvnot (bvxor p9 (ite (= ptr #x6fac17cb61e34e69) #x00000001 #x00000000)))) (bvsub state #x00000cff))))
(assert (or (distinct expected #x16e4e4d3) (distinct tagindex (ite (= tag #x16e4e4d3) #x000023f8 #x000023da)) (distinct pindex (ite (= ptr #x6fac17cb61e34e69) #x000008b4 #x000008e8))))''',
    'adid_context_gate_pointer64.smt2':'''(declare-fun p () (_ BitVec 64))
(define-fun a () (_ BitVec 64) (bvadd p #x58ce03d8d8c95487))
(define-fun b () (_ BitVec 64) (bvadd p #x6fac17cb61e34e69))
(assert (or (distinct (bvadd a #xa731fc272736ab79) p) (distinct (bvadd b #x9053e8349e1cb197) p) (distinct (bvadd b #x9053e8349e1cb19f) (bvadd p #x0000000000000008))))'''}
    proofs=[]
    for name,body in queries.items():
        path=ROOT/name;path.write_text('(set-logic QF_BV)\n(set-option :timeout 30000)\n'+body+'\n(check-sat)\n');run=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);assert run.stdout.strip()=='unsat' and not run.stderr
        proofs.append({'path':name,'sha256':sha(path.read_bytes()),'result':'unsat','scope':'Full stated local BV domains;guard proof fixes original state0xd5b;not full/native protocol proof.'})
    windows=[]
    for a,z,role in [(0x10019bdb4,0x10019be18,'tag comparison and error branch'),(0x10019e484,0x10019e4fc,'pointer24 comparison and branch'),
        (0x10019e5f0,0x10019e608,'pointer24 decode plus8 read'),(0x10019be68,0x10019bf10,'pointer8 compare and decoding'),(0x10019c1b0,0x10019c1c8,'later pointer read'),
        (0x1001997d8,0x100199894,'complete vector loop prefix/body'),(0x10019c098,0x10019c0cc,'final status store'),(0x10019e6a4,0x10019e6f0,'earlier status store')]:
        raw=s.read(a,z-a);windows.append({'start':hex(a),'end':hex(z),'role':role,'bytes':raw.hex(),'sha256':sha(raw),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(raw,a)]})
    table=0x1002c40c0;branches=[]
    for index in (0x23f8,0x23da,0x8b4,0x8e8):branches.append({'index':index,'pointer':s.decoded[table+index*8]})
    literals=[{'address':hex(a),'bytes16':s.read(a,16).hex()} for a in (0x1002ae070,0x1002ae080,0x1002ae090,0x1002ae0a0,0x1002ae0f0)]
    vectors=[e for e in events if e['kind']=='original_context_table_vector'];loads=[e for e in events if e['kind']=='original_context_gate_load']
    out={'scope':__doc__,'thin_sha256':THIN_SHA,'uuid':s.meta['uuid'],'proofs':proofs,'original_windows':windows,'branch_table_base':hex(table),'guard_branches':branches,'vector_literals':literals,
        'baseline_vector_chunks':vectors,'baseline_gate_loads':loads,'observed_block_address':hex(BLOCK),'observed_transform_extent_bytes':64,'original_image_bytes64':s.read(BLOCK,64).hex(),
        'compact_transform':'y[i]=(155*x[i]) XOR ((i*i-k*k) XOR k),all per-byte modulo256;inverse x[i]=147*(y[i] XOR ((i*i-k*k) XOR k)) modulo256.',
        'scope_boundary':'One original local state transformation and guarded accesses;64-byte observation does not establish a complete native object type,cryptographic algorithm or valid native context.',
        'generator_sha256':sha(Path(__file__).read_bytes()),'dependencies':{n:sha((ROOT/n).read_bytes()) for n in ['adid_reader.py','probe_adid_context_gates.py','adid_context_gate_profiles.json','adid_context_profiles.json','adid_driver_dispatch_frame.json']},'native_target_executed':False,'full_goal_complete':False}
    (ROOT/'adid_context_gate_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'proofs':len(proofs),'windows':len(windows),'guard_branches':len(branches),'vector_chunks':len(vectors),'literal_vectors':len(literals)}))


if __name__=='__main__':main()
