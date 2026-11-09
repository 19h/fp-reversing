#!/usr/bin/env python3
"""Original address-derived state word and aligned word-rotation reduction.

Original source/fixups and local full-domain proofs only. O(B+F+R) time/space;
each SMT obligation has a separate30s timeout. No native target/API operation.
"""
import json
from pathlib import Path
import subprocess
from adid_reader import Adid,ROOT,CS,sha,THIN_SHA
from probe_adid_startup import unpack_records
from adid_state_codec import MULTIPLIER,XOR_WORD,SWAP_MULTIPLIER


def main():
    s=Adid();p=json.loads((ROOT/'adid_state_producer_profiles.json').read_text());old=json.loads((ROOT/'adid_context_gate_contracts.json').read_text())
    queries={
      'adid_state_producer_key32.smt2':'''(declare-fun p () (_ BitVec 64))
(define-fun key () (_ BitVec 32) (bvxor (bvmul ((_ extract 31 0) p) #xb15198a9) #x2a379458))
(define-fun low () (_ BitVec 8) (bvxor (bvmul ((_ extract 7 0) p) #xa9) #x58))
(assert (or (distinct ((_ extract 7 0) key) low) (and (= (bvand p #x0000000000000007) #x0000000000000000) (distinct (bvand key #x00000007) #x00000000))))''',
      'adid_state_producer_swap_index.smt2':'''(declare-fun k () (_ BitVec 32))
(declare-fun i () (_ BitVec 32))
(assert (and (bvuge i #x00000001) (bvule i #x00000007)))
(assert (= (bvand k #x00000007) #x00000000))
(define-fun v () (_ BitVec 32) (bvmul (bvxor (bvadd k i) k) #x01000193))
(define-fun j () (_ BitVec 32) (bvsub v (bvmul (bvudiv v i) i)))
(assert (or (distinct (bvxor (bvadd k i) k) i) (distinct j #x00000000)))''',
      'adid_state_producer_xor_swap64.smt2':'''(declare-fun a () (_ BitVec 64))
(declare-fun b () (_ BitVec 64))
(define-fun b1 () (_ BitVec 64) (bvxor a b))
(define-fun a1 () (_ BitVec 64) (bvxor a b1))
(define-fun b2 () (_ BitVec 64) (bvxor b1 a1))
(assert (or (distinct a1 b) (distinct b2 a)))'''}
    declarations='\n'.join('(declare-fun w'+str(i)+' () (_ BitVec 64))' for i in range(8));words=['w'+str(i) for i in range(8)]
    for i in range(1,8):words[0],words[i]=words[i],words[0]
    target=['w7']+['w'+str(i) for i in range(7)];restored=words[1:]+words[:1]
    assertions=['(distinct '+a+' '+b+')' for a,b in zip(words,target)]+['(distinct '+a+' w'+str(i)+')' for i,a in enumerate(restored)]
    queries['adid_state_producer_rotation64.smt2']=declarations+'\n(assert (or '+' '.join(assertions)+'))'
    proofs=[]
    for name,body in queries.items():
        path=ROOT/name;path.write_text('(set-logic QF_BV)\n(set-option :timeout 30000)\n'+body+'\n(check-sat)\n');run=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);assert run.stdout.strip()=='unsat' and not run.stderr
        proofs.append({'path':name,'sha256':sha(path.read_bytes()),'result':'unsat','scope':'Full stated local BV domains;fixed source constants and aligned address/key prefix as asserted.'})
    windows=[]
    for a,z,role in [(0x100199778,0x1001997d8,'pointer-derived state word and complete eight-word swap loop'),(0x1001997d8,0x100199894,'complete64-byte vector phase')]:
        raw=s.read(a,z-a);windows.append({'start':hex(a),'end':hex(z),'role':role,'bytes':raw.hex(),'sha256':sha(raw),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(raw,a)]})
    observations=[]
    for row in p['profiles']:
        es=unpack_records(row);inputs=next(e for e in es if e['kind']=='original_state_producer_inputs');key=next(e for e in es if e['kind']=='original_state_word');swaps=[e for e in es if e['kind']=='original_state_swap']
        observations.append({'label':row['fixture']['label'],'address':inputs['address'],'source_constants':{k:inputs[k] for k in ('mul_u32','xor_u32','swap_mul_u32')},'state_u32':key['state_u32'],'indices':[e['selected_index_u32'] for e in swaps],
            'analyst_owned_fixture':'codec_address' in row['fixture'],'native_type_or_valid_context_established':False})
    out={'scope':__doc__,'thin_sha256':THIN_SHA,'uuid':s.meta['uuid'],'source_constants':{'mul_u32':MULTIPLIER,'xor_u32':XOR_WORD,'swap_mul_u32':SWAP_MULTIPLIER},'original_windows':windows,'proofs':proofs,
        'prior_byte_proofs':old['proofs'][:2],'observed_prefixes':observations,'general_swap_formula':'j=((((i+k) XOR k)*0x01000193) mod2^32) mod i, i=1..7.',
        'aligned_reduction':'For A AND7=0,k=(low32(A)*0xb15198a9) XOR0x2a379458 has low3bits0;all j=0,eight words rotate right one.',
        'ABI_scope':'One local in-place64-byte transformation;source input pointer comes from frame+0x3fb0 and scalar prefix constants are checked. No complete native object,valid context,IPC or crypto contract.',
        'generator_sha256':sha(Path(__file__).read_bytes()),'dependencies':{n:sha((ROOT/n).read_bytes()) for n in ['adid_reader.py','adid_state_codec.py','probe_adid_state_producers.py','adid_state_producer_profiles.json','adid_context_gate_contracts.json','adid_context_gate_profiles.json','adid_context_profiles.json']},'native_target_executed':False,'full_goal_complete':False}
    (ROOT/'adid_state_producer_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'new_proofs':len(proofs),'prior_byte_proofs':len(out['prior_byte_proofs']),'windows':len(windows),'prefix_observations':len(observations)}))


if __name__=='__main__':main()
