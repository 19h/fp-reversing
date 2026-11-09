#!/usr/bin/env python3
"""Source-pinned ADID collection lookup/update contracts and local BV proofs.

O(B+F+R+V) time/space; each SMT query has a 30 s timeout. Local arithmetic
proofs require their stated source constants; no native object or IPC claim.
"""
import json
from pathlib import Path
import subprocess
from adid_reader import Adid,ROOT,CS,sha,THIN_SHA
from probe_adid_startup import unpack_records


def main():
    s=Adid();p=json.loads((ROOT/'adid_context_lookup_profiles.json').read_text());prior=json.loads((ROOT/'adid_context_contracts.json').read_text())
    queries={
      'adid_context_lookup_count32.smt2':'''(declare-fun n () (_ BitVec 32))
(define-fun tag () (_ BitVec 32) (bvadd n #x16e4e4d3))
(define-fun w1 () (_ BitVec 32) (bvor (bvsub #x00000d5b #x00000afa) #x00001018))
(define-fun w5 () (_ BitVec 32) (bvxor #x0000388a (bvshl w1 #x00000001)))
(define-fun w4 () (_ BitVec 32) (bvor (bvsub w5 #x000013d8) #x0000030e))
(define-fun origin () (_ BitVec 32) (bvxor w4 (bvadd #xb1e4c5a4 #x00000866)))
(define-fun end () (_ BitVec 32) (bvadd tag #x9affe0d1))
(define-fun loop5 () (_ BitVec 32) (bvadd w4 #x00000f9b))
(define-fun loop6 () (_ BitVec 32) (bvmul (bvxor w4 #x00000b9b) #x0000001d))
(define-fun first_lhs () (_ BitVec 32) (bvadd tag #xe91affe2 loop5))
(define-fun first_rhs () (_ BitVec 32) (bvxor loop6 #xfffff9ff))
(assert (or (distinct w4 #x00000bae) (distinct origin #xb1e4c5a4)
 (distinct end (bvadd origin n)) (distinct first_lhs (bvsub n #x00000002))
 (distinct first_rhs #xfffffffe) (distinct (= tag #x16e4e4d3) (= n #x00000000))
 (distinct (bvuge first_lhs first_rhs) (bvule n #x00000001))))''',
      'adid_context_lookup_cursor32.smt2':'''(declare-fun i () (_ BitVec 32))
(define-fun cursor () (_ BitVec 32) (bvadd #x17a54c85 i))
(define-fun loop5 () (_ BitVec 32) (bvand (bvadd #x00000bae #xeeb88fab) #x11477fef))
(define-fun next () (_ BitVec 32) (bvadd (bvxor loop5 #x00001b48) cursor))
(define-fun current () (_ BitVec 32) (bvadd cursor #x9a3f7920))
(define-fun index () (_ BitVec 32) (bvadd (bvsub loop5 #x00000f9b) cursor #xe85aa7cd))
(assert (or (distinct loop5 #x00001b49) (distinct next (bvadd cursor #x00000001))
 (distinct current (bvadd #xb1e4c5a4 i #x00000001)) (distinct index i)))''',
      'adid_context_lookup_circular32.smt2':'''(declare-fun origin () (_ BitVec 32))
(declare-fun end () (_ BitVec 32))
(declare-fun cur () (_ BitVec 32))
(define-fun wrap_end () Bool (bvult end origin))
(define-fun wrap_cur () Bool (bvult cur origin))
(define-fun proceed () Bool (ite (distinct wrap_end wrap_cur) wrap_end (bvult cur end)))
(assert (distinct proceed (bvult (bvsub cur origin) (bvsub end origin))))''',
      'adid_context_lookup_pointers64.smt2':'''(declare-fun p () (_ BitVec 64))
(declare-fun o () (_ BitVec 64))
(declare-fun q () (_ BitVec 64))
(declare-fun i () (_ BitVec 32))
(define-fun a () (_ BitVec 64) (bvadd p #x58ce03d8d8c95487))
(define-fun h () (_ BitVec 64) (bvadd o #x2d1ade42073e28af))
(define-fun r () (_ BitVec 64) (bvadd q #x6fac17cb61e34e69))
(define-fun stride () (_ BitVec 64) (bvshl ((_ zero_extend 32) i) #x0000000000000004))
(assert (or
 (distinct (bvadd a stride #xa731fc272736ab81) (bvadd p stride #x0000000000000008))
 (distinct (= (bvadd a stride #x5ffc55efdda2115e) #xb8ca59c8b66b65e5) (= (bvadd p stride) #x0000000000000000))
 (distinct (bvadd h #xd2e521bdf8c1d751) o)
 (distinct (= (bvadd h #x0407769533fd540f) #x312254d73b3b7cbe) (= o #x0000000000000000))
 (distinct (= (bvadd r #x16e7f8c11e983058) #x8694108c807b7ec1) (= q #x0000000000000000))
 (distinct (bvadd r #x9053e8349e1cb19f) (bvadd q #x0000000000000008))
 (distinct (bvadd r #x9053e8349e1cb22f) (bvadd q #x0000000000000098))
 (distinct (bvadd r #x9053e8349e1cb237) (bvadd q #x00000000000000a0))))''',
      'adid_context_lookup_fields.smt2':'''(declare-fun request_key () (_ BitVec 64))
(declare-fun stored_key () (_ BitVec 64))
(declare-fun request_value () (_ BitVec 64))
(declare-fun euid () (_ BitVec 32))
(declare-fun stored_uid () (_ BitVec 32))
(define-fun key_match () Bool (= (bvxor stored_key #xda8ca8cae5dfbd2d) (bvxor request_key #xda8ca8cae5dfbd2d)))
(define-fun uid_match () Bool (= (bvadd stored_uid #x0046d726) (bvadd euid #x0046d726)))
(assert (or (distinct (and key_match uid_match) (and (= stored_key request_key) (= stored_uid euid)))
 (distinct (bvxor (bvxor request_value #xda8ca8cae5dfbd2d) #xda8ca8cae5dfbd2d) request_value)))'''}
    proofs=[]
    for name,body in queries.items():
        path=ROOT/name;path.write_text('(set-logic QF_BV)\n(set-option :timeout 30000)\n'+body+'\n(check-sat)\n');run=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);assert run.stdout.strip()=='unsat' and not run.stderr,(name,run.stdout,run.stderr)
        proofs.append({'path':name,'sha256':sha(path.read_bytes()),'result':'unsat','scope':'Full declared local BV domains with fixed source constants; memory validity and native reachability excluded.'})
    windows=[]
    for a,z,role in [(0x10019bdb4,0x10019c328,'complete inspected collection count, array scan, key/EUID match and update region'),(0x10021ac1c,0x10021ac3c,'encoded value load and frame-slot producer'),(0x1001af140,0x1001af178,'original BE64 reader/fold'),(0x10019cfbc,0x10019cfe4,'encoded result slot load'),(0x10021b8cc,0x10021b938,'encoded payload status fold')]:
        raw=s.read(a,z-a);windows.append({'start':hex(a),'end':hex(z),'role':role,'bytes':raw.hex(),'sha256':sha(raw),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(raw,a)]})
    cells={};summaries=[]
    for row in p['profiles']:
        es=unpack_records(row)
        for e in es:
            if e['kind']=='original_lookup_pointer_cell':cells[e['cell']]=s.decoded[int(e['cell'],16)]
        summaries.append({'label':row['fixture']['label'],'prepared':row['lookup_prepared'],'array_reads':[r['offset_bytes'] for r in row['lookup_reads'] if r['region']=='array'],'writes':row['lookup_writes'],
            'reply_payloads':[e['payload_bytes'] for e in es if e.get('name')=='_xpc_dictionary_set_data'],'core_returns':[e for e in es if e['kind']=='original_core_record_return'],
            'IOKit_calls':[e for e in es if e.get('name','').startswith('_IO')],'stop_reason':row['stop_reason']})
    out={'scope':__doc__,'thin_sha256':THIN_SHA,'uuid':s.meta['uuid'],'original_windows':windows,'proofs':proofs,'prior_request_proofs':[r for r in prior['proofs'] if r['path'] in ['adid_context_argument64.smt2','adid_context_header32.smt2','adid_context_status32.smt2']],
        'original_pointer_cells':list(cells.values()),'case_summaries':summaries,
        'local_contract':'N=u32(view[0]-0x16e4e4d3); array=u64(view[8]-0x58ce03d8d8c95487); entry stride16, holder pointer at+8 minus0x2d1ade42073e28af; nested pointer holder[0] minus0x6fac17cb61e34e69. First matching nested[8] key XOR and nested[0xa0] EUID+bias receives second-request-field XOR at nested+0x98.',
        'scope_boundary':'Owned readable arrays/objects under frozen full-callback API/PAC models. Native object types, producers, credentials, IPC rights and protected IOKit transaction remain unknown.',
        'generator_sha256':sha(Path(__file__).read_bytes()),'dependencies':{n:sha((ROOT/n).read_bytes()) for n in ['adid_reader.py','adid_state_codec.py','probe_adid_context_lookup.py','adid_context_lookup_profiles.json','adid_context_contracts.json']},'native_target_executed':False,'full_goal_complete':False}
    (ROOT/'adid_context_lookup_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'new_proofs':len(proofs),'prior_request_proofs':len(out['prior_request_proofs']),'windows':len(windows),'pointer_cells':len(cells),'cases':len(summaries)}))


if __name__=='__main__':main()
