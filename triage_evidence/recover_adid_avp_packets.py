#!/usr/bin/env python3
"""Recover local typed-record and representation codecs from original ADID.

Full bit-width arithmetic proofs are local contracts with stated register/cursor
assumptions; not native packet admission. O(B+F+P+R) time/space excluding
solver internals; each of six queries has a 30 s timeout. No native target.
"""
import json
from pathlib import Path
import struct
import subprocess
from adid_reader import Adid,ROOT,CS,sha,THIN_SHA
from probe_adid_startup import unpack_records


def records(raw):
    out=[];cursor=0
    while cursor<len(raw):
        if len(raw)-cursor<10:raise ValueError('incomplete ten-byte header')
        key,tag,n=struct.unpack_from('>IHI',raw,cursor);end=cursor+10+n
        if end>len(raw):raise ValueError('payload outside retained buffer')
        if tag not in (0x9777,0x8485,0x50db):raise ValueError('unrecognized local tag')
        if tag==0x9777 and n!=4 or tag==0x8485 and n!=8:raise ValueError('scalar extent mismatch')
        out.append({'offset_bytes':cursor,'raw_key_u32':key,'tag_u16':tag,'payload_size_bytes':n,'payload_hex':raw[cursor+10:end].hex()});cursor=end
    return out


def main():
    s=Adid();queries={
      'adid_avp_packet_byte8.smt2':'''(declare-fun b () (_ BitVec 8))
(define-fun incoming () (_ BitVec 8)
 (bvsub (bvsub b (bvand #xd0 (bvshl b #x01))) #x18))
(define-fun reverse () (_ BitVec 8)
 (bvsub (bvadd b (bvor #x2f (bvnot (bvshl b #x01)))) #x17))
(assert (or (distinct incoming (bvxor b #xe8))
 (distinct reverse (bvxor b #xe8))
 (distinct (bvxor incoming #xe8) b)))''',
      'adid_avp_packet_word32.smt2':'''(declare-fun raw () (_ BitVec 32))
(define-fun k () (_ BitVec 32) #xcf5ff7fe)
(define-fun pair () (_ BitVec 32) (bvadd (bvxor raw k) (bvand #x9ebfeffc (bvshl raw #x00000001))))
(define-fun plain_length () (_ BitVec 32) (bvadd pair #x30a00802))
(define-fun scalar () (_ BitVec 32) (bvadd pair #x30e6df28))
(define-fun key_prefix () (_ BitVec 32) (bvxor #x00000d5b (bvadd k #x000002a7)))
(define-fun key () (_ BitVec 32) (bvadd (bvadd (bvxor key_prefix raw) #x30e6df28) (bvand #x9ebfeffc (bvshl raw #x00000001))))
(assert (or (distinct plain_length raw)
 (distinct scalar (bvadd raw #x0046d726))
 (distinct key (bvadd raw #x0046d726))))''',
      'adid_avp_packet_tag16.smt2':'''(declare-fun tag () (_ BitVec 16))
(define-fun normalized () (_ BitVec 16)
 (bvadd (bvsub tag (bvand #xb48e (bvshl tag #x0001))) #x5a57))
(define-fun selected () Bool (or (= normalized #x0aac) (= normalized #xded2) (= normalized #xcd40)))
(assert (or (distinct normalized (bvadd (bvxor tag #x5a47) #x0010))
 (distinct selected (or (= tag #x50db) (= tag #x8485) (= tag #x9777)))))''',
      'adid_avp_packet_scalar64.smt2':'''(declare-fun raw () (_ BitVec 64))
(define-fun decoded () (_ BitVec 64)
 (bvsub (bvadd raw #xf048dd51c8511450) (bvand #xe091baa390a228a0 (bvshl raw #x0000000000000001))))
(assert (distinct decoded (bvxor raw #xf048dd51c8511450)))''',
      'adid_avp_packet_extent64.smt2':'''(declare-fun offset () (_ BitVec 32))
(declare-fun payload () (_ BitVec 32))
(declare-fun capacity () (_ BitVec 32))
(define-fun off () (_ BitVec 64) ((_ zero_extend 32) offset))
(define-fun n () (_ BitVec 64) ((_ zero_extend 32) payload))
(define-fun cap () (_ BitVec 64) ((_ zero_extend 32) capacity))
(define-fun x9_before () (_ BitVec 64) (bvadd #x366c08f7bb6af577 off))
(define-fun x16 () (_ BitVec 64) (bvadd (bvadd x9_before n) #xc993f70857df5f1b))
(define-fun x10 () (_ BitVec 64) (bvadd cap #x00000000134a5488))
(assert (distinct (bvule x16 x10) (bvule (bvadd (bvadd off n) #x000000000000000a) cap)))''',
      'adid_avp_packet_return_count64.smt2':'''(declare-fun size () (_ BitVec 64))
(define-fun published () (_ BitVec 32) (bvadd ((_ extract 31 0) size) #x0046d726))
(assert (distinct (= published #x0046d7b6) (= ((_ extract 31 0) size) #x00000090)))'''}
    proofs=[]
    for name,query in queries.items():
        path=ROOT/name;path.write_text('(set-logic QF_BV)\n(set-option :timeout 30000)\n'+query+'\n(check-sat)\n');run=subprocess.run(['z3',str(path)],capture_output=True,text=True,check=True);assert run.stdout.strip()=='unsat' and not run.stderr,(name,run.stdout,run.stderr);proofs.append({'path':name,'sha256':sha(path.read_bytes()),'result':'unsat'})
    windows=[]
    for a,z,role in [(0x10024bb64,0x10024bb94,'forward per-byte physical representation'),(0x10024b510,0x10024b540,'reverse per-byte physical representation'),(0x10025fc18,0x10025fc3c,'outgoing XOR/copy store'),(0x10025fd08,0x10025fd28,'reverse-order XOR/copy to parser input'),(0x100260c60,0x100260e64,'BE32 length/key,extent and BE16 tag selection'),(0x100260ed0,0x100260f2c,'BE32 scalar and internal encoding'),(0x100262000,0x1002620a0,'BE64 scalar and local XOR reduction'),(0x100146438,0x100146638,'time and random staging into original local arrays'),(0x1001466a4,0x100146a00,'small allocation initialization/source input staging'),(0x10024e178,0x10024e1fc,'transport status and published32-bit returned-count comparison')]:
        raw=s.read(a,z-a);windows.append({'start':hex(a),'end':hex(z),'role':role,'bytes':raw.hex(),'sha256':sha(raw),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(raw,a)]})
    p=json.loads((ROOT/'adid_command_dispatch_profiles.json').read_text());row=next(r for r in p['profiles'] if r['fixture']['label']=='environment_iokit_opaque');event=next(e for e in unpack_records(row) if e['kind']=='original_method100_boundary');raw=bytes.fromhex(event['input_bytes']);outer=records(raw);nested=records(raw[42:122]);assert len(raw)==144 and len(outer)==4 and len(nested)==5
    out={'scope':__doc__,'thin_sha256':THIN_SHA,'uuid':s.meta['uuid'],'proofs':proofs,'original_windows':windows,'baseline_method100_request':{'source_profile':'environment_iokit_opaque','bytes144':raw.hex(),'outer_records':outer,'nested_records_at42_size80':nested,'complete_accepted_driver_protocol_established':False},'local_contracts':{'physical_byte':'b XOR0xe8','typed_length':'raw BE32,extent guard before body','typed_key_when_control_d5b':'raw BE32+0x46d726 modulo2^32','typed_scalar32':'raw BE32+0x46d726 modulo2^32','typed_scalar64':'raw BE64 XOR0xf048dd51c8511450','tag_normalized16':'(raw BE16 XOR0x5a47)+0x10 modulo2^16','extent_assumption':'x9_before=0x366c08f7bb6af577+zero_extend(offset32);capacity32 and payload32;compares64-bit sums'},'generator_sha256':sha(Path(__file__).read_bytes()),'dependencies':{n:sha((ROOT/n).read_bytes()) for n in ['adid_reader.py','adid_command_dispatch_profiles.json']},'native_target_executed':False,'full_goal_complete':False};(ROOT/'adid_avp_packet_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'new_proofs_unsat':len(proofs),'source_windows':len(windows),'outer_records':len(outer),'nested_records':len(nested)}))


if __name__=='__main__':main()
