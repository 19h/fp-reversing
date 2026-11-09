#!/usr/bin/env python3
"""Source-pinned RPC502 wrapper, protected route, PID predicate and QoS edges.

No daemon execution, IDB mutation or runtime PAC validation. Native-to-formula
translation is manually audited. O(B+F+D) extraction time/space for image bytes,
fixups and retained instructions, plus exhaustive byte-bank and SMT costs.
"""
import hashlib
import json
from pathlib import Path
import subprocess
from capstone import CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET
from capstone.arm64 import ARM64_OP_MEM
from daemon_receive_tools import *


def main():
    spans = [
      (0x1000050c8,0x100005274,'MIG502 request guards and application ABI'),
      (0x100422d48,0x100422f64,'RPC502 entry and first filename byte'),
      (0x10008a958,0x10008a97c,'filename scan loop'),
      (0x1000bcca8,0x1000bccd0,'scan completion'),
      (0x1000238e4,0x100023af8,'argument/control records, dispatch and return'),
      (0x10046f89c,0x10046fa94,'copy helper, including complete aligned32 route'),
      (0x10065ffd8,0x100660254,'protected adapter and scratch protocol'),
      (0x10061a2d0,0x10061a990,'protected core prefix and first dispatcher'),
      (0x1004c244c,0x1004c3638,'shared operation-root setup'),
      (0x100610388,0x1006103d8,'signed tag partition'),
      (0x1005283ac,0x1005283f8,'next signed tag partition'),
      (0x100524a58,0x100524ac0,'RPC502 tag equality'),
      (0x1006126c4,0x10061271c,'argument record guard'),
      (0x1007fc57c,0x1007fc79c,'argument loads, audit copies and PID extraction'),
      (0x100528dd8,0x100528e24,'nonzero-PID early return'),
      (0x1005c18c8,0x1005c19dc,'zero-PID thread and QoS query'),
      (0x100579c6c,0x100579cf0,'successful-query QoS set'),
      (0x1005be85c,0x1005be8c4,'query failure continuation boundary'),
    ]
    native=[]
    CS.detail=True
    for a,z,label in spans:
        raw=IMAGE.read(a,z-a);decoded=list(CS.disasm(raw,a))
        assert sum(i.size for i in decoded)==len(raw)
        native.append({'start':hex(a),'end':hex(z),'label':label,'bytes':raw.hex(),
          'sha256':hashlib.sha256(raw).hexdigest(),
          'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in decoded]})
    # Incoming W2 is not a hidden scan bound: no source instruction reads it
    # before the explicit overwrite with the audit-copy size.
    unused_length_checks=0
    for a,z in [(0x100422d48,0x100422f64),(0x10008a958,0x10008a97c),
                (0x1000bcca8,0x1000bccd0),(0x1000238e4,0x100023930)]:
        for i in CS.disasm(IMAGE.read(a,z-a),a):
            assert not {'x2','w2'} & {i.reg_name(r) for r in i.regs_access()[0]},hex(i.address)
            unused_length_checks+=1
    # Independently refresh source hashes that justified previous shared-core
    # algebra; do not execute or import the old proof scripts.
    prior=[]
    for a,z,want in [
      (0x10065ffd8,0x100660254,'2844d07280ed0a6a4e54e3f1f1207bd3f3b06f2e13145eb2b374d6f90221e302'),
      (0x10061a464,0x10061a990,'21c5d4d2fca54a4532adfc1aecc1ede019deda02cfa96352f71ff76b0bb2a220'),
      (0x1004c24a4,0x1004c3638,'4986b12a14f82fdb87babdaac530f86910deddc9c8b8ab55d02a82e52e552c19'),
      (0x100610388,0x1006103d8,'7d44670170a0f62b58d4eb860efafc7406b49e6d53e56f088adb2fd03cf6aded')]:
        got=hashlib.sha256(IMAGE.read(a,z-a)).hexdigest();assert got==want
        prior.append({'start':hex(a),'end':hex(z),'sha256':got,'matches':True})
    # The long setup fragment preserves the routing words and frame root.
    protected=[(0x928,0x92c),(0x9a0,0x9a4),(0x9b8,0x9bc),(0x9d8,0x9e0),(0x580,0x588)]
    stores=0
    for i in CS.disasm(IMAGE.read(0x1004c24a4,0x1194),0x1004c24a4):
        assert 'sp' not in {i.reg_name(r) for r in i.regs_access()[1]}
        if i.address!=0x1004c3634:
            assert not any(i.group(g) for g in (CS_GRP_JUMP,CS_GRP_CALL,CS_GRP_RET))
        if i.mnemonic.startswith('st'):
            assert i.mnemonic=='str' and i.operands[1].type==ARM64_OP_MEM
            m=i.operands[1].mem;assert i.reg_name(m.base)=='sp' and not m.index and not i.writeback
            reg=i.reg_name(i.operands[0].reg);width=8 if reg.startswith('x') else 4
            if i.address!=0x1004c24bc:
                assert all(m.disp+width<=lo or m.disp>=hi for lo,hi in protected)
            stores+=1
    assert stores==129
    cases=[
      ('wrapper state',0x100e99a00,0x100f4e390,0x78,0x121f,POOL,0xffffffffd48f0c0e,0x1010b7f18),
      ('wrapper state1',0x100e99700,0x100f4e190,0x81,0x4c,POOL,0xffffffffec9e1772,0x1010c4670),
      ('wrapper table',0x100fc4130,0x101031ea0,0xa3,0x8a8,POOL,0xffffffffd0c4d1ee,TABLE),
      ('audit copy',0x100e99700,0x100f4e190,0x81,0xcb6b,TABLE,0,0x10046f89c),
      ('frame extent global',0x100e99a00,0x100f4e390,0x78,0xcea,POOL,0xffffffffc7024c75,0x1010c4d68),
      ('protected adapter',0x100fc4130,0x101031ea0,0xa3,0xcc77,TABLE,0,0x10065ffd8),
      ('adapter state',0x101031da0,0x100e99900,0xa,0xe68,POOL,0xffffffff988c9a86,0x1010b9178),
      ('adapter state1',0x100fc4130,0x101031ea0,0xbb,-0x27,POOL,0xffffffffec9e1772,0x1010c4670),
      ('adapter extent',0x100e99700,0x100f4e190,0x56,0xd77,POOL,0xffffffffc7024c75,0x1010c4d68),
      ('adapter table',0x100fc4130,0x101031ea0,0xbb,0x85f,POOL,0xffffffffd0c4d1ee,TABLE),
      ('protected core',0x100fc4230,0x101031fa0,0x6c,0xce92,TABLE,0,0x10061a2d0),
      ('core table',0x100fc4230,0x101031fa0,0x6c,0x893,POOL,0xffffffffd0c4d1ee,TABLE),
      ('core audit copies',0x100fc4230,0x101031fa0,0x6c,0xcb2c,TABLE,0,0x10046f89c),
      ('extract audit PID',0x100e99a00,0x100f4e390,0x9c,0xcc94,TABLE,0,'libbsm/_audit_token_to_au32'),
      ('current pthread',0x100fc4230,0x101031fa0,0x6c,0xcdcc,TABLE,0,'libSystem/_pthread_self'),
      ('query QoS',0x100fc4130,0x101031ea0,0xbb,0xcd2d,TABLE,0,'libSystem/_pthread_get_qos_class_np'),
      ('set QoS',0x101031da0,0x100e99900,0x9a,0xcd59,TABLE,0,'libSystem/_pthread_set_qos_class_self_np'),
    ]
    banks=[]
    for label,l,r,key,a,base,bias,want in cases:
        rec=selected(l,r,key,a,base,bias)
        assert rec['target']==(hex(want) if isinstance(want,int) else want),(label,rec)
        rec['label']=label;banks.append(rec)
    branches={0x232f:0x10008a958,0x2372:0x1000238e4,0xa14f:0x1000bcca8,
      0x6cf4:0x1004c244c,0x8061:0x100610388,0xb31b:0x1005283ac,
      0x6567:0x100524a58,0x6295:0x1006126c4,0xbe65:0x1007fc57c,
      0x5bcc:0x1005c18c8,0x28fc:0x100528dd8,0xca27:0x100579c6c,0x6ac2:0x1005be85c}
    for ix,t in branches.items():assert qword(TABLE+8*ix)==t
    mask=0xffffffff
    assert ((0x2372+0xf5fcc52d)&mask)&0x35ed177d==0x35ec001d
    assert (0x35ec001d+0xca146cd7)&mask==0x6cf4
    assert 0xbc84919b-(1<<32) > 0xad952088-(1<<32)
    assert 0xbc84919b-(1<<32) < 0xd5525452-(1<<32)
    assert (3*(0xb2f3^0x933e))&mask==0x6567
    assert 0x6567^0xbc84f4fc==0xbc84919b
    assert ((0x6567+0xc7a57a18)&mask)&0x385a7edd==0x5e5d
    assert ((0x5e5d+0x14430f97)&mask)&0x6bbcfeff==0x6cf4
    assert 0x5e5d^(0x6cf4-0x302c)==0x6295
    assert 0x6cf4+0x5171==0xbe65
    assert (((0xbe65+0xc3a44199)&mask)^0xc3a4fffe)==0
    assert (0x6cf4^0x636)==0x6ac2
    assert (((0x6ac2+0x5fe8943a)&mask)&0xa0176df7)==0x6cf4
    assert 0x6ac2^((0x6ac2+0x614f)^0x6cf4)==0xca27
    assert 0x74c29dee^0x8b3dc651==0xffff5bbf

    queries={
      'core_pointer_fold': '''(declare-fun x () (_ BitVec 64))
(assert (not (= (bvxor (bvadd (bvsub (bvor x #x39048b9ddf8693f2)
 (bvor x #xc6fb746220796c0d)) #xc6fb746220796c0d) #x839101713528993b)
 (bvxor x #xba958aeceaae0ac9))))''',
      'rpc502_tag': '''(declare-fun x () (_ BitVec 32))
(define-fun p () (_ BitVec 32) (bvmul (bvxor x #xeaae0ac9) #x7398180b))
(assert (or (not (= (bvxor (bvxor p #x00006cf4) p) #x00006cf4))
 (not (= (bvxor (bvxor p #xbc84919b) p) #xbc84919b))))''',
      'pid_gate': '''(declare-fun pid () (_ BitVec 32))
(define-fun b () (_ BitVec 32)
 (bvlshr (bvnot (bvor (bvsub pid #x00000000) (bvsub #x00000000 pid))) #x0000001f))
(define-fun ix () (_ BitVec 32) (bvxor #x000028fc (bvmul b #x00007330)))
(assert (not (= ix (ite (= pid #x00000000) #x00005bcc #x000028fc))))''',
      'scratch_restore': '''(declare-fun s () (_ BitVec 64))
(define-fun restored () (_ BitVec 64) (bvadd (bvsub s #x00000000000000e0) #x00000000000000e0))
(define-fun adjustment () (_ BitVec 32)
 (bvshl (bvand (bvsub ((_ extract 31 0) restored) ((_ extract 31 0) s)) #x0000ffff) #x00000004))
(assert (not (= adjustment #x00000000)))''',
    }
    proofs=[]
    for name,body in queries.items():
        p=ROOT/f'rpc502_{name}.smt2';p.write_text('(set-logic QF_BV)\n'+body+'\n(check-sat)\n')
        out=subprocess.run(['z3','-smt2',str(p)],check=True,capture_output=True,text=True).stdout.strip()
        assert out=='unsat',(name,out);proofs.append({'name':name,'path':p.name,'result':out})
    used=[int(x['slot'],16) for x in banks]+[TABLE+8*ix for ix in branches]
    # Include bank-pointer setup words actually reused by the source slices.
    used += [POOL+o for o in (0x6188,0x3030,0x1658,0x26a0,0x29c8,0x4c18,0x60f0,0x2240)]
    fixups=verify_original_fixups(used)
    evidence={'image':str(SOURCE),'sha256':hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
      'native_ranges':native,'prior_source_readback':prior,'setup_stores_checked':stores,
      'bank_proofs':banks,'original_fixup_checks':fixups,'proofs':proofs,
      'branch_slots':[{'index':hex(ix),'slot':hex(TABLE+8*ix),'target':hex(t),'fixup':FIXUPS[TABLE+8*ix]} for ix,t in branches.items()],
      'control_tag':'0xbc84919b','core_first_index':'0x6cf4',
      'pid_output_site':'0x1007fc754','pid_gate_site':'0x1007fc758',
      'nonzero_pid_return_u32':'0xffff5bbf','nonzero_pid_return_signed':-42049,
      'incoming_ool_length_forwarded_in_private_record':False,
      'incoming_length_no_read_instruction_checks':unused_length_checks,
      'audit_copy_bytes':32,'private_record_prefix_bytes':120,
      'unknowns':['installed framework service access/trailer guarantees and native reachability',
        'actual runtime libbsm/PAC behavior','complete downstream context construction and QoS restoration',
        'service-name-dependent policy, file validation and successful output ownership',
        'runtime object/alias identity across the declared protocol'],
      'target_executed':False,'idb_mutated':False,'fresh_daemon_ida_snapshot':False}
    (ROOT/'daemon_rpc502_contracts.json').write_text(json.dumps(evidence,indent=2)+'\n')
    print(json.dumps({'native_ranges':len(native),'prior_source_hashes':len(prior),'setup_stores':stores,
      'bank_proofs':len(banks),'branch_slots':len(branches),'original_fixup_words':len(fixups['records']),
      'smt_unsat':len(proofs),'pid_nonzero_status':-42049}))


if __name__=='__main__':main()
