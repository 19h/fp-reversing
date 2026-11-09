#!/usr/bin/env python3
"""Source-pinned local receive-callback recovery, without executing fairplayd.

Native-to-formula lifting is manual and reviewable in the accompanying report.
The SMT queries cover complete 32-bit domains; byte banks are exhaustive over
all 256 inputs. Neither check proves runtime reachability or hardware PAC.
O(B+F+D) storage/time for file bytes, parsed fixups and captured disassembly,
plus finite bank checks and solver-dependent SMT cost.
"""
import hashlib
import json
from pathlib import Path
import subprocess
from daemon_receive_tools import *


def main():
    starts=[0x100425f78,0x10014695c,0x100203a78,0x10020a37c,
        0x1001a59b0,0x10010c040,0x10006d214,0x10007fd74,
        0x1000eedac,0x1000a6e9c,0x1000c2ed4,0x10010b3c8,
        0x100264b4c,0x100175a84,0x100149a3c,0x10006cfe8,
        0x1000bcb00,0x1000bb86c,0x100264bbc,0x1000ba34c,
        0x100093b3c,0x1000c7ad0,0x1001313bc,0x10006ce30,
        0x1000350e0,0x1000df4a8,0x10003cc40,0x100073b34,
        0x100e2a8e0,0x100e2a8f0]
    ranges=[block(a) for a in starts]
    # Explicit function extents include the branch tails omitted by block().
    demuxes=[(0x100004b80,0x100004c10),(0x100005004,0x100005094),
             (0x100005274,0x100005304),(0x1000053c8,0x1000054b8),
             (0x1000055ac,0x1000056c8)]
    for a,z in demuxes:
        ranges.append({'start':hex(a),'end':hex(z),'bytes':IMAGE.read(a,z-a).hex(),
          'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}
                          for i in CS.disasm(IMAGE.read(a,z-a),a)]})
    live=json.loads((ROOT/'daemon_receive_wrappers_native.json').read_text())
    live_checks=[]
    for f in live['functions']:
        raw=bytes.fromhex(f['bytes'])
        assert IMAGE.read(int(f['start'],16),len(raw))==raw
        live_checks.append({'start':f['start'],'size':len(raw),'matches':True})

    # (label,left,right,key,additive,table/pool,bias,expected target)
    cases=[
      ('entry state0',0x100fc4230,0x101031fa0,0xf3,0x9b6,POOL,0xfffffffff70b6af9,0x1010c4e30),
      ('entry state1',0x100fc4230,0x101031fa0,0xf3,0x51,POOL,0xffffffffec9e1772,0x1010c4670),
      ('entry branch table',0x101031da0,0x100e99900,0xa,0x830,POOL,0xffffffffd0c4d1ee,TABLE),
      ('1000 header',0x101031da0,0x100e99900,0x9a,0xa35,POOL,0xffffffffc1e77bee,0x101038128),
      ('1000 malloc',0x100e99a00,0x100f4e390,0x6d,0xcb3d,TABLE,0,'libSystem/_malloc'),
      ('1200 header',0x100fc4130,0x101031ea0,0x4e,0x7fb,POOL,0xffffffffe9b2a74e,0x101038040),
      ('1200 malloc',0x100fc4130,0x101031ea0,0xbb,0xcb52,TABLE,0,'libSystem/_malloc'),
      ('500 header',0x100e99a00,0x100f4e390,0x78,0x574,POOL,0xffffffffcef5fc45,0x1010381c0),
      ('500 malloc',0x100fc4230,0x101031fa0,0x6c,0xcb86,TABLE,0,'libSystem/_malloc'),
      ('41471 header',0x100fc4230,0x101031fa0,0x6c,0x802,POOL,0xffffffffd5ba80c9,0x101038258),
      ('41471 malloc',0x101031da0,0x100e99900,0x86,0xcbb5,TABLE,0,'libSystem/_malloc'),
      ('61471 header',0x100fc4130,0x101031ea0,0xa3,0x1ee,POOL,0xffffffff96433c2e,0x1010382a0),
      ('61471 malloc',0x100e99a00,0x100f4e390,0xd7,0xcb81,TABLE,0,'libSystem/_malloc'),
      ('1000 demux',0x100e99800,0x100f4e290,0x61,0xcb88,TABLE,0,0x100005004),
      ('1200 demux',0x100e99800,0x100f4e290,0x61,0xcdc0,TABLE,0,0x100004b80),
      ('500 demux',0x101031da0,0x100e99900,0xa,0xcbae,TABLE,0,0x100005274),
      ('41471 demux',0x100fc4230,0x101031fa0,0xe4,0xcc90,TABLE,0,0x1000053c8),
      ('61471 demux',0x100e99a00,0x100f4e390,0x9c,0xce8c,TABLE,0,0x1000055ac),
      ('free reply',0x100e99700,0x100f4e190,0x56,0xcbf4,TABLE,0,'libSystem/_free'),
      ('destroy request',0x100fc4230,0x101031fa0,0xe4,0xcd98,TABLE,0,'libSystem/_mach_msg_destroy'),
      ('destroy reply',0x100e99700,0x100f4e190,0x81,0xcdad,TABLE,0,'libSystem/_mach_msg_destroy'),
      ('send reply',0x100fc4230,0x101031fa0,0xf3,0xce30,TABLE,0,'libSystem/_mach_msg'),
    ]
    banks=[]
    for label,l,r,k,a,b,bias,want in cases:
        rec=selected(l,r,k,a,b,bias)
        assert rec['target']==(hex(want) if isinstance(want,int) else want),(label,rec)
        rec['label']=label;banks.append(rec)
    # Prefix register setup, including the post-SP+0 record for left/right banks.
    setups=[(0x60f0,0xffffffffa75b1642,0x100fc4230),
        (0x2240,0xfffffffffa184636,0x101031fa0),
        (0x6640,0xffffffffdaeb98b6,0x100e99800),
        (0x4048,0xffffffffb971d649,0x100f4e290),
        (0x2b50,0xfffffffff02ce87e,0x101031da0),
        (0x30f8,-0xd45667,0x100e99900),
        (0x1658,0xffffffffa6e7fab5,0x100e99a00),
        (0x26a0,0xffffffff9d07c0b2,0x100f4e390)]
    for off,bias,want in setups:assert (qword(POOL+off)+bias)&MASK64==want
    assert (qword(0x1010a4328)+0xffffffffaa591739)&MASK64==0x100fc4130
    assert (qword(0x1010a6578)+0xffffffff8af86dcd)&MASK64==0x101031ea0
    assert (qword(0x1010a7ae8)+0xffffffffdc8ddf91)&MASK64==0x100e99700
    assert (qword(0x1010a4990)+0xffffffffc6a5784a)&MASK64==0x100f4e190

    def t(index,target):
        assert qword(TABLE+8*index)==target,(hex(index),hex(target))
    branches={0xc243:0x100203a78,0xc23f:0x10014695c,
        0x8a82:0x10020a37c,0x8a85:0x1001a59b0,
        0x6b4a:0x10006d214,0x6b9f:0x10010c040,
        0x7873:0x1000eedac,0x786f:0x10007fd74,
        0x9ef6:0x1000a6e9c,0x986f:0x100073b34,
        0xc51f:0x1000c2ed4,0xc539:0x100073b34,
        0x531a:0x10010b3c8,0x52ff:0x100073b34,
        0x9848:0x100264b4c,0x8430:0x100175a84,0x83ef:0x100073b34,
        0xc419:0x100149a3c,0xc40f:0x100073b34,
        0x1b9e:0x10006cfe8,0x18d7:0x1000bcb00,0x1900:0x1000bb86c,
        0x4c99:0x100264bbc,0x5406:0x1000ba34c,0x3086:0x100093b3c,
        0x8bd5:0x1000c7ad0,0x8bbd:0x1001313bc,
        0x8437:0x100264bbc,0x83c6:0x10006ce30,0xbef6:0x1000bcb00,
        0x4b26:0x1000df4a8,0x4b27:0x1000350e0,
        0x7e6a:0x10003cc40,0x7e98:0x1000bcb00}
    for ix,target in branches.items():t(ix,target)
    u32=lambda x:x&0xffffffff
    # Route-specific scalar states entering the common post-demux block.
    assert ((u32(0x323fd5f9+0x851e26c8))&0x48a2033e)==0
    w27=u32((0x52ff^0x033085f4)+0xfccf4493)
    assert w27==0x1b9e
    assert (u32(w27+0x5214a3dc)&0xadeb4085)==0
    w26=u32(0x9848+0x4f7e6773)&0x0331d74f
    assert u32(w26+0xfccf4493)==0x1b9e
    assert (u32(0x1b9e+0x888662f8)&0x77798169)==0
    assert 0xc40f^0xdf91==0x1b9e
    assert u32(0x1b9e-0x1b9e)==0
    # After common-state reduction, all handled paths use these constants.
    assert u32(0x4c99+0xacda0f55)&0x5325ef37==0x4b26
    assert (u32(0x4c99+0x4c07bc73)|0x21922430)==0x6d9a2d3c
    assert u32(0x4b26+0x74cdb4d8)==0x74cdfffe
    assert 0x74cdfffe&0x8b327e6b==0x7e6a
    assert 0x7e6a^0x7e75==0x1f
    assert 0x7e6a^0x0330a961==u32(0x7e6a+0x033058a1)==0x0330d70b
    assert u32(0x0330d70b+0xfccfc164)==0x986f
    assert u32(0x0330d70b+0xfccf41cc)==0x18d7

    prefix='(set-logic QF_BV)\n(declare-fun x () (_ BitVec 32))\n'
    queries={
      'range1200':'''(define-fun a () (_ BitVec 64)
 (bvsub #x0000000000000004 ((_ zero_extend 32) (bvsub x #x000004b0))))
(define-fun b () (_ BitVec 64)
 (bvneg (bvxor ((_ zero_extend 32) (bvsub #x000004b4 x)) a)))
(assert (not (= (= ((_ extract 63 63) (bvor a b)) #b0)
 (and (bvuge x #x000004b0) (bvule x #x000004b4)))))''',
      'range41471':'''(assert (not (= (bvult (bvadd x #xffff5e01) #x00000002)
 (or (= x #x0000a1ff) (= x #x0000a200)))))''',
      'range61471':'''(assert (not (= (bvult (bvsub x #x0000f01f) #x00000002)
 (or (= x #x0000f01f) (= x #x0000f020)))))''',
      'demux_boolean':'''(define-fun sign () (_ BitVec 32)
 (bvlshr (bvor x (bvneg x)) #x0000001f))
(define-fun bit () (_ BitVec 32)
 (bvand #x00000001 (bvnot (bvxor #x00004c99 sign))))
(define-fun idx () (_ BitVec 32)
 (bvxor #x000018d7 (bvmul bit #x000001d7)))
(assert (not (= idx (ite (= x #x00000000) #x000018d7 #x00001900))))''',
      'simple_status_sign':'''(define-fun bit () (_ BitVec 32)
 (bvlshr (bvnot (bvor (bvand (bvxor x #xffffffff) x) x)) #x0000001f))
(assert (not (= (= bit #x00000001) (bvsge x #x00000000))))''',
      'send_cleanup':'''(define-fun folded () (_ BitVec 32)
 (bvadd (bvxor x #xdffd7e7e) #x1002817f
   (bvand (bvshl x #x00000001) #xbffafcfc)))
(assert (not (= (bvule folded #x00000001)
 (or (= x #x10000003) (= x #x10000004)))))''',
    }
    proofs=[]
    for name,body in queries.items():
        p=ROOT/f'daemon_receive_{name}.smt2';p.write_text(prefix+body+'\n(check-sat)\n')
        answer=subprocess.run(['z3','-smt2',str(p)],check=True,text=True,capture_output=True).stdout.strip()
        assert answer=='unsat',(name,answer)
        proofs.append({'name':name,'file':p.name,'result':answer,'domain_bits':32})
    for header,size in [(0x101038128,200),(0x101038040,212),(0x1010381c0,384),
                        (0x101038258,36),(0x1010382a0,40)]:
        assert struct.unpack('<I',IMAGE.read(header+16,4))[0]==size
    used=[int(r['slot'],16) for r in banks]+[TABLE+ix*8 for ix in branches]
    used += [POOL+off for off,bias,want in setups]
    used += [0x1010a4328,0x1010a6578,0x1010a7ae8,0x1010a4990]
    used += [0x1010b1c40,0x1010b1c48]
    assert FIXUPS[0x1010b1c40]['target']=='CoreFoundation/_CFMachPortCreate'
    assert FIXUPS[0x1010b1c48]['target']=='CoreFoundation/_CFMachPortCreateWithPort'
    original_fixups=verify_original_fixups(used)
    out={'image':str(SOURCE),'sha256':hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        'scope':__doc__,'ranges':ranges,'live_ida_original_checks':live_checks,
        'bank_proofs':banks,'branch_slots':[{'index':hex(ix),'slot':hex(TABLE+ix*8),
           'target':hex(target),'fixup':FIXUPS.get(TABLE+ix*8)} for ix,target in branches.items()],
        'smt_proofs':proofs,'callback_context_record_bytes':40,
        'routing':[
          {'callback_ids':[1000,1002],'table':'0x101038128','max_reply':200,'demux':'0x100005004'},
          {'callback_ids':[1200,1204],'table':'0x101038040','max_reply':212,'demux':'0x100004b80'},
          {'callback_ids':[500,502],'table':'0x1010381c0','max_reply':384,'demux':'0x100005274'},
          {'callback_ids':[41471,41472],'table':'0x101038258','max_reply':36,'demux':'0x1000053c8'},
          {'callback_ids':[61471,61472],'table':'0x1010382a0','max_reply':40,'demux':'0x1000055ac'}],
        'no_nonnull_stub_ids_within_callback_ranges':[500,501,41472,61472],
        'unknowns':['per-service registration call chains','installed CF receive/trailer allocation and cleanup',
          'application authorization and successful incoming OOL ownership','native destination port object identity'],
        'original_fixup_checks':original_fixups,'target_executed':False}
    (ROOT/'daemon_receive_contracts.json').write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'native_ranges':len(ranges),'live_byte_checks':len(live_checks),
        'bank_proofs':len(banks),'branch_slots':len(branches),'smt_unsat':len(proofs),
        'mig_routes':len(out['routing']),
        'original_fixup_words':len(original_fixups['records'])}))


if __name__=='__main__':main()
