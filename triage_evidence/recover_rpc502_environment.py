#!/usr/bin/env python3
"""Original-byte RPC502 scheduling/CSR/BootPolicy contract recovery.

Synthetic fixtures are independent artifacts with explicit models/PAC bypasses;
they are not native execution or end-to-end authorization evidence.
O(B+F+D+P) extraction time/space for image, fixups, instructions and fixtures,
plus finite byte-bank checks and solver-dependent SMT proof cost.
"""
import hashlib
import json
import subprocess
from daemon_receive_tools import *
from daemon_import_bindings import binding


def main():
    starts=[0x1005c18c8,0x100579c6c,0x1005be85c,0x100547604,
      0x1005806fc,0x1004b9abc,0x1009ab9bc,0x10050bc14,
      0x10056fca8,0x10058781c,0x10049b2c0,0x100520a64,
      0x1004d6650,0x100616000,0x100607ec4,0x10041a5e0,
      0x1004ac1c4,0x1005ec794,0x1004f8bd4,0x1004cfcec,
      0x100592a00,0x1005bbb20]
    native=[block(a,0x1800) for a in starts]
    for r in native:r['sha256']=hashlib.sha256(bytes.fromhex(r['bytes'])).hexdigest()
    cases=[
      ('QoS set',0x101031da0,0x100e99900,0x9a,0xcd59,TABLE,0,'libSystem/_pthread_set_qos_class_self_np'),
      ('guarded global',0x101031da0,0x100e99900,0x86,0xa45,POOL,0xffffffffa748856d,0x1010b5f70),
      ('CSR getter',0x100e99a00,0x100f4e390,0x6d,0xcdc4,TABLE,0,'libSystem/_csr_get_active_config'),
      ('comparison helper',0x100fc4130,0x101031ea0,0x4e,0xcac7,TABLE,0,0x10041a5e0),
      ('BootPolicy query',0x100fc4130,0x101031ea0,0xa3,0xcdbe,TABLE,0,'libbootpolicy/_bootpolicy_get_security_mode'),
    ]
    banks=[]
    for label,l,r,k,a,base,bias,want in cases:
        rec=selected(l,r,k,a,base,bias)
        assert rec['target']==(hex(want) if isinstance(want,int) else want)
        rec['label']=label;banks.append(rec)
    imported_data=[]
    for l,r,key,additive,neg,symbol in [
      (0x101031da0,0x100e99900,0x86,0x402,-0x7bed81d2,'_bootpolicy_default_policy_volume_path_value'),
      (0x100e99a00,0x100f4e390,0x6d,0x907,-0x4677e24f,'_bootpolicy_root_volume_uuid_value')]:
        c=bank(l,r,key);slot=POOL+8*(additive+c);b=binding(slot)
        assert b['symbol']==symbol and b['total_addend']+neg==0
        assert b['library_path']=='/usr/lib/libbootpolicy.dylib'
        imported_data.append({'left':hex(l),'right':hex(r),'key':hex(key),
          'constant':hex(c),'inputs_checked':256,'pool_index':hex(additive+c),
          'binding':b,'native_adjustment':neg,'resolved_expression':'original symbol address'})
    calls=[binding(a) for a in [0x1010a1390,0x1010a1070]]
    branches={0x2738:0x1005806fc,0x273e:0x100547604,0x9dcd:0x1004b9abc,
      0x242c:0x1009ab9bc,0x246b:0x10050bc14,0xa437:0x10056fca8,
      0xaaea:0x10058781c,0x3b7f:0x10049b2c0,
      0x705a:0x1004cfcec,0x709c:0x100607ec4,0x1781:0x1004ac1c4,
      0x1786:0x1005ec794,0x2af9:0x100592a00,0x2b0b:0x1005bbb20}
    for ix,target in branches.items():assert qword(TABLE+8*ix)==target
    mask=0xffffffff
    assert ((0x6cf4+0x2f74b649)&mask)&0xd08addcb==0x109
    assert ((0x109^0x4fe6)+(0x6cf4-0x1016))==0xabcd
    assert ((0x6cf4+0xe4a6a793)&mask)&0x1b58eb79==1
    assert ((0x6cf4-0x6cf3)&mask)==1
    queries={
      'origin_fold': '''(declare-fun o () (_ BitVec 64))
(define-fun encoded () (_ BitVec 64)
 (bvadd (bvxor o #xfd5ff337f77dd6ba) #x7fee7ffee9daef60
  (bvand (bvshl o #x0000000000000001) #xfabfe66feefbad74)))
(assert (not (= encoded (bvadd o #x7d4e7336e158c61a))))''',
      'comparison_frame': '''(declare-fun p () (_ BitVec 64))
(assert (= (bvand p #x0000000000000003) #x0000000000000000))
(define-fun caller () (_ BitVec 64)
 (bvmul (bvxor (bvadd (bvsub p (bvshl (bvand p #x67ce1d6a3c76f0c0) #x0000000000000001))
  #xe7ce1d6a3c76f0c3) #xaa2dbff8c5a269b7) #x00000000da51a827))
(define-fun callee () (_ BitVec 64)
 (bvmul (bvxor (bvsub (bvor p #xee9763edb3ce6674) (bvand p #xee9763edb3ce6674))
  #xa374c17f4a1aff00) #x00000000da51a827))
(assert (not (= caller callee)))''',
      'csr_indicator': '''(declare-fun c () (_ BitVec 32))
(define-fun nz () (_ BitVec 32) (ite (= c #x00000000) #x00000000 #x00000001))
(define-fun low () (_ BitVec 32)
 (ite (= c #x00000000) #x00000000
  (ite (bvsgt (bvor c (bvneg c)) #xffffffff) #x00000001 #x00000000)))
(define-fun result () (_ BitVec 32)
 (ite (= (bvand c (bvxor low #xffffffef)) #x00000000) #x00000000 nz))
(assert (not (= result (ite (= (bvand c #xffffffef) #x00000000) #x00000000 #x00000001))))''',
      'bind_cancellation': '''(declare-fun s () (_ BitVec 64))
(assert (or
 (not (= (bvadd s #x000000007bed81d2 #xffffffff84127e2e) s))
 (not (= (bvadd s #x000000004677e24f #xffffffffb9881db1) s))))''',
    }
    proofs=[]
    for name,body in queries.items():
        p=ROOT/f'rpc502_environment_{name}.smt2'
        p.write_text('(set-logic QF_BV)\n'+body+'\n(check-sat)\n')
        answer=subprocess.run(['z3','-smt2',str(p)],check=True,capture_output=True,text=True).stdout.strip()
        assert answer=='unsat',(name,answer)
        proofs.append({'name':name,'path':p.name,'result':answer})
    profiles=[]
    for name in ['pid123','pid0','csr0','qosfail','qossetfail','csr10','csr4','csr1','csrerr','cpuabcd']:
        p=ROOT/f'rpc502_probe_{name}.json';r=json.loads(p.read_text())
        assert r['source_sha256']==hashlib.sha256(SOURCE.read_bytes()).hexdigest()
        assert not r['native_target_executed'] and r['synthetic_target_instructions_executed']
        assert not r['target_host_ipc_files_or_system_calls_executed']
        assert r['stop_reason'] in ('returned_to_fixture','unmodeled_import','unmodeled_imported_data')
        if name=='pid123':assert r['end_registers']['x0']=='0xffff5bbf'
        cp=next((c for c in r['records'] if c['kind']=='checkpoint' and c['pc']=='0x1004cfcec'),None)
        indicator=int(cp['registers']['x23'],16) if cp else None
        expected={'csr0':0,'qosfail':0,'qossetfail':0,'csr10':0,'csr4':1,'csr1':1,'csrerr':2}
        if name in expected:assert indicator==expected[name],(name,indicator)
        profiles.append({'file':p.name,'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),
          'scope':'finite private model, PAC bypassed and imports modeled explicitly',
          'steps':r['steps'],'stop_reason':r['stop_reason'],'indicator':indicator,
          'last_record':r['records'][-1]})
    out={'source_sha256':hashlib.sha256(SOURCE.read_bytes()).hexdigest(),'native_ranges':native,
      'bank_proofs':banks,'imported_data_bank_proofs':imported_data,'original_import_bindings':calls,
      'branch_slots':[{'index':hex(ix),'target':hex(a),'fixup':FIXUPS[TABLE+8*ix]} for ix,a in branches.items()],
      'proofs':proofs,'synthetic_profiles':profiles,
      'guarded_global':{'address':'0x1010b5f70','original_bytes':IMAGE.read(0x1010b5f70,32).hex(),
        'matched_prefix_hex':'56a054c0','full_runtime_layout':'unknown','is_string':'not established'},
      'csr_indicator':'getter nonzero -> 2; getter zero -> ((u32_config & 0xffffffef)!=0)',
      'bootpolicy_call_site':'0x1004cfe24','bootpolicy_output_read_site':'0x100592a08',
      'unknowns':['actual imported data values/types and runtime BootPolicy library ABI/service',
        'global object lifecycle and warm/reentrant/concurrent behavior','final use of CSR/BootPolicy states',
        'QoS restoration and context outputs/ownership','native IPC/path/PAC/environment reachability'],
      'native_target_executed':False,'synthetic_target_instructions_executed':True,'idb_mutated':False}
    (ROOT/'rpc502_environment_contracts.json').write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'native_ranges':len(native),'bank_proofs':len(banks)+len(imported_data),
      'nonzero_addend_bindings':len(imported_data),'branch_slots':len(branches),
      'smt_unsat':len(proofs),'finite_synthetic_profiles':len(profiles)}))


if __name__=='__main__':main()
