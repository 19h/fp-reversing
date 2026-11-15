#!/usr/bin/env python3
"""Independent shared-holder guards, record/header join and fallback lift.
O(I+256R+query DAG) construction time/space, excluding SMT search.
30 s/query. Free/allocation/status seams are explicit source abstractions.
"""
import copy
import json
from hashlib import sha256
import z3
from capstone.arm64 import ARM64_EXT_UXTB, ARM64_OP_REG
from kext_port_tools import ROOT, SOURCE, IMAGE, POOL, TABLE, qword
from lskd_values_symbolic import resize, mem
from verify_daemon_reader_record_payloads_publication import read, sha
import audit_userclient_uidlist_cleanup as UID
import recover_userclient_hash_table_bootstrap as R

HOLDER=0xfffffe000ccceac0
SUCCESS=0x7cb541a6

def number(v):
    v=z3.simplify(v);assert z3.is_bv_value(v);return v.as_long()

def validate_input(e):
    UID.validate_input({**e,'bank_rules':e['bank_rules'][:2]})
    for r in e['bank_rules'][2:]:
        assert (qword(int(r['slot'],16))+int(r['bias'],16))&((1<<64)-1)==int(r['target'],16)
    for d in e['hash_table_descriptors']:
        raw=IMAGE.read(int(d['address'],16),64)
        assert raw.hex()==d['normalized64_bytes_hex']
        assert d['name']=='site.FPHashTable' and d['signature']=='21'
        assert int.from_bytes(raw[44:48],'little')==d['size_bytes']==16
    assert e['global_holder']=={'address':hex(HOLDER),'original_collection_bytes_hex':'00'*8,
                                'normalized_file_backed':False,'native_current_value_known':False}
    f=e['initializer_function'];raw=bytes.fromhex(f['bytes_hex'])
    assert IMAGE.read(int(f['start'],16),len(raw))==raw

class Model(UID.Source):
    def __init__(self,e):
        super().__init__(e)
        self.h0,self.h1,self.allocation=z3.BitVecs('HT_initial_holder64 HT_reloaded_holder64 HT_allocation64',64)
        self.status=z3.BitVec('HT_initializer_output32',32)
        def bv(x):return z3.BitVecVal(x,64)
        def choice(cond,i,j):return (TABLE+8*z3.If(cond,bv(i),bv(j)),z3.If(cond,bv(qword(TABLE+8*i)),bv(qword(TABLE+8*j))))
        fixed={
            0xfffffe000a626a68:(POOL+0x840,self.base['TL']),0xfffffe000a626a80:(POOL+0xbb8,self.base['TR']),
            0xfffffe000a626aa0:(POOL+8*0x1ac,HOLDER+4),0xfffffe000a626aa4:(HOLDER,self.h0),
            0xfffffe000a626ac0:choice(self.h0==0,0x8c8,0x370),
            0xfffffe000a626ac4:(POOL+0x4f0,self.base['UL']+4),0xfffffe000a626acc:(POOL+0x578,self.base['UR']+4),
            0xfffffe000a626ad8:(POOL+0xc08,self.base['VL']+8),0xfffffe000a626ae0:(POOL+0x158,self.base['VR']+4),
            0xfffffe000a626b4c:(TABLE+8*0xf13,0xfffffe000c4ba154),0xfffffe000a626b68:(POOL+8*0x31,0xfffffe000847b964),
            0xfffffe000a626b98:choice(self.allocation==0,0x397,0x3a6),
            0xfffffe000a626c5c:(TABLE+8*0xf77,0xfffffe000a627400),
            0xfffffe000a626c98:choice(self.status==SUCCESS,0x7b9,0x7d3),
            0xfffffe000a626d08:(TABLE+8*0xf2b,0xfffffe000c4ba368),0xfffffe000a626d34:(POOL+8*0x4f,0xfffffe000847b9a4),
            0xfffffe000a626d48:(TABLE+8*0x397,0xfffffe000a626d54),0xfffffe000a626d64:(HOLDER,self.h1),
            0xfffffe000a626d80:choice(self.h1==0,0x39b,0x370),
            0xfffffe000a626db0:(TABLE+8*0x370,0xfffffe000a626dc8),
        }
        self.binding.update({pc:[value] for pc,value in fixed.items()})
        for pc,addr in [
            (0xfffffe000a626a54,UID.CTRL_A),(0xfffffe000a626a58,UID.CTRL_B),
            (0xfffffe000a626b18,UID.CTRL_A),(0xfffffe000a626b1c,UID.CTRL_B),
            (0xfffffe000a626c0c,UID.CTRL_A),(0xfffffe000a626c10,UID.CTRL_B),
            (0xfffffe000a626cb8,UID.CTRL_A),(0xfffffe000a626cbc,UID.CTRL_B)]:
            self.binding[pc]=[(addr,z3.BitVec('HT_controller_at_'+format(pc,'x'),32))]
        self.bank_pc.update({
            0xfffffe000a626a74:'TL',0xfffffe000a626a88:'TR',0xfffffe000a626b34:'TL',
            0xfffffe000a626b3c:'TR',0xfffffe000a626b58:'TR',0xfffffe000a626c30:'UL',0xfffffe000a626c44:'UR',
            0xfffffe000a626ce0:'freeL',0xfffffe000a626cf0:'freeR',0xfffffe000a626d14:'VL',0xfffffe000a626d24:'VR'})

    def operand(self,i,o,n):
        if o.ext==ARM64_EXT_UXTB:
            assert o.type==ARM64_OP_REG
            return (resize(self.read(i.reg_name(o.reg)),n)&255)<<o.shift.value
        return super().operand(i,o,n)

    def address(self,i,o):
        a=super().address(i,o)
        if i.writeback:
            assert i.address==0xfffffe000a626aa4 and i.mnemonic=='ldr' and len(i.operands)==2
            self.write(i.reg_name(o.mem.base),a)
        return a

    def owned(self):
        # Include the larger caller record/frame and all newly used immutable
        # ranges. The pointer publication proof itself requires no native lock.
        def separate(a,n,b,m):return z3.Or(z3.ULE(a+n,b),z3.ULE(b+m,a))
        out=self.ownership_premises()+[z3.ULE(self.sp,(1<<64)-1-0xc0),
            separate(self.sp,0xc0,self.node,16)]
        protected=[(HOLDER,8)]+[(self.base[n],256) for n in self.base]+[(int(r['slot'],16),8) for r in self.e['bank_rules']]+[(int(p['slot'],16),8) for p in self.e['branch_pointers']]+[(int(d['address'],16),64) for d in self.e['hash_table_descriptors']]
        for a,n in protected:
            out.extend([separate(self.sp,0xc0,z3.BitVecVal(a,64),n),separate(self.node,16,z3.BitVecVal(a,64),n)])
            out.append(z3.Implies(self.allocation!=0,separate(self.allocation,16,z3.BitVecVal(a,64),n)))
        out.extend([z3.Implies(self.allocation!=0,z3.And(z3.ULE(self.allocation,(1<<64)-17),
                    separate(self.allocation,16,self.sp,0xc0),separate(self.allocation,16,self.node,16)))])
        return out

def bank_audit(e):
    rows=[]
    for r in e['bank_rules']:
        pair=r.get('pair',r['name']);left=bytes.fromhex(e['banks'][pair+'L']['bytes_hex']);right=bytes.fromhex(e['banks'][pair+'R']['bytes_hex'])
        key,c=int(r['key'],16),int(r['constant'],16)
        assert all(x^right[left[x]^key]==c for x in range(256))
        rows.append({'name':r['name'],'input_cases_checked':256,'constant8':c})
    return rows

def proofs(e):
    out=[];coverage=[]
    def prove(label,v,bad,premises,rewrites=()):
        s=z3.Solver();s.set(timeout=30000);s.add(*v.owned(),*premises)
        assert s.check()==z3.sat,label
        s.add(z3.simplify(z3.Or(*[z3.Not(x) for x in v.address_checks],bad)))
        assert s.check()==z3.unsat,(label,s.reason_unknown())
        out.append({'label':label,'premises_nonvacuous':True,'query':s.to_smt2(),'result':'unsat','certified_rewrites':list(rewrites)})
        coverage.append({'label':label,'source_instruction_instances':v.count,'read_instances':len(v.reads),'write_instances':len(v.stores)})
    def start():
        v=Model(e)
        for label in ['root_literals','head_phase','node_gate','holder_guard']:v.run(label)
        return v
    def allocate(v):
        v.run('allocate');v.after_return();v.seed('x0',v.allocation);v.run('allocation_gate')
    def initialize(v):
        allocate(v);v.run('initializer_request')
    def initializer_return(v):
        v.after_return();mem(v,v.sp+0x90,4,v.status);v.run('initializer_gate')
    def cell(v,at,n):return v.memory[(z3.simplify(at).sexpr(),n)]
    v=start();guard=[v.marker!=UID.MAGIC]
    prove('all_holder64_marker_unequal_shared_global_guard',v,z3.Or(v.read('x19')!=HOLDER,v.read('x21')!=v.h0,
          v.read('w22')!=0x2d4,v.read('w24')!=0x397,v.read('x17')!=0x678,
          v.read('x8')!=z3.If(v.h0==0,z3.BitVecVal(0xfffffe000a626af4,64),z3.BitVecVal(0xfffffe000a626dc8,64))),guard)
    v.run('allocate')
    prove('null_holder_original_typed_FPHashTable_allocation_ABI',v,z3.Or(v.read('x0')!=0xfffffe000847b960,
          v.read('x10')!=0xfffffe000c4ba154,v.read('x17')!=0xd0c8,v.read('x28')!=0xa41a4d891208c018,
          v.read('w22')!=0x7b9,v.read('w26')!=0x370),guard+[v.h0==0])
    v.after_return();v.seed('x0',v.allocation);v.run('allocation_gate')
    prove('all_allocation_pointer_bits_select_record_or_reload',v,v.read('x8')!=z3.If(v.allocation==0,
          z3.BitVecVal(0xfffffe000a626d54,64),z3.BitVecVal(0xfffffe000a626ba4,64)),guard+[v.h0==0])
    v.run('initializer_request')
    prove('nonnull_allocation_original_initializer_record_and_target',v,z3.Or(v.read('x0')!=v.sp+0x90,
          v.read('x21')!=v.allocation,cell(v,v.sp+0x98,8)!=v.allocation,
          v.read('x8')!=0xfffffe000a627400,v.read('x17')!=0x2bbe),guard+[v.h0==0,v.allocation!=0])
    d=Model(e);d.memory=dict(v.memory);d.sp=v.sp-0xa0;d.seed('sp',d.sp);d.seed('x0',v.sp+0x90);d.run('initializer_header')
    # Source decoding uses only incoming X0, SP and caller-produced record
    # cells in this selected prefix. An object-size interpretation of its
    # other fields is not imported from its unrecovered later code.
    caller_key=v.values[(0xfffffe000a626bec,'w10')];callee_key=d.values[(0xfffffe000a627538,'w12')]
    lemma='caller_initializer_pre_multiply_codec_key_equivalence'
    prove(lemma,d,caller_key!=callee_key,v.owned()+guard+[v.h0==0,v.allocation!=0])
    decoded=z3.substitute(d.read('w24'),(callee_key,caller_key))
    prove('original_caller_record_to_initializer_header_codec_join',d,z3.Or(decoded!=0xabd,
          d.read('x20')!=v.allocation,cell(d,v.allocation,4)!=0,cell(d,v.allocation+4,4)!=128),
          v.owned()+guard+[v.h0==0,v.allocation!=0],
          [{'lemma':lemma,'rewrite':'Substitute equal pre-multiply key expressions by congruence through the same u32 multiplication and XOR decoder.'}])
    initializer_return(v)
    prove('all_initializer_output32_exact_publication_status_gate',v,z3.Or(v.read('x26')!=0xa41a4d891208c018,
          v.read('x8')!=z3.If(v.status==SUCCESS,z3.BitVecVal(0xfffffe000a626d9c,64),z3.BitVecVal(0xfffffe000a626ca8,64))),
          guard+[v.h0==0,v.allocation!=0])
    success=copy.copy(v);success.regs=dict(v.regs);success.memory=dict(v.memory);success.stores=list(v.stores);success.reads=list(v.reads);success.address_checks=list(v.address_checks);success.calls_per_pc=dict(v.calls_per_pc);success.values=dict(v.values)
    success.run('publish')
    prove('matching_status_publishes_allocated_global_and_enters_processing',success,z3.Or(cell(success,z3.BitVecVal(HOLDER,64),8)!=v.allocation,
          success.read('x8')!=0xfffffe000a626dc8,success.read('w22')!=0x2d4,
          success.read('w28')!=0x4d08a3fb,success.read('x2')!=UID.CTRL_B,success.read('x3')!=UID.CTRL_A),
          guard+[v.h0==0,v.allocation!=0,v.status==SUCCESS])
    v.run('rollback')
    prove('nonmatching_status_typed_FPHashTable_rollback_ABI',v,z3.Or(v.read('x0')!=0xfffffe000847b9a0,
          v.read('x1')!=v.allocation,v.read('x10')!=0xfffffe000c4ba368,v.read('x17')!=0x4d6a,
          v.read('w22')!=0x397,v.read('w26')!=0x370),guard+[v.h0==0,v.allocation!=0,v.status!=SUCCESS])
    v.after_return();v.run('rollback_return');v.run('reload_guard')
    common=z3.Or(v.read('w24')!=0x980,v.read('w22')!=0x2d4,v.read('x26')!=0xa41a4d891208c018,
          v.read('w28')!=0x4d08a3fb,v.read('x8')!=z3.If(v.h1==0,z3.BitVecVal(0xfffffe000a626920,64),z3.BitVecVal(0xfffffe000a626dc8,64)))
    prove('rollback_return_reloads_global_for_UID_free_or_processing',v,common,guard+[v.h0==0,v.allocation!=0,v.status!=SUCCESS])
    v=start();allocate(v);v.run('reload_guard')
    prove('null_allocation_reloads_global_for_UID_free_or_processing',v,z3.Or(v.read('w24')!=0x980,
          v.read('x26')!=0xa41a4d891208c018,v.read('w28')!=0x4d08a3fb,
          v.read('x8')!=z3.If(v.h1==0,z3.BitVecVal(0xfffffe000a626920,64),z3.BitVecVal(0xfffffe000a626dc8,64))),
          [v.marker!=UID.MAGIC,v.h0==0,v.allocation==0])
    v.run('node_free');v.after_return();v.run('node_continue')
    prove('unequal_marker_null_holder_fallback_drains_UID_node_and_joins_successor',v,z3.Or(
          v.values[(0xfffffe000a6269ac,'x1')]!=v.node,
          v.values[(0xfffffe000a6269a8,'x0')]!=0xfffffe000847b2a0,
          v.values[(0xfffffe000a626990,'x11')]!=0xfffffe000c4ba368,
          v.values[(0xfffffe000a6269b0,'x17')]!=0x4d6a,
          v.read('x20')!=v.next,v.read('w19')!=0xe5e,v.read('w21')!=0x58c,
          v.read('x8')!=z3.If(v.next==0,z3.BitVecVal(0xfffffe000a626838,64),z3.BitVecVal(0xfffffe000a6269e4,64))),
          [v.marker!=UID.MAGIC,v.h0==0,v.allocation==0,v.h1==0])
    return out,coverage

def audit():
    e=json.loads(read(ROOT/(R.P+'_checks.json')));validate_input(e);banks=bank_audit(e);ps,coverage=proofs(e)
    rechecked=[]
    priors=[('userclient_uidlist_cleanup_audit.json','source_proofs','label',[
        'all_controller_words_original_typed_UIDList_free_ABI',
        'ordinary_return_preserves_saved_successor_and_selects_loop_or_context_free']),
        ('userclient_context_lifecycle_checks.json','proofs','name',[
        'context_destroy_empty_head_exact_typed_free_ABI','context_destroy_after_free_clears_original_cell_and_returns_zero',
        'context_destroy_normal_epilogue_uses_raw_status_in_w8'])]
    for name,key,label,names in priors:
        for p in json.loads(read(ROOT/name))[key]:
            if p[label] not in names:continue
            s=z3.Solver();s.set(timeout=30000);s.add(*z3.parse_smt2_string(p['query']));assert s.check()==z3.unsat
            rechecked.append({'source':name,'label':p[label],'query_sha256':sha256(p['query'].encode()).hexdigest(),'result':'unsat'})
    assert len(rechecked)==5
    altered=[]
    for what in ['new_source_byte','new_bank_byte','hash_table_descriptor_size','global_holder_claim']:
        bad=copy.deepcopy(e)
        if what=='new_source_byte':r=bad['spans'][5];r['bytes_hex']=(bytes([bytes.fromhex(r['bytes_hex'])[0]^1])+bytes.fromhex(r['bytes_hex'])[1:]).hex()
        elif what=='new_bank_byte':r=bad['banks']['TL'];r['bytes_hex']=(bytes([bytes.fromhex(r['bytes_hex'])[0]^1])+bytes.fromhex(r['bytes_hex'])[1:]).hex()
        elif what=='hash_table_descriptor_size':bad['hash_table_descriptors'][0]['size_bytes']=24
        else:bad['global_holder']['native_current_value_known']=True
        try:validate_input(bad)
        except AssertionError:altered.append({'alteration':what,'rejected':True})
        else:raise AssertionError('altered evidence admitted')
    return {'auditor_sha256':sha(__file__),'scope':R.SCOPE,'source_sha256':sha(SOURCE),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),
            'dependencies':{n:sha(ROOT/n) for n in R.DEPS+['recover_userclient_hash_table_bootstrap.py']},
            'bank_audits':banks,'source_proofs':ps,'rechecked_prior_source_proofs':rechecked,
            'altered_evidence_controls':altered,'source_coverage':coverage,
            'independent_totals':{'new_source_queries_unsat':len(ps),'prior_source_queries_unsat':5,'bank_input_cases_checked':2048,
                                  'altered_evidence_rejections':4,'source_instruction_instances':sum(x['source_instruction_instances'] for x in coverage)},
            'conditional_global_hash_table_bootstrap_established':True,**{n:False for n in R.FALSE}}

if __name__=='__main__':
    a=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a['independent_totals']),flush=True)
