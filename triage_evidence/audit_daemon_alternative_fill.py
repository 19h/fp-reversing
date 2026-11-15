#!/usr/bin/env python3
"""Source equations for alternative allocation, loop induction and reader masks.
O(parent bytes + selected replay*32 + source DAG) time/space, excluding solver
search (30 s/query). Three universal normalizer lemmas qualify proof cuts.
No native allocation, continuation admission, target interval or IDB mutation.
"""
import json
import z3
from daemon_receive_tools import ROOT, SOURCE, TABLE
from audit_daemon_append_fields import Lift
from audit_daemon_alternate_word import LemmaLift
from audit_daemon_record_storage import word, index
from audit_daemon_storage_flag import replay
from lskd_values_symbolic import resize
from verify_daemon_reader_record_payloads_publication import read, sha
import recover_daemon_alternative_fill as R

DEPS = ['audit_daemon_append_fields.py', 'audit_daemon_alternate_word.py', 'audit_daemon_record_storage.py',
        'audit_daemon_storage_flag.py', 'audit_daemon_state_table_mixing.py', 'audit_daemon_environment_outputs.py',
        'lskd_values_symbolic.py', 'recover_daemon_return_bank_origins.py']
KEYS = [0x473c853ae26b7ab8, 0x8f0490db2637da4e, 0x639ff74d03d39428, 0xa34408d6869aa02f,
        0x0a23823d71e7a74e, 0x6c2f97ea7411e380, 0x3d107423d6820c5f, 0x71ef41f1f2e87b90]
BIAS = 0xb4016435


class Source(Lift):
    def __init__(self, values=None):
        super().__init__()
        self.supplied, self.loads = values or {}, []

    def load(self, address, n):
        assert self.pc in self.supplied, hex(self.pc)
        size, value = self.supplied[self.pc]
        assert size == n
        self.loads.append((self.pc, address, n))
        return resize(value, n*8)

    def one(self, ins):
        if ins.mnemonic == 'strb' and ins.writeback:
            self.pc = ins.address
            assert len(ins.operands) == 3 and ins.operands[2].imm == 1
            base = ins.reg_name(ins.operands[1].mem.base)
            self.store(self.address(ins, ins.operands[1]), 1, self.read(ins.reg_name(ins.operands[0].reg)), ins.address)
            self.write(base, self.read(base)+1)
            return
        return super().one(ins)


class Reduced(Source):
    def __init__(self, values, contexts):
        super().__init__(values)
        self.contexts, self.cuts, self.inputs = contexts, [], {}

    def one(self, ins):
        for j, (a, b, reg, k) in enumerate(R.NORMALIZERS):
            if ins.address == a:
                self.inputs[j] = self.read(reg)
                for n, value in self.contexts[j].items():
                    assert z3.is_true(z3.simplify(self.read(n) == value)), (hex(a), n)
        super().one(ins)
        for j, (a, b, reg, k) in enumerate(R.NORMALIZERS):
            if ins.address+4 == b:
                self.write(reg, self.inputs[j]^KEYS[k])
                self.cuts.append({'start': hex(a), 'end_exclusive': hex(b), 'register': reg, 'round': k,
                                  'context': {n: hex(v) for n,v in self.contexts[j].items()}})


def obligations():
    out, contexts = [], []
    def prove(label, bad, premises=()):
        s = z3.Solver()
        s.set(timeout=30000)
        s.add(*premises)
        assert s.check() == z3.sat, label
        s.add(z3.simplify(bad))
        result = s.check()
        assert result == z3.unsat, (label, str(result), s.reason_unknown())
        out.append({'label': label, 'premises_nonvacuous': True, 'result': 'unsat', 'query': s.to_smt2()})
        print(json.dumps({'source_proof': label, 'result': 'unsat'}), flush=True)
    def seed(v, values):
        for n,x in values.items():
            v.seed(n,x)
        return v
    def loads(v, expected):
        assert {pc for pc,a,n in v.loads} == set(expected)
        return [a != expected[pc] for pc,a,n in v.loads]
    frame, result, companion, callee = z3.BitVecs('fill_frame64 fill_result64 fill_companion64 fill_callee64',64)
    encoded, c0, c1 = z3.BitVecs('fill_encoded_extent32 fill_controller032 fill_controller132',32)
    extent = encoded+0x89271594
    v = seed(Source(), {'sp':frame})
    v.run_block(*R.SPANS['zero_slots'])
    assert len(v.stores)==2
    prove('initial_two_saved_base_cells_zero',z3.Or(*[
        z3.Or(w['address']!=frame+off,w['value']!=0,w['size_bytes']!=8)
        for w,off in zip(v.stores,[0x2338,0x3e00])]))
    # Exhaustive immutable bank rows in the extractor establish the right byte
    # as low8(controller expression) XOR constant. Address obligations below
    # establish that the source consumes precisely those two table entries.
    l = z3.BitVec('fill_bank_left_byte8',8)
    u = ((c0+c1)^0xa6)*0x0a5cd4cf
    vals = {0x1008c0770:(8,0x1010b8dc8),0x1008c0774:(4,c0),
            0x1008c0778:(8,0x1010c4670),0x1008c077c:(4,c1),
            0x1008c0798:(8,0x101031da0),0x1008c07a0:(1,l),
            0x1008c07ac:(8,0x100e99900),0x1008c07b0:(1,z3.Extract(7,0,u)^0xea),
            0x1008c07c8:(8,TABLE),0x1008c07cc:(8,callee)}
    v = seed(Source(vals), {'sp':frame,'w9':0x6cf4,'w22':encoded})
    v.run_block(0x1008c0750,0x1008c07d4)
    prove('alternative_allocator_source_addresses_and_full_u32_extent',z3.Or(
        *loads(v,{0x1008c0770:frame+0x9c8,0x1008c0774:0x1010b8dc8,
            0x1008c0778:frame+0x9c0,0x1008c077c:0x1010c4670,
            0x1008c0798:frame+0x5f0,0x1008c07a0:0x101031da0+z3.ZeroExt(56,z3.Extract(7,0,u)),
            0x1008c07ac:frame+0x5e0,0x1008c07b0:0x100e99900+z3.ZeroExt(56,l^0x0a),
            0x1008c07c8:frame+0x9d8,0x1008c07cc:TABLE+8*0xcc0d}),
        v.read('x0')!=z3.ZeroExt(32,extent),v.read('x8')!=callee,v.read('x17')!=0x6aa4,
        v.read('w19')!=0x76bf,v.read('w23')!=0x4d13))
    v = seed(Source({0x1008c07e4:(8,companion),0x1008c07e8:(8,callee)}),
             {'sp':frame,'x0':result,'x24':TABLE,'w23':0x4d13})
    v.run_block(0x1008c07d8,0x1008c07f0)
    prove('alternative_return_publishes_U0_cell_and_mode_zero',z3.Or(
        v.stores[0]['address']!=frame+0x2338,v.stores[0]['value']!=result,
        v.read('x21')!=result,v.read('x0')!=companion,v.read('w20')!=0,
        *loads(v,{0x1008c07e4:frame+0x3e00,0x1008c07e8:TABLE+8*0x4d13}),v.read('x17')!=0x62b1))
    v = seed(Source({0x100934304:(8,companion),0x100934308:(8,callee)}),
             {'sp':frame,'x0':result,'x23':TABLE,'w20':0x4d13})
    v.run_block(0x100934300,0x100934314)
    prove('clear_return_publishes_U8_cell_and_mode_one',z3.Or(
        v.stores[0]['address']!=frame+0x3e00,v.stores[0]['value']!=result,
        v.read('x21')!=companion,v.read('x0')!=result,v.read('w20')!=1,
        *loads(v,{0x100934304:frame+0x2338,0x100934308:TABLE+8*0x4d13}),v.read('x17')!=0x62b1))
    v = seed(Source({0x100934a48:(8,TABLE)}),{'sp':frame,'x21':result,'x0':companion,'w19':0x76bf})
    v.run_block(0x100934a2c,0x100934a4c)
    prove('shared_pointer_gate_is_OR_of_both_saved_bases',v.read('w9')!=z3.If(
        result|companion==0,z3.BitVecVal(0x76bf,32),z3.BitVecVal(0x76d3,32)))
    u = ((c1-c0)^0xa6)*0x0a5cd4cf
    vals = {0x1008a0fcc:(8,0x1010b8dc8),0x1008a0fd0:(4,c0),
            0x1008a0fd4:(8,0x1010c4670),0x1008a0fd8:(4,c1),
            0x1008a0ff4:(8,0x101031da0),0x1008a0ffc:(1,l),
            0x1008a100c:(8,0x100e99900),0x1008a1010:(1,z3.Extract(7,0,u)^0x58),
            0x1008a1028:(8,TABLE),0x1008a102c:(8,callee)}
    v = seed(Source(vals),{'sp':frame,'x0':companion,'w19':0x76bf})
    v.run_block(0x1008a0fa0,0x1008a1038)
    prove('shared_object_allocator_is_48_bytes_and_same_malloc_slot',z3.Or(
        v.read('x0')!=48,v.read('x8')!=callee,v.read('x17')!=0x6aa4,
        v.read('w24')!=0x6802,v.read('w19')!=0xb9dcdf6b,v.read('w23')!=0x5fc1,
        *loads(v,{0x1008a0fcc:frame+0x9c8,0x1008a0fd0:0x1010b8dc8,
            0x1008a0fd4:frame+0x9c0,0x1008a0fd8:0x1010c4670,0x1008a0ff4:frame+0x5f0,
            0x1008a0ffc:0x101031da0+z3.ZeroExt(56,z3.Extract(7,0,u)),
            0x1008a100c:frame+0x5e0,0x1008a1010:0x100e99900+z3.ZeroExt(56,l^0x86),
            0x1008a1028:frame+0x9d8,0x1008a102c:TABLE+8*0xcc0d})))
    v = seed(Source({0x1008a1060:(8,callee)}),{'sp':frame,'x0':result,'x25':TABLE,
        'w19':0xb9dcdf6b,'w23':0x5fc1,'w24':0x6802})
    v.run_block(0x1008a103c,0x1008a1068)
    idx = z3.If(result==0,z3.BitVecVal(0x6802,64),z3.BitVecVal(0x6819,64))
    prove('object_result_save_and_failure_success_routes',z3.Or(
        v.stores[0]['address']!=frame+0x76e0,v.stores[0]['value']!=result,
        *loads(v,{0x1008a1060:TABLE+8*idx}),v.read('x17')!=0x6d40))
    mode = z3.BitVec('fill_mode32',32)
    v = seed(Source({0x10092fb6c:(8,TABLE)}),{'sp':frame,'w23':0x5fc1,'w20':mode})
    v.run_block(0x10092fb3c,0x10092fb70)
    prove('mode_split_formula_and_next_phase',z3.Or(v.read('w8')!=(0x5fc1^(mode*0x19)),
        v.read('w24')!=0x1282,v.read('w11')!=0x12b1))
    prove('mode_zero_fill_mode_one_emitter_partition',v.read('w8')!=z3.If(mode==0,
        z3.BitVecVal(0x5fc1,32),z3.BitVecVal(0x5fd8,32)),[z3.ULE(mode,1)])
    n = z3.BitVec('fill_extent32',32)
    vals = {0x10087cec4:(8,TABLE),0x10087cec8:(8,0x1007d39f0)}
    v = seed(Source(vals),{'sp':frame,'w11':0x12b1,'w22':n-0x89271594})
    v.run_block(0x10087ce80,0x10087cf24)
    prove('encoded_count_reduces_to_bias_plus_zero_extended_extent',z3.Or(
        v.read('x9')!=z3.ZeroExt(32,n)+BIAS,v.read('w8')!=0,v.read('w10')!=0x1e73,
        v.read('w11')!=z3.If(n==0,z3.BitVecVal(0xc68d,32),z3.BitVecVal(0xa0f6,32)),
        v.stores[0]['address']!=frame+0x92a0,v.stores[0]['value']!=0x1007d39f0,
        *loads(v,{0x10087cec4:frame+0x9d8,0x10087cec8:TABLE+8*0x12b1})))
    base, table, cached = z3.BitVecs('fill_base64 fill_table64 fill_cached64',64)
    vals = {0x1006f67e4:(8,TABLE),0x1006f67e8:(8,0x1004e8b28),
            0x1006f68d4:(8,0x1010c8268),0x1006f68d8:(8,0x1010c67d4)}
    v = seed(Source(vals),{'sp':frame,'w10':0x1e73,'x21':base})
    v.run_block(0x1006f67d4,0x1006f6910)
    prove('positive_fill_initial_state_and_all_normalizer_constants',z3.Or(
        *[v.read(reg)!=value for reg,value in R.CONTEXT.items()],
        v.read('x11')!=base<<3,v.read('x12')!=BIAS+1,v.read('x13')!=1,
        v.read('x26')!=base,v.read('w10')!=0x4870,v.read('x27')!=0x1004e8b28,v.read('x17')!=0xc336,
        v.read('x0')!=0x1010c67d4,v.read('x30')!=0x1010c8268,
        v.stores[0]['address']!=frame+0x9b8,v.stores[0]['value']!=0x6cf4,
        *loads(v,{0x1006f67e4:frame+0x9d8,0x1006f67e8:TABLE+8*0x1e73,
                  0x1006f68d4:frame+0x858,0x1006f68d8:frame+0x878})))
    x = z3.BitVec('fill_normalizer_input64',64)
    for a,b,reg,k in R.NORMALIZERS:
        v = LemmaLift(reg)
        seed(v,R.CONTEXT);v.seed(reg,x)
        v.run_block(a,b)
        prove('normalizer_'+hex(a),v.read(reg)!=x^KEYS[k])
        contexts.append(v.context)
    mask = z3.BitVec('fill_mask32',32)
    i = z3.BitVec('fill_iteration32',32)
    address = base+z3.ZeroExt(32,i)
    vals = {0x1004e8b54:(4,mask),0x1004e8b5c:(8,table),0x1004e8b60:(8,cached),
            0x1004e8c3c:(8,TABLE),0x1004e8c40:(8,callee)}
    v = seed(Reduced(vals,contexts),{**R.CONTEXT,'sp':frame,'x21':address,'x26':address,
        'x11':address<<3,'x12':BIAS+z3.ZeroExt(32,i)+1,'x13':z3.ZeroExt(32,i)+1,
        'x9':BIAS+z3.ZeroExt(32,n),'w8':0,'w10':0x4870,'x0':0x1010c67d4,'x30':0x1010c8268})
    v.run_block(0x1004e8b28,0x1004e8c58)
    assert len(v.cuts)==3 and len(v.stores)==1 and len(v.loads)==5
    cuts = v.cuts
    byte = z3.Extract(7,0,z3.LShR(word(address,cached),(address&7)*8))
    active = [z3.ULT(i,n)]
    route = z3.If(z3.ULT(z3.ZeroExt(32,i)+1,z3.ZeroExt(32,n)),z3.BitVecVal(0x4870,64),z3.BitVecVal(0x487d,64))
    prove('loop_cache_addresses_and_repeat_or_completion_slot',z3.Or(*loads(v,{
        0x1004e8b54:0x1010c67d4,0x1004e8b5c:0x1010c8268,
        0x1004e8b60:table+index(address,mask),0x1004e8c3c:frame+0x9d8,
        0x1004e8c40:TABLE+8*route})),active)
    prove('loop_store_is_same_address_mask_as_alternative_readers',z3.Or(
        v.stores[0]['address']!=address,v.stores[0]['value']!=byte,v.stores[0]['size_bytes']!=1))
    prove('loop_induction_updates_and_preserved_key_context',z3.Or(
        v.read('x21')!=address+1,v.read('x26')!=address+1,v.read('x11')!=(address+1)<<3,
        v.read('x12')!=BIAS+z3.ZeroExt(32,i)+2,v.read('x13')!=z3.ZeroExt(32,i)+2,
        v.read('x9')!=BIAS+z3.ZeroExt(32,n),v.read('w8')!=0,v.read('w10')!=0x4870,
        v.read('x17')!=0x6d4e,*[v.read(reg)!=value for reg,value in R.CONTEXT.items()]))
    prove('same_epoch_reader_XOR_decodes_each_fill_byte_to_zero',v.stores[0]['value']^byte!=0)
    prove('mask255_keeps_each_cache_word_within_256_bytes',z3.Or(
        z3.UGT(index(address,z3.BitVecVal(255,32)),248),index(address,z3.BitVecVal(255,32))&7!=0))
    v = seed(Source({0x1006e5c30:(8,0x6cf4),0x1006e5c3c:(8,0x1007d39f0),
                     0x1006e5c40:(8,TABLE),0x1006e5c44:(8,0x1007f39ac)}),{'sp':frame})
    v.run_block(0x1006e5c2c,0x1006e5c4c)
    prove('positive_fill_completion_reloads_original_saved_continuation',z3.Or(
        v.read('x12')!=0x1007d39f0,v.read('x8')!=0x1007f39ac,v.read('x17')!=0xddd5,
        *loads(v,{0x1006e5c30:frame+0x9b8,0x1006e5c3c:frame+0x92a0,
                  0x1006e5c40:frame+0x9d8,0x1006e5c44:TABLE+8*0xbe45})))
    v = seed(Source(),{'x12':callee})
    v.run_block(0x1007f39ac,0x1007f39b0)
    prove('zero_and_positive_fill_share_saved_return_bridge',z3.Or(v.read('x12')!=callee,v.read('x17')!=0x6094))
    return out,cuts


def controls():
    a,b = z3.BitVecs('fill_control_new_pointer64 fill_control_companion64',64)
    writer,reader = z3.BitVecs('fill_control_writer_mask8 fill_control_reader_mask8',8)
    addr = z3.BitVec('fill_control_address64',64)
    specs = [('NULL_new_pointer_nonzero_companion_passes_OR_gate',z3.And(a==0,b!=0,a|b!=0),'sat'),
             ('changed_epoch_mask_can_destroy_zero_decoding',z3.And(writer!=reader,writer^reader!=0),'sat'),
             ('arbitrary_mask_does_not_bound_cache_to_256_bytes',z3.UGT(index(addr,z3.BitVecVal(0xffffffff,32)),248),'sat'),
             ('decimal_13_dispatch_delta_is_not_hexadecimal_13',z3.BitVecVal(0x4870^13,32)==0x4870^0x13,'unsat')]
    out=[]
    for label,condition,expected in specs:
        s=z3.Solver();s.set(timeout=30000);s.add(condition)
        assert str(s.check())==expected,label
        out.append({'label':label,'result':expected,'query':s.to_smt2(),
                    'source_scalar_model_only':True,'native_admission_established':False})
    for n in [0,1,21,0xffffffff]:
        for i in sorted({0,max(0,n-1)}):
            active=i<n
            assert not active or i+1<=0xffffffff
            route=0x4870 if active and i+1<n else 0x487d if active else None
            out.append({'label':'counter_boundary_'+str(n)+'_'+str(i),'extent_bytes':n,
                'iteration_index':i,'body_reached':active,'next_index32':hex(route) if route is not None else 'not read',
                'source_scalar_model_only':True,'native_admission_established':False})
    return out


def audit():
    e=json.loads(read(ROOT/(R.P+'_checks.json')))
    assert e==R.extract()
    proofs,cuts=obligations()
    return {'scope':__doc__,'generator_sha256':sha(R.__file__),'auditor_sha256':sha(__file__),
            'source_sha256':sha(SOURCE),'dependencies':{p:sha(ROOT/p) for p in DEPS},
            'independent_totals':replay(e),'source_proofs':proofs,'scalar_controls':controls(),
            'proof_cut_lemmas':3,'proof_cut_applications':3,'proof_cut_contexts_verified':cuts,
            'alternative_allocation_and_fill_contract_established':True,
            'alternative_constructor_completion_established':False,'alternative_branch_observed':False,
            'native_cache_epoch_established':False,'new_port_emission_established':False,
            'target_instruction_rewrites':0,'prior_admissions_rerun':False,'new_target_intervals':0,
            'new_guest_input_bytes':0,'new_API_return_premises':0,'native_target_executed':False,'full_goal_complete':False}


if __name__=='__main__':
    a=audit()
    (ROOT/(R.P+'_audit.json')).write_text(json.dumps(a,indent=2)+'\n')
    print(json.dumps({'source_proofs':len(a['source_proofs']),**a['independent_totals']}),flush=True)
