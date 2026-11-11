#!/usr/bin/env python3
"""Original-source clock high-water accumulator, release and continuation record.

Static scalar certificates with conditional phase, roots, extents and returning
calls. No native target execution or IDB mutation. O(B+I) extraction and O(I)
expression construction; solver cost separate. Frozen live IDA byte checks are
compared against the original KC rather than used as a replacement for it.
"""
import argparse
import json

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
import z3

from kernel_native_reader import Kernel
from kext_port_tools import ROOT, SOURCE
from lskd_values_symbolic import part, mem, cell, resize
from recover_aes_cleanup_epoch import span
from recover_kext_cold_init import pointer
from recover_lskd_clock_reader import ReaderLift, MASK, K, TABLE
from verify_daemon_reader_record_payloads_publication import read, sha

SPANS = {
    'default_delta': (0xfffffe000a5177e0, 0xfffffe000a5177f8),
    'common': (0xfffffe000a524054, 0xfffffe000a5246c4),
    'greater': (0xfffffe000a5271b8, 0xfffffe000a52744c),
    'advance': (0xfffffe000a534e34, 0xfffffe000a5351d0),
}
IDA_READBACK = {
    'captured_UTC': '2026-11-11T03:33:54Z',
    'method': 'ida.get_bytes', 'database_handle': '71c5aa51f433',
    'database_name': 'com.apple.driver.FairPlayIOKit',
    'ranges': [
        {'address': '0xfffffe000a517624', 'size_B': 64,
         'bytes_hex': '9f2403d5f3f700f9fa0318aa6ebd9752ce4bbd72f8030daaf40319aa998d1551e8cf9a5248c3a372ca7b8552aa3cbc722803080b0a010a0a88708052eabb01b9'},
        {'address': '0xfffffe000a534e34', 'size_B': 64,
         'bytes_hex': '9f2403d531848452f19eb87265dc9b520561a772b102110b3702050a516a85d231bbadf2f1c9d3f2b119f9f2f10211caef0111caf1010dcaa57c86d20520bcf2'},
    ],
    'scoped_recall': [
        {'database_handle': '71c5aa51f433', 'query': 'SecureTime monotonicclock LSKD 0xa517624',
         'count': 0, 'truncated': False},
        {'database_handle': '70f8437872ac', 'query': 'SecureTime monotonicclock FairPlayIOKit',
         'count': 0, 'truncated': False},
    ],
    'scope': 'Two 64-byte live IDA spot checks and two exact scoped memory queries; not a whole-IDB or whole-memory census.',
}


class FlowLift(ReaderLift):
    def run(self, label):
        saved = self.c
        row = next(s for s in saved['spans'] if s['label'] == label)
        cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        cs.detail = True
        data = bytes.fromhex(row['bytes_hex'])
        insns = list(cs.disasm(data, int(row['start'], 16)))
        assert len(insns)*4 == len(data)
        for ins in insns:
            self.pc = ins.address
            if ins.mnemonic == 'ldursw':
                dest=ins.reg_name(ins.operands[0].reg)
                self.write(dest,z3.SignExt(32,self.load(self.address(ins,ins.operands[1]),4)))
                self.count += 1
            elif ins.mnemonic == 'csel':
                assert ins.op_str.rsplit(',', 1)[1].strip() == 'ne'
                dest, left, right = [ins.reg_name(o.reg) for o in ins.operands[:3]]
                self.write(dest, z3.If(z3.Not(self.equal), self.read(left), self.read(right)))
                self.count += 1
            else:
                self.c = {'spans': [{'label': label, 'start': hex(ins.address), 'bytes_hex': bytes(ins.bytes).hex()}]}
                super().run(label)
        self.c = saved
        return self


def prove(capture):
    f, p, t = 0x51000000, 0x59000000, 0x58000000
    d, h, o, encoded_delta = z3.BitVecs('seed_98_64 seed_D8_64 object0_64 encoded_delta64', 64)
    a, b, l, field, field10 = z3.BitVecs('seed_A0_64 seed_68_64 seed_10_64 object30_64 object10_64', 64)
    fresh = z3.BitVec('fresh_clock32', 32)
    v = (d & MASK) ^ 0x23c7e4b4853b50c4
    w = (h & MASK) ^ 0x5629ca6fff2637b4
    j = (b & MASK) ^ 0xe95d80091182118a
    accumulator = o ^ v
    complement = field10 ^ j
    elapsed = accumulator + complement + 1
    old = (a & MASK) ^ field ^ K
    fold = (l & MASK) ^ 0x5e129968b0f85b1f
    q, counts, controls = {}, {}, {}

    def run(name, start, end, seeds, cells=()):
        obj = FlowLift(part(capture, name, start, end))
        for reg, value in seeds.items(): obj.seed(reg, value)
        for address, width, value in cells: mem(obj, address, width, value)
        obj.run(name)
        counts[name] = obj.count
        return obj

    obj = run('default_delta', 0xfffffe000a5177e0, 0xfffffe000a5177f8, {'x19': h})
    q['default_encoded_delta'] = obj.read('x8') != w
    obj = run('common_object_delta', 0xfffffe000a524058, 0xfffffe000a524104,
        {'x11': p, 'x9': 255, 'x10': t}, [(p+8,8,p), (p,8,o), (t+0x98,8,d)])
    q['common_object_xor_delta'] = z3.Or(obj.read('x13') != (o ^ v) - v, obj.read('x14') != v)
    obj = run('common_input_delta', 0xfffffe000a524104, 0xfffffe000a5241a0,
        {'x9':255, 'x10':t, 'x8':encoded_delta}, [(t+0xd8,8,h)])
    q['common_input_xor_delta'] = z3.Or(obj.read('x8') != (encoded_delta ^ w) - w, obj.read('x10') != w)
    obj = run('common_add_composition', 0xfffffe000a5241a0, 0xfffffe000a5241c0,
        {'x14':v, 'x10':w, 'x8':(encoded_delta ^ w)-w, 'x13':(o ^ v)-v})
    q['common_decoded_sum'] = obj.read('x8') != accumulator + (encoded_delta ^ w) + 0x6899ef3b645fcefd
    u = z3.BitVec('carry_input64',64)
    obj = run('common_carry_inverse', 0xfffffe000a5241c0, 0xfffffe000a5243d4,
        {'x8':u, 'x12':d & MASK, 'x11':p})
    q['common_carry_inverse'] = cell(obj,p,8) != (u - 0x6899ef3b645fcefd) ^ v
    new_o = (accumulator + (encoded_delta ^ w)) ^ v
    q['default_delta_preserves_object'] = z3.substitute(new_o, (encoded_delta,w)) != o

    # First part of the greater arm: prove separate operand deltas, then compose.
    obj = run('greater_fresh_delta', 0xfffffe000a5271bc, 0xfffffe000a527240,
        {'w21':0x3de, 'x15':l & MASK, 'x13':fold ^ resize(fresh,64)})
    source_phase = obj.read('w23')
    fresh_component = obj.read('x17')
    # The exact component is C - FOLD. A separate source fold cancels FOLD.
    q['greater_fresh_component'] = z3.Or(source_phase != 0x6e3,
        fresh_component != resize(fresh,64) - fold)
    obj = run('greater_stored_delta', 0xfffffe000a527240, 0xfffffe000a5272c8,
        {'x16':a & MASK, 'x14':field})
    clock_mask = (a & MASK) ^ K
    q['greater_stored_component'] = z3.Or(obj.read('x2') != old - clock_mask,
        obj.read('x1') != ~clock_mask)
    obj = run('greater_delta_join', 0xfffffe000a5272c8, 0xfffffe000a5272d8,
        {'x0':fold, 'x1':~clock_mask, 'x2':old-clock_mask, 'x17':resize(fresh,64)-fold})
    q['greater_clock_delta'] = z3.Or(obj.read('x17') != resize(fresh,64) - old,
        obj.read('x0') != fold-clock_mask)

    obj = run('greater_base_delta', 0xfffffe000a5272d8, 0xfffffe000a52737c,
        {'x11':p, 'x9':255, 'x10':t}, [(p+8,8,p), (p+16,8,field10), (p,8,o), (t+0x98,8,d)])
    q['greater_base_xor_delta'] = z3.Or(obj.read('x6') != accumulator-v, obj.read('x5') != v,
        obj.read('x1') != o, obj.read('x2') != d & MASK, obj.read('x3') != field10)
    obj = run('greater_complement_delta', 0xfffffe000a52737c, 0xfffffe000a52741c,
        {'x9':255, 'x10':t, 'x3':field10}, [(t+0x68,8,b)])
    q['greater_complement_xor_delta'] = z3.Or(obj.read('x19') != j-complement,
        obj.read('x7') != j,obj.read('x4') != b & MASK)
    obj = run('greater_elapsed_join', 0xfffffe000a52741c, 0xfffffe000a52742c,
        {'x5':v, 'x7':j, 'x6':accumulator-v, 'x19':j-complement})
    q['elapsed_from_object_words'] = obj.read('x5') != elapsed
    delta = z3.BitVec('clock_delta64',64)
    obj = run('greater_elapsed_partition', 0xfffffe000a52742c, 0xfffffe000a527440,
        {'x17':delta, 'x5':elapsed, 'w21':0x3de})
    q['greater_elapsed_partition'] = obj.read('w17') != z3.If(z3.UGT(delta,elapsed),
        z3.BitVecVal(0x876,32),z3.BitVecVal(0x3de,32))

    # Baseline complement is composed with the previously proved initializer.
    initial_field10 = o ^ ((d ^ b) & MASK) ^ 0x35659b426b46beb1
    q['initial_complement_relation'] = z3.substitute(complement,(field10,initial_field10)) != ~accumulator
    q['initial_elapsed_zero'] = accumulator + ~accumulator + 1 != 0

    obj = run('advance_fresh_component', 0xfffffe000a534e38, 0xfffffe000a534ec8,
        {'w21':0x3de, 'x15':l & MASK, 'x13':fold ^ resize(fresh,64)})
    q['advance_fresh_component'] = z3.Or(obj.read('w23') != 0x6e3,
        obj.read('x13') != resize(fresh,64)-fold)
    obj = run('advance_stored_component', 0xfffffe000a534ec8, 0xfffffe000a534f3c,
        {'x16':a & MASK, 'x14':field})
    q['advance_stored_component'] = obj.read('x14') != old-clock_mask
    obj = run('advance_complement_component', 0xfffffe000a534f3c, 0xfffffe000a534fc4,
        {'x4':b & MASK, 'x3':field10})
    q['advance_complement_component'] = z3.Or(obj.read('x16') != j-complement, obj.read('x15') != ~j)
    obj = run('advance_base_component', 0xfffffe000a534fc4, 0xfffffe000a53504c,
        {'x2':d & MASK, 'x1':o})
    q['advance_base_component'] = z3.Or(obj.read('x1') != accumulator-v, obj.read('x17') != ~v)
    obj = run('advance_increment_join', 0xfffffe000a53504c, 0xfffffe000a535068,
        {'x0':fold-clock_mask, 'x14':old-clock_mask, 'x15':~j, 'x17':~v,
         'x1':accumulator-v, 'x16':j-complement, 'x13':resize(fresh,64)-fold})
    increment = resize(fresh,64)-old-elapsed
    q['advance_increment_join'] = obj.read('x13') != increment
    inc = z3.BitVec('increment64',64)
    obj = run('advance_encode', 0xfffffe000a535068, 0xfffffe000a53509c,
        {'w9':255, 'x10':t, 'x13':inc}, [(t+0xd8,8,h)])
    q['advance_encoded_increment'] = z3.Or(obj.read('x13') != inc ^ w, obj.read('x15') != w)
    obj = run('advance_compare_operands', 0xfffffe000a53509c, 0xfffffe000a535194,
        {'x13':inc ^ w, 'x14':h & MASK, 'x8':w, 'x12':h & MASK, 'x15':w})
    bias=0x80cbbedb
    q['advance_compare_operands'] = z3.Or(obj.read('x16') != inc+bias,
        obj.read('x12') != -w, obj.read('x15') != w+bias, obj.read('w14') != bias)
    obj = run('advance_final_select', 0xfffffe000a535194, 0xfffffe000a5351c4,
        {'x16':inc+bias, 'x12':-w, 'x15':w+bias, 'w14':bias, 'x13':inc ^ w, 'x8':w})
    q['advance_final_select'] = obj.read('x8') != inc ^ w

    # High-water induction under the two preceding source gates. E and D are
    # arbitrary unsigned words; the fitting fresh-minus-old bound is separate.
    e, dc = z3.BitVecs('elapsed64 positive_clock_delta64',64)
    base = z3.BitVec('baseline64',64)
    accumulated = base+e
    update=z3.If(z3.UGT(dc,e),dc-e,z3.BitVecVal(0,64))
    next_accumulated=accumulated+update
    next_elapsed=next_accumulated-base
    q['high_water_update'] = next_elapsed != z3.If(z3.UGT(dc,e),dc,e)
    q['high_water_nondecreasing'] = z3.ULT(next_elapsed,e)
    q['clock_delta_fits_u32'] = z3.And(z3.UGT(resize(fresh,64),old),
        z3.Or(z3.UGT(old,0xffffffff),z3.UGT(resize(fresh,64)-old,0xffffffff)))
    q['high_water_u32_induction'] = z3.And(z3.ULE(e,0xffffffff),z3.ULE(dc,0xffffffff),
        z3.UGT(next_elapsed,0xffffffff))
    controls['decoded_accumulator_can_wrap'] = z3.And(z3.UGT(dc,e),
        z3.ULE(e,0xffffffff),z3.ULE(dc,0xffffffff),
        z3.ULT(next_accumulated,accumulated),z3.UGT(next_elapsed,e))

    fp, embedded = z3.BitVecs('reader_FP64 embedded_RW64',64)
    record=fp-0xb0
    obj = run('release_record', 0xfffffe000a52441c, 0xfffffe000a524460,
        {'x29':fp,'x8':embedded,'w23':0x6e3})
    release_key=resize((record ^ 0xdfb9786f)*0x1e2776fd,32)
    q['release_record'] = z3.Or(cell(obj,record,4) != release_key+0x1d3,
        cell(obj,record+8,8) != embedded)

    seed_c0, current_o = z3.BitVecs('seed_C0_64 current_object0_64',64)
    obj=run('release_fresh_member_and_views',0xfffffe000a5243d4,0xfffffe000a52441c,
        {'x20':0x55000000,'sp':f,'w1':0xa7d93298},
        [(0x55000000,8,p),(p+8,8,p),(p,8,current_o),(p+24,8,embedded),
         (f+0x198,8,0x53000000),(f+0x1a0,8,0x54000000),
         (0x53000000,8,t),(0x54000000,4,255),(t+0xc0,8,seed_c0),(t+0x98,8,d)])
    q['fresh_release_member_and_views']=z3.Or(obj.read('x8')!=embedded,obj.read('x19')!=current_o,
        obj.read('x21')!=seed_c0,obj.read('x22')!=d)
    obj=run('post_release_scalar',0xfffffe000a5244bc,0xfffffe000a5244c8,
        {'x22':d,'x21':seed_c0,'x19':current_o})
    scalar=current_o ^ ((d ^ seed_c0)&MASK)
    q['post_release_scalar']=obj.read('x8')!=scalar
    context=z3.BitVec('context_word178_64',64)
    obj=run('context_compare_operands',0xfffffe000a5244c8,0xfffffe000a5245cc,
        {'x8':scalar,'x26':0x53000000,'x24':0x54000000,'sp':f},
        [(f+0x1f8,8,0x55000000),(0x55000178,8,context),
         (0x53000000,8,t),(0x54000000,4,255),(t+0xc0,8,seed_c0)])
    current_decoded=current_o ^ v
    q['context_compare_operands']=z3.Or(obj.read('x24') != current_decoded+0x081864b3,
        obj.read('x26') != context+0xab53c9aef42360b8,
        obj.read('w11') != z3.If(z3.ULT(current_decoded+0x081864b3,0x081864b3),z3.BitVecVal(1,32),z3.BitVecVal(0,32)),
        obj.read('w21') != z3.If(z3.ULT(context+0xab53c9aef42360b8,0x081864b3),z3.BitVecVal(1,32),z3.BitVecVal(0,32)))

    obj=run('continuation_record_key',0xfffffe000a5245d8,0xfffffe000a52461c,{'x25':record})
    key64=(record ^ 0x4c2e944469e35e3f)*0x7a59c441
    q['continuation_record_key']=obj.read('x10')!=key64
    key_symbol=z3.BitVec('continuation_key64',64)
    obj=run('continuation_record_fields',0xfffffe000a52461c,0xfffffe000a524654,
        {'x29':fp,'x10':key_symbol,'w8':0xf6074c82,'w9':0xf6074dc1,'w23':0x6e3,'x22':d})
    lowkey=resize(key_symbol,32)
    q['continuation_record_fields']=z3.Or(cell(obj,record,8)!=key_symbol,
        cell(obj,record+8,4)!=0x392d87ef-lowkey,cell(obj,record+12,4)!=lowkey ^ 0xf6074dc1,
        cell(obj,record+20,4)!=lowkey ^ 0xf6074dd4,cell(obj,record+24,4)!=lowkey,
        cell(obj,record+28,4)!=0xf6074c82-lowkey,cell(obj,record+32,8)!=d-key_symbol)
    footprint=[{'pc':hex(s['pc']), 'offset_B':z3.simplify(s['address']-record).as_long(),
        'size_B':s['size_bytes']} for s in obj.stores]
    written={b for s in footprint for b in range(s['offset_B'],s['offset_B']+s['size_B'])}
    assert written==set(range(40))-set(range(16,20))
    return_index=z3.BitVec('helper_return_index32',32)
    target=z3.BitVec('helper_return_target64',64)
    signed_slot=resize(TABLE,64)+(z3.SignExt(32,return_index)<<3)
    obj=run('continuation_signed_index',0xfffffe000a5246b0,0xfffffe000a5246bc,
        {'x29':fp,'x28':TABLE},[(record+16,4,return_index),(signed_slot,8,target)])
    q['continuation_signed_index']=z3.Or(obj.values[(0xfffffe000a5246b4,'x8')]!=signed_slot,
        obj.read('x8')!=target)
    controls['return_index_needs_callee_contract']=z3.And(return_index==0xffffffff,
        signed_slot==resize(TABLE-8,64))

    results = {}
    for name, query in q.items():
        solver=z3.Solver();solver.set(timeout=10000);solver.add(query)
        result=solver.check();print(name,result,flush=True)
        assert result==z3.unsat,(name,str(result),solver.model() if result==z3.sat else solver.reason_unknown())
        results[name]={'result':str(result),'query':solver.sexpr()}
    counterexamples={}
    for name,query in controls.items():
        solver=z3.Solver();solver.set(timeout=10000);solver.add(query)
        assert solver.check()==z3.sat
        model=solver.model()
        counterexamples[name]={'result':'sat','query':solver.sexpr(),
            'model':{str(v):hex(model[v].as_long()) for v in sorted(model,key=str)}}
    return results, counts, counterexamples, footprint


def build():
    kernel=Kernel();spans=[]
    for name,bounds in SPANS.items():
        row=span(kernel,*bounds);row['bytes_hex']=row.pop('bytes');row['label']=name;spans.append(row)
    proofs,counts,controls,footprint=prove({'spans':spans})
    for row in IDA_READBACK['ranges']:
        assert kernel.read(int(row['address'],16),row['size_B']).hex()==row['bytes_hex']
    slot=pointer(kernel,TABLE+8*0x876)
    assert slot['target']=='0xfffffe000a534e34' and slot['authenticated'] and slot['diversity']=='0x4c8d'
    return {'scope':__doc__,'generator_sha256':sha(__file__),'spans':spans,'proofs':proofs,
        'source_lift_counts':counts,'negative_controls':controls,'IDA_readback':IDA_READBACK,
        'advance_slot':slot,'kernel_collection_sha256':kernel.sha256,'normalized_image_sha256':sha(SOURCE),
        'continuation_record_stores':footprint,
        'verified_counts':{'spans':len(spans),'instructions':sum(len(s['instructions']) for s in spans),
            'code_B':sum(len(bytes.fromhex(s['bytes_hex'])) for s in spans),
            'source_lifted_instances':sum(counts.values()),'queries_unsat':len(proofs),
            'negative_controls_sat':len(controls),'record_written_B':36,'record_envelope_B':40,
            'IDA_spotcheck_B':sum(r['size_B'] for r in IDA_READBACK['ranges'])},
        'selected_contract':{'conditional_incoming_phase32':'0x6e3','flag32':255,
            'fresh_clock_B':4,'accumulator_B':8,'elapsed_max':'0xffffffff',
            'actual_incoming_phase_proven':False,'actual_frame_roots_proven':False,
            'actual_helper_targets_proven':False,'upstream_request_recovered':False,
            'native_epoch_matched':False},
        'solver_version':z3.get_version_string(),'dependencies':{n:sha(ROOT/n) for n in [
            'kernel_native_reader.py','kext_port_tools.py','lskd_values_symbolic.py','recover_aes_cleanup_epoch.py',
            'recover_kext_cold_init.py','recover_lskd_clock_reader.py','lskd_clock_reader_checks.json',
            'lskd_clock_completion_checks.json','lskd_continuations_proofs.json',
            'verify_daemon_reader_record_payloads_publication.py']},
        'new_IDA_access':True,'new_native_execution':False,'new_IDB_mutations':False,'full_goal_complete':False}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--verify',action='store_true');args=parser.parse_args()
    output=build();path=ROOT/'lskd_clock_accumulator_checks.json'
    if args.verify:assert json.loads(read(path))==output
    else:path.write_text(json.dumps(output,indent=2)+'\n')
    print(json.dumps(output.get('verified_counts',{'queries':len(output['proofs'])})))
