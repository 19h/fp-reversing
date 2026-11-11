#!/usr/bin/env python3
"""Original AES configuration routing, command records and FIFO/trace contracts.

Static source certificates with explicit object, call and snapshot premises.
Payload values are symbolic; no native device/target execution or IDB mutation.
O(B+I+P) source/path expression time and space; SMT cost is separate.
"""
import argparse
import copy
import json

import z3
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_EXT_UXTB

from kernel_native_reader import Kernel
from kext_port_tools import ROOT
from recover_kext_aes_handoff import function
from recover_kext_cold_init import pointer
from recover_aes_dma_preparation import DMALift
from lskd_values_symbolic import resize, part
from verify_daemon_reader_record_payloads_publication import read, sha

F = 0xfffffe0053000000
H = 0xfffffe0009d40000
FUNCTIONS = {'configure': H+0xfcf8, 'key_command': H+0x107c4, 'dsb_command': H+0x10914,
             'space': H+0x11dfc, 'push': H+0x11e38, 'quantum': H+0x10a28}


class ConfigLift(DMALift):
    def width(self, name):
        return 128 if name.startswith(('q', 'v')) and name[1:].isdigit() else 32 if name.startswith('s') and name[1:].isdigit() else super().width(name)

    def key(self, name):
        if name.startswith(('q', 'v', 'd', 's')) and name[1:].isdigit(): return 'v'+name[1:]
        return super().key(name)

    def write(self, name, value):
        if self.key(name).startswith('v'):
            value = resize(value, self.width(name))
            self.regs[self.key(name)] = resize(value, 128)
            self.values[(self.pc, name)] = value
        else: super().write(name, value)

    def seed(self, name, value):
        if self.key(name).startswith('v'): self.regs[self.key(name)] = resize(value, 128)
        else: super().seed(name, value)

    def read(self, name):
        if self.key(name).startswith('v'):
            assert self.key(name) in self.regs, ('undefined vector', name)
            return resize(self.regs[self.key(name)], self.width(name))
        return super().read(name)

    def operand(self, ins, op, width):
        if op.ext == ARM64_EXT_UXTB:
            assert not op.shift.type
            return resize(self.read(ins.reg_name(op.reg)), width) & 255
        return super().operand(ins, op, width)

    def condition(self, name):
        if name == 'eq': return self.equal
        if name == 'ne': return z3.Not(self.equal)
        if name == 'gt': return self.cmp_left > self.cmp_right
        if name == 'hi': return z3.UGT(self.cmp_left, self.cmp_right)
        if name in ['hs', 'cs']: return z3.UGE(self.cmp_left, self.cmp_right)
        if name in ['lo', 'cc']: return z3.ULT(self.cmp_left, self.cmp_right)
        if name == 'ls': return z3.ULE(self.cmp_left, self.cmp_right)
        raise AssertionError(('unknown condition', name))

    def run(self, label):
        saved = self.c; row = next(r for r in saved['spans'] if r['label'] == label)
        cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); cs.detail = True
        raw = bytes.fromhex(row['bytes_hex']); insns = list(cs.disasm(raw, int(row['start'], 16)))
        assert len(insns)*4 == len(raw)
        for ins in insns:
            self.pc = ins.address; ops = ins.operands
            if ins.mnemonic == 'movi':
                assert ins.op_str in ['v0.2d, #0000000000000000', 'v0.2s, #2']
                self.write('q0', 0 if '.2d' in ins.op_str else 2 | (2 << 32)); self.count += 1
            elif ins.mnemonic == 'ld1':
                assert ins.op_str == '{v0.s}[1], [x8]'
                value = self.load(self.read('x8'), 4)
                self.write('q0', (self.read('q0') & ~resize(0xffffffff << 32, 128)) | (resize(value, 128) << 32)); self.count += 1
            elif ins.mnemonic == 'cinc':
                d, a = [ins.reg_name(o.reg) for o in ops[:2]]
                self.write(d, z3.If(self.condition(ins.op_str.rsplit(',', 1)[1].strip()), self.read(a)+1, self.read(a))); self.count += 1
            elif ins.mnemonic == 'csinc':
                d, a, b = [ins.reg_name(o.reg) for o in ops[:3]]
                self.write(d, z3.If(self.condition(ins.op_str.rsplit(',', 1)[1].strip()), self.read(a), self.read(b)+1)); self.count += 1
            elif ins.mnemonic == 'ubfx':
                self.write(ins.reg_name(ops[0].reg), z3.LShR(self.read(ins.reg_name(ops[1].reg)), ops[2].imm) & ((1 << ops[3].imm)-1)); self.count += 1
            elif ins.mnemonic == 'subs':
                d = ins.reg_name(ops[0].reg); width = self.width(d)
                a, b = self.operand(ins, ops[1], width), self.operand(ins, ops[2], width)
                self.write(d, a-b); self.equal = a-b == 0; self.cmp_left, self.cmp_right = a, b; self.count += 1
            else:
                self.c = {'spans': [{'label': label, 'start': hex(ins.address), 'bytes_hex': bytes(ins.bytes).hex()}]}
                super().run(label)
        self.c = saved
        return self


def fork(obj):
    other = copy.copy(obj)
    for name in ['regs', 'fixed', 'values']: setattr(other, name, getattr(obj, name).copy())
    for name in ['stores', 'byte_events', 'table_loads']: setattr(other, name, getattr(obj, name).copy())
    other.fixed_stores = obj.fixed_stores.copy()
    return other


def forest(capture, label, entry, stops, seeds, cells):
    """Fork only the original scalar routing instructions; calls are frontiers."""
    row = next(r for r in capture['spans'] if int(r['start'], 16) <= entry < int(r['end'], 16))
    cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); cs.detail = True
    code = {i.address: i for i in cs.disasm(bytes.fromhex(row['bytes_hex']), int(row['start'], 16))}
    obj = ConfigLift({'spans': []})
    for reg, value in seeds.items(): obj.seed(reg, value)
    for at, n, value in cells: obj.fixed[(z3.simplify(resize(at, 64)).sexpr(), n)] = resize(value, n*8)
    pending = [(entry, obj, z3.BoolVal(True), [])]; leaves = []
    while pending:
        pc, obj, predicate, visits = pending.pop()
        assert len(visits) < 64
        if pc in stops:
            leaves.append((pc, obj, predicate, visits)); continue
        ins = code[pc]; visits = visits+[pc]; m = ins.mnemonic; ops = ins.operands
        if m == 'b': pending.append((ops[0].imm & ((1 << 64)-1), obj, predicate, visits)); continue
        condition = None
        if m.startswith('b.'): condition = obj.condition(m[2:])
        elif m in ['cbz', 'cbnz']:
            condition = obj.read(ins.reg_name(ops[0].reg)) == 0
            if m == 'cbnz': condition = z3.Not(condition)
        if condition is not None:
            pending.append((ops[-1].imm & ((1 << 64)-1), fork(obj), z3.And(predicate, condition), visits))
            pending.append((pc+4, fork(obj), z3.And(predicate, z3.Not(condition)), visits))
        else:
            assert m in ['mov', 'cmp', 'sub', 'ldr', 'ubfx', 'csel']
            obj.c = {'spans': [{'label': label, 'start': hex(pc), 'bytes_hex': bytes(ins.bytes).hex()}]}
            obj.run(label); pending.append((pc+4, obj, predicate, visits))
    return leaves


def prove(capture):
    queries, pieces, counts = {}, {}, {}
    provider, command, key, source, packet = z3.BitVecs('provider64 command64 key_metadata64 source64 packet64', 64)
    operation, header, selector, channel, status, index = z3.BitVecs('operation32 header32 selector32 channel32 FIFO_status32 trace_index32', 32)
    data0, data1, extra = z3.BitVecs('declared_payload0_128 declared_payload1_128 declared_extra128', 128)

    def run(name, a, z, seeds, cells=(), writes=()):
        obj = ConfigLift(part(capture, name, a, z))
        for reg, value in seeds.items(): obj.seed(reg, value)
        for at, n, value in cells: obj.fixed[(z3.simplify(resize(at, 64)).sexpr(), n)] = resize(value, n*8)
        for at, n in writes: obj.fixed_stores.add((z3.simplify(resize(at, 64)).sexpr(), n))
        obj.run(name); assert obj.count == (z-a)//4
        pieces[name] = {'start': hex(a), 'end': hex(z), 'instructions': obj.count}; counts[name] = obj.count
        return obj

    def cell(obj, at, n): return obj.fixed[(z3.simplify(resize(at, 64)).sexpr(), n)]

    operation_leaves = forest(capture, 'operation_forest', H+0xfd3c, {H+0xfdb8, H+0xfe68, H+0x10028},
        {'x1': command, 'x21': command}, [(command+0x40, 4, operation), (command+0x48, 8, key), (key+0x24, 4, header)])
    admitted = z3.Or(z3.ULE(operation, 5), z3.And(operation == 6, header == 3102))
    accepted = z3.Or(*[p for pc, _, p, _ in operation_leaves if pc == H+0xfdb8])
    queries['operation_partition'] = accepted != admitted
    mode = z3.If(z3.Or(operation == 0, operation == 1), resize(0x10000, 32), z3.If(z3.Or(operation == 4, operation == 5), resize(0x20000, 32), resize(0, 32)))
    direction = z3.If(z3.Or(operation == 0, operation == 2, operation == 4, operation == 5), resize(0x100000, 32), resize(0, 32))
    for j, (pc, obj, predicate, _) in enumerate(operation_leaves):
        if pc == H+0xfdb8:
            queries[f'operation_flags_leaf_{j}'] = z3.And(predicate, z3.Or(obj.read('w24') != mode, obj.read('w25') != direction))
    obj = run('selector_strip', H+0xfdcc, H+0xfdd4, {'w28': header, 'x27': key}, writes=[(key+0x24, 4)])
    queries['selector_strip'] = z3.Or(obj.read('w10') != (header & 0x7fffffff), cell(obj, key+0x24, 4) != (header & 0x7fffffff))
    queries['selector_strip_both_arms'] = z3.If((header & 0x80000000) != 0, obj.read('w10'), header) != (header & 0x7fffffff)
    stops = {H+0x10048: [0], H+0x100c4: [1000], H+0xfe00: [1001], H+0x100a4: [2000],
             H+0x100e4: [2001], H+0xff74: [3000, 3100], H+0xfeb4: [3102], H+0xfe4c: [4000, 4001, 4002, 4003], H+0x100fc: []}
    selector_leaves = forest(capture, 'selector_forest', H+0xfddc, set(stops), {'w10': selector}, [])
    recognized = sorted({n for group in stops.values() for n in group})
    for stop, values in stops.items():
        predicate = z3.Or(*[p for pc, _, p, _ in selector_leaves if pc == stop])
        expected = z3.Or(*[selector == n for n in values]) if values else z3.Not(z3.Or(*[selector == n for n in recognized]))
        queries['selector_frontier_'+hex(stop)] = z3.And(z3.ULT(selector, 1 << 31), predicate != expected)

    obj = run('configuration_arguments', H+0xfd20, H+0xfd2c, {'x0': provider, 'x1': command, 'x2': resize(channel, 64)})
    queries['configuration_arguments'] = z3.Or(obj.read('x19') != provider, obj.read('x21') != command, obj.read('w20') != channel)
    obj = run('quantum_configuration_arguments', H+0x10d40, H+0x10d4c, {'x19': provider, 'x22': command})
    queries['quantum_configuration_arguments'] = z3.Or(obj.read('x0') != provider, obj.read('x1') != command, obj.read('w2') != 0)
    obj = run('FIFO_sleep_arguments', H+0x1025c, H+0x10264, {'x19': provider})
    queries['FIFO_sleep_arguments'] = z3.Or(obj.read('x1') != provider+0x150, obj.read('w2') != 2)
    obj = run('scratch_zero32', H+0xfdd4, H+0xfddc, {'sp': F}, writes=[(F+0x40, 16), (F+0x50, 16)])
    queries['scratch_zero32'] = z3.Or(cell(obj, F+0x40, 16) != 0, cell(obj, F+0x50, 16) != 0)
    obj = run('selector_4000_flags', H+0xfe4c, H+0xfe64, {'w10': selector})
    queries['selector_4000_flags'] = z3.Or(obj.read('w13') != 0, obj.read('w9') != 0,
        obj.read('w8') != 0x64000000+(selector << 24), obj.read('w28') != ((selector & 3) << 23), obj.read('w26') != 0x02000000)
    obj = run('selector_3000_3100_index', H+0xff74, H+0xff80, {'w10': selector})
    queries['selector_3000_3100_index'] = obj.read('w23') != z3.If(selector == 3000, resize(2, 32), resize(3, 32))
    key_bits = z3.BitVec('key_width_header32', 32)
    obj = run('inline_width_and_data', H+0x1006c, H+0x1008c, {'w9': key_bits, 'x27': key},
              [(key+4, 16, data0), (key+0x14, 16, data1)])
    size_flags = z3.If(key_bits == 256, resize(0x800000, 32), z3.If(key_bits == 192, resize(0x400000, 32), resize(0, 32)))
    queries['inline_width_and_data'] = z3.Or(obj.read('w9') != size_flags, obj.read('q0') != data0, obj.read('q1') != data1)
    obj = run('inline_data_scratch', H+0x1009c, H+0x100a0, {'sp': F, 'q0': data0, 'q1': data1}, writes=[(F+0x40, 16), (F+0x50, 16)])
    queries['inline_data_scratch'] = z3.Or(cell(obj, F+0x40, 16) != data0, cell(obj, F+0x50, 16) != data1)
    obj = run('channel_word', H+0x101d0, H+0x101e0, {'w20': channel})
    channel_word = z3.If(channel == 0, resize(0x10000000, 32), resize(0x18000000, 32))
    queries['channel_word'] = obj.read('w11') != channel_word
    slot, key_flags, ext_flags, kind_flags, direction_flags = z3.BitVecs('slot32 key_flags32 extension_flags32 kind_flags32 direction_flags32', 32)
    obj = run('command_word_merge', H+0x101e0, H+0x101f8,
              {'w13': slot, 'w9': key_flags, 'w10': ext_flags, 'w11': channel_word, 'w8': kind_flags, 'w25': direction_flags})
    queries['command_word_merge'] = obj.read('w25') != key_flags | ext_flags | channel_word | kind_flags | ((slot & 255) << 18) | direction_flags
    iv_flags, route_flags = z3.BitVecs('IV_flags32 route_flags32', 32)
    obj = run('IV_command_header', H+0x1038c, H+0x103a4, {'sp': F, 'w26': iv_flags, 'w20': channel, 'w28': route_flags},
              writes=[(F+0x24, 8), (F+0x1c, 8), (F+0x18, 4)])
    iv_header = (iv_flags & ~0x0c000000) | ((channel & 3) << 26) | route_flags | 0x20000000
    queries['IV_command_header'] = z3.Or(cell(obj, F+0x18, 4) != iv_header, cell(obj, F+0x1c, 8) != 0, cell(obj, F+0x24, 8) != 0)
    obj = run('IV_command_payload', H+0x103a8, H+0x103b4, {'sp': F, 'x8': source}, [(source, 16, data0)], [(F+0x1c, 16)])
    queries['IV_command_payload'] = cell(obj, F+0x1c, 16) != data0
    obj = run('IV_command_call', H+0x103b4, H+0x103c0, {'sp': F, 'x19': provider})
    queries['IV_command_call'] = z3.Or(obj.read('x0') != provider, obj.read('x1') != F+0x18, obj.read('w2') != 20)
    obj = run('configure_zero_result', H+0x103c8, H+0x103cc, {})
    queries['configure_zero_result'] = obj.read('x19') != 0
    obj = run('key_command_zero64', H+0x107e4, H+0x107f4, {'sp': F, 'w1': header}, writes=[(F+o, 16) for o in [0x20, 0x30, 0x40, 0x50]]+[(F+0x1c, 4)])
    queries['key_command_zero64'] = z3.Or(cell(obj, F+0x1c, 4) != header, *[cell(obj, F+o, 16) != 0 for o in [0x20, 0x30, 0x40, 0x50]])
    obj = run('extended_key_record', H+0x10838, H+0x10858, {'sp': F, 'x3': source, 'x20': key, 'x19': provider, 'w2': header},
              [(source, 16, extra), (key, 16, data0), (key+16, 16, data1)],
              [(F+0x20, 4), (F+0x30, 16), (F+0x40, 16), (F+0x50, 16)])
    queries['extended_key_record'] = z3.Or(cell(obj, F+0x20, 4) != header, cell(obj, F+0x30, 16) != extra,
        cell(obj, F+0x40, 16) != data0, cell(obj, F+0x50, 16) != data1,
        obj.read('x0') != provider, obj.read('x1') != F+0x1c, obj.read('w2') != 68)
    size_leaves = forest(capture, 'key_size_forest', H+0x10864, {H+0x108b4, H+0x10894}, {'w1': header}, [])
    code = z3.LShR(header, 22) & 3
    expected_bytes = z3.If(code == 0, resize(16, 32), z3.If(code == 1, resize(24, 32), resize(32, 32)))
    for j, (pc, obj, predicate, _) in enumerate(size_leaves):
        if pc == H+0x108b4: queries[f'key_size_leaf_{j}'] = z3.And(predicate, obj.read('w21') != expected_bytes)
    queries['key_size_partition'] = z3.Or(*[p for pc, _, p, _ in size_leaves if pc == H+0x108b4]) != (code != 3)
    selected_code = z3.LShR(size_flags, 22) & 3
    selected_bytes = z3.If(selected_code == 0, resize(16, 32), z3.If(selected_code == 1, resize(24, 32), resize(32, 32)))
    queries['key_width_unit_relation'] = z3.And(z3.Or(key_bits == 128, key_bits == 192, key_bits == 256), selected_bytes*8 != key_bits)
    num_bytes = z3.BitVec('command_byte_count32', 32)
    obj = run('FIFO_available', H+0x11e08, H+0x11e24, {'w1': num_bytes, 'x0': provider},
              [(provider+0x178, 8, source), (source+0x24, 4, status)])
    occupied = z3.LShR(status, 8) & 255
    words = z3.LShR(num_bytes, 2)
    queries['FIFO_available'] = obj.read('w0') != z3.If(z3.ULE(words+occupied, 128), resize(1, 32), resize(0, 32))
    queries['FIFO_addition_no_wrap'] = z3.ZeroExt(32, words+occupied) != z3.ZeroExt(32, words)+z3.ZeroExt(32, occupied)
    obj = run('trace_pointer_scale', H+0x11eb8, H+0x11ed4, {'x20': provider, 'x24': provider+0x1fc}, [(provider+0x9fc, 4, index)])
    queries['trace_pointer_scale'] = z3.And(z3.ULE(index, 255), z3.Or(obj.read('x10') != z3.ZeroExt(32, index)*8,
        obj.read('x11') != provider+0x1fc+z3.ZeroExt(32, index)*8))
    obj = run('trace_record', H+0x11ed4, H+0x11ee0, {'x8': source, 'x11': packet}, [(source, 4, header)], [(packet, 8)])
    queries['trace_record'] = cell(obj, packet, 8) != z3.Concat(header, resize(2, 32))
    obj = run('trace_index_update', H+0x11ee0, H+0x11ef0, {'w9': index, 'x20': provider}, writes=[(provider+0x9fc, 4)])
    next_index = cell(obj, provider+0x9fc, 4)
    queries['trace_index_update'] = next_index != z3.If(z3.ULT(index, 255), index+1, resize(0, 32))
    queries['trace_index_bounded_after_update'] = z3.UGT(next_index, 255)
    queries['trace_current_record_extent'] = z3.And(z3.ULE(index, 255),
        z3.Or(z3.ULT(0x1fc+z3.ZeroExt(32, index)*8, 0x1fc), z3.UGT(0x1fc+z3.ZeroExt(32, index)*8+8, 0x9fc)))
    version = z3.BitVec('hardware_version32', 32)
    word_index, remaining_words = z3.BitVecs('emitter_word_index64 remaining_words64', 64)
    obj = run('MMIO_word_emission', H+0x11ef0, H+0x11f0c,
        {'x20': provider, 'x19': key, 'x22': word_index, 'x25': 0x200, 'x26': 0x100},
        [(provider+0x128, 4, version), (key+(word_index << 2), 4, header), (provider+0x178, 8, source)],
        [(source+z3.If(version == 0, resize(0x100, 64), resize(0x200, 64)), 4)])
    queries['MMIO_word_emission'] = cell(obj, source+z3.If(version == 0, resize(0x100, 64), resize(0x200, 64)), 4) != header
    obj = run('emitter_loop_start', H+0x11e80, H+0x11e88, {'w21': num_bytes})
    queries['emitter_loop_start'] = z3.Or(obj.read('x22') != 0, obj.read('x23') != z3.ZeroExt(32, words))
    obj = run('emitter_loop_step', H+0x11f0c, H+0x11f14, {'x22': word_index, 'x23': remaining_words})
    queries['emitter_loop_step'] = z3.Or(obj.read('x22') != word_index+1, obj.read('x23') != remaining_words-1, obj.equal != (remaining_words == 1))
    queries['emitter_loop_extent'] = z3.And((num_bytes & 3) == 0, z3.ULT(word_index, z3.ZeroExt(32, words)),
        z3.Or(z3.UGT((word_index << 2)+4, z3.ZeroExt(32, num_bytes)), z3.UGT(word_index+1, z3.ZeroExt(32, words))))
    obj = run('dsb_record', H+0x10944, H+0x10960, {'sp': F, 'x1': key, 'x2': source},
        [(key, 16, data0), (source, 16, data1)], [(F+0xc, 4), (F+0x10, 16), (F+0x20, 16)])
    queries['dsb_record'] = z3.Or(cell(obj, F+0xc, 4) != 0x30000000, cell(obj, F+0x10, 16) != data0,
        cell(obj, F+0x20, 16) != data1, obj.read('x1') != F+0xc, obj.read('w2') != 36)
    controls = {'width_units_require_recognized_header': selected_bytes*8 != key_bits}
    for label, leaves in [('operation', operation_leaves), ('selector', selector_leaves), ('key_size', size_leaves)]:
        predicates = [p for _, _, p, _ in leaves]
        queries[label+'_forest_coverage'] = z3.Not(z3.Or(*predicates))
        queries[label+'_forest_disjoint'] = z3.Or(*[z3.And(a, b) for j, a in enumerate(predicates) for b in predicates[j+1:]])
    return finish(capture, queries, controls, pieces, counts, operation_leaves, selector_leaves, size_leaves, recognized)


def finish(capture, queries, controls, pieces, counts, operation_leaves, selector_leaves, size_leaves, recognized):
    proofs = {}
    for name, query in queries.items():
        solver = z3.Solver(); solver.set(timeout=15000); solver.add(query); result = solver.check()
        assert result == z3.unsat, (name, str(result), solver.reason_unknown())
        proofs[name] = {'result': 'unsat', 'query': solver.sexpr()}; print(name, result, flush=True)
    negative = {}
    for name, query in controls.items():
        solver = z3.Solver(); solver.set(timeout=15000); solver.add(query); assert solver.check() == z3.sat
        negative[name] = {'result': 'sat', 'query': solver.sexpr(), 'scope': 'Abstract interpretation-premise control; no native input or reachability claim.'}
    def ledger(leaves):
        rows = []
        for pc, _, predicate, visits in leaves:
            solver = z3.Solver(); solver.set(timeout=15000); solver.add(predicate); assert solver.check() == z3.sat
            rows.append({'frontier': hex(pc), 'path_condition': predicate.sexpr(), 'path': [hex(a) for a in visits],
                         'declared_scalar_feasibility': 'sat', 'feasibility_query': solver.sexpr()})
        return rows
    return {'proofs': proofs, 'negative_controls': negative, 'source_pieces': pieces, 'source_lift_counts': counts, 'recognized_selectors': recognized,
            'operation_source_paths': ledger(operation_leaves), 'selector_source_paths': ledger(selector_leaves),
            'key_size_source_paths': ledger(size_leaves),
            'verified_counts': {'queries_unsat': len(proofs), 'controls_sat': len(negative), 'source_pieces': len(pieces), 'source_lifted_instances': sum(counts.values()),
                                'operation_source_paths': len(operation_leaves), 'selector_source_paths': len(selector_leaves), 'key_size_source_paths': len(size_leaves),
                                'scalar_path_feasibility_sat': len(operation_leaves)+len(selector_leaves)+len(size_leaves)}}


def build():
    k = Kernel(); entry = next(e for e in k.entries if e['name'] == 'com.apple.driver.AppleS8000AES')
    spans = []
    for label, address in FUNCTIONS.items():
        row = function(k, entry, address); row['label'] = label; spans.append(row)
    slots = {hex(a): pointer(k, a) for a in [0xfffffe00082fe588, 0xfffffe00082fe658, 0xfffffe0007f3fdb0]}
    for label, address in [('synchronize_stub', H+0x12af4), ('copy_stub', H+0x12c94)]:
        raw = k.read(address, 16)
        spans.append({'label': label, 'start': hex(address), 'end': hex(address+16), 'bytes_hex': raw.hex(),
                      'instructions': [{'ea': hex(i.address), 'mnemonic': i.mnemonic, 'operands': i.op_str} for i in k.cs.disasm(raw, address)]})
    result = prove({'spans': spans})
    configure = next(r for r in spans if r['label'] == 'configure')
    result['configuration_error_word_sites'] = [r['ea'] for r in configure['instructions'] if r['mnemonic'] == 'mov' and r['operands'] == 'w19, #0x2c2']
    result['verified_counts'].update(spans=len(spans), instructions=sum(len(r['instructions']) for r in spans),
        code_B=sum(len(bytes.fromhex(r['bytes_hex'])) for r in spans), original_slots=len(slots))
    return {'scope': __doc__, 'generator_sha256': sha(__file__), 'kernel_collection_sha256': k.sha256,
            'spans': spans, 'slots': slots, 'exact_symbols': k.symbols(list(FUNCTIONS.values())+[int(r['target'], 16) for r in slots.values()]),
            'dependencies': {n: sha(ROOT/n) for n in ['kernel_native_reader.py', 'recover_kext_aes_handoff.py', 'recover_kext_cold_init.py',
                'recover_aes_dma_preparation.py', 'aes_dma_preparation_checks.json', 'aes_quantum_binding_source.json',
                'aes_provider_admission_checks.json', 'lskd_values_symbolic.py', 'verify_daemon_reader_record_payloads_publication.py']},
            'solver_version': z3.get_version_string(), 'new_IDA_access': False, 'new_native_execution': False,
            'actual_key_bytes_captured': False, 'new_IDB_mutations': False, 'full_goal_complete': False, **result}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--verify', action='store_true'); args = parser.parse_args()
    result = build(); path = ROOT/'aes_configuration_commands_checks.json'
    if args.verify: assert json.loads(read(path)) == result
    else: path.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result['verified_counts']))
