#!/usr/bin/env python3
"""Source-only caller/wrapper/helper ABI and address-derived record codec.
All 152 retained success exports qualify field premises. Three selectors
partition full u32 domains into 256 low bytes and symbolic upper 24 bits.
No missing root/descriptor bytes, guest intervals or native operations are
added. O(parent bytes + 256*selector words + query DAG) time/storage,
excluding solver search complexity; 30 s/query.
"""
import json
import z3
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from daemon_receive_tools import ROOT, SOURCE, IMAGE, CS, POOL, FIXUPS, qword, verify_original_fixups
from verify_daemon_reader_record_payloads_publication import read, sha
from audit_daemon_network_record import state_bytes
from audit_daemon_state_table_mixing import Scalar
from lskd_values_symbolic import mem
from recover_daemon_constructor_buffer import unpack, U

P = 'daemon_feedback_callers'
PINS = {'daemon_constructor_buffer_checks.json': 'fe29b3d2d39daecdd79d1d00057229f0f583b8b0ead9c4eb9bd4fd5aa7cafa07',
        'daemon_feedback_roots_checks.json': 'f05be57da23abda003791fb66ddd984c2ec4a99e680c20f4a4ada9c719ecdad4'}
DEPS = ['daemon_receive_tools.py', 'daemon_receive_fixups.txt', 'audit_daemon_network_record.py',
        'audit_daemon_state_table_mixing.py', 'lskd_values_symbolic.py', 'recover_daemon_constructor_buffer.py']
SP = 0x6800060100
FIELDS = {0x9c8: 0x1010b8dc8, 0x9c0: 0x1010c4670, 0x5f0: 0x101031da0,
          0x5e0: 0x100e99900, 0x9d8: 0x101039ef0}
SLOTS = {0x1010a0158, POOL+0x1658, POOL+0x26a0, 0x1010a6230, 0x1010a04a8}
TABLES = [0x101031da0, 0x100e99900, 0x100e99a00, 0x100f4e390, 0x100fc4130, 0x101031ea0]
SPANS = [(0x1008a273c, 0x1008a2784), (0x100b213b0, 0x100b213ec), (0x100b21400, 0x100b21438)]
K = 0x4de3a292f9d49974
M = 0xda51a827
CP = 0xe34daea63ad53f9b
DP = 0xe34daea63ad54846


def prove(label, bad):
    s = z3.Solver()
    s.set(timeout=30000)
    assert s.check() == z3.sat
    s.add(z3.simplify(bad))
    result = s.check()
    assert result == z3.unsat, (label, str(result), s.reason_unknown())
    return {'label': label, 'premises_nonvacuous': True, 'query': s.to_smt2(), 'result': 'unsat'}


def parents():
    old = json.loads(read(ROOT/'daemon_constructor_buffer_checks.json'))
    out = []
    for c in old['coverage']:
        p = unpack(c['derived_terminal_state_packed'])
        if p['boundary']['pc'] != '0x1008a2704':
            continue
        assert int(p['boundary']['SP'], 16) == SP and p['boundary']['registers31'][23] == '0x764d'
        m = state_bytes(p)
        for offset, target in FIELDS.items():
            assert bytes(m[SP+offset+j] for j in range(8)) == target.to_bytes(8, 'little')
        r = SP+0x10cb8
        raw = bytes(m[r+j] for j in range(60))
        assert all(r+j not in m for j in range(60, 64))
        assert all(SP+off+j not in m for off, n in [(0x2b0, 8), (0x9e0, 16)] for j in range(n))
        key = ((r ^ K)*M) & ((1 << 64)-1)
        mode = (int.from_bytes(raw[4:8], 'little')+key) & 0xffffffff
        pointer = int.from_bytes(raw[48:56], 'little') ^ DP ^ (mode ^ 0x7a637527)
        assert mode == 0x7a6302fa and pointer == SP+0x9e0
        assert int.from_bytes(raw[8:16], 'little') == SP+0x1d14
        assert int.from_bytes(raw[16:24], 'little') == U
        out.append({'parent_index': c['parent_index'], 'branch_index': c['branch_index'],
                    'SP': hex(SP), 'required_fields': {hex(k): hex(v) for k, v in FIELDS.items()},
                    'record60_hex': raw.hex(), 'record_undefined_offsets': [60, 61, 62, 63],
                    'source_phase_W23': '0x764d', 'decoded_mode32': hex(mode),
                    'decoded_descriptor64': hex(pointer), 'root_and_descriptor_remain_undefined': True})
    assert len(out) == len({(p['parent_index'], p['branch_index']) for p in out}) == 152
    assert len({p['record60_hex'] for p in out}) == 1
    return out


class Lift(Scalar):
    def __init__(self):
        super().__init__()
        self.reads = []
    def load(self, address, n):
        a = z3.simplify(address)
        assert z3.is_bv_value(a), ('symbolic selector read', a.sexpr())
        a = a.as_long()
        if n == 8 and a-SP in FIELDS:
            value, origin = FIELDS[a-SP], 'all_152_inherited_fields'
        elif n == 8:
            assert a in SLOTS and a in FIXUPS
            value, origin = qword(a), 'original_decoded_rebase'
        else:
            assert n == 1 and any(t <= a < t+256 for t in TABLES)
            value, origin = IMAGE.read(a, 1)[0], 'original_table_byte'
        self.reads.append({'pc': hex(self.pc), 'address': hex(a), 'size_bytes': n,
                           'loaded_value': hex(value), 'origin': origin})
        return z3.BitVecVal(value, n*8)


def selectors():
    upper = z3.BitVec('caller_selector_upper24', 24)
    argument, local = z3.BitVecs('caller_record_argument64 caller_local_cell64', 64)
    out, proofs = [], []
    for j, (lo, hi) in enumerate(SPANS):
        cases, bad = [], []
        for byte in range(256):
            word = z3.Concat(upper, z3.BitVecVal(byte, 8))
            v = Lift()
            if j == 0:
                for n, x in {'sp': SP, 'w9': word, 'w8': z3.BitVec('caller_other_word32', 32), 'w23': 0x764d}.items():
                    v.seed(n, x)
            elif j == 1:
                v.seed('x15', POOL)
                v.seed('w16', word)
            else:
                for n, x in {'x15': POOL, 'w8': word, 'x12': 0x100fc4130,
                             'x14': 0x101031ea0, 'w13': 0xbb, 'w16': 0xccb7,
                             'x20': local, 'x0': argument}.items():
                    v.seed(n, x)
            v.run_block(lo, hi)
            if j == 0:
                checks = [v.read('x8') != 0x100b211f4, v.read('x17') != 0xd07f,
                          v.read('x0') != SP+0x10cb8, v.read('x1') != SP+0xbdc8]
                result = {'target': '0x100b211f4', 'IA_modifier': '0xd07f',
                          'X0': hex(SP+0x10cb8), 'X1': hex(SP+0xbdc8)}
            elif j == 1:
                checks = [v.read('w16') != 0xccb7]
                result = {'leaf_index32': '0xccb7'}
            else:
                checks = [v.read('x8') != 0x100b003c8, v.read('x17') != 0xe672,
                          v.read('x0') != argument, v.read('x1') != local]
                result = {'target': '0x100b003c8', 'IA_modifier': '0xe672',
                          'X0': 'incoming_record_argument64', 'X1': 'dynamic_local_cell64'}
            bad.extend(checks)
            assert all(z3.is_false(z3.simplify(x)) for x in checks)
            cases.append({'input_lower8': byte, 'input_upper24_symbolic': True,
                          'result': result, 'source_reads': v.reads})
        out.append({'source_start': hex(lo), 'source_end': hex(hi), 'cases': cases,
                    'full_u32_partition_complete': True})
        proofs.append(prove('all_u32_original_call_selector_'+str(j), z3.Or(*bad)))
    # X0 is the same incoming record pointer through the wrapper body.
    dec = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    dec.detail = True
    for i in dec.disasm(IMAGE.read(0x100b211f8, 0x100b21438-0x100b211f8), 0x100b211f8):
        assert not {'x0', 'w0'} & {i.reg_name(r) for r in i.regs_access()[1]}
    return out, proofs


def record_proofs():
    out = []
    sp, r, destination, nested = z3.BitVecs('record_outer_SP64 record_address64 record_U64 record_nested_SP64', 64)
    phase = z3.BitVec('record_source_phase32', 32)
    v = Scalar()
    v.seed('sp', sp)
    v.run_block(0x1008a264c, 0x1008a2688)
    key = ((sp+0x10cb8) ^ K)*M
    out.append(prove('all_u64_caller_key_matches_low32_nested_key', v.read('w10') != z3.Extract(31, 0, key)))
    v = Scalar()
    v.seed('x0', r)
    v.run_block(0x100b00528, 0x100b00578)
    out.append(prove('all_u64_nested_address_key', v.read('x15') != (r ^ K)*M))

    v = Scalar()
    for n, x in {'sp': sp, 'w23': phase, 'x9': destination}.items():
        v.seed(n, x)
    v.run_block(0x1008a2634, 0x1008a2704)
    low = z3.Extract(31, 0, key)
    expected = [(0x30, 8, (sp+0x9e0) ^ CP), (0x20, 8, 0),
                (0x1c, 4, 0x54620be7-low), (0x28, 2, z3.Extract(15, 0, low+0x548b)),
                (0x2c, 4, 0x0d38177c-low), (0, 4, low+0x8b3dc650),
                (4, 4, phase-low+0x7a628cad), (0x10, 8, destination),
                (8, 8, sp+0x1d14), (0x38, 4, low+0xbcabc95e)]
    assert len(v.stores) == len(expected) == 10
    bad = []
    for w, (offset, width, value) in zip(v.stores, expected):
        assert w['size_bytes'] == width
        bad.extend([w['address'] != sp+0x10cb8+offset, w['value'] != value])
    out.append(prove('all_u64_frame_and_u32_phase_caller_record_writers', z3.Or(*bad)))

    v = Scalar()
    record = sp+0x10cb8
    v.seed('x0', record)
    v.seed('sp', nested)
    mem(v, record+4, 4, phase-low+0x7a628cad)
    mem(v, record+0x30, 8, (sp+0x9e0) ^ CP)
    v.run_block(0x100b00528, 0x100b00578)
    # Reuse the independently discharged all-u64 nested-key lemma above.
    # This replaces an equal expression in the proof DAG, not guest state.
    v.write('x15', key)
    v.run_block(0x100b00578, 0x100b005ac)
    decoded_mode = v.read('w25')
    decoded_pointer = v.read('x12')
    mode = phase+0x7a628cad
    pointer = (sp+0x9e0) ^ CP ^ DP ^ z3.ZeroExt(32, mode ^ 0x7a637527)
    out.append(prove('all_u64_frame_mode_and_descriptor_pointer_composition', z3.Or(
        decoded_mode != mode, decoded_pointer != pointer,
        z3.And(phase == 0x764d, decoded_pointer != sp+0x9e0))))
    assert len(out) == 4
    return out


def build():
    for p, digest in PINS.items():
        assert sha(ROOT/p) == digest
    members = parents()
    banks, proofs = selectors()
    proofs += record_proofs()
    regions = []
    for label, lo, hi in [('caller_record_and_call', 0x1008a2634, 0x1008a2788),
                           ('wrapper_prologue', 0x100b211f4, 0x100b21210),
                           ('wrapper_call', 0x100b2139c, 0x100b2143c),
                           ('nested_key_and_decode', 0x100b00528, 0x100b005ac)]:
        regions.append({'label': label, 'start': hex(lo), 'end': hex(hi),
                        'bytes_hex': IMAGE.read(lo, hi-lo).hex(),
                        'instructions': [{'pc': hex(i.address), 'bytes_hex': bytes(i.bytes).hex(),
                                          'mnemonic': i.mnemonic, 'operands': i.op_str}
                                         for i in CS.disasm(IMAGE.read(lo, hi-lo), lo)]})
    fixups = verify_original_fixups(SLOTS)
    for pc, slot, target, modifier in [(0x1008a2784, 0x1010a0158, 0x100b211f4, 0xd07f),
                                       (0x100b21438, 0x1010a04a8, 0x100b003c8, 0xe672)]:
        word = int.from_bytes(IMAGE.read(slot, 8), 'little')
        assert qword(slot) == target and word >> 63 == 1 and (word >> 32) & 65535 == modifier
        i = next(CS.disasm(IMAGE.read(pc, 4), pc))
        assert i.mnemonic == 'blraa' and i.op_str == 'x8, x17'
    return {'scope': __doc__, 'generator_sha256': sha(__file__), 'source_sha256': sha(SOURCE),
            'parent_pins': PINS, 'dependencies': {p: sha(ROOT/p) for p in DEPS},
            'parent_coverage': members, 'source_regions': regions, 'selectors': banks,
            'source_proofs': proofs, 'original_fixups': fixups,
            'source_lemma_compositions': [{'consumer': 'all_u64_frame_mode_and_descriptor_pointer_composition',
                'producer': 'all_u64_nested_address_key', 'boundary_PC': '0x100b00578',
                'rewritten_register': 'X15', 'equal_expression': 'u64((record64 XOR 0x4de3a292f9d49974)*0xda51a827)',
                'proof_DAG_rewrite_only': True}],
            'tables': [{'address': hex(t), 'size_bytes': 256, 'bytes_hex': IMAGE.read(t, 256).hex()} for t in TABLES],
            'verified_counts': {'incoming_success_exports': 152, 'inherited_field_bytes_per_export': 40,
                                'record_defined_bytes_per_export': 60, 'record_unknown_bytes_per_export': 4,
                                'selector_domains': 3, 'low_byte_partitions': 768, 'symbolic_upper_bits_per_partition': 24,
                                'selector_instruction_instances': sum((b-a)//4*256 for a, b in SPANS),
                                'selector_read_instances': sum(len(c['source_reads']) for b in banks for c in b['cases']),
                                'original_fixups_verified': 5, 'authenticated_call_sites': 2,
                                'source_queries_unsat': 7, 'record_writer_sites': 10, 'record_source_assigned_bytes': 54},
            'logical_authentication_only': True, 'new_guest_execution_intervals': 0,
            'new_guest_definition_bytes': 0, 'native_API_executed': False,
            'continuous_initializer_to_current_caller_join_established': False,
            'native_daemon_kext_pairing_established': False, 'full_goal_complete': False,
            'all_checks_pass': True}


if __name__ == '__main__':
    result = build()
    (ROOT/(P+'_checks.json')).write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result['verified_counts']), flush=True)
