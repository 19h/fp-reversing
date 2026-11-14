#!/usr/bin/env python3
"""Resolve three feedback roots through original selector instructions.

Each selector covers all 256 low bytes with symbolic upper 24 bits. Original
image table reads and decoded pool rebases are retained; native execution,
PAC, concurrency and the current initializer epoch are not established.
O(256*selector words + source + query DAG) time/storage, excluding solver
search complexity; timeout 30 s/query.
"""
import json
import z3
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from daemon_receive_tools import ROOT, SOURCE, IMAGE, CS, FIXUPS, POOL, qword, verify_original_fixups
from verify_daemon_reader_record_payloads_publication import sha, read
from audit_daemon_state_table_mixing import Scalar

P = 'daemon_feedback_roots'
PARENT = 'daemon_constructor_descriptor_checks.json'
PARENT_SHA = '9d044ed5285d1fb392fb01eb10e016b19d8ba312435793760e28376c9bc50d3f'
DEPS = ['daemon_receive_tools.py', 'daemon_receive_fixups.txt',
        'audit_daemon_state_table_mixing.py', 'lskd_values_symbolic.py']
ROOTS = [0x1010b6590, 0x1010c4670, 0x1010b7cc0]
SPECS = [(0x100b21238, 0x100b2127c), (0x100b2128c, 0x100b212d0),
         (0x100b2132c, 0x100b21378)]
TABLES = [(0x100fc4130, 256), (0x101031ea0, 256),
          (0x101031da0, 256), (0x100e99900, 256)]
POOL_SLOTS = {0x1010aa0c8, 0x1010a1e00, 0x1010a3eb0,
              POOL+0x29c8, POOL+0x4c18, POOL+0x2b50, POOL+0x30f8}


class Selector(Scalar):
    def __init__(self):
        super().__init__()
        self.reads = []
    def load(self, address, n):
        a = z3.simplify(address)
        assert z3.is_bv_value(a), ('selector address still symbolic', a.sexpr())
        a = a.as_long()
        if n == 8:
            assert a in POOL_SLOTS and a in FIXUPS
            value = qword(a)
        else:
            assert n == 1 and any(lo <= a < lo+size for lo, size in TABLES)
            value = IMAGE.read(a, 1)[0]
        self.reads.append({'pc': hex(self.pc), 'address': hex(a), 'size_bytes': n,
                           'original_bytes_hex': IMAGE.read(a, n).hex(),
                           'loaded_value': hex(value), 'decoded_rebase': n == 8})
        return z3.BitVecVal(value, n*8)


def prove(label, bad):
    solver = z3.Solver()
    solver.set(timeout=30000)
    assert solver.check() == z3.sat
    solver.add(z3.simplify(bad))
    assert solver.check() == z3.unsat, label
    return {'label': label, 'premises_nonvacuous': True,
            'query': solver.to_smt2(), 'result': 'unsat'}


def selectors():
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    decoder.detail = True
    for i in decoder.disasm(IMAGE.read(0x100b2127c, 16), 0x100b2127c):
        assert not {'w13', 'x13'} & {i.reg_name(r) for r in i.regs_access()[1]}
    upper = z3.BitVec('feedback_selector_upper24', 24)
    payload = z3.BitVec('feedback_store_payload64', 64)
    out, proofs = [], []
    for j, (lo, hi) in enumerate(SPECS):
        cases, bad = [], []
        for byte in range(256):
            word = z3.Concat(upper, z3.BitVecVal(byte, 8))
            v = Selector()
            if j == 0:
                v.seed('w15', word)
            else:
                v.seed('x15', POOL)
                v.seed('w1' if j == 1 else 'w4', word)
                if j == 1:
                    v.seed('w13', 0xbb)
                else:
                    v.seed('x2', payload)
            v.run_block(lo, hi)
            if j == 0:
                address = v.read('x16')+v.read('x17')
                assert z3.simplify(v.read('w13')).as_long() == 0xbb
            elif j == 1:
                address = v.read('x1')+v.read('x3')
            else:
                address = v.stores[-1]['address']
                assert v.stores[-1]['size_bytes'] == 8
                bad.append(v.stores[-1]['value'] != payload)
            address = z3.simplify(address)
            assert z3.is_bv_value(address) and address.as_long() == ROOTS[j]
            bad.append(address != ROOTS[j])
            cases.append({'input_lower8': byte, 'input_upper24_symbolic': True,
                          'effective_address64': hex(address.as_long()), 'source_reads': v.reads,
                          'source_instruction_count': (hi-lo)//4})
        assert [x['input_lower8'] for x in cases] == list(range(256))
        out.append({'source_start': hex(lo), 'source_end': hex(hi),
                    'effective_root64': hex(ROOTS[j]), 'cases': cases,
                    'input_word_domain_bits': 32, 'partition_complete': True})
        proofs.append(prove('all_u32_original_selector_'+str(j)+'_root_and_payload', z3.Or(*bad)))
    return out, proofs


def controller():
    a, b, fp = z3.BitVecs('feedback_controller_A64 feedback_controller_B64 feedback_FP64', 64)
    v = Scalar()
    for name, value in {'x2': a, 'x4': b, 'x29': fp,
                        'x16': qword(0x1010aa0c8), 'x17': 0xfffffffffc5dedfd,
                        'x1': qword(0x1010a1e00), 'x3': 0xffffffffec9e1772}.items():
        v.seed(name, value)
    v.run_block(0x100b2122c, 0x100b21234)
    assert z3.simplify(v.read('x11')).as_long() == 0x0a5cd4cf
    v.run_block(0x100b212d4, 0x100b21308)
    d = b-a-(fp-0x28)
    k = 0x73d046208eaed1a6
    first, second = (d*0x0a5cd4cf)^k, (d^k)*0x0a5cd4cf
    assert len(v.stores) == 2
    return prove('all_u64_original_controller_pair_updates', z3.Or(
        v.stores[0]['address'] != ROOTS[0], v.stores[0]['value'] != first,
        v.stores[1]['address'] != ROOTS[1], v.stores[1]['value'] != second))


def build():
    assert sha(ROOT/PARENT) == PARENT_SHA
    parent = json.loads(read(ROOT/PARENT))
    assert parent['all_checks_pass'] and not parent['feedback_store_destination_join_established']
    banks, proofs = selectors()
    proofs.append(controller())
    regions = []
    for label, lo, hi in [('whole_feedback_phase', 0x100b21210, 0x100b21378),
                           ('caller_root_copy', 0x1008a2704, 0x1008a2714)]:
        regions.append({'label': label, 'start': hex(lo), 'end': hex(hi),
                        'bytes_hex': IMAGE.read(lo, hi-lo).hex(),
                        'instructions': [{'pc': hex(i.address), 'mnemonic': i.mnemonic,
                                          'operands': i.op_str, 'bytes_hex': bytes(i.bytes).hex()}
                                         for i in CS.disasm(IMAGE.read(lo, hi-lo), lo)]})
    fixups = verify_original_fixups(POOL_SLOTS)
    assert parent['root_pool']['target'] == hex(ROOTS[2])
    counts = {'selector_domains': 3, 'low_byte_partitions': 768,
              'symbolic_upper_bits_per_partition': 24, 'source_queries_unsat': 4,
              'source_instruction_instances': sum((b-a)//4*256 for a, b in SPECS),
              'source_read_instances': sum(len(c['source_reads']) for b in banks for c in b['cases']),
              'pool_rebases_verified': len(POOL_SLOTS), 'resolved_root_cells': 3}
    return {'scope': __doc__, 'generator_sha256': sha(__file__), 'source_sha256': sha(SOURCE),
            'parent_checks_sha256': PARENT_SHA, 'dependencies': {p: sha(ROOT/p) for p in DEPS},
            'source_regions': regions, 'selectors': banks, 'source_proofs': proofs,
            'tables': [{'address': hex(a), 'size_bytes': n, 'bytes_hex': IMAGE.read(a, n).hex()}
                       for a, n in TABLES], 'original_fixups': fixups,
            'verified_counts': counts, 'feedback_store_destination_join_established': True,
            'resolved_feedback_cell64': hex(ROOTS[2]), 'native_epoch_join_established': False,
            'caller_old_equals_contemporaneous_global_proven': False,
            'native_API_executed': False, 'new_guest_execution_intervals': 0,
            'native_daemon_kext_pairing_established': False,
            'full_goal_complete': False, 'all_checks_pass': True}


if __name__ == '__main__':
    result = build()
    (ROOT/(P+'_checks.json')).write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result['verified_counts']), flush=True)
