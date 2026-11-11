#!/usr/bin/env python3
"""Original-source SecureTime fields, explicit unlock and registered clock provider.

Static bytes, local scalar lifts, nominal vtable bindings and SDK comparison.
No new target, sysctl, entropy, allocator, synchronization or IDB execution.
Extraction is O(B+I+N+256R); DAG construction O(I); solver cost is separate.
"""
import argparse
import json
from pathlib import Path
import re
import struct
import subprocess

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
import z3

from kernel_native_reader import Kernel
from kext_port_tools import ROOT, SOURCE, IMAGE, selected
from lskd_values_symbolic import Lift, part, mem, cell, resize
from recover_aes_cleanup_epoch import span
from recover_kext_cold_init import pointer
from recover_kext_aes_handoff import function
from verify_daemon_reader_record_payloads_publication import read, sha

TABLE = 0xfffffe000846c420
GLOBAL = 0xfffffe000ccc78c0
FLAG = 0xfffffe000ccc78e0
SEED_CELL = 0xfffffe000ccc78b8
SEEDS = 0xfffffe000ccc78f4
MASK = 0x7fffffffffffffff
SPANS = {
    'clock_result_consumer': (0xfffffe000a51c0e0, 0xfffffe000a51c208),
    'raw_result_return': (0xfffffe000a52e4b0, 0xfffffe000a52e4e4),
}
ANCHORS = {
    0xfffffe000a51c0e4: ('ldrsw', 'x8, [x9]'),
    0xfffffe000a51c104: ('bfi', 'w11, w10, #1, #3'),
    0xfffffe000a51c114: ('stp', 'x10, xzr, [x11, #0x30]'),
    0xfffffe000a51c118: ('ldr', 'x10, [x11, #8]'),
    0xfffffe000a51c15c: ('str', 'x8, [x11, #0x10]'),
    0xfffffe000a51c160: ('str', 'wzr, [x11, #0x20]'),
    0xfffffe000a51c164: ('ldr', 'x8, [x11, #0x18]'),
    0xfffffe000a51c18c: ('str', 'w9, [x0]'),
    0xfffffe000a51c190: ('str', 'x8, [x0, #8]'),
    0xfffffe000a51c1f0: ('blraa', 'x8, x17'),
    0xfffffe000a51c204: ('braa', 'x9, x17'),
    0xfffffe000a52e4b8: ('str', 'w8, [x9, #0x38]'),
}
PROVIDER_STARTS = [0xfffffe0009e411b8, 0xfffffe0009e4195c, 0xfffffe0009e419cc,
                   0xfffffe0009e43610, 0xfffffe0009e43650]
PROVIDER_ANCHORS = {
    0xfffffe0009e41664: ('str', 'x19, [x0, #0x18]'),
    0xfffffe0009e41668: ('bl', '#0xfffffe0009e44c10'),
    0xfffffe0009e41674: ('str', 'x19, [x0, #0x18]'),
    0xfffffe0009e41678: ('bl', '#0xfffffe0009e44c10'),
    0xfffffe0009e41684: ('lsr', 'x9, x9, #0xf'),
    0xfffffe0009e4199c: ('blraa', 'x8, x16'),
    0xfffffe0009e419a0: ('str', 'w0, [sp, #0xc]'),
    0xfffffe0009e419b0: ('mov', 'w2, #4'),
    0xfffffe0009e419b8: ('blraa', 'x8, x17'),
    0xfffffe0009e43640: ('blraa', 'x8, x16'),
    0xfffffe0009e43644: ('lsr', 'x0, x0, #0xf'),
    0xfffffe0009e43824: ('blraa', 'x8, x16'),
    0xfffffe0009e4390c: ('str', 'xzr, [sp, #0x40]'),
}
SDK_PROBE = '''#include <sys/sysctl.h>
#include <stddef.h>
static_assert(sizeof(struct sysctl_oid)==80);
static_assert(offsetof(struct sysctl_oid,oid_parent)==0);
static_assert(offsetof(struct sysctl_oid,oid_number)==16);
static_assert(offsetof(struct sysctl_oid,oid_kind)==20);
static_assert(offsetof(struct sysctl_oid,oid_arg1)==24);
static_assert(offsetof(struct sysctl_oid,oid_name)==40);
static_assert(offsetof(struct sysctl_oid,oid_handler)==48);
static_assert(offsetof(struct sysctl_oid,oid_fmt)==56);
static_assert(offsetof(struct sysctl_oid,oid_descr)==64);
static_assert(offsetof(struct sysctl_req,oldfunc)==40);
static_assert((CTLTYPE_INT|CTLFLAG_RD|CTLFLAG_KERN|CTLFLAG_OID2)==0x81400002U);
'''


class ClockLift(Lift):
    """Add exact LDRSW sign-extension and UMULL to the retained scalar lift."""
    def run(self, label):
        saved = self.c
        row = next(s for s in saved['spans'] if s['label'] == label)
        cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        cs.detail = True
        raw = bytes.fromhex(row['bytes_hex'])
        instructions = list(cs.disasm(raw, int(row['start'], 16)))
        assert sum(i.size for i in instructions) == len(raw)
        for ins in instructions:
            self.pc = ins.address
            if ins.mnemonic == 'ldrsw':
                assert ins.op_str == 'x8, [x9]'
                self.write('x8', z3.SignExt(32, self.load(self.address(ins, ins.operands[1]), 4)))
                self.count += 1
            elif ins.mnemonic == 'umull':
                assert ins.op_str == 'x9, w9, w22'
                self.write('x9', resize(self.read('w9'), 64) * resize(self.read('w22'), 64))
                self.count += 1
            else:
                self.c = {'spans': [{'label': label, 'start': hex(ins.address),
                                      'bytes_hex': bytes(ins.bytes).hex()}]}
                super().run(label)
        self.c = saved
        return self


def prove(capture):
    f = 0x51000000
    p, record, lock, req, callback, raw_object, ticks = z3.BitVecs(
        'secure_time64 record64 embedded_RW64 sysctl_request64 sysctl_output_callback64 object_word64 RTC_ticks64', 64)
    seed_a0, seed_68, seed_98 = z3.BitVecs('seed_A0_64 seed_68_64 seed_98_64', 64)
    clock = z3.BitVec('clock_output32', 32)
    qs, counts = {}, {}

    def run(name, a, z, seeds, cells=()):
        obj = ClockLift(part(capture, name, a, z))
        for reg, value in seeds.items():
            obj.seed(reg, value)
        for address, width, value in cells:
            mem(obj, address, width, value)
        obj.run(name)
        counts[name] = obj.count
        return obj

    obj = run('incoming_clock_constants', 0xfffffe000a511808, 0xfffffe000a511824,
              {'sp': f, 'x28': TABLE, 'w20': 0x4b},
              [(TABLE + 8*0x4b, 8, 0xfffffe000a51c0e0), (f + 0x120, 8, f + 0x8000)])
    qs['incoming_clock_constants'] = z3.Or(obj.read('x19') != 0x46ec7c7424bcc931,
        obj.read('w27') != 0xe1d88903, obj.read('x21') != 0xfffffe000a51c0e0)
    obj = run('controller_multiplier', 0xfffffe000a5118c4, 0xfffffe000a5118cc, {})
    qs['controller_multiplier'] = obj.read('w22') != 0xea5ebdeb
    obj = run('seed_98_mask', 0xfffffe000a5118e8, 0xfffffe000a5118f0, {})
    qs['seed_98_mask'] = obj.read('w24') != 0xa7d93298
    obj = run('seed_A0_mask', 0xfffffe000a51191c, 0xfffffe000a511924, {})
    qs['seed_A0_mask'] = obj.read('w2') != 0xeb78d3a0
    obj = run('post_query_frame_roots', 0xfffffe000a511950, 0xfffffe000a51195c,
              {'sp': f}, [(f + 0x78, 8, FLAG), (f + 0x80, 8, SEED_CELL), (f + 0x10, 8, GLOBAL)])
    qs['post_query_frame_roots'] = z3.Or(obj.read('x9') != FLAG,
        obj.read('x10') != SEED_CELL, obj.read('x26') != GLOBAL)
    obj = run('complete_field_writer', 0xfffffe000a51c0e4, 0xfffffe000a51c164,
              {'x9': FLAG, 'x10': SEED_CELL, 'w2': 0xeb78d3a0, 'w24': 0xa7d93298,
               'x19': 0x46ec7c7424bcc931, 'x15': resize(clock, 64), 'x26': GLOBAL},
              [(FLAG, 4, 255), (SEED_CELL, 8, SEEDS), (GLOBAL, 8, p),
               (SEEDS + 0xa0, 8, seed_a0), (SEEDS + 0x68, 8, seed_68),
               (SEEDS + 0x98, 8, seed_98), (p + 8, 8, p), (p, 8, raw_object)])
    qs['clock_field_30_and_zero_38'] = z3.Or(cell(obj, p + 0x30, 8) !=
        ((seed_a0 & MASK) ^ 0x46ec7c7424bcc931 ^ resize(clock, 64)), cell(obj, p + 0x38, 8) != 0)
    qs['field_10_and_zero_20'] = z3.Or(cell(obj, p + 0x10, 8) !=
        (raw_object ^ ((seed_98 ^ seed_68) & MASK) ^ 0x35659b426b46beb1), cell(obj, p + 0x20, 4) != 0)
    layout = [{'pc': hex(s['pc']), 'offset_B': z3.simplify(s['address'] - p).as_long(),
               'width_B': s['size_bytes']} for s in obj.stores]
    assert [(s['offset_B'], s['width_B']) for s in layout] == [(0x30, 8), (0x38, 8), (0x10, 8), (0x20, 4)]
    obj = run('explicit_unlock_record', 0xfffffe000a51c164, 0xfffffe000a51c194,
              {'sp': f, 'x11': p}, [(p + 0x18, 8, lock), (f + 0x128, 8, record), (f + 0x1a0, 4, 0x3be)])
    qs['explicit_unlock_record'] = z3.Or(cell(obj, record + 8, 8) != lock,
        cell(obj, record, 4) - resize((record ^ 0xdfb9786f) * 0x1e2776fd, 32) != 0x1d3)
    obj = run('return_dispatch_index', 0xfffffe000a51c1d8, 0xfffffe000a51c1dc, {'w27': 0x3be})
    qs['return_dispatch_index'] = obj.read('w19') != 0x30c
    obj = run('final_raw_success', 0xfffffe000a51c1f8, 0xfffffe000a51c200, {})
    qs['final_raw_success'] = obj.read('w8') != 0x5e561849
    obj = run('common_result_store', 0xfffffe000a52e4b4, 0xfffffe000a52e4bc,
              {'sp': f, 'w8': 0x5e561849}, [(f + 0x198, 8, p)])
    qs['common_result_store'] = cell(obj, p + 0x38, 4) != 0x5e561849
    obj = run('RTC_upcount_projection', 0xfffffe0009e43644, 0xfffffe0009e43648, {'x0': ticks})
    qs['RTC_upcount_projection'] = obj.read('x0') != z3.LShR(ticks, 15)
    obj = run('seconds_handler_output_contract', 0xfffffe0009e419a0, 0xfffffe0009e419b4,
              {'sp': f, 'x0': z3.LShR(ticks, 15), 'x19': req}, [(req + 0x28, 8, callback)])
    qs['seconds_handler_output_contract'] = z3.Or(cell(obj, f + 0xc, 4) != z3.Extract(46, 15, ticks),
        obj.read('x0') != req, obj.read('x1') != f + 0xc, obj.read('w2') != 4, obj.read('x8') != callback)
    projection = lambda value: z3.Extract(46, 15, value)
    qs['seconds_projection_period_2power47_ticks'] = projection(ticks + (1 << 47)) != projection(ticks)
    obj = run('microseconds_factor', 0xfffffe0009e41a00, 0xfffffe0009e41a08, {})
    qs['microseconds_factor'] = obj.read('w22') != 1000000
    obj = run('microseconds_integer_projection', 0xfffffe0009e41ae0, 0xfffffe0009e41af8,
              {'sp': f, 'x0': ticks, 'w22': 1000000})
    expected = z3.LShR(ticks, 15) * 1000000 + z3.LShR((ticks & 0x7fff) * 1000000, 15)
    qs['microseconds_integer_projection'] = cell(obj, f + 8, 8) != expected
    q, rem = z3.Ints('unsigned_tick_quotient unsigned_tick_remainder')
    qs['microseconds_quotient_remainder_identity'] = z3.And(q >= 0, q < 2**49, rem >= 0, rem < 32768,
        ((q*32768 + rem)*1000000) / 32768 != q*1000000 + (rem*1000000) / 32768)
    proofs = {}
    for name, mismatch in qs.items():
        solver = z3.Solver()
        solver.set(timeout=10000)
        solver.add(mismatch)
        result = str(solver.check())
        assert result == 'unsat', (name, result)
        proofs[name] = {'query': solver.to_smt2(), 'result': result}
    return proofs, counts, layout


def sdk_comparison():
    sdk = Path(subprocess.check_output(['xcrun', '--show-sdk-path'], text=True).strip())
    relative = 'System/Library/Frameworks/Kernel.framework/Headers'
    command = ['xcrun', 'clang++', '-target', 'arm64e-apple-macos13.0', '-isysroot', str(sdk),
               '-I', str(sdk / relative), '-DKERNEL', '-std=c++17', '-x', 'c++', '-fsyntax-only', '-']
    result = subprocess.run(command, input=SDK_PROBE, capture_output=True, text=True)
    assert result.returncode == 0 and not result.stderr and not result.stdout
    return {'scope': 'Installed SDK layout and flag comparison; not historical private-layout equivalence or native execution.',
            'target': 'arm64e-apple-macos13.0', 'probe_source': SDK_PROBE,
            'assertions': SDK_PROBE.count('static_assert('), 'compiler_exit': result.returncode,
            'SDK_version': subprocess.check_output(['xcrun', '--show-sdk-version'], text=True).strip(),
            'primary_header': {'path': 'installed SDK:' + relative + '/sys/sysctl.h',
                               'sha256': sha(sdk / relative / 'sys/sysctl.h')}}


def build():
    k = Kernel()
    rows = []
    for label, bounds in SPANS.items():
        row = span(k, *bounds)
        row['bytes_hex'] = row.pop('bytes')
        row['label'] = label
        rows.append(row)
    instructions = {int(i['ea'], 16): (i['mnemonic'], i['operands']) for r in rows for i in r['instructions']}
    assert all(instructions[pc] == expected for pc, expected in ANCHORS.items())
    provider = next(e for e in k.entries if e['name'] == 'com.apple.driver.AppleSPMIPMU')
    functions = [function(k, provider, a) for a in PROVIDER_STARTS]
    pins = {int(i['ea'], 16): (i['mnemonic'], i['operands']) for r in functions for i in r['instructions']}
    assert all(pins[pc] == expected for pc, expected in PROVIDER_ANCHORS.items())
    for row in functions:
        row['label'] = row['start']
        row['exact_symbols'] = k.symbols([int(row['start'], 16)])[row['start']]
    cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    cs.detail = True
    defined, writes, incoming_status_reads, length_loads = False, [], [], []
    for ins in cs.disasm(k.read(0xfffffe000a51c0e4, 0x10c), 0xfffffe000a51c0e4):
        assert ins.mnemonic not in ('bl', 'blr', 'blraa', 'blrab') and not ins.mnemonic.startswith('b.')
        reads, destinations = ins.regs_access()
        canon = lambda reg: re.sub('^w', 'x', ins.reg_name(reg))
        if 'x0' in {canon(r) for r in reads} and not defined:
            incoming_status_reads.append(hex(ins.address))
        if 'x0' in {canon(r) for r in destinations}:
            defined = True
            writes.append(hex(ins.address))
        if ins.mnemonic.startswith('ld') and '[sp, #0x1d8]' in ins.op_str:
            length_loads.append(hex(ins.address))
    assert writes == ['0xfffffe000a51c170'] and not incoming_status_reads and not length_loads
    bank = selected(0xfffffe0007920d10, 0xfffffe00079173c0, 0xbb, 0x92c, base=TABLE)
    original = pointer(k, int(bank['slot'], 16))
    assert bank['target'] == original['target'] == '0xfffffe000a551f38'
    assert original['authenticated'] and original['diversity'] == '0x84cc'
    bank['original_pointer'] = original
    assert all(k.read(a, 256) == IMAGE.read(a, 256) for a in [0xfffffe0007920d10, 0xfffffe00079173c0])
    bank['original_banks_hex'] = [k.read(a, 256).hex() for a in [0xfffffe0007920d10, 0xfffffe00079173c0]]
    return_slot = pointer(k, TABLE + 8*0x30c)
    assert return_slot['target'] == '0xfffffe000a52e4b0' and return_slot['diversity'] == '0x343'
    nominal = []
    for offset, target, diversity in [(0x8d8, 0xfffffe0009e43610, 0x3a08), (0x8e8, 0xfffffe0009e43650, 0xbe44)]:
        row = pointer(k, 0xfffffe000832d470 + 16 + offset)
        assert row['target'] == hex(target) and int(row['diversity'], 16) == diversity and row['authenticated']
        nominal.append({'offset_from_vptr_B': offset, 'original_pointer': row,
                        'exact_symbols': k.symbols([target])[hex(target)], 'runtime_vptr_matched': False})
    oids = []
    for address, name, handler in [(0xfffffe000cc6b508, 'monotonicclock', 0xfffffe0009e4195c),
                                    (0xfffffe000cc6b558, 'monotonicclock_usecs', 0xfffffe0009e419cc),
                                    (0xfffffe000cc6b5b0, 'monotonicclock_rate_usecs', 0xfffffe000c2dd5f0)]:
        raw = k.read(address, 80)
        fields = {hex(o): pointer(k, address + o) for o in [0, 40, 48, 56, 64]}
        assert fields['0x0']['target'] == '0xfffffe0007f889e0' and fields['0x30']['target'] == hex(handler)
        strings = {}
        for off in [40, 56, 64]:
            data = k.read(int(fields[hex(off)]['target'], 16), 128)
            assert b'\0' in data
            strings[hex(off)] = data.split(b'\0', 1)[0].decode()
        assert strings['0x28'] == name
        assert struct.unpack_from('<i', raw, 16)[0] == -1
        kind = struct.unpack_from('<I', raw, 20)[0]
        assert kind == (0x81400002 if address == 0xfffffe000cc6b508 else 0x81400004)
        oids.append({'address': hex(address), 'original80_hex': raw.hex(), 'pointer_fields': fields,
                     'strings': strings, 'kind32': hex(kind), 'name_number_file_s32': -1,
                     'handler_exact_symbols': k.symbols([handler])[hex(handler)],
                     'exact_symbols': k.symbols([address])[hex(address)],
                     'native_registration_observed': False})
    registration_stub = {'start': '0xfffffe0009e44c10', 'end': '0xfffffe0009e44c20',
        'bytes_hex': k.read(0xfffffe0009e44c10, 16).hex(),
        'instructions': [{'ea': hex(i.address), 'mnemonic': i.mnemonic, 'operands': i.op_str}
                         for i in k.cs.disasm(k.read(0xfffffe0009e44c10, 16), 0xfffffe0009e44c10)]}
    registration = pointer(k, 0xfffffe000832ec18)
    assert registration['target'] == '0xfffffe000c2dcf90'
    registration_symbols = k.symbols([0xfffffe000c2dcf90])['0xfffffe000c2dcf90']
    assert '_sysctl_register_oid' in {r['name'] for r in registration_symbols}
    prior = json.loads(read(ROOT / 'lskd_secure_time_checks.json'))
    proofs, counts, stores = prove({'spans': rows + functions + prior['spans']})
    newly_written = set()
    for s in stores:
        newly_written.update(range(s['offset_B'], s['offset_B'] + s['width_B']))
    old_written = set(range(0, 16)) | set(range(24, 32))
    assert len(newly_written) == 28 and len(newly_written | old_written) == 52
    assert set(range(64)) - newly_written - old_written == set(range(0x24, 0x30))
    sdk = sdk_comparison()
    return {'scope': __doc__, 'generator_sha256': sha(__file__), 'kernel_collection_sha256': k.sha256,
        'normalized_kext_sha256': sha(SOURCE), 'kext_spans': rows, 'provider_functions': functions,
        'provider_entry': {'name': provider['name'], 'uuid': provider['uuid']},
        'proofs': proofs, 'source_lift_counts': counts, 'solver_version': z3.get_version_string(),
        'proof_strategy': {'microseconds': 'Original decomposition plus an independent unsigned integer quotient/remainder identity; final u64 reduction is modular congruence.',
            'initial_direct_widened_bitvector_query': 'unknown with a 10000 ms limit; excluded from certificates and replaced by exact compositional proof of the same projection.'},
        'release_bank': bank, 'return_slot': return_slot, 'new_object_stores': stores,
        'nominal_vtable_bindings': nominal, 'nominal_vtable_exact_symbols': k.symbols([0xfffffe000832d470])['0xfffffe000832d470'],
        'OIDs': oids, 'parent_exact_symbols': k.symbols([0xfffffe0007f889e0])['0xfffffe0007f889e0'],
        'registration_stub': registration_stub, 'registration_binding': registration,
        'registration_exact_symbols': registration_symbols, 'SDK_comparison': sdk,
        'source_status_audit': {'incoming_sysctl_status_reads_before_overwrite': incoming_status_reads,
            'X0_writes_before_unlock': writes, 'returned_length_reloads': length_loads,
            'conditional_branches_before_unlock': 0},
        'selected_contract': {'newly_written_object_B': 28, 'combined_explicit_object_write_B': 52,
            'object_declared_B': 64, 'unproved_object_bytes': {'first_B': 36, 'exclusive_end_B': 48},
            'unlock_phase32': '0x1d3', 'unlock_pointer_offset_B': 24, 'raw_success32': '0x5e561849',
            'seconds_output_B': 4, 'seconds_tick_bits_inclusive': [15, 46], 'ticks_shift': 15,
            'microseconds_factor': 1000000, 'provider_native_availability_established': False,
            'physical_tick_calibration_measured': False, 'native_lock_balance_established': False,
            'SecureTime_object_free_recovered': False, 'daemon_reply_established': False},
        'dependencies': {n: sha(ROOT / n) for n in ['kernel_native_reader.py', 'kext_port_tools.py',
            'lskd_values_symbolic.py', 'recover_aes_cleanup_epoch.py', 'recover_kext_cold_init.py',
            'recover_kext_aes_handoff.py', 'verify_daemon_reader_record_payloads_publication.py',
            'lskd_secure_time_checks.json', 'lskd_continuations_contracts.json',
            'lskd_continuations_proofs.json', 'lskd_continuations_unlock_record_selector_original.smt2',
            'lskd_continuations_unlock_explicit_pointer_gate_original.smt2',
            'lskd_continuations_unlock_cached_pointer_gate_original.smt2']},
        'verified_counts': {'kext_spans': len(rows), 'kext_instructions': len(instructions),
            'kext_code_B': 4*len(instructions), 'provider_functions': len(functions),
            'provider_instructions': len(pins), 'provider_code_B': 4*len(pins),
            'kext_operand_anchors': len(ANCHORS), 'provider_operand_anchors': len(PROVIDER_ANCHORS),
            'banks': 1, 'bank_inputs': 256, 'return_slots': 1, 'nominal_vtable_slots': len(nominal),
            'original_OIDs': len(oids), 'queries_unsat': len(proofs),
            'source_lifted_instances': sum(counts.values()), 'SDK_assertions': sdk['assertions']},
        'new_target_execution': False, 'new_IDA_access': False, 'native_epoch_matched': False,
        'full_goal_complete': False, 'all_checks_pass': True}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify', action='store_true')
    args = parser.parse_args()
    output = build()
    path = ROOT / 'lskd_clock_completion_checks.json'
    if args.verify:
        assert json.loads(read(path)) == output
    else:
        path.write_text(json.dumps(output, indent=2) + '\n')
    print(json.dumps(output['verified_counts']))
