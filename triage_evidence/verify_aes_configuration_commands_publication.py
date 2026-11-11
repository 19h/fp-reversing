#!/usr/bin/env python3
"""Audit original AES configuration commands and exact publication delta.

Read-only. O(source and owned bytes + source paths) time/space, plus finite
integer interpretation and separate SMT cost. No native target/device access.
"""
from hashlib import sha256
import json
from pathlib import Path
import subprocess

from compression import zstd
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
import z3

from audit_aes_configuration_packets import audit
from kernel_native_reader import Kernel
from recover_kext_aes_handoff import starts
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read, sha, size
from verify_lskd_vector_origin_publication import path_hygiene

ROOT = Path(__file__).resolve().parent
BASE = ROOT.parent
PREVIOUS = '68f9836a39d11ec08bbc8d3ec0ac40151d4af565'
MANIFEST = 'triage_evidence/interface_manifest.json'
CHANGED = {'aes_dma_preparation_report.md', 'aes_quantum_binding_report.md', 'aes_provider_admission_report.md',
           'foundational_triage_report.md', 'interface_abi_report.md', 'interface_investigation_status.md',
           'obfuscated_routines_report.md', 'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED = {'aes_configuration_commands_report.md', 'triage_evidence/recover_aes_configuration_commands.py',
         'triage_evidence/aes_configuration_commands_checks.json', 'triage_evidence/audit_aes_configuration_packets.py',
         'triage_evidence/verify_aes_configuration_commands_publication.py'}
ARCHIVES = {MANIFEST, 'triage_evidence/aes_configuration_commands_checks.json'}
OWNED = ((CHANGED | ADDED)-ARCHIVES) | {p+'.zst' for p in ARCHIVES}
COUNTS = {'queries_unsat': 56, 'controls_sat': 1, 'source_pieces': 25, 'source_lifted_instances': 104,
          'operation_source_paths': 9, 'selector_source_paths': 12, 'key_size_source_paths': 3, 'scalar_path_feasibility_sat': 24,
          'spans': 8, 'instructions': 1308, 'code_B': 5232, 'original_slots': 3}
ORACLES = {'operation_integer_cases': 39, 'selector_integer_cases': 4100, 'size_integer_cases': 12,
           'extended_record_byte_cases': 8, 'IV_record_byte_cases': 32, 'inline_copy_byte_cases': 6,
           'dsb_record_byte_cases': 2, 'trace_record_byte_cases': 4}
H = 0xfffffe0009d40000


def git(*args): return subprocess.check_output(['git', *args], cwd=BASE)


def check(query, expected):
    solver = z3.Solver(); solver.set(timeout=15000); solver.from_string(query); result = solver.check()
    assert result == expected, (str(result), str(expected), solver.reason_unknown())


def main():
    old_raw = zstd.decompress(git('show', PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(old_raw).hexdigest() == '891bff77a33170132c3688e50beaa487683728b1e46cd1a3f01ef337239eb652'
    previous, current = json.loads(old_raw), json.loads(read(BASE/MANIFEST))
    old = {r['path']: r for r in previous['files']}; new = {r['path']: r for r in current['files']}
    assert len(old) == len(previous['files']) == 8086 and len(new) == len(current['files']) == 8091
    assert not old.keys()-new.keys() and new.keys()-old.keys() == ADDED
    assert {p for p in old if old[p] != new[p]} == CHANGED
    assert current['inputs_preserved'] == previous['inputs_preserved']
    for row in current['inputs_preserved']:
        assert sha(BASE/row['path']) == row['sha256'] and size(BASE/row['path']) == row['size_bytes']
    for p in CHANGED | ADDED:
        assert sha(BASE/p) == new[p]['sha256'] and size(BASE/p) == new[p]['size_bytes']
    report = read(BASE/'aes_configuration_commands_report.md')
    assert all(f'| AC{i} |' in report for i in range(1, 9)) and all(f'**QG{i}**' in report for i in range(1, 8))
    e = json.loads(read(ROOT/'aes_configuration_commands_checks.json'))
    assert e['generator_sha256'] == sha(ROOT/'recover_aes_configuration_commands.py')
    for p, digest in e['dependencies'].items(): assert sha(ROOT/p) == digest
    assert e['verified_counts'] == COUNTS and len(e['proofs']) == 56 and len(e['negative_controls']) == 1
    for proof in e['proofs'].values(): assert proof['result'] == 'unsat'; check(proof['query'], z3.unsat)
    for control in e['negative_controls'].values(): assert control['result'] == 'sat'; check(control['query'], z3.sat)
    prior = json.loads(read(ROOT/'aes_dma_preparation_checks.json')); assert len(prior['proofs']) == 43
    for proof in prior['proofs'].values(): assert proof['result'] == 'unsat'; check(proof['query'], z3.unsat)
    k = Kernel(); assert e['kernel_collection_sha256'] == k.sha256
    cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); cs.detail = True
    spans = {r['label']: r for r in e['spans']}; assert len(spans) == 8
    ranges = sorted((int(r['start'], 16), int(r['end'], 16)) for r in spans.values())
    assert all(z <= a for (_, z), (a, _) in zip(ranges, ranges[1:]))
    for row in spans.values():
        a, z = int(row['start'], 16), int(row['end'], 16); raw = bytes.fromhex(row['bytes_hex'])
        assert len(raw) == z-a == 4*len(row['instructions']) and k.read(a, len(raw)) == raw
        assert row['instructions'] == [{'ea': hex(i.address), 'mnemonic': i.mnemonic, 'operands': i.op_str} for i in cs.disasm(raw, a)]
        if 'entry' in row:
            catalog = starts(k, next(x for x in k.entries if x['name'] == row['entry']))
            assert a in catalog and catalog[catalog.index(a)+1] == z and sha256(raw).hexdigest() == row['sha256']
        else: assert len(raw) == 16 and row['label'] in ['synchronize_stub', 'copy_stub']
    assert sum(len(r['instructions']) for r in spans.values()) == 1308
    assert sum(len(bytes.fromhex(r['bytes_hex'])) for r in spans.values()) == 5232
    frozen = json.loads(read(ROOT/'aes_quantum_binding_source.json'))['functions']
    for label in ['configure', 'quantum']:
        row = spans[label]; old_row = next(r for r in frozen if r['start'] == row['start'])
        assert row['end'] == old_row['end'] and row['bytes_hex'] == old_row.get('bytes_hex', old_row.get('bytes'))
    assert len(e['slots']) == 3
    for a, row in e['slots'].items(): assert row == pointer(k, int(a, 16)) and row['authenticated'] and row['chain_membership_verified']
    addresses = {int(r['target'], 16) for r in e['slots'].values()} | {int(r['start'], 16) for r in spans.values() if 'entry' in r}
    assert e['exact_symbols'] == k.symbols(addresses)
    for address, name in [(0xfffffe000be82c2c, '_OSSynchronizeIO'), (0xfffffe000c51e1d4, '__ZN13IOCommandGate12commandSleepEPvj')]:
        assert [r['name'] for r in e['exact_symbols'][hex(address)]] == [name]
    assert {r['name'] for r in e['exact_symbols']['0xfffffe000c647f10']} == {'_memcpy', '_memmove'}
    code = {int(r['ea'], 16): (r['mnemonic'], r['operands']) for row in spans.values() for r in row['instructions']}
    assert len(e['source_pieces']) == 25 and sum(e['source_lift_counts'].values()) == 104
    for name, cut in e['source_pieces'].items():
        a, z = int(cut['start'], 16), int(cut['end'], 16)
        assert cut['instructions'] == (z-a)//4 == e['source_lift_counts'][name]
        assert any(left <= a < z <= right for left, right in ranges)
        assert not any(i.mnemonic.startswith('b.') or i.mnemonic in ['b', 'bl', 'blr', 'blraa', 'cbz', 'cbnz', 'tbz', 'tbnz'] for i in cs.disasm(k.read(a, z-a), a))
    forest_count = 0
    for label, root, exits, expected in [
        ('operation_source_paths', H+0xfd3c, {H+0xfdb8, H+0xfe68, H+0x10028}, 9),
        ('selector_source_paths', H+0xfddc, {H+0x10048, H+0x100c4, H+0xfe00, H+0x100a4, H+0x100e4,
                                          H+0xff74, H+0xfeb4, H+0xfe4c, H+0x100fc}, 12),
        ('key_size_source_paths', H+0x10864, {H+0x108b4, H+0x10894}, 3),
    ]:
        rows = e[label]; assert len(rows) == expected
        for row in rows:
            path = [int(a, 16) for a in row['path']]; frontier = int(row['frontier'], 16)
            assert path[0] == root and frontier in exits and len(path) == len(set(path))
            assert row['declared_scalar_feasibility'] == 'sat'; check(row['feasibility_query'], z3.sat); forest_count += 1
            for pc, successor in zip(path, path[1:]+[frontier]):
                ins = next(cs.disasm(k.read(pc, 4), pc)); m = ins.mnemonic
                assert m in ['mov', 'cmp', 'sub', 'ldr', 'ubfx', 'csel', 'b', 'b.eq', 'b.ne', 'b.gt', 'b.lo', 'b.hs', 'cbz']
                if m == 'b': assert successor == ins.operands[0].imm & ((1 << 64)-1)
                elif m.startswith('b.') or m == 'cbz': assert successor in [pc+4, ins.operands[-1].imm & ((1 << 64)-1)]
                else: assert successor == pc+4
    assert forest_count == 24 and e['recognized_selectors'] == [0, 1000, 1001, 2000, 2001, 3000, 3100, 3102, 4000, 4001, 4002, 4003]

    def at(offset, mnemonic, operands): assert code[H+offset] == (mnemonic, operands), (hex(H+offset), code[H+offset])

    # The gate/record/loop source edges below qualify the bounded cuts.
    for off, m, op in [
        (0xfdbc, 'cbz', 'x27, #0xfffffe0009d4fe20'),
        (0xfdc8, 'tbz', 'w28, #0x1f, #0xfffffe0009d4fdd4'),
        (0x1004c, 'tbnz', 'w28, #0x1f, #0xfffffe0009d503d0'),
        (0x101f8, 'tbz', 'w23, #0, #0xfffffe0009d50290'),
        (0x10268, 'blraa', 'x8, x16'),
        (0x103a4, 'cbz', 'x8, #0xfffffe0009d503b4'),
        (0x103c0, 'bl', '#0xfffffe0009d51e38'),
        (0x103c4, 'bl', '#0xfffffe0009d52af4'),
        (0x107f4, 'tst', 'w1, #0x7000000'), (0x107f8, 'b.eq', '#0xfffffe0009d50818'),
        (0x10804, 'tbnz', 'w8, #0xf, #0xfffffe0009d5085c'),
        (0x10810, 'mov', 'w2, #4'), (0x1081c, 'cbz', 'w5, #0xfffffe0009d50864'),
        (0x10830, 'b.hi', '#0xfffffe0009d5085c'), (0x10834, 'cbz', 'x3, #0xfffffe0009d50910'),
        (0x108bc, 'bl', '#0xfffffe0009d51dfc'), (0x108c0, 'cbz', 'w0, #0xfffffe0009d508fc'),
        (0x108e0, 'mov', 'w2, #4'), (0x108e4, 'bl', '#0xfffffe0009d51e38'),
        (0x108f4, 'bl', '#0xfffffe0009d51e38'), (0x108f8, 'mov', 'w0, #1'),
        (0x10960, 'bl', '#0xfffffe0009d51e38'),
        (0x11e00, 'tst', 'w1, #3'), (0x11e04, 'b.ne', '#0xfffffe0009d51e28'),
        (0x11e5c, 'tst', 'w2, #3'), (0x11e60, 'b.ne', '#0xfffffe0009d51f34'),
        (0x11e74, 'bl', '#0xfffffe0009d51dfc'), (0x11e78, 'tbz', 'w0, #0, #0xfffffe0009d51f38'),
        (0x11e7c, 'cbz', 'w21, #0xfffffe0009d51f18'),
        (0x11ed8, 'ld1', '{v0.s}[1], [x8]'),
        (0x11efc, 'ldr', 'w9, [x19, x22, lsl #2]'),
        (0x11edc, 'str', 'd0, [x11]'), (0x11eec, 'str', 'w8, [x20, #0x9fc]'),
        (0x11f08, 'str', 'w9, [x8]'), (0x11f14, 'b.ne', '#0xfffffe0009d51e9c'),
        (0x10d4c, 'bl', '#0xfffffe0009d4fcf8'),
    ]: at(off, m, op)
    errors = [hex(a) for a, ins in code.items() if int(spans['configure']['start'], 16) <= a < int(spans['configure']['end'], 16) and ins == ('mov', 'w19, #0x2c2')]
    assert errors == e['configuration_error_word_sites'] and len(errors) == 9
    for a in errors: assert code[int(a, 16)+4] == ('movk', 'w19, #0xe000, lsl #16')
    assert audit() == ORACLES
    assert not any(e[n] for n in ['new_IDA_access', 'new_native_execution', 'actual_key_bytes_captured', 'new_IDB_mutations', 'full_goal_complete'])
    assert current['validation']['aes_configuration_commands_increment_checks'] == COUNTS
    assert current['validation']['aes_configuration_commands_static_scope'] == e['scope']
    assert current['validation']['reports'] == previous['validation']['reports']+1 == 396
    assert current['validation']['unavailable_external_primary_references'] == previous['validation']['unavailable_external_primary_references']
    assert current['goal_status'] == 'active' and len(OWNED) == 14
    for p in ARCHIVES: assert not (BASE/p).exists()
    for p in OWNED: path_hygiene((BASE/p).read_bytes())
    path_hygiene(git('show', '-s', '--format=fuller', 'HEAD'))
    print(json.dumps({'unchanged_manifest_entries': len(old)-len(CHANGED), 'owned_physical_files': len(OWNED),
                     'original_inputs_preserved': 3, 'new_UNSAT_queries_rechecked': 56, 'prior_UNSAT_queries_rechecked': 43,
                     'scalar_path_feasibility_SAT': 24, 'SAT_premise_control': 1, 'source_instructions_retained': 1308,
                     'original_fixup_addresses': 3, 'independent_interpretation': ORACLES,
                     'analyst_path_literals_absent': True, 'all_checks_pass': True}))


if __name__ == '__main__': main()
