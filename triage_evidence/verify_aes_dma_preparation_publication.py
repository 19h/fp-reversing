#!/usr/bin/env python3
"""Independent source, proof, manifest and path audit for DMA preparation.

Read-only. O(source + owned artifact bytes + retained expressions) time/space;
SMT solver cost separate. Native mappings and completion remain unproved.
"""
from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess

from compression import zstd
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_MEM
import z3

from kernel_native_reader import Kernel
from recover_kext_aes_handoff import starts
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read, sha, size
from verify_lskd_vector_origin_publication import path_hygiene

ROOT = Path(__file__).resolve().parent
BASE = ROOT.parent
PREVIOUS = 'a85038dba3501e5f30c159201e1435de5d8e6faf'
MANIFEST = 'triage_evidence/interface_manifest.json'
CHANGED = {
    'aes_quantum_binding_report.md', 'aes_provider_admission_report.md', 'kext_buffer_report.md',
    'foundational_triage_report.md', 'interface_abi_report.md', 'interface_investigation_status.md',
    'obfuscated_routines_report.md', 'triage_evidence/validate_rpc502_sidecar_delivery.py',
}
ADDED = {
    'aes_dma_preparation_report.md', 'triage_evidence/recover_aes_dma_preparation.py',
    'triage_evidence/aes_dma_preparation_checks.json', 'triage_evidence/verify_aes_dma_preparation_publication.py',
}
ARCHIVES = {MANIFEST, 'triage_evidence/aes_dma_preparation_checks.json'}
OWNED = ((CHANGED | ADDED) - ARCHIVES) | {p+'.zst' for p in ARCHIVES}
COUNTS = {'queries_unsat': 43, 'controls_sat': 1, 'source_pieces': 39, 'source_lifted_instances': 115,
          'spans': 13, 'instructions': 2501, 'code_B': 10004, 'original_slots': 9, 'cache_source_paths': 4}


def git(*args):
    return subprocess.check_output(['git', *args], cwd=BASE)


def check(query, expected):
    solver = z3.Solver(); solver.set(timeout=15000); solver.from_string(query)
    result = solver.check()
    assert result == expected, (str(result), str(expected), solver.reason_unknown())


def main():
    previous_raw = zstd.decompress(git('show', PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(previous_raw).hexdigest() == '5b5896074e67f8083003f1a7554fcac6b4164c2f0b615f118b62d4704233d920'
    previous, current = json.loads(previous_raw), json.loads(read(BASE/MANIFEST))
    old = {r['path']: r for r in previous['files']}; new = {r['path']: r for r in current['files']}
    assert len(old) == len(previous['files']) == 8082 and len(new) == len(current['files']) == 8086
    assert not old.keys()-new.keys() and new.keys()-old.keys() == ADDED
    assert {p for p in old if old[p] != new[p]} == CHANGED
    assert current['inputs_preserved'] == previous['inputs_preserved']
    for row in current['inputs_preserved']:
        assert sha(BASE/row['path']) == row['sha256'] and size(BASE/row['path']) == row['size_bytes']
    for p in CHANGED | ADDED:
        assert sha(BASE/p) == new[p]['sha256'] and size(BASE/p) == new[p]['size_bytes']
    report = read(BASE/'aes_dma_preparation_report.md')
    assert all(f'| DP{i} |' in report for i in range(1, 9)) and all(f'**QG{i}**' in report for i in range(1, 8))
    e = json.loads(read(ROOT/'aes_dma_preparation_checks.json'))
    assert e['generator_sha256'] == sha(ROOT/'recover_aes_dma_preparation.py')
    for p, digest in e['dependencies'].items():
        assert sha(ROOT/p) == digest
    assert e['verified_counts'] == COUNTS and len(e['proofs']) == 43 and len(e['negative_controls']) == 1
    for proof in e['proofs'].values():
        assert proof['result'] == 'unsat'; check(proof['query'], z3.unsat)
    for control in e['negative_controls'].values():
        assert control['result'] == 'sat'; check(control['query'], z3.sat)
    prior = json.loads(read(ROOT/'aes_provider_admission_checks.json'))
    assert len(prior['proofs']) == 29
    for proof in prior['proofs'].values():
        assert proof['result'] == 'unsat'; check(proof['query'], z3.unsat)
    k = Kernel(); assert e['kernel_collection_sha256'] == k.sha256
    cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); cs.detail = True
    spans = {r['label']: r for r in e['spans']}; assert len(spans) == 13
    ranges = sorted((int(r['start'], 16), int(r['end'], 16)) for r in spans.values())
    assert all(z <= a for (_, z), (a, _) in zip(ranges, ranges[1:]))
    for row in spans.values():
        a, z = int(row['start'], 16), int(row['end'], 16)
        data = bytes.fromhex(row['bytes_hex'])
        assert len(data) == z-a == 4*len(row['instructions']) and k.read(a, len(data)) == data
        assert sha256(data).hexdigest() == row['sha256']
        assert row['instructions'] == [{'ea': hex(i.address), 'mnemonic': i.mnemonic, 'operands': i.op_str} for i in cs.disasm(data, a)]
        if 'entry' in row:
            entry = next(x for x in k.entries if x['name'] == row['entry']); catalog = starts(k, entry)
        else:
            catalog = k.starts
        assert a in catalog and catalog[catalog.index(a)+1] == z
    assert sum(len(r['instructions']) for r in spans.values()) == 2501
    assert sum(len(bytes.fromhex(r['bytes_hex'])) for r in spans.values()) == 10004
    frozen = json.loads(read(ROOT/'aes_quantum_binding_source.json'))['functions']
    for label in ['quantum', 'transfer', 'output_little64']:
        row = spans[label]; old_row = next(r for r in frozen if r['start'] == row['start'])
        assert row['end'] == old_row['end'] and row['bytes_hex'] == old_row.get('bytes_hex', old_row.get('bytes'))
    assert len(e['source_pieces']) == 39 and sum(e['source_lift_counts'].values()) == 115
    for name, cut in e['source_pieces'].items():
        a, z = int(cut['start'], 16), int(cut['end'], 16)
        assert cut['instructions'] == (z-a)//4 == e['source_lift_counts'][name]
        assert any(left <= a < z <= right for left, right in ranges)
        assert not any(i.mnemonic.startswith('b') or i.mnemonic in ['cbz', 'cbnz', 'tbz', 'tbnz'] for i in cs.disasm(k.read(a, z-a), a))
    assert len(e['slots']) == 9
    for address, row in e['slots'].items():
        assert row == pointer(k, int(address, 16)) and row['authenticated'] and row['chain_membership_verified']
    addresses = {int(r['target'], 16) for r in e['slots'].values()} | {int(r['start'], 16) for r in spans.values() if 'entry' not in r}
    assert e['exact_symbols'] == k.symbols(addresses)
    for address, fragment in [(0xfffffe000c528964, 'setMemoryDescriptor'), (0xfffffe000c52818c, 'prepareEyybb'),
                              (0xfffffe000c5365e8, 'dmaCommandOperation'), (0xfffffe000c529dd8, 'OutputLittle64')]:
        assert len(e['exact_symbols'][hex(address)]) == 1 and fragment in e['exact_symbols'][hex(address)][0]['name']
    assert e['exact_symbols']['0xfffffe000c526dc8'] == [] and e['exact_symbols']['0xfffffe000c527590'] == []
    code = {r['ea']: (r['mnemonic'], r['operands']) for row in spans.values() for r in row['instructions']}

    def at(address, mnemonic, operands):
        assert code[hex(address)] == (mnemonic, operands), (hex(address), code[hex(address)])

    # Exact branches qualify source-cut composition, including shortcut/failure paths.
    for a, m, op in [
        (0xfffffe000c528988, 'b.eq', '#0xfffffe000c5289a8'),
        (0xfffffe000c528990, 'cbz', 'x8, #0xfffffe000c528a24'),
        (0xfffffe000c528998, 'cbz', 'w8, #0xfffffe000c5289f0'),
        (0xfffffe000c5289a8, 'tbnz', 'w2, #0, #0xfffffe000c528bf0'),
        (0xfffffe000c528a24, 'cbz', 'x20, #0xfffffe000c528bf0'),
        (0xfffffe000c528a7c, 'cbnz', 'w0, #0xfffffe000c528bf4'),
        (0xfffffe000c528b78, 'cbz', 'w22, #0xfffffe000c528bf0'),
        (0xfffffe000c528bb4, 'cbz', 'w0, #0xfffffe000c528bf4'),
        (0xfffffe000c528bd4, 'mov', 'x20, x0'),
        (0xfffffe000c528be8, 'mov', 'x0, x20'),
        (0xfffffe000c5281cc, 'cbz', 'x9, #0xfffffe000c528780'),
        (0xfffffe000c5281d4, 'cbnz', 'x2, #0xfffffe000c5281dc'),
        (0xfffffe000c5281e4, 'b.ls', '#0xfffffe000c5281f0'),
        (0xfffffe000c5281fc, 'cbz', 'w9, #0xfffffe000c52821c'),
        (0xfffffe000c528208, 'b.ne', '#0xfffffe000c528780'),
        (0xfffffe000c528224, 'cbz', 'x9, #0xfffffe000c528230'),
        (0xfffffe000c528238, 'cbz', 'x9, #0xfffffe000c528244'),
        (0xfffffe000c536634, 'cmp', 'w8, #1'),
        (0xfffffe000c536638, 'b.eq', '#0xfffffe000c536750'),
        (0xfffffe000c536758, 'cmp', 'w3, #0x20'),
        (0xfffffe000c53675c, 'b.lo', '#0xfffffe000c536f10'),
        (0xfffffe000c5367b0, 'cbz', 'w9, #0xfffffe000c536924'),
        (0xfffffe000c52758c, 'b', '#0xfffffe000c526dc8'),
        (0xfffffe000c527554, 'ldr', 'x16, [x0, #0x50]'),
        (0xfffffe000c527568, 'mov', 'x3, x16'),
        (0xfffffe000c527574, 'adrp', 'x16, #0xfffffe000c527000'),
        (0xfffffe000c527578, 'add', 'x16, x16, #0x590'),
        (0xfffffe000c527584, 'mov', 'x2, x16'),
        (0xfffffe000c526e00, 'tbnz', 'w1, #6, #0xfffffe000c526e0c'),
        (0xfffffe000c526e08, 'cbz', 'w9, #0xfffffe000c526ea4'),
        (0xfffffe000c526e28, 'cbz', 'w9, #0xfffffe000c5273c8'),
        (0xfffffe000c526e40, 'b.hs', '#0xfffffe000c526eac'),
        (0xfffffe000c5275d8, 'b.hi', '#0xfffffe000c52760c'),
        (0xfffffe000c5275e8, 'cbz', 'x9, #0xfffffe000c52760c'),
        (0xfffffe000c5275f4, 'cbz', 'w9, #0xfffffe000c527604'),
        (0xfffffe000c527608, 'cbz', 'x9, #0xfffffe000c5275f8'),
        (0xfffffe0009d51220, 'cbnz', 'w0, #0xfffffe0009d513b4'),
        (0xfffffe0009d51264, 'cbnz', 'w0, #0xfffffe0009d51388'),
    ]:
        at(a, m, op)
    for a in [0xfffffe000c526e0c, 0xfffffe000c526e10, 0xfffffe000c526e14]:
        at(a, 'cbz', {0xfffffe000c526e0c: 'x4', 0xfffffe000c526e10: 'x5', 0xfffffe000c526e14: 'x6'}[a]+', #0xfffffe000c526e98')
    # Calls use the slots above, rather than similarly numbered methods in another class.
    for a, m, operands in [
        (0xfffffe000c528a5c, 'mov', 'x17, #0x150'), (0xfffffe000c528a78, 'blraa', 'x9, x16'),
        (0xfffffe000c528b8c, 'mov', 'x17, #0x160'), (0xfffffe000c528bb0, 'blraa', 'x8, x16'),
        (0xfffffe000c528bc8, 'mov', 'x17, #0x150'), (0xfffffe000c528be4, 'blraa', 'x8, x16'),
        (0xfffffe000c536788, 'mov', 'x17, #0x1e8'), (0xfffffe000c5367a0, 'blraa', 'x8, x16'),
        (0xfffffe000c527628, 'blraa', 'x8, x17'),
    ]:
        at(a, m, operands)
    # Complete selected cache paths have one field load, no range use or call/store.
    assert len(e['cache_source_paths']) == 4
    for row in e['cache_source_paths']:
        forbidden = row['descriptor_bit18_set']; operation = row['operation32']
        expected = list(range(0xfffffe000c531c08, 0xfffffe000c531c1c, 4))
        if forbidden:
            expected += [0xfffffe000c531c50]
        else:
            expected += list(range(0xfffffe000c531c1c, 0xfffffe000c531c3c, 4))
            if operation == 2: expected += [0xfffffe000c531c3c, 0xfffffe000c531c40]
            expected += [0xfffffe000c531c44, 0xfffffe000c531c48, 0xfffffe000c531c4c]
        assert row['path'] == [hex(a) for a in expected]
        assert row['raw_status32'] == (0xe00002d9 if forbidden else 0)
        assert row['barriers_in_source'] == (0 if forbidden else 1) and row['native_barriers_executed'] == 0
        memory = []
        for a in expected:
            ins = next(cs.disasm(k.read(a, 4), a))
            assert not re.search(r'\b[wx][23]\b', ins.op_str)
            assert ins.mnemonic not in ['bl', 'blr', 'blraa', 'str', 'stp', 'stur']
            if any(o.type == ARM64_OP_MEM for o in ins.operands): memory.append((ins.mnemonic, ins.op_str))
        assert memory == [('ldr', 'w8, [x19, #0x20]')]
    for a, m, op in [(0xfffffe000c531c18, 'tbnz', 'w8, #0x12, #0xfffffe000c531c50'),
                     (0xfffffe000c531c2c, 'cmp', 'w1, #0x31'), (0xfffffe000c531c30, 'b.gt', '#0xfffffe000c531c74'),
                     (0xfffffe000c531c34, 'cmp', 'w1, #1'), (0xfffffe000c531c38, 'b.eq', '#0xfffffe000c531c44'),
                     (0xfffffe000c531c3c, 'cmp', 'w1, #2'), (0xfffffe000c531c40, 'b.ne', '#0xfffffe000c531c54'),
                     (0xfffffe000c531c44, 'dsb', 'sy'), (0xfffffe000c531c4c, 'b', '#0xfffffe000c531c54'),
                     (0xfffffe000c531c50, 'add', 'w0, w0, #0x12')]: at(a, m, op)

    # These no-call guards do not overwrite the selected offset/length/state roots.
    for ins in cs.disasm(k.read(0xfffffe000c5281dc, 0x68), 0xfffffe000c5281dc):
        if ins.mnemonic in ['cmp', 'cmn', 'tst']:
            word = int.from_bytes(ins.bytes, 'little'); assert word & 31 == 31 and word & (1 << 29)
            writes = {'nzcv'}
        else:
            writes = {re.sub(r'^w(?=\d)', 'x', ins.reg_name(r)) for r in ins.regs_access()[1]}
        assert not writes & {'x1', 'x2', 'x21'}
    selected = e['selected_contract']
    assert selected['binding_prepare_offset64'] == selected['binding_prepare_length64'] == 0
    assert selected['binding_prepare_flags'] == [True, True] and selected['cache_operation_codes'] == [1, 2]
    assert selected['cache_barrier'] == 'dsb sy' and selected['generate_flags'] == 0x80
    assert not any(selected[n] for n in ['native_descriptor_extent_matched', 'complete_mapper_semantics_proven',
                                       'native_hardware_completion_proven', 'daemon_request_lineage_proven'])
    assert not any(e[n] for n in ['new_IDA_access', 'new_native_execution', 'new_IDB_mutations', 'full_goal_complete'])
    assert current['validation']['aes_dma_preparation_increment_checks'] == COUNTS
    assert current['validation']['aes_dma_preparation_static_scope'] == e['scope']
    assert current['validation']['reports'] == previous['validation']['reports']+1 == 395
    assert current['validation']['unavailable_external_primary_references'] == previous['validation']['unavailable_external_primary_references']
    assert current['goal_status'] == 'active' and len(OWNED) == 13
    for p in ARCHIVES: assert not (BASE/p).exists()
    for p in OWNED: path_hygiene((BASE/p).read_bytes())
    path_hygiene(git('show', '-s', '--format=fuller', 'HEAD'))
    print(json.dumps({'unchanged_manifest_entries': len(old)-len(CHANGED), 'owned_physical_files': len(OWNED),
                     'original_inputs_preserved': 3, 'new_UNSAT_queries_rechecked': 43, 'prior_UNSAT_queries_rechecked': 29,
                     'SAT_premise_controls_rechecked': 1, 'source_instructions_retained': 2501, 'original_fixup_addresses': 9,
                     'cache_source_paths': 4, 'analyst_path_literals_absent': True, 'all_checks_pass': True}))


if __name__ == '__main__': main()
