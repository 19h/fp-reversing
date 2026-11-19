#!/usr/bin/env python3
"""Replay installed schema output through the shared holder to pending transfers."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from hashlib import sha256
import json
from pathlib import Path

from audit_daemon_iokit_native_registry import command, sysctl
from audit_live_fairplay_cf_receive import assert_instructions
from audit_live_fairplay_connection_retirement import verify_fixup
from audit_live_fairplay_context_lifecycle import POOL, POOL_ROOTS, TABLE, read_descriptor, replay_proof
from audit_live_fairplay_early_header import SUCCESS
from audit_live_fairplay_early_publication import PROOF_TIMEOUT_SECONDS
from audit_live_fairplay_entry import shifted, verify_layout
from audit_live_fairplay_replacement import CALLER_RELOCATIONS
from audit_live_fairplay_schema_scalar import (
    AUDIT as SCALAR_SOURCE, CHECKS as SCALAR_CHECKS, ERROR_PC, SEARCH_CHECKS, SUCCESS_PC,
    TYPE_ERROR, ScalarReplay, check_scalar_layout, check_source, scalar_cases,
)
from audit_live_fairplay_shared_table import EXTRA_BANKS, HEADER_ALLOC, HOLDER
from audit_live_fairplay_table_cleanup import LOOKUP
from audit_live_fairplay_uidlist import receipt
from audit_live_kext_selector26 import Collection, IDENTITIES

CHECKS = '8e32cec6eec4718c2699fc97189b15c574f9bdce395d9bd55ce4dbf74f20cc72'
AUDIT = 'c476c63e75e118210b73cda2052a0a756e5947b794bcb81722543989fdf899b1'
INSTALLED_SCALAR = '2259ced668cbf394972a70417bf1a27fff94c9df5d09cbd4378138aa490fc857'
U32 = (1 << 32) - 1
U64 = (1 << 64) - 1
HEADER = 0x6300019000
LOOKUP_CALL = shifted('0xfffffe000a65b52c')
ALLOCATE_CALL = shifted('0xfffffe000a65ad50')
CLEANUP = shifted('0xfffffe000a66229c')
CALLBACK = shifted('0xfffffe000a6367b4')
CODEC = LOOKUP + 0x74


def verify_code(image, source, adapter, allocate):
    *spans, codec = source['spans']
    layout = verify_layout(image, {'registry': dict(source, spans=spans)})
    rows = layout['spans']['registry']
    assert len(rows) == 16 and sum(row['words'] for row in rows) == 293
    assert len(layout['branch_fixups']) == 75
    assert [int(word['address'], 16) for row in rows for word in row['changes']] == [
        row[0] for row in CALLER_RELOCATIONS[2:6]
    ]
    layout['relocated_instructions'] = assert_instructions(image.read, CALLER_RELOCATIONS[2:6])
    raw = bytes.fromhex(codec['bytes_hex'])
    assert codec['label'] == 'registry_lookup_codec' and len(raw) == 80
    assert CODEC - LOOKUP == int(codec['start'], 16) - 0xfffffe000a5ae354
    assert image.read(CODEC, len(raw)) == raw
    layout['helper_codec'] = dict(start=hex(CODEC), words=20, sha256=sha256(raw).hexdigest())

    original = bytes.fromhex(adapter['bytes'])
    current = image.read(allocate, len(original))
    assert len(original) == 28 and sha256(original).hexdigest() == adapter['sha256']
    assert current[:24] == original[:24]
    tail = image.branch(allocate + 24, 'b')
    layout['typed_allocator_adapter'] = dict(
        entry=hex(allocate), equal_words=6, direct_branch_site=hex(allocate + 24),
        direct_branch_target=hex(tail), sha256=sha256(current).hexdigest(),
    )
    return layout, {shifted(word['pc']) for span in spans for word in span['instructions']}


def verify_banks(image, checks, allocate):
    archive = checks['registry_banks']
    arrays, bases, roots = {}, {}, {}
    for offset, (target, name, bias) in (POOL_ROOTS | EXTRA_BANKS).items():
        name = {'AL': 'EL', 'AR': 'ER'}.get(name, name)
        if name in archive:
            base = target + bias
            arrays[name] = image.read(base, 256)
            assert arrays[name].hex() == archive[name]['bytes_hex']
            roots[name] = verify_fixup(image, POOL + offset, target)
            bases[int(archive[name]['address'], 16)] = base
    assert len(arrays) == 6
    targets = dict(holder=HOLDER, allocate=allocate, allocate_descriptor=HEADER_ALLOC, lookup=LOOKUP)
    bindings = {}
    for row in checks['registry_bank_rules']:
        name = row['name']
        left, right = (arrays[row[k]] for k in ('left_name', 'right_name'))
        key = int(row['key'], 16)
        constant, = {i ^ right[left[i] ^ key] for i in range(256)}
        index = constant + int(row['additive'], 16)
        assert (constant, index) == (int(row['constant'], 16), int(row['index'], 16))
        pointer = row['original_pointer']
        slot = (TABLE if pointer['authenticated'] else POOL) + index * 8
        target = (targets[name] - int(row['bias'], 16)) & U64
        fixup = verify_fixup(image, slot, target, pointer['diversity'])
        bindings[name] = dict(inputs=256, index=hex(index), effective_target=hex(targets[name]),
                              fixup=fixup)
    assert bindings.keys() == targets.keys()
    return dict(roots=roots, rules=bindings), bases


def verify_descriptor(image, archived):
    descriptor = read_descriptor(image, HEADER_ALLOC, 'site.FPHashTable', '21', 16)
    assert all(descriptor[key] == archived[key] for key in ('name', 'signature', 'flags_u32', 'size_bytes'))
    original = bytes.fromhex(archived['normalized64_bytes_hex'])
    current = bytes.fromhex(descriptor['bytes'])
    assert current[:16] == original[:16] and current[24:32] == original[24:32]
    assert current[40:] == original[40:]
    return descriptor


class RegistryReplay(ScalarReplay):
    holder = None

    def load(self, address, width, discarded=False):
        if self.holder is not None and address == HOLDER:
            assert width == 8 and not discarded
            self.holder_reads.append((self.pc, address, width, self.holder))
            return self.holder
        value = super().load(address, width, discarded)
        if self.holder and HEADER <= address < HEADER + 16:
            assert not discarded
            self.holder_reads.append((self.pc, address, width, value))
        return value

    def helper_codec(self, record):
        g, pc = self.g, self.pc
        self.g = [None] * 31
        self.g[0] = record
        for self.pc in range(CODEC, CODEC + 80, 4):
            word, = self.cs.disasm(self.image.read(self.pc, 4), self.pc)
            assert self.step(word) == self.pc + 4
        result = self.g[13]
        self.g, self.pc = g, pc
        return result

    def registry(self, allowed, scalar, archived, bases, allocate, fixture):
        F = self.sp
        S, C, H, J, Z = (int(cut['result'], 16) for cut in self.cuts)
        extent = scalar['committed_cursor_bytes']
        output = scalar['output32']
        raw_status = int(scalar['raw_status32'], 16)
        R = S + 0x968
        protected = self.value(Z, extent)
        cells = {}
        for cell in archived['registry_additional_source_cells']:
            assert cell['root'] == 'F'
            offset, width = int(cell['offset'], 16), cell['size_bytes']
            original = int.from_bytes(bytes.fromhex(cell['reconstructed_bytes_hex']), 'little')
            current = self.value(F + offset, width)
            assert current == bases.get(original, original), (hex(offset), hex(current), hex(original))
            cells[hex(offset)] = dict(value=hex(current), size_bytes=width)
        assert len(cells) == 10
        assert self.value(F+0x648, 8) == S+0xbc4 and self.value(F+0x908, 8) == C+0x418
        assert self.value(F+0x998, 8) == R and self.value(C+0x418, 8) == H
        assert self.value(F+0xaa8, 8) == extent
        assert (self.pc, self.g[23]) == (SUCCESS_PC if output is not None else ERROR_PC, raw_status)
        self.holder_reads = []
        if fixture is not None:
            self.holder = HEADER
            capacity, entries = fixture
            header = bytes(4) + capacity.to_bytes(4, 'little') + entries.to_bytes(8, 'little')
            assert all(HEADER + i not in self.state for i in range(len(header)))
            for base, size in ((F, 0x10f0), (S, 0x4000), (C, 0x1000), (H, 16), (J, 32), (Z, extent)):
                assert HEADER >= base + size or HEADER + len(header) <= base
            self.state.update((HEADER + i, byte) for i, byte in enumerate(header))
            endpoint = LOOKUP
        elif output is not None:
            self.holder = 0
            endpoint = allocate
        else:
            endpoint = CLEANUP

        gap = tuple(self.state.get(R+i) for i in range(0x18, 0x20))
        first_edge, first_store = len(self.edges), len(self.publication_stores)
        visits = 0
        while self.pc != endpoint:
            assert visits < len(allowed) and self.pc in allowed, hex(self.pc)
            self.ix += 1
            word, = self.cs.disasm(self.image.read(self.pc, 4), self.pc)
            if word.mnemonic == 'blraa':
                assert self.pc in (LOOKUP_CALL, ALLOCATE_CALL)
            if self.pc == shifted('0xfffffe000a63683c'):
                assert self.g[8] == (output ^ SUCCESS) and self.g[23] == 0x160
            self.pc = self.step(word)
            visits += 1

        actual = self.publication_stores[first_store:]
        edges = self.edges[first_edge:]
        assert self.value(S+0xbc4, 4) == (output or 0) and self.value(F+0xaa8, 8) == extent
        assert self.value(Z, extent) == protected and self.value(H, 16) == (J << 64) | J
        assert self.value(J+0x18, 8) == Z and self.value(J+0x10, 4) == extent
        assert all(int(a, 16)+w <= Z or Z+extent <= int(a, 16) for _, a, w, _ in actual)
        assert tuple(self.state.get(R+i) for i in range(0x18, 0x20)) == gap
        expected_reads = [] if output is None else [
            (shifted('0xfffffe000a65ac58'), HOLDER, 8, self.holder)
        ]
        result = {}
        transfers = []
        if output is not None:
            assert self.value(F+0x9e0, 8) == HOLDER
            transfers.append(('0xfffffe000a65abf8', 0x8d40))
        if fixture is not None:
            expected_reads.extend([(shifted('0xfffffe000a65b418'), HEADER+8, 8, entries),
                                   (shifted('0xfffffe000a65b41c'), HEADER+4, 4, capacity)])
            transfers.extend([('0xfffffe000a65affc', 0xa830), ('0xfffffe000a6367b4', 0xcb79),
                              ('0xfffffe000a6367fc', 0xd4c), ('0xfffffe000a65b16c', 0x44f9),
                              ('0xfffffe000a65b3ac', 0x9092), ('0xfffffe000a65b408', 0xbe19)])
            tramp = shifted('0xfffffe000a65b5f8')
            outer = shifted('0xfffffe000a636854')
            key = self.helper_codec(R)
            assert key == ((R ^ 0xec7859d5734a22b2) * 0x8c229611) & U64
            k32 = key & U32
            decoded = 0x652019cc00000000 | (output ^ 0x6a48ac59)
            fields = ((0, 8, (decoded-key) & U64), (8, 8, S+0x10), (0x20, 8, entries),
                      (0x10, 8, S+0xa28), (0x28, 4, (k32+0x541) & U32),
                      (0x2c, 4, ((capacity+0x4f950919) & U32) ^ k32))
            assert all(self.value(R+offset, width) == val for offset, width, val in fields)
            sites = ('0xfffffe000a65b4c4', '0xfffffe000a65b4c4', '0xfffffe000a65b4c8',
                     '0xfffffe000a65b4d0', '0xfffffe000a65b4d8', '0xfffffe000a65b4d8')
            origin = [('0xfffffe000a65ac5c', F+0x9e0, 8, HOLDER),
                      ('0xfffffe000a65b18c', C+0x30, 8, outer),
                      ('0xfffffe000a65b3c0', C+0x680, 8, tramp),
                      ('0xfffffe000a65b3c8', S+0xa28, 4, 0)]
            origin.extend((site, R+offset, width, value) for site, (offset, width, value) in zip(sites, fields))
            assert self.value(S+0xa28, 4) == 0 and self.value(C+0x30, 8) == outer
            assert self.value(C+0x680, 8) == tramp
            assert self.g[0] == R and self.g[19] == C+0x440 and self.g[30] == LOOKUP_CALL+4
            pending = ('blraa', LOOKUP_CALL, LOOKUP, 0x6a0f)
            result.update(path='lookup', packet=hex(R), packet_bytes=48, initialized_bytes=40,
                          codec64=hex(key), helper_token=hex(0x541), decoded_key32=hex(output),
                          derived_entry_key64=hex(0x1ee45f68039f9913+output), x0=hex(R))
        elif output is not None:
            transfers.append(('0xfffffe000a65ac84', 0xa830))
            origin = [('0xfffffe000a65ac5c', F+0x9e0, 8, HOLDER)]
            assert self.g[0] == HEADER_ALLOC and self.g[19] == CALLBACK and self.g[30] == ALLOCATE_CALL+4
            pending = ('blraa', ALLOCATE_CALL, allocate, 0xd0c8)
            result.update(path='allocate', x0=hex(HEADER_ALLOC))
        else:
            origin = [('0xfffffe000a641c38', S+0x1c, 4, TYPE_ERROR)]
            assert self.value(S+0x1c, 4) == TYPE_ERROR and self.g[19] == C+0x418
            pending = ('braa', shifted('0xfffffe000a641c5c'), CLEANUP, 0xb23e)
            result.update(path='cleanup', published_status=hex(TYPE_ERROR), status_slot=hex(S+0x1c))
        assert actual == [(hex(shifted(pc)), hex(a), w, hex(v)) for pc, a, w, v in origin], actual
        assert self.holder_reads == expected_reads
        assert [(row['kind'], row['target'], row['modifier64']) for row in edges[:-1]] == [
            ('braa', hex(shifted(target)), hex(modifier)) for target, modifier in transfers
        ]
        kind, pc, target, modifier = pending
        edge = edges[-1]
        assert (edge['kind'], edge['pc'], edge['target'], edge['modifier64']) == (
            kind, hex(pc), hex(target), hex(modifier))
        return dict(result, instruction_visits=visits, source_cells=cells, stores=actual,
                    holder_loads=[dict(pc=hex(p), address=hex(a), size_bytes=w, value=hex(v))
                                  for p, a, w, v in self.holder_reads],
                    logical_edges=edges, x19=hex(self.g[19]),
                    nominal_link=hex(self.g[30]) if kind == 'blraa' else None,
                    transfer=edge, target_executed=False)


def audit(path):
    build = command('sw_vers', '-buildVersion').strip().decode()
    assert build == '26C5035r' and sysctl('kern.uuid').lower() == IDENTITIES[1][1]
    image = Collection(path, IDENTITIES[1])
    registry = receipt('userclient_schema_registry_checks', CHECKS)
    prior = receipt('userclient_schema_registry_audit', AUDIT)
    scalar = receipt('userclient_schema_scalar_checks', SCALAR_CHECKS)
    preceding = receipt('userclient_schema_scalar_audit', SCALAR_SOURCE)
    installed = receipt('live_fairplay_schema_scalar_audit', INSTALLED_SCALAR)
    search = receipt('userclient_schema_search_checks', SEARCH_CHECKS)
    assert registry['kernel_collection_sha256'] == prior['kernel_collection_sha256'] == IDENTITIES[0][0]
    assert prior['checks_sha256'] == CHECKS and prior['conditional_schema_registry_request_established']
    assert registry['scalar_source'] == scalar['source'] and registry['lookup_source'] == scalar['lookup_source']
    assert installed['identity'] == list(IDENTITIES[1]) and installed['historical_audit_sha256'] == SCALAR_SOURCE

    allocate = image.named('_IOMallocTypeImpl')
    layout, allowed = verify_code(image, registry['source'], registry['registry_allocation_adapter'], allocate)
    banks, bases = verify_banks(image, registry, allocate)
    descriptor = verify_descriptor(image, registry['registry_allocation_descriptor'])
    _, search_spans = check_source(image, search)
    _, scalar_spans = check_scalar_layout(image, scalar)
    predecessors = {case['predecessor_case_index']: case for case in registry['predecessor_states']}
    cases = []
    expected = {case['fixture']: case for case in installed['cases']}
    cases_source = partial(scalar_cases, image, scalar, preceding, search_spans, scalar_spans, RegistryReplay)
    headers = {'adid_field': (128, 0x630001a000), 'u32_nonzero': (64, 0x630001b000)}
    for case, replay in cases_source():
        assert json.loads(json.dumps(case)) == expected[case['fixture']]
        index, name, result = case['case_index'], case['fixture'], case['result']
        continuation = replay.registry(allowed, result, predecessors[index], bases, allocate, headers.get(name))
        cases.append(dict(fixture=name, case_index=index, scalar=result, registry=continuation))
    case, replay = next(cases_source())
    assert case['fixture'] == 'adid_field' and case['result']['output32'] == 0
    index, result = case['case_index'], case['result']
    continuation = replay.registry(allowed, result, predecessors[index], bases, allocate, None)
    cases.append(dict(fixture=case['fixture'], case_index=index, scalar=result, registry=continuation))
    assert len(cases) == 6 and len(prior['source_proofs']) == 13
    with ThreadPoolExecutor(max_workers=4) as workers:
        proofs = list(workers.map(partial(replay_proof, timeout_seconds=PROOF_TIMEOUT_SECONDS),
                                  prior['source_proofs']))
    return dict(build=build, identity=IDENTITIES[1], layout=layout, banks=banks,
                allocation_descriptor=descriptor, cases=cases, source_proofs=proofs,
                historical_checks_sha256=CHECKS, historical_audit_sha256=AUDIT,
                installed_scalar_audit_sha256=INSTALLED_SCALAR, proof_timeout_seconds=PROOF_TIMEOUT_SECONDS,
                continuous_writer_execution=False, native_transaction_observed=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    print(json.dumps(audit(parser.parse_args().collection), indent=2))
