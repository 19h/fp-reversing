#!/usr/bin/env python3
"""Replay the second installed FPMessage parse through publication and mode dispatch."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from functools import partial
import json
from pathlib import Path

from audit_daemon_iokit_native_registry import command, sysctl
from audit_live_fairplay_context_lifecycle import replay_proof
from audit_live_fairplay_early_data import CHECKS as DATA_CHECKS, DATA_CALL, check_bindings
from audit_live_fairplay_early_header import CHECKS as HEADER_CHECKS, NODE_CALL, NODE_TYPE, SUCCESS, node_bindings
from audit_live_fairplay_early_publication import (
    CHECKS as PUBLICATION_CHECKS, ENTRY, PROOF_TIMEOUT_SECONDS, check_bank,
)
from audit_live_fairplay_early_writer import AUDITS as WRITER_AUDITS, CHECKS as WRITER_CHECKS
from audit_live_fairplay_entry import INPUT_BYTE, in_private, shifted, verify_layout
from audit_live_fairplay_message_initialization import (
    CHECKS as INITIALIZATION_CHECKS, MESSAGE, initialization_cases, verify_source,
)
from audit_live_fairplay_message_parser import (
    CHECKS as PARSER_CHECKS, COMPLETION, CONTAINER, FLAG_GATE, FLAG_LOAD, FLAG_TARGETS, PUBLISH,
    ParserReplay, verify_parser,
)
from audit_live_fairplay_uidlist import receipt
from audit_live_kext_selector26 import Collection, IDENTITIES

PREFIX = '58499ee3d551c128a09b05c252f24855b1c90b119f950cdd84c8d0def3c320ce'
CHECKS = dict(early_header=HEADER_CHECKS, **DATA_CHECKS, **WRITER_CHECKS, early_publication=PUBLICATION_CHECKS)
NODE = CONTAINER+0x40
RECORD = CONTAINER+0x80
INPUT_ORDER = (6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 10, 11, 12, 13)
APPEND = 0xfffffe000a6a3d58


def protect(raw, address):
    result = bytearray()
    for at, value in enumerate(raw, address):
        aligned = at & ~7
        rotated = (aligned >> 8) | ((aligned & 255) << 56)
        summed = (rotated + 0x02e859d27e491464) & 0xffffffffffffffff
        lane = (summed ^ 0x4dae26df20976138) >> (8*(at & 7))
        result.append(value ^ (lane & 255))
    return bytes(result)


def edge_contract(edge):
    return tuple(edge[key] for key in ('pc', 'target', 'kind', 'modifier64'))


class RecordReplay(ParserReplay):
    scratch_reads = None

    def load(self, address, width, discarded=False):
        fallback = self.scratch_reads.get(self.pc) if self.scratch_reads is not None else None
        if fallback is not None:
            assert (address, width, discarded) == (*fallback, False)
            missing = [offset for offset in range(width) if address+offset not in self.state]
            if missing:
                data = bytes(self.state.get(address+i, self.scratch_byte(address+i)) for i in range(width))
                value = int.from_bytes(data, 'little')
                self.scratch_loads.append(dict(pc=hex(self.pc), address=hex(address), missing=missing))
                self.private_reads.append((address, width, False))
                self.parser_reads.append((hex(self.pc), hex(address), width, hex(value)))
                return value
        return super().load(address, width, discarded)

    def scratch_byte(self, address):
        return ((address ^ address >> 8)*0xb7 + 0x1d) & 255 if self.patterned_scratch else 0

    def finish(self, allowed, writer, mode, patterned_scratch):
        assert self.pc == INPUT_BYTE
        S, C, H, J, Z = (int(cut['result'], 16) for cut in self.cuts)
        F, I, N = self.sp, self.input_address, self.input_extent
        assert N == len(self.payload) == 14
        assert self.value(CONTAINER, 16) == 0
        assert in_private(NODE, 32) and in_private(RECORD, N)
        assert not any(a in self.state for a in range(NODE, RECORD+N))
        before = self.message_bytes()
        first_record = self.value(Z, N).to_bytes(N, 'little')
        assert first_record == protect(self.payload, Z)
        prior_reads = len(self.input_loads)
        self.allow_input_reads = True
        self.patterned_scratch = patterned_scratch
        roots = {'S': S, 'C': C}
        self.scratch_reads = {
            shifted(c['source_PC']): (roots[c['root']]+int(c['offset'], 16), c['size_bytes'])
            for c in writer['predecessor_handoffs'][0]['writer_input_cells']
            if '00' in c['known_mask_hex']
        }
        assert len(self.scratch_reads) == 8
        self.scratch_loads = []
        first_read, first_store, first_edge = len(self.parser_reads), len(self.publication_stores), len(self.edges)
        sites, calls, landmarks = [], [], {}
        flag = {'mode_zero': 0, 'mode_nonzero': 1}[mode]
        target = FLAG_TARGETS[flag]
        checkpoints = {ENTRY, COMPLETION}
        while self.pc != target:
            assert self.pc in allowed and len(sites) < 3*len(allowed), hex(self.pc)
            self.ix += 1
            sites.append(hex(self.pc))
            if self.pc in checkpoints:
                assert hex(self.pc) not in landmarks
                landmarks[hex(self.pc)] = {f'x{j}': hex(self.g[j]) for j in (0, 1, 2, 3, 4, 7, 12, 20, 21, 22, 23, 28, 30)}
            if self.pc == ENTRY:
                assert self.value(CONTAINER, 16) == 0 and self.value(RECORD, N).to_bytes(N, 'little') == protect(
                    self.payload, RECORD)
            if self.pc == COMPLETION:
                assert self.value(C+0x50, 8) == 0 and self.value(CONTAINER, 16) == NODE | (NODE << 64)
                assert self.value(MESSAGE, 8) == 0 and self.value(S+0xa10, 8) == N
            word, = self.cs.disasm(self.image.read(self.pc, 4), self.pc)
            if self.pc == NODE_CALL:
                assert self.g[0] == NODE_TYPE
                assert self.value(S+0xa10, 8) == N and self.value(C+0x20, 8) == CONTAINER
                allocate = self.image.named('_IOMallocTypeImpl')
                calls.append(self.external_return(word, self.pc, F, allocate, 0xd0c8, NODE, 1))
                self.pc += 4
            elif self.pc == DATA_CALL:
                assert self.g[0] == N and self.value(C+0x58, 8) == NODE
                assert self.value(NODE, 16) == 0 and self.value(NODE+0x10, 4) == N
                allocate = self.image.named('_IOMallocData')
                calls.append(self.external_return(word, self.pc, F, allocate, 0xca0c, RECORD, 2))
                self.pc += 4
            else:
                assert word.mnemonic != 'blraa', hex(self.pc)
                self.pc = self.step(word)
        offsets = self.input_loads[prior_reads:]
        assert tuple(offsets) == INPUT_ORDER and tuple(self.input_loads[:prior_reads]) == INPUT_ORDER
        assert len(calls) == 2 and len(landmarks) == len(checkpoints) and self.sp == F
        assert self.value(H, 8) == self.value(H+8, 8) == J and self.value(J+0x18, 8) == Z
        assert self.value(Z, N).to_bytes(N, 'little') == first_record
        assert self.value(CONTAINER, 8) == self.value(CONTAINER+8, 8) == NODE
        assert self.value(NODE, 16) == 0 and self.value(NODE+0x10, 4) == N
        assert self.value(NODE+0x18, 8) == RECORD and self.value(S+0xa10, 8) == N
        assert self.value(MESSAGE, 8) == CONTAINER and self.message_bytes()[8:] == before[8:]
        assert self.value(S+0xc94, 4) == self.g[23] == SUCCESS
        loads, stores, edges = (self.parser_reads[first_read:], self.publication_stores[first_store:],
                                self.edges[first_edge:])
        assert [(addr, width, val) for _, addr, width, val in loads if I <= int(addr, 16) < I+N] == [
            (hex(I+offset), 1, hex(self.payload[offset])) for offset in INPUT_ORDER]
        assert all(int(addr, 16)+width <= I or I+N <= int(addr, 16) for _, addr, width, _ in stores)
        assert len(self.scratch_loads) == 8 and sum(len(row['missing']) for row in self.scratch_loads) == 46
        assert [row for row in loads if row[0] == hex(FLAG_LOAD)] == [(hex(FLAG_LOAD), hex(MESSAGE+0x60), 1, hex(flag))]
        assert [row for row in stores if row[0] == hex(PUBLISH)] == [(hex(PUBLISH), hex(MESSAGE), 8, hex(CONTAINER))]
        assert [row for row in stores if row[0] == hex(APPEND)] == [
            (hex(APPEND), hex(CONTAINER+offset), 8, hex(NODE)) for offset in (0, 8)]
        serialized = self.value(RECORD, N).to_bytes(N, 'little')
        assert serialized == protect(self.payload, RECORD)
        emitted = [(int(addr, 16), width) for _, addr, width, _ in stores if RECORD <= int(addr, 16) < RECORD+N]
        assert sorted(byte for addr, width in emitted for byte in range(addr, addr+width)) == list(range(RECORD, RECORD+N))
        assert (edges[-1]['pc'], edges[-1]['modifier64'], edges[-1]['target']) == (hex(FLAG_GATE), '0xeeda', hex(target))
        return dict(sites=sites, calls=calls, loads=loads, stores=stores, edges=edges, input_offsets=offsets,
                    scratch_reads=self.scratch_loads, landmarks=landmarks, serialized_hex=serialized.hex(),
                    first_record_hex=first_record.hex(), first_record=hex(Z), second_record=hex(RECORD),
                    input_hex=self.payload.hex(), flag=flag, target=hex(target))


def audit(path):
    build = command('sw_vers', '-buildVersion').strip().decode()
    assert build == '26C5035r' and sysctl('kern.uuid').lower() == IDENTITIES[1][1]
    image = Collection(path, IDENTITIES[1])
    archived = {name: receipt(f'userclient_{name}_checks', digest) for name, digest in CHECKS.items()}
    parser = receipt('userclient_message_parser_checks', PARSER_CHECKS)
    prefix = receipt('live_fairplay_message_parser_audit', PREFIX)
    assert prefix['historical_checks_sha256'] == PARSER_CHECKS and prefix['identity'] == list(IDENTITIES[1])
    init = receipt('userclient_message_initialization_checks', INITIALIZATION_CHECKS)
    assert all(row['kernel_collection_sha256'] == IDENTITIES[0][0] for row in (*archived.values(), parser, init))
    sources = {name: row['source'] for name, row in archived.items()}
    node = sources['early_node']
    sources['early_node'] = dict(node, spans=[s for s in node['spans'] if s['label'].startswith('source_')])
    layout = verify_layout(image, sources)
    bindings = dict(header=node_bindings(image, sources['early_header']),
                    allocations=check_bindings(image, node, sources['early_data']),
                    publication=check_bank(image, sources['early_publication']))
    allocate = image.named('_IOMallocTypeImpl')
    _, parser_words, literals, _ = verify_parser(image, parser, allocate)
    allowed = parser_words | {shifted(word['pc']) for source in sources.values()
                              for span in source['spans'] for word in span['instructions']}
    parents = {(r['fixture'], r['mode']): r for r in prefix['cases'] if r['allocation_nonnull']}
    cases, baseline = [], {}
    init_source = verify_source(image, init, allocate)
    for patterned in (False, True):
        for case, replay in initialization_cases(image, init, init_source, (True,), RecordReplay):
            fixture, mode = case['fixture'], case['result']['profile']
            parent = parents[(fixture, mode)]
            start = replay.reenter(parser_words, literals, allocate, True)
            assert json.loads(json.dumps(start)) == parent['prefix']
            result = replay.finish(allowed, archived['early_writer'], mode, patterned)
            expected = parent['independent_completion']
            ix = result['sites'].index(hex(COMPLETION))
            assert result['sites'][ix:] == expected['sites']
            assert list(map(edge_contract, result['edges'][-len(expected['edges']):])) == list(
                map(edge_contract, expected['edges']))
            assert json.loads(json.dumps(result['stores'][-2:])) == expected['stores']
            incoming = result['landmarks'][hex(COMPLETION)]
            for register, value in expected['seed_registers'].items():
                if register != 'w22':
                    assert incoming['x'+register[1:]] == value
            assert incoming['x22'] == bindings['publication']['descriptor']['address']
            projection = (result['sites'], result['edges'], result['serialized_hex'],
                          [(pc, address, width) for pc, address, width, _ in result['loads']],
                          [(pc, address, width) for pc, address, width, _ in result['stores']])
            if patterned:
                assert projection == baseline[(fixture, mode)]
            else:
                baseline[(fixture, mode)] = projection
            cases.append(dict(fixture=fixture, mode=mode, patterned_scratch=patterned, result=result))
    assert len(cases) == 8 and len(parents) == 4
    proofs = []
    for name, digest in WRITER_AUDITS.items():
        prior = receipt(f'userclient_{name}_audit', digest)
        assert prior['checks_sha256'] == CHECKS[name]
        assert len(prior['source_proofs']) == {'early_writer': 14, 'early_payload': 15}[name]
        proofs.extend(prior['source_proofs'])
    with ThreadPoolExecutor(max_workers=4) as workers:
        source_proofs = list(workers.map(partial(replay_proof, timeout_seconds=PROOF_TIMEOUT_SECONDS), proofs))
    return dict(build=build, identity=IDENTITIES[1], source_layout=layout, bindings=bindings, cases=cases,
                historical_checks=CHECKS, historical_writer_audits=WRITER_AUDITS, source_proofs=source_proofs,
                installed_prefix_sha256=PREFIX, complete_second_parse_replayed=True,
                native_allocators_executed=False, native_PAC_verified=False, native_transaction_observed=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    print(json.dumps(audit(parser.parse_args().collection), indent=2))
