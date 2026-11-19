#!/usr/bin/env python3
"""Carry reconstructed selector 26 input through the installed first parser."""

import argparse
import json
from pathlib import Path

from audit_daemon_selector26_request_bytes import archive, archived_avp, records, selector_requests, sha
from audit_live_fairplay_context_lifecycle import CODE_DELTA, function_starts
from audit_live_fairplay_early_data import DATA_CALL
from audit_live_fairplay_early_header import CHECKS as HEADER_CHECKS, NODE_CALL, NODE_TYPE, SUCCESS
from audit_live_fairplay_early_publication import EXHAUSTED, NEXT_HEADER
from audit_live_fairplay_early_writer import CHECKS as WRITER_CHECKS
from audit_live_fairplay_entry import CONTROLLERS, INPUT_BYTE, InstalledReplay, STAGING_CALL, TLV_RELEASE, in_private, shifted
from audit_live_fairplay_message_parse_completion import APPEND, RecordReplay, protect
from audit_live_fairplay_uidlist import receipt
from audit_live_kext_selector26 import Collection, IDENTITIES
from kext_port_tools import IMAGE as ORIGINAL
from replay_userclient_fpttlv_entry import PRIVATE

REQUEST_SHA = '2e1a288a55f811522c497d0d3e27ba670779e912b5f8ca81352d12dcb67fc82f'
COMMAND_RECEIPT_SHA = '0074b126c7bc1dde66e5842de7870fbc367b62f326236ecc05387f06c89d84c5'
COMMAND_BRANCH = 0xfffffe000a697e88
ZERO_TAG_BRANCH = shifted('0xfffffe000a661944')
ZERO_TAG_SUCCESS = shifted('0xfffffe000a661948')
NODE_AREA = PRIVATE + 0x1a000
DATA_AREA = PRIVATE + 0x1a800
DATA_FREE = 0xfffffe000a6a1978
NODE_FREE = 0xfffffe000a6a1898


class AggregateReplay(RecordReplay):
    def __init__(self, image, template, payload, scratch, patterned, provider=0):
        InstalledReplay.__init__(self, image, template)
        self.payload = payload
        self.base = self.g[0]
        self.extent = self.g[1] = len(payload)
        self.provider = self.g[2] = provider
        self.end = self.base + self.extent
        self.input_address = self.base
        self.input_extent = self.extent
        self.input_loads = []
        self.allow_input_reads = True
        self.patterned_scratch = patterned
        self.scratch_loads = []
        self.parser_reads = None
        self.publication_stores = []
        self.words = {}
        self.sites = []
        self.nodes = []
        self.data_regions = []
        self.calls = []
        self.events = []
        self.scratch_plan = scratch
        self.retired = []
        self.bindings = {}

    def check_live(self, address, width):
        assert all(address + width <= a or a + n <= address for a, n in self.retired)

    def load(self, address, width, discarded=False):
        self.check_live(address, width)
        value = super().load(address, width, discarded)
        if width == 8 and address not in CONTROLLERS and not in_private(address, width):
            row = self.image.fixups.get(self.image.offset(address, width))
            if row is not None and address not in self.bindings:
                assert int(row['raw'], 16) == int.from_bytes(self.image.read(address, 8), 'little')
                assert int(row['target'], 16) == value
                self.bindings[address] = self.image.pointer(address)
        return value

    def store(self, address, width, value):
        self.check_live(address, width)
        return super().store(address, width, value)

    def word(self):
        if self.pc not in self.words:
            word, = self.cs.disasm(self.image.read(self.pc, 4), self.pc)
            self.words[self.pc] = word
        return self.words[self.pc]

    def prefix(self):
        fixtures = {row['source_visit_index']: row for row in self.row['API_models']}
        for self.ix, visit in enumerate(self.row['source_visits']):
            if self.pc == INPUT_BYTE:
                break
            assert self.pc == shifted(visit['pc'])
            self.sites.append(self.pc)
            word = self.word()
            if self.ix in fixtures:
                self.pc = InstalledReplay.allocation(self, word, fixtures[self.ix])
            else:
                self.pc = self.step(word)
        assert self.pc == INPUT_BYTE and self.input_loads == []
        self.parser_reads = []
        assert len(self.cuts) == 3
        self.workspace, self.caller, self.container = (int(cut['result'], 16) for cut in self.cuts)
        S, C = self.workspace, self.caller
        self.scratch_reads = {
            shifted(cell['source_PC']): ({'S': S, 'C': C}[cell['root']] + int(cell['offset'], 16), cell['size_bytes'])
            for cell in self.scratch_plan
            if '00' in cell['known_mask_hex']
        }
        assert len(self.scratch_reads) == 8
        assert self.value(self.sp + 0x8f8, 8) == self.base
        assert self.value(self.sp + 0x878, 8) == self.extent
        assert self.value(self.sp + 0x738, 8) == self.provider
        assert self.value(C + 0x98, 8) == self.base and self.value(S + 0xb5c, 4) == self.extent ^ SUCCESS
        assert self.value(C + 0xb0, 8) == self.container and self.value(self.container, 16) == 0

    def allocator(self, word, headers):
        S, C = self.workspace, self.caller
        if self.pc == NODE_CALL:
            index = len(self.nodes)
            assert index < len(headers)
            header = headers[index]
            assert header['key'] != '00000000' and self.g[0] == NODE_TYPE
            assert self.value(S + 0xa10, 8) == header['end']
            name, modifier = '_IOMallocTypeImpl', 0xd0c8
            result = NODE_AREA + 0x40*index
            self.nodes.append(result)
        else:
            index = len(self.data_regions)
            assert index + 1 == len(self.nodes)
            header = headers[index]
            size = header['body_size'] + 10
            assert self.g[0] == size and self.value(C + 0x58, 8) == self.nodes[index]
            assert self.value(self.nodes[index] + 0x10, 4) == size
            name, modifier = '_IOMallocData', 0xca0c
            result = DATA_AREA + 0x200*index
            self.data_regions.append((result, size))
        assert in_private(result, 32) and all(result + i not in self.state for i in range(32))
        called = self.external_return(word, self.pc, self.sp, self.image.named(name), modifier,
                                      result, len(self.calls) + 1)
        self.calls.append(dict(called, function=name, wire_offset=header['offset']))
        return self.pc + 4

    def check_chain(self, headers):
        H = self.container
        nodes = self.nodes
        assert nodes and len(nodes) == len(self.data_regions)
        assert self.value(H, 8) == nodes[0] and self.value(H + 8, 8) == nodes[-1]
        output = []
        for index, (node, (address, size)) in enumerate(zip(nodes, self.data_regions, strict=True)):
            head = headers[index]
            raw = self.value(address, size).to_bytes(size, 'little')
            expected = self.payload[head['offset']:head['end']]
            assert raw == protect(expected, address)
            prev = nodes[index-1] if index else 0
            successor = nodes[index+1] if index + 1 < len(nodes) else 0
            assert self.value(node, 8) == successor and self.value(node + 8, 8) == prev
            assert self.value(node + 0x10, 4) == size and self.value(node + 0x18, 8) == address
            output.append({'offset': head['offset'], 'key': head['key'], 'extent': size,
                           'node': hex(node), 'record': hex(address), 'stored_sha256': sha(raw),
                           'decoded_sha256': sha(expected)})
        return output

    def retire(self, word):
        if self.pc == DATA_FREE:
            address, size = self.g[:2]
            assert (address, size) in self.data_regions
            name, modifier = '_IOFreeData', 0x85d
        else:
            descriptor, address = self.g[:2]
            name, modifier = '_IOFreeTypeImpl', 0x4d6a
            if self.pc == NODE_FREE:
                assert descriptor == 0xfffffe00084928c0 and address in self.nodes
                size = 32
            else:
                assert descriptor == 0xfffffe0008492880 and address == self.container
                size = 16
        self.check_live(address, size)
        called = self.external_return(word, self.pc, self.sp, self.image.named(name), modifier,
                                      0, len(self.calls) + 1)
        self.calls.append(dict(called, function=name, retired=hex(address), size_bytes=size))
        self.retired.append((address, size))
        return self.pc + 4

    def run_aggregate(self):
        self.prefix()
        start = self.image.named('_PRnut72j9')
        roots = function_starts(self.image)
        end = roots[roots.index(start) + 1]
        headers, tail = records(self.payload)
        assert tail is None
        S, C, H = self.workspace, self.caller, self.container
        published = None
        while self.pc != STAGING_CALL:
            assert len(self.sites) < 30000 and start <= self.pc < end and self.pc != COMMAND_BRANCH, hex(self.pc)
            self.ix += 1
            self.sites.append(self.pc)
            if self.pc in (NEXT_HEADER, INPUT_BYTE, EXHAUSTED, APPEND, ZERO_TAG_BRANCH):
                self.events.append({'site': hex(self.pc), 'cursor': self.value(S+0xa10, 8),
                                    'input_reads': len(self.input_loads)})
            word = self.word()
            if self.pc in (NODE_CALL, DATA_CALL):
                self.pc = self.allocator(word, headers)
            elif self.pc in (DATA_FREE, NODE_FREE, TLV_RELEASE):
                if published is None:
                    published = self.check_chain(headers)
                self.pc = self.retire(word)
            else:
                assert word.mnemonic != 'blraa', (hex(self.pc), word.op_str)
                self.pc = self.step(word)
        assert [r['key'] for r in published] == ['744b91e8', '812b9aed', '172ba3a8']
        expected_releases = []
        for node, data in zip(self.nodes, self.data_regions, strict=True):
            expected_releases.extend((data, (node, 32)))
        assert self.retired == expected_releases + [(H, 16)]
        assert self.value(C + 0x418, 8) == 0
        assert all(C+0x600+i not in self.state for i in range(8))
        assert self.value(S+0xc94, 4) == SUCCESS and self.value(S+0xa10, 8) == self.extent
        assert sorted(self.input_loads) == list(range(self.extent - 1))
        zero_edge, = (row for row in self.edges if row['pc'] == hex(ZERO_TAG_BRANCH)
                      and row['target'] == hex(ZERO_TAG_SUCCESS))
        word = self.word()
        assert word.mnemonic == 'blraa' and self.g[0] == self.extent
        assert self.reg(word.reg_name(word.operands[0].reg)) == self.image.named('_IOMallocData')
        assert self.g[17] == 0xca0c
        assert not any(self.base <= int(addr, 16) < self.end for _, addr, _, _ in self.publication_stores)
        return {
            'published': published, 'events': self.events, 'calls': self.calls,
            'instruction_visits': len(self.sites), 'edges': self.edges,
            'scratch_loads': self.scratch_loads, 'input_offsets': self.input_loads,
            'endpoint': hex(self.pc), 'raw_status': hex(self.g[23]), 'cursor': self.value(S+0xa10, 8),
            'saved_parser_status': hex(self.value(S+0xc94, 4)), 'x0': self.g[0],
            'zero_tag_edge': zero_edge, 'command_request_reached': False,
        }


def inputs():
    parent, digest = archive('daemon_selector26_request_bytes_audit')
    command, command_digest = archive('daemon_selector26_command_audit')
    assert digest == REQUEST_SHA and command_digest == COMMAND_RECEIPT_SHA
    assert command['parent_receipt_sha256'] == digest
    fixtures = {}
    packets, packet_rows, _ = archived_avp()
    prior = {row['aggregate_sha256']: row for row in command['daemon_cases']}

    def observe(_, blob, case):
        digest = case['aggregate_sha256']
        assert prior[digest]['command_record'] == blob[:14].hex()
        fixtures[digest] = blob

    cases, fixups = selector_requests(packets, packet_rows, observe)
    assert cases == parent['cases'] and fixups == parent['verified_fixups']
    return [(row, fixtures[row['aggregate_sha256']]) for row in cases]


def kernel_inputs():
    header = receipt('userclient_early_header_checks', HEADER_CHECKS)
    template = next(row for row in header['cases']
                    if row['input']['profile'] == 'unknown_type'
                    and row['input']['placement'] == 0 and row['input']['global_fixture'] == 'original')
    writer = receipt('userclient_early_writer_checks', WRITER_CHECKS['early_writer'])
    scratch = writer['predecessor_handoffs'][0]['writer_input_cells']
    return template, scratch


def replay_cases(image, fixtures):
    template, scratch = kernel_inputs()
    cases, words, fixups = [], {}, {}
    for source, blob in fixtures:
        assert sha(blob) == source['aggregate_sha256']
        baseline = None
        for provider in (0, PRIVATE + 0x1000):
            for patterned in (False, True):
                replay = AggregateReplay(image, template, blob, scratch, patterned, provider)
                row = replay.run_aggregate()
                if baseline is None:
                    baseline = row.copy()
                else:
                    assert row == baseline
                row.update(aggregate_sha256=source['aggregate_sha256'], caller_class=source['class'],
                           aggregate_size=len(blob), patterned_scratch=patterned, provider_nonzero=bool(provider))
                cases.append(row)
                words.update(replay.words)
                fixups.update(replay.bindings)
    differences = []
    for pc, word in sorted(words.items()):
        old = ORIGINAL.read(pc - CODE_DELTA, 4)
        if word.bytes != old:
            differences.append({'pc': hex(pc), 'old_bytes': old.hex(), 'installed_bytes': word.bytes.hex(),
                                'instruction': f'{word.mnemonic} {word.op_str}'})
    return {'collection_identity': IDENTITIES[1], 'cases': cases, 'original_words_compared': len(words),
            'relocated_words': differences, 'loaded_fixups': [fixups[address] for address in sorted(fixups)],
            'parent_request_sha256': REQUEST_SHA, 'parent_command_sha256': COMMAND_RECEIPT_SHA,
            'native_transaction_observed': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    parser.add_argument('receipt', type=Path)
    args = parser.parse_args()
    image = Collection(args.collection, IDENTITIES[1])
    args.receipt.write_text(json.dumps(replay_cases(image, inputs()), indent=2, sort_keys=True) + '\n')


if __name__ == '__main__':
    main()
