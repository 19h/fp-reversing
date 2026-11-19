#!/usr/bin/env python3
"""Join installed fallback allocation, protected parsing and selector 26 span publication."""

import argparse
import json
from pathlib import Path

from audit_daemon_selector26_request_bytes import archive, records, sha
from audit_live_fairplay_context_lifecycle import CODE_DELTA, function_starts
from audit_live_fairplay_entry import STAGING_CALL, in_private, verify_fixup
from audit_live_fairplay_selector26_parse import (
    AggregateReplay, Collection, IDENTITIES, ORIGINAL, PRIVATE, SUCCESS, inputs, kernel_inputs, protect,
)

PARENT_SHA = 'bb95c2a4ba4dddf097816590c64f2a944924d9691dc40adf5902572947f87c01'
ALLOC_CONTAINER = 0xfffffe000a683228
ALLOC_NODE = 0xfffffe000a68375c
ALLOC_RECORD = 0xfffffe000a683950
FREE_CONTEXT = 0xfffffe000a6a73f0
FREE_WORKSPACE = 0xfffffe000a6a7440
COMMAND_RESUME = 0xfffffe000a697d98
COMMAND_COMPARE = 0xfffffe000a67bee0
NULL_PROVIDER = 0xfffffe000a698090
READER_ENTRY = 0xfffffe000a6a3bb8
READER_RESUME = 0xfffffe000a698254
READER_CALL = 0xfffffe000a67ef5c
ALLOC_OUTPUT = 0xfffffe000a67f118
CONTAINER_TYPE, NODE_TYPE, CONTEXT_TYPE = 0xfffffe00084920c0, 0xfffffe0008492ac0, 0xfffffe0008492500
B, H = PRIVATE + 0x1c000, PRIVATE + 0x1e000
NODES = tuple(H + 0x100 + 0x40 * i for i in range(3))
DATA = tuple(H + 0x800 + 0x200 * i for i in range(3))
OUT = PRIVATE + 0x1f000


def describe(image, address, name, signature, size, flags):
    raw = image.read(address, 64)
    assert int.from_bytes(raw[40:44], 'little') == flags
    assert int.from_bytes(raw[44:48], 'little') == size
    pointers = {}
    for offset, value in ((16, name), (32, signature)):
        slot = address + offset
        pointer = image.pointer(slot)
        encoded = int(pointer['raw'], 16)
        target = int(pointer['target'], 16)
        assert encoded == int.from_bytes(image.read(slot, 8), 'little')
        assert image.read(target, len(value) + 1) == value.encode() + bytes(1)
        pointers[hex(offset)] = pointer
    return dict(address=hex(address), name=name, signature=signature, size_bytes=size,
                flags=hex(flags), fixups=pointers)


class FallbackReplay(AggregateReplay):
    def call(self, frame, name, args, modifier, result=None, size=None):
        word = self.word()
        pc = self.pc
        target = self.image.named(name)
        assert word.mnemonic == 'blraa' and self.sp == frame
        assert tuple(self.g[:len(args)]) == args
        target_reg, modifier_reg = (word.reg_name(op.reg) for op in word.operands)
        assert self.reg(target_reg) == target and self.reg(modifier_reg) == modifier
        if size is not None and result:
            assert in_private(result, size)
            self.check_live(result, size)
            assert self.end <= result or result + size <= self.base
            assert all(result + i not in self.state for i in range(size))
            assert all(result + size <= at or at + n <= result for at, n in self.new_objects)
            self.new_objects.append((result, size))
        row = dict(pc=hex(pc), target=hex(target), modifier=hex(modifier), link=hex(pc+4))
        if result is not None:
            row = self.external_return(word, pc, frame, target, modifier, result, 101 + len(self.fallback_calls))
            self.pc += 4
        self.fallback_calls.append(dict(row, function=name, arguments=list(map(hex, args))))

    @staticmethod
    def accesses(journal, address, size):
        return [(pc, int(at, 16) - address, width, int(value, 16))
                for pc, at, width, value in journal
                if address < int(at, 16) + width and int(at, 16) < address + size]

    def check_copy(self, first_input, first_load, first_store):
        size = self.extent
        offsets = list(range(size - 1, -1, -1))
        assert self.input_loads[first_input:] == offsets
        masked = protect(self.payload, B)
        assert self.value(B, size).to_bytes(size, 'little') == masked
        writes = self.accesses(self.publication_stores[first_store:], B, size)
        reads = self.accesses(self.parser_reads[first_load:], self.base, size)
        assert reads == [(hex(0xfffffe000a682fa0), i, 1, self.payload[i]) for i in offsets]
        assert writes == [(hex(0xfffffe000a682fd8), i, 1, masked[i]) for i in offsets]
        return dict(buffer=hex(B), size_bytes=size, protected_sha256=sha(masked),
                    decoded_sha256=sha(self.payload), first_offset=offsets[0], last_offset=offsets[-1],
                    read_pc=reads[0][0], write_pc=writes[0][0])

    def check_publication(self, headers, first_load, first_store, frame):
        C, S = self.caller, self.workspace
        assert self.value(C + 0x600, 8) == H and self.value(C + 0x228, 8) == H
        assert self.value(H, 8) == NODES[0] and self.value(H + 8, 8) == NODES[-1]
        assert self.g[23] == SUCCESS and self.value(frame + 0xa80, 8) == self.extent
        writes = self.accesses(self.publication_stores[first_store:], C + 0x600, 8)
        assert writes == [(hex(0xfffffe000a683034), 0, 8, 0),
                          (hex(0xfffffe000a6a1c60), 0, 8, H)]
        reads = self.accesses(self.parser_reads[first_load:], B, self.extent)
        assert sorted(offset for _, offset, _, _ in reads) == list(range(self.extent - 1))
        mask = protect(self.payload, B)
        assert all(width == 1 and mask[offset] == value for _, offset, width, value in reads)
        cursors = self.accesses(self.publication_stores[first_store:], frame + 0xa80, 8)
        assert [(offset, width, value) for _, offset, width, value in cursors] == [
            (0, 8, value) for value in [0, *(row['end'] for row in headers)]
        ]
        assert self.value(S + 0xc8c, 4) == self.extent ^ SUCCESS
        published = []
        for index, head in enumerate(headers[:3]):
            start, end = head['offset'], head['end']
            node, data = NODES[index], DATA[index]
            assert self.value(node, 8) == (NODES[index+1] if index+1 < len(NODES) else 0)
            assert self.value(node + 8, 8) == (NODES[index-1] if index else 0)
            assert self.value(node + 0x10, 4) == end - start and self.value(node + 0x18, 8) == data
            serialized = self.value(data, end - start).to_bytes(end - start, 'little')
            assert serialized == protect(self.payload[start:end], data)
            published.append(dict(tag=head['key'], node=hex(node), data=hex(data), offset=start,
                                  size_bytes=end-start, protected_sha256=sha(serialized),
                                  decoded_sha256=sha(self.payload[start:end])))
        return dict(container=hex(H), output_cell=hex(C + 0x600), records=published,
                    parser_reads=reads, cursors=cursors, output_stores=writes, raw_status=hex(SUCCESS))

    def check_reader(self, headers, first_load, first_store):
        C, S = self.caller, self.workspace
        assert self.g[23] == SUCCESS and self.value(C + 0x128, 8) == OUT
        assert self.value(S + 0xaa8, 4) == 19 ^ SUCCESS
        header = headers[2]
        expected = self.payload[header['offset']+10:header['end']]
        assert len(expected) == 19
        assert self.value(OUT, 19).to_bytes(19, 'little') == expected
        writes = self.publication_stores[first_store:]
        assert self.accesses(writes, OUT, 19) == [
            (hex(0xfffffe000a67f27c), i, 1, expected[i]) for i in range(18, -1, -1)
        ]
        assert self.accesses(writes, C + 0x128, 8) == [(hex(0xfffffe000a67f2a8), 0, 8, OUT)]
        assert self.accesses(writes, S + 0xaa8, 4) == [(hex(0xfffffe000a67efe8), 0, 4, 19 ^ SUCCESS)]
        edge = self.edges[-1]
        assert (edge['pc'], edge['target'], edge['modifier64']) == (
            hex(0xfffffe000a6a42ac), hex(READER_RESUME), '0x3aa3'
        )
        node_reads = []
        for index, head in enumerate(headers[:3]):
            start, end = head['offset'], head['end']
            masked = protect(self.payload[start:end], DATA[index])
            reads = self.accesses(self.parser_reads[first_load:], DATA[index], len(masked))
            assert all(width == 1 and 0 <= offset < len(masked) and masked[offset] == value
                       for _, offset, width, value in reads)
            offsets = [offset for _, offset, _, _ in reads]
            if index < 2:
                assert offsets == list(range(4))
            else:
                assert offsets[:4] == list(range(4)) and offsets[-19:] == list(range(28, 9, -1))
                assert set(offsets) == set(range(29))
            node_reads.append(dict(tag=head['key'], offsets=offsets))
        return dict(decoded_sha256=sha(expected), payload_offset=header['offset']+10,
                    payload_size_bytes=19, last_byte=expected[-1], publication_pc=hex(0xfffffe000a67f2a8),
                    pointer_cell=hex(C + 0x128), length_cell=hex(S + 0xaa8), encoded_length=hex(19 ^ SUCCESS),
                    raw_status=hex(self.g[23]), resume_edge=edge, node_reads=node_reads)

    def run_fallback(self, nonnull, bounds):
        F, C, S = self.sp, self.caller, self.workspace
        first_input, first_load = len(self.input_loads), len(self.parser_reads)
        first_store, first_edge = len(self.publication_stores), len(self.edges)
        headers, tail = records(self.payload)
        assert tail is None and [row['key'] for row in headers] == ['744b91e8', '812b9aed', '172ba3a8', '00000000']
        self.new_objects, self.fallback_calls = [], []
        sites = []
        result = {}
        node_index = data_index = 0
        reader_store = None
        endpoint = FREE_WORKSPACE
        if nonnull:
            endpoint = READER_RESUME if self.provider else NULL_PROVIDER
        assert self.pc == STAGING_CALL
        self.call(F, '_IOMallocData', (self.extent,), 0xca0c, B if nonnull else 0, self.extent)
        sites.append(STAGING_CALL)
        while self.pc != endpoint:
            assert bounds[0] <= self.pc < bounds[1] and len(sites) < 28000, hex(self.pc)
            self.ix += 1
            pc = self.pc
            sites.append(pc)
            word = self.word()
            if pc == ALLOC_CONTAINER:
                result['copy'] = self.check_copy(first_input, first_load, first_store)
                assert self.value(C + 0x90, 8) == self.value(C + 0x358, 8) == self.value(C + 0x618, 8) == B
                assert self.value(C + 0x188, 8) == C + 0x600
                assert self.value(C + 0x5c8, 8) == COMMAND_RESUME
                assert self.value(C + 0x600, 8) == self.value(C + 0x3c0, 8) == self.value(F + 0xa80, 8) == 0
                assert self.value(S + 0xbe4, 4) == SUCCESS
                self.call(F, '_IOMallocTypeImpl', (CONTAINER_TYPE,), 0xd0c8, H, 16)
                parser_load = len(self.parser_reads)
            elif pc == ALLOC_NODE:
                self.call(F, '_IOMallocTypeImpl', (NODE_TYPE,), 0xd0c8, NODES[node_index], 32)
                node_index += 1
            elif pc == ALLOC_RECORD:
                head = headers[data_index]
                extent = head['end'] - head['offset']
                self.call(F, '_IOMallocData', (extent,), 0xca0c, DATA[data_index], extent)
                data_index += 1
            elif pc == FREE_CONTEXT:
                assert not nonnull and self.g[23] == SUCCESS and self.value(C+0x90, 8) == 0
                self.call(F, '_IOFreeTypeImpl', (CONTEXT_TYPE, C), 0x4d6a, 0)
                self.retired.append((C, 0x1000))
            elif pc == ALLOC_OUTPUT:
                assert reader_store is not None
                self.call(F, '_IOMallocData', (19,), 0xca0c, OUT, 19)
            else:
                if pc == COMMAND_RESUME:
                    assert node_index == data_index == 3
                    result['publication'] = self.check_publication(headers, parser_load, first_store, F)
                if pc == COMMAND_COMPARE:
                    value = int.from_bytes(self.payload[10:14], 'big')
                    assert value == 0x88594abe and self.g[8] == self.value(S + 0xcf0, 4) == value ^ SUCCESS
                    result['command'] = dict(decoded=hex(value), encoded=hex(self.g[8]), compare_pc=hex(pc))
                if pc == READER_CALL:
                    assert self.provider and self.g[22] == H and self.g[9:12] == [0x2685a3ce, S + 0xaa8, C + 0x128]
                    assert self.g[24] == 0x133
                    reader_load = len(self.parser_reads)
                    reader_store = len(self.publication_stores)
                assert word.mnemonic not in ('blraa', 'bl', 'blr', 'retab', 'ret'), (hex(pc), word.mnemonic)
                self.pc = self.step(word)
                if pc == COMMAND_COMPARE:
                    assert self.pc == 0xfffffe000a67eea4
                if pc == READER_CALL:
                    assert self.pc == READER_ENTRY and self.edges[-1]['modifier64'] == '0x73ed'
                    result['reader_request'] = self.edges[-1]

        sites.append(self.pc)
        self.word()
        if nonnull:
            assert {'copy', 'publication', 'command'} <= result.keys()
            assert len(self.input_loads) == first_input + self.extent
            assert self.value(B, self.extent).to_bytes(self.extent, 'little') == protect(self.payload, B)
            if self.provider:
                assert len(self.fallback_calls) == 9
                result['reader_output'] = self.check_reader(headers, reader_load, reader_store)
            else:
                assert len(self.fallback_calls) == 8
                assert self.g[23] == 0xce515bbf and reader_store is None
        else:
            assert first_input == len(self.input_loads)
            assert not self.accesses(self.publication_stores[first_store:], C + 0x600, 8)
            assert self.g[23] == SUCCESS and len(self.fallback_calls) == 2
            self.call(F, '_IOFreeAligned', (S, 0x4000), 0x84ff)
        assert not self.accesses(self.publication_stores[first_store:], self.base, self.extent)
        return dict(result, calls=self.fallback_calls, endpoint=hex(endpoint), raw_status=hex(self.g[23]),
                    instruction_visits=len(sites), edges=self.edges[first_edge:]), set(sites)


def replay_cases(image, fixtures):
    parent, digest = archive('live_fairplay_selector26_parse_audit')
    assert digest == PARENT_SHA and parent['collection_identity'] == list(IDENTITIES[1])
    prior = {(row['aggregate_sha256'], row['provider_nonzero'], row['patterned_scratch']): row
             for row in parent['cases']}
    template, scratch = kernel_inputs()
    start = image.named('_PRnut72j9')
    roots = function_starts(image)
    bounds = start, roots[roots.index(start) + 1]
    descriptors = [
        describe(image, CONTAINER_TYPE, 'site.FPTTLV', '11', 16, 0xe4),
        describe(image, NODE_TYPE, 'site.FPTTLVNode', '1121', 32, 0x64),
        describe(image, CONTEXT_TYPE, 'site.AllocType', '1' * 512, 4096, 0xe4),
    ]
    resume = verify_fixup(image, 0xfffffe000848a358, READER_RESUME, '0x3aa3')
    assert int(resume['raw'], 16) == int.from_bytes(image.read(0xfffffe000848a358, 8), 'little')
    cases, words, fixups = [], {}, {}
    for source, blob in fixtures:
        digest = sha(blob)
        assert digest == source['aggregate_sha256']
        for provider in (0, PRIVATE + 0x1000):
            for patterned in (False, True):
                flags = dict(aggregate_sha256=digest, caller_class=source['class'], aggregate_size=len(blob),
                             patterned_scratch=patterned, provider_nonzero=bool(provider))
                for nonnull in (False, True):
                    replay = FallbackReplay(image, template, blob, scratch, patterned, provider)
                    prefix = dict(replay.run_aggregate(), **flags)
                    assert json.loads(json.dumps(prefix)) == prior[digest, bool(provider), patterned]
                    inherited = replay.bindings.copy()
                    row, sites = replay.run_fallback(nonnull, bounds)
                    cases.append(dict(row, **flags, fallback_buffer_nonnull=nonnull))
                    words.update((pc, replay.words[pc]) for pc in sites)
                    fixups.update((a, r) for a, r in replay.bindings.items() if a not in inherited)
    differences = []
    for pc, word in sorted(words.items()):
        original = ORIGINAL.read(pc - CODE_DELTA, 4)
        if original != word.bytes:
            differences.append(dict(pc=hex(pc), original=original.hex(), installed=word.bytes.hex(),
                                    instruction=f'{word.mnemonic} {word.op_str}'))
    return dict(parent_sha256=PARENT_SHA, collection_identity=IDENTITIES[1], cases=cases,
                type_descriptors=descriptors, command_reader_resume_fixup=resume,
                original_words_compared=len(words), relocated_words=differences,
                new_loaded_fixups=[fixups[a] for a in sorted(fixups)], native_transaction_observed=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    parser.add_argument('receipt', type=Path)
    args = parser.parse_args()
    image = Collection(args.collection, IDENTITIES[1])
    args.receipt.write_text(json.dumps(replay_cases(image, inputs()), indent=2, sort_keys=True) + '\n')


if __name__ == '__main__':
    main()
