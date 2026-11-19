#!/usr/bin/env python3
"""Replay selector 26 message attributes, nested publication and found-key dispatch."""

import argparse
import json
from pathlib import Path

from audit_daemon_selector26_request_bytes import archive, records, sha
from audit_live_fairplay_context_lifecycle import CODE_DELTA, function_starts
from audit_live_fairplay_entry import ALLOC_TLV, TLV_TYPE
from audit_live_fairplay_message_attributes import RANDOM_CALLS
from audit_live_fairplay_message_initialization import PARSER
from audit_live_fairplay_message_modes import ATTRIBUTE_FREE, KEXT_LOOKUP, LOOKUP_RETURN
from audit_live_fairplay_message_parser import FLAG_TARGETS, PUBLISH
from audit_live_fairplay_selector26_consumer import (
    ATTR, MESSAGE, MESSAGE_ATTR_CALL, MESSAGE_ATTR_TYPE, Q, WORKSPACE_READ, ConsumerReplay,
)
from audit_live_fairplay_selector26_fallback import OUT, describe
from audit_live_fairplay_selector26_parse import (
    DATA_CALL, NODE_CALL, NODE_TYPE, ORIGINAL, PRIVATE, SUCCESS, Collection, IDENTITIES,
    inputs, kernel_inputs, protect,
)

PARENT_SHA = 'f3486100341b48047579fe4efe50cdf04c475be1c7d1761057577b2695862fdc'
ATTRIBUTE = OUT + 0x800
NESTED_CONTAINER = OUT + 0x900
NESTED_NODES = tuple(PRIVATE + 0x3040 + i*0x40 for i in range(4))
NESTED_RECORDS = tuple(PRIVATE + 0x3800 + i*0x200 for i in range(4))
ATTRIBUTE_FREE_TYPE = 0xfffffe00084923c0
PENDING = 0xfffffe000a680f5c
PENDING_TARGET = 0xfffffe000a6c3c50
MESSAGE_BYTE_MASK = bytes.fromhex('e43a4ec1536f29ded6b30e155e083e20')
KEYS = ('7976211a', 'f93d7930', 'f7859101', 'fd2821c7', '00000000')
POST_LOOKUPS = (
    (0x5c241ab2, 0x68, 0xfffffe000a6a3e5c, None),
    (0x7976211a, 0x710, 0xfffffe000a6a2dc4, 0),
    (0xfd2821c7, 0xa0, 0xfffffe000a6a4540, 3),
    (0xf93d7930, 0x538, 0xfffffe000a6a4760, 1),
    (0xf7859101, 0x740, 0xfffffe000a6a4b78, 2),
)


def random_word(index, patterned):
    return ((index*0x01f24b7d + 0x92fce199) if patterned else (index*7 + 1)) & 0x7fffffff


class NestedReplay(ConsumerReplay):
    def check_formed(self, generated, first_read, first_store):
        C, S = self.caller, self.workspace
        assert self.value(C+0x380, 8) == ATTRIBUTE and self.value(S+0xd0c, 4) == self.workspace_probe
        attr = bytearray(112)
        attr[:4] = (0x3908f615).to_bytes(4, 'little')
        attr[8:72] = generated
        attr[0x51] = 0x1a
        header = self.value(ATTR, 4).to_bytes(4, 'little')
        assert header == bytes([7, 0, 0, 0])
        attr[0x54:0x58] = header
        attr[0x58:0x68] = bytes([0xc7])*16
        attr[0x6c] = 3
        message = bytearray(128)
        message[0x10:0x14] = attr[:4]
        message[0x18:0x58] = generated
        message[0x61] = 0x1a
        message[0x60] = 0
        message[0x64:0x68] = attr[0x54:0x58]
        message[0x68:0x78] = bytes(a ^ b for a, b in zip(attr[0x58:0x68], MESSAGE_BYTE_MASK, strict=True))
        message[0x7c] = 0xcb
        holes = {'attribute': {0x52, 0x53, 0x6d, 0x6e, 0x6f}, 'message': {0x62, 0x63, 0x7d, 0x7e, 0x7f}}
        rows = {}
        for key, base, expected in (('attribute', ATTRIBUTE, attr), ('message', MESSAGE, message)):
            missing = {i for i in range(len(expected)) if base+i not in self.state}
            assert missing == holes[key], (key, sorted(missing))
            for i, byte in enumerate(expected):
                if i not in missing:
                    assert self.state[base+i] == byte, (key, hex(i), self.state[base+i], byte)
            stores = self.accesses(self.publication_stores[first_store:], base, len(expected))
            touched = {i for _, offset, width, _ in stores for i in range(offset, offset+width)}
            previous = set(range(16)) if key == 'message' else set()
            assert touched | previous == set(range(len(expected))) - missing
            rows[key] = dict(defined_sha256=sha(bytes(byte for i, byte in enumerate(expected) if i not in missing)),
                             unwritten_offsets=sorted(missing), new_byte_positions=len(touched), writes=len(stores))
        reads = self.accesses(self.parser_reads[first_read:], ATTRIBUTE, len(attr))
        assert {i for _, offset, width, _ in reads for i in range(offset, offset+width)} == set(range(112)) - holes['attribute']
        hold = self.accesses(self.publication_stores[first_store:], S+0xd0c, 4)
        assert hold == [(hex(0xfffffe000a694854), 0, 4, self.workspace_probe)]
        return dict(rows, mode_byte=message[0x60], alternate_word=message[0x14], generated_sha256=sha(generated))

    def check_nested(self, headers, body, first_read, first_store, frame):
        C, S = self.caller, self.workspace
        assert self.value(C+0x380, 8) == 0
        assert self.value(MESSAGE, 8) == NESTED_CONTAINER and self.value(MESSAGE+8, 8) == 0
        assert self.value(S+0xa10, 8) == len(body)
        assert self.value(S+0xc94, 4) == self.g[23] == SUCCESS
        assert self.value(NESTED_CONTAINER, 8) == NESTED_NODES[0]
        assert self.value(NESTED_CONTAINER+8, 8) == NESTED_NODES[-1]
        reads = self.accesses(self.parser_reads[first_read:], Q, len(body))
        assert sorted(offset for _, offset, _, _ in reads) == list(range(len(body)-10))
        assert all(width == 1 and body[offset] == byte for _, offset, width, byte in reads)
        assert not self.accesses(self.publication_stores[first_store:], Q, len(body))
        cursors = self.accesses(self.publication_stores[first_store:], S+0xa10, 8)
        assert [(offset, width, value) for _, offset, width, value in cursors] == [
            (0, 8, value) for value in [0, *(head['end'] for head in headers)]
        ]
        rows = []
        for i, head in enumerate(headers[:-1]):
            node, data = NESTED_NODES[i], NESTED_RECORDS[i]
            begin, end = head['offset'], head['end']
            assert self.value(node, 8) == (NESTED_NODES[i+1] if i < 3 else 0)
            assert self.value(node+8, 8) == (NESTED_NODES[i-1] if i else 0)
            assert self.value(node+0x10, 4) == end-begin and self.value(node+0x18, 8) == data
            original = body[begin:end]
            protected = self.value(data, end-begin).to_bytes(end-begin, 'little')
            assert protected == protect(original, data)
            rows.append(dict(tag=head['key'], header_offset=begin, serialized_size_bytes=end-begin,
                             decoded_sha256=sha(original), protected_sha256=sha(protected)))
        writes = self.accesses(self.publication_stores[first_store:], MESSAGE, 8)
        assert writes[-1] == (hex(PUBLISH), 0, 8, NESTED_CONTAINER)
        return dict(records=rows, first_read_pc=reads[0][0], first_read_offset=reads[0][1],
                    read_count=len(reads), skipped_tail_bytes=10, cursors=cursors, publication=writes[-1],
                    continuation=self.edges[-1], frame=hex(frame))

    def run_nested(self, bounds, workspace, patterned_random):
        C, S, F = self.caller, self.workspace, self.sp
        assert self.pc == WORKSPACE_READ
        self.workspace_probe = workspace
        first_read, first_store, first_edge = len(self.parser_reads), len(self.publication_stores), len(self.edges)
        first_call = len(self.fallback_calls)
        body_size = self.extent-64
        body = self.payload[24:24+body_size]
        headers, tail = records(body)
        assert tail is None and tuple(h['key'] for h in headers) == KEYS
        n = nj = nr = 0
        sites, generated, lookups = [], [], []
        result = {}
        match = None
        while self.pc != PENDING:
            pc = self.pc
            assert bounds[0] <= pc < bounds[1] and len(sites) < 22000, hex(pc)
            self.ix += 1
            sites.append(pc)
            word = self.word()
            if pc == MESSAGE_ATTR_CALL:
                self.call(F, '_IOMallocTypeImpl', (MESSAGE_ATTR_TYPE,), 0xd0c8, ATTRIBUTE, 112)
            elif pc in RANDOM_CALLS:
                assert n < 64 and pc == RANDOM_CALLS[n//32]
                value = random_word(n, patterned_random)
                self.call(F, '_random', (), 0xc350, value)
                generated.append((value & 255) ^ 0xc7)
                n += 1
            elif pc == ATTRIBUTE_FREE:
                assert n == 64
                result['formation'] = self.check_formed(bytes(generated), first_read, first_store)
                self.call(F, '_IOFreeTypeImpl', (ATTRIBUTE_FREE_TYPE, ATTRIBUTE), 0x4d6a, 0)
                self.retired.append((ATTRIBUTE, 112))
            elif pc == ALLOC_TLV:
                assert self.value(C+0x98, 8) == Q and self.value(S+0xb5c, 4) == body_size ^ SUCCESS
                assert self.value(S+0xa10, 8) == 0
                self.call(F, '_IOMallocTypeImpl', (TLV_TYPE,), 0xd0c8, NESTED_CONTAINER, 16)
            elif pc == NODE_CALL:
                head = headers[nj]
                assert self.value(S+0xa10, 8) == head['end']
                self.call(F, '_IOMallocTypeImpl', (NODE_TYPE,), 0xd0c8, NESTED_NODES[nj], 32)
                nj += 1
            elif pc == DATA_CALL:
                head = headers[nr]
                assert self.value(C+0x58, 8) == NESTED_NODES[nr] and nj == nr+1
                size = head['end']-head['offset']
                self.call(F, '_IOMallocData', (size,), 0xca0c, NESTED_RECORDS[nr], size)
                nr += 1
            else:
                if pc == PARSER:
                    assert self.value(C+0x718, 8) == MESSAGE and self.value(C+0x18, 8) == Q
                    assert self.value(S+0xc8, 4) == body_size ^ SUCCESS and self.value(S+0x1e0, 4) == 0xfbb3f478
                    assert not self.accesses(self.parser_reads[first_read:], Q, body_size)
                    result['parser_entry'] = self.edges[-1]
                if pc == FLAG_TARGETS[0]:
                    assert nj == nr == 4
                    result['nested'] = self.check_nested(headers, body, first_read, first_store, F)
                if 'nested' in result and pc == KEXT_LOOKUP:
                    tag, output, callback, index = POST_LOOKUPS[len(lookups)]
                    assert self.g[22] == NESTED_CONTAINER and self.g[9] == tag ^ SUCCESS
                    assert self.g[10] == C+output and self.edges[-1]['modifier64'] == '0xee9'
                    match = (tag, output, callback, index, self.edges[-1]['pc'])
                elif 'nested' in result and pc == LOOKUP_RETURN:
                    assert match is not None
                    tag, output, callback, index, emitter = match
                    status = SUCCESS if index is not None else 0xce515bda
                    assert self.g[23] == status and self.g[8] == callback
                    expected = NESTED_NODES[index] if index is not None else 0
                    assert self.value(C+output, 8) == expected
                    lookups.append(dict(tag=hex(tag), emitter=emitter, output_offset=hex(output),
                                        status=hex(status), callback=hex(callback), node=hex(expected)))
                    match = None
                assert word.mnemonic not in ('blraa', 'bl', 'blr', 'ret', 'retab', 'brk'), (hex(pc), word.mnemonic)
                self.pc = self.step(word)
        assert len(lookups) == 5 and match is None
        assert self.sp == F
        assert self.word().mnemonic == 'blraa'
        target_reg = self.word().reg_name(self.word().operands[0].reg)
        assert self.reg(target_reg) == PENDING_TARGET and self.g[17] == 0x9ae8 and self.g[0] == S+0x968
        sites.append(self.pc)
        result['pending'] = dict(pc=hex(PENDING), target=hex(PENDING_TARGET), modifier='0x9ae8',
                                 x0_workspace_offset='0x968', w23=hex(self.g[23]))
        # These cells are output channels across multiple private phases.
        result['phase_cells'] = {hex(offset): hex(self.value(S+offset, width))
                                 for offset, width in ((0x260, 4), (0x968, 8), (0x980, 4), (0x9c0, 4))}
        result['lookup_results'] = lookups
        return dict(result, workspace_probe=hex(workspace), patterned_random=patterned_random,
                    instruction_visits=len(sites)-1, calls=self.fallback_calls[first_call:],
                    encoded_edges=self.edges[first_edge:]), set(sites)


def replay_cases(image, fixtures):
    parent, digest = archive('live_fairplay_selector26_consumer_audit')
    assert digest == PARENT_SHA and parent['collection_identity'] == list(IDENTITIES[1])
    prior = {(row['aggregate_sha256'], row['patterned_scratch']): row for row in parent['cases']}
    template, scratch = kernel_inputs()
    start = image.named('_PRnut72j9')
    roots = function_starts(image)
    bounds = start, roots[roots.index(start)+1]
    descriptors = [
        describe(image, MESSAGE_ATTR_TYPE, 'site.FPMessageAttr', '', 112, 0x6c),
        describe(image, ATTRIBUTE_FREE_TYPE, 'site.FPMessageAttr', '', 112, 0x6c),
        describe(image, TLV_TYPE, 'site.FPTTLV', '11', 16, 0xe4),
        describe(image, NODE_TYPE, 'site.FPTTLVNode', '1121', 32, 0x64),
    ]
    assert PENDING_TARGET in roots
    cases, words, fixups = [], {}, {}
    for source, blob in fixtures:
        digest = sha(blob)
        assert digest == source['aggregate_sha256']
        for patterned in (False, True):
            flags = dict(aggregate_sha256=digest, caller_class=source['class'], aggregate_size=len(blob),
                         patterned_scratch=patterned, provider_nonzero=True, fallback_buffer_nonnull=True)
            for fill in (0, 0x10203040):
                replay = NestedReplay(image, template, blob, scratch, patterned, PRIVATE+0x1000)
                replay.run_aggregate()
                replay.run_fallback(True, bounds)
                prefix, _ = replay.run_consumer(bounds)
                assert json.loads(json.dumps(dict(prefix, **flags))) == prior[digest, patterned]
                inherited = set(replay.bindings)
                case, sites = replay.run_nested(bounds, fill, patterned)
                cases.append(dict(case, **flags))
                words.update((pc, replay.words[pc]) for pc in sites)
                fixups.update((a, r) for a, r in replay.bindings.items() if a not in inherited)
    assert len(cases) == 2*len(prior) == 16
    differences = []
    for pc, word in sorted(words.items()):
        original = ORIGINAL.read(pc-CODE_DELTA, 4)
        if word.bytes != original:
            differences.append(dict(pc=hex(pc), original=original.hex(), installed=word.bytes.hex(),
                                    text=f'{word.mnemonic} {word.op_str}'))
    return dict(parent_sha256=PARENT_SHA, collection_identity=IDENTITIES[1], cases=cases,
                type_descriptors=descriptors, original_words_compared=len(words), differing_words=differences,
                loaded_fixups=[fixups[a] for a in sorted(fixups)], native_transaction_observed=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    parser.add_argument('receipt', type=Path)
    args = parser.parse_args()
    image = Collection(args.collection, IDENTITIES[1])
    args.receipt.write_text(json.dumps(replay_cases(image, inputs()), indent=2, sort_keys=True)+'\n')


if __name__ == '__main__':
    main()
