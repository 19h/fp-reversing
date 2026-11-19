#!/usr/bin/env python3
"""Verify the selector 26 discriminator, second copying reader and FPMessage handoff."""

import argparse
from copy import copy
import json
from pathlib import Path

from audit_daemon_selector26_request_bytes import archive, records, sha
from audit_live_fairplay_context_lifecycle import CODE_DELTA, function_starts
from audit_live_fairplay_entry import verify_fixup
from audit_live_fairplay_message_initialization import ZERO
from audit_live_fairplay_selector26_fallback import (
    ALLOC_OUTPUT, DATA, H, NODES, OUT, READER_ENTRY, READER_RESUME, FallbackReplay, describe,
)
from audit_live_fairplay_selector26_parse import (
    ORIGINAL, PRIVATE, SUCCESS, Collection, IDENTITIES, inputs, kernel_inputs, protect,
)

PARENT_SHA = '3319b02d521f7abcd11d36ab0ec6941b836177e2be5d7ae5aa34afe8b338dae1'
HASH_FIRST = 0xfffffe000a698314
HASH_NEXT = 0xfffffe000a6983c4
HASH_REDUCE = 0xfffffe000a698400
HASH_STORE = 0xfffffe000a698430
SECOND_READER = 0xfffffe000a6984a8
SECOND_RESUME = 0xfffffe000a6984ac
ATTR_CALL = 0xfffffe000a698560
ATTR_TYPE = 0xfffffe0008492240
CLEAR_CALLS = {0xfffffe000a69866c: 0xb00, 0xfffffe000a6987d8: 0xcc8}
MESSAGE_CALL = 0xfffffe000a6988e8
MESSAGE_TYPE = 0xfffffe0008492000
WORKSPACE_READ = 0xfffffe000a693fac
MESSAGE_ATTR_CALL = 0xfffffe000a69405c
MESSAGE_ATTR_TYPE = 0xfffffe0008491c80
Q, ATTR, MESSAGE = (OUT + offset for offset in (0x200, 0x400, 0x600))
U64 = (1 << 64) - 1


def discriminator(data):
    hash64 = 5381
    for byte in data:
        hash64 = (33 * hash64 + byte) & U64
    return hash64, hash64 % ((1 << 32) - 1)


class ConsumerReplay(FallbackReplay):
    workspace_probe = None

    def step(self, word):
        if word.address != HASH_REDUCE:
            return super().step(word)
        assert word.mnemonic == 'umulh' and word.op_str == 'x9, x11, x9'
        self.g[9] = (self.g[11] * self.g[9]) >> 64
        return self.pc + 4

    def load(self, address, width, discarded=False):
        if self.workspace_probe is not None and self.pc == WORKSPACE_READ:
            assert (address, width, discarded) == (self.workspace + 0xd0c, 4, False)
            assert all(address + i not in self.state for i in range(width))
            self.parser_reads.append((hex(self.pc), hex(address), width, hex(self.workspace_probe)))
            return self.workspace_probe
        return super().load(address, width, discarded)

    def probe_workspace(self, body_size, value):
        # Keep the unfilled predecessor and all of its journals intact.
        r = copy(self)
        for name in ('g', 'd', 'state', 'parser_reads', 'publication_stores', 'private_reads', 'private_writes',
                     'input_loads', 'scratch_loads', 'edges', 'bindings', 'fallback_calls'):
            setattr(r, name, getattr(r, name).copy())
        r.workspace_probe = value
        start = len(r.parser_reads)
        F = r.sp
        sites = []
        while r.pc != MESSAGE_ATTR_CALL:
            assert len(sites) < 128, hex(r.pc)
            sites.append(r.pc)
            r.ix += 1
            word = r.word()
            assert word.mnemonic not in ('blraa', 'bl', 'blr', 'ret', 'retab', 'brk')
            r.pc = r.step(word)
        sites.append(r.pc)
        assert not r.accesses(r.parser_reads[start:], Q, body_size)
        assert r.g[19] == value
        r.call(F, '_IOMallocTypeImpl', (MESSAGE_ATTR_TYPE,), 0xd0c8)
        row = dict(modeled_cell=hex(value), w19_at_pending_call=hex(r.g[19]), body_reads=0,
                   pending_call=r.fallback_calls[-1], executed_words=len(sites)-1)
        return row, set(sites)

    def hash_result(self, first_read, first_store, body):
        C, S = self.caller, self.workspace
        assert len(body) == 19 and body[-1] == 0 and 0 not in body[:-1]
        hash64, reduced = discriminator(body[:-1])
        reads = self.accesses(self.parser_reads[first_read:], OUT, len(body))
        assert reads == [(hex(HASH_FIRST if i == 0 else HASH_NEXT), i, 1, value)
                         for i, value in enumerate(body)]
        assert not self.accesses(self.parser_reads[first_read:], S + 0xaa8, 4)
        pointers = self.accesses(self.parser_reads[first_read:], C + 0x128, 8)
        assert pointers == [(hex(0xfffffe000a6982c0), 0, 8, OUT)]
        stores = self.accesses(self.publication_stores[first_store:], S + 0xc90, 4)
        assert stores == [(hex(HASH_STORE), 0, 4, reduced)]
        return dict(reads=[dict(pc=pc, offset=offset) for pc, offset, _, _ in reads],
                    output_offset='0xc90', hash64=hex(hash64), reduced=hex(reduced),
                    length_cell_reads=0, input_sha256=sha(body))

    def second_output(self, head, source, first_read, first_store):
        C, S = self.caller, self.workspace
        assert self.pc == SECOND_RESUME and self.g[23] == SUCCESS
        assert self.value(C + 0x178, 8) == Q and self.value(S + 0xabc, 4) == len(source) ^ SUCCESS
        assert self.value(C + 0x400, 8) == NODES[1] and self.value(C + 0x728, 8) == DATA[1]
        assert self.value(C + 0x88, 8) == DATA[1] + 10 and self.value(S + 0xc78, 8) == len(source) + 10
        assert self.value(Q, len(source)).to_bytes(len(source), 'little') == source
        reads = self.parser_reads[first_read:]
        assert [offset for _, offset, width, _ in self.accesses(reads, DATA[0], 14) if width == 1] == list(range(4))
        assert not self.accesses(reads, DATA[2], 29)
        middle = self.accesses(reads, DATA[1], len(source)+10)
        masked = protect(self.payload[head['offset']:head['end']], DATA[1])
        offsets = [offset for _, offset, _, _ in middle]
        assert offsets[:4] == list(range(4))
        assert set(offsets) == set(range(len(source)+10))
        assert offsets[-len(source):] == list(range(len(source)+9, 9, -1))
        assert all(width == 1 and 0 <= offset < len(masked) and masked[offset] == byte
                   for _, offset, width, byte in middle)
        stores = self.publication_stores[first_store:]
        assert self.accesses(stores, Q, len(source)) == [(hex(0xfffffe000a67f27c), index, 1, source[index])
                                                        for index in range(len(source)-1, -1, -1)]
        pointer_store = self.accesses(stores, C + 0x178, 8)
        length_store = self.accesses(stores, S + 0xabc, 4)
        assert pointer_store == [(hex(0xfffffe000a67f2a8), 0, 8, Q)]
        assert length_store == [(hex(0xfffffe000a67efe8), 0, 4, len(source) ^ SUCCESS)]
        pc, target, modifier = (self.edges[-1][key] for key in ('pc', 'target', 'modifier64'))
        assert (pc, target, modifier) == ('0xfffffe000a6a42ac', hex(SECOND_RESUME), '0x3aa3')
        return dict(tag=head['key'], body_offset=head['offset']+10, body_size_bytes=len(source),
                    body_sha256=sha(source), head_tag_reads=4, middle_record_reads=offsets, tail_reads=0,
                    pointer_store=pointer_store, length_store=length_store, resume=self.edges[-1])

    def run_consumer(self, bounds):
        F, C, S = self.sp, self.caller, self.workspace
        assert self.pc == READER_RESUME and self.g[23] == SUCCESS
        first_read, first_store, first_edge = len(self.parser_reads), len(self.publication_stores), len(self.edges)
        start_of_calls = len(self.fallback_calls)
        headers, tail = records(self.payload)
        assert tail is None
        middle, path = headers[1:3]
        pathname = self.payload[path['offset']+10:path['end']]
        body = self.payload[middle['offset']+10:middle['end']]
        assert len(body) in (208, 224) and len(body) == self.extent - 64
        sites, clear_calls = [], []
        result = {}
        while self.pc != WORKSPACE_READ:
            pc = self.pc
            assert bounds[0] <= pc < bounds[1] and len(sites) < 10000, hex(pc)
            sites.append(pc)
            self.ix += 1
            word = self.word()
            if pc == SECOND_READER:
                result['discriminator'] = self.hash_result(first_read, first_store, pathname)
                assert self.g[22] == H and self.g[24] == 0x134
                raw = int(middle['key'], 16)
                assert raw == 0x812b9aed and self.g[9:12] == [raw ^ SUCCESS, S + 0xabc, C + 0x178]
                reader_read, reader_store = len(self.parser_reads), len(self.publication_stores)
                self.pc = self.step(word)
                assert self.pc == READER_ENTRY and self.edges[-1]['modifier64'] == '0x73ed'
                result['reader_request'] = self.edges[-1]
            elif pc == ALLOC_OUTPUT:
                self.call(F, '_IOMallocData', (len(body),), 0xca0c, Q, len(body))
            elif pc == ATTR_CALL:
                assert self.g[23] == SUCCESS and self.value(C + 0x178, 8) == Q
                self.call(F, '_IOMallocTypeImpl', (ATTR_TYPE,), 0xd0c8, ATTR, 8)
            elif pc in CLEAR_CALLS:
                destination = S + CLEAR_CALLS[pc]
                assert self.g[:3] == [destination, 0, 32] and self.g[17] == 0x46ae
                self.pc = self.step(word)
                assert self.pc == ZERO and self.edges[-1]['modifier64'] == '0x46ae'
                record = self.clear(destination, pc+4)
                clear_calls.append(dict(call_pc=hex(pc), destination_offset=hex(destination-S), **record))
                for address in record['sites']:
                    site = int(address, 16)
                    if site not in self.words:
                        self.words[site], = self.cs.disasm(self.image.read(site, 4), site)
            elif pc == MESSAGE_CALL:
                assert self.value(C + 0x498, 8) == Q and self.value(S + 0x150, 4) == len(body) ^ SUCCESS
                assert self.value(C + 0x430, 8) == C + 0x210 and self.value(C + 0x5d0, 8) == 0xfffffe000a698ad0
                self.call(F, '_IOMallocTypeImpl', (MESSAGE_TYPE,), 0xd0c8, MESSAGE, 128)
            else:
                if pc == SECOND_RESUME:
                    result['second_output'] = self.second_output(middle, body, reader_read, reader_store)
                assert word.mnemonic not in ('blraa', 'bl', 'blr', 'ret', 'retab', 'brk'), (hex(pc), word.mnemonic)
                self.pc = self.step(word)

        assert self.word().mnemonic == 'ldr' and self.word().op_str == 'w19, [x4, #0xd0c]'
        assert self.g[4] == S and self.g[0] == self.value(C + 0x788, 8) == MESSAGE
        assert all(S + 0xd0c + i not in self.state for i in range(4))
        assert not self.accesses(self.parser_reads[first_read:], Q, len(body))
        assert self.value(C + 0x6d0, 8) == self.value(C + 0xf0, 8) == ATTR
        assert self.value(ATTR, 6) == 0x010100000007
        assert all(ATTR + i not in self.state for i in (6, 7))
        assert self.value(S + 0xc90, 4) == int(result['discriminator']['reduced'], 16)
        calls = self.fallback_calls[start_of_calls:]
        assert [c['pc'] for c in calls] == list(map(hex, (ALLOC_OUTPUT, ATTR_CALL, MESSAGE_CALL)))
        assert len(clear_calls) == 2
        sites.append(WORKSPACE_READ)
        comparison_sites = set(sites)
        comparison_sites.update(int(pc, 16) for row in clear_calls for pc in row['sites'])
        state = dict(endpoint=hex(self.pc), unresolved_workspace_offset='0xd0c', unresolved_width_bytes=4,
                     x0=hex(self.g[0]), workspace=hex(S), body_reads=0, raw_status=hex(self.g[23]))
        probes = []
        for fill in (0, 0x10203040):
            probe, more_sites = self.probe_workspace(len(body), fill)
            probes.append(probe)
            comparison_sites.update(more_sites)
        assert probes[0]['pending_call'] == probes[1]['pending_call']
        return dict(result, calls=calls, clear_calls=clear_calls, pending=state,
                    workspace_probes=probes, edges=self.edges[first_edge:],
                    core_visits=len(sites)-1, clear_visits=sum(c['instruction_visits'] for c in clear_calls)), comparison_sites


def replay_cases(image, fixtures):
    parent, digest = archive('live_fairplay_selector26_fallback_audit')
    assert digest == PARENT_SHA and parent['collection_identity'] == list(IDENTITIES[1])
    prior = {(r['aggregate_sha256'], r['patterned_scratch']): r for r in parent['cases'] if 'reader_output' in r}
    template, scratch = kernel_inputs()
    start = image.named('_PRnut72j9')
    roots = function_starts(image)
    bounds = start, roots[roots.index(start) + 1]
    slot = 0xfffffe000848a360
    resume = verify_fixup(image, slot, SECOND_RESUME, '0x3aa3')
    assert int(resume['raw'], 16) == int.from_bytes(image.read(slot, 8), 'little')
    descriptors = [
        describe(image, ATTR_TYPE, 'site.FPSecureTunnelAttr', '', 8, 0x6c),
        describe(image, MESSAGE_TYPE, 'site.FPMessage', '1122222222222222', 128, 0x64),
        describe(image, MESSAGE_ATTR_TYPE, 'site.FPMessageAttr', '', 112, 0x6c),
    ]
    helper = image.read(ZERO, 360)
    assert helper == ORIGINAL.read(ZERO - CODE_DELTA, 360)
    cases, words, fixups = [], {}, {}
    for source, blob in fixtures:
        digest = sha(blob)
        assert digest == source['aggregate_sha256']
        for patterned in (False, True):
            replay = ConsumerReplay(image, template, blob, scratch, patterned, PRIVATE + 0x1000)
            flags = dict(aggregate_sha256=digest, caller_class=source['class'], aggregate_size=len(blob),
                         patterned_scratch=patterned, provider_nonzero=True, fallback_buffer_nonnull=True)
            replay.run_aggregate()
            prefix, _ = replay.run_fallback(True, bounds)
            assert json.loads(json.dumps(dict(prefix, **flags))) == prior[digest, patterned]
            inherited = set(replay.bindings)
            case, sites = replay.run_consumer(bounds)
            cases.append(dict(case, **flags))
            words.update((pc, replay.words[pc]) for pc in sites)
            fixups.update((a, r) for a, r in replay.bindings.items() if a not in inherited)
    assert len(cases) == len(prior) == 8
    changes = []
    for pc, word in sorted(words.items()):
        old = ORIGINAL.read(pc - CODE_DELTA, 4)
        if old != word.bytes:
            changes.append(dict(pc=hex(pc), original=old.hex(), installed=word.bytes.hex(),
                                instruction=f'{word.mnemonic} {word.op_str}'))
    return dict(collection_identity=IDENTITIES[1], parent_sha256=PARENT_SHA, cases=cases,
                descriptors=descriptors, second_resume_fixup=resume, clear_helper_sha256=sha(helper),
                original_words_compared=len(words), differing_words=changes,
                loaded_fixups=[fixups[a] for a in sorted(fixups)], native_transaction_observed=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    parser.add_argument('receipt', type=Path)
    args = parser.parse_args()
    image = Collection(args.collection, IDENTITIES[1])
    args.receipt.write_text(json.dumps(replay_cases(image, inputs()), indent=2, sort_keys=True) + '\n')


if __name__ == '__main__':
    main()
