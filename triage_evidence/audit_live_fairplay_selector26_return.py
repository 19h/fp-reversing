#!/usr/bin/env python3
"""Reconstruct the installed selector 26 core return for the retained requests."""

import argparse
from collections import Counter
import json
import re
from pathlib import Path

from audit_daemon_selector26_request_bytes import archive, sha
from audit_live_fairplay_context_lifecycle import function_starts
from audit_live_fairplay_entry import InstalledReplay
from audit_live_fairplay_selector26_consumer import Q
from audit_live_fairplay_selector26_fallback import ALLOC_CONTAINER, B, CONTAINER_TYPE, OUT
from audit_live_fairplay_selector26_helper import HelperReplay
from audit_live_fairplay_selector26_nested import NESTED_RECORDS, PENDING_TARGET
from audit_live_fairplay_selector26_parse import Collection, IDENTITIES, PRIVATE, SUCCESS, inputs, kernel_inputs
from audit_live_kext_selector26_transfer import descriptor_slots, imported_call, words

HELPER_SHA = '47787985d8651eff9da158e07233ade7cb2b32856b9024c27c4e0b3c3d0008ed'
NESTED_SHA = 'cb30ece1bc512b29990b67ca1427bb00bf953e676f01760ba3e9595b254b1167'
STAGING_STORE = 0xfffffe000a6a7284
STATUS_STORE = 0xfffffe000a6a6254
VECTOR_RESTORE = 0xfffffe000a6a7484
CORE_RETURN = VECTOR_RESTORE + 4
FRESH = PRIVATE + 0x4000
TYPE_FREE = {
    0xfffffe000a6a1754: (0xfffffe0008492880, 16),     # FPTTLV
    0xfffffe000a6a1898: (0xfffffe00084928c0, 32),     # FPTTLVNode
    0xfffffe000a6a1bb0: (0xfffffe0008491e00, 128),
    0xfffffe000a6a0238: (0xfffffe0008491f80, 8),
    0xfffffe000a6a73f0: (0xfffffe0008492500, 4096),
}
DATA_FREE = {0xfffffe000a6a1978, 0xfffffe000a69fb74, 0xfffffe000a6a039c, 0xfffffe000a6a7318}
ALIGNED_FREE = 0xfffffe000a6a7440


class ReturnReplay(HelperReplay):
    def store(self, address, width, value):
        if self.pc == STAGING_STORE:
            assert width == 1 and self.base <= address < self.end
            self.check_live(address, width)
            InstalledReplay.store(self, address, width, value)
            self.publication_stores.append((hex(self.pc), hex(address), width, hex(value & 0xff)))
            return
        super().store(address, width, value)

    def release(self, frame, owned):
        pc = self.pc
        first, second = self.g[:2]
        if pc in TYPE_FREE:
            descriptor, size = TYPE_FREE[pc]
            assert first == descriptor
            assert int.from_bytes(self.image.read(descriptor + 44, 4), 'little') == size
            name, modifier, address = '_IOFreeTypeImpl', 0x4d6a, second
        elif pc in DATA_FREE:
            name, modifier, address, size = '_IOFreeData', 0x85d, first, second
            if pc == 0xfffffe000a69fb74:
                assert (address, size) == (0, 0)
            elif pc == 0xfffffe000a6a039c:
                assert address == Q
            elif pc == 0xfffffe000a6a7318:
                assert address == B
        else:
            assert pc == ALIGNED_FREE and first == self.workspace and second == 16384
            name, modifier, address, size = '_IOFreeAligned', 0x84ff, first, second
        if address:
            assert owned.pop(address) == size, (hex(pc), hex(address), size)
            self.check_live(address, size)
        self.call(frame, name, (first, second), modifier, 0)
        if address:
            self.retired.append((address, size))
        return dict(self.fallback_calls[-1], retired=hex(address), size_bytes=size)

    def run_return(self, bounds, fresh):
        frame = self.sp
        C, S = self.caller, self.workspace
        body = self.value(C + 0x618, 8)
        assert body == NESTED_RECORDS[-1] + 10
        body_size = self.value(S + 0xc8c, 4) ^ SUCCESS
        assert body_size in (96, 112)
        owned = {address: size for address, size in self.new_objects
                 if not any(address == freed for freed, _ in self.retired)}
        owned.update({S: 16384, C: 4096})
        self.call(frame, '_IOMallocTypeImpl', (CONTAINER_TYPE,), 0xd0c8, FRESH if fresh else 0, 16)
        allocation = self.fallback_calls[-1]
        assert allocation['pc'] == hex(ALLOC_CONTAINER)
        if fresh:
            owned[FRESH] = 16
        start_reads, start_stores = len(self.parser_reads), len(self.publication_stores)
        releases, visits = [], []
        while True:
            pc = self.pc
            assert bounds[0] <= pc < bounds[1] and len(visits) < 14000, hex(pc)
            self.ix += 1
            visits.append(pc)
            word = self.word()
            if pc == VECTOR_RESTORE:
                assert (word.mnemonic, word.op_str) == ('ldp', 'd11, d10, [sp], #0x80')
                assert self.sp == int(self.row['entry_SP'], 16) - 0x80
                self.d[11] = self.load(self.sp, 8)
                self.d[10] = self.load(self.sp + 8, 8)
                self.sp += 0x80
                self.pc += 4
            elif pc == CORE_RETURN:
                assert word.mnemonic == 'retab'
                self.pc = self.step(word)
                break
            elif word.mnemonic == 'blraa':
                releases.append(self.release(frame, owned))
            else:
                assert word.mnemonic not in ('bl', 'blr', 'brk', 'ret', 'retab', 'retaa')
                self.pc = self.step(word)

        stores = self.publication_stores[start_stores:]
        restored = self.accesses(stores, self.base, self.extent)
        assert restored == [(hex(STAGING_STORE), i, 1, self.payload[i])
                            for i in reversed(range(self.extent))]
        buffer = self.value(self.base, self.extent).to_bytes(self.extent, 'little')
        assert buffer == self.payload
        raw = 0xce515bb8 if fresh else 0xce515bb2
        assert self.accesses(stores, S + 0xd98, 4) == [(hex(STATUS_STORE), 0, 4, raw)]
        reads = self.accesses(self.parser_reads[start_reads:], body, body_size)
        assert sorted((offset, width) for _, offset, width, _ in reads) == (
            [(i, 1) for i in range(10)] if fresh else [])
        assert self.sp == int(self.row['entry_SP'], 16)
        assert self.pc == self.g[30] == int(self.row['entry_registers31'][30], 16)
        assert self.g[19:30] == [int(v, 16) for v in self.row['entry_registers31'][19:30]]
        assert self.d[8:12] == [int(v, 16) & ((1 << 64) - 1) for v in self.row['entry_Q_registers32'][8:12]]
        assert self.edges[-1]['pc'] == hex(CORE_RETURN) and self.edges[-1]['kind'] == 'retab'
        assert self.g[0] == raw ^ SUCCESS
        assert owned == {OUT: 19}
        return dict(allocator_returns_fresh=fresh, allocation=allocation,
                    fourth_body_size_bytes=body_size, fourth_body_reads=reads,
                    raw_status=hex(raw), returned_x0=hex(self.g[0]), restored_staging_sha256=sha(buffer),
                    staging_bytes_verified=self.extent, release_requests=releases,
                    logical_return=self.edges[-1], restored_sp=hex(self.sp),
                    unretired_model_objects=[(hex(address), size) for address, size in sorted(owned.items())],
                    instruction_visits=len(visits)), set(visits)


def compare(actual, expected):
    assert all(json.loads(json.dumps(value)) == expected[key] for key, value in actual.items())


def verify_handoff(image):
    """Check the selected straight-line status route and conditional error arms."""
    reference, digest = archive('live_kext_selector26_transfer_audit')
    assert digest == '19568bd216d51e18fc15710d6a61e1d496df9493ea99706dba8cda2398d84e79'
    reference = reference['current']
    assert reference['identity'] == list(IDENTITIES[1])
    provider = words(image, 0xfffffe000a54648c, 0xf8)
    handler = words(image, 0xfffffe000a54521c, 0x48)
    mig = words(image, 0xfffffe000be816e4, 0x18)
    assert provider == reference['provider'][0x164 // 4:]
    assert handler == reference['handler'][0x58 // 4:]
    assert mig == reference['success_reply_assembly'][:6]
    assert image.branch(0xfffffe000a54648c, 'bl') == image.named('_PRnut72j9')

    for pc, mnemonic, operands in (
        (0xfffffe000a546490, 'mov', 'x21, x0'),
        (0xfffffe000a5464bc, 'mov', 'x0, x19'),
        (0xfffffe000a5464c0, 'mov', 'x1, #0'),
        (0xfffffe000a5464c4, 'mov', 'x2, x24'),
        (0xfffffe000a5464c8, 'mov', 'x3, x20'),
        (0xfffffe000a5464d4, 'blraa', 'x9, x17'),
        (0xfffffe000a546568, 'mov', 'x0, x21'),
        (0xfffffe000a546580, 'retab', ''),
        (0xfffffe000a545220, 'mov', 'x21, x0'),
        (0xfffffe000a545224, 'cbz', 'w0, #0xfffffe000a54523c'),
        (0xfffffe000a545238, 'b', '#0xfffffe000a54524c'),
        (0xfffffe000a54524c, 'mov', 'x0, x21'),
        (0xfffffe000a545260, 'retab', ''),
        (0xfffffe000be816e4, 'cbz', 'w0, #0xfffffe000be816fc'),
        (0xfffffe000be816e8, 'str', 'w0, [x21, #0x28]'),
        (0xfffffe000be816f8, 'b', '#0xfffffe000be815e4'),
    ):
        image.instruction(pc, mnemonic, operands)

    saved_interval = [row for row in provider if '0xfffffe000a546490' < row['pc'] < '0xfffffe000a546568']
    calls = [row['pc'] for row in saved_interval if row['mnemonic'] == 'blraa']
    assert calls == list(map(hex, (0xfffffe000a5464d4, 0xfffffe000a546510, 0xfffffe000a546528,
                                   0xfffffe000a54654c, 0xfffffe000a546564)))
    assert all(not re.search(r'\b[xw]21\b', row['operands']) for row in saved_interval)
    branches = [(row['pc'], row['operands']) for row in saved_interval if row['mnemonic'].startswith('b.')
                or row['mnemonic'] in ('b', 'cbz', 'cbnz', 'tbz', 'tbnz')]
    assert branches == [(hex(pc), '#' + hex(pc + 8)) for pc in (0xfffffe000a5464ac, 0xfffffe000a5464f0)]
    dispatch_names = {0x210: 'writeBytes', 0x220: 'complete', 0x28: 'release'}
    dispatch = {name: descriptor_slots(image, name, {offset: symbol for offset, symbol in dispatch_names.items()
                                                      if offset != 0x210 or name == 'IOGeneralMemoryDescriptor'})
                for name in ('IOGeneralMemoryDescriptor', 'IOBufferMemoryDescriptor')}
    for name, slots in dispatch.items():
        assert all(reference['nominal_dispatch'][name][offset] == row for offset, row in slots.items())
    assert imported_call(image, 0xfffffe000a545234, '_IOLog') == reference['bindings']['log']
    return dict(provider=provider, handler=handler, mig=mig, descriptor_slots=dispatch,
                saved_status_register='x21', copy_count_used=False, descriptor_calls=calls)


def project_status(core):
    status = int(core['returned_x0'], 16)
    assert status in (0xffff5bd4, 0xffff5bde)
    return dict(provider_core_link='0xfffffe000a546490', provider_copy_back_pc='0xfffffe000a5464d4',
                requested_count_bytes=core['staging_bytes_verified'], actual_count_bytes=None,
                handler_branch_pc='0xfffffe000a545224', handler_success_taken=False,
                handler_return_x0=hex(status), mig_short_status_pc='0xfffffe000be816e8',
                mig_status_u32=hex(status), kernel_retcode_offset_bytes=40)

def run_cases(image, fixtures):
    nested, nested_sha = archive('live_fairplay_selector26_nested_audit')
    helper, helper_sha = archive('live_fairplay_selector26_helper_audit')
    assert (nested_sha, helper_sha) == (NESTED_SHA, HELPER_SHA)
    assert nested['collection_identity'] == helper['collection_identity'] == list(IDENTITIES[1])
    template, scratch = kernel_inputs()
    roots = function_starts(image)
    core = image.named('_PRnut72j9')
    bounds = core, roots[roots.index(core) + 1]
    helper_end = roots[roots.index(PENDING_TARGET) + 1]
    by_digest = {sha(blob): blob for _, blob in fixtures}
    identifiers = ('aggregate_sha256', 'caller_class', 'aggregate_size', 'workspace_probe', 'patterned_scratch')
    handoff = verify_handoff(image)
    cases, core_words = [], {}
    for source, previous in zip(nested['cases'], helper['cases'], strict=True):
        identity = {key: source[key] for key in identifiers}
        compare(identity, previous)
        for fresh in (False, True):
            replay = ReturnReplay(image, template, by_digest[source['aggregate_sha256']], scratch,
                                  source['patterned_scratch'], PRIVATE + 0x1000)
            replay.run_aggregate()
            replay.run_fallback(True, bounds)
            replay.run_consumer(bounds)
            result, _ = replay.run_nested(bounds, int(source['workspace_probe'], 16), source['patterned_scratch'])
            compare(result, source)
            result, _, _ = replay.run_helper(bounds, helper_end)
            compare(result, previous)
            result, sites = replay.run_return(bounds, fresh)
            cases.append(dict(identity, **result, nominal_handoff=project_status(result)))
            core_words.update((pc, replay.words[pc].bytes.hex()) for pc in sites)
    assert len(cases) == 32 and sum(case['staging_bytes_verified'] for case in cases) == 8960
    assert Counter(case['returned_x0'] for case in cases) == {'0xffff5bd4': 16, '0xffff5bde': 16}
    return dict(helper_sha256=HELPER_SHA, nested_sha256=NESTED_SHA, collection_identity=IDENTITIES[1],
                cases=cases, core_words={hex(pc): core_words[pc] for pc in sorted(core_words)},
                core_epilogue=words(image, VECTOR_RESTORE, 8),
                nominal_handoff_source=handoff, native_transaction_observed=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    parser.add_argument('receipt', type=Path)
    args = parser.parse_args()
    image = Collection(args.collection, IDENTITIES[1])
    args.receipt.write_text(json.dumps(run_cases(image, inputs()), indent=2, sort_keys=True) + '\n')


if __name__ == '__main__':
    main()
