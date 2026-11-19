#!/usr/bin/env python3
"""Follow the selector 26 private argument record through status and return."""

import argparse
import json
from pathlib import Path

from capstone.arm64 import ARM64_SFT_ROR

from audit_live_fairplay_context_lifecycle import function_starts
from audit_live_fairplay_entry import ORDER
from audit_live_fairplay_selector26_fallback import ALLOC_CONTAINER, CONTAINER_TYPE, describe
from audit_live_fairplay_selector26_nested import NestedReplay, PENDING, PENDING_TARGET
from audit_live_fairplay_selector26_parse import Collection, IDENTITIES, PRIVATE, SUCCESS, inputs, kernel_inputs
from audit_daemon_selector26_request_bytes import archive, sha

PARENT_SHA = 'cb30ece1bc512b29990b67ca1427bb00bf953e676f01760ba3e9595b254b1167'
STATUS_STORE = 0xfffffe000a6c427c
STATUS_LOAD = PENDING + 8
GLOBAL_SITES = {0xfffffe000a6c3d48: 0xfffffe000cd47580, 0xfffffe000a6c3d50: 0xfffffe000cd430d8}
FIELDS = ((0, 8), (8, 8), (0x10, 8), (0x18, 4), (0x20, 8), (0x28, 8),
          (0x30, 4), (0x38, 8), (0x40, 4), (0x48, 8), (0x50, 8), (0x58, 4))


class HelperReplay(NestedReplay):
    def load(self, address, width, discarded=False):
        if any(base <= address < address + width <= base + 8 for base in GLOBAL_SITES.values()):
            raw = self.image.read(address, width)
            data = bytes(self.state.get(address + i, byte) for i, byte in enumerate(raw))
            value = int.from_bytes(data, 'little')
            if self.parser_reads is not None:
                assert not discarded
                self.parser_reads.append((hex(self.pc), hex(address), width, hex(value)))
            return value
        return super().load(address, width, discarded)

    def store(self, address, width, value):
        if self.pc not in GLOBAL_SITES:
            return super().store(address, width, value)
        assert address == GLOBAL_SITES[self.pc] and width == 8
        raw = (value & ((1 << 64) - 1)).to_bytes(width, 'little')
        self.state.update({address + i: byte for i, byte in enumerate(raw)})
        self.publication_stores.append((hex(self.pc), hex(address), width, hex(value)))

    def operand(self, word, op, n=64):
        if op.shift.type != ARM64_SFT_ROR:
            return super().operand(word, op, n)
        assert not op.ext
        value = self.reg(word.reg_name(op.reg)) & ((1 << n) - 1)
        shift = op.shift.value
        return ((value >> shift) | (value << (n - shift))) & ((1 << n) - 1)

    def step(self, word):
        mnemonic, operands = word.mnemonic, word.operands
        if mnemonic == 'ldurb':
            dest = word.reg_name(operands[0].reg)
            mem = operands[1].mem
            assert not mem.index and not word.writeback
            address = self.reg(word.reg_name(mem.base)) + mem.disp
            self.set(dest, self.load(address, 1))
        elif mnemonic == 'ldp' and word.writeback and len(operands) == 4:
            mem = operands[2].mem
            assert not mem.index and mem.disp == 0
            base = word.reg_name(mem.base)
            address = self.reg(base)
            for i, reg in enumerate(operands[:2]):
                dest = word.reg_name(reg.reg)
                assert dest.startswith('x') and dest != base
                self.set(dest, self.load(address + 8 * i, 8))
            self.set(base, address + operands[3].imm)
        elif mnemonic in ('mvn', 'bic', 'extr', 'ror'):
            dest = word.reg_name(operands[0].reg)
            width = 32 if dest.startswith('w') else 64
            a = self.operand(word, operands[1], width)
            if mnemonic == 'mvn':
                value = ~a
            else:
                b = self.operand(word, operands[2], width)
                if mnemonic == 'bic':
                    value = a & ~b
                elif mnemonic == 'extr':
                    value = ((a << width) | b) >> operands[3].imm
                else:
                    shift = b % width
                    value = (a >> shift) | (a << (width - shift))
            self.set(dest, value)
        else:
            return super().step(word)
        return self.pc + 4

    def run_helper(self, core_bounds, helper_end):
        assert self.pc == PENDING
        frame = self.sp
        saved = self.g[19:30].copy()
        argument = self.workspace + 0x968
        assert self.g[0] == argument and self.g[20] == argument
        before = {hex(off): hex(self.value(argument + off, width))
                  for off, width in FIELDS if off != 0x40}
        assert all(argument + 0x40 + i not in self.state for i in range(4))
        context = self.value(argument, 8)
        bound = self.value(argument + 0x38, 8) + 64
        reads, writes, edges = len(self.parser_reads), len(self.publication_stores), len(self.edges)
        old_bindings = set(self.bindings)
        visits = []
        milestones = {}
        branch_targets = {PENDING: (PENDING_TARGET, 0x9ae8), 0xfffffe000a6c3e2c: (ORDER, 0x4d6a)}

        while self.pc != ALLOC_CONTAINER:
            pc = self.pc
            assert (core_bounds[0] <= pc < core_bounds[1] or PENDING_TARGET <= pc < helper_end
                    or ORDER <= pc < ORDER + 0x14) and len(visits) < 30000, hex(pc)
            self.ix += 1
            visits.append(pc)
            word = self.word()
            if word.mnemonic == 'blraa':
                target, modifier = branch_targets[pc]
                assert self.reg(word.reg_name(word.operands[0].reg)) == target and self.g[17] == modifier
                if target == ORDER:
                    assert self.g[:2] == [bound, context] and bound <= context
            else:
                assert word.mnemonic not in ('bl', 'blr', 'brk'), (hex(pc), word.mnemonic)
            if pc == PENDING + 4:
                assert self.sp == frame and self.g[19:30] == saved
                assert self.value(argument + 0x40, 4) == SUCCESS
                milestones['return'] = dict(pc=hex(pc), x0=hex(self.g[0]), w23=hex(self.g[23]), sp=hex(frame))
            self.pc = self.step(word)
        assert 'return' in milestones and self.sp == frame and self.g[23] == SUCCESS
        self.call(frame, '_IOMallocTypeImpl', (CONTAINER_TYPE,), 0xd0c8)
        assert self.fallback_calls[-1]['pc'] == hex(ALLOC_CONTAINER)
        local_reads = self.parser_reads[reads:]
        local_writes = self.publication_stores[writes:]
        status_writes = self.accesses(local_writes, argument + 0x40, 4)
        status_reads = self.accesses(local_reads, argument + 0x40, 4)
        assert status_writes == [(hex(STATUS_STORE), 0, 4, SUCCESS)]
        assert status_reads == [(hex(STATUS_LOAD), 0, 4, SUCCESS)]
        transfers = self.edges[edges:]
        assert any(e['pc'] == hex(ORDER + 12) and e['target'] == hex(0xfffffe000a6c3e30) for e in transfers)
        assert any(e['pc'] == hex(0xfffffe000a680f70) and e['target'] == hex(0xfffffe000a681f7c) for e in transfers)
        globals_written = [row for row in local_writes if int(row[1], 16) in GLOBAL_SITES.values()]
        assert [int(row[0], 16) for row in globals_written] == list(GLOBAL_SITES)
        record_reads = self.accesses(local_reads, argument, 0x5c)
        assert all(0 <= offset and offset + width <= 0x5c for _, offset, width, _ in record_reads)
        return dict(
            input_fields=before, record_reads=[(p, hex(o), n, hex(v)) for p, o, n, v in record_reads],
            status_write=status_writes[0], status_read=status_reads[0], globals_written=globals_written,
            globals_read=[row for row in local_reads if any(base <= int(row[1], 16) < base + 8
                                                           for base in GLOBAL_SITES.values())],
            order_arguments=[hex(bound), hex(context)], transfers=transfers, milestones=milestones,
            pending_allocator=self.fallback_calls[-1], instruction_visits=len(visits),
        ), set(visits) | {ALLOC_CONTAINER}, {a: r for a, r in self.bindings.items() if a not in old_bindings}


def run_cases(image, fixtures):
    parent, digest = archive('live_fairplay_selector26_nested_audit')
    assert digest == PARENT_SHA and parent['collection_identity'] == list(IDENTITIES[1])
    template, scratch = kernel_inputs()
    roots = function_starts(image)
    core = image.named('_PRnut72j9')
    core_bounds = (core, roots[roots.index(core) + 1])
    helper_end = roots[roots.index(PENDING_TARGET) + 1]
    by_digest = {sha(blob): blob for _, blob in fixtures}
    cases, words, fixups = [], {}, {}
    for case in parent['cases']:
        digest = case['aggregate_sha256']
        patterned = case['patterned_scratch']
        probe = int(case['workspace_probe'], 16)
        replay = HelperReplay(image, template, by_digest[digest], scratch, patterned, PRIVATE + 0x1000)
        replay.run_aggregate()
        replay.run_fallback(True, core_bounds)
        replay.run_consumer(core_bounds)
        predecessor, _ = replay.run_nested(core_bounds, probe, patterned)
        assert all(json.loads(json.dumps(v)) == case[k] for k, v in predecessor.items())
        result, sites, bindings = replay.run_helper(core_bounds, helper_end)
        cases.append(dict(result, aggregate_sha256=digest, caller_class=case['caller_class'],
                          aggregate_size=case['aggregate_size'], workspace_probe=hex(probe),
                          patterned_scratch=patterned))
        words.update((pc, replay.words[pc].bytes.hex()) for pc in sites)
        fixups.update(bindings)
    assert len(cases) == 16
    descriptor = describe(image, CONTAINER_TYPE, 'site.FPTTLV', '11', 16, 0xe4)
    return dict(parent_sha256=PARENT_SHA, collection_identity=IDENTITIES[1],
                helper_bounds=[hex(PENDING_TARGET), hex(helper_end)], cases=cases, descriptor=descriptor,
                instruction_words={hex(pc): words[pc] for pc in sorted(words)},
                loaded_fixups=[fixups[a] for a in sorted(fixups)], native_transaction_observed=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    parser.add_argument('receipt', type=Path)
    args = parser.parse_args()
    image = Collection(args.collection, IDENTITIES[1])
    args.receipt.write_text(json.dumps(run_cases(image, inputs()), indent=2, sort_keys=True) + '\n')


if __name__ == '__main__':
    main()
