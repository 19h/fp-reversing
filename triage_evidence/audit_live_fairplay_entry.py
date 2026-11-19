#!/usr/bin/env python3
"""Replay installed FairPlay core entry against archived private paths."""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs

from audit_daemon_iokit_native_registry import command, sysctl
from audit_live_fairplay_cf_receive import assert_instructions
from audit_live_fairplay_connection_retirement import verify_fixup
from audit_live_fairplay_context_lifecycle import CODE_DELTA, POOL, POOL_ROOTS, TABLE, function_starts
from audit_live_fairplay_shared_table import EXTRA_BANKS
from audit_live_fairplay_uidlist import BODY_HASH, receipt
from audit_live_kext_selector26 import Collection, IDENTITIES
from kext_port_tools import POOL as ARCHIVED_POOL, qword
from replay_userclient_fpttlv_entry import M, PRIVATE, Replay

ARCHIVES = {
    'entry_execution': 'd0975eb53ea85b662d125d43e9a6e05aca48f30307a11d4b94c148d87cd9effe',
    'fpttlv_entry': 'e45e1feb725aa40d54c43c510686adbd9e46f0c7dc67eca15147b168f7f5a62a',
}
CONTROLLERS = (0xfffffe000cd42eb0, 0xfffffe000cd430d8)
PROBE = 0xfffffe000a5e2e54
ORDER = 0xfffffe000a6c905c
ALLOC_ALIGNED = 0xfffffe000a67656c
ALLOC_TYPED = 0xfffffe000a676600
ALLOC_TLV = 0xfffffe000a677594
INPUT_BYTE = 0xfffffe000a6a1f5c
STAGING_CALL = 0xfffffe000a682e88
TLV_RELEASE = 0xfffffe000a6a1754
AUX_RELEASE = 0xfffffe000a6a73f0
AUX_TYPE = 0xfffffe0008492940
AUX_FREE = 0xfffffe0008492500
TLV_TYPE = 0xfffffe0008492600
TLV_FREE = 0xfffffe0008492880


def shifted(address):
    return int(address, 16) + CODE_DELTA


def in_private(address, width):
    return PRIVATE <= address < address + width <= PRIVATE + 0x20000


def read_type(image, descriptor, name, signature, size):
    raw = image.read(descriptor, 64)
    assert int.from_bytes(raw[40:48], 'little') == ((size << 32) | 0xe4)
    resolved = {}
    for label, offset, value in (('name', 16, name), ('signature', 32, signature)):
        row = image.pointer(descriptor + offset)
        target = int(row['target'], 16)
        resolved[label] = verify_fixup(image, descriptor + offset, target)
        assert image.read(target, len(value) + 1) == value.encode() + b'\0'
    return dict(address=hex(descriptor), name=name, signature=signature, size_bytes=size,
                flags=0xe4, fixups=resolved)


def verify_layout(image, sources):
    start = image.named('_PRnut72j9')
    starts = function_starts(image)
    end = starts[starts.index(start) + 1]
    assert hashlib.sha256(image.read(start, end - start)).hexdigest() == BODY_HASH
    transfers = {}
    spans = {}
    for name, source in sources.items():
        assert start == shifted(source['container']['start'])
        assert end == shifted(source['container']['end_exclusive'])
        spans[name] = []
        for span in source['spans']:
            address = shifted(span['start'])
            old = bytes.fromhex(span['bytes_hex'])
            raw = image.read(address, len(old))
            changed = [i for i in range(0, len(raw), 4) if raw[i:i+4] != old[i:i+4]]
            changed_words = [image.instructions(address + i, 4)[0] for i in changed]
            spans[name].append(dict(label=span['label'], start=hex(address), words=len(raw) // 4,
                                    sha256=hashlib.sha256(raw).hexdigest(), changes=[
                dict(address=hex(x.address), mnemonic=x.mnemonic, operands=x.op_str)
                for x in changed_words
            ]))
        for row in source['branch_pointers']:
            target = shifted(row['target'])
            slot = TABLE + row['index'] * 8
            fixup = verify_fixup(image, slot, target, row['diversity'])
            image.instruction(target, 'bti', 'j')
            transfers[hex(slot)] = fixup
    probe = image.pointer(0xfffffe00084930b8)
    assert int(probe['target'], 16) == PROBE
    assert (probe['format'], probe['auth'], probe['diversity'], probe['address_diversity'],
            probe['key']) == (8, 1, '0x0', 1, 0)
    assert image.branch(0xfffffe000a54648c, 'bl') == start
    provider_args = assert_instructions(image.read, (
        (0xfffffe000a546480, 'mov', 'x0, x24'),
        (0xfffffe000a546484, 'mov', 'x1, x22'),
        (0xfffffe000a546488, 'mov', 'x2, x21'),
    ))
    saved_args = assert_instructions(image.read, (
        (0xfffffe000a6763dc, 'str', 'x2, [sp, #0x738]'),
        (0xfffffe000a6763e0, 'str', 'x1, [sp, #0x878]'),
        (0xfffffe000a6763e4, 'str', 'x0, [sp, #0x8f8]'),
    ))
    return dict(entry=hex(start), end_exclusive=hex(end), spans=spans,
                branch_fixups=transfers, stack_probe=probe, provider_arguments=provider_args,
                core_saves=saved_args)


def verify_banks(image, sources):
    roots = {}
    for offset, (target, _, bias) in (POOL_ROOTS | EXTRA_BANKS).items():
        old = qword(ARCHIVED_POOL + offset) + bias
        roots[hex(old)] = (target + bias, verify_fixup(image, POOL + offset, target))
    targets = dict(
        first_controller=CONTROLLERS[0], second_controller=CONTROLLERS[1], table=TABLE,
        aligned_allocator=image.named('_IOMallocAligned'), typed_allocator=image.named('_IOMallocTypeImpl'),
        typed_descriptor=AUX_TYPE, workspace_order=ORDER, typed_order=ORDER,
        FPTTLV_allocator=image.named('_IOMallocTypeImpl'), FPTTLV_descriptor=TLV_TYPE,
        null_release=image.named('_IOFreeTypeImpl'), null_release_descriptor=AUX_FREE,
        container_free=image.named('_IOFreeTypeImpl'), retirement_descriptor=TLV_FREE,
        staging_allocation=image.named('_IOMallocData'),
    )
    rules = {}
    for source in sources.values():
        for row in source['bank_rules']:
            name = row['name']
            left, right = (image.read(roots[row[key]][0], 256) for key in ('left', 'right'))
            assert left.hex() == row['left256_hex'] and right.hex() == row['right256_hex']
            key = int(row['key'], 16)
            constant, = {x ^ right[left[x] ^ key] for x in range(256)}
            index = constant + int(row['additive'], 16)
            assert constant == int(row['constant'], 16) and index == int(row['index'], 16)
            base = TABLE if row['original_pointer']['authenticated'] else POOL
            target = (targets[name] - int(row['bias'], 16)) & M
            fixup = verify_fixup(image, base + 8 * index, target, row['original_pointer']['diversity'])
            rules[name] = dict(constant=hex(constant), index=hex(index), target=hex(targets[name]),
                               fixup=fixup)
    assert len(rules) == 15
    return dict(roots=[root for _, root in roots.values()], rules=rules)


class InstalledReplay(Replay):
    """Use the archived integer instruction semantics with installed memory."""

    def __init__(self, image, row):
        self.image = image
        self.g = [int(v, 16) for v in row['entry_registers31']]
        self.d = [int(v, 16) & M for v in row['entry_Q_registers32']]
        self.sp = int(row['entry_SP'], 16)
        self.pc = shifted(row['entry_PC'])
        self.nzcv = int(row['entry_NZCV'], 16)
        self.count = Counter()
        self.edges = []
        self.models = {}
        self.state = {}
        self.cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        self.cs.detail = True
        self.initial = {}
        self.private_reads = []
        self.private_writes = []
        self.row = row
        self.input = row['input']
        for index, address in enumerate(CONTROLLERS):
            fixture = self.input['global_fixture']
            if fixture == 'original':
                data = image.read(address, 8)
            else:
                seed = 0 if fixture == 'zero' else 0x12345678a5a50000 + (index + 6) * 0x111111111
                data = seed.to_bytes(8, 'little')
            self.initial.update({address + n: b for n, b in enumerate(data)})
        self.cuts = []

    def value(self, address, width):
        return int.from_bytes(bytes(self.state[address + n] for n in range(width)), 'little')

    def load(self, address, width, discarded=False):
        if in_private(address, width):
            self.private_reads.append((address, width, discarded))
            assert discarded or all(address + n in self.state for n in range(width))
            data = bytes(self.state.get(address + n, 0xa5) for n in range(width))
        elif address in CONTROLLERS:
            data = bytes(self.state.get(address + n, self.initial[address + n])
                         for n in range(width))
        else:
            raw = self.image.read(address, width)
            row = self.image.fixups.get(self.image.offset(address, width)) if width == 8 else None
            data = int(row['target'], 16).to_bytes(8, 'little') if row else raw
        return int.from_bytes(data, 'little')

    def store(self, address, width, value):
        if in_private(address, width):
            self.private_writes.append((address, width))
        else:
            assert width == 8 and address in CONTROLLERS
        raw = (value % (1 << (8 * width))).to_bytes(width, 'little')
        self.state.update({address + n: b for n, b in enumerate(raw)})

    def allocation(self, instr, replay):
        assert instr.mnemonic == 'blraa'
        target = self.reg(instr.reg_name(instr.operands[0].reg))
        expected = {
            ALLOC_ALIGNED: ('_IOMallocAligned', (0x4000, 64)),
            ALLOC_TYPED: ('_IOMallocTypeImpl', (AUX_TYPE,)),
            ALLOC_TLV: ('_IOMallocTypeImpl', (TLV_TYPE,)),
        }
        name, args = expected[self.pc]
        assert target == self.image.named(name)
        assert tuple(self.g[:len(args)]) == args, (hex(self.pc), tuple(map(hex, self.g[:2])))
        assert replay['target_executed'] is False and replay['model_memory_writes'] == 0
        result = int(replay['result_X0_fixture'], 16)
        self.cuts.append(dict(pc=hex(self.pc), target=hex(target), name=name,
                              arguments=list(map(hex, args)), result=hex(result)))
        self.g[0] = result
        for j in range(1, 18):
            self.g[j] = 0xf000000000000000 + j * 0x1111
        self.nzcv = 0xf0000000
        self.g[30] = self.pc + 4
        return self.pc + 4

    def replay(self):
        fixtures = {row['source_visit_index']: row for row in self.row['API_models']}
        expected_edges = self.row['logical_edges']
        visit_count = 0
        for self.ix, visit in enumerate(self.row['source_visits']):
            assert self.pc == shifted(visit['pc']), (hex(self.pc), hex(shifted(visit['pc'])))
            instr, = self.cs.disasm(self.image.read(self.pc, 4), self.pc)
            if self.ix in fixtures:
                self.pc = self.allocation(instr, fixtures[self.ix])
            else:
                self.pc = self.step(instr)
            visit_count += 1
        assert len(self.edges) == len(expected_edges)
        for current, old in zip(self.edges, expected_edges, strict=True):
            assert current['pc'] == hex(shifted(old['pc']))
            assert current['target'] == hex(shifted(old['target']))
            assert current['kind'] == old['kind']
            if shifted(old['target']) != PROBE:
                assert current['modifier64'] == old['modifier64']

        for key, actual in (('source_reads', self.private_reads), ('source_writes', self.private_writes)):
            archived = []
            for row in self.row[key]:
                a, n = int(row['address'], 16), row['size_bytes']
                if in_private(a, n):
                    archived.append((a, n, row['probe_only']) if key == 'source_reads' else (a, n))
            assert actual == archived, key

        assert self.pc == shifted(self.row['boundary']['pc'])
        frame = int(self.row['frame_base_SP'], 16)
        assert self.sp == frame == int(self.row['entry_SP'], 16) - 0x10f0
        I, A, Q = self.input['inputs8'][:3]
        assert (self.value(frame + 0x8f8, 8), self.value(frame + 0x878, 8),
                self.value(frame + 0x738, 8)) == (I, A, Q)
        cut = self.verify_boundary(I, A)
        return dict(controller_fixture=self.input['global_fixture'], placement=self.input['placement'],
                    inputs=[hex(I), A, hex(Q)], instruction_visits=visit_count,
                    logical_edges=len(self.edges), private_read_events=len(self.private_reads),
                    private_write_events=len(self.private_writes), allocation_cuts=self.cuts,
                    boundary=cut)

    def verify_boundary(self, source, extent):
        instr, = self.cs.disasm(self.image.read(self.pc, 4), self.pc)
        if self.pc != AUX_RELEASE:
            assert self.value(PRIVATE + 0x8000 + 0xb5c, 4) == extent ^ 0x31ae0066
            assert self.value(PRIVATE + 0xc000 + 0x98, 8) == source
        if self.pc == INPUT_BYTE:
            assert (instr.mnemonic, instr.op_str) == ('ldrb', 'w11, [x10, x9]')
            assert self.g[10] == source and self.g[9] == 6 and extent >= 10
            assert self.value(PRIVATE + 0xe000, 16) == 0
            return dict(pc=hex(self.pc), kind='input_byte', address=hex(source + 6))
        assert instr.mnemonic == 'blraa'
        target = self.reg(instr.reg_name(instr.operands[0].reg))
        if self.pc == STAGING_CALL:
            assert target == self.image.named('_IOMallocData') and self.g[0] == extent
            return dict(pc=hex(self.pc), kind='staging_allocation', target=hex(target), size_bytes=extent)
        assert self.pc in (AUX_RELEASE, TLV_RELEASE)
        assert target == self.image.named('_IOFreeTypeImpl')
        object_pointer = PRIVATE + (0xc000 if self.pc == AUX_RELEASE else 0xe000)
        assert self.g[1] == object_pointer
        assert self.g[0] == (AUX_FREE if self.pc == AUX_RELEASE else TLV_FREE)
        details = dict(pc=hex(self.pc), kind='typed_release',
                       target=hex(target), descriptor=hex(self.g[0]), object=hex(object_pointer))
        if self.pc == TLV_RELEASE:
            assert extent < 10
            assert self.value(object_pointer, 16) == 0
            status = self.value(PRIVATE + 0x8000 + 0xc94, 4)
            assert status == (0x31ae0066 if extent == 0 else 0xce515bb8)
            cell = PRIVATE + 0xc000 + (0x418 if extent == 0 else 0x3d0)
            assert self.value(cell, 8) == object_pointer and self.g[19] == cell
            details.update(parser_status=hex(status), cleanup_cell=hex(cell))
        return details


def audit(path):
    build = command('sw_vers', '-buildVersion').strip().decode()
    assert build == '26C5035r' and sysctl('kern.uuid').lower() == IDENTITIES[1][1]
    image = Collection(path, IDENTITIES[1])
    active = {}
    results = []
    for name, digest in ARCHIVES.items():
        archive = receipt(f'userclient_{name}_checks', digest)
        assert archive['kernel_collection_sha256'] == IDENTITIES[0][0]
        active[name] = archive['source']
        for row in archive['cases']:
            source, extent, _ = row['input']['inputs8'][:3]
            if name == 'entry_execution' and source:
                continue
            if source not in (0, PRIVATE + 0x2000) or extent > 0xffffffff:
                continue
            results.append(InstalledReplay(image, row).replay())
    layout = verify_layout(image, active)
    banks = verify_banks(image, active)
    descriptors = dict(
        aux_allocate=read_type(image, AUX_TYPE, 'site.AllocType', '1' * 512, 4096),
        aux_release=read_type(image, AUX_FREE, 'site.AllocType', '1' * 512, 4096),
        container_allocate=read_type(image, TLV_TYPE, 'site.FPTTLV', '11', 16),
        container_release=read_type(image, TLV_FREE, 'site.FPTTLV', '11', 16),
    )
    assert len(results) == 66
    return dict(build=build, identity=IDENTITIES[1], archives=ARCHIVES, layout=layout,
                banks=banks, descriptors=descriptors, cases=results, native_transaction_observed=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    print(json.dumps(audit(parser.parse_args().collection), indent=2))
