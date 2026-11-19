#!/usr/bin/env python3
"""Verify the installed RPC 502 request's original-byte OOL data path."""

import argparse
import hashlib
import json
from pathlib import Path
import struct

from audit_live_fairplay_cf_receive import assert_instructions, prior_receipt
from audit_live_fairplay_rpc_abi import Daemon, PINNED_DAEMON_SHA
from audit_live_kext_selector26 import Collection, IDENTITIES
from audit_live_kext_selector26_transfer import address_pair

MAP_CELL = 0xfffffe0007f06638
POOL = 0xfffffe00084889a0
TABLE = 0xfffffe00084899c0
PUBLISH = 0xfffffe000c679168

BANKS = {
    'ipc_kernel_map cell': ((0xfffffe00084895a8, 8), (0xfffffe0008488af8, 4)),
    'kmem_alloc adapter': ((0xfffffe00084891e0, 0), (0xfffffe0008489558, 0)),
    'name memcpy/memmove': ((0xfffffe00084891e0, 0), (0xfffffe0008489558, 0)),
    'request copyin adapter': ((0xfffffe00084891e0, 0), (0xfffffe0008489558, 0)),
    'request free adapter': ((0xfffffe0008488df8, 8), (0xfffffe0008488fd8, 12)),
}

WINDOWS = {
    'startup submap producer': ((0xfffffe000c679140, 0x2c), (0xfffffe000be09a08, 0x24),
                               (0xfffffe000be0f0c8, 0x18), (0xfffffe000be0f154, 0x18)),
    'kext staging and VM copy': ((0xfffffe000a64c608, 0x40), (0xfffffe000a64c690, 0x1c),
                               (0xfffffe000a64c788, 0x18), (0xfffffe000a64c8b0, 0x64),
                               (0xfffffe000a656ff8, 0x70)),
    'small object construction': ((0xfffffe000be19744, 0x10), (0xfffffe000be19864, 0x28),
                                  (0xfffffe000be199ec, 0x64), (0xfffffe000be1a038, 0xb4)),
    'RPC 502 packing and signing': ((0xfffffe000a5e322c, 0x60), (0xfffffe000a6e04b4, 0x10),
                                    (0xfffffe000bd3dd1c, 0x14), (0xfffffe000bd3d930, 0x14),
                                    (0xfffffe000bd0e9a8, 0x30), (0xfffffe000bd0ea98, 0x10),
                                    (0xfffffe000bd0a34c, 0x28), (0xfffffe000bd0a3a0, 0x20)),
    'receive copyout': ((0xfffffe000bd0d3a4, 0x38), (0xfffffe000bd0d544, 0x3c),
                        (0xfffffe000bd0d618, 0x94), (0xfffffe000be1968c, 0x80),
                        (0xfffffe000be1359c, 0x34), (0xfffffe000bd0d88c, 0x3c),
                        (0xfffffe000be13d84, 0x18), (0xfffffe000be13f78, 0x10),
                        (0xfffffe000be1400c, 0x20), (0xfffffe000be140bc, 0x48)),
}

CHECKS = (
    (0xfffffe000c679144, 'ldr', 'x0, [x19, #0x880]'),
    (0xfffffe000c679150, 'mov', 'w2, #0x4000000'),
    (PUBLISH, 'str', 'x0, [x8, #0x638]'),
    (0xfffffe000be09a18, 'mov', 'w3, #0xe'),
    (0xfffffe000be0f0d4, 'strb', 'w24, [x0, #0x2c]'),
    (0xfffffe000be0f168, 'stp', 'x9, x8, [x20, #0x10]'),
    (0xfffffe000a64c644, 'ldr', 'x0, [x21, #-4]!'),
    (0xfffffe000a64c6a8, 'blraa', 'x8, x17'),
    (0xfffffe000a64c798, 'blraa', 'x8, x17'),
    (0xfffffe000a64c8b4, 'ldr', 'x0, [x21]'),
    (0xfffffe000a64c900, 'add', 'x4, x28, #0x28'),
    (0xfffffe000a64c904, 'ldr', 'x2, [sp, #0x118]'),
    (0xfffffe000a64c908, 'mov', 'w3, #0'),
    (0xfffffe000a64c910, 'blraa', 'x8, x17'),
    (0xfffffe000a657064, 'blraa', 'x8, x17'),
    (0xfffffe000be19878, 'cmp', 'x2, #8, lsl #12'),
    (0xfffffe000be1a0bc, 'stp', 'x23, xzr, [x0, #0x20]'),
    (0xfffffe000be1a0c8, 'strb', 'w8, [x0, #0x2d]'),
    (0xfffffe000be1a0e8, 'str', 'x22, [x25]'),
    (0xfffffe000a5e3234, 'stur', 'x1, [sp, #0x2c]'),
    (0xfffffe000a5e323c, 'stp', 'w8, w2, [sp, #0x34]'),
    (0xfffffe000a5e3250, 'str', 'w2, [sp, #0x44]'),
    (0xfffffe000bd3dd24, 'mov', 'x4, #0x2000000000'),
    (0xfffffe000bd0e9b8, 'tbnz', 'x22, #0x25, #0xfffffe000bd0ea98'),
    (0xfffffe000bd0a3b8, 'movk', 'x16, #0x5d4f, lsl #48'),
    (0xfffffe000bd0a350, 'pacda', 'x17, x16'),
    (0xfffffe000bd0d630, 'autda', 'x16, x17'),
    (0xfffffe000be196a8, 'cmp', 'x9, x8'),
    (0xfffffe000bd0d570, 'str', 'x8, [x19]'),
    (0xfffffe000bd0d574, 'str', 'w26, [x19, #0xc]'),
    (0xfffffe000bd0d89c, 'ldur', 'x8, [x29, #-0x60]'),
    (0xfffffe000be1400c, 'cbz', 'w23, #0xfffffe000be14100'),
    (0xfffffe000be14020, 'autda', 'x16, x17'),
)

DAEMON_CHECKS = (
    (0x1000050f4, 'ldr', 'w8, [x0, #0x28]'),
    (0x1000050f8, 'ldr', 'w9, [x0, #0x34]'),
    (0x1000050fc, 'cmp', 'w8, w9'),
    (0x1000051b0, 'ldur', 'x9, [x0, #0x1c]'),
    (0x1000051b4, 'ldr', 'w2, [x0, #0x28]'),
    (0x1000051f4, 'mov', 'x1, x9'),
    (0x1000051f8, 'bl', '#0x100422d48'),
)


def current_banks(image, reference):
    result = {}
    for proof in prior_receipt('kext_port_vm_contracts')['bank_proofs']:
        name = proof['label']
        if name not in BANKS:
            continue
        tables, pointers = [], []
        for field, (slot, bias) in zip(('left', 'right'), BANKS[name]):
            pointer = image.pointer(slot)
            start = int(pointer['target'], 16) - bias
            table = image.read(start, 256)
            assert table == reference.read(int(proof[field], 16), 256)
            tables.append(table)
            pointers.append(dict(fixup=pointer, bias=bias, address=hex(start), original_bytes=table.hex()))
        left, right = tables
        key, addend = (int(proof[field], 16) for field in ('key', 'additive'))
        values = {byte ^ right[left[byte] ^ key] for byte in range(256)}
        assert values == {int(proof['constant'], 16)}
        offset = addend + values.pop()
        base = POOL if name == 'ipc_kernel_map cell' else TABLE
        slot = base + 8 * offset
        assert offset == int(proof['index'], 16) and slot == int(proof['slot'], 16) + 0x16aa0
        result[name] = dict(banks=pointers, key=key, addend=addend, index=offset,
                            selector_inputs_checked=256, fixup=image.pointer(slot))
    assert result.keys() == BANKS.keys()
    assert int(result['ipc_kernel_map cell']['fixup']['target'], 16) - 4 == MAP_CELL
    for name, symbol, diversity in (
        ('kmem_alloc adapter', '_kmem_alloc', 0x84ff),
        ('request copyin adapter', '_vm_map_copyin', 0xdff5),
        ('request free adapter', '_kmem_free', 0xa860),
    ):
        row = result[name]
        assert int(row['fixup']['diversity'], 16) == diversity
        adapter = int(row['fixup']['target'], 16)
        image.instruction(adapter, 'bti', 'c')
        stub = image.branch(adapter + 4, 'b')
        slot = address_pair(image, stub, 'x17')
        image.instruction(stub + 8, 'ldr', 'x16, [x17]')
        image.instruction(stub + 12, 'braa', 'x16, x17')
        target = image.pointer(slot)
        assert int(target['target'], 16) == image.named(symbol)
        row.update(stub=hex(stub), import_fixup=target, symbol=symbol)
    assert '_memcpy' in image.names(int(result['name memcpy/memmove']['fixup']['target'], 16))
    return result


def cell_references(image):
    """Bound the scan to adjacent ADRP and unsigned-offset u64 LDR/STR."""
    counts, loads, stores = {}, [], []
    for segment in image.root['segments']:
        if segment['name'] not in ('__TEXT_EXEC', '__TEXT_BOOT_EXEC'):
            continue
        base, size, start = (segment[key] for key in ('address', 'file_size', 'file_offset'))
        previous = None
        for index, (word,) in enumerate(struct.iter_unpack('<I', memoryview(image.data)[start:start + size])):
            pc = base + 4 * index
            if previous is not None and word & 0xff800000 == 0xf9000000:
                displacement = ((word >> 10) & 0xfff) * 8
                if (word >> 5) & 31 == previous and displacement == MAP_CELL & 0xfff:
                    (loads if word & 0x00400000 else stores).append(hex(pc))
            previous = None
            if word & 0x9f000000 == 0x90000000:
                imm = ((word >> 3) & 0x1ffffc) | ((word >> 29) & 3)
                pages = (imm & 0xfffff) - (imm & 0x100000)
                if (pc & ~0xfff) + pages * 4096 == MAP_CELL & ~0xfff:
                    previous = word & 31
        counts[segment['name']] = size // 4
    assert stores == [hex(PUBLISH)] and loads
    return dict(executable_words=counts, adjacent_loads=loads, adjacent_stores=stores)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    parser.add_argument('reference_collection', type=Path)
    parser.add_argument('daemon', type=Path)
    args = parser.parse_args()
    image = Collection(args.collection, IDENTITIES[1])
    reference = Collection(args.reference_collection, IDENTITIES[0])
    daemon = Daemon(args.daemon)
    assert hashlib.sha256(daemon.data).hexdigest() == PINNED_DAEMON_SHA
    assert image.named('_ipc_kernel_map') == MAP_CELL and image.read(MAP_CELL, 8) == bytes(8)
    assert image.named('_kernel_map') == 0xfffffe0007f92880
    policy = int.from_bytes(image.read(0xfffffe0007e7601c, 4), 'little')
    assert policy == 2
    rpc_stub = 0xfffffe000a6e04b4
    rpc_fixup = image.pointer(address_pair(image, rpc_stub, 'x17'))
    rpc_wrapper = image.named('_mach_msg_rpc_from_kernel_proper')
    assert int(rpc_fixup['target'], 16) == rpc_wrapper == 0xfffffe000bd3dd1c
    edges = (
        (0xfffffe000c679160, 'bl', 0xfffffe000be09998),
        (0xfffffe000be09a1c, 'bl', 0xfffffe000be0f06c),
        (0xfffffe000a5e3288, 'bl', rpc_stub),
        (0xfffffe000bd3dd2c, 'b', 0xfffffe000bd3d8d4),
        (0xfffffe000bd3d93c, 'bl', 0xfffffe000bd0e880),
        (0xfffffe000bd0ea9c, 'bl', 0xfffffe000bd0a328),
        (0xfffffe000bd0d3d8, 'b', 0xfffffe000bd0d520),
        (0xfffffe000bd0d654, 'bl', 0xfffffe000be1963c),
        (0xfffffe000bd0d6a4, 'bl', 0xfffffe000be13524),
        (0xfffffe000bd0d8b4, 'bl', image.named('_vm_map_copy_discard')),
        (0xfffffe000be135c4, 'bl', 0xfffffe000be13d60),
        (0xfffffe000be140cc, 'bl', 0xfffffe000bd46b3c),
        (0xfffffe000be140fc, 'bl', 0xfffffe000bdbcec0),
    )
    for site, op, target in edges:
        word = int.from_bytes(image.read(site, 4), 'little')
        assert (word >> 26) == {'b': 5, 'bl': 37}[op]
        assert site + (((word & 0x1ffffff) - (word & 0x2000000)) << 2) == target
        assert image.branch(site, op) == target
    windows = {}
    for role, spans in WINDOWS.items():
        windows[role] = [dict(address=hex(start), bytes=image.read(start, size).hex(),
                              assembly=[(i.mnemonic, i.op_str) for i in image.instructions(start, size)])
                         for start, size in spans]
    receipt = dict(
        current_collection_sha256=image.digest, kernel_uuid=IDENTITIES[1][1],
        fairplayiokit_uuid=IDENTITIES[1][2], reference_collection_sha256=reference.digest,
        daemon_sha256=PINNED_DAEMON_SHA, startup_map_capacity_bytes=64 * 1024 * 1024,
        startup_map_page_shift=14, policy_cell_file_word=policy,
        kernel_checks=assert_instructions(image.read, CHECKS),
        daemon_checks=assert_instructions(daemon.read, DAEMON_CHECKS),
        source_windows=windows, current_bank_selections=current_banks(image, reference),
        adjacent_cell_references=cell_references(image),
        direct_edges=[dict(site=hex(site), opcode=op, target=hex(target)) for site, op, target in edges],
        rpc_wrapper_fixup=rpc_fixup, native_transaction_observed=False,
    )
    print(json.dumps(receipt, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
