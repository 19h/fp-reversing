#!/usr/bin/env python3
"""Read original RPC 502 request retirement code and inventory a retained trace."""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import struct

from audit_live_fairplay_cf_receive import assert_instructions, prior_receipt
from audit_live_fairplay_rpc_abi import Daemon, PINNED_DAEMON_SHA, command
from audit_live_kext_selector26 import Collection, IDENTITIES
from audit_live_xpc_log_sites import connect_stub
from bootpolicy_cache_reader import CS, Cache, Dylib

DAEMON_CHECKS = (
    (0x1000051b0, 'ldur', 'x9, [x0, #0x1c]'),
    (0x1000051b4, 'ldr', 'w2, [x0, #0x28]'),
    (0x1000051fc, 'cbz', 'w0, #0x100005228'),
    (0x100005200, 'str', 'w0, [x19, #0x20]'),
    (0x100005254, 'stp', 'w8, w9, [x19]'),
    (0x100422edc, 'ldrb', 'w12, [x1]'),
    (0x10008a958, 'ldrb', 'w13, [x11, #1]!'),
    (0x10006ce34, 'str', 'wzr, [x28, #8]'),
    (0x10006ce84, 'ldr', 'x8, [x23, w8, uxtw #3]'),
    (0x10006ce88, 'mov', 'x0, x28'),
    (0x10006ce8c, 'mov', 'x17, #0xc429'),
    (0x10006ce90, 'blraa', 'x8, x17'),
)

CACHE_CHECKS = (
    (0x180549bdc, 'ldr', 'w0, [x0, #8]'),
    (0x180549c0c, 'ldr', 'w20, [x19, #0x18]'),
    (0x180549c18, 'add', 'x19, x19, #0x1c'),
    (0x180549c20, 'ldr', 'w8, [x19, #8]'),
    (0x180549c24, 'lsr', 'w9, w8, #0x18'),
    (0x180549c74, 'cmp', 'w9, #1'),
    (0x180549c7c, 'tst', 'w8, #0xff'),
    (0x180549c84, 'ldr', 'w2, [x19, #0xc]'),
    (0x180549c88, 'cbnz', 'w2, #0x180549cd0'),
    (0x180549cd0, 'ldr', 'x1, [x19]'),
    (0x180549cd4, 'ldr', 'w0, [x22, #0x920]'),
    (0x18054a7e8, 'cmp', 'w0, w8'),
    (0x18054a7ec, 'b.ne', '#0x18054a81c'),
    (0x180548a8c, 'mov', 'x16, #-0xc'),
    (0x180548a90, 'svc', '#0x80'),
    (0x1805701ac, 'str', 'x2, [sp, #0x28]'),
    (0x1805701ec, 'mov', 'x4, #0x12c100000000'),
    (0x180548c18, 'mov', 'x16, #-0x2f'),
    (0x180548c1c, 'svc', '#0x80'),
    (0x18479d790, 'ldr', 'x0, [sp, #0x68]'),
    (0x18479d794, 'cmp', 'x0, x24'),
    (0x18479d7a0, 'cbz', 'w8, #0x18479d7a8'),
    (0x1847ca1b0, 'mov', 'x0, #0'),
)

KERNEL_CHECKS = (
    (0xfffffe000bd0e488, 'mov', 'w17, #-0xff0100'),
    (0xfffffe000bd0e530, 'and', 'w6, w16, #0xff00'),
    (0xfffffe000bd0e580, 'cmp', 'w6, #0x100'),
    (0xfffffe000bd0e58c, 'str', 'x26, [x6, #-0x10]!'),
    (0xfffffe000bd0e590, 'and', 'w16, w16, w17'),
    (0xfffffe000bd0e594, 'cinc', 'w24, w16, eq'),
    (0xfffffe000bd0e4b0, 'stp', 'w24, w7, [x15, #-8]'),
    (0xfffffe000bebfba4, 'sub', 'x20, x9, w8, sxtw'),
    (0xfffffe000bebfbb0, 'add', 'x8, x20, x20, lsl #1'),
    (0xfffffe000bebfbb4, 'lsl', 'x8, x8, #3'),
    (0xfffffe000bebfbd4, 'ldr', 'x22, [x23, #8]'),
    (0xfffffe000bebfcc8, 'blraa', 'x22, x17'),
    (0xfffffe000bd23404, 'ldr', 'x16, [x0, #0x28]!'),
    (0xfffffe000bd23414, 'autda', 'x16, x17'),
    (0xfffffe000bd23438, 'ldp', 'x1, x2, [x19, #8]'),
    (0xfffffe000be0a064, 'adds', 'x8, x1, x2'),
    (0xfffffe000be0a06c, 'ldrb', 'w9, [x0, #0x2c]'),
    (0xfffffe000be0a080, 'bic', 'x1, x1, x9'),
    (0xfffffe000be0a088, 'and', 'x2, x8, x10'),
    (0xfffffe000be0a090, 'b.ls', '#0xfffffe000be0a0a0'),
)


def branch(read, site, target, opcode):
    raw = read(site, 4)
    word, = struct.unpack('<I', raw)
    assert word >> 26 == {'b': 5, 'bl': 37}[opcode]
    displacement = ((word & 0x1ffffff) - (word & 0x2000000)) * 4
    assert site + displacement == target
    expected, = assert_instructions(read, [(site, opcode, f'#0x{target:x}')])
    return expected


def windows(read, ranges):
    records = []
    for address, size in ranges:
        raw = read(address, size)
        assembly = [(i.mnemonic, i.op_str) for i in CS.disasm(raw, address)]
        assert len(assembly) * 4 == size
        records.append(dict(start=hex(address), original_bytes=raw.hex(), assembly=assembly))
    return records


def daemon_evidence(path):
    daemon = Daemon(path)
    assert hashlib.sha256(daemon.data).hexdigest() == PINNED_DAEMON_SHA
    proof, = (row for row in prior_receipt('daemon_receive_contracts')['bank_proofs']
              if row['label'] == 'destroy request')
    left, right = (daemon.read(int(proof[field], 16), 256) for field in ('left', 'right'))
    assert {x ^ right[left[x] ^ 0xe4] for x in range(256)} == {0x5d}
    slot = 0x101039ef0 + 8 * (0xcd98 + 0x5d)
    assert slot == int(proof['slot'], 16)
    assert daemon.read(slot, 8).hex() == proof['original_slot_word']
    wanted = ' '.join(proof['fixup']['line'].split())
    lines = command('xcrun', 'dyld_info', '-fixups', str(path)).decode().splitlines()
    assert wanted in {' '.join(line.split()) for line in lines}
    return dict(sha256=PINNED_DAEMON_SHA, pins=assert_instructions(daemon.read, DAEMON_CHECKS),
                selector=proof, windows=windows(daemon.read, (
                    (0x1000051f8, 0x7c), (0x10006ce30, 0x64), (0x100422edc, 0x14),
                )))


def cache_evidence():
    cache = Cache()
    kernel = Dylib(cache, '/usr/lib/system/libsystem_kernel.dylib')
    cf = Dylib(cache, '/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation')
    malloc = Dylib(cache, '/usr/lib/system/libsystem_malloc.dylib')
    prior = prior_receipt('live_fairplay_cf_receive_audit')
    assert (cache.uuid, cf.uuid, kernel.uuid) == (
        prior['cache_uuid'], prior['corefoundation_uuid'], prior['libsystem_kernel_uuid'])
    expected = {
        '_mach_msg_destroy': 0x180549bbc, '_mach_vm_deallocate': 0x18054a7a4,
        '__kernelrpc_mach_vm_deallocate_trap': 0x180548a8c, '_mach_task_self_': 0x1ed902920,
    }
    assert {key: kernel.exports[key]['address'] for key in expected} == expected
    edges = [(0x180549cd8, 0x18054a7a4, 'bl'), (0x18054a7dc, 0x180548a8c, 'bl'),
             (0x18054a818, 0x180570188, 'b'), (0x1805701f8, 0x18055b918, 'bl'),
             (0x18055b960, 0x180548c18, 'bl'), (0x18479d7a4, 0x18806c3d0, 'bl')]
    return dict(cache_uuid=cache.uuid, libsystem_kernel_uuid=kernel.uuid, corefoundation_uuid=cf.uuid,
                pins=assert_instructions(cache.read, CACHE_CHECKS),
                free_binding=connect_stub(cache, 0x18806c3d0, malloc, '_free'),
                edges=[branch(cache.read, site, target, op) for site, target, op in edges],
                functions=[kernel.function(address) for address in (
                    0x180549bbc, 0x18054a7a4, 0x180548a8c, 0x180570188)],
                windows=windows(cache.read, ((0x18479d790, 0x18), (0x18055b918, 0x4c))))


def kernel_evidence(path):
    image = Collection(path, IDENTITIES[1])
    table = 0xfffffe0007f07018
    entry = table + 12 * 24
    meta = image.read(entry, 8)
    assert meta == bytes((3, 5, 0, 0, 0, 0, 0, 0))
    handler = image.pointer(entry + 8)
    assert int(handler['target'], 16) == 0xfffffe000bd233e0
    assert (handler['auth'], handler['diversity'], handler['address_diversity']) == (1, '0x307a', 0)
    assert image.named('_mach_vm_deallocate') == 0xfffffe000be75ed8
    original_flags = 0x01000100
    packed_flags = (original_flags & 0xff00ff00) + int((original_flags & 0xff00) == 0x0100)
    assert packed_flags == 0x01000101
    edges = [(0xfffffe000bd0e598, 0xfffffe000bd0e4b0, 'b'),
             (0xfffffe000bd233fc, 0xfffffe000bd433e4, 'bl'),
             (0xfffffe000bd23448, 0xfffffe000be0a058, 'b'),
             (0xfffffe000be75edc, 0xfffffe000be0a058, 'b'),
             (0xfffffe000be0a09c, 0xfffffe000be1302c, 'b')]
    return dict(sha256=image.digest, uuid=IDENTITIES[1][1], trap_table=hex(table), slot12=handler,
                slot12_metadata=meta.hex(), sender_flags=hex(original_flags), receiver_flags=hex(packed_flags),
                pins=assert_instructions(image.read, KERNEL_CHECKS),
                edges=[branch(image.read, site, target, op) for site, target, op in edges],
                windows=windows(image.read, (
                    (0xfffffe000bd0e524, 0x78), (0xfffffe000bd0e4a4, 0x18),
                    (0xfffffe000bebfb98, 0x54), (0xfffffe000bebfcc0, 0x10),
                    (0xfffffe000bd233e0, 0x6c), (0xfffffe000be0a058, 0x58),
                )))


def trace_evidence(path):
    raw = path.read_bytes()
    lines = raw.decode().splitlines()
    header = re.compile(r'(?:\b(?:send|received) bits=.*?\bid=|\bbridge: (?:sent|received) id )([0-9]+)\b')
    ids = Counter(int(match[1]) for line in lines if (match := header.search(line)))
    vm_traps = sum('_kernelrpc_mach_vm_deallocate_trap(' in line for line in lines)
    assert (len(lines), sum(ids.values()), vm_traps) == (1748, 64, 19)
    assert ids[502] == ids[602] == 0
    return dict(sha256=hashlib.sha256(raw).hexdigest(), lines=len(lines), headers=sum(ids.values()),
                message_id_counts=dict(sorted(ids.items())), vm_deallocation_trap_lines=vm_traps,
                rpc502_header_count=ids[502], rpc602_header_count=ids[602])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    parser.add_argument('daemon', type=Path)
    parser.add_argument('trace', type=Path)
    args = parser.parse_args()
    receipt = dict(build='26C5035r', daemon=daemon_evidence(args.daemon), cache=cache_evidence(),
                   kernel=kernel_evidence(args.collection), trace=trace_evidence(args.trace),
                   native_transaction_observed=False)
    print(json.dumps(receipt, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
