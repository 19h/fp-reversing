#!/usr/bin/env python3
"""Cross-check current FairPlay MIG clients, reply copyback and daemon emitter."""

import argparse
import json
from pathlib import Path
import re
import struct

from audit_daemon_iokit_native_registry import PINNED_DAEMON_SHA, command, digest, sysctl
from audit_fairplay_live_slice_identity import audit as live_slice_audit
from audit_live_fairplay_constructor_mode import compiler_bounds
from audit_live_fairplay_kernel_rpc import client
from audit_live_kext_selector26 import Collection, CS, DRIVER, IDENTITIES
from audit_live_kext_selector26_transfer import imported_call, words
from verify_interface_contracts import Image

CLIENTS = ((502, 602, 0xfffffe000a5e31f4), (700, 800, 0xfffffe000a5e3464))
CLIENT_SIZE = 624


class Daemon(Image):
    def instructions(self, address, size):
        result = list(CS.disasm(self.read(address, size), address))
        assert sum(word.size for word in result) == size
        return result

    def instruction(self, address, mnemonic, operands):
        word, = self.instructions(address, 4)
        assert (word.mnemonic, word.op_str) == (mnemonic, operands)


def daemon_abi(path):
    image = Daemon(path)
    assert digest(image.data) == PINNED_DAEMON_SHA
    fixup_text = command('xcrun', 'dyld_info', '-fixups', str(path)).decode()
    bind_rows = {
        int(address, 16): body.strip()
        for address, body in re.findall(
            r'^\s*\S+\s+\S+\s+(0x[0-9a-fA-F]+)\s+(auth-rebase\s+.*|auth-bind\s+.*|bind\s+.*)$',
            fixup_text, re.M)
    }
    fixed = {
        0x101038238: 'auth-rebase  0x1000050C8 (div=0x0000 ad=0 key=IA)',
        0x1010a1288: 'auth-bind  libSystem/_mach_msg (div=0x67EB ad=0 key=IA)',
        0x1010b1e10: 'bind  libSystem/_NDR_record',
    }
    for address, relation in fixed.items():
        assert bind_rows[address].split() == relation.split()
    assert struct.unpack('<3I', image.read(0x1010381c8, 12)) == (500, 503, 384)
    assert struct.unpack('<Q', image.read(0x101038238, 8))[0] & 0xffffffff == 0x50c8
    assert 0x1010381e0 + 40 * 502 - 0x4e18 == 0x101038238
    left, right = image.read(0x100fc4230, 256), image.read(0x101031fa0, 256)
    assert {x ^ right[left[x] ^ 0xf3] for x in range(256)} == {0x43}
    assert 0x101039ef0 + 8 * (0xce30 + 0x43) == 0x1010a1288
    for pc, op, args in (
        (0x1000050d0, 'ldr', 'w8, [x0, #0x18]'),
        (0x1000050d4, 'cmp', 'w8, #1'),
        (0x1000050e0, 'cmp', 'w8, #0x50'),
        (0x1000050e8, 'ldrb', 'w8, [x0, #0x27]'),
        (0x1000050f4, 'ldr', 'w8, [x0, #0x28]'),
        (0x1000050f8, 'ldr', 'w9, [x0, #0x34]'),
        (0x1000051ac, 'ldr', 'w8, [x0, #0xc]'),
        (0x1000051b0, 'ldur', 'x9, [x0, #0x1c]'),
        (0x1000051b8, 'ldp', 'x3, x4, [x0, #0x38]'),
        (0x1000051bc, 'ldr', 'x5, [x0, #0x48]'),
        (0x1000051c0, 'add', 'x13, x1, #0xcc'),
        (0x1000051c4, 'add', 'x14, x1, #0x178'),
        (0x1000051c8, 'add', 'x15, x1, #0x17c'),
        (0x1000051e8, 'add', 'x7, x1, #0x44'),
        (0x1000051f8, 'bl', '#0x100422d48'),
        (0x100005200, 'str', 'w0, [x19, #0x20]'),
        (0x100005228, 'ldr', 'w8, [x19, #0x178]'),
        (0x10000522c, 'str', 'w8, [x19, #0x28]'),
        (0x100005230, 'ldr', 'w8, [x19, #0x17c]'),
        (0x100005234, 'str', 'w8, [x19, #0x38]'),
        (0x100005250, 'mov', 'w9, #0x180'),
        (0x100005258, 'mov', 'w8, #2'),
        (0x100005274, 'mov', 'w8, #0x24'),
        (0x100005280, 'ldr', 'w10, [x0, #8]'),
        (0x10000528c, 'add', 'w8, w8, #0x64'),
        (0x100005290, 'stp', 'w10, wzr, [x1, #8]'),
        (0x100005294, 'stp', 'wzr, w8, [x1, #0x10]'),
        (0x100035158, 'ldr', 'w2, [x20, #4]'),
        (0x10003516c, 'mov', 'x0, x20'),
        (0x100035180, 'mov', 'x17, #0x67eb'),
        (0x100035184, 'blraa', 'x8, x17'),
    ):
        image.instruction(pc, op, args)
    return {'thin_sha256': digest(image.data), 'fixups': [
                {'address': hex(address), 'raw': image.read(address, 8).hex(), 'target': bind_rows[address]}
                for address in fixed],
            'send_bank_bytes': [left.hex(), right.hex()],
            'windows': {name: words(image, start, size) for name, start, size in (
                ('stub', 0x1000050c8, 0x1ac), ('demux', 0x100005274, 0x90),
                ('send', 0x1000350e0, 0xa8))}}


def clients(image):
    starts = compiler_bounds(image)
    captures = {}
    bodies = []
    for index, (request, reply, entry) in enumerate(CLIENTS, start=343):
        assert starts[index:index + 2] == [entry, entry + CLIENT_SIZE]
        rows = image.instructions(entry, CLIENT_SIZE)
        bodies.append(rows)
        for offset, op, args in (
            (0x1c, 'mov', 'x20, x7'), (0x20, 'mov', 'x21, x6'),
            (0x3c, 'str', 'w22, [sp, #0x28]'), (0x40, 'stur', 'x1, [sp, #0x2c]'),
            (0x48, 'stp', 'w8, w2, [sp, #0x34]'), (0x5c, 'str', 'w2, [sp, #0x44]'),
            (0x60, 'stp', 'x3, x4, [sp, #0x48]'), (0x64, 'str', 'x5, [sp, #0x58]'),
            (0x88, 'add', 'x0, sp, #8'), (0xd0, 'ldr', 'w8, [sp, #0x24]'),
            (0xdc, 'cmp', f'w8, #{reply:#x}'), (0xec, 'cmp', 'w8, #0x2c'),
            (0xf4, 'ldr', 'w8, [sp, #0x30]'), (0x100, 'ldr', 'x9, [sp, #0x10]'),
            (0x134, 'cmp', 'w9, #2'), (0x13c, 'cmp', 'w8, #0x188'),
            (0x144, 'ldr', 'x8, [sp, #0x10]'), (0x14c, 'ldrb', 'w8, [sp, #0x37]'),
            (0x158, 'ldrb', 'w8, [sp, #0x47]'), (0x164, 'ldr', 'w8, [sp, #0x38]'),
            (0x168, 'ldr', 'w9, [sp, #0x188]'), (0x174, 'ldr', 'w9, [sp, #0x48]'),
            (0x178, 'ldr', 'w10, [sp, #0x18c]'), (0x1c0, 'stp', 'q0, q1, [x21]'),
            (0x1c8, 'add', 'x11, x11, #0xd4'), (0x1f4, 'stur', 'q0, [x20, #0x9c]'),
            (0x204, 'ldp', 'x11, x10, [x29, #0x20]'), (0x208, 'ldp', 'x13, x12, [x29, #0x10]'),
            (0x214, 'str', 'x14, [x13]'), (0x218, 'str', 'w8, [x12]'),
            (0x220, 'str', 'x8, [x11]'), (0x224, 'str', 'w9, [x10]'),
        ):
            image.instruction(entry + offset, op, args)
        captures[request] = {'entry': hex(entry), 'expected_reply_id': reply,
                             'transport': client(image, entry, entry + 0x94, request),
                             'words': words(image, entry, CLIENT_SIZE), 'imports': {
                                 name: imported_call(image, entry + offset, name)
                                 for offset, name in ((0x68, '_mig_get_reply_port'),
                                                      (0xc4, '_mig_put_reply_port'),
                                                      (0x114, '_mig_dealloc_reply_port'))}}
    differences = []
    for offset, (a, b) in enumerate(zip(*bodies, strict=True)):
        if a.bytes != b.bytes:
            assert a.mnemonic == b.mnemonic
            if a.mnemonic == 'bl':
                assert a.op_str == b.op_str
            differences.append({'offset': hex(offset * 4), 'mnemonic': a.mnemonic,
                                'a': a.op_str, 'b': b.op_str})
    assert [int(row['offset'], 16) for row in differences] == [0x68, 0x80, 0x94, 0xc4, 0xdc, 0x114, 0x234, 0x26c]
    return {'clients': captures, 'differences': differences}


def copyback(image):
    wrapper = image.named('_mach_msg_rpc_from_kernel_proper')
    assert image.branch(wrapper + 0x10, 'b') == 0xfffffe000bd3d8d4
    header_call = 0xfffffe000bd3dc70
    copy_call = 0xfffffe000bd3dcb4
    assert image.branch(header_call, 'bl') == 0xfffffe000bd0e110
    assert image.branch(copy_call, 'bl') == 0xfffffe000bd0f4d8
    for pc, op, args in (
        (wrapper + 8, 'mov', 'x4, #0x2000000000'),
        (0xfffffe000bd3d928, 'mov', 'x25, x2'),
        (0xfffffe000bd3d934, 'stp', 'x4, x0, [sp, #0x10]'),
        (0xfffffe000bd3dc38, 'ldr', 'w19, [x16, #4]'),
        (0xfffffe000bd3dc3c, 'adds', 'w20, w19, #0x44'),
        (0xfffffe000bd3dc44, 'cmp', 'w8, w19'),
        (0xfffffe000bd3dc80, 'add', 'x9, x19, #8'),
        (0xfffffe000bd3dc84, 'cmp', 'x9, w25, uxtw'),
        (0xfffffe000bd3dc88, 'ldp', 'x1, x0, [sp, #0x10]'),
        (0xfffffe000bd3dc90, 'cmp', 'w25, w20'),
        (0xfffffe000bd3dc98, 'mov', 'x19, x9'),
        (0xfffffe000bd3dcb0, 'mov', 'x3, x19'),
        (0xfffffe000bd0e170, 'ldp', 'x23, x24, [x19, #8]'),
        (0xfffffe000bd0e24c, 'stp', 'x24, x8, [x19, #8]'),
        (0xfffffe000bd0f4fc, 'mov', 'x20, x1'),
        (0xfffffe000bd0f5c4, 'tbz', 'x20, #0x25, #0xfffffe000bd0f5e0'),
        (0xfffffe000bd0f644, 'movk', 'x17, #0x5d4f, lsl #48'),
        (0xfffffe000bd0f648, 'autda', 'x16, x17'),
        (0xfffffe000bd0f6a8, 'str', 'x8, [x10], #0x10'),
    ):
        image.instruction(pc, op, args)
    return {'header_conversion_call': hex(header_call), 'reply_copyback_call': hex(copy_call),
            'windows': {name: words(image, start, size) for name, start, size in (
                ('transport_return', 0xfffffe000bd3dc38, 0x80),
                ('header_conversion', 0xfffffe000bd0e110, 0x15c),
                ('descriptor_copyback', 0xfffffe000bd0f4d8, 0x1ec))}}


def runtime_identity(daemon):
    assert sysctl('kern.uuid').lower() == IDENTITIES[1][1]
    listing = command('kmutil', 'showloaded', '-b', DRIVER).decode()
    assert any(DRIVER in line and IDENTITIES[1][2] in line.lower() for line in listing.splitlines())
    full = live_slice_audit(daemon)
    assert full['build'] == '26C5035r'
    return {key: full[key] for key in ('build', 'started_utc', 'fairplayd_file_comparison')} | {
        'matched_process': full['processes']['fairplayd']}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    parser.add_argument('daemon', type=Path)
    parser.add_argument('--observe', action='store_true')
    args = parser.parse_args()
    collection = Collection(args.collection, IDENTITIES[1])
    receipt = {'kernel_identity': IDENTITIES[1], 'daemon': daemon_abi(args.daemon),
               'kernel_clients': clients(collection), 'return_transport': copyback(collection),
               'native_message_observed': False}
    if args.observe:
        receipt['runtime_identity'] = runtime_identity(args.daemon)
    print(json.dumps(receipt, indent=2))
