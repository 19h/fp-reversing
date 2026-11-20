#!/usr/bin/env python3
"""Correlate installed IOKit discovery stubs with a pinned archived trace."""

import argparse
import hashlib
import json
import re
import struct
from pathlib import Path

from audit_live_iokit_mach_transport import (
    CACHE_UUID, CS, IOKIT, LIBKERNEL, Cache, Dylib, clean_pointer, dyld_uuid,
)

TRACE_SHA256 = '78578ddda9f769b2ecdf22e71235e1c2012433e017acb89d92b308e9e7ae439e'


def installed_discovery():
    cache = Cache()
    assert cache.uuid == CACHE_UUID == dyld_uuid()
    iokit = Dylib(cache, IOKIT)
    kernel = Dylib(cache, LIBKERNEL)
    assert iokit.uuid == '82be1de5-91c4-3152-b63b-81db4c5e7992'
    assert kernel.uuid == '780a6c1f-be02-34cc-84dd-00e05f61c89b'
    bindings = {}
    for pc, image, name, address in (
        (0x188080c60, kernel, '_mach_host_self', 0x180549a50),
        (0x188088a70, kernel, '_host_get_io_main', 0x18056b3dc),
        (0x18806c480, kernel, '_mach_port_deallocate', 0x18054a06c),
        (0x188076d50, kernel, '_mig_get_reply_port', 0x180548f00),
        (0x188088af0, kernel, '_mach_msg2_internal', 0x18055b918),
        (0x188076560, Dylib(cache, '/usr/lib/system/libdispatch.dylib'),
         '_dispatch_once', 0x185598570),
    ):
        assert name in {row['name'] for row in image.symbols_at(address)}
        words = list(CS.disasm(cache.read(pc, 16), pc))
        assert [i.mnemonic for i in words] == ['adrp', 'add', 'ldr', 'braa']
        assert [i.op_str for i in words[2:]] == ['x16, [x17]', 'x16, x17']
        slot = sum(int(i.op_str.split('#')[-1], 16) for i in words[:2])
        pointer = clean_pointer(cache.pointer(slot))
        assert pointer['authenticated'] and pointer['chain_membership_verified']
        assert int(pointer['target'], 16) == address
        bindings[name] = dict(pointer, veneer=hex(pc))

    instructions = {}
    for pc, asm in (
        (0x184ee2330, 'b #0x184ebc218'),
        (0x184ebc234, 'bl #0x188080c60'),
        (0x184ebc240, 'bl #0x188088a70'),
        (0x184ebc278, 'add x16, x16, #0x2e8'),
        (0x184ebc298, 'cmn x8, #1'),
        (0x184ebc2b4, 'bl #0x18806c480'),
        (0x184ebc2dc, 'bl #0x188076560'),
        (0x184ebc30c, 'bl #0x184ebc34c'),
        (0x184ebc314, 'str xzr, [x19]'),
        (0x184ebc320, 'mov w9, #0x5184'),
        (0x184ebc324, 'movk w9, #0x133, lsl #16'),
        (0x184ebc32c, 'b.hi #0x184ebc340'),
        (0x184ebc338, 'and x9, x9, #0xfffffffffffffffe'),
        (0x184ebc33c, 'str x9, [x8, #0x3f8]'),
        (0x184ebc384, 'bl #0x188076d50'),
        (0x184ebc394, 'stp w20, w0, [sp, #8]'),
        (0x184ebc3cc, 'bl #0x188088af0'),
        (0x184ebc418, 'cmp w8, #0xba1'),
        (0x184ebc42c, 'cmp w8, #0x2c'),
        (0x184ebc4c0, 'str x8, [x19]'),
        (0x184ebd1b0, 'bl #0x184ebc218'),
        (0x184ebd1cc, 'bl #0x184ebc6cc'),
        (0x184ebd1f0, 'tbnz w8, #0, #0x184ebd220'),
        (0x184ebd1f4, 'cmp x23, #0x1ff'),
        (0x184ebd210, 'bl #0x184f5e134'),
        (0x184ebd220, 'cmp x23, #0xfff'),
        (0x184ebd240, 'bl #0x184ebd2c4'),
        (0x184ebd26c, 'bl #0x184f60800'),
        (0x184ebd288, 'cmp w20, w19'),
        (0x184ebd2a0, 'bl #0x18806c480'),
        (0x184ebd388, 'str w21, [sp, #0x20]'),
        (0x184ebd390, 'and w8, w8, #0x3ffc'),
        (0x184ebd394, 'add w21, w8, #0x24'),
        (0x184ebd398, 'bl #0x188076d50'),
        (0x184ebd3a4, 'stp w20, w0, [sp, #8]'),
        (0x184ebd3dc, 'bl #0x188088af0'),
        (0x184ebd428, 'cmp w8, #0xba5'),
        (0x184ebd480, 'cmp w9, #1'),
        (0x184ebd488, 'cmp w8, #0x28'),
        (0x184ebd490, 'ldr w8, [sp, #8]'),
        (0x184ebd498, 'ldrh w8, [sp, #0x26]'),
        (0x184ebd4a0, 'cmp w8, #0x110, lsl #12'),
        (0x184ebd4b0, 'str w8, [x19]'),
        (0x184ebd514, 'bl #0x184ebd530'),
        (0x184ebd520, 'csel w0, w8, wzr, eq'),
        (0x184ebd554, 'bl #0x188076d50'),
        (0x184ebd564, 'stp w19, w0, [sp, #8]'),
        (0x184ebd59c, 'bl #0x188088af0'),
        (0x184ebd5e8, 'cmp w8, #0xb56'),
        (0x184ebd670, 'str w8, [x20]'),
        (0x184ebdb60, 'b #0x18806c480'),
        (0x184f5e230, 'bl #0x188088af0'),
        (0x184f5e304, 'str w8, [x19]'),
        (0x184f60828, 'str w22, [sp, #0x18]'),
        (0x184f60898, 'bl #0x188088af0'),
        (0x184f60970, 'str w9, [x19]'),
        (0x180549a50, 'b #0x180548b4c'),
        (0x18054a084, 'bl #0x180548ac8'),
        (0x18054a090, 'cmp w0, w8'),
        (0x18054a0b8, 'b #0x18056d928'),
        (0x180548acc, 'svc #0x80'),
        (0x180548b4c, 'mov x16, #-0x1d'),
        (0x180548b50, 'svc #0x80'),
        (0x18056b400, 'bl #0x180548f00'),
        (0x18056b410, 'stp w19, w0, [sp, #8]'),
        (0x18056b448, 'bl #0x18055b918'),
        (0x18056b488, 'cmp w8, #0x131'),
        (0x18056b510, 'str w8, [x20]'),
        (0x18056d99c, 'bl #0x18055b918'),
        (0x18055b960, 'bl #0x180548c18'),
        (0x180548c1c, 'svc #0x80'),
    ):
        raw = cache.read(pc, 4)
        word, = CS.disasm(raw, pc)
        assert f'{word.mnemonic} {word.op_str}'.strip() == asm, hex(pc)
        instructions[hex(pc)] = {'bytes': raw.hex(), 'instruction': asm}

    literals = {}
    for pc, values in (
        (0x18057e3a8, (0x1513, 24)),
        (0x18057e5a0, (0, 205)),
        (0x1eb1ee3f8, (1, 0)),
        (0x184f98930, (0x1513, 24)),
        (0x184f98b60, (0, 2877)),
        (0x184f98b80, (0, 2881)),
        (0x184f98948, (0, 2802)),
        (0x184f98958, (0, 2804)),
        (0x184f989d8, (0x80001513, 56)),
        (0x184f98ab0, (0, 2857)),
    ):
        raw = cache.read(pc, 8)
        assert struct.unpack('<II', raw) == values
        literals[hex(pc)] = {'bytes': raw.hex(), 'words': values}
    task_self = clean_pointer(cache.pointer(0x1e01cbff0))
    assert task_self['chain_membership_verified']
    assert int(task_self['target'], 16) == kernel.exports['_mach_task_self_']['address']
    return {
        'uuids': {'cache': cache.uuid, 'IOKit': iokit.uuid, 'libsystem_kernel': kernel.uuid},
        'authenticated_bindings': bindings,
        'task_self_binding': task_self,
        'instructions': instructions,
        'literals': literals,
    }


def archived_discovery(trace):
    raw = trace.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == TRACE_SHA256
    lines = raw.decode().splitlines()
    payload = re.compile(r'^\[[^\]]+\]     ([0-9a-f]{4})  (.*?)  \|')

    def message(start):
        chunks = bytearray()
        for line in lines[start:]:
            chunk = payload.match(line)
            if chunk is None:
                break
            assert int(chunk[1], 16) == len(chunks)
            chunks.extend(bytes.fromhex(chunk[2]))
        bits, size, remote, local, voucher, msg_id = struct.unpack_from('<6I', chunks)
        assert size <= len(chunks)
        return (bits, size, remote, local, voucher, msg_id), bytes(chunks[:size])

    transactions = []
    for send_line, recv_line, trap_line, request, size, destination, output, x6 in (
        (1677, 1681, 1686, 205, 24, 0xc03, 0x1703, 48),
        (1687, 1692, 1697, 2877, 24, 0x1703, None, 52),
        (1699, 1709, 1714, 2881, 100, 0x1703, 0x1803, 48),
        (1715, 1720, 1725, 2802, 24, 0x1803, 0x1903, 48),
    ):
        send, send_raw = message(send_line)
        recv, recv_raw = message(recv_line)
        assert send == (0x1513, size, destination, 0x507, 0, request)
        recv_bits, recv_size = (0x1200, 44) if output is None else (0x80001200, 40)
        assert recv == (recv_bits, recv_size, 0, 0x507, 0, request + 100)
        if output is None:
            assert struct.unpack_from('<IQ', recv_raw, 32) == (0, 0x134647a)
        else:
            assert struct.unpack_from('<II', recv_raw, 24) == (1, output)
            assert struct.unpack_from('<H', recv_raw, 38) == (0x11,)
        if request == 2881:
            n, = struct.unpack_from('<I', send_raw, 32)
            assert n == 64 and size == 36 + ((n + 3) & ~3)
            assert b'IOProviderClass\0' in send_raw[36:]
            assert b'com_apple_driver_FairPlayIOKit\0' in send_raw[36:]
        trap = lines[trap_line - 1]
        args = trap.split('mach_msg2_trap(', 1)[1].split(')', 1)[0]
        _, options, x2, x3, x4, x5, recv_capacity, timeout = [
            int(field.strip(), 0) for field in args.split(',')
        ]
        assert 'pc=0x180547c20 ' in trap and trap.endswith(' = 0x0')
        assert (options, x2, x3, x4, x5, recv_capacity, timeout) == (
            0x200000003, size << 32 | 0x1513, 0x507 << 32 | destination,
            request << 32, 0x507 << 32, x6, 0,
        )
        transactions.append({
            'send_line': send_line, 'reply_line': recv_line, 'trap_line': trap_line,
            'guest_destination': hex(destination),
            'guest_output_send_name': None if output is None else hex(output),
            'send_hex': send_raw.hex(), 'reply_hex': recv_raw.hex(),
        })
    assert 'host_self_trap() = 0xc03' in lines[1676 - 1]
    assert '_kernelrpc_mach_port_deallocate_trap(515, 3075) = 0x0' in lines[1698 - 1]
    assert 'remote=0x1903 local=0x507 voucher=0x0 id=2862' in lines[1726 - 1]
    return {'trace_sha256': TRACE_SHA256, 'transactions': transactions}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('trace', type=Path)
    args = parser.parse_args()
    result = {
        'installed': installed_discovery(),
        'archived': archived_discovery(args.trace),
        'scope': 'Static installed framework and historical guest wire records. Native pairing unverified.',
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
