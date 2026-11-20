#!/usr/bin/env python3
"""Corroborate the installed FPDI DeviceIdentity completion and output ABI."""

import argparse
import json
from pathlib import Path
from struct import iter_unpack, unpack_from

from audit_live_fpdi_selector26_route import TABLE
from audit_live_fpdi_startup import (
    CALLS as STARTUP_CALLS, SHA256, UUID, ThinView, bindings, commands, daemon_slices,
    digest, selected_identity, window,
)

CALLS = {
    pc: STARTUP_CALLS[pc] for pc in (0x10000117c, 0x1000013dc, 0x1000013e8)
}
CALLS.update({
    0x1000011a4: (0x10054bb34, 0x1005e9e00, 'libSystem/_dispatch_queue_create'),
    0x10000130c: (0x10054bb44, 0x1005e9e08, 'libSystem/_dispatch_semaphore_create'),
    0x1000017ec: (0x10054bb54, 0x1005e9e10, 'libSystem/_dispatch_semaphore_signal'),
})
for pcs, binding in (
    ((0x100001420, 0x100001564, 0x100001570, 0x1000017e4),
     (0x10054b9f4, 0x1005e9d58, 'CoreFoundation/_CFRelease')),
    ((0x100001440, 0x1000014dc), (0x10054ba34, 0x1005e9d10, 'Security/_SecCertificateCopyData')),
    ((0x100001454, 0x1000014f0), (0x10054b994, 0x1005e9d28, 'CoreFoundation/_CFDataGetLength')),
    ((0x100001474, 0x100001510), (0x10054bbc4, 0x1005e9e48, 'libSystem/_malloc_type_malloc')),
    ((0x100001490, 0x10000152c), (0x10054b984, 0x1005e9d20, 'CoreFoundation/_CFDataGetBytes')),
    ((0x1000013c4, 0x100001684, 0x100001690, 0x100001834),
     (0x10054bc04, 0x1005e9d80, 'libobjc/_objc_retain')),
    ((0x1000017bc, 0x1000017f4, 0x1000017fc), (0x10054bbf4, 0x1005e9d78, 'libobjc/_objc_release')),
    ((0x100001714, 0x10000178c), (0x10054bab4, 0x1005e9dc8, 'libSystem/__os_log_impl')),
    ((0x10000158c, 0x1000015a0, 0x1000015ac, 0x10000189c, 0x1000018a8, 0x1000018b4),
     (0x10054ba54, 0x1005e9d98, 'libSystem/__Block_object_dispose')),
    ((0x100001844, 0x100001854), (0x10054ba44, 0x1005e9d90, 'libSystem/__Block_object_assign')),
):
    CALLS.update(dict.fromkeys(pcs, binding))

SELECTORS = (
    ((0x100001244,), 0x10054be60, 0x40, 0x1005bf397, 'numberWithUnsignedChar:'),
    ((0x10000169c,), 0x10054bdc0, 0x18, 0x1005bf343, 'count'),
    ((0x1000016d4, 0x10000174c), 0x10054be00, 0x28, 0x1005bf35f, 'description'),
    ((0x1000017a4,), 0x10054bda0, 0x10, 0x1005bf33e, 'copy'),
    ((0x100001434, 0x1000014d0), 0x10054be80, 0x48, 0x1005bf3af, 'objectAtIndexedSubscript:'),
)
CHECKS = (
    (0x100000e7c, 'cbz', 'w0, #0x100000ee0'),
    (0x100000e80, 'cmp', 'w19, #1'),
    (0x100000e84, 'b.ne', '#0x100000ea4'),
    (0x100001154, 'mov', 'x20, x5'),
    (0x100001158, 'mov', 'x21, x4'),
    (0x10000115c, 'mov', 'x23, x3'),
    (0x100001160, 'mov', 'x24, x2'),
    (0x100001164, 'mov', 'x26, x1'),
    (0x100001168, 'mov', 'x22, x0'),
    (0x100001180, 'cbz', 'w0, #0x10000140c'),
    (0x1000011b4, 'cbz', 'x19, #0x100001414'),
    (0x10000122c, 'ldr', 'x8, [x8, #0xf40]'),
    (0x100001234, 'stp', 'x9, x8, [sp, #0x100]'),
    (0x100001240, 'mov', 'x2, x22'),
    (0x100001254, 'stur', 'x0, [x22, #0x28]'),
    (0x100001308, 'mov', 'x0, #0'),
    (0x100001328, 'str', 'w9, [sp, #0xb8]'),
    (0x100001338, 'str', 'xzr, [sp, #0x98]'),
    (0x100001374, 'stp', 'x16, xzr, [sp, #0x70]'),
    (0x1000013a4, 'adrp', 'x16, #0x100001000'),
    (0x1000013a8, 'add', 'x16, x16, #0x658'),
    (0x1000013ac, 'pacia', 'x16, x11'),
    (0x1000013b0, 'adrp', 'x11, #0x1005c0000'),
    (0x1000013b4, 'add', 'x11, x11, #0x40'),
    (0x1000013b8, 'stp', 'x16, x11, [sp, #0x20]'),
    (0x1000013bc, 'stp', 'x8, x10, [sp, #0x38]'),
    (0x1000013c0, 'str', 'x9, [sp, #0x48]'),
    (0x1000013cc, 'str', 'x0, [sp, #0x30]'),
    (0x1000013d0, 'add', 'x2, sp, #0x10'),
    (0x1000013d4, 'mov', 'x0, x19'),
    (0x1000013d8, 'ldr', 'x1, [sp, #8]'),
    (0x1000013e4, 'mov', 'x1, #-1'),
    (0x1000013f4, 'cbz', 'x8, #0x100001574'),
    (0x100001400, 'cbz', 'x26, #0x10000141c'),
    (0x100001404, 'str', 'x0, [x26]'),
    (0x10000140c, 'mov', 'w20, #4'),
    (0x100001414, 'mov', 'w20, #3'),
    (0x100001424, 'cbz', 'x24, #0x100001498'),
    (0x100001430, 'mov', 'x2, #0'),
    (0x10000145c, 'mov', 'w22, w27'),
    (0x10000147c, 'cbz', 'x0, #0x1000014a8'),
    (0x100001488, 'mov', 'x2, x22'),
    (0x10000149c, 'mov', 'w27, #0'),
    (0x1000014ac, 'mov', 'w9, #3'),
    (0x1000014b0, 'str', 'w9, [x8, #0x18]'),
    (0x1000014b4, 'str', 'x28, [x24]'),
    (0x1000014bc, 'str', 'w27, [x23]'),
    (0x1000014c0, 'cbz', 'x21, #0x100001534'),
    (0x1000014cc, 'mov', 'w2, #1'),
    (0x1000014f8, 'mov', 'w22, w24'),
    (0x100001518, 'cbz', 'x0, #0x100001544'),
    (0x100001524, 'mov', 'x2, x22'),
    (0x100001538, 'mov', 'w24, #0'),
    (0x100001548, 'mov', 'w9, #3'),
    (0x10000154c, 'str', 'w9, [x8, #0x18]'),
    (0x100001550, 'str', 'x27, [x21]'),
    (0x100001558, 'str', 'w24, [x20]'),
    (0x100001578, 'ldr', 'w20, [x8, #0x18]'),
    (0x1000015e0, 'mov', 'x0, x20'),
    (0x100001644, 'str', 'x8, [x0, #0x28]'),
    (0x100001648, 'str', 'xzr, [x1, #0x28]'),
    (0x100001674, 'mov', 'x22, x3'),
    (0x100001678, 'mov', 'x21, x1'),
    (0x10000167c, 'mov', 'x20, x0'),
    (0x100001680, 'mov', 'x0, x2'),
    (0x1000016a0, 'cmp', 'x0, #2'),
    (0x1000016a4, 'b.ne', '#0x100001724'),
    (0x1000016b0, 'cbz', 'x22, #0x10000179c'),
    (0x1000016b4, 'mov', 'w9, #1'),
    (0x1000016b8, 'str', 'w9, [x8, #0x18]'),
    (0x10000172c, 'mov', 'w9, #2'),
    (0x100001730, 'str', 'w9, [x8, #0x18]'),
    (0x100001744, 'cbz', 'w0, #0x1000017cc'),
    (0x100001798, 'b', '#0x1000017cc'),
    (0x10000179c, 'str', 'wzr, [x8, #0x18]'),
    (0x1000017a8, 'ldr', 'x8, [x20, #0x30]'),
    (0x1000017b4, 'str', 'x0, [x9, #0x28]'),
    (0x1000017c0, 'ldr', 'x8, [x20, #0x38]'),
    (0x1000017c8, 'str', 'x21, [x8, #0x18]'),
    (0x1000017cc, 'cbz', 'x21, #0x1000017e8'),
    (0x1000017dc, 'cbnz', 'x8, #0x1000017e8'),
    (0x1000017e8, 'ldr', 'x0, [x20, #0x20]'),
    (0x10000187c, 'b', '#0x10054ba44'),
    (0x1000018d4, 'b', '#0x10054bbf4'),
)
WINDOWS = {
    'prefetch_caller': (0x100000e44, 0x100000f4c),
    'bridge': (0x100001130, 0x100001658),
    'completion': (0x100001658, 0x100001818),
    'completion_capture_helpers': (0x100001818, 0x1000018d8),
}
STRINGS = {
    0x1005be9ce: 'v32@?0^{__SecKey=}8@"NSArray"16@"NSError"24',
    0x1005bec3c: 'Failed to obtain BAA certificates: %@',
    0x1005bec62: 'BAA Certificate(s) are expired: %@',
}
ADDITIONAL_FIXUPS = {
    0x1005c0050: 'auth-rebase 0x100001818 (div=0x0000 ad=1 key=IA)',
    0x1005c0058: 'auth-rebase 0x100001880 (div=0x0000 ad=1 key=IA)',
    0x1005c0060: 'rebase 0x1005BE9CE',
    TABLE + 8 * 0x4e04: 'auth-rebase 0x100001130 (div=0xF447 ad=0 key=IA)',
    0x1005e9f40: 'bind DeviceIdentity/_kMAOptionsBAASkipNetworkRequest',
    0x1005e9f90: 'bind libSystem/__NSConcreteStackBlock',
}


def check_auth_stub(image, fixups, stub, slot, name):
    image.instruction(stub, 'adrp', f'x17, #{slot & ~0xfff:#x}')
    image.instruction(stub + 4, 'add', f'x17, x17, #{slot & 0xfff:#x}')
    image.instruction(stub + 8, 'ldr', 'x16, [x17]')
    image.instruction(stub + 12, 'braa', 'x16, x17')
    bound = fixups[slot]
    assert bound == f'auth-bind {name} (div=0x0000 ad=1 key=IA)'
    return {'stub': hex(stub), 'bind_slot': hex(slot), 'binding': bound,
            'word': image.read(slot, 8).hex()}


def text_branches_to(thin, target):
    for offset, kind, _ in commands(thin, 0):
        if kind != 0x19:
            continue
        count, = unpack_from('<I', thin, offset + 64)
        for section in range(offset + 72, offset + 72 + 80 * count, 80):
            if thin[section:section + 32] != b'__text'.ljust(16, b'\0') + b'__TEXT'.ljust(16, b'\0'):
                continue
            base, size, start = unpack_from('<QQI', thin, section + 32)
            for index, (word,) in enumerate(iter_unpack('<I', memoryview(thin)[start:start + size])):
                if word & 0x7c000000 != 0x14000000:
                    continue
                pc = base + index * 4
                displacement = ((word & 0x1ffffff) - (word & 0x2000000)) * 4
                if pc + displacement == target:
                    yield pc


def inspect(daemon):
    _, _, thin = next(row for row in daemon_slices(daemon.read_bytes()) if row[1] == 0x80000002)
    assert selected_identity(thin)['uuid'] == UUID and digest(thin) == SHA256
    image, fixups = ThinView(thin), bindings(daemon, '-arch', 'arm64e')
    for pc, mnemonic, operands in CHECKS:
        image.instruction(pc, mnemonic, operands)
    calls = {}
    for pc, (stub, slot, name) in CALLS.items():
        image.instruction(pc, 'bl', f'#{stub:#x}')
        calls[hex(pc)] = check_auth_stub(image, fixups, stub, slot, name)
    selectors = {}
    for pcs, stub, offset, address, name in SELECTORS:
        for pc in pcs:
            image.instruction(pc, 'bl', f'#{stub:#x}')
        slot = 0x1005ec000 + offset
        image.instruction(stub, 'adrp', 'x1, #0x1005ec000')
        image.instruction(stub + 4, 'ldr', f'x1, [x1, #{offset:#x}]')
        assert fixups[slot] == f'rebase 0x{address:X}'
        assert image.read(address, len(name) + 1) == name.encode('ascii') + b'\0'
        selectors[name] = {
            'calls': [hex(pc) for pc in pcs], 'stub': hex(stub), 'selector_slot': hex(slot),
            'selector_address': hex(address),
            'dispatch': check_auth_stub(image, fixups, stub + 8, 0x1005e9d70, 'libobjc/_objc_msgSend'),
        }
    for address, value in STRINGS.items():
        assert image.read(address, len(value) + 1) == value.encode('ascii') + b'\0'
    for slot, binding in ADDITIONAL_FIXUPS.items():
        assert fixups[slot] == binding
    assert unpack_from('<QQ', image.read(0x1005c0040, 16)) == (0, 64)
    callers = list(text_branches_to(thin, 0x100001130))
    assert callers == [0x100000e74, 0x100000ec8]
    for pc, mode in zip(callers, (1, 0)):
        image.instruction(pc - 24, 'mov', f'w0, #{mode}')
        for arg in range(1, 6):
            image.instruction(pc - 24 + arg * 4, 'mov', f'x{arg}, #0')
    windows = {name: window(image, low, high) for name, (low, high) in WINDOWS.items()}
    return {
        'uuid': UUID, 'sha256': SHA256, 'anchor_checks': len(CHECKS), 'calls': calls,
        'selectors': selectors, 'direct_text_callers': [hex(pc) for pc in callers],
        'additional_fixups': {
            hex(slot): {'binding': binding, 'word': image.read(slot, 8).hex()}
            for slot, binding in ADDITIONAL_FIXUPS.items()
        },
        'strings': {hex(address): value for address, value in STRINGS.items()},
        'instruction_count': sum(map(len, windows.values())), 'windows': windows,
        'native_completion_observed': False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('daemon', type=Path)
    args = parser.parse_args()
    print(json.dumps(inspect(args.daemon), indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
