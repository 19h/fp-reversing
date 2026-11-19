#!/usr/bin/env python3
"""Audit the two installed lskdd call blocks and conditional IOKit envelopes."""

import json
import struct
from pathlib import Path

from audit_daemon_iokit_native_registry import command, daemon_slices, digest, sysctl
from audit_fairplay_additional_clients import registry, window
from audit_fairplay_live_slice_identity import CS_OPS_CDHASH, CS_OPS_PIDOFFSET, query_cs
from audit_live_fairplay_adid_ipc import ThinView, bindings, reference
from audit_live_fairplay_cf_receive import assert_instructions
from audit_live_iokit_mach_transport import CACHE_UUID, Cache, Dylib, dyld_uuid

UUID = '90195379-954d-3ca3-baac-327341f14211'
SHA = 'a8c3110a3e5f3f4d7d64295218e3a966644c84d2a8c375c7a7b042b6629780c6'
MODIFIER = '(div=0x21C3 ad=0 key=IA)'
CALLS = {
    18: (0x100584b8c, 0x100584cc8, 3096, 0x8d41, 'x28',
         ('ldr', 'w0, [x10]'), ('mov', 'x2, x20'), ('mov', 'x4, x21'),
         ('add', 'x5, sp, #0x90')),
    19: (0x100474cc4, 0x100474e38, 3088, 0x8caa, 'x22',
         ('ldr', 'w0, [x20]'), ('ldr', 'x2, [x8, #0x590]'), ('mov', 'x4, x19'),
         ('add', 'x5, x5, #0xaa0')),
}
CALLER_SITES = {
    18: (0x100584c9c, 0x100584cb8, 0x100584cc0, 0x100584cb0),
    19: (0x100474dcc, 0x100474db0, 0x100474e30, 0x100474e24),
}
FIXUPS = {
    0x100e38ff8: 'auth-rebase 0x100474CC4 (div=0xE28D ad=0 key=IA)',
    0x100e44f08: 'auth-rebase 0x100584B8C (div=0x29FC ad=0 key=IA)',
    0x100e738d0: 'auth-bind IOKit/_IOConnectCallStructMethod ' + MODIFIER,
    0x100e738d8: 'auth-bind CoreFoundation/_CFDataGetTypeID ' + MODIFIER,
    0x100e739c0: 'auth-bind libSystem/_vm_allocate ' + MODIFIER,
    0x100e739c8: 'auth-rebase 0x100345E24 ' + MODIFIER,
}
FRAMEWORK = (
    (0x184ebedc8, 'stp', 'x4, x5, [sp]'),
    (0x184ebedcc, 'mov', 'x2, #0'),
    (0x184ebedd0, 'mov', 'w3, #0'),
    (0x184ebeddc, 'mov', 'x6, #0'),
    (0x184ebede0, 'mov', 'x7, #0'),
    (0x184ebede4, 'bl', '#0x184ebdd74'),
    (0x184ebdd98, 'cmp', 'x5, #1, lsl #12'),
    (0x184ebddd4, 'ldr', 'x11, [x19]'),
    (0x184ebdddc, 'b.ne', '#0x184ebde28'),
    (0x184ebde28, 'cmp', 'x11, #1, lsl #12'),
    (0x184ebde2c, 'b.hi', '#0x184ebde3c'),
    (0x184ebde5c, 'bl', '#0x184ebde8c'),
    (0x184ebde78, 'str', 'x8, [x19]'),
    (0x184ebdf2c, 'str', 'w1, [sp, #0x30]'),
    (0x184ebdf54, 'lsl', 'w25, w3, #3'),
    (0x184ebdf6c, 'str', 'w24, [sp, #0x34]'),
    (0x184ebdfd0, 'add', 'w8, w22, #3'),
    (0x184ebdfd4, 'and', 'w8, w8, #0x3ffc'),
    (0x184ebdfec, 'add', 'x0, x26, #0x2c'),
    (0x184ebdff8, 'str', 'w22, [x26, #0x28]'),
    (0x184ebdffc, 'add', 'w22, w25, #0x54'),
    (0x184ebe01c, 'str', 'w8, [x28, #0x3c]'),
    (0x184ebe04c, 'bl', '#0x188076d50'),
    (0x184ebe050, 'mov', 'w8, #0x1513'),
    (0x184ebe05c, 'stp', 'w9, w0, [sp, #0x18]'),
    (0x184ebe084, 'mov', 'x4, #0xb3100000000'),
    (0x184ebe088, 'mov', 'w6, #0x10bc'),
    (0x184ebe090, 'bl', '#0x188088af0'),
    (0x184ebe0dc, 'cmp', 'w8, #0xb95'),
    (0x184ebe164, 'ldr', 'w20, [sp, #0x34]'),
    (0x184ebe180, 'add', 'w9, w20, #3'),
    (0x184ebe184, 'and', 'w10, w9, #0xfffffffc'),
    (0x184ebe19c, 'ldr', 'w11, [x9, #0x28]'),
    (0x184ebe1b8, 'lsl', 'w22, w11, #3'),
    (0x184ebe1bc, 'add', 'w10, w22, #0x34'),
    (0x184ebe1c0, 'cmp', 'w8, w10'),
    (0x184ebe1c4, 'b.ne', '#0x184ebe150'),
    (0x184ebe1f8, 'add', 'x1, x8, #0x28'),
    (0x184ebe200, 'bl', '#0x18806c550'),
    (0x184ebe204, 'str', 'w20, [x26]'),
)


def audit():
    assert command('sw_vers', '-buildVersion').strip() == b'26C5035r'
    assert sysctl('kern.uuid').lower() == UUID
    child, = [row for row in registry()['children'] if row['process'] == 'lskdd']
    pid = child['pid']
    executable = Path(command('ps', '-ww', '-p', str(pid), '-o', 'comm=').decode().strip())
    assert executable.name == 'lskdd'
    offset = query_cs(pid, CS_OPS_PIDOFFSET, 8)
    cdh = query_cs(pid, CS_OPS_CDHASH, 20)
    assert offset[:2] == cdh[:2] == (0, 0)
    assert struct.unpack('<Q', offset[2]) == (0x124000,)
    assert cdh[2].hex() == '889f3cbb6ca7cf137820822e65589b0ead73d4e0'
    thin, = [row[2] for row in daemon_slices(executable.read_bytes()) if row[1] == 0x80000002]
    assert digest(thin) == SHA
    image = ThinView(thin)
    fixups = bindings(executable, '-arch', 'arm64e')
    for slot, expected in FIXUPS.items():
        assert fixups[slot] == expected
    aliases = {slot: row for slot, row in fixups.items() if row.endswith(MODIFIER)}
    assert set(aliases) == set(FIXUPS) - {0x100e38ff8, 0x100e44f08}

    comparison = reference('live_kext_selector26_comparison')
    current = comparison['current']
    assert current['kernel_uuid'] == UUID
    cache = Cache()
    assert cache.uuid == CACHE_UUID == dyld_uuid()
    framework = Dylib(cache, '/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit')
    assert framework.uuid == '82be1de5-91c4-3152-b63b-81db4c5e7992'
    assert framework.exports['_IOConnectCallStructMethod']['address'] == 0x184ebedb0
    header = cache.read(0x184f98af8, 8)
    assert struct.unpack('<II', header) == (0, 2865)

    results = {}
    for selector, (start, pc, extent, bias, table_reg, *arguments) in CALLS.items():
        for site, pair in zip(CALLER_SITES[selector], arguments, strict=True):
            image.instruction(site, *pair)
        selector_site = 0x100584cb4 if selector == 18 else 0x100474e28
        image.instruction(selector_site, 'mov', f'w1, #{selector:#x}')
        image.instruction(pc - 0xc, 'mov', f'w3, #{extent:#x}')
        image.instruction(pc - 4, 'mov', 'x17, #0x21c3')
        image.instruction(pc, 'blraa', 'x8, x17')
        if selector == 19:
            image.instruction(0x100474e20, 'add', 'x5, sp, #0xa, lsl #12')
            image.instruction(0x100474dc0, 'str', 'x8, [x2]')
            image.instruction(0x100474dc4, 'mov', 'w8, #0xc00')
            image.instruction(0x100474dc8, 'str', 'w8, [x2, #8]')
        indexed_load = 0x100584cac if selector == 18 else 0x100474e1c
        image.instruction(indexed_load - 8, 'mov', f'w9, #{bias:#x}')
        image.instruction(indexed_load - 4, 'add', 'w8, w9, w8, uxtb')
        image.instruction(indexed_load, 'ldr', f'x8, [{table_reg}, w8, uxtw #3]')
        row = current['method_map']['methods'][str(selector)]
        assert row['count_in'] == row['count_out'] == extent
        assert row['flags'] == 3 and row['adjustment'] == 0
        assert extent % 4 == 0 and extent <= 4096
        results[selector] = dict(call_site=hex(pc), caller_words=window(image, start, pc + 4),
                                 method_record=row, candidate_bias=bias,
                                 output_capacity_verified=False,
                                 inline_request_bytes=84 + extent,
                                 inline_success_reply_bytes=52 + extent)
    assert offset == query_cs(pid, CS_OPS_PIDOFFSET, 8)
    assert cdh == query_cs(pid, CS_OPS_CDHASH, 20)
    assert child in registry()['children']
    return dict(build='26C5035r', live_slice_sha256=SHA, live_cdhash=cdh[2].hex(),
                kernel_uuid=UUID, kext_uuid=current['kext_uuid'], cache_uuid=cache.uuid,
                framework_uuid=framework.uuid, request_header_tail=header.hex(),
                framework_words=assert_instructions(cache.read, FRAMEWORK),
                lskdd_fixups={hex(slot): dict(binding=row, raw=image.read(slot, 8).hex())
                              for slot, row in FIXUPS.items()},
                methods=results, runtime_calls_observed=False,
                reaching_indirect_targets_established=False)


if __name__ == '__main__':
    print(json.dumps(audit(), indent=2))
