#!/usr/bin/env python3
"""Audit peer delivery, request and reply fields in the installed FPDI daemon."""

import argparse
import json
from pathlib import Path
import re

from audit_daemon_iokit_native_registry import command, daemon_slices, digest
from audit_fairplay_additional_clients import window
from audit_fairplay_live_slice_identity import selected_identity
from audit_live_fairplay_adid_ipc import ThinView, bindings, selection

UUID = '0a404c50-4901-312f-9e36-04565d30f305'
SHA256 = 'f73ababfd9265e1bdacde11467d5a3701cec634c49ce3a65f5769cf5ccd843f0'
POOL = 0x1005e7c40
TABLE = 0x1005c0a80
RANGES = {
    'listener_registration': (0x1000022d4, 0x100002354),
    'peer_installation': (0x1000025a8, 0x100002638),
    'peer_event_entry': (0x100002638, 0x10000272c),
    'token_zero_fill': (0x10020bc88, 0x10020bdec),
    'protected_entry': (0x1001f4de4, 0x1001f53fc),
    'null_first_allocation': (0x100096130, 0x10009616c),
    'nonnull_first_allocation': (0x100015bf4, 0x100015c28),
    'second_size_helper': (0x10001b0b8, 0x10001b18c),
    'first_initialization_on_nonnull': (0x100071970, 0x1000719cc),
    'request_data': (0x100096c9c, 0x100096d78),
    'reply_create': (0x1000987c4, 0x10009887c),
    'reply_data': (0x10002b7fc, 0x10002b8b4),
    'reply_status_and_send': (0x100063f94, 0x1000640ec),
}
CHECKS = {
    0x10020bc88: ('neg', 'w8, w0'),
    0x10020bc8c: ('and', 'x8, x8, #7'),
    0x10020bc94: ('csel', 'x8, x2, x8, lo'),
    0x10020bcd8: ('strb', 'w1, [x0], #1'),
    0x10020bcf4: ('sub', 'x8, x2, x8'),
    0x10020bd08: ('mul', 'x9, x9, x10'),
    0x10020bd60: ('str', 'x9, [x0], #8'),
    0x10020bd88: ('and', 'x8, x8, #7'),
    0x1000022e0: ('mov', 'w2, #1'),
    0x100002328: ('add', 'x16, x16, #0x5a8'),
    0x1000025c0: ('ldr', 'x1, [x0, #0x20]'),
    0x1000025fc: ('add', 'x16, x16, #0x638'),
    0x100002600: ('pacia', 'x16, x8'),
    0x100002610: ('str', 'x19, [sp, #0x28]'),
    0x100002668: ('b.eq', '#0x100002690'),
    0x100002680: ('b.eq', '#0x1000026cc'),
    0x10000269c: ('b.eq', '#0x1000026f4'),
    0x1000026cc: ('ldr', 'x0, [x19, #0x20]'),
    0x1000026d0: ('mov', 'x1, x20'),
    0x1000026f0: ('b', '#0x1001f4de4'),
    0x100002708: ('ldr', 'x0, [x19, #0x20]'),
    0x1001f4e08: ('str', 'x1, [sp, #0xc0]'),
    0x1001f4e0c: ('str', 'x0, [sp, #0x80]'),
    0x1001f4e84: ('adrp', 'x23, #0x1005e7000'),
    0x1001f4e88: ('add', 'x23, x23, #0xc40'),
    0x1001f5074: ('ldr', 'x8, [x23, w8, uxtw #3]'),
    0x1001f5080: ('add', 'x28, x8, x10'),
    0x1001f50f8: ('add', 'x0, sp, #0x2f8'),
    0x1001f50fc: ('mov', 'w1, #0'),
    0x1001f5100: ('mov', 'w2, #0x20'),
    0x1001f521c: ('add', 'x1, sp, #0x2f8'),
    0x1001f5220: ('ldr', 'x0, [sp, #0xc0]'),
    0x1001f5244: ('stp', 'x24, x21, [sp, #0x1a0]'),
    0x1001f5294: ('mov', 'x7, x28'),
    0x1001f5280: ('mov', 'w0, #0x80'),
    0x1001f52ac: ('cmp', 'x0, #0'),
    0x1001f5324: ('str', 'x10, [sp, #0x30]'),
    0x1001f533c: ('str', 'x10, [sp, #0x180]'),
    0x1001f5350: ('str', 'x10, [sp, #0x178]'),
    0x1001f5364: ('str', 'x10, [sp, #0x98]'),
    0x1001f5378: ('str', 'x10, [sp, #0x90]'),
    0x1001f53e8: ('stp', 'x7, x27, [sp, #0x1d8]'),
    0x1001f53f8: ('braa', 'x8, x17'),
    0x100015c24: ('braa', 'x10, x17'),
    0x10001b118: ('mov', 'w0, #0x70'),
    0x10001b154: ('cmp', 'x0, #0'),
    0x10001b188: ('braa', 'x8, x17'),
    0x1000719b4: ('stp', 'w8, w12, [x0]'),
    0x1000719c0: ('stp', 'w8, w8, [x0, #0x48]'),
    0x1000719c8: ('strh', 'w8, [x0, #0x50]'),
    0x100096d10: ('add', 'x2, sp, #0x3f8'),
    0x100096d14: ('ldr', 'x0, [sp, #0xc0]'),
    0x100096d40: ('cmp', 'x0, #0'),
    0x100098820: ('ldr', 'x0, [sp, #0xc0]'),
    0x100098848: ('str', 'x0, [sp, #0x478]'),
    0x10009884c: ('cmp', 'x0, #0'),
    0x10002b800: ('ldr', 'x2, [sp, #0x468]'),
    0x10002b81c: ('add', 'w3, w9, w8'),
    0x10002b858: ('ldr', 'x21, [sp, #0x478]'),
    0x10002b878: ('add', 'x1, x9, x10'),
    0x10002b87c: ('mov', 'x0, x21'),
    0x100063fb8: ('sxtw', 'x2, w8'),
    0x10002b8a8: ('ldr', 'x8, [x7, w20, sxtw #3]'),
    0x10002b8ac: ('mov', 'x17, #0xc36c'),
    0x10002b8b0: ('braa', 'x8, x17'),
    0x100064044: ('mov', 'x0, x21'),
    0x1000640a4: ('ldr', 'x0, [sp, #0x80]'),
    0x1000640a8: ('mov', 'x1, x21'),
}
STUB_CALLS = {
    0x1000022e4: (0x10054bcc4, '_xpc_connection_create_mach_service'),
    0x100002348: (0x10054bce4, '_xpc_connection_set_event_handler'),
    0x100002350: (0x10054bca4, '_xpc_connection_activate'),
    0x1000025c8: (0x10054bcf4, '_xpc_connection_set_target_queue'),
    0x10000261c: (0x10054bce4, '_xpc_connection_set_event_handler'),
    0x100002624: (0x10054bcd4, '_xpc_connection_resume'),
    0x100002658: (0x10054bd44, '_xpc_get_type'),
    0x100002670: (0x10054bd44, '_xpc_get_type'),
    0x1000026b0: (0x10054bd14, '_xpc_dictionary_get_string'),
    0x100002728: (0x10054bcb4, '_xpc_connection_cancel'),
}
# Source pool offsets and negative adjustments assembled with MOV/MOVK.
REBASED = {
    'zero_left': (0xc48, -0x37e16e8b, 0x10057a0e0),
    'zero_right': (0x1288, -0x37a99043, 0x1005a5d90),
    'table_left': (0xcb8, -0x1f8b99df, 0x1005b1940),
    'table_right': (0x1f0, -0x498592e6, 0x1005bbf30),
    'audit_left': (0x1118, -0x2c314b13, 0x1005b1a40),
    'audit_right': (0x40, -0x1519c73e, 0x1005bc030),
    'key_left': (0x14f8, -0x66efef57, 0x1005b1b40),
    'key_right': (0x3b8, -0x5d4cb0ff, 0x1005bc230),
    'read_left': (0x12a8, -0xc23537f, 0x10057a1e0),
    'read_right': (0xbb8, -0x7bbd7fff, 0x1005a5e90),
    'reply_left': (0x490, -0x378296d2, 0x1005bc130),
    'reply_right': (0x10f8, -0x57b787d7, 0x10057a2e0),
}


def negative_adjust(low, high):
    return (high << 16 | low & 0xffff) - (1 << 32)


def inspect(path):
    _, _, thin = next(row for row in daemon_slices(path.read_bytes()) if row[1] == 0x80000002)
    identity = selected_identity(thin)
    assert identity['uuid'] == UUID and digest(thin) == SHA256
    image = ThinView(thin)
    fixups = bindings(path, '-arch', 'arm64e')
    for pc, operands in CHECKS.items():
        image.instruction(pc, *operands)
    symbols = command('otool', '-arch', 'arm64e', '-Iv', str(path)).decode()
    for pc, (stub, symbol) in STUB_CALLS.items():
        image.instruction(pc, 'b' if pc == 0x100002728 else 'bl', f'#{stub:#x}')
        assert re.search(rf'^0x0*{stub:x}\s+\d+\s+{symbol}$', symbols, re.M)
    objects = {
        0x1005e9fa8: '__xpc_error_connection_invalid',
        0x1005e9fb0: '__xpc_error_key_description',
        0x1005e9fb8: '__xpc_type_dictionary',
        0x1005e9fc0: '__xpc_type_error',
    }
    for slot, symbol in objects.items():
        assert fixups[slot] == 'bind libSystem/' + symbol

    rebase_rows = {}
    for label, (offset, adjust, expected) in REBASED.items():
        slot = POOL + offset
        kind, target = fixups[slot].split()
        assert kind == 'rebase' and int(target, 16) + adjust == expected, label
        rebase_rows[label] = dict(slot=hex(slot), target=target, adjustment=adjust,
                                  bank=hex(expected), raw=image.read(slot, 8).hex())

    def banks(stem):
        return (REBASED[stem + '_left'][2], REBASED[stem + '_right'][2])

    def selected(stem, key, addend, base, target, adjust=0):
        return selection(image, fixups, banks(stem), key, addend, base, target, adjust)

    pool_selection = {
        'table': selected('table', 0xb8, 0x16d, POOL, TABLE,
                          negative_adjust(-0x502b, 0xdde1)),
        'data_key': selected('key', 0x9d, 0xfb, POOL, 0x1005795a6,
                             negative_adjust(-0x179e, 0x996e)),
        'status_key': selected('table', 0xb8, 0x262, POOL, 0x1005a8528,
                               negative_adjust(-0x4646, 0xc7bf)),
    }
    assert image.read(0x1005795a6, 5) == b'data\0'
    assert image.read(0x1005a8528, 7) == b'status\0'

    calls = {}
    for pc, stem, key, addend, target, modifier, register in (
        (0x1001f5108, 'zero', 0x6d, 0x4cf7, 0x10020bc88, 0x7c87, 'x8'),
        (0x1001f51bc, 'table', 0xb8, 0x4dc2, 0x1001fb0ac, 0x854f, 'x8'),
        (0x1001f5228, 'audit', 0x2e, 0x4cde, 'libSystem/_xpc_dictionary_get_audit_token', 0x730c, 'x8'),
        (0x1001f5288, 'audit', 0x2d, 0x4c31, 0x10020b5f0, 0xd2ea, 'x8'),
        (0x10001b120, 'zero', 0x6d, 0x4cbc, 0x10020b5f0, 0xd2ea, 'x8'),
        (0x100096d1c, 'read', 0x56, 0x4cd2, 'libSystem/_xpc_dictionary_get_data', 0xc646, 'x8'),
        (0x100098828, 'audit', 0x2d, 0x4c72, 'libSystem/_xpc_dictionary_create_reply', 0xb403, 'x8'),
        (0x10002b884, 'reply', 0xda, 0x4d05, 'libSystem/_xpc_dictionary_set_data', 0xeb7f, 'x8'),
        (0x100064054, 'read', 0xdb, 0x4dd1, 'libSystem/_xpc_dictionary_set_int64', 0x2eec, 'x10'),
        (0x1000640b0, 'read', 0xdb, 0x4def, 'libSystem/_xpc_connection_send_message', 0x9de4, 'x8'),
    ):
        record = selected(stem, key, addend, TABLE, target)
        assert record['binding'].endswith(f'(div=0x{modifier:04X} ad=0 key=IA)')
        image.instruction(pc - 4, 'mov', f'x17, #{modifier:#x}')
        image.instruction(pc, 'blraa', f'{register}, x17')
        calls[hex(pc)] = record
    routes = {}
    second_success = ((0x895bcad4 + 0x76a43b1a - 0x101) & 0xffffffff) ^ 0x34d8
    w19 = (0x895bcad4 + 0x76a43b1a - 0x5be) & 0xffffffff
    w20 = (0x895bccd4 + 0x76a43b1a + 0xd1e) & 0xffffffff
    assert (w19, w20) == (0x30, 0x150c)
    second_null = (((1 ^ w19) & 1) ^ 1) * 42 ^ w20
    second_nonnull = (((0 ^ w19) & 1) ^ 1) * 42 ^ w20
    def select_index(slot):
        return (slot - TABLE) // 8
    for label, index, target, div in (
        ('null', 0x801, 0x100096130, 0xc8a7),
        ('nonnull', 0x801 ^ 7, 0x100015bf4, 0xc8a7),
        ('nonnull_next', second_success, 0x10001b0b8, 0xc0a0),
        ('null_next', 0xef4, 0x1000962e8, 0xa7a7),
        ('second_null', second_null, 0x1000968d0, 0x4011),
        ('second_nonnull', second_nonnull, 0x100071970, 0x4011),
        ('reader_entry', select_index(0x1005ca6a8), 0x100096c9c, 0xe0e6),
        ('reply_create_entry', select_index(0x1005df398), 0x1000987c4, 0xeefe),
        ('reply_data_entry', select_index(0x1005cd218), 0x10002b7fc, 0xed8a),
        ('reply_status_entry', select_index(0x1005d3198), 0x100063f94, 0xc36c),
    ):
        slot = TABLE + index * 8
        row = fixups[slot]
        assert row == f'auth-rebase 0x{target:X} (div=0x{div:04X} ad=0 key=IA)'
        routes[label] = dict(index=hex(index), slot=hex(slot), fixup=row)
    return dict(identity=identity, pool_selection=pool_selection, table_routes=routes,
                rebases=rebase_rows, exact_instruction_checks=len(CHECKS),
                object_bindings={hex(slot): fixups[slot] for slot in objects},
                stub_calls={hex(pc): [hex(stub), symbol] for pc, (stub, symbol) in STUB_CALLS.items()},
                authenticated_calls=calls, windows={
                    label: window(image, *span) for label, span in RANGES.items()})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('installed_daemon', type=Path)
    print(json.dumps(inspect(parser.parse_args().installed_daemon), indent=2, sort_keys=True))
