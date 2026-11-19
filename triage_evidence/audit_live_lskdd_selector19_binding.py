#!/usr/bin/env python3
"""Verify lskdd's frame-relative selector bindings from the installed image."""

import argparse
import json
from pathlib import Path

from audit_daemon_iokit_native_registry import daemon_slices
from audit_fairplay_additional_clients import window
from audit_fairplay_live_slice_identity import selected_identity
from audit_live_fairplay_adid_ipc import ThinView, bindings, selection
from audit_live_lskdd_method_abi import FIXUPS, SHA

POOL = 0x100e73f20
TABLE = 0x100e2ce30
BANKS = (0x100e07090, 0x100cb47e0)
EXTRA_FIXUPS = {
    0x100e74818: 'rebase 0x100E0709C',
    0x100e75f90: 'rebase 0x100CB47E0',
    0x100e74c50: 'rebase 0x100E2CE34',
    0x100e73758: 'auth-rebase 0x100316938 (div=0x0199 ad=0 key=IA)',
    0x100e73878: 'auth-bind CoreFoundation/_CFFileDescriptorCreate (div=0x417D ad=0 key=IA)',
}
WINDOWS = {
    'large_frame_reservation': (0x1005b38b8, 0x1005b38c0),
    'large_frame_pool': (0x1005b3958, 0x1005b3960),
    'large_frame_call_banks': (0x1005b39fc, 0x1005b3a18),
    'large_frame_root_banks': (0x1005b3aa4, 0x1005b3ab8),
    'large_frame_root_equation_and_store': (0x1005b3b38, 0x1005b3c10),
    'large_frame_left_word_store': (0x1005b3c60, 0x1005b3c64),
    'large_frame_right_word_and_banks': (0x1005b3e98, 0x1005b3ec4),
    'selector19_predecessor': (0x100b5c91c, 0x100b5c950),
    'selector19_calls': (0x100474d34, 0x100474e6c),
    'return_only_target': (0x100316938, 0x100316940),
    'selector19_buffers_and_capacity': (0x100a35bfc, 0x100a35ca0),
    'small_frame_pool': (0x1005affc4, 0x1005affcc),
    'small_frame_capacity_and_root': (0x1005b00c0, 0x1005b0140),
    'selector18_call': (0x100584c7c, 0x100584ccc),
}
SITES = (
    (0x1005b38b8, 'sub', 'sp, sp, #0x1c, lsl #12'),
    (0x1005b38bc, 'sub', 'sp, sp, #0x9c0'),
    (0x1005b3958, 'adrp', 'x20, #0x100e73000'),
    (0x1005b395c, 'add', 'x20, x20, #0xf20'),
    (0x1005b39fc, 'ldr', 'x10, [x20, #0x8f8]'),
    (0x1005b3a0c, 'sub', 'x25, x10, #0xc'),
    (0x1005b3a14, 'ldr', 'x28, [x20, #0x2070]'),
    (0x1005b3aa4, 'adrp', 'x11, #0x100d3f000'),
    (0x1005b3aa8, 'add', 'x11, x11, #0x820'),
    (0x1005b3ab0, 'adrp', 'x12, #0x100d06000'),
    (0x1005b3ab4, 'add', 'x12, x12, #0x570'),
    (0x1005b3b38, 'add', 'x9, x12, w8, uxtb'),
    (0x1005b3b3c, 'ldrb', 'w9, [x9]'),
    (0x1005b3b40, 'mov', 'w10, #0x50'),
    (0x1005b3b44, 'eor', 'w9, w9, w10'),
    (0x1005b3b48, 'ldrb', 'w9, [x11, w9, uxtw]'),
    (0x1005b3b4c, 'eor', 'w8, w8, w9'),
    (0x1005b3bfc, 'and', 'w8, w8, #0xff'),
    (0x1005b3c00, 'add', 'w8, w8, #0x129'),
    (0x1005b3c04, 'ldr', 'x8, [x20, w8, uxtw #3]'),
    (0x1005b3c08, 'sub', 'x10, x8, #4'),
    (0x1005b3c0c, 'str', 'x10, [sp, #0x5ff8]'),
    (0x1005b3c60, 'str', 'x22, [sp, #0x5fe0]'),
    (0x1005b3e98, 'str', 'x24, [sp, #0x5fe8]'),
    (0x1005b3eac, 'str', 'x25, [sp, #0x5bb8]'),
    (0x1005b3ec0, 'str', 'x28, [sp, #0x5bb0]'),
    (0x100b5c91c, 'add', 'x8, sp, #1, lsl #12'),
    (0x100b5c920, 'add', 'x8, x8, #0xb98'),
    (0x100b5c924, 'ldr', 'w8, [x8, #0x3ffc]'),
    (0x100b5c930, 'mov', 'w10, #-0x2d6e'),
    (0x100b5c934, 'add', 'w8, w8, w10'),
    (0x100b5c938, 'ldr', 'x10, [sp, #0x5ff8]'),
    (0x100b5c93c, 'ldr', 'x8, [x10, w8, sxtw #3]'),
    (0x100b5c948, 'mov', 'x17, #0xe28d'),
    (0x100b5c94c, 'braa', 'x8, x17'),
    (0x100474d34, 'ldr', 'x25, [sp, #0x5fe0]'),
    (0x100474d3c, 'ldr', 'x26, [sp, #0x5fe8]'),
    (0x100474d68, 'ldr', 'x27, [sp, #0x5bb8]'),
    (0x100474d6c, 'add', 'x11, x27, w10, uxtb'),
    (0x100474d70, 'ldrb', 'w11, [x11]'),
    (0x100474d74, 'mov', 'w19, #0xcf'),
    (0x100474d78, 'eor', 'w11, w11, w19'),
    (0x100474d7c, 'ldr', 'x28, [sp, #0x5bb0]'),
    (0x100474d80, 'ldrb', 'w11, [x28, w11, uxtw]'),
    (0x100474d88, 'eor', 'w8, w10, w11'),
    (0x100474d8c, 'mov', 'w9, #0x8c7b'),
    (0x100474d90, 'add', 'w8, w9, w8, uxtb'),
    (0x100474d94, 'ldr', 'x22, [sp, #0x5ff8]'),
    (0x100474d98, 'ldr', 'x8, [x22, w8, uxtw #3]'),
    (0x100474da0, 'mov', 'x17, #0x199'),
    (0x100474da4, 'blraa', 'x8, x17'),
    (0x100316938, 'ret', ''),
    (0x100474da8, 'add', 'x8, sp, #9, lsl #12'),
    (0x100474dac, 'add', 'x8, x8, #0x558'),
    (0x100474db0, 'ldr', 'x2, [x8, #0x590]'),
    (0x100474dcc, 'ldr', 'w0, [x20]'),
    (0x100474df4, 'add', 'x9, x27, w8, uxtb'),
    (0x100474df8, 'ldrb', 'w9, [x9]'),
    (0x100474dfc, 'eor', 'w9, w9, w19'),
    (0x100474e00, 'ldrb', 'w9, [x28, w9, uxtw]'),
    (0x100474e04, 'add', 'x10, sp, #8, lsl #12'),
    (0x100474e08, 'add', 'x10, x10, #0x450'),
    (0x100474e0c, 'ldr', 'x19, [x10, #0x5a8]'),
    (0x100474e10, 'eor', 'w8, w8, w9'),
    (0x100474e14, 'mov', 'w9, #0x8caa'),
    (0x100474e18, 'add', 'w8, w9, w8, uxtb'),
    (0x100474e1c, 'ldr', 'x8, [x22, w8, uxtw #3]'),
    (0x100474e20, 'add', 'x5, sp, #0xa, lsl #12'),
    (0x100474e24, 'add', 'x5, x5, #0xaa0'),
    (0x100474e28, 'mov', 'w1, #0x13'),
    (0x100474e2c, 'mov', 'w3, #0xc10'),
    (0x100474e30, 'mov', 'x4, x19'),
    (0x100474e34, 'mov', 'x17, #0x21c3'),
    (0x100474e38, 'blraa', 'x8, x17'),
    (0x100474e3c, 'cmp', 'w0, #0'),
    (0x100a35bfc, 'add', 'x11, sp, #0xc, lsl #12'),
    (0x100a35c00, 'add', 'x11, x11, #0xda8'),
    (0x100a35c04, 'ldr', 'x9, [x11, #0xa50]'),
    (0x100a35c08, 'add', 'x10, sp, #0x10, lsl #12'),
    (0x100a35c0c, 'add', 'x10, x10, #0xdb0'),
    (0x100a35c10, 'add', 'x19, x10, x9'),
    (0x100a35c14, 'add', 'x10, sp, #9, lsl #12'),
    (0x100a35c18, 'add', 'x10, x10, #0x558'),
    (0x100a35c1c, 'str', 'x19, [x10, #0x590]'),
    (0x100a35c20, 'add', 'x10, x19, #0xc10'),
    (0x100a35c24, 'add', 'x12, sp, #8, lsl #12'),
    (0x100a35c28, 'add', 'x12, x12, #0x450'),
    (0x100a35c2c, 'str', 'x10, [x12, #0x5a8]'),
    (0x100a35c30, 'mov', 'w10, #0x1820'),
    (0x100a35c34, 'add', 'x9, x9, x10'),
    (0x100a35c38, 'str', 'x9, [x11, #0xa50]'),
    (0x100a35c3c, 'mov', 'w9, #0xc10'),
    (0x100a35c40, 'add', 'x10, sp, #0xa, lsl #12'),
    (0x100a35c44, 'add', 'x10, x10, #0x688'),
    (0x100a35c48, 'str', 'x9, [x10, #0x418]'),
    (0x100a35c64, 'ldr', 'x9, [sp, #0x5ff8]'),
    (0x1005affc4, 'adrp', 'x0, #0x100e73000'),
    (0x1005affc8, 'add', 'x0, x0, #0xf20'),
    (0x1005b00c0, 'add', 'x13, sp, #0xa0'),
    (0x1005b00c8, 'add', 'x20, x13, #0x10'),
    (0x1005b00cc, 'add', 'x21, x13, #0xc28'),
    (0x1005b00d0, 'mov', 'w13, #0xc18'),
    (0x1005b00d4, 'str', 'x13, [sp, #0x90]'),
    (0x1005b00ec, 'adrp', 'x13, #0x100e07000'),
    (0x1005b00f0, 'add', 'x13, x13, #0x90'),
    (0x1005b00f4, 'add', 'x13, x13, w10, uxtb'),
    (0x1005b00f8, 'ldrb', 'w13, [x13]'),
    (0x1005b00fc, 'mov', 'w14, #0x74'),
    (0x1005b0100, 'eor', 'w13, w13, w14'),
    (0x1005b0104, 'adrp', 'x14, #0x100cb4000'),
    (0x1005b0108, 'add', 'x14, x14, #0x7e0'),
    (0x1005b010c, 'ldrb', 'w13, [x14, w13, uxtw]'),
    (0x1005b0110, 'eor', 'w10, w10, w13'),
    (0x1005b0114, 'and', 'w10, w10, #0xff'),
    (0x1005b0118, 'add', 'w10, w10, #0x184'),
    (0x1005b011c, 'ldr', 'x10, [x0, w10, uxtw #3]'),
    (0x1005b0120, 'sub', 'x28, x10, #4'),
    (0x100584c7c, 'ldr', 'x9, [sp, #0x78]'),
    (0x100584c80, 'add', 'x9, x9, w8, uxtb'),
    (0x100584c84, 'ldrb', 'w9, [x9]'),
    (0x100584c88, 'mov', 'w10, #0xf2'),
    (0x100584c8c, 'eor', 'w9, w9, w10'),
    (0x100584c90, 'ldr', 'x10, [sp, #0x80]'),
    (0x100584c94, 'ldrb', 'w9, [x10, w9, uxtw]'),
    (0x100584ca0, 'eor', 'w8, w8, w9'),
    (0x100584ca4, 'mov', 'w9, #0x8d41'),
    (0x100584ca8, 'add', 'w8, w9, w8, uxtb'),
    (0x100584cac, 'ldr', 'x8, [x28, w8, uxtw #3]'),
    (0x100584cb0, 'add', 'x5, sp, #0x90'),
    (0x100584cbc, 'mov', 'w3, #0xc18'),
    (0x100584cc4, 'mov', 'x17, #0x21c3'),
    (0x100584cc8, 'blraa', 'x8, x17'),
)


def audit(path):
    thin, = [blob for cpu, subtype, blob in daemon_slices(path.read_bytes())
             if (cpu, subtype) == (0x0100000c, 0x80000002)]
    identity = selected_identity(thin)
    assert identity['sha256'] == SHA
    assert identity['uuid'] == '28d510e5-3b91-3916-97ab-b765a3a7ba21'
    assert '889f3cbb6ca7cf137820822e65589b0ead73d4e0' in identity['cdhash_candidates']
    image = ThinView(thin)
    fixups = bindings(path, '-arch', 'arm64e')
    checked_fixups = FIXUPS | EXTRA_FIXUPS
    for slot, expected in checked_fixups.items():
        assert fixups[slot] == expected, (hex(slot), fixups[slot])
    for pc, mnemonic, operands in SITES:
        word, = image.instructions(pc, 4)
        assert (word.mnemonic, word.op_str) == (mnemonic, operands), (
            hex(pc), word.mnemonic, word.op_str)

    import_name = 'IOKit/_IOConnectCallStructMethod'
    equations = {
        'large_frame_root': selection(image, fixups, (0x100d06570, 0x100d3f820),
                                     0x50, 0x129, POOL, TABLE, -4),
        'selector19_preparatory_call': selection(image, fixups, BANKS, 0xcf, 0x8c7b,
                                                 TABLE, 0x100316938),
        'selector19_struct_method': selection(image, fixups, BANKS, 0xcf, 0x8caa,
                                              TABLE, import_name),
        'small_frame_root': selection(image, fixups, BANKS, 0x74, 0x184, POOL, TABLE, -4),
        'selector18_reused_banks_negative_control': selection(
            image, fixups, BANKS, 0xf2, 0x8d41, TABLE, 'CoreFoundation/_CFFileDescriptorCreate'),
    }
    assert {name: row['slot'] for name, row in equations.items()} == {
        'large_frame_root': '0x100e74c50',
        'selector19_preparatory_call': '0x100e73758',
        'selector19_struct_method': '0x100e738d0',
        'small_frame_root': '0x100e74c50',
        'selector18_reused_banks_negative_control': '0x100e73878',
    }
    assert TABLE + 8 * (0x45a7 - 0x2d6e) == 0x100e38ff8
    assert 0x1b98 + 0x3ffc == 0x5b94
    assert POOL + 0x8f8 == 0x100e74818 and POOL + 0x2070 == 0x100e75f90
    assert (0x100e0709c - 0xc, 0x100cb47e0) == BANKS
    assert 0x9558 + 0x590 == 0x9ae8 and 0x8450 + 0x5a8 == 0x89f8
    assert 0xa688 + 0x418 == 0xa000 + 0xaa0 == 0xaaa0
    assert 0xcda8 + 0xa50 == 0xd7f8
    assert 2 * 0xc10 == 0x1820 and 0xcc8 - 0xb0 == 0xc18

    return {
        'identity': identity,
        'checked_instruction_count': len(SITES),
        'instruction_windows': {name: window(image, *span) for name, span in WINDOWS.items()},
        'fixups': {hex(slot): {'binding': row, 'raw': image.read(slot, 8).hex()}
                   for slot, row in checked_fixups.items()},
        'byte_equations': equations,
        'selector19_candidate_predecessor': {
            'state_stack_offset': '0x5b94', 'required_word': '0x45a7',
            'index': '0x1839', 'slot': '0x100e38ff8', 'target': '0x100474cc4',
        },
        'selector19_buffer_producer': {
            'input_pointer_stack_offset': '0x9ae8', 'output_pointer_stack_offset': '0x89f8',
            'cursor_stack_offset': '0xd7f8', 'buffer_base_stack_offset': '0x10db0',
            'count_stack_offset': '0xaaa0', 'count_bytes': 0xc10, 'cursor_increment_bytes': 0x1820,
            'inline_request_bytes': 0xc10 + 84, 'inline_success_reply_bytes': 0xc10 + 52,
        },
        'selector18_candidate_buffer_producer': {
            'input_stack_offset': '0xb0', 'output_stack_offset': '0xcc8',
            'count_stack_offset': '0x90', 'count_bytes': 0xc18,
        },
        'continuous_frame_route_verified': False,
        'selector18_binding_resolved': False,
        'native_request_observed': False,
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path, help='unmodified fat lskdd executable')
    print(json.dumps(audit(parser.parse_args().image), indent=2))
