#!/usr/bin/env python3
"""Verify the installed FPDI record adapter's selector 26 route and result ABI."""

import argparse
import json
from pathlib import Path
import subprocess

from audit_daemon_iokit_native_registry import daemon_slices, digest
from audit_fairplay_additional_clients import window
from audit_fairplay_live_slice_identity import selected_identity
from audit_live_fairplay_adid_ipc import ThinView, bindings, selection
from audit_live_fpdi_xpc import POOL, SHA256, TABLE, UUID, negative_adjust

CHECKS = {
    0x1000503dc: ('add', 'w11, w20, #0x202'),
    0x1000503e0: ('sub', 'x12, x29, #0x80'),
    0x100050418: ('mul', 'w12, w12, w13'),
    0x10005041c: ('eor', 'w11, w11, w12'),
    0x100050424: ('stp', 'x13, x21, [x29, #-0x70]'),
    0x100050428: ('sub', 'w12, w28, w12'),
    0x100050430: ('stur', 'w11, [x29, #-0x80]'),
    0x100050434: ('stur', 'w10, [x29, #-0x78]'),
    0x100050494: ('ldr', 'x8, [x26, w8, uxtw #3]'),
    0x100050498: ('sub', 'x0, x29, #0x80'),
    0x10005049c: ('mov', 'x17, #0x132e'),
    0x1000504a0: ('blraa', 'x8, x17'),
    0x1000504a8: ('ldur', 'w21, [x29, #-0x7c]'),
    0x1001f7e68: ('pacibsp', ''),
    0x1001f7e88: ('mov', 'x19, x0'),
    0x1001f7fac: ('orr', 'w16, w15, w19'),
    0x1001f7fb0: ('and', 'w15, w19, w15'),
    0x1001f7fbc: ('sub', 'w15, w16, w15'),
    0x1001f7fc0: ('eor', 'w15, w15, w17'),
    0x1001f7fcc: ('mul', 'w16, w15, w16'),
    0x1001f7fd0: ('ldr', 'w15, [x19]'),
    0x1001f7fd4: ('eor', 'w17, w15, w16'),
    0x1001f7fd8: ('ldp', 'x15, x2, [x19, #0x10]'),
    0x1001f7fdc: ('ldr', 'w0, [x19, #8]'),
    0x1001f7fec: ('add', 'w20, w16, w0'),
    0x1001f7ff0: ('str', 'x20, [sp]'),
    0x1001f7ff4: ('cmp', 'x15, #0'),
    0x1001f7ff8: ('ccmp', 'x2, #0, #4, ne'),
    0x1001f801c: ('ldrb', 'w13, [x13]'),
    0x1001f8020: ('mov', 'w16, #0xda'),
    0x1001f8030: ('cset', 'w0, eq'),
    0x1001f8040: ('eon', 'w16, w22, w0'),
    0x1001f8044: ('ubfiz', 'w16, w16, #1, #1'),
    0x1001f8050: ('add', 'w12, w12, #0x161'),
    0x1001f8058: ('eor', 'w12, w16, w17'),
    0x1001f8064: ('add', 'x23, x11, x13'),
    0x1001f8068: ('ldr', 'x12, [x23, w12, sxtw #3]'),
    0x1001f8074: ('mov', 'x17, #0x2c19'),
    0x1001f8078: ('braa', 'x12, x17'),
    0x100015948: ('ldr', 'w0, [x15, #4]'),
    0x100015980: ('mov', 'w11, #0xfd'),
    0x1000159a4: ('mov', 'w9, #0x4c6b'),
    0x1000159ac: ('ldr', 'x8, [x23, w8, uxtw #3]'),
    0x1000159b0: ('mov', 'x5, sp'),
    0x1000159b4: ('mov', 'w1, #0x1a'),
    0x1000159b8: ('mov', 'x3, x20'),
    0x1000159bc: ('mov', 'x4, x2'),
    0x1000159c0: ('mov', 'x17, #0xb0da'),
    0x1000159c4: ('blraa', 'x8, x17'),
    0x1000159d0: ('lsl', 'w8, w0, w8'),
    0x1000159dc: ('and', 'w8, w8, w9'),
    0x1000159e0: ('subs', 'w8, w0, w8'),
    0x1000159e8: ('cset', 'w8, eq'),
    0x1000159f4: ('eor', 'w8, w8, w22'),
    0x100015a00: ('braa', 'x8, x17'),
    0x10009cfb4: ('ldr', 'x8, [sp]'),
    0x10009cfbc: ('cmp', 'x8, x20'),
    0x10009cfc0: ('csel', 'w11, w24, w9, eq'),
    0x10009cfcc: ('braa', 'x8, x17'),
    0x1000101d4: ('str', 'w11, [x19, #4]'),
    0x1000101f0: ('retab', ''),
}
WINDOWS = {
    'record_adapter': (0x1001f7e68, 0x1001f807c),
    'in_place_method': (0x100015930, 0x100015a04),
    'output_count_test': (0x10009cfb4, 0x10009cfd0),
    'common_epilogue': (0x1000101d4, 0x1000101f4),
    'candidate_caller_record': (0x1000503c4, 0x1000504b8),
}
EXPECTED_FIXUPS = {
    0x1005c6ae8: 'auth-rebase 0x1000503C4 (div=0x20CD ad=0 key=IA)',
    0x1005e7990: 'auth-rebase 0x1001F7E68 (div=0x132E ad=0 key=IA)',
    0x1005e06e8: 'auth-rebase 0x1000101D4 (div=0x2C19 ad=0 key=IA)',
    0x1005e06f8: 'auth-rebase 0x100015930 (div=0x2C19 ad=0 key=IA)',
    0x1005d5440: 'auth-rebase 0x1000101D4 (div=0x40CB ad=0 key=IA)',
    0x1005d9630: 'auth-rebase 0x10009CFB4 (div=0x40CB ad=0 key=IA)',
    0x1005e7300: 'auth-bind IOKit/_IOConnectCallStructMethod (div=0xB0DA ad=0 key=IA)',
}


def verify_status_and_index():
    # Prove the normalized arithmetic by checking that each negation is unsatisfiable.
    query = """(set-logic QF_BV)
(declare-fun p () (_ BitVec 32))
(declare-fun status () (_ BitVec 32))
(push 1)
(assert (distinct
  (bvxor (bvsub (bvor p #xfefddeba) (bvand p #xfefddeba)) #x4a5c7a0a)
  (bvxor p #xb4a1a4b0)))
(check-sat)
(pop 1)
(push 1)
(assert (= (bvand p #x00000007) #x00000000))
(assert (distinct
  (bvxor (bvadd (bvsub (bvor p #xa4e0531b) p) (bvand p #x5b1face0)) #x1041f7ab)
  (bvxor p #xb4a1a4b0)))
(check-sat)
(pop 1)
(assert (distinct
  (= (bvsub status (bvand (bvshl status #x00000001) #x2cb8bbaa)) #x00000000)
  (= status #x00000000)))
(check-sat)
"""
    result = subprocess.run(['z3', '-in'], text=True, input=query, capture_output=True, check=True)
    assert result.stdout.split() == ['unsat', 'unsat', 'unsat']
    state = 0x3f8d
    w22 = state - 0x1655
    selected = {label: TABLE + 8 * (state ^ (((~(w22 ^ flag)) & 1) << 1))
                for label, flag in (('both_nonnull', 0), ('null_bypass', 1))}
    assert selected == {'both_nonnull': 0x1005e06f8, 'null_bypass': 0x1005e06e8}
    assert ((((w22 + 0x15cd) | 0x88) - 0x3f8c) & 31) == 1
    assert TABLE + 8 * (w22 ^ 0x184e) == 0x1005d9630
    assert TABLE + 8 * w22 == 0x1005d5440
    return {'smt2': query, 'verdicts': result.stdout.split(),
            'selected_slots': {key: hex(value) for key, value in selected.items()}}


def inspect(path):
    _, _, thin = next(row for row in daemon_slices(path.read_bytes()) if row[1] == 0x80000002)
    assert selected_identity(thin)['uuid'] == UUID and digest(thin) == SHA256
    image, fixups = ThinView(thin), bindings(path, '-arch', 'arm64e')
    for pc, instruction in CHECKS.items():
        image.instruction(pc, *instruction)
    for slot, row in EXPECTED_FIXUPS.items():
        assert fixups[slot] == row

    selections = {
        'dispatch_table': selection(image, fixups, (0x1005bc130, 0x10057a2e0), 0xda,
                                    0x161, POOL, TABLE, negative_adjust(-0x502b, 0xdde1)),
        'structure_call': selection(image, fixups, (0x10057a0e0, 0x1005a5d90), 0xfd,
                                    0x4c6b, TABLE, 'IOKit/_IOConnectCallStructMethod'),
    }
    windows = {name: window(image, start, end) for name, (start, end) in WINDOWS.items()}
    return {
        'uuid': UUID, 'sha256': SHA256, 'checks': len(CHECKS),
        'fixups': {hex(slot): {'binding': row, 'word': image.read(slot, 8).hex()}
                   for slot, row in EXPECTED_FIXUPS.items()},
        'selections': selections, 'geometry_and_status': verify_status_and_index(),
        'windows': windows, 'instruction_count': sum(map(len, windows.values())),
        'native_request_observed': False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('daemon', type=Path)
    parser.add_argument('receipt', type=Path)
    args = parser.parse_args()
    args.receipt.write_text(json.dumps(inspect(args.daemon), indent=2, sort_keys=True) + '\n')


if __name__ == '__main__':
    main()
