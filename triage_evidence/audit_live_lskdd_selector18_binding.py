#!/usr/bin/env python3
"""Check selector 18's conditional call bindings in the original arm64e slice."""

import argparse
import json
from pathlib import Path

from audit_daemon_iokit_native_registry import daemon_slices
from audit_fairplay_additional_clients import window
from audit_fairplay_live_slice_identity import selected_identity
from audit_live_fairplay_adid_ipc import ThinView, bindings, selection
from audit_live_lskdd_method_abi import SHA
from audit_live_lskdd_selector19_binding import BANKS, POOL, TABLE

BANK_PRODUCERS = (
    (0x100e74818, 'rebase 0x100E0709C', 12),
    (0x100e75f90, 'rebase 0x100CB47E0', 0),
    (POOL + 0x1fd0, 'rebase 0x100D3F724', 4),
    (POOL + 0x2648, 'rebase 0x100E06F98', 8),
)
SITES = (
    (0x1005b0120, 'sub', 'x28, x10, #4'),
    (0x1005b013c, 'braa', 'x12, x17'),
    (0x1005d3628, 'strb', 'wzr, [x20, x8]'),
    (0x1005892cc, 'strb', 'wzr, [x21, x12]'),
    (0x1006533f0, 'ldr', 'x11, [x27, #0x28]'),
    (0x1005b3410, 'str', 'w22, [x27, #0x30]'),
    (0x1009e9034, 'mov', 'x15, #0'),
    (0x1009e9078, 'str', 'x11, [x20]'),
    (0x1009e9104, 'ldr', 'x11, [x0, #0x1fd0]'),
    (0x1009e9108, 'sub', 'x11, x11, #4'),
    (0x1009e910c, 'str', 'x11, [sp, #0x78]'),
    (0x1009e9110, 'ldr', 'x11, [x0, #0x2648]'),
    (0x1009e9114, 'sub', 'x11, x11, #8'),
    (0x1009e9118, 'str', 'x11, [sp, #0x80]'),
    (0x100654a4c, 'str', 'x13, [sp, #0x40]'),
    (0x100654a5c, 'ldrb', 'w9, [x15]'),
    (0x100654a80, 'adrp', 'x10, #0x100e74000'),
    (0x100654a84, 'add', 'x10, x10, #0x818'),
    (0x100654a88, 'ldr', 'x11, [x10]'),
    (0x100654a8c, 'sub', 'x11, x11, #0xc'),
    (0x100654a90, 'ldr', 'x10, [x10, #0x1778]'),
    (0x100654a94, 'stp', 'x11, x10, [sp, #0x50]'),
    (0x100584c08, 'ldr', 'x9, [sp, #0x50]'),
    (0x100584c14, 'mov', 'w10, #0xcf'),
    (0x100584c1c, 'ldr', 'x10, [sp, #0x58]'),
    (0x100584c28, 'mov', 'w9, #0x8c7b'),
    (0x100584c30, 'ldr', 'x8, [x28, w8, uxtw #3]'),
    (0x100584c4c, 'mov', 'x17, #0x199'),
    (0x100584c50, 'blraa', 'x8, x17'),
    (0x100584c7c, 'ldr', 'x9, [sp, #0x78]'),
    (0x100584c88, 'mov', 'w10, #0xf2'),
    (0x100584c90, 'ldr', 'x10, [sp, #0x80]'),
    (0x100584c98, 'ldr', 'x10, [sp, #0x40]'),
    (0x100584c9c, 'ldr', 'w0, [x10]'),
    (0x100584ca4, 'mov', 'w9, #0x8d41'),
    (0x100584cac, 'ldr', 'x8, [x28, w8, uxtw #3]'),
    (0x100584cc4, 'mov', 'x17, #0x21c3'),
    (0x100584cc8, 'blraa', 'x8, x17'),
)
EDGE_ROWS = (
    (0x6a8e, 0x1005d3624, 0xba9a),
    (0x6a3c, 0x1005892b4, 0xba9a),
    (0x258c, 0x1005892b4, 0xe008),
    (0x2573, 0x1006533e8, 0xe008),
    (0x542c, 0x1005b3410, 0xc944),
    (0x5438, 0x1009e9034, 0xc944),
    (0x37cb, 0x100654a48, 0x613b),
)


def audit(path):
    thin, = [data for _, subtype, data in daemon_slices(path.read_bytes()) if subtype == 0x80000002]
    identity = selected_identity(thin)
    assert identity['sha256'] == SHA
    image = ThinView(thin)
    fixups = bindings(path, '-arch', 'arm64e')
    for site, mnemonic, operands in SITES:
        image.instruction(site, mnemonic, operands)

    banks = []
    for slot, row, adjustment in BANK_PRODUCERS:
        assert fixups[slot] == row
        banks.append(int(row.split()[1], 16) - adjustment)
    assert tuple(banks[:2]) == BANKS
    assert tuple(banks[2:]) == (0x100d3f720, 0x100e06f90)
    prep = selection(image, fixups, banks[:2], 0xcf, 0x8c7b, TABLE, 0x100316938)
    method = selection(image, fixups, banks[2:], 0xf2, 0x8d41, TABLE,
                       'IOKit/_IOConnectCallStructMethod')
    assert prep['binding'] == 'auth-rebase 0x100316938 (div=0x0199 ad=0 key=IA)'
    assert method['binding'] == 'auth-bind IOKit/_IOConnectCallStructMethod (div=0x21C3 ad=0 key=IA)'
    image.instruction(0x100316938, 'ret', '')

    entry_index = 0x6a8e
    input_done = entry_index - 0x52
    output_done = input_done - 0x44c9
    assert input_done ^ 0xb2 == entry_index
    assert output_done - 0x2572 == 1
    assert (((output_done + 0x95cb2fb9) & 0x6a34feff) ^ 0x5834) == 3096
    assert output_done ^ 0xff == 0x258c
    edges = {}
    for index, target, modifier in EDGE_ROWS:
        slot = TABLE + 8 * index
        expected = f'auth-rebase {target:#X} (div=0x{modifier:04X} ad=0 key=IA)'
        assert fixups[slot].upper() == expected.upper(), (hex(slot), fixups[slot])
        edges[hex(index)] = dict(slot=hex(slot), binding=fixups[slot], word=image.read(slot, 8).hex())

    return dict(identity=identity, instruction_checks=len(SITES)+1,
                instructions=[window(image, pc, pc+4)[0] for pc, *_ in SITES],
                bank_rebases={hex(slot): row for slot, row, _ in BANK_PRODUCERS},
                preparatory_call=prep, selector18_method=method, conditional_entry_edges=edges,
                modeled_clear_bytes_each=3096, native_request_observed=False,
                uninterrupted_route_to_method_established=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path, help='unmodified fat lskdd executable')
    print(json.dumps(audit(parser.parse_args().image), indent=2))
