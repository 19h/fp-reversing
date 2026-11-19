#!/usr/bin/env python3
"""Audit current FairPlay host-port lookup and kernel RPC emission anchors."""

import argparse
import json
from pathlib import Path
import struct

from audit_live_kext_selector26 import Collection, IDENTITIES
from audit_live_kext_selector26_transfer import imported_call, words

TABLE = 0xfffffe00084899c0
# Each bank anchor is a chained data pointer. The bias removes interior offsets.
HOST_BANKS = (0xfffffe00084891e0, 0, 0xfffffe0008489558, 0)
SPECIAL_BANKS = (0xfffffe0008489510, 0, 0xfffffe00084893b0, 0)
RPC_BANKS = (0xfffffe00084895a8, 8, 0xfffffe0008488af8, 4)
SELECTIONS = (
    ('host_priv_self', HOST_BANKS, 0x3e, 0xf4a, 0xf9e, 0xfffffe000a64bd94),
    ('host_get_special_port', SPECIAL_BANKS, 0x32, 0xeb4, 0xfad, 0xfffffe000a64be48),
    ('rpc502', RPC_BANKS, 0x98, 0xed9, 0xf6e, 0xfffffe000a64ca38),
    ('rpc700', SPECIAL_BANKS, 0x32, 0xec0, 0xfb9, 0xfffffe000a64e54c),
    ('ipc_port_release_send', RPC_BANKS, 0x6d, 0xefe, 0xf11, 0xfffffe000a6570bc),
)


def select(image, name, anchors, key, additive, index, call):
    left, left_bias, right, right_bias = anchors
    left_entry, right_entry = image.pointer(left), image.pointer(right)
    lraw = image.read(int(left_entry['target'], 16) - left_bias, 256)
    rraw = image.read(int(right_entry['target'], 16) - right_bias, 256)
    assert {value ^ rraw[lraw[value] ^ key] for value in range(256)} == {index - additive}
    slot = image.pointer(TABLE + 8 * index)
    assert (slot['auth'], slot['key'], slot['address_diversity']) == (1, 0, 0)
    image.instruction(call - 4, 'mov', f"x17, #{slot['diversity']}")
    image.instruction(call, 'blraa', 'x8, x17')
    symbols = image.names(int(slot['target'], 16))
    if not name.startswith('rpc'):
        assert '_' + name in symbols
    return {'call': hex(call), 'left': left_entry, 'right': right_entry, 'xor_key': hex(key),
            'bank_biases': [left_bias, right_bias], 'left_bytes': lraw.hex(),
            'right_bytes': rraw.hex(), 'table_index': hex(index), 'slot': slot, 'symbols': symbols}


def client(image, entry, site, message_id):
    page, load = image.instructions(site - 0x18, 8)
    assert (page.mnemonic, load.mnemonic) == ('adrp', 'ldr')
    assert page.op_str.startswith('x8, #') and load.op_str.startswith('d0, [x8, #')
    constant = int(page.op_str.split('#')[1], 0) + int(load.op_str.split('#')[1][:-1], 0)
    assert struct.unpack('<II', image.read(constant, 8)) == (0, message_id)
    image.instruction(site - 0x10, 'str', 'd0, [sp, #0x20]')
    image.instruction(site - 8, 'mov', 'w1, #0x58')
    image.instruction(site - 4, 'mov', 'w2, #0x190')
    return {'request_id': message_id, 'constant': hex(constant), 'emission_site': hex(site),
            'binding': imported_call(image, site, '_mach_msg_rpc_from_kernel_proper'),
            'words': words(image, entry, site + 4 - entry)}


def audit(path):
    image = Collection(path, IDENTITIES[1])
    assert int(image.pointer(0xfffffe0008488b38)['target'], 16) - 12 == TABLE
    selections = {row[0]: select(image, *row) for row in SELECTIONS}
    dispatch_edges = {}
    for index, target in (
        (0xc96, 0xfffffe000a64bd04),
        (0x8ea, 0xfffffe000a64e4c4),
        (0x906, 0xfffffe000a64c9b0),
    ):
        edge = image.pointer(TABLE + 8 * index)
        assert int(edge['target'], 16) == target
        dispatch_edges[hex(index)] = edge
    clients = [
        client(image, int(selections[name]['slot']['target'], 16), site, message_id)
        for name, site, message_id in (
            ('rpc502', 0xfffffe000a5e3288, 502), ('rpc700', 0xfffffe000a5e34f8, 700)
        )
    ]
    wrapper = image.named('_mach_msg_rpc_from_kernel_proper')
    assert all(int(row['binding']['address'], 16) == wrapper for row in clients)
    common = image.branch(wrapper + 0x10, 'b')
    assert common == 0xfffffe000bd3d8d4
    assert image.branch(0xfffffe000bd3da9c, 'bl') == 0xfffffe000bd0effc
    for pc, mnemonic, operand in (
        (0xfffffe000a64bda4, 'csel', 'w2, w9, w8, eq'),
        (0xfffffe000a64be3c, 'add', 'x3, x28, #0x18'),
        (0xfffffe000a64c988, 'ldr', 'x0, [x28, #0x18]'),
        (0xfffffe000bd3d8fc, 'mrs', 'x19, tpidr_el1'),
        (0xfffffe000bd3d960, 'ldr', 'x21, [x19, #0x3f0]'),
        (0xfffffe000a6570a0, 'ldur', 'x0, [x28, #0x18]'),
        (0xfffffe000bd3da20, 'str', 'x21, [x23, #0x10]'),
        (0xfffffe000bd3da94, 'mov', 'w1, #0x10001'),
    ):
        image.instruction(pc, mnemonic, operand)
    return {'identity': IDENTITIES[1], 'dispatch_table': hex(TABLE), 'selections': selections,
            'dispatch_edges': dispatch_edges, 'rpc_clients': clients, 'wrapper': words(image, wrapper, 0x14),
            'windows': {
                role: words(image, pc, size) for role, pc, size in (
                    ('host_and_slot_selection', 0xfffffe000a64bd94, 0xb8),
                    ('destination_and_rpc502', 0xfffffe000a64c974, 0xc8),
                    ('rpc700_dispatch', 0xfffffe000a64e4c4, 0x8c),
                    ('cleanup_exit', 0xfffffe000a657070, 0x50),
                    ('current_kernel_transport', common, wrapper - common),
                )
            },
            'native_exchange_observed': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    print(json.dumps(audit(parser.parse_args().collection), indent=2))
