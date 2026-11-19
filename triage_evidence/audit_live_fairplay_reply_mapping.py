#!/usr/bin/env python3
"""Verify RPC 602 reply mapping and close against pinned boot collections."""

import argparse
import json
from pathlib import Path

from audit_live_kext_selector26 import Collection, IDENTITIES
from audit_live_kext_selector26_transfer import address_pair

CODE_BASE = 0xfffffe0000000000
TABLE = 0xfffffe00084899c0
DATA = 0xfffffe00084889a0
TABLE_DELTA = 0x16aa0
REPLY_ROOTS = ((0x458, 8), (0x638, 12))
OWNER_ROOTS = ((0x840, 0), (0xbb8, 0))
# Bank roots, XOR key, additive constant, resulting table index.
SELECTORS = {
    'copyout': (REPLY_ROOTS, 0x47, 0xef9, 0xf74),
    'discard': (REPLY_ROOTS, 0x87, 0xe45, 0xf24),
    'alternate discard': (((0xc08, 8), (0x158, 4)), 5, 0xef7, 0xf24),
    'wire': (((0xf50, 4), (0xf20, 4)), 0x93, 0xecb, 0xfb7),
    'unwire': (((0x4f0, 4), (0x578, 4)), 0xac, 0xf82, 0xf88),
    'deallocate': (OWNER_ROOTS, 0x5c, 0xe0b, 0xedd),
    'typed free': (OWNER_ROOTS, 0x3e, 0xed7, 0xf2b),
    'map install': (OWNER_ROOTS, 0x3e, 0x10e, 0x162),
    'map close': (OWNER_ROOTS, 0x5c, 0x90, 0x162),
    'page install': (OWNER_ROOTS, 0xd8, 0x163, 0x183),
    'page close': (REPLY_ROOTS, 0x47, 0x108, 0x183),
    'type view': (OWNER_ROOTS, 0x16, 0x34, 0xbc),
}
CALLS = {
    'copyout': (0xa549fc4, '_vm_map_copyout', 0x327a),
    'discard': (0xa549fb4, '_vm_map_copy_discard', 0xd0c8),
    'alternate discard': (0xa549fb4, '_vm_map_copy_discard', 0xd0c8),
    'wire': (0xa549f9c, '_vm_map_wire_external', 0x55db),
    'unwire': (0xa549fa4, '_vm_map_unwire', 0xdff5),
    'deallocate': (0xa549fac, '_vm_deallocate', 0x8bbb),
    'typed free': (0xc509988, '_IOFreeTypeImpl', 0x4d6a),
}
ROUTES = {
    0x206: 0xa64e560, 0x267: 0xa64e5b0, 0x977: 0xa64e6ac,
    0x207: 0xa656fd4, 0x163: 0xa64e718, 0xcff: 0xa652890,
    0xd14: 0xa64e7d8, 0x258: 0xa656fd4, 0x264: 0xa65295c,
    0x26d: 0xa656fd4, 0xbaa: 0xa64e814, 0xb9f: 0xa65349c,
    0xe53: 0xa656fd4, 0xe51: 0xa6536ec,
}
WINDOWS = {
    'rpc 602 output addresses': ((0xa64c95c, 0xa64c964), (0xa64c994, 0xa64c998),
                                 (0xa64ca18, 0xa64ca3c)),
    'rpc 700 output arguments': ((0xa64e52c, 0xa64e550),),
    'mig stores': ((0xa5e33f8, 0xa5e341c),),
    'primary marker and copyout': ((0xa64e6ac, 0xa64e814),),
    'failed copyout disposal': ((0xa652890, 0xa6529d0),),
    'mapped state and wire': ((0xa65349c, 0xa653658),),
    'child publication': ((0xa64bce0, 0xa64bce4), (0xa64bfd8, 0xa64bfdc),
                          (0xa652264, 0xa65226c), (0xa657778, 0xa657790)),
    'close bank staging': ((0xa6012b4, 0xa601300),),
    'normal close': ((0xa601f1c, 0xa602304),),
    'copyout wrapper': ((0xbe19724, 0xbe19744),),
}
CHECKS = {
    0xa64c95c: ('add', 'x20, x28, #0x90'),
    0xa64c960: ('add', 'x27, x28, #0x40'),
    0xa64c994: ('ldr', 'x22, [x28, #0x98]'),
    0xa64ca18: ('ldr', 'x9, [sp, #0x170]'),
    0xa64ca20: ('ldp', 'x6, x9, [sp, #0x88]'),
    0xa64ca28: ('ldr', 'x9, [sp, #0x128]'),
    0xa64ca30: ('mov', 'x7, x22'),
    0xa64e530: ('stp', 'x27, x9, [sp, #0x10]'),
    0xa64e534: ('ldp', 'x6, x9, [sp, #0x88]'),
    0xa64e540: ('stp', 'x20, x9, [sp]'),
    0xa64e544: ('mov', 'x7, x22'),
    0xa64e54c: ('blraa', 'x8, x17'),
    0xa64ca1c: ('stp', 'x27, x9, [sp, #0x10]'),
    0xa64ca2c: ('stp', 'x20, x9, [sp]'),
    0xa5e3408: ('str', 'x14, [x13]'),
    0xa5e340c: ('str', 'w8, [x12]'),
    0xa5e3414: ('str', 'x8, [x11]'),
    0xa5e3418: ('str', 'w9, [x10]'),
    0xa64e7ac: ('blraa', 'x8, x17'),
    0xa64e7e8: ('ldur', 'x8, [x29, #-0x80]'),
    0xa652920: ('blraa', 'x8, x17'),
    0xa6529cc: ('blraa', 'x8, x17'),
    0xa65355c: ('blraa', 'x8, x17'),
    0xa65359c: ('str', 'x8, [x21, #0x48]'),
    0xa6535a8: ('str', 'w9, [x21, #0x50]'),
    0xa6535ac: ('str', 'xzr, [x21, #0x58]'),
    0xa6535b0: ('str', 'wzr, [x21, #0x60]'),
    0xa653614: ('mvn', 'w13, w10'),
    0xa653650: ('blraa', 'x11, x17'),
    0xa64bce0: ('str', 'x0, [x28, #0x58]'),
    0xa64bfd8: ('str', 'x27, [sp, #0x88]'),
    0xa652264: ('ldr', 'x10, [sp, #0x88]'),
    0xa657778: ('ldur', 'x10, [x10, #0x60]'),
    0xa657780: ('mov', 'w11, #0x98'),
    0xa657784: ('csel', 'w11, wzr, w11, eq'),
    0xa65778c: ('str', 'w11, [x20, #0x2f0]'),
    0xa601fbc: ('sub', 'x22, x10, #4'),
    0xa6022f4: ('sub', 'x0, x8, #8'),
    0xa6022f8: ('mov', 'x1, x20'),
    0xa652268: ('stur', 'x10, [x27, #0x60]'),
    0xa657788: ('str', 'x10, [x20, #0x2e8]'),
    0xa601f1c: ('ldr', 'x20, [x20, #0x2e8]'),
    0xa60210c: ('blraa', 'x11, x17'),
    0xa602178: ('blraa', 'x8, x17'),
    0xa60225c: ('blraa', 'x8, x17'),
    0xa602300: ('blraa', 'x10, x17'),
    0xbe1972c: ('ldr', 'x3, [x2, #0x20]'),
    0xbe19730: ('mov', 'w4, #1'),
    0xbe19738: ('str', 'xzr, [x1]'),
    0xbe1973c: ('mov', 'w0, #0'),
}


def data_address(image, offset, bias, base=DATA):
    return int(image.pointer(base + offset)['target'], 16) - bias


def resolve_call(image, entry, name):
    endpoint, symbol, discriminator = CALLS[name]
    assert int(entry['target'], 16) == CODE_BASE + endpoint, (name, entry)
    assert entry['auth'] and int(entry['diversity'], 16) == discriminator
    if name != 'typed free':
        image.instruction(CODE_BASE + endpoint, 'bti', 'c')
        veneer = image.branch(CODE_BASE + endpoint + 4, 'b')
        slot = address_pair(image, veneer, 'x17')
        image.instruction(veneer + 8, 'ldr', 'x16, [x17]')
        image.instruction(veneer + 12, 'braa', 'x16, x17')
        imported = image.pointer(slot)
        assert int(imported['target'], 16) == image.named(symbol), (
            name, image.names(int(imported['target'], 16)))
        return dict(entry=entry, symbol=symbol, veneer=hex(veneer), imported=imported)
    assert int(entry['target'], 16) == image.named(symbol)
    return dict(entry=entry, symbol=symbol)


def audit_selectors(image, reference):
    results = {}
    for name, (roots, key, addend, index) in SELECTORS.items():
        left, right = (image.read(data_address(image, *root), 256) for root in roots)
        prior_banks_match = [bank == reference.read(data_address(reference, *root, base=DATA - TABLE_DELTA), 256)
                             for bank, root in zip((left, right), roots, strict=True)]
        assert all(prior_banks_match), name
        decoded = {value ^ right[left[value] ^ key] for value in range(256)}
        assert decoded == {index - addend}, (name, decoded)
        if name in CALLS:
            result = resolve_call(image, image.pointer(TABLE + index * 8), name)
        else:
            adjust = -4 if name.startswith('map') else -8 if name == 'type view' else 0
            entry = image.pointer(DATA + index * 8)
            result = dict(entry=entry, target_adjustment=adjust)
            if name != 'type view':
                symbol = '_kernel_map' if adjust else '_PAGE_SHIFT_CONST'
                assert int(entry['target'], 16) == image.named(symbol) - adjust, (name, entry)
                result['symbol'] = symbol
            else:
                view = int(entry['target'], 16) + adjust
                assert view == 0xfffffe0008492700
                assert image.read(view + 0x28, 8) == bytes.fromhex('6400000098000000')
                name_pointer = image.pointer(view + 0x10)
                name_address = int(name_pointer['target'], 16)
                assert image.read(name_address, len(b'site.FPAppSecurityInfo\0')) == b'site.FPAppSecurityInfo\0'
                result.update(view=hex(view), size_bytes=152, name_pointer=name_pointer,
                              type_name='site.FPAppSecurityInfo')
        results[name] = dict(roots=[hex(data_address(image, *root)) for root in roots],
                             banks=[left.hex(), right.hex()], prior_banks_match=prior_banks_match, xor_key=key,
                             addend=addend, index=index, **result)
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    parser.add_argument('reference_collection', type=Path)
    args = parser.parse_args()
    image = Collection(args.collection, IDENTITIES[1])
    reference = Collection(args.reference_collection, IDENTITIES[0])
    selectors = audit_selectors(image, reference)
    for address, check in CHECKS.items():
        image.instruction(CODE_BASE + address, *check)
    assert image.named('_oh70aLVr') == CODE_BASE + 0xa601118
    assert image.branch(CODE_BASE + 0xbe19728, 'cbz') == CODE_BASE + 0xbe19738
    assert image.branch(CODE_BASE + 0xbe19734, 'b') == CODE_BASE + 0xbe13524
    routes = {}
    for index, address in ROUTES.items():
        route = image.pointer(TABLE + index * 8)
        assert int(route['target'], 16) == CODE_BASE + address, (hex(index), route)
        routes[hex(index)] = route
    windows = {
        label: [[hex(word.address), word.bytes.hex(), word.mnemonic, word.op_str]
                for start, end in ranges
                for word in image.instructions(CODE_BASE + start, end - start)]
        for label, ranges in WINDOWS.items()
    }
    receipt = dict(collection_identity=IDENTITIES[1], reference_identity=IDENTITIES[0],
                   selectors=selectors, routes=routes, windows=windows,
                   exact_instruction_checks=len(CHECKS))
    print(json.dumps(receipt, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
