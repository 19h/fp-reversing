#!/usr/bin/env python3
"""Audit selector 26 caller equivalence and nominal descriptor dispatch."""

import argparse
import json
from pathlib import Path

from audit_live_kext_selector26 import Collection, IDENTITIES
from resolve_kernel_collection_interfaces import CACHE

HANDLERS = (0xfffffe000a504034, 0xfffffe000a5451c4)
PROVIDERS = (0xfffffe000a505198, 0xfffffe000a546328)


def address_pair(image, address, register):
    page, add = image.instructions(address, 8)
    assert (page.mnemonic, add.mnemonic) == ('adrp', 'add')
    assert page.op_str.startswith(f'{register}, #')
    assert add.op_str.startswith(f'{register}, {register}, #')
    return sum(int(word.op_str.split('#')[1], 0) for word in (page, add))


def identify(image, address, name):
    symbols = image.names(address)
    assert any(name in symbol for symbol in symbols), (hex(address), name, symbols)
    return {'address': hex(address), 'symbols': symbols}


def imported_call(image, address, name):
    veneer = image.branch(address, 'bl')
    slot = image.pointer(address_pair(image, veneer, 'x17'))
    image.instruction(veneer + 8, 'ldr', 'x16, [x17]')
    image.instruction(veneer + 12, 'braa', 'x16, x17')
    return {'veneer': hex(veneer), 'fixup': slot,
            **identify(image, int(slot['target'], 16), name)}


def imported_data(image, address, register, name):
    page, load = image.instructions(address, 8)
    assert (page.mnemonic, load.mnemonic) == ('adrp', 'ldr')
    assert page.op_str.startswith(f'{register}, #')
    assert load.op_str.startswith(f'{register}, [{register}, #')
    slot_address = int(page.op_str.split('#')[1], 0) + int(load.op_str.split('#')[1][:-1], 0)
    slot = image.pointer(slot_address)
    return {'fixup': slot, **identify(image, int(slot['target'], 16), name)}


def words(image, address, size):
    return [{'pc': hex(word.address), 'word': word.bytes.hex(),
             'mnemonic': word.mnemonic, 'operands': word.op_str}
            for word in image.instructions(address, size)]


def descriptor_slots(image, class_name, offsets):
    address_point = image.named(f'__ZTV{len(class_name)}{class_name}') + 16
    entries = {}
    for offset, name in offsets.items():
        slot = image.pointer(address_point + offset)
        target = int(slot['target'], 16)
        first = image.instructions(target, 4)[0]
        if first.mnemonic == 'bti':
            following = image.instructions(target + 4, 4)[0]
            if following.mnemonic == 'b':
                target = image.branch(target + 4, 'b')
        entries[hex(offset)] = {'fixup': slot, **identify(image, target, name)}
    return entries


def capture(path, index):
    image = Collection(path, IDENTITIES[index])
    handler, provider = HANDLERS[index], PROVIDERS[index]
    log_string = address_pair(image, handler + 0x68, 'x0')
    result = {
        'identity': IDENTITIES[index],
        'handler': words(image, handler, 0xa0),
        'provider': words(image, provider, 0x25c),
        'bindings': {
            'task_factory': imported_call(image, provider + 0x3c, 'IOMemoryDescriptor16withAddressRange'),
            'buffer_factory': imported_call(image, provider + 0xb8, 'IOBufferMemoryDescriptor17inTaskWithOptions'),
            'core_entry': identify(image, image.branch(provider + 0x164, 'bl'), 'PRnut72j9'),
            'log': imported_call(image, handler + 0x70, '_IOLog'),
            'log_format': image.read(log_string, 160).split(b'\0', 1)[0].decode('ascii'),
        },
    }
    for offset, register, name in ((0x8c, 'x8', '_kernel_task'), (0x98, 'x8', '_PAGE_SHIFT_CONST')):
        result['bindings'][name] = imported_data(image, provider + offset, register, name)
    if index == 1:
        common = {0x28: 'release', 0x218: 'prepare', 0x220: 'complete'}
        result['nominal_dispatch'] = {
            'IOGeneralMemoryDescriptor': descriptor_slots(
                image, 'IOGeneralMemoryDescriptor', {**common, 0x208: 'readBytes', 0x210: 'writeBytes'}),
            'IOBufferMemoryDescriptor': descriptor_slots(
                image, 'IOBufferMemoryDescriptor', {**common, 0x308: 'getBytesNoCopy'}),
        }
        core = int(result['bindings']['core_entry']['address'], 16)
        result['core_entry'] = words(image, core, 0x50)
        result['success_reply_assembly'] = words(image, 0xfffffe000be816e4, 0x78)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('current', type=Path)
    parser.add_argument('--pinned', type=Path, default=CACHE)
    args = parser.parse_args()
    pinned, current = capture(args.pinned, 0), capture(args.current, 1)
    changed = {}
    for key, allowed, count in (
        ('handler', {0x68, 0x6c, 0x70}, 2),
        ('provider', {0x3c, 0x8c, 0x90, 0x98, 0x9c, 0xb8, 0x164}, 4),
    ):
        differences = {index * 4 for index, (before, after) in enumerate(zip(pinned[key], current[key]))
                       if before['word'] != after['word']}
        assert len(differences) == count and differences <= allowed, (key, differences)
        changed[key] = [hex(offset) for offset in sorted(differences)]
    assert pinned['bindings']['log_format'] == current['bindings']['log_format']
    print(json.dumps({'changed_offsets': changed, 'pinned': pinned, 'current': current}, indent=2))


if __name__ == '__main__':
    main()
