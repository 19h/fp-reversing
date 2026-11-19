#!/usr/bin/env python3
"""Compare synchronous FairPlayIOKit interfaces in two boot filesets."""

import argparse
import hashlib
import json
import struct
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs

from resolve_kernel_collection_interfaces import CACHE, chained_rebases, commands, macho, string

DRIVER = 'com.apple.driver.FairPlayIOKit'
CLIENT = '40com_apple_driver_FairPlayIOKitUserClient'
PROVIDER = '30com_apple_driver_FairPlayIOKit'
CS = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
BASE_MASK = (1 << 64) - 1
IDS = (2816, 2862, 2865)
EXPECTED_SELECTORS = (1, 6, 16, 18, 19, 20, 21, 22, 23, 26, 30, 31, 32, 33, 34, 35, 40)
IDENTITIES = (
    ('d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe',
     '9b65bd6e-027b-34d1-a22b-ac03dccffc84', '227f9df7-645d-39b8-b74a-685303d16b4b'),
    ('0389ee48091668ef1f3f5bb9f85e1b020e442451f9321df695ba48e49cc64126',
     '90195379-954d-3ca3-baac-327341f14211', '316464f8-eade-30ca-938e-2f430b1ed5bc'),
)


class Collection:
    def __init__(self, path, identity):
        self.data = path.read_bytes()
        self.digest = hashlib.sha256(self.data).hexdigest()
        self.root = macho(self.data, 0, 'collection')
        _, _, self.fixups = chained_rebases(self.data)
        self.entries = {}
        for offset, command, _ in commands(self.data, 0):
            if command == 0x80000035:
                _, head, name_offset, _ = struct.unpack_from('<QQII', self.data, offset + 8)
                name = string(self.data, offset + name_offset)
                if name in ('com.apple.kernel', DRIVER):
                    self.entries[name] = macho(self.data, head, name)
        assert (self.digest, self.entries['com.apple.kernel']['uuid'],
                self.entries[DRIVER]['uuid']) == identity
        self.symbols = {}
        for obj in self.entries.values():
            start, count, strings, string_size = obj['symtab']
            for index in range(count):
                name, kind, _, _, address = struct.unpack_from('<IBBHQ', self.data, start + index * 16)
                if name and kind & 0x0e == 0x0e and not kind & 0xe0:
                    assert name < string_size
                    self.symbols.setdefault(string(self.data, strings + name), set()).add(address)

    def named(self, name):
        value, = self.symbols[name]
        return value

    def names(self, address):
        return sorted(name for name, values in self.symbols.items() if address in values)

    def offset(self, address, size):
        segment = next(s for s in self.root['segments']
                       if s['address'] <= address
                       and address + size <= s['address'] + s['file_size'])
        return segment['file_offset'] + address - segment['address']

    def read(self, address, size):
        offset = self.offset(address, size)
        return self.data[offset:offset + size]

    def pointer(self, address):
        return {'slot': hex(address), **self.fixups[self.offset(address, 8)]}

    def instructions(self, address, size):
        words = list(CS.disasm(self.read(address, size), address))
        assert len(words) * 4 == size
        return words

    def instruction(self, address, mnemonic, operands):
        word, = self.instructions(address, 4)
        assert (word.mnemonic, word.op_str) == (mnemonic, operands)

    def branch(self, address, mnemonic):
        word, = self.instructions(address, 4)
        assert word.mnemonic == mnemonic
        return int(word.op_str.split('#')[-1], 0) & BASE_MASK


def method_map(image):
    entry = image.named(f'__ZN{CLIENT}26getTargetAndMethodForIndexEPP9IOServicej')
    words = image.instructions(entry, 0x58)
    assert [i.mnemonic for i in words] == [
        'bti', 'mov', 'mov', 'sub', 'cmp', 'b.hi', 'mov', 'movk', 'movk', 'lsr', 'tbz',
        'ubfiz', 'adrp', 'add', 'cmp', 'add', 'add', 'movk', 'csel', 'ldr', 'str', 'ret',
    ]
    for index, operands in {
        3: 'w9, w2, #1', 4: 'w9, #0x27', 9: 'x10, x10, x9',
        11: 'x9, x9, #3, #0x20', 19: 'x0, [x11]', 20: 'x8, [x1]',
    }.items():
        assert words[index].op_str == operands
    reject = entry + 0x54
    assert image.branch(entry + 0x14, 'b.hi') == image.branch(entry + 0x28, 'tbz') == reject
    bitmap = 0
    for shift, word in enumerate(words[6:9]):
        bitmap |= int(word.op_str.split('#')[1].split(',')[0], 0) << (16 * shift)
    table = int(words[12].op_str.split('#')[1], 16) + int(words[13].op_str.split('#')[1], 16)
    methods = {}
    for index in range(40):
        slot = table + index * 8
        raw = image.read(slot, 8)
        if not (bitmap >> index & 1):
            assert raw == bytes(8)
            continue
        pointer = image.pointer(slot)
        address = int(pointer['target'], 16)
        target, _, adjustment, flags, count_in, count_out = struct.unpack('<6Q', image.read(address, 48))
        member = image.pointer(address + 8)
        methods[index + 1] = {
            'record': pointer, 'member': member,
            'member_symbols': image.names(int(member['target'], 16)),
            'target_word': hex(target), 'adjustment': adjustment, 'flags': flags,
            'count_in': count_in, 'count_out': count_out,
        }
    assert tuple(methods) == EXPECTED_SELECTORS
    return {'router': hex(entry), 'bitmap': hex(bitmap), 'table': hex(table), 'methods': methods}


def selector26(image, methods):
    record = methods['methods'][26]
    assert (record['target_word'], record['adjustment'], record['flags'],
            record['count_in'], record['count_out']) == ('0x0', 0, 3, 16, 16)
    assert (record['member']['key'], record['member']['diversity']) == (0, '0x705d')
    member = int(record['member']['target'], 16)
    for offset, mnemonic, operands in (
        (0x24, 'ldr', 'x1, [x1]'), (0x28, 'ldr', 'w2, [x20, #8]'),
        (0x2c, 'ldp', 'x4, x3, [x0, #0xe0]'), (0x30, 'ldr', 'x8, [x0, #0xd8]'),
        (0x44, 'mov', 'x17, #0xa20'), (0x54, 'movk', 'x16, #0x3499, lsl #48'),
        (0x58, 'blraa', 'x9, x16'), (0x7c, 'str', 'x8, [x19]'),
        (0x84, 'str', 'w8, [x19, #8]'),
    ):
        image.instruction(member + offset, mnemonic, operands)
    assert image.branch(member + 0x60, 'cbz') == member + 0x78
    provider = image.pointer(image.named(f'__ZTV{PROVIDER}') + 0x10 + 0xa20)
    assert (provider['key'], provider['diversity']) == (0, '0x3499')
    provider_address = int(provider['target'], 16)
    for offset, operands in (
        (0x28, 'x0, x1'), (0x2c, 'w20, w2'), (0x30, 'x1, x20'),
        (0x34, 'w2, #3'), (0x38, 'x3, x4'),
    ):
        image.instruction(provider_address + offset, 'mov', operands)
    factory_call = provider_address + 0x3c
    veneer = image.branch(factory_call, 'bl')
    adrp, add, load, branch = image.instructions(veneer, 16)
    assert [i.mnemonic for i in (adrp, add, load, branch)] == ['adrp', 'add', 'ldr', 'braa']
    assert (load.op_str, branch.op_str) == ('x16, [x17]', 'x16, x17')
    factory = image.pointer(int(adrp.op_str.split('#')[1], 16) + int(add.op_str.split('#')[1], 16))
    factory_names = image.names(int(factory['target'], 16))
    assert any('IOMemoryDescriptor16withAddressRange' in name for name in factory_names)
    return {
        'provider_slot': provider, 'provider_symbols': image.names(provider_address),
        'provider_call': hex(member + 0x58),
        'member_prefix_sha256': hashlib.sha256(image.read(member, 0x68)).hexdigest(),
        'factory_call': hex(factory_call), 'factory_veneer': hex(veneer),
        'factory_slot': factory, 'factory_symbols': factory_names,
    }


def mig_map(image):
    kernel = image.entries['com.apple.kernel']
    const = next(seg for seg in kernel['segments'] if seg['name'] == '__DATA_CONST')
    start = const['file_offset']
    length = const['file_size']
    pattern = struct.pack('<III', 2800, 2892, 4296)
    positions = []
    offset = start
    while (offset := image.data.find(pattern, offset, start + length)) != -1:
        head = offset - 8
        if head in image.fixups and (head - start) % 8 == 0:
            positions.append(const['address'] + head - start)
        offset += 1
    subsystem, = positions
    selector = image.pointer(subsystem)
    assert (selector['auth'], selector['diversity']) == (1, '0x423')
    routines = {}
    for message_id in IDS:
        record = subsystem + 0x20 + (message_id - 2800) * 32
        stub = image.pointer(record + 8)
        assert (stub['auth'], stub['diversity']) == (1, '0x3a83')
        fields = struct.unpack('<4I', image.read(record + 16, 16))
        routines[message_id] = {'record': hex(record), 'stub': stub, 'fields': list(fields)}
    assert [routines[i]['fields'] for i in IDS] == [[1, 0, 0, 44], [8, 0, 1, 64], [17, 0, 0, 4284]]
    return {'subsystem': hex(subsystem), 'selector': selector, 'routines': routines}


def synchronous_path(image, method, mig):
    client = image.named(f'__ZTV{CLIENT}') + 0x10
    dispatch = image.pointer(client + 0x880)
    router = image.pointer(client + 0x970)
    assert router['target'] == method['router']
    assert (dispatch['auth'], dispatch['diversity']) == (1, '0xb352')
    assert (router['auth'], router['diversity']) == (1, '0xbdaa')
    external = int(dispatch['target'], 16)
    assert external == image.named(
        '__ZN12IOUserClient14externalMethodEjP25IOExternalMethodArgumentsP24IOExternalMethodDispatchP8OSObjectPv')
    stub = int(mig['routines'][2865]['stub']['target'], 16)
    importer = image.branch(stub + 0x118, 'bl')
    image.instruction(importer + 0x38, 'cmp', 'w8, #0x27')
    implementation = image.branch(stub + 0x188, 'bl')
    helper = image.branch(implementation + 0x2ac, 'bl')
    for address, mnemonic, args in (
        (helper + 0x94, 'ldr', 'x9, [x16, #0x880]'),
        (helper + 0xac, 'movk', 'x17, #0xb352, lsl #48'),
        (helper + 0xb0, 'blraa', 'x9, x17'),
        (external + 0x280, 'ldr', 'x11, [x16, #0x970]'),
        (external + 0x294, 'movk', 'x17, #0xbdaa, lsl #48'),
        (external + 0x298, 'blraa', 'x11, x17'),
        (external + 0x360, 'cmp', 'w8, #3'),
        (stub + 0x18c, 'stur', 'w0, [x24, #-4]'),
        (stub + 0x1bc, 'str', 'w0, [x21, #0x28]'),
    ):
        image.instruction(address, mnemonic, args)
    assert image.branch(external + 0x36c, 'b.eq') == external + 0x40c
    adapter = image.branch(external + 0x424, 'bl')
    for offset, mnemonic, args in (
        (0x1c, 'ldr', 'x8, [x0, #0x20]'),
        (0x20, 'mov', 'w9, #-1'),
        (0x24, 'cmp', 'x8, x9'),
        (0x28, 'mov', 'w19, w3'),
        (0x2c, 'ccmp', 'x8, x19, #4, ne'),
        (0x34, 'ldr', 'x10, [x20, #0x28]'),
        (0x4c, 'ldr', 'x9, [x5]'),
        (0x50, 'cmp', 'x9, x10'),
        (0x88, 'mov', 'w21, #0x2c2'),
        (0x8c, 'movk', 'w21, #0xe000, lsl #16'),
        (0x16c, 'mov', 'x0, x21'),
        (0x260, 'braa', 'x17, x7'),
    ):
        image.instruction(adapter + offset, mnemonic, args)
    assert image.branch(adapter + 0x30, 'b.ne') == adapter + 0x88
    assert image.branch(adapter + 0x54, 'b.ne') == adapter + 0xf8
    assert image.branch(adapter + 0xf4, 'b') == adapter + 0x16c
    return {
        'connection_import_call': hex(stub + 0x118),
        'connection_import': hex(importer),
        'implementation_call': hex(stub + 0x188),
        'implementation': hex(implementation),
        'dispatch_helper': hex(helper),
        'dispatch_call': hex(helper + 0xb0),
        'external_method': dispatch,
        'router_call': hex(external + 0x298),
        'router_slot': router,
        'structure_adapter_call': hex(external + 0x424),
        'structure_adapter': hex(adapter),
        'input_mismatch_branch': hex(adapter + 0x30),
        'output_mismatch_branch': hex(adapter + 0x54),
        'short_reply_status_store': hex(stub + 0x1bc),
    }


def inspect(path, identity):
    image = Collection(path, identity)
    methods = method_map(image)
    mig = mig_map(image)
    return {
        'root_uuid': image.root['uuid'],
        'kernel_uuid': image.entries['com.apple.kernel']['uuid'],
        'kext_uuid': image.entries[DRIVER]['uuid'],
        'collection_sha256': image.digest,
        'collection_bytes': len(image.data),
        'kext_fileset_header_offset': image.entries[DRIVER]['header_offset'],
        'method_map': methods,
        'selector_26': selector26(image, methods),
        'mig': mig,
        'synchronous_path': synchronous_path(image, methods, mig),
    }


def compare(old_path, current_path):
    old, current = (inspect(path, identity)
                    for path, identity in zip((old_path, current_path), IDENTITIES, strict=True))
    for selector in EXPECTED_SELECTORS:
        a = old['method_map']['methods'][selector]
        b = current['method_map']['methods'][selector]
        for field in ('target_word', 'adjustment', 'flags', 'count_in', 'count_out', 'member_symbols'):
            assert a[field] == b[field], (selector, field)
    assert old['selector_26']['member_prefix_sha256'] == current['selector_26']['member_prefix_sha256']
    assert old['selector_26']['provider_symbols'] == current['selector_26']['provider_symbols']
    return {'pinned': old, 'current': current, 'populated_selectors_compared': len(EXPECTED_SELECTORS),
            'static_metadata_matches': True, 'native_method_observed': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('current_collection', type=Path)
    parser.add_argument('--pinned-collection', type=Path, default=CACHE)
    args = parser.parse_args()
    print(json.dumps(compare(args.pinned_collection, args.current_collection), indent=2, sort_keys=True))
