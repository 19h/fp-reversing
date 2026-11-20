#!/usr/bin/env python3
"""Recover ordinary spawn and exec producers of the current Arcade AST."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import struct

from audit_live_fairplay_reply_rights import compiler_ranges
from audit_live_kext_selector26 import Collection, IDENTITIES
from audit_live_kext_selector26_transfer import address_pair, words

SYSENT = 0xfffffe0007f39230
SYSCALL_NAMES = 0xfffffe000cb1b0e8
AST_HANDLER = 0xfffffe000bd29e80
ARCADE_HANDOFF = 0xfffffe000bd29958
USER_RETURN = 0xfffffe000bce4038
ENTITLEMENT = 0xfffffe000704a90a
SYSCALLS = (
    (59, 'execve', 0xfffffe000c2f5c74, 3),
    (244, 'posix_spawn', 0xfffffe000c2f09f4, 5),
    (380, '__mac_execve', 0xfffffe000c2f5ca8, 4),
)
WRITERS = (
    (0xfffffe000c2f1bd8, 'x27', 'x19', 'x21', 0xfffffe000c2f09f4),
    (0xfffffe000c2f63b8, 'x20', 'x23', 'x25', 0xfffffe000c2f5ca8),
)


def syscall_table(image):
    source = Path(__file__).with_name('xnu_dispatch_reference_bsd_kern_syscalls.master.txt').read_bytes()
    assert address_pair(image, 0xfffffe000c48a954, 'x9') == SYSENT
    for address, mnemonic, operand in (
        (0xfffffe000c48a94c, 'and', 'x8, x28, #0xffff'),
        (0xfffffe000c48a950, 'add', 'x8, x8, w28, uxth #1'),
        (0xfffffe000c48a95c, 'add', 'x23, x9, x8, lsl #3'),
        (0xfffffe000c48aafc, 'ldr', 'x8, [x23]'),
        (0xfffffe000c48ab0c, 'mov', 'x17, #0xbcad'),
        (0xfffffe000c48ab10, 'blraa', 'x8, x17'),
    ):
        image.instruction(address, mnemonic, operand)
    rows = {}
    for number, name, entry, argc in SYSCALLS:
        assert re.search(rf'^\s*{number}\s+\S+\s+ALL\s+\{{\s+int\s+{name}\(', source.decode(), re.M)
        address = SYSENT + 24 * number
        record = image.read(address, 24)
        pointer = image.pointer(address)
        name_pointer = image.pointer(SYSCALL_NAMES + 8 * number)
        assert (int(pointer['target'], 16), pointer['auth'], pointer['key'], pointer['diversity']) == (
            entry, 1, 0, '0xbcad')
        assert image.read(int(name_pointer['target'], 16), len(name) + 1) == name.encode() + b'\0'
        assert struct.unpack_from('<IHH', record, 16) == (1, argc, argc * 4)
        rows[number] = {'name': name, 'row': record.hex(), 'handler_fixup': pointer, 'name_fixup': name_pointer,
                        'argument_count': argc, 'compat_argument_bytes': argc * 4}
    assert image.branch(0xfffffe000c2f5c98, 'bl') == SYSCALLS[-1][2]
    return {'syscalls': rows, 'source_sha256': sha256(source).hexdigest(),
            'indexing': words(image, 0xfffffe000c48a94c, 20),
            'invoke': words(image, 0xfffffe000c48aafc, 24),
            'execve_forwarder': words(image, SYSCALLS[0][2], SYSCALLS[2][2] - SYSCALLS[0][2])}


def writer_census(image):
    text = next(segment for segment in image.root['segments'] if segment['name'] == '__TEXT_EXEC')
    base, size, offset = text['address'], text['file_size'], text['file_offset']
    code = memoryview(image.data)[offset:offset + size]
    triples, callers = {}, {}
    for index, (word,) in enumerate(struct.iter_unpack('<I', code)):
        pc = base + 4 * index
        if word >> 26 in (5, 37):
            target = pc + 4 * ((word & 0x1ffffff) - (word & 0x2000000))
            if target in (USER_RETURN, AST_HANDLER, ARCADE_HANDOFF):
                callers[pc] = target
        if word & 0xfffffc00 != 0x9110f000 or 4 * index + 12 > size:
            continue
        move, atomic = struct.unpack_from('<II', code, 4 * index + 4)
        if move & 0xffe00000 != 0x52800000 or atomic & 0xff20fc00 != 0xb8203000:
            continue
        if (move & 31) != (atomic >> 16) & 31 or (word & 31) != (atomic >> 5) & 31:
            continue
        triple = words(image, pc, 12)
        assert triple[0]['mnemonic'] == 'add' and triple[2]['mnemonic'].startswith(('ldset', 'stset'))
        triples[pc] = {'mask': (move >> 5) & 0xffff, 'instructions': triple}
    assert callers == {0xfffffe000bce3d30: USER_RETURN, 0xfffffe000bce4040: AST_HANDLER,
                       0xfffffe000bd29f84: ARCADE_HANDOFF}
    assert {pc for pc, triple in triples.items() if triple['mask'] & 0x800} == {
        start + 0x24 for start, *_ in WRITERS}
    assert any(triple['mask'] == 0x40 for triple in triples.values())
    return {'segment_address': hex(base), 'instruction_words': size // 4, 'segment_sha256': sha256(code).hexdigest(),
            'immediate_branches': {hex(pc): hex(dest) for pc, dest in callers.items()},
            'matched_triples': {hex(pc): triple for pc, triple in triples.items()}}


def event_path(image):
    platform_query = image.named('_task_get_platform_binary')
    entitlement_query = image.named('_IOTaskHasEntitlement')
    literal = b'com.apple.developer.arcade-operations\0'
    assert image.read(ENTITLEMENT, len(literal)) == literal
    bounds = compiler_ranges(image)
    producers = []
    for start, image_params, task, thread, function in WRITERS:
        assert function <= start < bounds[function][1]
        assert image.branch(start + 8, 'bl') == platform_query
        assert image.branch(start + 0x1c, 'bl') == entitlement_query
        assert address_pair(image, start + 0x10, 'x1') == ENTITLEMENT
        for offset, mnemonic, operands in (
            (0, 'ldr', f'{thread}, [{image_params}, #0x2b8]'),
            (4, 'mov', f'x0, {task}'),
            (0xc, 'cbnz', f'w0, #{start + 0x30:#x}'),
            (0x18, 'mov', f'x0, {task}'),
            (0x20, 'cbz', f'w0, #{start + 0x30:#x}'),
            (0x24, 'add', f'x8, {thread}, #0x43c'),
            (0x28, 'mov', 'w9, #0x800'),
            (0x2c, 'ldset', 'w9, w8, [x8]'),
        ):
            image.instruction(start + offset, mnemonic, operands)
        end = bounds[function][1]
        producers.append({'function_start': hex(function), 'function_end': hex(end),
                          'function_sha256': sha256(image.read(function, end - function)).hexdigest(),
                          'instructions': words(image, start, 0x30)})

    for address, mnemonic, operands in (
        (0xfffffe000bce3cf8, 'ldr', 'x4, [x3, #0x1c0]'),
        (0xfffffe000bce3cfc, 'ldr', 'w0, [x4, #0x4c]'),
        (0xfffffe000bce3d04, 'cbz', 'x28, #0xfffffe000bce4038'),
        (0xfffffe000bd29e98, 'mrs', 'x19, tpidr_el1'),
        (0xfffffe000bd29ee4, 'ldr', 'w10, [x19, #0x43c]'),
        (0xfffffe000bd29ee8, 'orr', 'w8, w8, w10'),
        (0xfffffe000bd29eec, 'str', 'w8, [x9, #0x4c]'),
        (0xfffffe000bd29f1c, 'tbnz', 'w21, #0xb, #0xfffffe000bd29f78'),
        (0xfffffe000bd29f78, 'add', 'x8, x19, #0x43c'),
        (0xfffffe000bd29f7c, 'mov', 'w9, #0x800'),
        (0xfffffe000bd29f80, 'ldclr', 'w9, w8, [x8]'),
        (0xfffffe000bd29c2c, 'ldr', 'x27, [x0, #0x18]'),
        (0xfffffe000bd29c54, 'mov', 'x0, x27'),
        (0xfffffe000bd29c5c, 'mov', 'w3, #0x1000'),
        (0xfffffe000c3bc500, 'ldr', 'x16, [x0, #0x598]'),
    ):
        image.instruction(address, mnemonic, operands)
    assert image.branch(0xfffffe000bce4040, 'bl') == AST_HANDLER
    assert image.branch(0xfffffe000bd29f84, 'bl') == ARCADE_HANDOFF
    assert image.branch(0xfffffe000bd29c60, 'bl') == 0xfffffe000c3bc4e4
    assert image.branch(0xfffffe000c3bc530, 'bl') == image.named('_vnode_getwithvid')
    spans = ((0xfffffe000bce3ce8, 0x4c), (USER_RETURN, 0x18), (AST_HANDLER, bounds[AST_HANDLER][1] - AST_HANDLER),
             (0xfffffe000bd29c28, 0x3c), (0xfffffe000c3bc500, 0x38))
    return {'producer_blocks': producers, 'entitlement_literal': literal.rstrip(b'\0').decode(),
            'platform_query': hex(platform_query), 'entitlement_query': hex(entitlement_query),
            'downstream_windows': {hex(start): words(image, start, size) for start, size in spans}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    image = Collection(parser.parse_args().collection, IDENTITIES[1])
    print(json.dumps({'identity': IDENTITIES[1], 'syscall_table': syscall_table(image),
                      'writer_census': writer_census(image), 'event_path': event_path(image)},
                     indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
