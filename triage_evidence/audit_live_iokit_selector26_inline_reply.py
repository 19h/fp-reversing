#!/usr/bin/env python3
"""Capture current-image evidence for the nominal selector 26 inline reply."""

import argparse
import json
from pathlib import Path

from audit_live_iokit_mach_transport import CACHE_UUID, dyld_uuid
from audit_live_kext_selector26 import Collection, IDENTITIES, mig_map
from audit_live_kext_selector26_transfer import words
from bootpolicy_cache_reader import CS, Cache


def capture(path):
    image = Collection(path, IDENTITIES[1])
    routine = mig_map(image)['routines'][2865]
    assert routine['fields'] == [17, 0, 0, 4284]
    for pc, target in (
        (0xfffffe000bd3c310, 0xfffffe000bd0a43c),
        (0xfffffe000bd0a590, 0xfffffe000bd464ac),
        (0xfffffe000bd465cc, 0xfffffe000bdbdb58),
        (0xfffffe000bdbdc10, 0xfffffe000bce59c0),
        (0xfffffe000be816b4, 0xfffffe000c5bff74),
        (0xfffffe000c5c0120, 0xfffffe000c6979c0),
    ):
        assert image.branch(pc, 'bl') == target
    assert '_bzero' in image.names(0xfffffe000c6979c0)
    for pc, mnemonic, operands in (
        (0xfffffe000bd3c2fc, 'ldp', 'w0, w25, [x24, #0x10]'),
        (0xfffffe000bd3c30c, 'mov', 'w3, #0xb'),
        (0xfffffe000bd0a56c, 'bfi', 'w21, w8, #2, #1'),
        (0xfffffe000bd0a588, 'mov', 'x2, x21'),
        (0xfffffe000bd3c388, 'ldr', 'x16, [x17, #0xf0]!'),
        (0xfffffe000bd3c394, 'autda', 'x16, x17'),
        (0xfffffe000bd3c71c, 'mov', 'x4, x25'),
        (0xfffffe000bdbdbac, 'ldrh', 'w19, [x0, #0x34]'),
        (0xfffffe000bdbdc0c, 'mov', 'x1, x19'),
        (0xfffffe000bce5a44, 'umaxv', 'b0, v4.16b'),
        (0xfffffe000be81654, 'str', 'w8, [x24, #0xc]!'),
        (0xfffffe000be8168c, 'add', 'x8, x24, #4'),
        (0xfffffe000be816b0, 'stp', 'x8, x24, [sp]'),
        (0xfffffe000c5c0128, 'str', 'x8, [sp, #0x88]'),
        (0xfffffe000c5c0134, 'str', 'w24, [sp, #0x90]'),
    ):
        image.instruction(pc, mnemonic, operands)

    cache = Cache()
    assert cache.uuid == CACHE_UUID == dyld_uuid()
    copyout_pc, copyout_size = 0x184ebe15c, 0xb0
    framework_words = list(CS.disasm(cache.read(copyout_pc, copyout_size), copyout_pc))
    assert len(framework_words) * 4 == copyout_size
    return {
        'kernel_identity': IDENTITIES[1],
        'shared_cache_uuid': CACHE_UUID,
        'mig_record_2865': routine,
        'scope': 'Static code and fixup evidence. No live reply values.',
        'kernel_windows': {
            name: words(image, pc, size)
            for name, pc, size in (
                ('dispatcher_alloc_and_body', 0xfffffe000bd3c2fc, 0xe8),
                ('dispatcher_stub_arguments', 0xfffffe000bd3c6fc, 0x2c),
                ('split_constructor', 0xfffffe000bd0a43c, 0x2d8),
                ('typed_allocator', 0xfffffe000bd464ac, 0x1ec),
                ('zone_cache', 0xfffffe000bdbdb58, 0x11c),
                ('zero_reduction', 0xfffffe000bce59c0, 0x9c),
                ('mig_stub_inline_arguments_and_reply', 0xfffffe000be81620, 0x13c),
                ('iokit_method_arguments', 0xfffffe000c5bff74, 0x2b0),
                ('selector_26_handler', 0xfffffe000a5451c4, 0xa0),
            )
        },
        'framework_reply_copy': [
            {'pc': hex(word.address), 'word': word.bytes.hex(),
             'mnemonic': word.mnemonic, 'operands': word.op_str}
            for word in framework_words
        ],
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    print(json.dumps(capture(parser.parse_args().collection), indent=2))
