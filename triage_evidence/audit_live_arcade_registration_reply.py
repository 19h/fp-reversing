#!/usr/bin/env python3
"""Check Arcade registration dispatch and the kernel's status reply submission."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct

from audit_live_arcade_registration import REGISTRY_SLOT, SUBSYSTEM
from audit_live_kext_selector26 import Collection, IDENTITIES
from audit_live_kext_selector26_transfer import address_pair, words

REGISTRY = 0xfffffe000caff018
BUCKETS = 0xfffffe0007e68ab8
CAPACITY = 1031
REQUEST = 51471
STUB = 0xfffffe000bdda404
SERVER = 0xfffffe000bd3c048
INIT = 0xfffffe000c679d60


def rebuild_registry(image):
    original = image.read(BUCKETS, 24 * CAPACITY)
    assert not any(original)
    entries = {}
    ids = set()
    subsystems = []
    largest_probe = 0
    for index in range(20):
        pointer = image.pointer(REGISTRY + 8 * index)
        record = int(pointer['target'], 16)
        start, end, maximum = struct.unpack('<III', image.read(record + 8, 12))
        assert 0 < start <= end and maximum <= 0x3fbc
        populated = 0
        for routine_index in range(end - start):
            slot = record + 40 + routine_index * 32
            if not any(image.read(slot, 8)):
                continue
            message_id = start + routine_index
            assert message_id not in ids
            ids.add(message_id)
            populated += 1
            bucket = message_id % CAPACITY
            probes = 1
            while bucket in entries:
                bucket = (bucket + 1) % CAPACITY
                probes += 1
                assert probes <= CAPACITY
            reply_descriptors, reply_size = struct.unpack('<II', image.read(slot + 16, 8))
            assert 44 <= reply_size <= maximum
            entries[bucket] = {'id': message_id, 'pointer_slot': hex(slot), 'filter_index_initial': -1,
                               'reply_size': reply_size, 'reply_descriptors': reply_descriptors,
                               'probes': probes}
            largest_probe = max(probes, largest_probe)
        subsystems.append({'pointer': pointer, 'start': start, 'end_exclusive': end,
                           'maximum_reply_size': maximum, 'populated': populated})
    assert len(entries) == 358
    assert REGISTRY + 8 * 17 == REGISTRY_SLOT
    assert int(subsystems[17]['pointer']['target'], 16) == SUBSYSTEM
    bucket = REQUEST % CAPACITY
    result = entries[bucket]
    assert (bucket, result['id'], result['probes']) == (952, REQUEST, 1)
    assert (result['reply_size'], result['reply_descriptors']) == (44, 0)
    routine = image.pointer(int(result['pointer_slot'], 16))
    assert (int(routine['target'], 16), routine['auth'], routine['key'], routine['diversity']) == (
        STUB, 1, 0, '0x3a83')
    return {'subsystems': subsystems, 'buckets': CAPACITY, 'width': 24, 'populated': len(entries),
            'maximum_probe_count': largest_probe, 'initial_bytes_sha256': sha256(original).hexdigest(),
            'arcade': result | {'bucket': bucket, 'address': hex(BUCKETS + 24 * bucket), 'routine': routine}}


def audit(image):
    assert address_pair(image, INIT + 0x18, 'x9') == REGISTRY
    assert address_pair(image, INIT + 0x40, 'x0') == BUCKETS
    assert address_pair(image, 0xfffffe000bd3c24c, 'x12') == BUCKETS

    anchors = (
        (0xfffffe000c679d8c, 'mov', 'w13, #0x407'),
        (0xfffffe000c679d90, 'mov', 'w14, #0x18'),
        (0xfffffe000c679de4, 'ldr', 'x16, [x4, x5]'),
        (0xfffffe000c679e7c, 'str', 'w6, [x19]'),
        (0xfffffe000c679e84, 'str', 'x5, [x19, #8]'),
        (0xfffffe000c679e94, 'str', 'w5, [x19, #0x10]'),
        (0xfffffe000c679ea0, 'str', 'w16, [x19, #0x14]'),
        (0xfffffe000c679ea4, 'str', 'w17, [x19, #4]'),
        (0xfffffe000c679ed4, 'cmp', 'x8, #0x14'),
        (0xfffffe000bd3c22c, 'ldr', 'w28, [x22, #0x1c]'),
        (0xfffffe000bd3c244, 'mov', 'w10, #0x407'),
        (0xfffffe000bd3c248, 'mov', 'w11, #0x18'),
        (0xfffffe000bd3c284, 'cmp', 'w28, w14'),
        (0xfffffe000bd3c2fc, 'ldp', 'w0, w25, [x24, #0x10]'),
        (0xfffffe000bd3c654, 'mov', 'w9, #0x2c'),
        (0xfffffe000bd3c660, 'ubfx', 'w9, w9, #8, #5'),
        (0xfffffe000bd3c668, 'ldr', 'x9, [x8, #0x10]'),
        (0xfffffe000bd3c66c, 'stp', 'x9, xzr, [x16, #8]'),
        (0xfffffe000bd3c678, 'add', 'w8, w8, #0x64'),
        (0xfffffe000bd3c67c, 'str', 'w8, [x16, #0x1c]'),
        (0xfffffe000bd3c708, 'ldr', 'x8, [x24, #8]'),
        (0xfffffe000bd3c720, 'mov', 'x17, #0x3a83'),
        (0xfffffe000bd3c724, 'blraa', 'x8, x17'),
        (0xfffffe000bdda4a8, 'str', 'w0, [x19, #8]'),
        (0xfffffe000bd3c574, 'ldr', 'w8, [x16, #0x28]'),
        (0xfffffe000bd3c580, 'mov', 'w1, #3'),
        (0xfffffe000bd3c5c0, 'ldr', 'x8, [x16, #8]'),
        (0xfffffe000bd3c5f8, 'b.eq', '#0xfffffe000bd3c5d0'),
        (0xfffffe000bd0f304, 'mov', 'x19, x0'),
        (0xfffffe000bd0f36c, 'mov', 'x19, x0'),
        (0xfffffe000bd0f3b0, 'mov', 'x1, #0'),
        (0xfffffe000bd0f3b8, 'ldr', 'x20, [x20, #8]'),
        (0xfffffe000bd0f444, 'mov', 'x1, #0'),
        (0xfffffe000bd0f44c, 'ldr', 'x20, [x20, #8]'),
        (0xfffffe000bd0f1f8, 'add', 'x0, x20, #0x28'),
        (0xfffffe000bd0f1fc, 'mov', 'x1, x19'),
        (0xfffffe000bd0f200, 'mov', 'x2, x21'),
        (0xfffffe000bd0f204, 'mov', 'x3, x22'),
    )
    for pc, opcode, operands in anchors:
        image.instruction(pc, opcode, operands)

    calls = {
        0xfffffe000bd0f2fc: SERVER,
        0xfffffe000bd0f364: SERVER,
        0xfffffe000bd0f3b4: 0xfffffe000bd0c150,
        0xfffffe000bd0f448: 0xfffffe000bd0c150,
        0xfffffe000bd0f208: 0xfffffe000bd0fbf0,
        0xfffffe000bd3c4d4: image.named('_ipc_port_release_send'),
        0xfffffe000bdda4a4: 0xfffffe000bd29758,
    }
    for site, target in calls.items():
        assert image.branch(site, 'bl') == target

    windows = {
        'registry_initialization': (INIT, 0x26c),
        'kernel_object_server': (SERVER, 0x8b0),
        'arcade_stub': (STUB, 0xf0),
        'send_worker': (0xfffffe000bd0effc, 0x4dc),
        'destination_queue_send': (0xfffffe000bd0fbf0, 0x214),
    }
    return {'identity': IDENTITIES[1], 'fileset_sha256': sha256(image.data).hexdigest(),
            'registry': rebuild_registry(image), 'request_id': REQUEST, 'reply_id': REQUEST + 100,
            'instruction_assertions': len(anchors) + 3,
            'direct_calls': {hex(site): hex(target) for site, target in calls.items()},
            'windows': {role: words(image, start, size) for role, (start, size) in windows.items()},
            'native_exchange_observed': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    print(json.dumps(audit(Collection(parser.parse_args().collection, IDENTITIES[1])), indent=2))
