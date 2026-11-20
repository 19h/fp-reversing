#!/usr/bin/env python3
"""Check the executable offset producer and its observed daemon data flow."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import subprocess

from audit_live_fairplay_reply_rights import compiler_ranges
from audit_live_kext_selector26 import Collection, IDENTITIES
from audit_live_kext_selector26_transfer import words

IMAGE_ACTIVATE = 0xfffffe000c2f3c08
FAT_ACTIVATE = 0xfffffe000c2ebe5c
RESET_TEXT = 0xfffffe000c2f4a4c
DAEMON_SHA = '4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
PROFILE_SHA = 'ed6633a3046bdb7080822d10afa65f8fd1ca3e47a0d4ab15ea28efb9c506d5bc'


def profile_evidence(path):
    compressed = path.read_bytes()
    digest = sha256(compressed).hexdigest()
    assert digest == PROFILE_SHA
    data = json.loads(subprocess.check_output(['zstd', '-dcq'], input=compressed))
    profiles = {profile['label']: profile for profile in data['profiles']}
    cases = {'default': 0x1122334455667788, 'opaque0': 0, 'opaquemax': 0xffffffffffffffff,
             'path_one': 0x1122334455667788}
    outputs = {}
    payloads = {}
    for label, expected_offset in cases.items():
        profile = profiles[label]
        seed = profile['seed']
        baseline = profiles['default']['seed']
        changed = {key for key in seed if seed[key] != baseline[key]}
        expected_changes = {'synthetic_ool_prefix'} if label == 'path_one' else {'opaque'}
        assert changed == (set() if label == 'default' else expected_changes)
        assert int(seed['opaque'], 16) == expected_offset
        assert profile['source_sha256'] == DAEMON_SHA
        assert profile['stop_reason'] == 'outgoing_arcade_xpc_message_boundary'
        assert not profile['native_target_executed'] and not profile['target_host_operations_executed']
        argument, = (row for row in profile['records'] if row['kind'] == 'native_subscription_argument_record')
        raw = bytes.fromhex(argument['argument_bytes_40'])
        assert len(raw) == 40 and int.from_bytes(raw[24:32], 'little') == expected_offset
        reads = [row for row in profile['records'] if row['kind'] == 'native_argument_read']
        assert sorted(row['offset_bytes'] for row in reads) == [0, 8, 32]
        assert all(row['offset_bytes'] + row['size_bytes'] <= 24 or row['offset_bytes'] >= 32 for row in reads)

        setter, = (call for call in profile['calls'] if call['name'] == 'libSystem/_xpc_dictionary_set_data')
        sender, = (call for call in profile['calls'] if call['name'] == 'libSystem/_xpc_connection_send_message_with_reply_sync')
        assert (setter['return_pc'], sender['return_pc']) == ('0x10077e5c8', '0x10077e618')
        fields = sender['message']['fields']
        assert setter['key'] == 'data' and set(fields) == {'data'} and fields['data']['kind'] == 'data'
        assert fields['data']['value'] == setter['value']
        payload = bytes.fromhex(setter['value']['bytes'])
        assert len(payload) == setter['value']['size_bytes']
        payloads[label] = payload
        outputs[label] = {'offset': hex(expected_offset), 'size_bytes': len(payload),
                          'payload_sha256': sha256(payload).hexdigest(), 'record_reads': reads}
    assert payloads['default'] == payloads['opaque0'] == payloads['opaquemax']
    assert payloads['path_one'] != payloads['default']
    assert (outputs['default']['size_bytes'], outputs['path_one']['size_bytes']) == (160, 112)
    return {'profiles_sha256': digest, 'daemon_sha256': DAEMON_SHA, 'cases': outputs}


def audit(image, profiles):
    getter = image.named('_proc_getexecutableoffset')
    assert getter == 0xfffffe000c30bb64
    anchors = (
        (0xfffffe000c2f2b18, 'mov', 'x0, x27'),
        (0xfffffe000c2f2e70, 'mov', 'x0, x26'),
        (0xfffffe000c2f2e74, 'mov', 'x1, x27'),
        (0xfffffe000c2f5f10, 'mov', 'x0, x20'),
        (0xfffffe000c2f6090, 'mov', 'x0, x21'),
        (0xfffffe000c2f6094, 'mov', 'x1, x20'),
        (0xfffffe000c2f3fbc, 'str', 'xzr, [x19, #0x90]'),
        (0xfffffe000c2f3fc4, 'str', 'x9, [x19, #0x98]'),
        (0xfffffe000c2f4128, 'mov', 'x0, x19'),
        (0xfffffe000c2f4130, 'cmn', 'w0, #2'),
        (0xfffffe000c2f4134, 'b.eq', '#0xfffffe000c2f4104'),
        (0xfffffe000c2ebec4, 'ldr', 'w8, [x22]'),
        (0xfffffe000c2ebec8, 'mov', 'w9, #0xfeca'),
        (0xfffffe000c2ebecc, 'movk', 'w9, #0xbeba, lsl #16'),
        (0xfffffe000c2ebed0, 'cmp', 'w8, w9'),
        (0xfffffe000c2ec064, 'add', 'x5, sp, #0x10'),
        (0xfffffe000c2ec088, 'ldr', 'w4, [sp, #0x18]'),
        (0xfffffe000c2ec0e8, 'ldp', 'd1, d0, [sp, #0x10]'),
        (0xfffffe000c2ec0ec, 'ushll', 'v0.2d, v0.2s, #0'),
        (0xfffffe000c2ec0f0, 'str', 'q0, [x19, #0x90]'),
        (0xfffffe000c2ec0f8, 'mov', 'w19, #-2'),
        (0xfffffe000c2f4a6c, 'mov', 'x20, x0'),
        (0xfffffe000c2f4a8c, 'ldr', 'x23, [x1, #0x20]'),
        (0xfffffe000c2f4a94, 'ldr', 'x24, [x1, #0x90]'),
        (0xfffffe000c2f4acc, 'cbz', 'w0, #0xfffffe000c2f4b20'),
        (0xfffffe000c2f4ad4, 'mov', 'x24, #0'),
        (0xfffffe000c2f4b1c, 'cbnz', 'w0, #0xfffffe000c2f4ad0'),
        (0xfffffe000c2f4b28, 'pacda', 'x17, x16'),
        (0xfffffe000c2f4b2c, 'str', 'x17, [x20, #0x598]'),
        (0xfffffe000c2f4b30, 'str', 'x24, [x20, #0x5a0]'),
        (getter + 4, 'ldr', 'x0, [x0, #0x5a0]'),
        (0xfffffe000bd29c94, 'ldr', 'x3, [x27, #0x5a0]'),
        (0xfffffe000bdda304, 'str', 'x3, [sp, #0x40]'),
    )
    for pc, opcode, operands in anchors:
        image.instruction(pc, opcode, operands)
    calls = {
        0xfffffe000c2f2b1c: IMAGE_ACTIVATE,
        0xfffffe000c2f2e78: RESET_TEXT,
        0xfffffe000c2f5f14: IMAGE_ACTIVATE,
        0xfffffe000c2f6098: RESET_TEXT,
        0xfffffe000c2f412c: FAT_ACTIVATE,
        0xfffffe000c2ec074: 0xfffffe000c3a5268,
        0xfffffe000c2ec0b0: image.named('_vn_rdwr_64'),
        0xfffffe000c2f4aa4: 0xfffffe000bf86f24,
        0xfffffe000bd29cb0: 0xfffffe000bdda298,
        0xfffffe000bdda33c: 0xfffffe000bd3d8d4,
    }
    for site, target in calls.items():
        assert image.branch(site, 'bl') == target

    bounds = compiler_ranges(image)
    regions = {hex(start): (start, bounds[start][1] - start) for start in (FAT_ACTIVATE, RESET_TEXT, getter)}
    regions.update({'image_initialization': (0xfffffe000c2f3fac, 0x20),
                    'activator_dispatch': (0xfffffe000c2f4104, 0x38),
                    'spawn_activation': (0xfffffe000c2f2b18, 8),
                    'spawn_publish': (0xfffffe000c2f2e70, 12),
                    'exec_activation': (0xfffffe000c2f5f10, 8),
                    'exec_publish': (0xfffffe000c2f6090, 12),
                    'upcall_arguments': (0xfffffe000bd29c94, 0x20),
                    'upcall_pack_and_submit': (0xfffffe000bdda304, 0x3c)})
    diagnostic = b'exec_resettextvp: expected valid vp'
    assert image.read(0xfffffe00070ae553, len(diagnostic)) == diagnostic
    return {'identity': IDENTITIES[1], 'instruction_assertions': len(anchors),
            'direct_calls': {hex(site): hex(target) for site, target in calls.items()},
            'windows': {role: words(image, start, size) for role, (start, size) in regions.items()},
            'retained_profile_checks': profile_evidence(profiles)}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    parser.add_argument('profiles', type=Path)
    args = parser.parse_args()
    print(json.dumps(audit(Collection(args.collection, IDENTITIES[1]), args.profiles), indent=2))
