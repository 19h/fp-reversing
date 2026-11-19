#!/usr/bin/env python3
"""Join FairPlay's printed reset policy to installed launchd recovery and Mach ABI."""

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import plistlib
import re
import struct
import subprocess

from audit_daemon_iokit_native_registry import command, sysctl
from audit_fairplay_live_slice_identity import installed_slices
from audit_live_fairplay_adid_ipc import ThinView, reference
from audit_live_fairplay_cf_receive import assert_instructions
from audit_live_fairplay_reply_rights import compiler_ranges
from audit_live_host_special_publication import windows
from audit_live_iokit_mach_transport import CACHE_UUID, LIBKERNEL, Cache, Dylib, dyld_uuid
from audit_live_kext_selector26 import Collection, IDENTITIES
from audit_live_rpc700_publication import running_identity

EXPECTED_SLOTS = {'com.apple.unfreed': 17, 'com.apple.arcade.fpsd': 31}
SERVICE = 'com.apple.fairplayd'

LAUNCHD_CHECKS = (
    (0x100047108, 'stp', 'x23, x22, [x0, #0x90]'),
    (0x100047148, 'add', 'x16, x16, #0x844'),
    (0x10004715c, 'stp', 'x19, x20, [sp, #0x30]'),
    (0x100047168, 'bl', '#0x10005f504'),
    (0x10005c864, 'ldp', 'x20, x19, [x0, #0x20]'),
    (0x10005c934, 'add', 'x1, x1, #0x9f6'),
    (0x10005c940, 'cbz', 'w0, #0x10005ca10'),
    (0x10005ca18, 'ldrh', 'w9, [x20, #0xa0]'),
    (0x10005ca20, 'mov', 'w8, #0x10'),
    (0x10005ca24, 'csel', 'w8, w8, wzr, eq'),
    (0x10005ca28, 'and', 'w9, w9, #0xffffffef'),
    (0x10005ca64, 'strh', 'w8, [x20, #0xa0]'),
    (0x10004748c, 'ldr', 'w22, [x21, #0x54]'),
    (0x1000474ec, 'ldrh', 'w8, [x21, #0xa0]'),
    (0x100047500, 'tst', 'w8, #1'),
    (0x100047520, 'ldrh', 'w8, [x21, #0xa0]'),
    (0x100047524, 'tst', 'w8, #8'),
    (0x100047528, 'csel', 'x8, x23, x22, eq'),
    (0x100047544, 'ldrh', 'w8, [x21, #0xa0]'),
    (0x100047548, 'tst', 'w8, #0x10'),
    (0x10004754c, 'csel', 'x8, x22, x23, eq'),
    (0x100047558, 'add', 'x2, x2, #0x832'),
    (0x100046ed4, 'adrp', 'x16, #0x100047000'),
    (0x100046ed8, 'add', 'x16, x16, #0x858'),
    (0x100046eec, 'str', 'x19, [sp, #0x20]'),
    (0x100046ef8, 'bl', '#0x100045c0c'),
    (0x100045cc8, 'stp', 'x22, x20, [sp, #0x50]'),
    (0x100045cd4, 'bl', '#0x10005de34'),
    (0x100045e34, 'ldr', 'x0, [x19, #0x20]'),
    (0x100045e40, 'blraa', 'x9, x8'),
    (0x100045e48, 'bl', '#0x10005ddc4'),
    (0x100045e6c, 'b', '#0x10005c6ec'),
    (0x100045eb8, 'ldrb', 'w8, [x0, #0x29]'),
    (0x100045ec0, 'tbz', 'w8, #0, #0x100045edc'),
    (0x100045ee8, 'bl', '#0x10005e3d4'),
    (0x100047868, 'ldr', 'x19, [x0, #0x20]'),
    (0x10004786c, 'ldrh', 'w8, [x19, #0xa0]'),
    (0x100047870, 'tbnz', 'w8, #4, #0x1000478d0'),
    (0x10004787c, 'bl', '#0x100046c48'),
    (0x100047884, 'ldr', 'x1, [x19, #0x70]'),
    (0x100047888, 'bl', '#0x10000cf4c'),
    (0x10004789c, 'mov', 'w2, #4'),
    (0x1000478a0, 'mov', 'x3, #0'),
    (0x1000478a4, 'mov', 'w4, #0'),
    (0x1000478a8, 'bl', '#0x10005e454'),
    (0x1000478d4, 'bl', '#0x10005ccb8'),
    (0x1000478dc, 'and', 'w9, w8, #0xfffffffe'),
    (0x1000478e0, 'orr', 'w9, w9, #0x40'),
    (0x1000478e4, 'strh', 'w9, [x19, #0xa0]'),
    (0x1000478e8, 'tbz', 'w8, #8, #0x100047900'),
    (0x1000478f0, 'bl', '#0x10005cedc'),
    (0x1000478f8, 'and', 'w8, w8, #0xfffffeff'),
    (0x10005cf1c, 'mov', 'w22, #0x14'),
    (0x10005cf3c, 'mov', 'w1, #0x102'),
    (0x10005cf40, 'mov', 'w2, #0'),
    (0x10005cf44, 'mov', 'w3, #0x20'),
    (0x10005cf54, 'bl', '#0x10005e374'),
    (0x10005cf84, 'bl', '#0x10005e394'),
    (0x100047900, 'ldp', 'x3, x2, [x19, #0x90]'),
    (0x100047908, 'mov', 'w1, #1'),
    (0x100047924, 'braaz', 'x3'),
    (0x10000cf78, 'mov', 'w2, #8'),
    (0x10000cf7c, 'mov', 'w4, #2'),
    (0x10000cf80, 'bl', '#0x10005e3b4'),
    (0x10005ccf0, 'str', 'xzr, [x19, #0x68]'),
    (0x10005cd3c, 'add', 'x16, x16, #0xa4c'),
    (0x10005cd5c, 'bl', '#0x10005dc04'),
    (0x100047a7c, 'mov', 'w2, #0'),
    (0x100047a80, 'bl', '#0x10005e3e4'),
    (0x10002a6c8, 'add', 'x16, x16, #0x950'),
    (0x10002a6d8, 'bl', '#0x100047084'),
    (0x10002aa34, 'b', '#0x10005aab0'),
    (0x10005aae0, 'ldrsh', 'w9, [x20, #0x12c]'),
    (0x10005aaf0, 'strh', 'w10, [x20, #0x12c]'),
    (0x10005ad14, 'bl', '#0x100030778'),
    (0x10005ad18, 'ldrh', 'w8, [x19, #0xb0]'),
    (0x10005ad1c, 'cbnz', 'w8, #0x10005ab18'),
    (0x10005ad20, 'ldr', 'w8, [x20, #0x120]'),
    (0x10005ad4c, 'b', '#0x10005af58'),
    (0x10005af60, 'str', 'wzr, [x0, #0x120]'),
    (0x10005af70, 'b', '#0x100021eb4'),
    (0x1000307a0, 'bl', '#0x100047620'),
    (0x100047658, 'b.ne', '#0x100047668'),
    (0x100047674, 'strh', 'w8, [x19, #0xa0]'),
    (0x1000476bc, 'b', '#0x10005cd94'),
)

KERNEL_CHECKS = (
    (0xfffffe000bdd0300, 'bl', '#0xfffffe000bd27a50'),
    (0xfffffe000bdcee0c, 'bl', '#0xfffffe000bd28e38'),
    (0xfffffe000bd27a8c, 'cmp', 'w2, #4'),
    (0xfffffe000bd27aa8, 'bl', '#0xfffffe000bd142b4'),
    (0xfffffe000bd27cf0, 'orr', 'w8, w10, #0x300'),
    (0xfffffe000bd27cf4, 'str', 'w8, [x9, #0x10]'),
    (0xfffffe000bd28e54, 'cmp', 'w2, #8'),
    (0xfffffe000bd28e5c, 'cmp', 'w4, #2'),
    (0xfffffe000bd28e90, 'bl', '#0xfffffe000bd142b4'),
    (0xfffffe000bd28ea0, 'tbz', 'w9, #0xa, #0xfffffe000bd28ef8'),
    (0xfffffe000bd28ea4, 'ldr', 'x20, [x8, #0x78]'),
    (0xfffffe000bd28ea8, 'tbz', 'w9, #0xb, #0xfffffe000bd28ed8'),
    (0xfffffe000bd28eac, 'ldr', 'x9, [x21]'),
    (0xfffffe000bd28eb0, 'cmp', 'x20, x9'),
    (0xfffffe000bd28eb4, 'b.ne', '#0xfffffe000bd28ed8'),
    (0xfffffe000bd28ec8, 'mov', 'w0, #0'),
)


def launchd_evidence(path):
    identity = running_identity({'pid': 1}, path, installed_slices(path))
    row = identity['matched_slice']
    assert row['arch'] == 'arm64e'
    assert row['sha256'] == 'd35f01f9669f314a1058e17acca27d3141ba8be1b0ca0d9e9d5edbb787607243'
    with path.open('rb') as source:
        source.seek(row['file_offset_bytes'])
        image = ThinView(source.read(row['slice_size_bytes']))
    strings = {0x1000759f6: 'ResetAtClose', 0x100075832: 'reset = %s',
               0x100075825: 'managed = %s'}
    for address, literal in strings.items():
        assert image.read(address, len(literal) + 1) == literal.encode() + b'\0'
    checks = assert_instructions(image.read, LAUNCHD_CHECKS)
    prior = reference('port_destroyed_return_source')
    previous_drain = {}
    for variant in prior['variants']:
        instructions = variant['roles']['endpoint_reset']['instructions']
        branch, = (i for i in instructions if i['mnemonic'] == 'tbz' and i['operands'].startswith('w8, #8,'))
        branch_index = instructions.index(branch)
        assert instructions[branch_index + 2]['operands'] == '#' + variant['roles']['receive_drain']['start']
        previous_drain[variant['label']] = branch
    return dict(identity=identity, strings={hex(k): v for k, v in strings.items()},
                checks=checks, previous_drain=previous_drain, windows=windows(image.read, {
                    'config_boolean': (0x10005ca10, 0x20),
                    'report_flags': (0x1000474ec, 0x80),
                    'activation_block': (0x100046ed0, 0x2c),
                    'notification_event_block': (0x100045e00, 0x80),
                    'notification_cancel_block': (0x100045e80, 0xb8),
                    'endpoint_return_block': (0x100047858, 0xd0),
                    'endpoint_rearm': (0x100047620, 0xa4),
                }))


def kernel_evidence(path):
    image = Collection(path, IDENTITIES[1])
    assert sysctl('kern.uuid').lower() == IDENTITIES[1][1]
    base = 0xfffffe0007e73b08
    assert image.pointer(0xfffffe000caff020)['target'] == hex(base)
    assert struct.unpack('<III', image.read(base + 8, 12)) == (3200, 3243, 576)
    entries = {}
    bounds = compiler_ranges(image)
    for identifier, stub, core in (
        (3218, 0xfffffe000bdd0264, 0xfffffe000bd27a50),
        (3242, 0xfffffe000bdced70, 0xfffffe000bd28e38),
    ):
        entry = base + 32 + (identifier - 3200) * 32
        pointer = image.pointer(entry + 8)
        assert int(pointer['target'], 16) == stub and pointer['auth'] == 1
        row = image.read(entry, 32)
        assert struct.unpack_from('<4I', row, 16) == (5, 0, 0, 44)
        entries[identifier] = dict(address=hex(entry), row=row.hex(), stub=pointer,
                                   windows=windows(image.read, {
                                       'stub': (stub, bounds[stub][1] - stub),
                                       'core': (core, bounds[core][1] - core),
                                   }))
    return dict(identity=IDENTITIES[1], entries=entries,
                checks=assert_instructions(image.read, KERNEL_CHECKS))


def library_evidence():
    cache = Cache()
    assert cache.uuid == CACHE_UUID == dyld_uuid()
    lib = Dylib(cache, LIBKERNEL)
    assert lib.uuid == '780a6c1f-be02-34cc-84dd-00e05f61c89b'
    result = {}
    for name, address, body, pins, identifier, words in (
        ('set', 0x18054b6f8, 0x18054b6fc, (0x18054b758, 0x18054b770, 0x18054b7ac, 0x18054b7b8),
         3218, 0),
        ('assert', 0x1805670b8, 0x18056fec8, (0x18056ff24, 0x18056ff3c, 0x18056ff78, 0x18056ff84),
         3242, 2),
    ):
        assert lib.exports[f'_mach_port_{name}_attributes']['address'] == address
        shift, extent, rpc_id, send = pins
        checks = assert_instructions(cache.read, (
            (address, 'b', f'#{hex(body)}'),
            (shift, 'lsl', 'w21, w4, #2'),
            (extent, 'add', 'w20, w21, #0x2c'),
            (rpc_id, 'mov', f'x4, #{hex(identifier << 32)}'),
            (send, 'bl', '#0x18055b918'),
        ))
        result[name] = dict(id=identifier, attribute_words=words, request_bytes=44 + 4 * words,
                            checks=checks, cache_uuid=cache.uuid, library_uuid=lib.uuid)
    return result


def observation(plist_path):
    plist_raw = plist_path.read_bytes()
    plist = plistlib.loads(plist_raw)
    assert plist['Label'] == SERVICE
    configuration = plist['MachServices']
    assert len(configuration) == 6 and plist['KeepAlive'] == {'Crashed': True}
    assert all(options is True or 'resetatclose' not in {key.casefold() for key in options}
               for options in configuration.values())
    expected_slots = {name: attrs['HostSpecialPort'] for name, attrs in configuration.items()
                      if isinstance(attrs, dict) and 'HostSpecialPort' in attrs}
    assert expected_slots == EXPECTED_SLOTS
    started = datetime.now(timezone.utc).isoformat()
    text = command('launchctl', 'print', 'system/' + SERVICE).decode()
    ended = datetime.now(timezone.utc).isoformat()
    body, = re.findall(r'^\tendpoints = \{\n(.*?)^\t\}$', text, re.M | re.S)
    rows = {}
    for name, fields in re.findall(r'^\t\t"([^"]+)" = \{\n(.*?)^\t\t\}$', body, re.M | re.S):
        bits = {key: int(value) for key, value in re.findall(
            r'^\t\t\t(active|managed|reset|watching|hide) = ([01])$', fields, re.M)}
        assert set(bits) == {'active', 'managed', 'reset', 'watching', 'hide'}
        slots = re.findall(r'^\t\t\thost-special port = (\d+)', fields, re.M)
        assert len(slots) <= 1
        rows[name] = dict(host_slot=int(slots[0]) if slots else None, **bits)
    assert rows.keys() == configuration.keys()
    assert {name: row['host_slot'] for name, row in rows.items() if row['host_slot']} == EXPECTED_SLOTS
    state, = re.findall(r'^\tstate = (.+)$', text, re.M)
    runs, = re.findall(r'^\truns = (\d+)$', text, re.M)
    last_exit, = re.findall(r'^\tlast exit code = (.+)$', text, re.M)
    return dict(started_utc=started, ended_utc=ended, plist_sha256=sha256(plist_raw).hexdigest(),
                launchctl_output_sha256=sha256(text.encode()).hexdigest(),
                job=SERVICE, state=state, runs=int(runs), never_exited=last_exit == '(never exited)',
                mach_services=configuration, keep_alive=plist['KeepAlive'], endpoints=rows)


def verify_sdk():
    src = b"""#include <mach/mach.h>
_Static_assert(MACH_PORT_TEMPOWNER == 4, "temporary owner flavor");
_Static_assert(MACH_PORT_GUARD_INFO == 8, "guard assertion flavor");
_Static_assert(MACH_PORT_GUARD_INFO_COUNT == 2, "guard word count");
_Static_assert(sizeof(natural_t) == 4, "attribute word size");
_Static_assert(sizeof(mach_port_guard_info_t) == 8, "guard size");
_Static_assert(sizeof(mach_msg_header_t) == 24 && sizeof(NDR_record_t) == 8, "MIG prefix");
"""
    subprocess.run(['xcrun', 'clang', '-arch', 'arm64e', '-fsyntax-only', '-x', 'c', '-'],
                   input=src, check=True)
    return dict(temporary_owner_flavor=4, guard_assertion_flavor=8, guard_word_count=2,
                attribute_word_bytes=4, header_bytes=24, ndr_bytes=8)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    parser.add_argument('launchd', type=Path)
    parser.add_argument('job_plist', type=Path)
    args = parser.parse_args()
    build = command('sw_vers', '-buildVersion').decode().strip()
    assert build == '26C5035r'
    print(json.dumps(dict(build=build, launchd=launchd_evidence(args.launchd),
                          library=library_evidence(), kernel=kernel_evidence(args.collection),
                          sdk=verify_sdk(), observation=observation(args.job_plist),
                          native_fairplay_return_callback_observed=False,
                          native_fairplay_restart_observed=False,
                          host_slot_continuity_established=False), indent=2))


if __name__ == '__main__':
    main()
