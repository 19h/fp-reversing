#!/usr/bin/env python3
"""Collect scoped IOService observations and compare installed daemon file bytes."""

import argparse
import hashlib
import itertools
import json
import plistlib
import re
import struct
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path

SERVICE = 'com_apple_driver_FairPlayIOKit'
CLIENT = SERVICE + 'UserClient'
ALTERNATE = 'AvpFairPlayDriver'
BUNDLE = 'com.apple.driver.FairPlayIOKit'
PINNED_DAEMON_SHA = '4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
REGISTRY_KEYS = ('IORegistryEntryID', 'IORegistryEntryName', 'IOObjectClass', 'IOClass',
                 'IOProviderClass', 'IOUserClientClass', 'CFBundleIdentifier')


def command(*args):
    return subprocess.check_output(args, timeout=30)


def sysctl(name):
    return command('sysctl', '-n', name).decode().strip()


def digest(blob):
    return hashlib.sha256(blob).hexdigest()


def snapshot():
    result = {}
    for cls in (SERVICE, ALTERNATE):
        raw = command('ioreg', '-r', '-c', cls, '-a', '-l', '-w', '0')
        roots = plistlib.loads(raw) if raw.strip() else []
        result[cls] = []
        for root in roots:
            clients = []
            for child in root.get('IORegistryEntryChildren', []):
                match = re.fullmatch(r'pid (\d+), (fairplayd|adid)', child.get('IOUserClientCreator', ''))
                if child.get('IOObjectClass') == CLIENT and match:
                    pid, creator = match.groups()
                    clients.append({
                        'registry_id': child['IORegistryEntryID'],
                        'object_class': CLIENT,
                        'pid': int(pid),
                        'creator': creator,
                    })
            result[cls].append({
                'service': {key: root[key] for key in REGISTRY_KEYS if key in root},
                'selected_children': sorted(clients, key=lambda row: row['pid']),
                'all_child_count': len(root.get('IORegistryEntryChildren', [])),
            })
    return result


def daemon_slices(fat):
    magic, count = struct.unpack_from('>II', fat)
    layouts = {0xcafebabe: '>IIIII', 0xcafebabf: '>IIQQII'}
    layout = layouts[magic]
    stride = struct.calcsize(layout)
    for index in range(count):
        cpu, subtype, offset, size, *_ = struct.unpack_from(layout, fat, 8 + index * stride)
        assert offset + size <= len(fat)
        yield cpu, subtype, fat[offset:offset + size]


def macho(blob):
    magic, cpu, subtype, _, count, table_size, _, _ = struct.unpack_from('<8I', blob)
    assert magic == 0xfeedfacf
    segments, linkedit = {}, {}
    offset = 32
    for _ in range(count):
        command_id, size = struct.unpack_from('<II', blob, offset)
        assert size >= 8 and offset + size <= 32 + table_size <= len(blob)
        if command_id == 0x1b:
            assert size == 24
            image_uuid = str(uuid.UUID(bytes=blob[offset + 8:offset + 24]))
        elif command_id == 0x19:
            name = blob[offset + 8:offset + 24].split(b'\0', 1)[0].decode('ascii')
            start, length = struct.unpack_from('<QQ', blob, offset + 40)
            if length:
                assert start + length <= len(blob)
                segments[name] = (start, length)
        elif command_id in (0x1d, 0x80000033, 0x80000034):
            start, length = struct.unpack_from('<II', blob, offset + 8)
            assert start + length <= len(blob)
            linkedit[command_id] = (start, length)
        offset += size
    assert offset == 32 + table_size
    return image_uuid, cpu, subtype, segments, linkedit


def signature_slots(blob, start, capacity):
    magic, size, count = struct.unpack_from('>III', blob, start)
    assert magic == 0xfade0cc0 and 12 + count * 8 <= size <= capacity
    result = {}
    for index in range(count):
        slot, offset = struct.unpack_from('>II', blob, start + 12 + 8 * index)
        assert 12 + count * 8 <= offset <= size - 8
        tag, length = struct.unpack_from('>II', blob, start + offset)
        assert 8 <= length <= size - offset and slot not in result
        result[slot] = (start + offset, start + offset + length, tag)
    return result


def compare_daemon(pid, pinned):
    path = command('ps', '-ww', '-p', str(pid), '-o', 'comm=').decode().strip()
    assert Path(path).name == 'fairplayd'
    blob = Path(path).read_bytes()
    assert digest(pinned) == PINNED_DAEMON_SHA
    expected = macho(pinned)
    matches = []
    slices = []
    for cpu, subtype, image in daemon_slices(blob):
        meta = macho(image)
        assert (cpu, subtype) == meta[1:3]
        slices.append({'uuid': meta[0], 'cpu_type': hex(cpu), 'cpu_subtype': hex(subtype),
                       'size_bytes': len(image)})
        if meta[0] == expected[0]:
            matches.append((meta, image))
    (meta, installed), = matches
    assert meta == expected and len(installed) == len(pinned)
    _, _, _, segments, linkedit = meta

    def different():
        return (i for i, (a, b) in enumerate(zip(installed, pinned, strict=True)) if a != b)

    ranges = []
    for _, group in itertools.groupby(enumerate(different()), lambda pair: pair[1] - pair[0]):
        indices = [offset for _, offset in group]
        ranges.append([indices[0], indices[-1] + 1])
    slots = signature_slots(installed, *linkedit[0x1d])
    assert slots == signature_slots(pinned, *linkedit[0x1d])
    start, end, tag = slots[0x10000]
    assert tag == 0xfade0b01 and all(start <= a < b <= end for a, b in ranges)
    return {
        'installed_universal_sha256': digest(blob),
        'installed_file_slices': slices,
        'matching_file_slice_uuid': meta[0],
        'matching_installed_slice_sha256': digest(installed),
        'pinned_thin_sha256': digest(pinned),
        'differing_bytes': sum(b - a for a, b in ranges),
        'difference_ranges_end_exclusive': [[hex(a), hex(b)] for a, b in ranges],
        'signature_slot_end_exclusive': [hex(start), hex(end)],
        'signature_slot': hex(0x10000),
        'equal_segments': {name: size for name, (offset, size) in segments.items()
                           if pinned[offset:offset + size] == installed[offset:offset + size]},
        'actual_loaded_slice_observed': False,
    }


def capture(thin):
    started = datetime.now(timezone.utc).isoformat()
    kernel_uuid = sysctl('kern.uuid').lower()
    first = snapshot()
    root, = first[SERVICE]
    selected = {item['creator']: item for item in root['selected_children']}
    live_names = {}
    for creator, child in selected.items():
        live = command('ps', '-p', str(child['pid']), '-o', 'ucomm=').decode().strip()
        assert live == creator
        live_names[creator] = live
    identity = compare_daemon(selected['fairplayd']['pid'], thin)
    line, = (s for s in command('kmutil', 'showloaded', '--list-only', '--bundle-identifier',
                                BUNDLE).decode().splitlines() if BUNDLE in s)
    kext = re.search(r'com\.apple\.driver\.FairPlayIOKit \(([^)]+)\) ([0-9A-Fa-f-]{36})', line)
    assert kext
    assert first == snapshot() and kernel_uuid == sysctl('kern.uuid').lower()
    return {
        'started_utc': started,
        'finished_utc': datetime.now(timezone.utc).isoformat(),
        'product_version': command('sw_vers', '-productVersion').decode().strip(),
        'build': command('sw_vers', '-buildVersion').decode().strip(),
        'architecture': command('uname', '-m').decode().strip(),
        'kernel_uuid': kernel_uuid,
        'kext_uuid': kext.group(2).lower(),
        'kext_version': kext.group(1),
        'vmm_present': int(sysctl('kern.hv_vmm_present')),
        'service_plane_snapshots_agree': True,
        'registry': first,
        'creator_pids_present_with_matching_names': live_names,
        'daemon_file_identity': identity,
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('pinned_daemon', type=Path)
    args = parser.parse_args()
    print(json.dumps(capture(args.pinned_daemon.read_bytes()), indent=2, sort_keys=True))
