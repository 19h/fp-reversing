#!/usr/bin/env python3
"""Join live FairPlay IOKit registry creators to installed Mach-O slices."""

import argparse
import ctypes
from datetime import datetime, timezone
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess

from audit_daemon_iokit_native_registry import (
    PINNED_DAEMON_SHA, SERVICE, command, compare_daemon, digest, macho, signature_slots, snapshot,
)

CS_OPS_CDHASH = 5
CS_OPS_PIDOFFSET = 6
PROC_PIDARCHINFO = 19
ARCHITECTURES = {
    (0x01000007, 3): 'x86_64',
    (0x0100000c, 0x80000002): 'arm64e',
    (0x0100000c, 0x8000000c): 'arm64e.x1',
}

csops = ctypes.CDLL(None, use_errno=True).csops
csops.argtypes = (ctypes.c_int, ctypes.c_uint, ctypes.c_void_p, ctypes.c_size_t)
csops.restype = ctypes.c_int
pidinfo = ctypes.CDLL('/usr/lib/libproc.dylib', use_errno=True).proc_pidinfo
pidinfo.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int)
pidinfo.restype = ctypes.c_int


def query_cs(pid, op, size):
    buf = ctypes.create_string_buffer(size)
    ctypes.set_errno(0)
    result = csops(pid, op, buf, size)
    return result, ctypes.get_errno(), buf.raw


def query_arch(pid):
    buf = ctypes.create_string_buffer(8)
    ctypes.set_errno(0)
    result = pidinfo(pid, PROC_PIDARCHINFO, 0, buf, len(buf))
    return {'returned_bytes': result, 'errno': errno.errorcode.get(ctypes.get_errno()),
            'word_pair': list(struct.unpack('<II', buf.raw)) if result == len(buf) else None}


def selected_identity(blob):
    image_uuid, cpu, subtype, _, linkedit = macho(blob)
    slots = signature_slots(blob, *linkedit[0x1d])
    cdhashes = set()
    for key, (start, end, magic) in slots.items():
        if key != 0 and not 0x1000 <= key < 0x1005:
            continue
        assert magic == 0xfade0c02 and end - start >= 40
        hash_type = blob[start + 37]
        algorithm = {1: 'sha1', 2: 'sha256', 3: 'sha256', 4: 'sha384'}[hash_type]
        cdhashes.add(hashlib.new(algorithm, blob[start:end]).hexdigest()[:40])
    assert cdhashes
    return {'uuid': image_uuid, 'cpu_type': hex(cpu), 'cpu_subtype': hex(subtype),
            'arch': ARCHITECTURES[cpu, subtype], 'sha256': digest(blob),
            'cdhash_candidates': sorted(cdhashes)}


def installed_slices(path):
    data = path.read_bytes()
    magic, count = struct.unpack_from('>II', data)
    layout = {0xcafebabe: '>IIIII', 0xcafebabf: '>IIQQII'}[magic]
    stride = struct.calcsize(layout)
    result = []
    for index in range(count):
        cpu, subtype, start, size, _ = struct.unpack_from(layout, data, 8 + index * stride)
        assert start + size <= len(data)
        row = selected_identity(data[start:start + size])
        assert (row['cpu_type'], row['cpu_subtype']) == (hex(cpu), hex(subtype))
        details = subprocess.check_output(
            ['codesign', '-d', '--arch', row['arch'], '--verbose=4', str(path)],
            stderr=subprocess.STDOUT, timeout=30)
        reported, = re.findall(rb'^CDHash=([0-9a-f]{40})$', details, re.M)
        assert reported.decode() in row['cdhash_candidates']
        result.append({**row, 'file_offset_bytes': start, 'slice_size_bytes': size,
                       'codesign_cdhash': reported.decode()})
    return result


def audit(pinned_path):
    started = datetime.now(timezone.utc).isoformat()
    pinned = pinned_path.read_bytes()
    assert digest(pinned) == PINNED_DAEMON_SHA
    pin = selected_identity(pinned)
    root, = snapshot()[SERVICE]
    clients = {row['creator']: row for row in root['selected_children']}
    assert set(clients) == {'adid', 'fairplayd'}
    results = {}
    control = query_arch(os.getpid())
    assert control['returned_bytes'] == 8
    for name, client in sorted(clients.items()):
        pid = client['pid']
        before = command('ps', '-p', str(pid), '-o', 'lstart=').strip()
        path = Path(command('ps', '-ww', '-p', str(pid), '-o', 'comm=').decode().strip())
        assert path.name == name and path.is_relative_to('/System/Library/PrivateFrameworks')
        observed = query_cs(pid, CS_OPS_CDHASH, 20)
        offset = query_cs(pid, CS_OPS_PIDOFFSET, 8)
        archinfo = query_arch(pid)
        assert observed[:2] == offset[:2] == (0, 0)
        live_hash = observed[2].hex()
        live_offset, = struct.unpack('<q', offset[2])
        slices = installed_slices(path)
        by_hash, = [row for row in slices if live_hash in row['cdhash_candidates']]
        by_offset, = [row for row in slices if live_offset == row['file_offset_bytes']]
        assert by_hash == by_offset and by_hash['codesign_cdhash'] == live_hash
        assert query_cs(pid, CS_OPS_CDHASH, 20) == observed
        assert query_cs(pid, CS_OPS_PIDOFFSET, 8) == offset
        assert before and before == command('ps', '-p', str(pid), '-o', 'lstart=').strip()
        if name == 'fairplayd':
            assert live_hash in pin['cdhash_candidates'] and by_hash['uuid'] == pin['uuid']
            file_compare = compare_daemon(pid, pinned)
            assert file_compare['matching_installed_slice_sha256'] == by_hash['sha256']
            assert file_compare['differing_bytes'] == 262
            assert file_compare['signature_slot'] == '0x10000'
        results[name] = {'registry_entry': client, 'proc_pidarchinfo': archinfo,
                         'live_cdhash': live_hash, 'live_slice_offset_bytes': live_offset,
                         'matched_slice': by_hash, 'installed_slices': slices}
    assert snapshot()[SERVICE] == [root]
    return {'started_utc': started, 'build': command('sw_vers', '-buildVersion').decode().strip(),
            'registry_service_id': root['service']['IORegistryEntryID'],
            'fairplayd_file_comparison': {
                key: file_compare[key] for key in (
                    'differing_bytes', 'difference_ranges_end_exclusive', 'signature_slot',
                    'signature_slot_end_exclusive', 'equal_segments',
                )
            },
            'process_architecture_self_control': control,
            'processes': results, 'pinned_fairplayd': pin, 'native_selector_observed': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('pinned_fairplayd', type=Path)
    print(json.dumps(audit(parser.parse_args().pinned_fairplayd), indent=2))
