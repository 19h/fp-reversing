#!/usr/bin/env python3
"""Compare live FairPlayIOKit clients' entitlement exports with their signed slices."""

import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import plistlib
import struct
import subprocess

from audit_daemon_iokit_native_registry import macho, signature_slots
from audit_fairplay_live_slice_identity import (
    CS_OPS_CDHASH, CS_OPS_PIDOFFSET, csops, installed_slices, query_cs,
)
from audit_live_iokit_open_owner import ACCESS, BUILD, CACHE_UUID, IDENTITIES, dyld_uuid, snapshot

CS_OPS_STATUS = 0
CS_OPS_ENTITLEMENTS_BLOB = 7
CS_OPS_DER_ENTITLEMENTS_BLOB = 16
CS_OPS_VALIDATION_CATEGORY = 17
PLATFORM = 1
FLAGS = {
    'CS_VALID': 0x1,
    'CS_ENTITLEMENTS_VALIDATED': 0x4000,
    'CS_PLATFORM_BINARY': 0x04000000,
    'CS_SIGNED': 0x20000000,
}
HASH_TYPES = {1: ('sha1', 20), 2: ('sha256', 32), 3: ('sha256', 20), 4: ('sha384', 48)}
CLIENTS = {'adid', 'fairplayd', 'lskdd'}


def read_cs(pid, op, fmt):
    status, error, raw = query_cs(pid, op, struct.calcsize(fmt))
    assert (status, error) == (0, 0), (pid, op, status, error)
    value, = struct.unpack(fmt, raw)
    return value


def identity(pid):
    return {
        'cdhash': read_cs(pid, CS_OPS_CDHASH, '20s').hex(),
        'slice_offset_bytes': read_cs(pid, CS_OPS_PIDOFFSET, '<q'),
        'status_flags': hex(read_cs(pid, CS_OPS_STATUS, '<I')),
        'validation_category': read_cs(pid, CS_OPS_VALIDATION_CATEGORY, '<I'),
    }


def read_blob(pid, op, magic):
    sentinel = b'\xa5' * 8
    header = ctypes.create_string_buffer(sentinel, len(sentinel))
    ctypes.set_errno(0)
    status = csops(pid, op, header, len(header))
    error = ctypes.get_errno()
    if (status, error, header.raw) == (0, 0, sentinel):
        return None, {'header_result': status, 'header_errno': error, 'header_unchanged': True}

    assert (status, error) == (-1, errno.ERANGE), (pid, op, status, error)
    hint_magic, length = struct.unpack('>II', header.raw)
    assert hint_magic == 0 and 8 < length <= 1024 * 1024
    fetched, fetch_errno, raw = query_cs(pid, op, length)
    assert (fetched, fetch_errno) == (0, 0), (pid, op, fetched, fetch_errno)
    assert struct.unpack_from('>II', raw) == (magic, length)
    return raw, {
        'header_result': status, 'header_errno': error, 'header_hex': header.raw.hex(),
        'fetch_result': fetched, 'fetch_errno': fetch_errno, 'length_bytes': length,
        'magic': hex(magic), 'sha256': hashlib.sha256(raw).hexdigest(),
    }


def signed_blobs(path, observed):
    offset = observed['slice_offset_bytes']
    cdhash = observed['cdhash']
    by_offset, = (row for row in installed_slices(path) if row['file_offset_bytes'] == offset)
    assert by_offset['codesign_cdhash'] == cdhash and by_offset['arch'] == 'arm64e'
    with path.open('rb') as stream:
        stream.seek(offset)
        image = stream.read(by_offset['slice_size_bytes'])
    assert hashlib.sha256(image).hexdigest() == by_offset['sha256']
    image_uuid, _, _, _, linkedit = macho(image)
    assert image_uuid == by_offset['uuid']
    slots = signature_slots(image, *linkedit[0x1d])
    matching = []
    for slot, (start, end, magic) in slots.items():
        if slot != 0 and not 0x1000 <= slot < 0x1005:
            continue
        assert magic == 0xfade0c02 and end - start >= 40
        hash_size, hash_type = struct.unpack_from('BB', image, start + 36)
        algorithm, expected_size = HASH_TYPES[hash_type]
        assert hash_size == expected_size
        if hashlib.new(algorithm, image[start:end]).hexdigest()[:40] == cdhash:
            matching.append((slot, start, end, algorithm, hash_size))
    (directory_slot, start, end, algorithm, hash_size), = matching
    hash_offset, _, number_special_slots = struct.unpack_from('>III', image, start + 16)
    assert 40 <= hash_offset - number_special_slots * hash_size <= hash_offset <= end - start

    blobs, details = {}, {}
    for slot, expected_magic in ((5, 0xfade7171), (7, 0xfade7172)):
        blob_start, blob_end, magic = slots[slot]
        assert slot <= number_special_slots and magic == expected_magic
        blob = image[blob_start:blob_end]
        special_start = start + hash_offset - slot * hash_size
        stored = image[special_start:special_start + hash_size]
        assert stored == hashlib.new(algorithm, blob).digest()[:hash_size]
        blobs[slot] = blob
        details[slot] = {
            'length_bytes': len(blob), 'magic': hex(magic),
            'sha256': hashlib.sha256(blob).hexdigest(), 'special_slot_hash': stored.hex(),
        }
    return blobs, {
        'slice': by_offset, 'code_directory_slot': hex(directory_slot),
        'code_directory_hash_algorithm': algorithm, 'special_slot_hash_bytes': hash_size,
        'embedded_entitlement_slots': details,
    }


def process(pid):
    output = subprocess.check_output(
        ['ps', '-ww', '-p', str(pid), '-o', 'lstart=', '-o', 'uid=', '-o', 'comm='],
        text=True, env={**os.environ, 'LC_ALL': 'C'},
    ).strip()
    weekday, month, day, time, year, euid, name = output.split(None, 6)
    return (weekday, month, day, time, year), int(euid), Path(name)


def clients():
    current = snapshot()
    attached = [child for child in current['children'] if child['creator'] in CLIENTS]
    assert {child['creator'] for child in attached} == CLIENTS
    return current['service_id'], attached


def observe():
    assert subprocess.check_output(['sw_vers', '-buildVersion'], text=True).strip() == BUILD
    assert subprocess.check_output(['sysctl', '-n', 'kern.uuid'], text=True).strip().lower() == IDENTITIES[1][1]
    assert dyld_uuid() == CACHE_UUID
    service, before = clients()
    observer = os.getpid()
    observer_euid = os.geteuid()
    assert observer_euid != 0
    operations = ((5, CS_OPS_ENTITLEMENTS_BLOB, 0xfade7171), (7, CS_OPS_DER_ENTITLEMENTS_BLOB, 0xfade7172))
    control = {}
    for slot, op, magic in operations:
        raw, detail = read_blob(observer, op, magic)
        assert raw is None
        control[slot] = detail

    results = []
    for attached in before:
        pid, name = attached['pid'], attached['creator']
        start, euid, path = process(pid)
        assert path.name == name and path.is_relative_to('/System/Library')
        live = identity(pid)
        flags = int(live['status_flags'], 16)
        assert all(flags & mask for mask in FLAGS.values())
        assert live['validation_category'] == PLATFORM
        embedded, signature = signed_blobs(path, live)
        exports = {}
        for slot, op, magic in operations:
            raw, evidence = read_blob(pid, op, magic)
            assert raw is not None
            exports[slot] = evidence
            if slot == 5:
                assert raw[8:13] == embedded[slot][8:13] == b'<?xml'
                assert raw.find(b'\0', 8) == len(raw) - 1
                assert b'\0' not in embedded[slot][8:]
                live_values = plistlib.loads(raw[8:-1])
                signed_values = plistlib.loads(embedded[slot][8:])
                assert isinstance(live_values, dict) and isinstance(signed_values, dict)
                assert plistlib.dumps(live_values, fmt=plistlib.FMT_BINARY) == plistlib.dumps(
                    signed_values, fmt=plistlib.FMT_BINARY)
                assert live_values[ACCESS[0]] is True
                assert all(key not in live_values for key in ACCESS[1:])
                evidence['parsed_dictionary_equal'] = True
                evidence['dictionary_key_count'] = len(live_values)
                evidence['live_trailing_nul'] = True
                evidence['embedded_trailing_nul'] = False
            else:
                assert raw == embedded[slot]
            evidence['embedded_bytes_equal'] = raw == embedded[slot]
        assert live == identity(pid) and (start, euid, path) == process(pid)
        results.append({
            'attachment': attached, 'live_identity': live, 'signed_slice': signature,
            'observer_euid_differs': euid != observer_euid, 'exports': exports,
            'entitlement_values': {key: live_values.get(key) for key in ACCESS},
            'entitlement_keys_present': {key: key in live_values for key in ACCESS},
        })
    assert (service, before) == clients()
    return {
        'boot': {'build': BUILD, 'kernel_uuid': IDENTITIES[1][1], 'dyld_uuid': CACHE_UUID},
        'registry_service_id': service, 'status_flag_masks': FLAGS, 'clients': results,
        'self_control': {'non_root': True, 'identity': identity(observer), 'exports': control},
    }


if __name__ == '__main__':
    print(json.dumps(observe(), indent=2, sort_keys=True))
