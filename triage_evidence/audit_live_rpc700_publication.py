#!/usr/bin/env python3
"""Census current slot writers and match the running managed-app receiver candidates."""

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import struct
import subprocess

from audit_fairplay_live_slice_identity import (
    CS_OPS_CDHASH, CS_OPS_PIDOFFSET, installed_slices, query_arch, query_cs,
)
from audit_live_fairplay_cf_receive import assert_instructions
from audit_live_fairplay_reply_rights import compiler_ranges
from audit_live_fairplay_rpc_abi import PINNED_DAEMON_SHA
from audit_live_kext_selector26 import Collection, IDENTITIES
from audit_live_kext_selector26_transfer import words
from recover_rpc700_namespace import header_candidates
from resolve_kernel_collection_interfaces import commands, macho

TARGETS = {
    0xFFFFFE000BD3A224: 'setter_front',
    0xFFFFFE000BD3A2C0: 'setter_policy',
    0xFFFFFE000BD3A088: 'slot_replacement',
}
SITES = {
    0xFFFFFE000BDCBE50: (0xFFFFFE000BD3A224, None),
    0xFFFFFE000BD3A2A8: (0xFFFFFE000BD3A2C0, None),
    0xFFFFFE000BD3A3A0: (0xFFFFFE000BD3A088, None),
    0xFFFFFE000BD3AE88: (0xFFFFFE000BD3A088, 1),
    0xFFFFFE000BD3AEAC: (0xFFFFFE000BD3A088, 2),
    0xFFFFFE000BD83250: (0xFFFFFE000BD3A088, 3),
    0xFFFFFE000BDCB284: (0xFFFFFE000BD3A2C0, 10),
}
MANAGED = Path('/System/Library/Frameworks/ManagedAppDistribution.framework/Support')
FAIRPLAY = Path('/System/Library/PrivateFrameworks/CoreFP.framework/Versions/A/fairplayd')


def setter_census(path):
    collection = Collection(path, IDENTITIES[1])
    assert subprocess.check_output(['sysctl', '-n', 'kern.uuid'], text=True).strip().lower() == IDENTITIES[1][1]
    ranges = []
    hits = {}
    for at, kind, _ in commands(collection.data, 0):
        if kind != 0x19 or not struct.unpack_from('<i', collection.data, at + 60)[0] & 4:
            continue
        name = collection.data[at+8:at+24].split(b'\0')[0].decode()
        base, _, offset, size = struct.unpack_from('<4Q', collection.data, at + 24)
        assert (base | size) & 3 == 0 and offset + size <= len(collection.data)
        code = memoryview(collection.data)[offset:offset + size]
        ranges.append(dict(segment=name, address=hex(base), words=size // 4, sha256=sha256(code).hexdigest()))
        for index, (word,) in enumerate(struct.iter_unpack('<I', code)):
            opcode = word >> 26
            if opcode not in (5, 37):
                continue
            site = base + 4 * index
            delta = ((word & 0x1ffffff) - (word & 0x2000000)) * 4
            target = site + delta
            if target not in TARGETS:
                continue
            assert collection.branch(site, 'bl' if opcode == 37 else 'b') == target
            expected, fixed_slot = SITES[site]
            assert target == expected
            if fixed_slot is not None:
                instruction, = collection.instructions(site - 4, 4)
                register, immediate = instruction.op_str.split(', #')
                assert instruction.mnemonic == 'mov' and register == 'w1' and int(immediate, 0) == fixed_slot
            hits[site] = dict(site=hex(site), target=hex(target), target_role=TARGETS[target],
                              fixed_slot=fixed_slot, window=words(collection, site - 0x40, 0x44))
    assert hits.keys() == SITES.keys()
    exact_pointers = [row['target'] for row in collection.fixups.values() if int(row['target'], 16) in TARGETS]
    assert not exact_pointers
    bounds = compiler_ranges(collection)
    entries = {}
    for start, role in TARGETS.items():
        index, end = bounds[start]
        data = collection.read(start, end - start)
        entries[role] = dict(start=hex(start), end=hex(end), ordinal=index, bytes=data.hex(),
                             sha256=sha256(data).hexdigest())
    pins = assert_instructions(collection.read, (
        (0xFFFFFE000BDCBE10, 'ldr', 'w1, [x21, #8]'),
        (0xFFFFFE000BD3A240, 'cbz', 'x21, #0xfffffe000bd3a2b0'),
        (0xFFFFFE000BD3A244, 'sub', 'w8, w1, #0x25'),
        (0xFFFFFE000BD3A248, 'cmn', 'w8, #0x1d'),
        (0xFFFFFE000BD3A24C, 'b.lo', '#0xfffffe000bd3a2b0'),
        (0xFFFFFE000BD3A0A4, 'cmp', 'w1, #0x24'),
        (0xFFFFFE000BD3A0B8, 'cmp', 'w19, #0x1a'),
        (0xFFFFFE000BD3A0F0, 'ubfiz', 'x10, x19, #3, #0x20'),
        (0xFFFFFE000BD3A11C, 'autda', 'x16, x17'),
        (0xFFFFFE000BD3A130, 'pacda', 'x17, x16'),
        (0xFFFFFE000BD3A144, 'str', 'x17, [x9]'),
        (0xFFFFFE000BD3A1C4, 'bl', '#0xfffffe000bd1833c'),
    ))
    cell = 0xFFFFFE000CB4C248 + 8 * 34
    cell_bytes = collection.read(cell, 8)
    assert cell_bytes == bytes(8)
    return dict(collection_identity=IDENTITIES[1], scanned_ranges=ranges, kernel_setter_entries=entries,
                direct_edges=[hits[site] for site in sorted(hits)], instruction_pins=pins,
                chained_fixups_scanned=len(collection.fixups), exact_entry_fixups=exact_pointers,
                slot34_file_address=hex(cell), slot34_file_word=cell_bytes.hex())


def installed_candidate(path, slices):
    raw = path.read_bytes()
    result = {}
    for image in slices:
        arch = image['arch']
        if not arch.startswith('arm64e'):
            continue
        start = image['file_offset_bytes']
        data = raw[start:start + image['slice_size_bytes']]
        assert sha256(data).hexdigest() == image['sha256']
        info = macho(data, 0, path.name)
        assert info['uuid'] == image['uuid']
        candidates = header_candidates(data, info, 700)
        imports = subprocess.check_output(['xcrun', 'dyld_info', '-arch', arch, '-imports', path], text=True)
        names = re.findall(r'^\s+0x[0-9a-fA-F]+\s+(\S+)\s+\(from ', imports, re.M)
        assert names
        result[arch] = dict(image=image, import_count=len(names),
             matched_mach_host_mig_imports=[name for name in names if re.search(r'host_(get|set)|mach_|mig_', name, re.I)],
             selected_context_imports=[name for name in names if name.startswith('_xpc_connection_')
                                       or name in ('_dlsym', '_dlopen')],
             mig700_header_matches=candidates)
    assert result.keys() == {'arm64e', 'arm64e.x1'}
    return result


def job_snapshot(domain, name):
    spec = (f'gui/{os.getuid()}' if domain == 'gui' else domain) + '/' + name
    raw = subprocess.check_output(['/bin/launchctl', 'print', spec], text=True)
    pid, = re.findall(r'^\tpid = (\d+)$', raw, re.M)
    state, = re.findall(r'^\tstate = (.*)$', raw, re.M)
    block, = re.findall(r'^\tendpoints = \{\n(.*?)^\t\}', raw, re.M | re.S)
    endpoints = {}
    for service, fields in re.findall(r'^\t\t"([^"]+)" = \{\n(.*?)^\t\t\}', block, re.M | re.S):
        active, = re.findall(r'^\t\t\tactive = ([01])$', fields, re.M)
        slots = re.findall(r'^\t\t\thost-special port = (\d+)', fields, re.M)
        assert len(slots) <= 1
        endpoints[service] = dict(active=bool(int(active)), host_slot=int(slots[0]) if slots else None)
    assert endpoints
    return dict(domain=domain, pid=int(pid), state=state, endpoints=endpoints)


def running_identity(snapshot, path, slices):
    pid = snapshot['pid']
    process_name = ['ps', '-ww', '-p', str(pid), '-o', 'comm=']
    started = ['ps', '-p', str(pid), '-o', 'lstart=']
    before = subprocess.check_output(started, text=True)
    assert Path(subprocess.check_output(process_name, text=True).strip()).resolve() == path.resolve()
    cd = query_cs(pid, CS_OPS_CDHASH, 20)
    off = query_cs(pid, CS_OPS_PIDOFFSET, 8)
    assert cd[:2] == off[:2] == (0, 0)
    live_hash = cd[2].hex()
    file_off, = struct.unpack('<q', off[2])
    by_hash, = (row for row in slices if live_hash in row['cdhash_candidates'])
    by_offset, = (row for row in slices if file_off == row['file_offset_bytes'])
    assert by_hash == by_offset and by_hash['codesign_cdhash'] == live_hash
    arch = query_arch(pid)
    if arch['returned_bytes'] == 8:
        assert arch['word_pair'] == [int(by_hash[name], 16) for name in ('cpu_type', 'cpu_subtype')]
    assert before == subprocess.check_output(started, text=True)
    assert query_cs(pid, CS_OPS_CDHASH, 20) == cd and query_cs(pid, CS_OPS_PIDOFFSET, 8) == off
    return dict(matched_slice=by_hash, csops_cdhash=live_hash, csops_slice_offset_bytes=file_off,
                proc_pidarchinfo=arch)


def sdk_check():
    src = b'#include <mach/host_special_ports.h>\n_Static_assert(HOST_MANAGEDAPPDISTD_PORT == 34, "slot 34");\n'
    sdk = subprocess.check_output(['xcrun', '--show-sdk-path'], text=True).strip()
    subprocess.run(['xcrun', 'clang', '-arch', 'arm64e', '-isysroot', sdk, '-fsyntax-only', '-x', 'c', '-'],
                   input=src, check=True)
    return dict(name='HOST_MANAGEDAPPDISTD_PORT', slot=34)


def audit(collection, daemon, native):
    build = subprocess.check_output(['sw_vers', '-buildVersion'], text=True).strip()
    assert build == '26C5035r'
    source = setter_census(collection)
    control = daemon.read_bytes()
    assert sha256(control).hexdigest() == PINNED_DAEMON_SHA
    controls = header_candidates(control, macho(control, 0, 'fairplayd'), 502)
    positives = [row for row in controls if row['passes_common_header_gates']]
    assert [row['address'] for row in positives] == ['0x1010381c0']
    jobs = (
        ('system', 'com.apple.fairplayd', FAIRPLAY),
        ('system', 'com.apple.managedappdistributiond', MANAGED / 'managedappdistributiond'),
        ('gui', 'com.apple.managedappdistributionagent', MANAGED / 'managedappdistributionagent'),
    )
    images = {name: installed_slices(path) for _, name, path in jobs}
    candidates = {name: installed_candidate(path, images[name]) for _, name, path in jobs[1:]}
    result = dict(build=build, kernel=source, sdk=sdk_check(), managed_slices=candidates,
                  fairplayd_mig502_positive=positives, receiver_identified=False)
    if native:
        started = datetime.now(timezone.utc).isoformat()
        before = {name: job_snapshot(domain, name) for domain, name, _ in jobs}
        processes = {name: running_identity(before[name], path, images[name]) for _, name, path in jobs}
        assert before == {name: job_snapshot(domain, name) for domain, name, _ in jobs}
        result['native'] = dict(start_utc=started, end_utc=datetime.now(timezone.utc).isoformat(),
                                launchd_jobs=before, processes=processes, rpc700_observed=False)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    parser.add_argument('daemon', type=Path)
    parser.add_argument('--native', action='store_true', help='read active launchd job and process identity metadata')
    args = parser.parse_args()
    print(json.dumps(audit(args.collection, args.daemon, args.native), indent=2))
