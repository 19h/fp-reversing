#!/usr/bin/env python3
"""Search the installed managed-app Mach-O dependency closure for a conventional RPC 700 receiver."""

import argparse
from collections import Counter, deque
from hashlib import sha256
import json
from pathlib import Path
import struct
import subprocess

from audit_adid_legacy_mach_receive import Evidence, symbol, veneer
from audit_fairplay_live_slice_identity import installed_slices
from audit_live_iokit_mach_transport import CACHE_UUID, clean_pointer, dyld_uuid
from audit_live_rpc700_publication import MANAGED, PINNED_DAEMON_SHA
from bootpolicy_cache_reader import Cache, Dylib
from recover_rpc700_endpoint_inventory import scan_branches, scan_chains, scan_stubs
from recover_rpc700_namespace import header_candidates
from resolve_kernel_collection_interfaces import commands, macho


LOAD_COMMANDS = {
    0xc: 'load',
    0x80000018: 'weak',
    0x8000001f: 'reexport',
    0x80000023: 'upward',
    0x20: 'lazy',
}
LIBXPC = '/usr/lib/system/libxpc.dylib'
LIBKERNEL = '/usr/lib/system/libsystem_kernel.dylib'
RPC_ID = 700
CONTROL_ID = 71
CONTROL_ADDRESS = 0x1e240c7f8


def dylib_loads(data):
    loads = []
    for at, kind, size in commands(data, 0):
        if kind not in LOAD_COMMANDS:
            continue
        offset, = struct.unpack_from('<I', data, at + 8)
        raw = data[at + offset:at + size]
        assert 24 <= offset < size and b'\0' in raw
        loads.append((LOAD_COMMANDS[kind], raw.split(b'\0', 1)[0].decode()))
    return loads


def executable_roots():
    roots = {}
    for basename in ('managedappdistributiond', 'managedappdistributionagent'):
        path = MANAGED / basename
        raw = path.read_bytes()
        for image in installed_slices(path):
            arch = image['arch']
            if arch not in ('arm64e', 'arm64e.x1'):
                continue
            offset = image['file_offset_bytes']
            data = raw[offset:offset + image['slice_size_bytes']]
            assert sha256(data).hexdigest() == image['sha256']
            assert macho(data, 0, basename)['uuid'] == image['uuid']
            loads = dylib_loads(data)
            apple = subprocess.check_output(
                ['xcrun', 'dyld_info', '-arch', arch, '-dependents', path], text=True)
            assert [line.split()[-1] for line in apple.splitlines()
                    if line.split() and line.split()[-1].startswith('/')] == [
                        name for _, name in loads]
            roots[f'{basename}/{arch}'] = {'uuid': image['uuid'], 'sha256': image['sha256'],
                                           'dependencies': loads}
    assert len(roots) == 4
    assert len({tuple(row['dependencies']) for row in roots.values()}) == 1
    return roots


def closure(cache, roots):
    image_addresses = {row['path']: row['address'] for row in cache.images}
    images = {}
    weak_missing = {}
    queue = deque((root, edge) for root, record in roots.items() for edge in record['dependencies'])
    while queue:
        origin, (kind, path) = queue.popleft()
        if path in images:
            continue
        if path not in image_addresses:
            assert kind == 'weak' and path.startswith('/') and not Path(path).exists(), (origin, kind, path)
            weak_missing.setdefault(path, []).append(origin)
            continue
        address = image_addresses[path]
        header = cache.read(address, 32)
        magic, _, _, file_type, _, command_size = struct.unpack_from('<6I', header)
        assert magic == 0xfeedfacf and file_type == 6
        header += cache.read(address + 32, command_size)
        meta = macho(header, 0, path)
        meta['dependencies'] = dylib_loads(header)
        meta['header_sha256'] = sha256(header).hexdigest()
        meta['base'] = address
        images[path] = meta
        queue.extend((path, edge) for edge in meta['dependencies'])
    return images, {name: sorted(origins) for name, origins in sorted(weak_missing.items())}


def candidate_offsets(raw, address, wanted):
    aligned = (-address) % 8
    words = memoryview(raw)[aligned:aligned + ((len(raw) - aligned) // 8) * 8].cast('I')
    for index, start in enumerate(words[2:-5:2]):
        if start > wanted:
            continue
        end = words[2 * index + 3]
        max_reply = words[2 * index + 4]
        if wanted < end <= wanted + 4096 and 36 <= max_reply <= 1048576:
            yield aligned + 8 * index, start, end, max_reply


def pointer(cache, address):
    try:
        row = cache.pointer(address)
    except AssertionError:
        return None
    return clean_pointer(row)


def header_record(cache, library, path, section, raw, offset, start, end, max_reply, wanted):
    address = section['address'] + offset
    record = {'image': path, 'address': hex(address), 'section': section['section'],
              'segment': section['segment'], 'start': start, 'end': end, 'max_reply': max_reply,
              'header_bytes': raw[offset:offset + 32].hex()}
    if offset + 32 + 40 * (end - start) > len(raw):
        record['classification'] = 'descriptor array outside section'
        return record
    demux = pointer(cache, address)
    if demux is None:
        record['classification'] = 'no chained demultiplexer pointer'
        return record
    record['demultiplexer'] = demux
    functions = library(path)
    if int(demux['target'], 16) not in functions:
        record['classification'] = 'demultiplexer outside local compiler starts'
        return record
    routine = address + 32 + 40 * (wanted - start)
    record['requested_stub'] = pointer(cache, routine + 8)
    record['requested_stub_raw'] = cache.read(routine + 8, 8).hex()
    if record['requested_stub'] is None:
        record['classification'] = 'no chained stub for requested ID'
    elif int(record['requested_stub']['target'], 16) not in functions:
        record['classification'] = 'stub outside local compiler starts'
    else:
        record['classification'] = 'common MIG receiver'
    return record


def scan_sections(cache, images):
    results = []
    checks = []
    local_functions = {}

    def functions(path):
        if path not in local_functions:
            local_functions[path] = set(Dylib(cache, path).functions)
        return local_functions[path]

    for path, meta in sorted(images.items()):
        segments = {row['name']: row for row in meta['segments']}
        for section in meta['sections']:
            length = section['size']
            if (length < 32 or not section['file_offset'] or section['flags'] & 0x80000400
                    or section['flags'] & 0xff in (1, 0xc, 0x12)):
                continue
            segment = segments[section['segment']]
            relative = section['address'] - segment['address']
            assert 0 <= relative <= relative + length <= segment['file_size'], section
            raw = cache.read(section['address'], length)
            checks.append((path, hex(section['address']), length, sha256(raw).hexdigest()))
            for offset, start, end, max_reply in candidate_offsets(raw, section['address'], RPC_ID):
                results.append(header_record(cache, functions, path, section, raw, offset,
                                             start, end, max_reply, RPC_ID))
            if path == LIBXPC and section['address'] <= CONTROL_ADDRESS < section['address'] + length:
                controls = [
                    header_record(cache, functions, path, section, raw, offset, start, end,
                                  max_reply, CONTROL_ID)
                    for offset, start, end, max_reply in candidate_offsets(raw, section['address'], CONTROL_ID)
                    if section['address'] + offset == CONTROL_ADDRESS
                ]
                control, = controls
    symbol(Dylib(cache, LIBXPC), '_do_notify_subsystem', CONTROL_ADDRESS)
    assert control['classification'] == 'common MIG receiver', control
    return {'scanned_sections': checks, 'candidates': results, 'cache_positive_control': control,
            'classification_counts': dict(Counter(row['classification'] for row in results))}


def host_api_references(cache):
    system = Dylib(cache, LIBKERNEL)
    names = ('_host_get_special_port', '_host_set_special_port', '_mach_ports_lookup', '_mach_ports_register')
    targets = {system.exports[name]['address']: name for name in names}
    maps, refs, total = scan_chains(cache, targets)
    for row in refs:
        row['pointer'] = clean_pointer(row['pointer'])
    getter, = (row['pointer'] for row in refs if row['API'] == '_host_get_special_port')
    _, stubs, stub_count = scan_stubs(cache, {int(getter['address'], 16)})
    stub, = stubs
    stub_address = int(stub['address'], 16)
    addresses = {address: name for address, name in targets.items() if name in names[:2]}
    addresses[stub_address] = 'shared host getter veneer'
    _, calls, branch_count = scan_branches(cache, addresses)
    evidence = Evidence(cache.read)
    stub['pointer'] = veneer(cache, evidence, stub_address, system, '_host_get_special_port',
                            system.exports['_host_get_special_port']['address'])['pointer']
    expected = (
        (0x181ef06b8, 2, '/usr/lib/system/libsystem_darwin.dylib',
         0x181ef0660, '_os_crash_set_reporter_port'),
        (0x181ef0778, 2, '/usr/lib/system/libsystem_darwin.dylib',
         0x181ef0728, '_os_crash_get_reporter_port_array'),
        (0x1855b9ca0, 1, '/usr/lib/system/libdispatch.dylib',
         0x1855b9c74, '__dispatch_mach_host_port_init'),
    )
    assert [int(row['address'], 16) for row in calls] == [row[0] for row in expected]
    for row, (call, slot, path, start, name) in zip(calls, expected, strict=True):
        symbol(Dylib(cache, path), name, start)
        evidence.check([(call - 8, 'mov', 'w1, #-1'), (call - 4, 'mov', f'w2, #{slot}'),
                        (call, 'bl', f'#{stub_address:#x}')])
        row.update(host_slot=slot, caller=name, caller_start=hex(start))
    return {'targets': {name: hex(address) for address, name in targets.items()},
            'mappings_scanned': len(maps), 'chain_entries': total, 'references': refs,
            'veneer_candidate_starts': stub_count, 'veneer': stub, 'branch_words': branch_count,
            'getter_and_setter_direct_calls': calls, 'call_windows': evidence.windows}


def near_matches(cache, scan):
    by_address = {int(row['address'], 16): row for row in scan['candidates']
                  if 'requested_stub' in row}
    assert set(by_address) == {0x1eebf8798, 0x1eed6e6a8, 0x1eed6e798}
    assert all(row['section'] == '__objc_data' for row in by_address.values())
    appkit = by_address[0x1eebf8798]
    address = int(appkit['requested_stub']['target'], 16)
    protection = cache.mapping(address)['initprot']
    assert protection == 1
    appkit['requested_stub_initial_protection'] = protection
    swiftui = Dylib(cache, by_address[0x1eed6e6a8]['image'])
    names = (
        (0x1eed6e6a8, '_$s7SwiftUI19ImageAttachmentCellCMU'),
        (0x1eed6e798, '_$s7SwiftUI17AppKitToolbarItemCMU'),
    )
    for address, name in names:
        row = by_address[address]
        symbol(swiftui, name, int(row['demultiplexer']['target'], 16))
        label = subprocess.check_output(['xcrun', 'swift-demangle', '--compact', name[1:]],
                                        text=True).strip()
        assert label.startswith('ObjC metadata update function for SwiftUI.')
        row['demultiplexer_symbol'] = name
        row['demultiplexer_demangled'] = label
    assert by_address[0x1eed6e6a8]['requested_stub_raw'] == '0000000000000000'
    swift_core = Dylib(cache, '/usr/lib/swift/libswiftCore.dylib')
    row = by_address[0x1eed6e798]
    symbol(swift_core, '_swift_deletedMethodError', int(row['requested_stub']['target'], 16))
    row['requested_stub_symbol'] = '_swift_deletedMethodError'


def sdk():
    checks = {
        'sizeof(struct routine_descriptor)': 40,
        'offsetof(struct mig_subsystem, routine)': 32,
        'offsetof(struct mig_subsystem, start)': 8,
        'offsetof(struct mig_subsystem, end)': 12,
        'offsetof(struct mig_subsystem, maxsize)': 16,
        'offsetof(struct routine_descriptor, stub_routine)': 8,
    }
    source = ['#include <stddef.h>', '#include <mach/mig.h>']
    source.extend(f'_Static_assert({expr} == {value}, "{expr}");' for expr, value in checks.items())
    subprocess.run(['xcrun', 'clang', '-arch', 'arm64e', '-x', 'c', '-fsyntax-only', '-'],
                   input='\n'.join(source), text=True, check=True)
    return checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('fairplayd_control', type=Path)
    args = parser.parse_args()
    cache = Cache()
    assert cache.uuid == CACHE_UUID == dyld_uuid()
    control = args.fairplayd_control.read_bytes()
    assert sha256(control).hexdigest() == PINNED_DAEMON_SHA
    headers = header_candidates(control, macho(control, 0, 'fairplayd'), 502)
    positive, = [row for row in headers if row['passes_common_header_gates']]
    assert positive['address'] == '0x1010381c0'
    roots = executable_roots()
    images, missing_weak = closure(cache, roots)
    mig = scan_sections(cache, images)
    near_matches(cache, mig)
    result = {
        'cache_uuid': cache.uuid,
        'executable_roots': roots,
        'image_count': len(images),
        'unresolved_weak': missing_weak,
        'cache_images': {path: {key: value for key, value in image.items()
                                if key in ('uuid', 'base', 'header_sha256', 'dependencies')}
                         for path, image in images.items()},
        'common_MIG': mig,
        'sdk_layout_checks': sdk(),
        'host_api_references': host_api_references(cache),
        'fairplayd_MIG_positive_control': positive,
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
