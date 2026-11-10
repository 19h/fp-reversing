#!/usr/bin/env python3
"""Capture the original heap startup and tagged-view assignment interfaces."""
import json
import struct

from kernel_native_reader import Kernel
from kext_port_tools import ROOT
from recover_kext_cold_init import pointer
from recover_versioned_request_abi import FLAGS
from verify_daemon_reader_record_payloads_publication import read, sha

P = 'mixed_data_zone_geometry'
SCOPE = (
    'Original-source correspondence from allocator startup to the tagged MixedData '
    'view, heap family and 48-byte element extent under a matched startup epoch. '
    'Native family selection, bias, accounting pointers and allocation are unobserved.'
)
VIEW = 0xfffffe0007f94f98
STARTUP = 0xfffffe000cbeaea8
TABLE = 0xfffffe000cbc8a40
FAMILIES = 0xfffffe0007e6b270
ZONE_BASE = 0xfffffe000caeb480
FUNCTIONS = {
    'startup': 0xfffffe000c62a87c,
    'family_create': 0xfffffe000c62cbf0,
    'family_setup': 0xfffffe000bcfe21c,
    'zone_create': 0xfffffe000bd772b4,
    'variable_startup': 0xfffffe000c62c548,
    'variable_families': 0xfffffe000c62baa8,
    'view_sections': 0xfffffe000c62c7f8,
    'view_register': 0xfffffe000c62c1b8,
    'signature_flags': 0xfffffe000c62be28,
    'view_assign': 0xfffffe000c62aab4,
    'view_sort': 0xfffffe000c62ad34,
    'view_split_group': 0xfffffe000c62bfd4,
    'allocator': 0xfffffe000bcfe5b8,
    'retire_small': 0xfffffe000bcfed8c,
}
DEPS = [
    'kernel_zone_startup_source.json', 'mixed_data_backing_source.json',
    'mixed_data_backing_checks.json', 'mixed_data_retirement_source.json',
    'mixed_data_retirement_checks.json', 'kernel_native_reader.py',
    'kext_port_tools.py', 'recover_kext_cold_init.py', 'resolve_kernel_collection_interfaces.py',
    'verify_daemon_reader_record_payloads_publication.py',
    'recover_versioned_request_abi.py',
]


def section_for(kernel, name):
    return next(s for s in kernel.kernel['sections'] if s['section'] == name)


def string_fixup(kernel, address, expected):
    slot = pointer(kernel, address)
    raw = kernel.read(int(slot['target'], 16), len(expected) + 1)
    assert raw == expected.encode('ascii') + b'\0'
    return {'fixup': slot, 'literal': expected, 'bytes': raw.hex()}


def build():
    kernel = Kernel()
    functions = {name: kernel.function(address) for name, address in FUNCTIONS.items()}
    startup_prior = json.loads(read(ROOT / 'kernel_zone_startup_source.json'))
    creator_prior = next(f for f in startup_prior['functions'] if f['start'] == hex(FUNCTIONS['zone_create']))
    assert functions['zone_create'] == {k: v for k, v in creator_prior.items() if k != 'exact_symbols'}
    backing = json.loads(read(ROOT / 'mixed_data_backing_source.json'))
    retirement = json.loads(read(ROOT / 'mixed_data_retirement_source.json'))
    assert functions['allocator'] == backing['functions']['wrapper']
    assert functions['retire_small'] == retirement['functions']['retire_small']

    entry_section = section_for(kernel, '__init_entry_set')
    assert entry_section['address'] <= STARTUP < entry_section['address'] + entry_section['size']
    assert (STARTUP - entry_section['address']) % 24 == 0
    entry = kernel.read(STARTUP, 24)
    callback = pointer(kernel, STARTUP + 8)
    assert callback['target'] == hex(FUNCTIONS['startup']) and callback['authenticated']
    assert struct.unpack_from('<II', entry) == (7, 2) and not any(entry[16:])
    view_section = section_for(kernel, '__kalloc_var')
    view_index, remainder = divmod(VIEW - view_section['address'], 80)
    assert (view_index, remainder) == (372, 0) and view_section['size'] == 408 * 80
    view = kernel.read(VIEW, 80)
    assert struct.unpack_from('<I', view, 0x48)[0] == 0x61
    assert view[8:16] == bytes(8) and view[0x20:0x22] == bytes(2)

    fields = {
        'family_count_u16': (0xfffffe0007e63398, 2),
        'size_table_seed': (0xfffffe000700dcf8, 8),
        'size_table_initial_image': (TABLE, 88),
        'alternate_heap_image': (0xfffffe0007e63360, 24),
        'typed_heap_image': (0xfffffe0007e6a780, 24),
        'family_records_initial_image': (FAMILIES, 8 * 24),
    }
    data = {name: {'address': hex(address), 'bytes': kernel.read(address, size).hex()}
            for name, (address, size) in fields.items()}
    assert data['family_count_u16']['bytes'] == '0600'
    assert data['size_table_seed']['bytes'] == '1000000020000000'
    counts = {
        'captured_functions': len(functions),
        'captured_instructions': sum(len(f['instructions']) for f in functions.values()),
        'startup_entries_checked': 1,
        'kernel_variable_view_records': 408,
    }
    counts['captured_code_bytes'] = counts['captured_instructions'] * 4
    return {
        'generator_sha256': sha(__file__),
        'static_scope': SCOPE,
        'kernel_collection_sha256': kernel.sha256,
        'dependencies': {n: sha(ROOT / n) for n in DEPS},
        'functions': functions,
        'startup_entry': {'section': entry_section, 'address': hex(STARTUP),
                          'bytes': entry.hex(), 'callback': callback, 'phase': 7, 'rank': 2},
        'variable_view': {
            'section': view_section, 'index': view_index, 'address': hex(VIEW), 'bytes': view.hex(),
            'name': string_fixup(kernel, VIEW + 0x10, 'site.struct ioGMDData.struct ioPLBlock'),
            'signature_header': string_fixup(kernel, VIEW + 0x38, '1222223'),
            'signature_type': string_fixup(kernel, VIEW + 0x40, '11232'),
        },
        'data': data,
        'verified_source_counts': counts,
        'new_IDA_access': False,
        **{flag: False for flag in FLAGS},
    }


if __name__ == '__main__':
    source = build()
    (ROOT / (P + '_source.json')).write_text(json.dumps(source, indent=2) + '\n')
    print(json.dumps(source['verified_source_counts']), flush=True)
