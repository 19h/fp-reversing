#!/usr/bin/env python3
"""Extract original MixedData backing allocation and zone-check correspondence."""
import json

from kernel_native_reader import Kernel
from kext_port_tools import ROOT
from recover_kext_cold_init import pointer
from recover_versioned_request_abi import FLAGS
from verify_daemon_reader_record_payloads_publication import read, sha

P = 'mixed_data_backing'
TAG = 0xfffffe0007f94f99
HEAP = 0xfffffe0007f36938
ZONES = 0xfffffe000caeb480
ADDRESSES = {
    'creator': 0xfffffe000c537394,
    'helper': 0xfffffe000c536f94,
    'wrapper': 0xfffffe000bcfe5b8,
    'cache': 0xfffffe000bd75c64,
    'fallback': 0xfffffe000bd76394,
    'nonzero_check': 0xfffffe000bc9d9c0,
    'nonzero_diagnostic': 0xfffffe000c633ccc,
    'zone_diagnostic': 0xfffffe000c63392c,
    'panic': 0xfffffe000c62a2b0,
}
DEPS = [
    'mixed_data_lifecycle_source.json', 'mixed_data_lifecycle_checks.json',
    'dma_map_constraints_checks.json', 'kernel_native_reader.py',
    'resolve_kernel_collection_interfaces.py', 'recover_kext_cold_init.py',
    'verify_daemon_reader_record_payloads_publication.py',
    'recover_versioned_request_abi.py', 'kext_port_tools.py',
]
SCOPE = (
    'Original-source correspondence for the fresh 48-byte MixedData backing request, '
    'tagged allocation view, small-zone dispatch, checked successful element return '
    'and conditional preservation through creator and helper. Runtime zone values, '
    'cache population, complete allocator behavior and native lifetime remain open.'
)


def literal(kernel, address, size):
    raw = kernel.read(address, size)
    assert raw[-1] == 0 and 0 not in raw[:-1]
    return {'address': hex(address), 'bytes': raw.hex(), 'text': raw[:-1].decode('ascii')}


def build():
    kernel = Kernel()
    functions = {name: kernel.function(address) for name, address in ADDRESSES.items()}
    predecessor = json.loads(read(ROOT / 'mixed_data_lifecycle_source.json'))
    for name in ('creator', 'helper'):
        assert functions[name] == predecessor['functions'][name]

    view = TAG & ~1
    site = pointer(kernel, view + 0x10)
    assert site['target'] == '0xfffffe00070de434'
    name = 'site.struct ioGMDData.struct ioPLBlock'
    string = literal(kernel, int(site['target'], 16), len(name) + 1)
    assert string['text'] == name
    meta = {name: kernel.read(address, size).hex() for name, address, size in [
        ('tagged_view_prefix', view, 0x4c),
        ('ordinary_heap_prefix', HEAP, 0x18),
        ('alternate_bias_u16', 0xfffffe0007e63366, 2),
    ]}
    assert int.from_bytes(bytes.fromhex(meta['tagged_view_prefix'])[0x48:], 'little') == 0x61
    message = 'z_elems_free corruption'
    diagnostic = literal(kernel, 0xfffffe0007053ae7, len(message) + 1)
    assert diagnostic['text'] == message
    panic = kernel.symbols([ADDRESSES['panic']])[hex(ADDRESSES['panic'])]
    assert [row['name'] for row in panic] == ['_panic']
    counts = {
        'captured_functions': len(functions),
        'captured_instructions': sum(len(f['instructions']) for f in functions.values()),
    }
    counts['captured_code_bytes'] = 4 * counts['captured_instructions']
    return {
        'generator_sha256': sha(__file__),
        'static_scope': SCOPE,
        'kernel_collection_sha256': kernel.sha256,
        'dependencies': {name: sha(ROOT / name) for name in DEPS},
        'functions': functions,
        'source_data': meta,
        'view_site_fixup': site,
        'view_site_string': string,
        'zone_diagnostic_string': diagnostic,
        'panic_symbol': panic,
        'verified_source_counts': counts,
        'new_IDA_access': False,
        **{flag: False for flag in FLAGS},
    }


if __name__ == '__main__':
    source = build()
    (ROOT / (P + '_source.json')).write_text(json.dumps(source, indent=2) + '\n')
    print(json.dumps(source['verified_source_counts']), flush=True)
