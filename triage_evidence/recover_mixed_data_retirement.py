#!/usr/bin/env python3
"""Capture the original tagged backing retirement and allocation correspondence."""
import json

from kernel_native_reader import Kernel
from kext_port_tools import ROOT
from recover_versioned_request_abi import FLAGS
from verify_daemon_reader_record_payloads_publication import read, sha

P = 'mixed_data_retirement'
SCOPE = (
    'Static contract for retiring a selected 48-byte MixedData backing request. '
    'The original allocator and retirement wrapper agree on the logical element '
    'base under the declared metadata and pointer epochs. The retirement wrapper '
    'requests a complete element clear before zone handoff.'
)
FUNCTIONS = {
    'owner_free': 0xfffffe000c5397f0,
    'allocate': 0xfffffe000bcfe5b8,
    'retire': 0xfffffe000bcfec48,
    'lookup': 0xfffffe000bd792dc,
    'retire_small': 0xfffffe000bcfed8c,
    'zero': 0xfffffe000c6480c0,
    'zone_retire': 0xfffffe000bd74fcc,
    'zone_allocate': 0xfffffe000bd75c64,
}
DEPS = [
    'mixed_data_backing_source.json', 'mixed_data_backing_checks.json',
    'mixed_data_release_source.json', 'mixed_data_release_checks.json',
    'mixed_data_lifecycle_source.json', 'mixed_data_lifecycle_checks.json',
    'kernel_native_reader.py', 'kext_port_tools.py',
    'resolve_kernel_collection_interfaces.py',
    'verify_daemon_reader_record_payloads_publication.py',
    'recover_versioned_request_abi.py',
]
DESCRIPTOR = 0xfffffe0007f94f98
TAGGED = DESCRIPTOR | 1
ZONE_BASE = 0xfffffe000caeb480


def build():
    kernel = Kernel()
    functions = {name: kernel.function(address) for name, address in FUNCTIONS.items()}
    backing = json.loads(read(ROOT / 'mixed_data_backing_source.json'))
    release = json.loads(read(ROOT / 'mixed_data_release_source.json'))
    assert functions['allocate'] == backing['functions']['wrapper']
    assert functions['zone_allocate'] == backing['functions']['cache']
    assert functions['retire'] == release['functions']['raw_backing_retirement']
    assert functions['owner_free'] == release['functions']['free']

    symbols = kernel.symbols(FUNCTIONS.values())
    assert {row['name'] for row in symbols[hex(FUNCTIONS['zero'])]} == {'___bzero', '_bzero'}
    flags = int.from_bytes(kernel.read(DESCRIPTOR + 0x48, 4), 'little')
    assert flags == 0x61
    counts = {
        'captured_functions': len(functions),
        'captured_instructions': sum(len(f['instructions']) for f in functions.values()),
        'original_joins': 4,
    }
    counts['captured_code_bytes'] = 4 * counts['captured_instructions']
    return {
        'generator_sha256': sha(__file__),
        'static_scope': SCOPE,
        'kernel_collection_sha256': kernel.sha256,
        'dependencies': {n: sha(ROOT / n) for n in DEPS},
        'functions': functions,
        'exact_symbols': symbols,
        'descriptor_flags_u32': flags,
        'verified_source_counts': counts,
        'new_IDA_access': False,
        **{flag: False for flag in FLAGS},
    }


if __name__ == '__main__':
    source = build()
    (ROOT / (P + '_source.json')).write_text(json.dumps(source, indent=2) + '\n')
    print(json.dumps(source['verified_source_counts']), flush=True)
