#!/usr/bin/env python3
"""Capture the original descriptor preparation, completion and release interfaces."""
import json

from kernel_native_reader import Kernel
from kext_port_tools import IMAGE, ROOT
from recover_kext_cold_init import pointer
from recover_versioned_request_abi import FLAGS
from verify_daemon_reader_record_payloads_publication import read, sha

P = 'descriptor_prepare_lifecycle'
SCOPE = (
    'Source-level descriptor prepare and complete count, normal final-completion '
    'metadata interface, reinitialization and final-release drain, and kext caller '
    'handoffs. Lower VM effects and native execution remain unobserved.'
)
VTABLE = 0xfffffe0007f85d80
FUNCTIONS = {
    'prepare': 0xfffffe000c5353b4,
    'wire_virtual': 0xfffffe000c535624,
    'complete': 0xfffffe000c534a2c,
    'complete_auxiliary': 0xfffffe000c534e5c,
    'direction': 0xfffffe000c5316b8,
    'set_used': 0xfffffe000c5352b8,
    'base_init': 0xfffffe000c537720,
    'buffer_init': 0xfffffe000c524bdc,
    'dma_operation': 0xfffffe000c5365e8,
    'general_free': 0xfffffe000c538044,
    'buffer_free': 0xfffffe000c525288,
    'owner_free': 0xfffffe000c5397f0,
}
DEPS = [
    'buffer_construction_flow_source.json', 'buffer_construction_flow_checks.json',
    'dma_map_constraints_source.json', 'mixed_data_release_source.json',
    'mixed_data_release_checks.json', 'mixed_data_zone_geometry_checks.json',
    'kernel_native_reader.py', 'kext_port_tools.py', 'recover_kext_cold_init.py',
    'resolve_kernel_collection_interfaces.py',
    'verify_daemon_reader_record_payloads_publication.py',
    'recover_versioned_request_abi.py',
]


def fragment(kernel, start, end):
    raw = kernel.read(start, end - start)
    assert raw == IMAGE.read(start, end - start)
    instructions = [{'ea': hex(i.address), 'mnemonic': i.mnemonic, 'operands': i.op_str}
                    for i in kernel.cs.disasm(raw, start)]
    assert len(instructions) * 4 == len(raw)
    return {'start': hex(start), 'end': hex(end), 'bytes': raw.hex(),
            'instructions': instructions}


def build():
    kernel = Kernel()
    functions = {name: kernel.function(address) for name, address in FUNCTIONS.items()}
    construction = json.loads(read(ROOT / 'buffer_construction_flow_source.json'))
    release = json.loads(read(ROOT / 'mixed_data_release_source.json'))
    for name in ('prepare', 'base_init', 'buffer_init', 'dma_operation'):
        assert functions[name] == construction['functions'][name]
    for name in ('general_free', 'buffer_free', 'owner_free'):
        assert functions[name] == release['functions']['free' if name == 'owner_free' else name]

    kext = {
        'init': fragment(kernel, 0xfffffe000a5080d4, 0xfffffe000a508110),
        'cleanup': fragment(kernel, 0xfffffe000a5085f4, 0xfffffe000a50865c),
    }
    assert kext['cleanup'] == release['kext_cleanup']
    slots = []
    for offset in (0x28, 0xb0, 0x148, 0x1e8, 0x218, 0x220):
        p = pointer(kernel, VTABLE + offset)
        assert p['authenticated'] and p['chain_membership_verified']
        p['offset'] = offset
        slots.append(p)
    symbols = kernel.symbols([*FUNCTIONS.values(), *(int(p['target'], 16) for p in slots)])
    counts = {
        'captured_functions': len(functions),
        'kernel_instructions': sum(len(f['instructions']) for f in functions.values()),
        'kext_instructions': sum(len(f['instructions']) for f in kext.values()),
        'original_slots': len(slots),
    }
    counts['captured_code_bytes'] = 4 * (counts['kernel_instructions'] + counts['kext_instructions'])
    return {
        'generator_sha256': sha(__file__),
        'static_scope': SCOPE,
        'kernel_collection_sha256': kernel.sha256,
        'dependencies': {n: sha(ROOT / n) for n in DEPS},
        'functions': functions,
        'kext_fragments': kext,
        'nominal_slots': slots,
        'exact_symbols': symbols,
        'verified_source_counts': counts,
        'new_IDA_access': False,
        **{flag: False for flag in FLAGS},
    }


if __name__ == '__main__':
    source = build()
    (ROOT / (P + '_source.json')).write_text(json.dumps(source, indent=2) + '\n')
    print(json.dumps(source['verified_source_counts']), flush=True)
