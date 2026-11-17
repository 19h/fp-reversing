#!/usr/bin/env python3
"""Capture same-object parser completion and retirement boundaries."""
import json

from kext_port_tools import IMAGE, ROOT, TABLE, qword
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read, sha
import recover_userclient_container_staging as staging
import recover_userclient_fallback_metadata as metadata
import recover_userclient_parser_cleanup as cleanup
import recover_userclient_record_metadata as header
import recover_userclient_zero_tag_unwind as caller

NAME = 'userclient_nonzero_tag_completion'
pc = metadata.pc
capture = metadata.Parent.capture
SPANS = {
    'exhausted': (pc(0xa642180), pc(0xa6421b0)),
    'success': metadata.SPANS['success'],
    'input_gate': (pc(0xa6421dc), pc(0xa642248)),
    'header_extent': (pc(0xa642248), pc(0xa642330)),
    'outcome': (pc(0xa6423c0), pc(0xa6423f4)),
}
SPANS.update({
    name: (start if name in {'container_return', 'node_data_return', 'node_type_return'} else start - 4, end + 4)
    for name, (start, end) in cleanup.SPANS.items()
    if name not in cleanup.NO_TRANSFER and not name.startswith('pending_')
})
SPANS.update({name: caller.SPANS[name] for name in ('caller', 'field_gate', 'field_request')})

BRANCHES = {}
for table in (staging.BRANCHES, header.BRANCHES, metadata.BRANCHES, cleanup.BRANCHES, caller.BRANCHES):
    for address, indices in table.items():
        if any(start <= address < end for start, end in SPANS.values()):
            BRANCHES.setdefault(address, set()).update(indices)
BRANCHES = {address: sorted(indices) for address, indices in BRANCHES.items()}
BANK_PCS = {name: sites for name, sites in cleanup.BANK_PCS.items() if not name.startswith('pending_')}
PREFIX = (
    (0x5f8, 'context', 0x4e8, 0xa635d88),
    (0x988, 'context', 0x600, 0xa635e78),
    (0x5a8, 'context', 0x1f8, 0xa635c40),
    (0x9f8, 'literal', pc(0x7949ed0), 0xa636528),
    (0x9f0, 'literal', pc(0x792fec0), 0xa636538),
    (0xa10, 'literal', pc(0x7949fd0), 0xa635400),
    (0xa18, 'literal', pc(0x792ffc0), 0xa63541c),
)
DEPENDENCIES = (
    'userclient_nonzero_tag_record_checks.json', 'userclient_nonzero_tag_record_audit.json',
    'userclient_parser_cleanup_checks.json', 'userclient_parser_cleanup_audit.json',
    'userclient_early_data_checks.json', 'userclient_message_initialization_checks.json',
    'audit_userclient_nonzero_tag_record.py',
)
SCOPE = ('Conditional completion of the populated first-record parser state. Exhausted input publishes '
         'the same container and reaches the command lookup request. A short suffix retires the same '
         'record buffer, node and container by ABI request and resumes the failure arm. Native effects, '
         'command lookup results, outer return and daemon transaction identity remain unknown.')


def load(stem):
    return json.loads(read(ROOT / (stem + '.json')))


def prefix_receipts():
    early = load('userclient_early_data_checks')
    init = load('userclient_message_initialization_checks')
    rows = []
    for state in init['predecessor_states']:
        index = state['predecessor_case_index']
        case = early['cases'][index]
        frame = int(case['frame_base_SP'], 16)
        context = int(state['handoff_state']['registers31'][11], 16)
        contents, known, provenance = (
            bytes.fromhex(case['frame'][key]) for key in ('bytes_hex', 'known_mask_hex', 'provenance_hex')
        )
        cells = []
        for offset, role, value, producer in PREFIX:
            start = frame + offset
            stores = []
            for store in case['source_writes']:
                address = int(store['address'], 16)
                raw = bytes.fromhex(store['after_hex'])
                if max(address, start) < min(address + len(raw), start + 8):
                    stores.append((address, raw, store))
            (address, raw, store), = stores
            stop = offset + 8
            assert address == start and int(store['pc'], 16) == pc(producer) and len(raw) == 8
            assert raw == contents[offset:stop] and known[offset:stop] == provenance[offset:stop] == bytes([1]) * 8
            assert int.from_bytes(raw, 'little') == (context + value if role == 'context' else value)
            cells.append({'offset': hex(offset), 'store': store})
        rows.append({'predecessor_case_index': index, 'frame': hex(frame), 'cells': cells})
    return rows


def build():
    kernel = Kernel()
    parent = load('userclient_nonzero_tag_record_checks')
    destroy = load('userclient_parser_cleanup_checks')
    spans = [capture(kernel, 'nz_complete_' + name, start, end) for name, (start, end) in SPANS.items()]
    prefix = [capture(kernel, 'prefix_' + format(offset, 'x'), pc(producer), pc(producer + 4))
              for offset, _, _, producer in PREFIX]
    slots = []
    for address, indices in BRANCHES.items():
        for index in indices:
            slot = TABLE + 8 * index
            record = pointer(kernel, slot)
            assert int(record['target'], 16) == qword(slot)
            slots.append({'load': hex(address), 'slot': hex(slot), 'record': record})
    rules = [rule for rule in destroy['bank_rules'] if rule['name'] in BANK_PCS]
    for rule in rules:
        left, right = (kernel.read(int(rule[side], 16), 256) for side in ('left', 'right'))
        for side, data in zip(('left', 'right'), (left, right)):
            assert data == IMAGE.read(int(rule[side], 16), 256)
        key, constant = (int(rule[field], 16) for field in ('key', 'constant'))
        assert all(i ^ right[left[i] ^ key] == constant for i in range(256))
        assert pointer(kernel, int(rule['slot'], 16)) == rule['original_pointer']
    descriptors = [entry for entry in cleanup.build()['typed_descriptors']
                   if entry['role'] in {'container_retirement', 'list_node_retirement'}]
    assert len(descriptors) == 2
    return {
        'extractor_sha256': sha(__file__),
        'source_sha256': parent['source_sha256'],
        'kernel_collection_sha256': kernel.sha256,
        'scope': SCOPE,
        'dependencies': {name: sha(ROOT / name) for name in DEPENDENCIES},
        'spans': spans,
        'prefix_source': prefix,
        'prefix_receipts': prefix_receipts(),
        'pointer_observations': slots,
        'bank_rules': rules,
        'retirement_descriptors': descriptors,
    }


if __name__ == '__main__':
    print(json.dumps(build(), indent=2))
