#!/usr/bin/env python3
"""Compose the exhausted singleton parser result with the command lookup."""
import copy
from contextlib import redirect_stdout
import json
import sys

import z3

from kext_port_tools import CS, IMAGE, ROOT, TABLE, qword
from kernel_native_reader import Kernel
from lskd_values_symbolic import mem, resize
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import sha
import audit_userclient_nonzero_tag_completion as completion
import recover_userclient_command_dispatch as dispatcher

source = completion.source
first = completion.first
pc = source.pc
cell = first.cell
MISS = first.MISS
TYPE_EXIT = 0xce515ae1
MATCH = 0x45e5918e
NAME = 'userclient_populated_command_lookup'
SCOPE = ('Source-composed command lookup and status handoff for the exhausted '
         '14-byte singleton of transformed type 0x6685 under nominal pointer guards.')
COMMON = (
    ('search_entry', 0xa662be0, 0x7250),
    ('search_nonnull', 0xa662c00, 0xed3d),
    ('search_node', 0xa662c60, 0xb5a8),
    ('node_decode_prepare', 0xa656ef0, 0x5e04),
    ('word_bridge', 0xa637138, 0xf930),
    ('decode_word', 0xa63d624, 0xb745),
)
AFTER_HIT = (
    ('node_fields', 0xa656d9c, 0xf918),
    ('header_extent', 0xa656e48, 0xf918),
    ('header_prepare', 0xa656ef0, 0x5e04),
    ('word_bridge', 0xa637138, 0xf930),
    ('decode_word', 0xa6382a0, 0xb745),
    ('tag_return', 0xa63930c, 0x9c55),
    ('decode_type', 0xa6370ac, 0x1086),
    ('type_return', 0xa637128, 0x266f),
    ('length_bridge', 0xa637138, 0xf930),
    ('decode_word', 0xa63747c, 0xb745),
    ('length_extent', 0xa637514, 0x1253),
)
DECODERS = first.P.M.WORD_BYTES | first.P.M.TYPE_BYTES


def extract():
    prior = source.load('userclient_command_dispatch_checks')
    kernel = Kernel()
    assert kernel.sha256 == prior['kernel_collection_sha256']
    assert dispatcher.RETAGS.items() <= first.R.RETAGS.items()
    labels = set(dispatcher.REUSED) | {
        'node_buffer_root', 'field_result', 'node_fields', 'header_extent',
        'header_prepare', 'tag_return', 'type_return', 'length_extent',
        'type_gate', 'other_type_gate', 'scalar_return', 'cleanup_gate',
    }
    spans = []
    for row in prior['spans']:
        label = row['label']
        if label not in labels:
            continue
        start, end = (int(row[key], 16) for key in ('start', 'end_exclusive'))
        assert kernel.read(start, end - start) == bytes.fromhex(row['bytes_hex'])
        landing = next(CS.disasm(kernel.read(start - 4, 4), start - 4))
        if landing.mnemonic == 'bti' and label != 'scalar_return':
            start -= 4
        if label not in dispatcher.NO_TRANSFER:
            end += 4
        spans.append(source.capture(kernel, 'nz_lookup_' + label, start, end))
    assert len(spans) == len(labels)
    slots = []
    for site, indices in dispatcher.BRANCHES.items():
        if not any(int(s['start'], 16) <= site < int(s['end_exclusive'], 16) for s in spans):
            continue
        for index in indices:
            address = TABLE + 8 * index
            record = pointer(kernel, address)
            assert int(record['target'], 16) == qword(address)
            slots.append({'load': hex(site), 'slot': hex(address), 'record': record})
    (bank,) = prior['bank_rules']
    left, right = (kernel.read(int(bank[side], 16), 256) for side in ('left', 'right'))
    for region, data in zip(('left', 'right'), (left, right)):
        assert data == IMAGE.read(int(bank[region], 16), 256)
    key, constant = (int(bank[name], 16) for name in ('key', 'constant'))
    assert all(i ^ right[left[i] ^ key] == constant for i in range(256))
    assert pointer(kernel, int(bank['slot'], 16)) == bank['original_pointer']
    return spans, slots, bank


def buffer_root():
    early, init = (source.load(name) for name in (
        'userclient_early_data_checks', 'userclient_message_initialization_checks',
    ))
    receipts = []
    for state in init['predecessor_states']:
        index = state['predecessor_case_index']
        case = early['cases'][index]
        start = int(case['frame_base_SP'], 16) + 0x8e8
        expected = int(state['handoff_state']['registers31'][11], 16) + 0x770
        writes = []
        for write in case['source_writes']:
            address = int(write['address'], 16)
            raw = bytes.fromhex(write['after_hex'])
            if max(address, start) < min(address + len(raw), start + 8):
                writes.append((address, raw, write))
        (address, raw, write), = writes
        assert address == start and len(raw) == 8 and int(write['pc'], 16) == pc(0xa635c68)
        assert int.from_bytes(raw, 'little') == expected
        for key in ('known_mask_hex', 'provenance_hex'):
            assert bytes.fromhex(case['frame'][key])[0x8e8:0x8f0] == bytes([1]) * 8
        assert bytes.fromhex(case['frame']['bytes_hex'])[0x8e8:0x8f0] == raw
        receipts.append({'case_index': index, 'store': write})
    return receipts


class Model(completion.Model):
    def load(self, address, size):
        address = self.norm(address)
        if self.pc in self.lookup_slots:
            assert size == 8
            slots = self.lookup_slots[self.pc]
            self.address_checks.append(z3.Or(*[address == slot for slot, _ in slots]))
            value = resize(0, 64)
            for slot, target in slots:
                value = z3.If(address == slot, resize(target, 64), value)
            self.rom(address, size, 'original_lookup_pointer_table')
            return value
        if self.pc in DECODERS:
            assert size == 1
            owner, offset, _ = self.classify(address, size)
            assert owner == 'record_buffer'
            stored = self.byte_overlay[address.sexpr()]
            self.lookup_bytes.append(offset)
            self.accesses.append({'PC': self.pc, 'address': address, 'size': size,
                                  'kind': 'record_header', 'write': False})
            return stored
        return super().load(address, size)

    def lookup(self, label, target=None, modifier=None):
        self.connect('lookup_' + label)
        if target is not None:
            first.P.add_edge(self, target, modifier)


def trace(parent, parser, spans, slots, bank, hit, *, lookup_only=False):
    v, earlier, _ = completion.compose(parser, parent, 4)
    v.__class__ = Model
    v.lookup_slots = {}
    for row in slots:
        v.lookup_slots.setdefault(int(row['load'], 16), []).append(
            (int(row['slot'], 16), int(row['record']['target'], 16))
        )
    assert bank in v.evidence['bank_rules']
    prefix_cells = set(v.live_cells)
    prefix_regs = set(v.live_regs)
    prefix_guards = len(v.branch_guards)
    prefix_accesses = len(v.accesses)
    prefix_edges = len(v.edges)
    v.lookup_bytes = []
    v.e['spans'].extend(copy.deepcopy(spans))
    root = v.sp + 0x8e8
    root_key = (z3.simplify(root).sexpr(), 8)
    assert root_key not in v.memory
    mem(v, root, 8, v.ctx + 0x770)
    v.entry_memory[root_key] = cell(v, root, 8)
    v.address_checks.append(cell(v, v.J, 8) == 0)
    for step in COMMON:
        v.lookup(*step)
    decoded_tag = first.P.tag(v)
    tag_is_match = (decoded_tag ^ first.SUCCESS) == MATCH
    observed = v.read('w22')
    v.lookup('tag_match', 0xa662c44 if hit else 0xa63d680, 0xde40)
    if not hit:
        v.lookup('search_next', 0xa662c00, 0xed3d)
        v.lookup('search_node', 0xa662c44, 0xb5a8)
    v.lookup('search_result', 0xa662b00, 0x7250)
    v.lookup('search_callback', 0xa656cfc, 0x8d28)
    lookup_status = first.SUCCESS if hit else MISS
    final_status = TYPE_EXIT if hit else MISS
    contracts = {
        'protected_tag_read': observed != (decoded_tag ^ first.SUCCESS),
        'lookup_output_and_status': z3.Or(
            cell(v, v.ctx + 0x1f8, 8) != (v.J if hit else 0),
            cell(v, v.ctx + 0x2b0, 8) != (v.J if hit else 0),
            v.read('w23') != lookup_status,
        ),
    }
    if lookup_only:
        return v, earlier, contracts, tag_is_match, None
    v.lookup('field_result', 0xa656d48 if hit else 0xa656f00, 0x1253)
    if hit:
        for step in AFTER_HIT:
            v.lookup(*step)
        contracts['same_node_buffer_type_and_bounded_extent'] = z3.Or(
            cell(v, v.ctx + 0x770, 8) != v.Z, cell(v, v.J + 0x10, 4) != 14,
            cell(v, v.src + 0x1c0, 8) != 14, cell(v, v.src + 0xd88, 2) != 0x6685,
        )
        v.branch_choices[pc(0xa637524)] = True
        v.branch_choices[pc(0xa63a61c)] = True
        v.lookup('type_gate')
        v.lookup('other_type_gate')
        v.lookup('scalar_return', 0xa656f00, 0xf918)
        contracts['no_scalar_publication'] = z3.Or(
            cell(v, v.src + 0xcf0, 4) != first.SUCCESS, cell(v, v.sp + 0xa78, 8) != 14,
        )
    contracts['raw_status_at_common_cleanup'] = v.read('w23') != final_status
    v.lookup('cleanup_gate', 0xa656f4c, 0x082d)
    contracts['cleanup_retains_container_and_status'] = z3.Or(
        cell(v, v.src + 0xde4, 4) != final_status,
        cell(v, v.ctx + 0x600, 8) != v.object, v.read('w24') != 0x1a,
    )
    assert v.lookup_bytes == (list(range(4)) + list(range(10)) if hit else list(range(4)))
    assert set(v.live_cells) - prefix_cells <= {root_key}
    assert v.live_regs == prefix_regs
    for guard in v.branch_guards[prefix_guards:]:
        if not any(z3.eq(guard, normal) for normal in v.normal_guards):
            v.address_checks.append(guard)
    accesses = []
    for row in v.accesses[prefix_accesses:]:
        owner, offset = row['kind'], None
        if not owner.startswith('original_'):
            owner, offset, _ = v.classify(row['address'], row['size'])
        accesses.append({'PC': hex(row['PC']), 'owner': owner, 'offset_bytes': offset,
                         'width_bytes': row['size'], 'write': row['write']})
    profile = {'lookup_status': hex(lookup_status), 'cleanup_status': hex(final_status),
               'record_reads': v.lookup_bytes, 'accesses': accesses,
               'edges': [hex(row['PC']) for row in v.edges[prefix_edges:]],
               'predecessor_guard_count': prefix_guards,
               'contracts': list(contracts)}
    return v, earlier, contracts, tag_is_match, profile


def build():
    spans, slots, bank = extract()
    root_receipts = buffer_root()
    parent = source.load('userclient_nonzero_tag_record_checks')
    parser = source.load('userclient_nonzero_tag_completion_checks')
    queries = []
    profiles = {}
    for hit, name in ((False, 'miss'), (True, 'match')):
        v, earlier, contracts, matching, profile = trace(parent, parser, spans, slots, bank, hit)
        conditional = matching if hit else z3.Not(matching)
        assumptions = (v.owned() + v.branch_guards[:profile['predecessor_guard_count']]
                       + v.normal_guards + first.selected(v) + [conditional])
        goals = list(earlier.values()) + list(v.contracts.values()) + list(contracts.values())
        bad = z3.Or(*goals, *[z3.Not(check) for check in v.address_checks])
        queries.append(first.P.solve('populated_lookup_' + name, assumptions, bad))
        profiles[name] = profile
    altered = copy.deepcopy(spans)
    publish = next(row for row in altered if row['label'] == 'nz_lookup_search_result')
    data = bytearray.fromhex(publish['bytes_hex'])
    offset = pc(0xa662c4c) - int(publish['start'], 16)
    original = data[offset:offset + 4].hex()
    data[offset:offset + 4] = bytes.fromhex('1f2003d5')
    publish['bytes_hex'] = data.hex()
    v, earlier, contracts, matching, _ = trace(
        parent, parser, altered, slots, bank, True, lookup_only=True,
    )
    control = z3.SolverFor('QF_BV')
    control.set(timeout=60000)
    control.add(*v.owned(), *v.branch_guards, *first.selected(v), matching,
                *v.address_checks, *[z3.Not(g) for g in earlier.values()],
                *[z3.Not(g) for g in v.contracts.values()])
    assert control.check() == z3.sat, control.reason_unknown()
    control.add(contracts['lookup_output_and_status'])
    assert control.check() == z3.sat, control.reason_unknown()
    return {
        'scope': SCOPE, 'generator_sha256': sha(__file__),
        'source_sha256': parser['source_sha256'],
        'kernel_collection_sha256': parser['kernel_collection_sha256'],
        'inputs': {name: sha(ROOT / (name + '.json')) for name in (
            'userclient_command_dispatch_checks', 'userclient_nonzero_tag_record_checks',
            'userclient_nonzero_tag_completion_checks', 'userclient_early_data_checks',
            'userclient_message_initialization_checks',
        )},
        'spans': spans, 'branch_slots': slots, 'callback_bank': bank,
        'buffer_root_receipts': root_receipts, 'profiles': profiles, 'source_proofs': queries,
        'negative_source_control': {'PC': hex(pc(0xa662c4c)), 'original_word_hex': original,
                                    'omitted_store_result': 'sat', 'query': control.to_smt2()},
        'all_checks_pass': True,
        'native_execution_observed': False, 'full_goal_complete': False,
    }


if __name__ == '__main__':
    with redirect_stdout(sys.stderr):
        evidence = build()
    print(json.dumps(evidence, indent=2))
