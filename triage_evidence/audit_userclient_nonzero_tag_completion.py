#!/usr/bin/env python3
"""Lift parser continuations with the predecessor's live registers and memory."""
import copy
from contextlib import redirect_stdout
import json
import sys

import z3

from kext_port_tools import TABLE, qword
from lskd_values_symbolic import mem, resize
from verify_daemon_reader_record_payloads_publication import sha
import audit_userclient_nonzero_tag_record as first
import recover_userclient_nonzero_tag_completion as source

pc = source.pc
SUCCESS = first.SUCCESS
SHORT = 0xce515bb8
cell = first.cell


class Model(first.Model):
    def classify(self, address, size):
        owner = super().classify(address, size)
        assert owner[0] not in self.retired, ('access after retirement request return', hex(self.pc), owner)
        return owner

    def load(self, address, size):
        address = self.norm(address)
        for rule in self.completion['bank_rules']:
            name = rule['name']
            left_pc, right_pc, slot_pc = source.BANK_PCS[name]
            if self.pc == left_pc:
                assert size == 1
                left = int(rule['left'], 16)
                self.left[name] = z3.Extract(7, 0, address - left)
                self.bankbyte[name] = z3.BitVec('completion_bank_' + name, 8)
                self.address_checks.append(address == left + z3.ZeroExt(56, self.left[name]))
                self.rom(address, size, 'original_retirement_bank')
                return self.bankbyte[name]
            if self.pc == right_pc:
                assert size == 1
                index = self.bankbyte[name] ^ int(rule['key'], 16)
                self.address_checks.append(address == int(rule['right'], 16) + z3.ZeroExt(56, index))
                self.bank_events.append(name)
                self.rom(address, size, 'original_retirement_bank')
                return self.left[name] ^ int(rule['constant'], 16)
            if self.pc == slot_pc:
                assert size == 8
                self.address_checks.append(address == int(rule['slot'], 16))
                self.rom(address, size, 'original_retirement_bank_pointer')
                return resize(int(rule['original_pointer']['target'], 16), 64)
        if self.pc in source.BRANCHES:
            assert size == 8
            slots = [TABLE + 8 * index for index in source.BRANCHES[self.pc]]
            self.address_checks.append(z3.Or(*[address == slot for slot in slots]))
            value = resize(0, 64)
            for slot in slots:
                value = z3.If(address == slot, resize(qword(slot), 64), value)
            self.rom(address, size, 'original_completion_pointer_table')
            return value
        return super().load(address, size)

    def step(self, name, target, modifier):
        self.connect('complete_' + name)
        first.P.add_edge(self, target, modifier)

    def retire(self, name, owner, target, call, x0, x1):
        edge = self.edges[-1]
        self.contracts[name] = z3.Or(
            edge['PC'] != pc(call), edge['target'] != pc(target), edge['link'] != pc(call + 4),
            edge['arguments'][0] != x0, edge['arguments'][1] != x1,
        )
        self.returned(name, z3.BitVec('completion_ignored_' + name, 64))
        self.retired.add(owner)


def compose(evidence, parent, length, *, trace_caller=True):
    v, predecessor = first.compose(parent, length)
    prefix_regs = set(v.live_regs)
    prefix_guards = len(v.branch_guards)
    v.__class__ = Model
    v.completion = evidence
    v.retired = set()
    v.e['spans'].extend(copy.deepcopy(evidence['spans']))
    for offset, role, value, _ in source.PREFIX:
        address = v.sp + offset
        assert (z3.simplify(address).sexpr(), 8) not in v.memory
        mem(v, address, 8, v.ctx + value if role == 'context' else value)
        v.entry_memory[(z3.simplify(address).sexpr(), 8)] = cell(v, address, 8)

    v.contracts = {}
    prefix_accesses = len(v.accesses)
    if length == 4:
        v.step('exhausted', 0xa6421b0, 0x5ab2)
        v.step('success', 0xa660ac8, 0x8ba3)
    else:
        v.step('input_gate', 0xa642248, 0x55ab)
        v.step('header_extent', 0xa6423c0, 0x55ab)
        v.contracts['short_header_keeps_cursor'] = z3.Or(
            v.read('w23') != SHORT, cell(v, v.sp + 0xa80, 8) != 10 + length,
            cell(v, v.ctx + 0x3d8, 8) != v.buffer,
        )
        for name, target, modifier in (
            ('outcome', 0xa662440, 0xc9dc), ('failure_prepare', 0xa66229c, 0xb23e),
            ('failure_bridge', 0xa660468, 0x0189), ('destroy_entry', 0xa6604a4, 0xb775),
            ('destroy_object', 0xa6604fc, 0x53f6), ('destroy_head', 0xa660750, 0xad37),
            ('node_gate', 0xa660790, 0x776f),
        ):
            v.step(name, target, modifier)
        v.contracts['same_singleton_and_saved_successor'] = z3.Or(
            v.read('x23') != v.J, v.read('x25') != 0, cell(v, v.ctx + 0x4e8, 8) != v.object,
            cell(v, v.src + 0xc10, 4) != SHORT,
        )
        v.step('node_data_request', 0xc4ba84c, 0x085d)
        v.retire('buffer_free', 'record_buffer', 0xc4ba84c, 0xa6607e8, v.Z, 10 + length)
        v.run('nz_complete_node_data_return')
        first.P.add_edge(v, 0xa66066c, 0x776f)
        v.contracts['node_buffer_cleared_after_data_request'] = cell(v, v.J + 0x18, 8) != 0
        v.step('node_type_request', 0xc4ba368, 0x4d6a)
        v.retire('node_free', 'new_node', 0xc4ba368, 0xa660708, pc(0x847be20), v.J)
        v.run('nz_complete_node_type_return')
        first.P.add_edge(v, 0xa660534, 0xad37)
        v.step('container_request', 0xc4ba368, 0x4d6a)
        v.retire('container_free', 'container', 0xc4ba368, 0xa6605c4, pc(0x847bde0), v.object)
        v.run('nz_complete_container_return')
        first.P.add_edge(v, 0xa660614, 0x1fb3)
        v.step('destroy_resume', 0xa660a98, 0x4ed7)
        v.step('failure_return', 0xa660ac8, 0x8ba3)

    v.step('parser_output', 0xa660ae0, 0xcd46)
    v.step('parser_resume', 0xa656c08, 0x481b)
    status, output = (SUCCESS, v.object) if length == 4 else (SHORT, 0)
    v.contracts['caller_receives_status_output_and_cursor'] = z3.Or(
        v.read('w23') != status, v.read('w30') != SUCCESS, cell(v, v.ctx + 0x600, 8) != output,
        cell(v, v.sp + 0xa80, 8) != 10 + length,
    )
    if not trace_caller:
        return v, predecessor, v.accesses[prefix_accesses:]
    if length == 4:
        v.step('caller', 0xa656c44, 0x8d28)
        v.step('field_gate', 0xa656ca0, 0x6d31)
        v.step('field_request', 0xa662ab4, 0x0ee9)
        v.contracts['same_node_container_and_command_request'] = z3.Or(
            v.read('x22') != v.object, v.read('w9') != 0x45e5918e, v.read('x10') != v.ctx + 0x1f8,
            cell(v, v.ctx + 0x1f8, 8) != 0, cell(v, v.object, 8) != v.J,
            cell(v, v.object + 8, 8) != v.J, cell(v, v.J + 0x18, 8) != v.Z,
            cell(v, v.J + 0x10, 4) != 14,
            cell(v, v.src + 0xc10, 4) != SUCCESS,
        )
    else:
        v.step('caller', 0xa65f358, 0x8d28)
        v.contracts['short_suffix_cleanup_clears_both_container_cells'] = z3.Or(
            cell(v, v.ctx + 0x228, 8) != 0, cell(v, v.ctx + 0x4e8, 8) != 0,
            cell(v, v.src + 0xc10, 4) != SHORT,
        )
    assert v.live_regs == prefix_regs
    assert len(v.branch_guards) == prefix_guards
    return v, predecessor, v.accesses[prefix_accesses:]


def context_projection():
    parent = first.P.Parent
    evidence = source.load('userclient_fallback_parser_checks')
    proofs = []
    for mode in parent.MODES:
        actual = parent.tag_result(evidence, mode)
        context = actual.common['C']
        premises = actual.owned() + actual.guards + actual.extra
        entries = ((0x618, actual.buffer), (0x188, context + 0x600), (0x5c8, pc(0xa656c08)))
        for offset, expected in entries:
            actual_cell = parent.H.cell(actual, context + offset, 8)
            proofs.append(first.P.solve(mode + '_context_' + hex(offset), premises, actual_cell != expected))
    return proofs


def source_controls(evidence, parent):
    controls = []
    for length, address, contract in (
        (4, 0xa660ad0, 'caller_receives_status_output_and_cursor'),
        (2, 0xa6605e0, 'short_suffix_cleanup_clears_both_container_cells'),
    ):
        altered = copy.deepcopy(evidence)
        span = next(row for row in altered['spans'] if int(row['start'], 16) <= pc(address) < int(row['end_exclusive'], 16))
        data = bytearray.fromhex(span['bytes_hex'])
        offset = pc(address) - int(span['start'], 16)
        original = bytes(data[offset:offset + 4])
        data[offset:offset + 4] = bytes.fromhex('1f2003d5')
        span['bytes_hex'] = data.hex()
        result, previous, _ = compose(altered, parent, length, trace_caller=length != 4)
        solver = z3.SolverFor('QF_BV')
        solver.set(timeout=60000)
        solver.add(*result.owned(), *result.branch_guards, *first.selected(result), *result.address_checks)
        solver.add(*[z3.Not(q) for q in previous.values()], result.contracts[contract])
        assert solver.check() == z3.sat, (hex(pc(address)), solver.reason_unknown())
        controls.append({'PC': hex(pc(address)), 'original_word_hex': original.hex(),
                         'omitted_store_breaks': contract, 'query': solver.to_smt2(), 'result': 'sat'})
    return controls


def audit(evidence):
    parent = source.load('userclient_nonzero_tag_record_checks')
    proofs = context_projection()
    profiles = []
    for length in range(5):
        v, predecessor, accesses = compose(evidence, parent, length)
        premise = v.owned() + v.branch_guards + first.selected(v)
        bad = z3.Or(*predecessor.values(), *v.contracts.values(), *[z3.Not(c) for c in v.address_checks])
        proofs.append(first.P.solve('completion_length_' + str(length), premise, bad))
        inventory = []
        for access in accesses:
            if access['kind'].startswith('original_'):
                owner = access['kind']
                displacement = None
            else:
                # Retirement is checked online. Some accesses here predate a retirement.
                owner, displacement, _ = first.Model.classify(v, access['address'], access['size'])
                assert owner not in {'protected_input', 'original_input', 'record_buffer'}
            inventory.append({'PC': hex(access['PC']), 'owner': owner, 'offset_bytes': displacement,
                              'width_bytes': access['size'], 'write': access['write']})
        profiles.append({
            'body_bytes': length, 'suffix_bytes': 4 - length, 'contracts': list(v.contracts),
            'continuation_accesses': inventory,
            'ordinary_retirement_returns': v.returns[2:],
            'terminal_branch_PC': hex(v.edges[-1]['PC']),
            'terminal_target': hex(z3.simplify(v.edges[-1]['target']).as_long()),
        })
    return {
        'auditor_sha256': sha(__file__), 'scope': source.SCOPE, 'source_proofs': proofs,
        'profiles': profiles, 'negative_source_controls': source_controls(evidence, parent),
        'all_checks_pass': True, 'native_target_executed': False,
        'full_goal_complete': False,
    }


if __name__ == '__main__':
    with redirect_stdout(sys.stderr):
        receipt = audit(source.load(source.NAME + '_checks'))
    print(json.dumps(receipt, indent=2))
