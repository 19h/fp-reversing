#!/usr/bin/env python3
"""Trace the populated caller through destruction, copy-back and core return."""
from contextlib import redirect_stdout
import json
import sys

import z3

from kext_port_tools import IMAGE, ROOT, TABLE, qword
from kernel_native_reader import Kernel
from lskd_values_symbolic import mem, resize
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import sha
import audit_userclient_populated_command_lookup as lookup
import audit_userclient_zero_tag_provider as caller_model
import audit_userclient_zero_tag_return as local_return
import audit_userclient_zero_tag_unwind as common
import recover_userclient_zero_tag_unwind as unwind

source = lookup.source
first = lookup.first
pc = lookup.pc
cell = lookup.cell
NAME = 'userclient_populated_cleanup'
SCOPE = ('Source composition for both command-tag outcomes of the exhausted 14-byte singleton. '
         'Trace the destructor, original-input restoration, guarded core return and nominal '
         'selector 26 handler result.')
PATH = (
    ('destroy_request', 0xa66229c, 0xb23e),
    ('failure_bridge', 0xa660468, 0x0189),
    ('destroy_entry', 0xa6604a4, 0xb775),
    ('destroy_object', 0xa6604fc, 0x53f6),
    ('destroy_head', 0xa660750, 0xad37),
    ('node_gate', 0xa660790, 0x776f),
)
RETIREMENTS = (
    ('node_data_request', 'record_buffer', 0xc4ba84c, 0xa6607e8, 0x085d,
     'node_data_return', 0xa66066c, 0x776f),
    ('node_type_request', 'new_node', 0xc4ba368, 0xa660708, 0x4d6a,
     'node_type_return', 0xa660534, 0xad37),
    ('container_request', 'container', 0xc4ba368, 0xa6605c4, 0x4d6a,
     'container_return', 0xa660614, 0x1fb3),
)
TAIL = (
    ('aux_gate', 0xa665f8c, 0xd784),
    ('primary_load', 0xa665fc8, 0x1aac),
    ('copy_gate', 0xa66609c, 0x7924),
    ('copy_prepare', 0xa6660b4, 0x8a06),
    ('copy_step', 0xa666118, 0x8a06),
    ('primary_free', 0xc4ba84c, 0x085d),
    ('primary_return', 0xa6661bc, 0x2d2b),
    ('context_free', 0xc4ba368, 0x4d6a),
    ('workspace_free', 0xc4b9a24, 0x84ff),
)
TAIL_BANKS = ('primary_free', 'context_free', 'context_descriptor', 'workspace_free')
ROOT_CELLS = (
    ('F', 0x670, 'C', 0x90), ('F', 0x728, 'C', 0x3c0),
    ('F', 0x8f8, 'I', 0), ('F', 0x930, None, pc(0x792fdc0)),
    ('F', 0x928, None, pc(0x79392f0)),
    ('C', 0x90, 'B', 0), ('C', 0x3c0, None, 0),
    ('S', 0xe10, None, 14 + 0x621745fcc03f95d4),
)
DEPENDENCIES = (
    'userclient_nonzero_tag_record_checks.json', 'userclient_nonzero_tag_record_audit.json',
    'userclient_nonzero_tag_completion_checks.json', 'userclient_populated_command_lookup_audit.json',
    'userclient_fallback_parser_checks.json', 'userclient_zero_tag_unwind_checks.json',
    'userclient_zero_tag_return_checks.json', 'userclient_zero_tag_return_audit.json',
    'audit_userclient_populated_command_lookup.py', 'audit_userclient_zero_tag_unwind.py',
    'audit_userclient_zero_tag_return.py',
    'userclient_transfer_boundary_checks.json', 'userclient_zero_tag_provider_checks.json',
    'audit_userclient_zero_tag_provider.py', 'audit_userclient_transfer_boundary.py',
)


def extract(parser):
    kernel = Kernel()
    assert kernel.sha256 == parser['kernel_collection_sha256']
    caller = source.load('userclient_zero_tag_unwind_checks')
    start, end = unwind.SPANS['destroy_request']
    request = source.capture(kernel, 'nz_lookup_destroy_request', start, end)
    assert request['bytes_hex'] == next(s['bytes_hex'] for s in caller['source']['spans']
                                        if s['label'] == 'destroy_request')
    slots = []
    edges = dict(unwind.BRANCHES)
    # The common destructor stores the callback selected at this call site.
    for address, indices in ((pc(0xa656f7c), edges[pc(0xa656f7c)]),
                             (pc(0xa660470), [0x1a])):
        for index in indices:
            slot = TABLE + 8 * index
            record = pointer(kernel, slot)
            assert int(record['target'], 16) == qword(slot)
            slots.append({'load': hex(address), 'slot': hex(slot), 'record': record})
    tail = []
    for name, _, _ in TAIL:
        start, end = unwind.SPANS[name]
        label = 'populated_' + name
        row = source.capture(kernel, label, start, end)
        assert row['bytes_hex'] == next(s['bytes_hex'] for s in caller['source']['spans']
                                       if s['label'] == name)
        tail.append(row)
    for site, indices in unwind.BRANCHES.items():
        if not any(int(row['start'], 16) <= site < int(row['end_exclusive'], 16) for row in tail):
            continue
        for index in indices:
            slot = TABLE + 8 * index
            record = pointer(kernel, slot)
            assert int(record['target'], 16) == qword(slot)
            slots.append({'load': hex(site), 'slot': hex(slot), 'record': record})
    banks = []
    for name in TAIL_BANKS:
        rule = next(r for r in caller['bank_rules'] if r['name'] == name)
        data = []
        for side in ('left', 'right'):
            address = int(rule[side], 16)
            raw = kernel.read(address, 256)
            assert raw == IMAGE.read(address, 256)
            data.append(raw)
        left, right = data
        key, constant = (int(rule[field], 16) for field in ('key', 'constant'))
        assert all(i ^ right[left[i] ^ key] == constant for i in range(256))
        assert pointer(kernel, int(rule['slot'], 16)) == rule['original_pointer']
        banks.append(rule)
    returns = source.load('userclient_zero_tag_return_checks')
    assert kernel.sha256 == returns['kernel_collection_sha256']
    for row in returns['source']['spans']:
        start = int(row['start'], 16)
        expected = bytes.fromhex(row['bytes_hex'])
        assert kernel.read(start, len(expected)) == IMAGE.read(start, len(expected)) == expected
    for row in returns['source']['original_pointers']:
        assert pointer(kernel, int(row['slot'], 16)) == row
    return request, slots, tail, banks, returns


def root_projection():
    predecessor = first.P.Parent
    original = source.load('userclient_fallback_parser_checks')
    proofs = []
    for mode in predecessor.MODES:
        v = predecessor.tag_result(original, mode)
        c = v.common
        bases = {**c, 'I': v.original_input, 'B': v.buffer}
        premises = v.owned() + v.guards + v.extra
        normal = ((c['N'], resize(14, 32)), (c['L'], resize(4, 32)))
        violations = [z3.Or(c['N'] != 14, c['L'] != 4)]
        for owner, offset, role, value in ROOT_CELLS:
            prior = predecessor.H.cell(v, bases[owner] + offset, 8)
            expect = bases[role] + value if role else value
            violations.append(z3.simplify(z3.substitute(prior != expect, *normal)))
        for index, byte in enumerate(v.input_bytes):
            store = next(r for r in v.fallback_copy_stores if r['index'] == index)
            address = v.buffer + index
            expected = byte ^ first.P.M.mask(address, resize(first.P.M.KEY0, 64))
            violations.append(z3.simplify(z3.substitute(
                z3.Or(store['address'] != address, store['value'] != expected), *normal)))
        proofs.append(first.P.solve(mode + '_copyback_roots_and_all_input_writers', premises,
                                    z3.Or(*violations)))
    return proofs


class TailModel(lookup.Model):
    def load(self, address, size):
        address = self.norm(address)
        if self.pc == pc(0xa6660d4):
            index = 13 - len(self.restores)
            at = self.buffer + index
            self.address_checks.append(address == at)
            self.classify(at, size)
            self.accesses.append({'PC': self.pc, 'address': at, 'size': size,
                                  'kind': 'protected_input', 'write': False})
            return self.plain[index] ^ first.P.M.mask(at, resize(first.P.M.KEY0, 64))
        if self.pc in self.bank_sites:
            for rule in self.tail_banks:
                name = rule['name']
                left, right, pointer_site = unwind.BANK_PCS[name]
                if self.pc == left:
                    assert size == 1
                    base = int(rule['left'], 16)
                    self.left[name] = z3.Extract(7, 0, address - base)
                    self.address_checks.append(address == base + z3.ZeroExt(56, self.left[name]))
                    self.bankbyte[name] = z3.BitVec('populated_tail_' + name, 8)
                    self.rom(address, size, 'original_tail_bank')
                    return self.bankbyte[name]
                if self.pc == right:
                    assert size == 1
                    index = self.bankbyte[name] ^ int(rule['key'], 16)
                    self.address_checks.append(address == int(rule['right'], 16) +
                                               z3.ZeroExt(56, index))
                    self.rom(address, size, 'original_tail_bank')
                    return self.left[name] ^ int(rule['constant'], 16)
                if self.pc == pointer_site:
                    assert size == 8
                    self.address_checks.append(address == int(rule['slot'], 16))
                    self.rom(address, size, 'original_tail_bank_pointer')
                    return resize(int(rule['original_pointer']['target'], 16), 64)
        return super().load(address, size)

    def store(self, address, size, value, source_pc):
        if source_pc == pc(0xa6660f4):
            assert size == 1
            self.restores.append((self.norm(address), resize(value, 8)))
        return super().store(address, size, value, source_pc)


def continue_to_return(v, tail, banks, returns, status):
    v.__class__ = TailModel
    v.e['spans'].extend(tail)
    v.tail_banks = banks
    v.bank_sites = {site for rule in banks for site in unwind.BANK_PCS[rule['name']]}
    v.restores = []
    bases = {'F': v.sp, 'C': v.ctx, 'S': v.src, 'I': v.input, 'B': v.buffer}
    # A source-backed predecessor value is reusable only while its bytes survive.
    surviving = []
    for owner, offset, role, value in ROOT_CELLS:
        a = bases[owner] + offset
        expect = bases[role] + value if role else value
        key = (z3.simplify(a).sexpr(), 8)
        if key not in v.memory:
            mem(v, a, 8, expect)
            v.entry_memory[key] = cell(v, a, 8)
        assert z3.is_true(z3.simplify(cell(v, a, 8) == expect))
        surviving.append((a, 8))
    surviving.append((v.buffer, 14))
    prior_writes = [r for r in v.accesses if r['write']]
    for a, size in surviving:
        for r in prior_writes:
            d = z3.simplify(r['address'] - a)
            if z3.is_bv_value(d):
                offset = d.as_signed_long()
                assert offset >= size or offset + r['size'] <= 0, (a, offset, r)
            else:
                # Owner disjointness follows from the admitted allocation spans.
                assert first.Model.classify(v, a, size)[0] != first.Model.classify(
                    v, r['address'], r['size'])[0]
    v.contracts['null_auxiliary'] = cell(v, v.ctx + 0x3c0, 8) != 0
    pending = (
        ('protected_input', 0xc4ba84c, 0xa666188, v.buffer, 14),
        ('context', 0xc4ba368, 0xa666260, pc(0x847ba60), v.ctx),
    )
    for label, target, modifier in TAIL:
        label = 'populated_' + label
        if label == 'populated_copy_step':
            for index in range(13, -1, -1):
                common.Model.run(v, label)
                first.P.add_edge(v, 0xa6660b4 if index else target, modifier)
            assert len(v.restores) == 14
        else:
            v.run(label)
            first.P.add_edge(v, target, modifier)
        if label == 'populated_primary_free':
            v.retire('primary_buffer', *pending[0])
            v.contracts['raw_status_before_primary_return'] = v.read('w19') != status
        if label == 'populated_context_free':
            v.retire('caller_context', *pending[1])
            v.contracts['raw_status_before_context_return'] = v.read('w26') != status
    edge = v.edges[-1]
    v.contracts['workspace_pending'] = z3.Or(
        edge['PC'] != pc(0xa6662b0), edge['link'] != pc(0xa6662b4),
        edge['arguments'][0] != v.src, edge['arguments'][1] != 16384,
        v.read('w26') != status, v.read('sp') != v.sp,
    )
    v.contracts['restore_original_bytes'] = z3.Or(*[
        z3.Or(address != v.input + index, value != v.plain[index])
        for index, (address, value) in zip(range(13, -1, -1), v.restores)
    ])
    for row in v.accesses:
        if row['write']:
            owner, offset, _ = first.Model.classify(v, row['address'], row['size'])
            if owner == 'frame':
                assert offset + row['size'] <= 0x1060
    assert z3.is_true(z3.simplify(v.read('x29') == v.entry_regs['x29']))
    good = local_return.normal(returns, prior=v)
    failed = local_return.failed(returns, prior=v)
    decoded = status ^ first.SUCCESS
    v.contracts['local_return_result'] = z3.Or(
        good.read('x0') != decoded, good.read('sp') != v.sp + 0x10f0,
        good.read('x30') != good.signed_link,
        *[good.read('x' + str(j)) != good.initial['x' + str(j)] for j in range(19, 30)],
        *[good.read('d' + str(j)) != good.initial['d' + str(j)] for j in range(8, 12)],
        *[z3.Not(q) for q in good.address_checks],
    )
    assert good.stop['PC'] == hex(pc(0xa6662f8))
    return {'decoded_X0': hex(decoded), 'retab_PC': good.stop['PC'],
            'copyback_indices': list(range(13, -1, -1)),
            'primary_and_context_requests': list(v.returns[-2:]),
            'workspace_call_PC': hex(edge['PC']), 'workspace_nominal_resume_PC': hex(pc(0xa6662b4)),
            'guard_failure_trace': [hex(p) for p in sorted(failed.visited)]}, good, failed


def path(parent, parser, upstream, extracted, hit, *, mutation=False):
    request, slots, tail, banks, returns = extracted
    v, predecessor, contracts, matching, profile = lookup.trace(parent, parser, *upstream, hit)
    condition = matching if hit else z3.Not(matching)
    premises = (v.owned() + v.branch_guards[:profile['predecessor_guard_count']]
                + v.normal_guards + first.selected(v) + [condition])
    v.contracts.update(predecessor)
    v.contracts.update(contracts)
    for row in slots:
        v.lookup_slots.setdefault(int(row['load'], 16), []).append(
            (int(row['slot'], 16), int(row['record']['target'], 16))
        )
    v.e['spans'].append(request)
    start = len(v.accesses)
    saved_regs = set(v.live_regs)
    saved_cells = set(v.live_cells)
    v.lookup(*PATH[0])
    for step in PATH[1:]:
        v.step(*step)
    v.contracts['retiring_same_selected_instance'] = z3.Or(
        v.read('x23') != v.J, v.read('x25') != 0, v.read('x0') != v.Z,
    )
    status = lookup.TYPE_EXIT if hit else lookup.MISS
    args = ((v.Z, 14), (pc(0x847be20), v.J), (pc(0x847bde0), v.object))
    requests = []
    for row, (x0, x1) in zip(RETIREMENTS, args):
        call_label, owner, target, call, modifier, return_label, continuation, return_modifier = row
        v.step(call_label, target, modifier)
        v.retire(owner, owner, target, call, x0, x1)
        label = 'nz_complete_' + return_label
        v.run(label)
        first.P.add_edge(v, continuation, return_modifier)
        requests.append({'role': owner, 'call_PC': hex(pc(call)), 'target': hex(pc(target)),
                         'nominal_return_PC': hex(pc(call + 4))})
    v.step('destroy_resume', 0xa665e90, 0x4ed7)
    v.contracts['container_output_clears_and_status_survives'] = z3.Or(
        cell(v, v.ctx + 0x600, 8) != 0, cell(v, v.src + 0xde4, 4) != status,
        v.read('sp') != v.sp,
    )
    assert set(v.live_regs) == saved_regs
    seeded = {(z3.simplify(v.sp + offset).sexpr(), 8) for offset, _, _, _ in source.PREFIX}
    assert set(v.live_cells) - saved_cells <= seeded
    accesses = []
    for row in v.accesses[start:]:
        owner, offset = row['kind'], None
        if not owner.startswith('original_'):
            owner, offset, _ = first.Model.classify(v, row['address'], row['size'])
        accesses.append({'PC': hex(row['PC']), 'owner': owner, 'offset_bytes': offset,
                         'width_bytes': row['size'], 'write': row['write']})
    if mutation:
        control = z3.SolverFor('QF_BV')
        control.set(timeout=60000)
        control.add(*premises, *v.address_checks, v.contracts['container_output_clears_and_status_survives'])
        assert control.check() == z3.sat, control.reason_unknown()
        return control.to_smt2()
    guard_start = len(v.branch_guards)
    tail_profile, good, failed = continue_to_return(v, tail, banks, returns, status)
    # Pointer retag guards are shared premises, ordinary transfer choices are verified.
    for guard in v.branch_guards[guard_start:]:
        if not any(z3.eq(guard, normal) for normal in v.normal_guards):
            v.address_checks.append(guard)
    premises += v.normal_guards + [local_return.guard_separation(v.sp)]
    bad = z3.Or(*v.contracts.values(), *[z3.Not(g) for g in v.address_checks])
    branch = 'match' if hit else 'miss'
    proof = first.P.solve('populated_cleanup_' + branch,
                          premises + good.guards + [good.current_guard == good.saved_guard], bad)
    guard_proof = first.P.solve('populated_stack_guard_failure_' + branch,
                                premises + failed.guards + [failed.current_guard != failed.saved_guard],
                                z3.Or(*[z3.Not(q) for q in v.address_checks + failed.address_checks],
                                      z3.BoolVal(failed.guard_exit_target != pc(0xa66692c)),
                                      failed.edges[0]['target'] != pc(0xa69f294),
                                      failed.edges[-1]['target'] != pc(0xc629694),
                                      failed.edges[-1]['modifier'] != pc(0x847c478),
                                      failed.read('x30') != pc(0xa666930)))
    return [proof, guard_proof], {'status': hex(status), 'callback': hex(pc(0xa665e90)),
                                 'retirement_requests': requests, 'accesses': accesses, **tail_profile}


def caller_source(kernel_sha):
    kernel = Kernel()
    e = source.load('userclient_zero_tag_provider_checks')
    assert e['kernel_collection_sha256'] == kernel.sha256 == kernel_sha
    assert e['caller'] == source.load('userclient_transfer_boundary_checks')
    for row in (*e['caller']['functions'].values(), *e['caller']['veneers'].values()):
        base = int(row['start'], 16)
        raw = bytes.fromhex(row['bytes_hex'])
        assert raw == kernel.read(base, len(raw)) == IMAGE.read(base, len(raw))
    for row in e['caller']['bindings']:
        original = pointer(kernel, int(row['slot'], 16))
        assert all(row[key] == value for key, value in original.items())
    return e['caller']


def caller_projections(e, name, status):
    bv = caller_model.bv
    same = caller_model.T.same
    p = caller_model.Model(e, 'provider', 'normal')
    p.core_return = bv(status)
    p.run()
    d = {role: args for role, args, _ in p.events}
    core = next(b for b in p.boundaries if b['role'] == 'core')
    expected = [p.descriptor, bv(0), p.staging, bv(14)]
    assert [r for r, _, _ in p.events][5:] == [
        'copy_in', 'core', 'copy_out', 'buffer_complete', 'buffer_release',
        'task_complete', 'task_release',
    ]
    proofs = [first.P.solve(name + '_provider_copy_and_return', p.premises() + [
        p.extent_parameter == bv(14),
    ], z3.Or(*[z3.Not(q) for q in p.checks], same(d['copy_in'][:4], expected),
             same(d['copy_out'][:4], expected), same(d['core'][:3], [p.staging, bv(14), p.state]),
             core['target'] != pc(0xa635208), core['registers']['x30'] != pc(0xa505300),
             p.regread('x0') != bv(status)))]
    for alias in (False, True):
        h = caller_model.Model(e, 'handler', 'nonzero', alias)
        h.provider_return = bv(status)
        h.run()
        assert [role for role, _, _ in h.events] == ['provider', 'error_log']
        assert not any(site in (pc(0xa5040b0), pc(0xa5040b8)) for site, _, _, _ in h.stores)
        boundary = h.boundaries[0]
        modifier = (h.vprovider + 0xa20) & bv((1 << 48) - 1) | bv(0x3499 << 48)
        args = h.events[0][1]
        proof = first.P.solve(name + '_handler_' + ('alias' if alias else 'separate'),
                              h.premises() + [h.extent == 14], z3.Or(
            *[z3.Not(q) for q in h.checks],
            same(args, [h.provider, h.address, bv(14), h.state, h.task]),
            boundary['target'] != pc(0xa505198), boundary['modifier'] != modifier,
            core['registers']['x30'] != pc(0xa505300),
            h.regread('x0') != bv(status), h.private[h.key(h.sp - 0x40, 8)] != bv(status),
        ))
        proofs.append(proof)
    return proofs, {'provider_sites': [{'role': r, 'PC': hex(at)} for r, _, at in p.events],
                    'handler_sites': [{'role': r, 'PC': hex(at)} for r, _, at in h.events],
                    'provider_X0': hex(status), 'handler_X0': hex(status),
                    'core_argument_extent_bytes': 14,
                    'handler_descriptor_output_stores': 0}


def build():
    parent = source.load('userclient_nonzero_tag_record_checks')
    parser = source.load('userclient_nonzero_tag_completion_checks')
    upstream = lookup.extract()
    extracted = extract(parser)
    request, slots, tail, banks, _ = extracted
    caller = caller_source(parser['kernel_collection_sha256'])
    proofs = root_projection()
    profiles = {}
    for hit, name in ((False, 'miss'), (True, 'match')):
        proof, profile = path(parent, parser, upstream, extracted, hit)
        caller_proofs, forwarding = caller_projections(caller, name, int(profile['decoded_X0'], 16))
        profiles[name] = profile
        profile['caller_forwarding'] = forwarding
        proofs.extend(proof)
        proofs.extend(caller_proofs)
    altered = {**parser, 'spans': [dict(s) for s in parser['spans']]}
    span = next(s for s in altered['spans'] if s['label'] == 'nz_complete_container_return')
    data = bytearray.fromhex(span['bytes_hex'])
    offset = pc(0xa6605e0) - int(span['start'], 16)
    original = data[offset:offset + 4].hex()
    data[offset:offset + 4] = bytes.fromhex('1f2003d5')
    span['bytes_hex'] = data.hex()
    control = path(parent, altered, upstream, extracted, True, mutation=True)
    return {'generator_sha256': sha(__file__), 'source_sha256': parser['source_sha256'],
            'kernel_collection_sha256': parser['kernel_collection_sha256'],
            'scope': SCOPE, 'dependencies': {name: sha(ROOT / name) for name in DEPENDENCIES},
            'cleanup_request_span': request, 'original_branch_slots': slots, 'tail_spans': tail,
            'tail_banks': banks, 'profiles': profiles,
            'source_proofs': proofs,
            'negative_control': {'name': 'omitted_container_output_clear', 'PC': hex(pc(0xa6605e0)),
                                 'original_word_hex': original, 'result': 'sat', 'query': control},
            'all_checks_pass': True, 'native_execution_observed': False, 'full_goal_complete': False}


if __name__ == '__main__':
    with redirect_stdout(sys.stderr):
        evidence = build()
    print(json.dumps(evidence, indent=2))
