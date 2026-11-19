#!/usr/bin/env python3
"""Replay the installed schema lookup helper and its caller's result consumers."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from hashlib import sha256
import json
from pathlib import Path

from audit_daemon_iokit_native_registry import command, sysctl
from audit_live_fairplay_cf_receive import assert_instructions
from audit_live_fairplay_connection_retirement import verify_fixup
from audit_live_fairplay_context_lifecycle import POOL, POOL_ROOTS, TABLE, function_starts, replay_proof
from audit_live_fairplay_early_publication import PROOF_TIMEOUT_SECONDS
from audit_live_fairplay_entry import CONTROLLERS, in_private, shifted, verify_layout
from audit_live_fairplay_schema_registry import (
    CHECKS as REGISTRY_CHECKS, CLEANUP, HEADER, LOOKUP, SUCCESS, U64, RegistryReplay,
    verify_banks, verify_code,
)
from audit_live_fairplay_schema_scalar import (
    AUDIT as SCALAR_AUDIT, CHECKS as SCALAR_CHECKS, SEARCH_CHECKS, check_scalar_layout,
    check_source, scalar_cases,
)
from audit_live_fairplay_table_cleanup import RELOCATIONS
from audit_live_fairplay_uidlist import receipt
from audit_live_kext_selector26 import Collection, IDENTITIES

CHECKS = 'b5a623be2bbd10b22c15187c624997375d0cd0c703e773ff6dcba9b87eb2374f'
AUDIT = 'a715d19afc150fe6e385f787a8bf78fd2534bff52d04ef1ee1626bd97faeae81'
INSTALLED_REGISTRY = '3d14a1b88b8b9bba82ebd303ea5ec0a73e986f449e259ee4fc0a8cf9d8b3f4cb'
CONTROLLER = 0xfffffe000cd42f38
ENTRY_KEY = 0x1ee45f68039f9913
READY = shifted('0xfffffe000a636958')
RETURN = shifted('0xfffffe000a65b530')
RETAB = shifted('0xfffffe000a5ae888')
SIGNED_TOKEN = 0xf195aa55b0653c71
SAVED_FP_TOKEN = 0xf129bb55b0653c72
STATUSES = dict(hit_nonnull=None, hit_null=0xce515bda, empty_candidate=0xce515bc4,
                null_array=0xce515bbf)


def verify_result_source(image, checks):
    source = checks['source']
    original = checks['result_helper_envelope']
    raw = bytes.fromhex(original['bytes_hex'])
    assert len(raw) == 1336 and sha256(raw).hexdigest() == original['sha256']
    assert LOOKUP == shifted(original['start'])
    starts = function_starts(image)
    stop = starts[starts.index(LOOKUP) + 1]
    assert stop == shifted(original['end']) == LOOKUP + len(raw)
    installed = image.read(LOOKUP, len(raw))
    relocations = [(LOOKUP + offset, mnemonic, operands)
                   for offset, mnemonic, operands in RELOCATIONS['lookup']]
    assert [LOOKUP + i for i in range(0, len(raw), 4) if raw[i:i+4] != installed[i:i+4]] == [
        pc for pc, _, _ in relocations
    ]
    layout = verify_layout(image, {'result': source})
    assert len(layout['branch_fixups']) == 96 and len(layout['spans']['result']) == 29
    assert sum(span['words'] for span in layout['spans']['result']) == 433
    assert all(not span['changes'] for span in layout['spans']['result']
               if int(span['start'], 16) >= stop)
    layout['lookup_helper'] = dict(start=hex(LOOKUP), end_exclusive=hex(stop),
                                   sha256=sha256(installed).hexdigest(), words=334,
                                   relocated=assert_instructions(image.read, relocations))
    rule = checks['result_bank_rule']
    arrays = {}
    bindings = {}
    for offset in (0xf50, 0xf20):
        target, name, bias = POOL_ROOTS[offset]
        raw = image.read(target + bias, 256)
        assert raw.hex() == checks['result_banks'][name]['bytes_hex']
        arrays[name] = raw
        bindings[name] = verify_fixup(image, POOL + offset, target)
    left, right = arrays['BL'], arrays['BR']
    key = int(rule['key'], 16)
    constant, = {i ^ right[left[i] ^ key] for i in range(256)}
    index = constant + int(rule['additive'], 16)
    assert constant == int(rule['constant'], 16) and index == int(rule['index'], 16)
    slot = verify_fixup(image, POOL + index * 8, (TABLE - int(rule['bias'], 16)) & U64)
    layout['helper_table'] = dict(roots=bindings, slot=slot, exhaustive_bank_inputs=256,
                                  target=hex(TABLE), index=hex(index))
    return layout


class LookupReplay(RegistryReplay):
    """Keep table fixtures and nominal return state within the replay."""

    table_bounds = None
    helper_active = False
    caller_reads = None

    def reg(self, name):
        value = super().reg(name)
        if value == SAVED_FP_TOKEN:
            assert name in ('x29', 'fp') and self.pc == LOOKUP+0x1c
        if value == SIGNED_TOKEN:
            assert name in ('x30', 'lr') and self.pc == LOOKUP+0x1c
        return value

    def step(self, word):
        mnemonic = word.mnemonic
        if mnemonic == 'pacibsp' and self.pc == LOOKUP:
            self.entry_link = self.g[30]
            self.entry_sp = self.sp
            assert self.entry_link == RETURN and not self.helper_active
            assert self.g[29] is None
            self.g[29] = SAVED_FP_TOKEN
            self.saved_registers = tuple(self.g[19:30])
            self.g[30] = SIGNED_TOKEN
            self.helper_active = True
            return self.pc + 4
        if mnemonic == 'retab' and self.pc == RETAB:
            assert self.helper_active
            assert self.sp == self.entry_sp and self.g[30] == SIGNED_TOKEN
            assert tuple(self.g[19:30]) == self.saved_registers
            self.g[29] = None
            self.g[30] = self.entry_link
            self.helper_active = False
            return self.edge(word, self.entry_link, mnemonic)
        if mnemonic == 'tst':
            left, right = word.operands
            width = 32 if word.reg_name(left.reg).startswith('w') else 64
            value = self.operand(word, left, width) & self.operand(word, right, width)
            self.nzcv = ((value >> (width - 1)) << 31) | ((value == 0) << 30)
            return self.pc + 4
        if mnemonic == 'ccmp':
            condition = word.op_str.rsplit(',', 1)[1].strip()
            if not self.condition(condition):
                self.nzcv = word.operands[2].imm << 28
            else:
                left, right = word.operands[:2]
                width = 32 if word.reg_name(left.reg).startswith('w') else 64
                a, b = self.operand(word, left, width), self.operand(word, right, width)
                sign = 1 << (width - 1)
                value = (a - b) & (2 * sign - 1)
                overflow = bool((a ^ b) & (a ^ value) & sign)
                self.nzcv = ((value >> (width - 1)) << 31) | ((value == 0) << 30)
                self.nzcv |= ((a >= b) << 29) | (overflow << 28)
            return self.pc + 4
        if mnemonic in ('eon', 'bic'):
            dest, left, right = word.operands
            name = word.reg_name(dest.reg)
            width = 32 if name.startswith('w') else 64
            a, b = self.operand(word, left, width), self.operand(word, right, width)
            self.set(name, (a ^ ~b) if mnemonic == 'eon' else (a & ~b))
            return self.pc + 4
        return super().step(word)

    def load(self, address, width, discarded=False):
        if self.helper_active and address == CONTROLLER:
            assert (self.pc, width, discarded) == (LOOKUP+0x2c, 8, False)
            value = int.from_bytes(self.image.read(address, width), 'little')
        else:
            value = super().load(address, width, discarded)
        if self.helper_active and address in (CONTROLLER, CONTROLLERS[1]):
            self.controller_reads.append((self.pc, address, width, value))
        if self.table_bounds is not None and self.table_bounds[0] <= address < self.table_bounds[1]:
            assert address + width <= self.table_bounds[1] and not discarded
            self.table_reads.append((self.pc, address, width, value))
        if self.caller_reads is not None and self.pc in self.caller_sites:
            assert not discarded
            self.caller_reads.append((self.ix, self.pc, address, width, value))
        return value

    def store(self, address, width, value):
        if self.caller_reads is not None and self.pc == shifted('0xfffffe000a65b59c'):
            self.payload_copy_visit = self.ix
        if self.helper_active and address == CONTROLLER:
            assert (self.pc, width) == (LOOKUP+0x6c, 8)
            self.state.update((address + i, b) for i, b in enumerate(value.to_bytes(width, 'little')))
            self.publication_stores.append((hex(self.pc), hex(address), width, hex(value)))
            return
        super().store(address, width, value)

    def consume(self, allowed, scalar, profile, capacity, entries, payload, archived):
        F = self.sp
        S, C, H, J, Z = (int(cut['result'], 16) for cut in self.cuts)
        assert self.pc == LOOKUP
        v = scalar['output32']
        R = S + 0x968
        flag, idx, status, output, error = S+0x10, S+0xa28, R+0x18, C+0x440, S+0x1c
        cursor = F + 0xaa8
        assert self.g[0] == R and self.g[19] == output and self.value(idx, 4) == 0
        assert self.value(F+0xa30, 8) == CONTROLLERS[0] and self.value(F+0xa60, 8) == TABLE
        assert [(cell['offset'], cell['size_bytes']) for cell in archived['result_additional_source_cells']] == [
            ('0xa30', 8), ('0xa60', 8)
        ]
        preserved = [(Z, 14), (S+0xbc4, 4), (cursor, 8), (H, 16), (J, 32), (HEADER, 16)]
        preserved_bytes = [tuple(self.state.get(a+i) for i in range(n)) for a, n in preserved]
        assert self.value(cursor, 8) == 14 and self.value(S+0xbc4, 4) == v
        assert in_private(F-0x70, 0x70) and all(F <= a or a+n <= F-0x70 for a, n in preserved)
        assert not any(a in self.state for a in range(F-0x70, F))
        self.controller_reads, self.table_reads = [], []
        status_pc, index_pc, found_pc, payload_pc = map(
            shifted, ('0xfffffe000a65b53c', '0xfffffe000a65b578',
                      '0xfffffe000a6368d4', '0xfffffe000a636928')
        )
        self.caller_sites = {status_pc, index_pc, found_pc, payload_pc}
        self.caller_reads = []
        self.payload_copy_visit = None
        probe = v & (capacity - 1)
        occupied = profile.startswith('hit_')
        entry = entries + 24 * probe
        if entries:
            self.table_bounds = (entries, entries + 24 * capacity)
            assert in_private(entries, 24*capacity) and 0 <= probe < capacity
            assert all(entries >= a+n or self.table_bounds[1] <= a
                       for a, n in preserved + [(F-0x70, 0x1160), (S, 0x4000), (C, 0x1000)])
            assert not any(a in self.state for a in range(*self.table_bounds))
            entry_state = 0x629f8777 if occupied else 0x629f8775
            raw = (entry_state.to_bytes(4, 'little') + bytes(4) +
                   (ENTRY_KEY+v if occupied else ENTRY_KEY).to_bytes(8, 'little') +
                   payload.to_bytes(8, 'little'))
            self.state.update((entry+i, b) for i, b in enumerate(raw))
        else:
            assert profile == 'null_array'
        pre_output = tuple(self.state.get(output+i) for i in range(8))
        pre_flag = self.state.get(flag)
        error_value = STATUSES[profile]
        endpoint = READY if error_value is None else CLEANUP
        first_store, first_edge = len(self.publication_stores), len(self.edges)
        visits = 0
        while self.pc != endpoint:
            assert visits < len(allowed) and self.pc in allowed, (profile, hex(self.pc))
            word, = self.cs.disasm(self.image.read(self.pc, 4), self.pc)
            self.ix += 1
            self.pc = self.step(word)
            visits += 1
        assert not self.helper_active and self.sp == F
        for (a, n), before in zip(preserved, preserved_bytes, strict=True):
            assert tuple(self.state.get(a+i) for i in range(n)) == before
        edges = self.edges[first_edge:]
        ret, = (e for e in edges if e['kind'] == 'retab')
        assert (ret['pc'], ret['target']) == (hex(RETAB), hex(RETURN))
        assert all(e['kind'] in ('braa', 'retab') for e in edges)
        g0, g1 = self.controller_reads
        assert [(pc, a, n) for pc, a, n, _ in self.controller_reads] == [
            (LOOKUP+0x2c, CONTROLLER, 8), (LOOKUP+0x34, CONTROLLERS[1], 8)
        ]
        t = (F - 0x68 + g0[3] + g1[3]) & U64
        mix, mult = 0xa41a4d891208c018, 0x4d08a3fb
        helper_status = SUCCESS if entries else 0xce515bbf
        actual_stores = self.publication_stores[first_store:]
        exact = [(LOOKUP+0x6c, CONTROLLER, 8, ((t*mult)&U64) ^ mix),
                 (LOOKUP+0x70, CONTROLLERS[1], 8, ((t^mix)*mult)&U64)]
        table_reads = []
        if entries:
            table_reads.append((shifted('0xfffffe000a5ae718'), entry, 4, entry_state))
            exact.append((shifted('0xfffffe000a5ae524'), flag, 1, 0))
            if occupied:
                table_reads.append((shifted('0xfffffe000a5ae778'), entry+8, 8, ENTRY_KEY+v))
                exact.append((shifted('0xfffffe000a5ae834'), flag, 1, 1))
            exact.append((shifted('0xfffffe000a5ae84c'), idx, 4, probe))
            assert self.value(flag, 1) == int(occupied) and self.value(idx, 4) == probe
        else:
            assert self.state.get(flag) == pre_flag and self.value(idx, 4) == 0
            assert tuple(self.state.get(output+i) for i in range(8)) == pre_output
        exact.append((shifted('0xfffffe000a5ae868'), status, 4, helper_status))
        assert self.value(status, 4) == helper_status
        caller_reads = [(status_pc, status, 4, helper_status)]
        if entries:
            table_reads.append((shifted('0xfffffe000a65b598'), entry+16, 8, payload))
            exact.append((shifted('0xfffffe000a65b59c'), output, 8, payload))
            assert self.value(output, 8) == payload
            caller_reads.extend([(index_pc, idx, 4, probe), (found_pc, flag, 1, int(occupied))])
            assert self.caller_reads[1][0] < self.payload_copy_visit < self.caller_reads[2][0]
            if occupied:
                caller_reads.append((payload_pc, output, 8, payload))
        else:
            assert self.payload_copy_visit is None
        if error_value is not None:
            exact.append((shifted('0xfffffe000a641c38'), error, 4, error_value))
            assert self.value(error, 4) == error_value and self.g[19] == C+0x418
        else:
            assert self.g[23] == 0xce515bda
        assert [event[1:] for event in self.caller_reads] == caller_reads
        assert self.table_reads == table_reads
        data_stores = [store for store in actual_stores if not F-0x70 <= int(store[1], 16) < F]
        assert data_stores == [(hex(pc), hex(a), n, hex(val)) for pc, a, n, val in exact], data_stores
        frame_stores = [store for store in actual_stores if F-0x70 <= int(store[1], 16) < F]
        saved_pairs = ((28, 27), (26, 25), (24, 23), (22, 21), (20, 19), (29, 30))
        spilled = dict(zip(range(19, 30), self.saved_registers, strict=True))
        spilled[30] = SIGNED_TOKEN
        expected_frame = [
            (hex(LOOKUP+8+pair*4), hex(F-0x60+pair*16+i*8), 8, hex(spilled[register]))
            for pair, registers in enumerate(saved_pairs) for i, register in enumerate(registers)
        ]
        if entries:
            expected_frame.append((hex(shifted('0xfffffe000a5ae538')), hex(F-0x70), 8, hex(flag)))
        assert frame_stores == expected_frame, frame_stores
        return dict(profile=profile, capacity=capacity, entries=hex(entries),
                    input_entry_payload=hex(payload) if entries else None, decoded_key32=hex(v),
                    lookup_status=hex(helper_status), output_index=probe if entries else 0,
                    found=int(occupied) if entries else None, copied_payload=hex(payload) if entries else None,
                    published_error=hex(error_value) if error_value is not None else None,
                    endpoint=hex(endpoint), instruction_visits=visits, registers_restored=11,
                    table_reads=[dict(pc=hex(pc), address=hex(a), bytes=n, value=hex(value))
                                 for pc, a, n, value in self.table_reads],
                    controller_reads=[dict(pc=hex(pc), address=hex(a), bytes=n, value=hex(value))
                                      for pc, a, n, value in self.controller_reads],
                    caller_reads=[dict(visit=i, pc=hex(pc), address=hex(a), bytes=n, value=hex(value))
                                  for i, pc, a, n, value in self.caller_reads],
                    payload_copy_visit=self.payload_copy_visit,
                    stores=actual_stores, edges=edges, opaque_signed_token_round_trip=True,
                    opaque_saved_fp_round_trip=True,
                    authenticated_return_assumed=True)


def lookup_cases(image, checks, profiles=STATUSES, replay_type=LookupReplay):
    installed = receipt('live_fairplay_schema_registry_audit', INSTALLED_REGISTRY)
    registry = receipt('userclient_schema_registry_checks', REGISTRY_CHECKS)
    scalar = receipt('userclient_schema_scalar_checks', SCALAR_CHECKS)
    preceding = receipt('userclient_schema_scalar_audit', SCALAR_AUDIT)
    search = receipt('userclient_schema_search_checks', SEARCH_CHECKS)
    assert checks['registry_source'] == registry['source']
    assert checks['kernel_collection_sha256'] == IDENTITIES[0][0]
    assert installed['historical_checks_sha256'] == REGISTRY_CHECKS
    assert installed['identity'] == list(IDENTITIES[1])

    allocate = image.named('_IOMallocTypeImpl')
    _, registry_words = verify_code(image, registry['source'], registry['registry_allocation_adapter'], allocate)
    _, bases = verify_banks(image, registry, allocate)
    _, search_spans = check_source(image, search)
    _, scalar_spans = check_scalar_layout(image, scalar)
    allowed = {shifted(word['pc']) for span in checks['source']['spans'] for word in span['instructions']}
    error_span, = (span for span in registry['source']['spans'] if span['label'] == 'registry_error_status')
    allowed.update(shifted(word['pc']) for word in error_span['instructions'])
    predecessors = {case['predecessor_case_index']: case for case in checks['predecessor_states']}
    expected = {case['fixture']: case for case in installed['cases'] if case['registry']['path'] == 'lookup'}
    for profile in profiles:
        for case, replay in scalar_cases(image, scalar, preceding, search_spans, scalar_spans, replay_type):
            name, index, result = case['fixture'], case['case_index'], case['result']
            if name not in expected:
                break
            archived = predecessors[index]
            capacity, array = (128, 0x630001a000) if name == 'adid_field' else (64, 0x630001b000)
            entries = 0 if profile == 'null_array' else array
            payload = 0x630001c000 if profile == 'hit_nonnull' else 0
            request = replay.registry(registry_words, result, archived, bases, allocate, (capacity, entries))
            assert json.loads(json.dumps(result)) == expected[name]['scalar']
            if entries:
                assert json.loads(json.dumps(request)) == expected[name]['registry']
            observed = replay.consume(allowed, result, profile, capacity, entries, payload, archived)
            yield dict(fixture=name, case_index=index, result=observed), replay


def audit(path):
    build = command('sw_vers', '-buildVersion').strip().decode()
    assert build == '26C5035r' and sysctl('kern.uuid').lower() == IDENTITIES[1][1]
    image = Collection(path, IDENTITIES[1])
    checks = receipt('userclient_schema_lookup_result_checks', CHECKS)
    prior = receipt('userclient_schema_lookup_result_audit', AUDIT)
    assert prior['kernel_collection_sha256'] == IDENTITIES[0][0] and prior['checks_sha256'] == CHECKS
    layout = verify_result_source(image, checks)
    cases = [case for case, _ in lookup_cases(image, checks)]
    assert len(cases) == 8
    proofs = prior['source_proofs']
    assert len(proofs) == 298
    with ThreadPoolExecutor(max_workers=6) as workers:
        proof_results = list(workers.map(partial(replay_proof, timeout_seconds=PROOF_TIMEOUT_SECONDS), proofs))
    return dict(build=build, identity=IDENTITIES[1], layout=layout, cases=cases, source_proofs=proof_results,
                historical_checks_sha256=CHECKS, historical_audit_sha256=AUDIT,
                installed_registry_audit_sha256=INSTALLED_REGISTRY, proof_timeout_seconds=PROOF_TIMEOUT_SECONDS,
                continuous_writer_execution=False, native_PAC_verified=False, native_transaction_observed=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    print(json.dumps(audit(parser.parse_args().collection), indent=2))
