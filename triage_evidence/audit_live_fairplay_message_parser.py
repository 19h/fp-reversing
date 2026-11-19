#!/usr/bin/env python3
"""Check the installed FPMessage parser re-entry and independent completion cut."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from functools import partial
import json
from pathlib import Path

from audit_daemon_iokit_native_registry import command, sysctl
from audit_live_fairplay_cf_receive import assert_instructions
from audit_live_fairplay_connection_retirement import verify_fixup
from audit_live_fairplay_context_lifecycle import POOL, POOL_ROOTS, TABLE, replay_proof
from audit_live_fairplay_early_header import SUCCESS
from audit_live_fairplay_early_publication import PROOF_TIMEOUT_SECONDS
from audit_live_fairplay_entry import ALLOC_TLV, INPUT_BYTE, TLV_TYPE, in_private, read_type, shifted, verify_layout
from audit_live_fairplay_message_initialization import (
    CHECKS as INITIALIZATION_CHECKS, MESSAGE, PARSER, MessageReplay, initialization_cases, verify_source,
)
from audit_live_fairplay_shared_table import EXTRA_BANKS
from audit_live_fairplay_uidlist import receipt
from audit_live_kext_selector26 import Collection, IDENTITIES
from kext_port_tools import POOL as ARCHIVED_POOL, TABLE as ARCHIVED_TABLE

CHECKS = '565b2803433729d335ac4535e01be67c5e340e9dd889c3884ce12dc9aee3b6af'
AUDIT = 'fbec01eac93c22b1ef2c6ca299ea7a5544e05ff75d0627e6179e16eb920b1ffb'
INSTALLED_INITIALIZATION = 'ae5aab202fce8e6b237025505854703f6ce71c25a18b73cc5fffd730288560d6'
CONTAINER = 0x630001e400
CALLER_TAG = 0xfbb3f478
ALLOCATION_GATE = shifted('0xfffffe000a6366a8')
ALLOCATED = shifted('0xfffffe000a6366ac')
FAILURE = shifted('0xfffffe000a6650a4')
COMPLETION = shifted('0xfffffe000a660b2c')
COMPLETION_DISPATCH = shifted('0xfffffe000a660b88')
TAG_GATE = shifted('0xfffffe000a660bc4')
STATUS_GATE = shifted('0xfffffe000a66117c')
FLAG_LOAD = shifted('0xfffffe000a6611a0')
FLAG_GATE = shifted('0xfffffe000a6611e0')
FLAG_TARGETS = (shifted('0xfffffe000a6611e4'), shifted('0xfffffe000a663c9c'))
PUBLISH = shifted('0xfffffe000a660b70')
BANK_NAMES = {
    0xfffffe0007949dd0: 'TL', 0xfffffe000792fbc0: 'TR',
    0xfffffe0007949ed0: 'AL', 0xfffffe000792fec0: 'AR',
    0xfffffe0007949fd0: 'UL', 0xfffffe000792ffc0: 'UR',
    0xfffffe0007941f60: 'VL', 0xfffffe000794a0d0: 'VR',
}


def verify_parser(image, checks, allocate):
    source = checks['source']
    layout = verify_layout(image, {'parser': source})
    spans = layout['spans']['parser']
    assert len(spans) == 14 and sum(s['words'] for s in spans) == 436
    assert len(layout['branch_fixups']) == 13
    relocated = [
        (0xfffffe000a677558, 'adrp', 'x28, #0xfffffe0008488000'),
        (0xfffffe000a67755c, 'add', 'x28, x28, #0x9a0'),
    ]
    assert [int(w['address'], 16) for s in spans for w in s['changes']] == [x[0] for x in relocated]
    layout['pool_relocations'] = assert_instructions(image.read, relocated)
    layout['unexecuted_input_load'] = assert_instructions(image.read, [(INPUT_BYTE, 'ldrb', 'w11, [x10, x9]')])

    roots = {name: (slot, target, bias)
             for slot, (target, name, bias) in (POOL_ROOTS | EXTRA_BANKS).items()}
    bank_bytes, bank_targets, bank_fixups = {}, {}, {}
    for text, old_bytes in checks['banks'].items():
        old = int(text, 16)
        slot, target, bias = roots[BANK_NAMES[old]]
        bank_targets[old] = target + bias
        data = image.read(target+bias, 256)
        assert data.hex() == old_bytes
        bank_bytes[text] = data
        bank_fixups[text] = verify_fixup(image, POOL+slot, target)
    relations = []
    for row in checks['bank_rules']:
        left, right = (bank_bytes[row[key]] for key in ('left', 'right'))
        key = int(row['key'], 16)
        constant, = {x ^ right[left[x] ^ key] for x in range(256)}
        assert constant == int(row['constant'], 16)
        relations.append(dict(row, left_PC=hex(shifted(row['left_PC'])), right_PC=hex(shifted(row['right_PC']))))
    assert len(bank_bytes) == 8 and len(relations) == 11

    known_targets = {0xfffffe000c4ba154: allocate, 0xfffffe000847bb60: TLV_TYPE, **bank_targets}
    literals = {}
    for row in source['literal_pointers']:
        pointer = row['original_pointer']
        old_base, base = (ARCHIVED_TABLE, TABLE) if pointer['authenticated'] else (ARCHIVED_POOL, POOL)
        slot = base + int(row['slot'], 16) - old_base
        old_target = int(pointer['target'], 16)
        target = int(image.pointer(slot)['target'], 16)
        if old_target in known_targets:
            assert target == known_targets[old_target]
        fixup = verify_fixup(image, slot, target, pointer['diversity'])
        literals[shifted(row['source_PC'])] = dict(fixup, historical_slot=row['slot'],
                                                  historical_target=pointer['target'])
    assert len(literals) == 19
    descriptor = read_type(image, TLV_TYPE, 'site.FPTTLV', '11', 16)
    old = bytes.fromhex(checks['container_descriptor']['normalized64_hex'])
    current = image.read(TLV_TYPE, 64)
    assert current[:16] == old[:16] and current[24:32] == old[24:32] and current[40:] == old[40:]
    layout.update(bank_fixups=bank_fixups, bank_relations=relations,
                  literal_fixups={hex(pc): row for pc, row in literals.items()}, descriptor=descriptor)
    allowed = {shifted(word['pc']) for span in source['spans'] for word in span['instructions']}
    return layout, allowed, literals, bank_targets[0xfffffe0007949dd0]


class ParserReplay(MessageReplay):
    parser_reads = None

    def load(self, address, width, discarded=False):
        if self.parser_reads is not None:
            assert address+width <= self.input_address or self.input_address+self.input_extent <= address
        value = super().load(address, width, discarded)
        if self.parser_reads is not None:
            assert not discarded
            self.parser_reads.append((hex(self.pc), hex(address), width, hex(value)))
        return value

    def visit(self, allowed, endpoint, allocate=None, result=None):
        reads = len(self.parser_reads)
        stores, edges = len(self.publication_stores), len(self.edges)
        sites, call = [], None
        while self.pc != endpoint:
            assert self.pc in allowed and len(sites) < len(allowed), hex(self.pc)
            self.ix += 1
            sites.append(hex(self.pc))
            word, = self.cs.disasm(self.image.read(self.pc, 4), self.pc)
            if self.pc == ALLOC_TLV:
                assert allocate is not None and call is None
                self.check_request()
                call = self.external_return(word, self.pc, self.sp, allocate, 0xd0c8, result, 0)
                self.pc += 4
            else:
                assert word.mnemonic != 'blraa'
                self.pc = self.step(word)
        assert (call is not None) == (allocate is not None)
        return dict(endpoint=hex(endpoint), sites=sites, allocator=call, loads=self.parser_reads[reads:],
                    stores=self.publication_stores[stores:], edges=self.edges[edges:])

    def check_request(self):
        C, S = self.caller, self.workspace
        assert self.g[0] == TLV_TYPE and self.g[19:21] == [0x4a2, 0x68e]
        assert self.value(C+0x170, 8) == MESSAGE and self.value(C+0x98, 8) == self.input_address
        assert self.value(S+0xb5c, 4) == self.input_extent ^ SUCCESS
        assert self.value(S+0xa10, 8) == self.value(C+0x690, 8) == 0
        assert self.value(S+4, 4) == SUCCESS and self.value(S+0xc60, 8) == 0x8f98c6acce5848ca

    def message_bytes(self):
        return tuple(self.state.get(MESSAGE+i) for i in range(128))

    def reenter(self, allowed, literals, allocate, success):
        assert self.pc == PARSER
        self.workspace, self.caller = (int(cut['result'], 16) for cut in self.cuts[:2])
        C, S, F = self.caller, self.workspace, self.sp
        self.input_address = I = self.value(C+0x18, 8)
        self.input_extent = self.value(S+0xc8, 4) ^ SUCCESS
        assert I == self.base != 0 and self.input_extent == self.extent == 14
        assert self.value(S+0x1e0, 4) == CALLER_TAG
        assert self.value(C+0x718, 8) == self.value(C+0x788, 8) == MESSAGE
        assert self.value(MESSAGE, 16) == 0
        assert in_private(CONTAINER, 16) and MESSAGE+128 <= CONTAINER
        assert all(CONTAINER+i not in self.state for i in range(16))
        before = self.message_bytes()
        old_input_reads = len(self.input_loads)
        self.parser_reads = []
        endpoint = INPUT_BYTE if success else FAILURE
        H2 = CONTAINER if success else 0
        trace = self.visit(allowed, endpoint, allocate, H2)
        observed_literals = {int(pc, 16): (slot, width, val) for pc, slot, width, val in trace['loads']
                             if int(pc, 16) in literals}
        assert observed_literals == {pc: (row['slot'], 8, row['target']) for pc, row in literals.items()}
        assert self.sp == F and len(self.input_loads) == old_input_reads
        assert self.message_bytes() == before and self.value(C+0xb0, 8) == H2
        assert self.value(C+0x170, 8) == MESSAGE and self.value(S+0x1e0, 4) == CALLER_TAG
        allocation_edge = trace['edges'][1]
        assert (allocation_edge['pc'], allocation_edge['modifier64'], allocation_edge['target']) == (
            hex(ALLOCATION_GATE), '0x1fcb', hex(ALLOCATED if success else COMPLETION_DISPATCH))
        container_stores = [row for row in trace['stores'] if int(row[1], 16) in range(CONTAINER, CONTAINER+16)]
        if success:
            clear = hex(shifted('0xfffffe000a6366c8'))
            assert container_stores == [(clear, hex(H2+offset), 8, '0x0') for offset in (0, 8)]
            assert self.value(C+0x670, 8) == I and self.value(S+0xa10, 8) == 0
            assert self.g[8:11] == [0, 6, I] and self.g[23] == 0xce515bb8
        else:
            assert not container_stores and self.g[23] == 0xce515bb2
            edge = trace['edges'][-1]
            assert (edge['pc'], edge['modifier64'], edge['target']) == (hex(STATUS_GATE), '0xcb79', hex(FAILURE))
            assert hex(COMPLETION_DISPATCH) in trace['sites'] and hex(TAG_GATE) in trace['sites']
        trace.update(input_pointer=hex(I), extent_bytes=self.input_extent, caller_tag=hex(CALLER_TAG),
                     pending_input_address=hex(I+6) if success else None, raw_status=hex(self.g[23]),
                     container=hex(H2), input_loads=0, message_bytes_changed=0)
        return trace

    def completion(self, allowed, bank, mode):
        assert self.pc == INPUT_BYTE
        C, S, F = self.caller, self.workspace, self.sp
        before = self.message_bytes()
        regs = {'x2': C, 'x4': S, 'x7': TABLE, 'w1': 0x7795e642, 'w3': 0x886a1ca3,
                'w22': 0x7795e3ce, 'w23': SUCCESS, 'x28': bank, 'w12': 0x69c, 'w30': SUCCESS}
        self.g[:] = [None]*31
        self.nzcv = 0
        for reg, value in regs.items():
            self.set(reg, value)
        self.pc = COMPLETION
        flag = {'mode_zero': 0, 'mode_nonzero': 1}[mode]
        trace = self.visit(allowed, FLAG_TARGETS[flag])
        assert trace['stores'] == [
            (hex(shifted('0xfffffe000a660b4c')), hex(S+0xc94), 4, hex(SUCCESS)),
            (hex(PUBLISH), hex(MESSAGE), 8, hex(CONTAINER)),
        ]
        assert self.value(MESSAGE, 8) == CONTAINER and self.value(S+0xc94, 4) == SUCCESS
        assert self.message_bytes()[8:] == before[8:] and self.sp == F
        assert [row for row in trace['loads'] if row[0] == hex(FLAG_LOAD)] == [
            (hex(FLAG_LOAD), hex(MESSAGE+0x60), 1, hex(flag)),
        ]
        edge = trace['edges'][-1]
        assert (edge['pc'], edge['modifier64'], edge['target']) == (
            hex(FLAG_GATE), '0xeeda', hex(FLAG_TARGETS[flag]))
        trace.update(seed_registers={reg: hex(value) for reg, value in regs.items()}, entry=hex(COMPLETION),
                     sp=hex(F), flag=flag, bridged_from_header=False)
        return trace


def audit(path):
    build = command('sw_vers', '-buildVersion').strip().decode()
    assert build == '26C5035r' and sysctl('kern.uuid').lower() == IDENTITIES[1][1]
    image = Collection(path, IDENTITIES[1])
    checks = receipt('userclient_message_parser_checks', CHECKS)
    prior = receipt('userclient_message_parser_audit', AUDIT)
    init_checks = receipt('userclient_message_initialization_checks', INITIALIZATION_CHECKS)
    init = receipt('live_fairplay_message_initialization_audit', INSTALLED_INITIALIZATION)
    assert checks['kernel_collection_sha256'] == prior['kernel_collection_sha256'] == IDENTITIES[0][0]
    assert prior['checks_sha256'] == CHECKS
    assert init['identity'] == list(IDENTITIES[1]) and init['historical_checks_sha256'] == INITIALIZATION_CHECKS
    allocate = image.named('_IOMallocTypeImpl')
    layout, allowed, literals, bank = verify_parser(image, checks, allocate)
    init_source = verify_source(image, init_checks, allocate)
    parents = {(r['fixture'], r['result']['profile']): r for r in init['cases'] if r['result']['success']}
    cases = []
    for success in (True, False):
        for case, replay in initialization_cases(image, init_checks, init_source, (True,), ParserReplay):
            fixture, mode = case['fixture'], case['result']['profile']
            assert json.loads(json.dumps(case)) == parents[(fixture, mode)]
            trace = replay.reenter(allowed, literals, allocate, success)
            completion = replay.completion(allowed, bank, mode) if success else None
            cases.append(dict(fixture=fixture, mode=mode, allocation_nonnull=success, prefix=trace,
                              independent_completion=completion))
    assert len(cases) == 8 and len(parents) == 4
    visited = {int(pc, 16) for case in cases
               for trace in (case['prefix'], case['independent_completion']) if trace for pc in trace['sites']}
    third_tag = next(span for span in checks['source']['spans'] if span['label'] == 'completion_tag3')
    assert allowed - visited == {shifted(word['pc']) for word in third_tag['instructions']}
    proofs = prior['source_proofs']
    assert len(proofs) == 209 and len({p['semantic_contract'] for p in proofs}) == 17
    assert all(p['premises_nonvacuous'] for p in proofs)
    with ThreadPoolExecutor(max_workers=6) as workers:
        results = list(workers.map(partial(replay_proof, timeout_seconds=PROOF_TIMEOUT_SECONDS), proofs))
    return dict(build=build, identity=IDENTITIES[1], layout=layout, cases=cases, historical_source_proofs=results,
                historical_checks_sha256=CHECKS, historical_audit_sha256=AUDIT,
                installed_initialization_audit_sha256=INSTALLED_INITIALIZATION,
                native_allocator_observed=False, native_PAC_verified=False, native_transaction_observed=False,
                whole_second_parse_observed=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    print(json.dumps(audit(parser.parse_args().collection), indent=2))
