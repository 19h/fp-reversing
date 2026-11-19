#!/usr/bin/env python3
"""Check installed sole-node schema search using archived serialized bytes."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from functools import partial
from hashlib import sha256
import json
from pathlib import Path

from audit_daemon_iokit_native_registry import command, sysctl
from audit_live_fairplay_context_lifecycle import TABLE, replay_proof
from audit_live_fairplay_early_data import CHECKS as DATA_CHECKS
from audit_live_fairplay_early_header import SUCCESS
from audit_live_fairplay_early_publication import (
    CHECKS as PUB_CHECKS, DESCRIPTOR, MISS, PROOF_TIMEOUT_SECONDS, check_bank,
)
from audit_live_fairplay_early_schema import (
    CHECKS as SCHEMA_CHECKS, ENCODED_KEY, NONNULL, RAW_KEY, SchemaReplay,
)
from audit_live_fairplay_early_writer import AUDITS as WRITER_AUDITS
from audit_live_fairplay_entry import shifted, verify_layout
from audit_live_fairplay_uidlist import receipt
from audit_live_kext_selector26 import Collection, IDENTITIES

CHECKS = '4b6aa07b08d68275cb9ed0f47a744026cfe90c409606929ede81da6bb16968c0'
AUDIT = 'd3ecfc8a02cb3fa53a635b826b33cd58a1d005ad0a2d7cb0ca2d3ea8684cf2e9'
SCHEMA_AUDIT = '4fe41ab2d4aae815f799822c03b20552056c02bee7b82c675a88466050685da5'
BRIDGE = 0xfffffe000a698080
BRIDGE_BRANCH = BRIDGE + 12
DECODER = 0xfffffe000a6782c8
DECODER_RETURN = 0xfffffe000a679ff8
CALLER = 0xfffffe000a6778b8
CALLBACK = 0xfffffe000a6a2dc4
COMPARE = 0xfffffe000a67e7e0
EXTENT_BIAS = 0x7834dd25aad3a2b1
M64 = (1 << 64) - 1
SHARED = {'search_nonnull', 'search_node', 'search_result', 'search_callback'}


def check_source(image, checks):
    shared = checks['publication_source']
    spans = [span for span in shared['spans'] if span['label'] in SHARED]
    layout = verify_layout(image, {'search': checks['source'], 'shared': dict(shared, spans=spans)})
    search = layout['spans']['search']
    assert len(search) == 11 and sum(span['words'] for span in search) == 268
    assert all(not item['changes'] for item in search) and len(layout['branch_fixups']) == 51
    changed = [item for span in layout['spans']['shared'] for item in span['changes']]
    assert [(item['address'], item['mnemonic'], item['operands']) for item in changed] == [
        ('0xfffffe000a6a3cdc', 'adrp', 'x10, #0xfffffe0008488000'),
        ('0xfffffe000a6a3ce0', 'add', 'x10, x10, #0x9a0'),
    ]
    image.instruction(BRIDGE_BRANCH, 'braa', 'x11, x17')
    layout['bridge_terminal'] = dict(pc=hex(BRIDGE_BRANCH), bytes_hex=image.read(BRIDGE_BRANCH, 4).hex(),
                                     target=hex(DECODER), modifier='0xf930')
    assert int(image.pointer(TABLE + 8 * 0x1a2)['target'], 16) == DECODER_RETURN
    layout['normal_address_branches'] = {}
    for site in ('0xfffffe000a637150', '0xfffffe000a637188', '0xfffffe000a6371cc', '0xfffffe000a63720c'):
        pc = shifted(site)
        assert image.branch(pc, 'b.eq') == pc + 8
        layout['normal_address_branches'][hex(pc)] = hex(pc + 8)
    return layout, checks['source']['spans'] + spans


class SearchReplay(SchemaReplay):
    protected_bounds = None

    def step(self, word):
        if word.mnemonic == 'ror':
            dest, source, amount = word.operands
            register = word.reg_name(dest.reg)
            assert register.startswith('x') and 0 < amount.imm < 64
            value = self.operand(word, source)
            self.set(register, (value >> amount.imm) | (value << (64 - amount.imm)))
            return self.pc + 4
        return super().step(word)

    def load(self, address, width, discarded=False):
        if self.protected_bounds is not None:
            start, end = self.protected_bounds
            if start <= address < end:
                assert width == 1 and not discarded
                self.record_loads.append((self.pc, address))
        return super().load(address, width, discarded)

    def search(self, state, spans, protected, witness):
        S, C, H, J, Z = (int(cut['result'], 16) for cut in self.cuts)
        F = self.sp
        raw_tag = self.input['wire_tag32']
        found = raw_tag == RAW_KEY
        assert found == witness
        assert self.pc == NONNULL and self.value(H, 8) == J and self.value(J, 8) == 0
        alias, = state['schema_search_additional_source_cells']
        assert (alias['root'], alias['offset'], alias['size_bytes']) == ('F', '0x898', 8)
        assert self.value(F+0x898, 8) == C+0x560 == int.from_bytes(
            bytes.fromhex(alias['reconstructed_bytes_hex']), 'little')
        extent = self.value(J+0x10, 4)
        assert extent == len(protected) == self.extent
        assert not any(address in self.state for address in range(Z, Z + extent))
        self.state.update((Z + j, value) for j, value in enumerate(protected))
        self.protected_bounds = (Z, Z + extent)
        self.record_loads = []
        first_edge = len(self.edges)
        first_store = len(self.publication_stores)
        allowed = {shifted(word['pc']) for span in spans for word in span['instructions']}
        allowed.add(BRIDGE_BRANCH)
        frontier = BRIDGE if found else CALLER
        visits = 0
        while self.pc != CALLER:
            assert visits < len(allowed) + 17 and self.pc in allowed, hex(self.pc)
            if self.pc == COMPARE:
                assert (self.g[22], self.g[12]) == (raw_tag ^ SUCCESS, ENCODED_KEY)
            self.ix += 1
            word, = self.cs.disasm(self.image.read(self.pc, 4), self.pc)
            target = self.step(word)
            if target == CALLBACK:
                assert (self.g[22], self.g[23]) == (DESCRIPTOR, SUCCESS if found else MISS)
                assert self.value(C+0x710, 8) == (J if found else 0)
            self.pc = target
            visits += 1
            if self.pc == BRIDGE and word.address == shifted('0xfffffe000a661e3c'):
                break
        assert self.pc == frontier
        loads = ('0xfffffe000a637158', '0xfffffe000a637190', '0xfffffe000a6371d4', '0xfffffe000a637214')
        assert self.record_loads == [(shifted(pc), Z+j) for j, pc in enumerate(loads)]
        assert self.value(H, 8) == self.value(H+8, 8) == J and self.value(J, 16) == 0
        assert self.value(C+0x418, 8) == H and self.value(J+0x18, 8) == Z
        assert self.value(J+0x10, 4) == self.value(S+0xa10, 8) == extent
        assert self.value(S+0xbc4, 4) == 0 and self.value(Z, extent) == int.from_bytes(protected, 'little')
        stores = [('0xfffffe000a662c18', C+0x2b0, 8, J)]
        transfers = [('0xfffffe000a662c00', 0xed3d), ('0xfffffe000a662c60', 0xb5a8),
                     ('0xfffffe000a656ef0', 0x5e04), ('0xfffffe000a637138', 0xf930),
                     ('0xfffffe000a63d624', 0xb745)]
        if found:
            transfers.append(('0xfffffe000a662c44', 0xde40))
        else:
            transfers.extend([('0xfffffe000a63d680', 0xde40), ('0xfffffe000a662c00', 0xed3d),
                              ('0xfffffe000a662c44', 0xb5a8)])
            stores.append(('0xfffffe000a662c18', C+0x2b0, 8, 0))
        transfers.extend([('0xfffffe000a662b00', 0x7250), ('0xfffffe000a661c34', 0x8d28)])
        stores.append(('0xfffffe000a662c4c', C+0x710, 8, J if found else 0))
        if found:
            transfers.extend([('0xfffffe000a661c88', 0x3751), ('0xfffffe000a661cec', 0xd784),
                              ('0xfffffe000a661da0', 0x3751), ('0xfffffe000a656ef0', 0x5e04)])
            stores.extend([('0xfffffe000a661cb8', C+0x560, 8, Z),
                           ('0xfffffe000a661d54', S+0x260, 8, EXTENT_BIAS + extent),
                           ('0xfffffe000a661d5c', F+0xbd0, 8, 0)])
            assert (self.g[8], self.g[9], self.g[11]) == (Z, 0x1a2, 0xe07)
            assert (self.g[10] + self.g[1]) & M64 == 0 and self.g[23] == 0xce515bb8
        else:
            transfers.extend([('0xfffffe000a661e40', 0x3751), ('0xfffffe000a636728', 0x415f)])
            assert self.g[23] == MISS
        edges = self.edges[first_edge:]
        assert [(edge['kind'], edge['target'], edge['modifier64']) for edge in edges] == [
            ('braa', hex(shifted(target)), hex(modifier)) for target, modifier in transfers
        ]
        actual = self.publication_stores[first_store:]
        assert actual == [(hex(shifted(pc)), hex(address), width, hex(value))
                          for pc, address, width, value in stores]
        assert all(address + width <= Z or Z + extent <= address for _, address, width, _ in stores)
        return dict(case_index=state['predecessor_case_index'], derived_adid_field=witness,
                    found=found, raw_tag32=hex(raw_tag), instruction_visits=visits,
                    protected_input_sha256=sha256(protected).hexdigest(), extent_bytes=extent,
                    record_loads=[dict(pc=hex(pc), address=hex(address)) for pc, address in self.record_loads],
                    output_node=hex(self.value(C+0x710, 8)), final_status=hex(self.g[23]),
                    stores=actual, logical_edges=edges, final_target=hex(self.pc))


def replay_cases(image, checks, prior, spans):
    data = receipt('userclient_early_data_checks', DATA_CHECKS['early_data'])
    payload = receipt('userclient_early_payload_audit', WRITER_AUDITS['early_payload'])
    installed = receipt('live_fairplay_early_schema_audit', SCHEMA_AUDIT)
    assert installed['historical_checks_sha256'] == SCHEMA_CHECKS and installed['identity'] == list(IDENTITIES[1])
    states = {row['predecessor_case_index']: row for row in checks['predecessor_states']}
    stored_payloads = {row['predecessor_case_index']: row for row in payload['partial_state_evaluations']}
    shared = checks['publication_source']
    schema_spans = checks['schema_source']['spans'] + [
        span for span in shared['spans'] if span['label'] == 'search_entry']
    cases = []
    for expected in installed['cases']:
        index = expected['case_index']
        state = states[index]
        replay = SearchReplay(image, data['cases'][index])
        assert replay.input == state['input'] and stored_payloads[index]['profile'] == replay.input['profile']
        replay.replay()
        replay.publication(state, shared)
        previous = replay.schema(state, schema_spans)
        previous['stores'] = [list(store) for store in previous['stores']]
        assert previous == expected
        protected = bytes.fromhex(stored_payloads[index]['protected_record_hex'])
        cases.append(replay.search(state, spans, protected, witness=False))
    assert len(cases) == 24

    certificate = prior['ADID_field_certificate']
    index = certificate['source_predecessor_case_index']
    assert index in {case['case_index'] for case in cases}
    state = deepcopy(states[index])
    row = dict(data['cases'][index], input=dict(state['input']))
    raw = bytes.fromhex(certificate['raw_record_hex'])
    assert len(raw) == row['input']['wire_length32'] + 10 == row['input']['declared_size64'] == 14
    assert raw.hex() == checks['adid_evidence']['packets'][0]['field_record_hex']
    row['input'].update(input_fixture_hex=raw.hex(), wire_tag32=RAW_KEY)
    tag_cell, = (cell for cell in state['source_defined_cells'] if (cell['root'], cell['offset']) == ('S', '0x1d0'))
    tag_cell['reconstructed_bytes_hex'] = ENCODED_KEY.to_bytes(4, 'little').hex()
    state['input'] = row['input']
    replay = SearchReplay(image, row)
    replay.replay()
    replay.publication(state, shared)
    replay.schema(state, schema_spans)
    protected = bytes.fromhex(certificate['protected_record_hex'])
    cases.append(replay.search(state, spans, protected, witness=True))
    return cases


def audit(path):
    build = command('sw_vers', '-buildVersion').strip().decode()
    assert build == '26C5035r' and sysctl('kern.uuid').lower() == IDENTITIES[1][1]
    image = Collection(path, IDENTITIES[1])
    checks = receipt('userclient_schema_search_checks', CHECKS)
    prior = receipt('userclient_schema_search_audit', AUDIT)
    schema = receipt('userclient_early_schema_checks', SCHEMA_CHECKS)
    publication = receipt('userclient_early_publication_checks', PUB_CHECKS)
    assert checks['kernel_collection_sha256'] == prior['kernel_collection_sha256'] == IDENTITIES[0][0]
    assert prior['checks_sha256'] == CHECKS and prior['conditional_schema_search_step_established']
    assert checks['schema_source'] == schema['source'] and checks['publication_source'] == publication['source']
    layout, spans = check_source(image, checks)
    bank = check_bank(image, checks['source'])
    cases = replay_cases(image, checks, prior, spans)
    assert len(prior['source_proofs']) == 22
    with ThreadPoolExecutor(max_workers=4) as workers:
        proofs = list(workers.map(partial(replay_proof, timeout_seconds=PROOF_TIMEOUT_SECONDS),
                                  prior['source_proofs']))
    return dict(build=build, identity=IDENTITIES[1], layout=layout, bank=bank, cases=cases,
                historical_checks_sha256=CHECKS, historical_audit_sha256=AUDIT,
                installed_schema_audit_sha256=SCHEMA_AUDIT, source_proofs=proofs,
                proof_timeout_seconds=PROOF_TIMEOUT_SECONDS, continuous_writer_execution=False,
                native_transaction_observed=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    print(json.dumps(audit(parser.parse_args().collection), indent=2))
