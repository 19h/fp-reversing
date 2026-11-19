#!/usr/bin/env python3
"""Replay installed schema scalar decoding and caller status selection."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from functools import partial
import json
from pathlib import Path

from audit_daemon_iokit_native_registry import command, sysctl
from audit_live_fairplay_context_lifecycle import replay_proof
from audit_live_fairplay_early_data import CHECKS as DATA_CHECKS
from audit_live_fairplay_early_header import SUCCESS
from audit_live_fairplay_early_publication import PROOF_TIMEOUT_SECONDS
from audit_live_fairplay_early_schema import FRAME_HEADER, RAW_KEY
from audit_live_fairplay_early_writer import AUDITS as WRITER_AUDITS
from audit_live_fairplay_entry import shifted, verify_layout
from audit_live_fairplay_schema_search import (
    AUDIT as SEARCH_AUDIT, BRIDGE, BRIDGE_BRANCH, CHECKS as SEARCH_CHECKS, DECODER_RETURN,
    SearchReplay, check_source, replay_derived_prefix,
)
from audit_live_fairplay_uidlist import receipt
from audit_live_kext_selector26 import Collection, IDENTITIES

CHECKS = 'd83365fed0e9cddd837d509254651e6f45c7b718b60f166ea730cbcc0ce50440'
AUDIT = '27e7a4cc7dcea11fdcb4e89d72d11f34dca9da4e0615fccea176f4c4ca2e84e3'
INSTALLED_SEARCH = '0a3355f3a1099c14b0bcf940b9a20a025d79927b2d726b634aeaa0b8ca676e0f'
SUCCESS_PC = shifted('0xfffffe000a63677c')
ERROR_PC = shifted('0xfffffe000a641c1c')
TYPE_ERROR = 0xce515ae1
REUSED = {'word_bridge_read', 'decode_word', 'schema_caller_return'}
WORD_LOADS = ('0xfffffe000a637158', '0xfffffe000a637190', '0xfffffe000a6371d4', '0xfffffe000a637214')


def check_scalar_layout(image, checks):
    lookup = checks['lookup_source']
    reused = [span for span in lookup['spans'] if span['label'] in REUSED]
    spans = checks['source']['spans']
    layout = verify_layout(image, {'scalar': checks['source'], 'reused': dict(lookup, spans=reused)})
    assert len(layout['spans']['scalar']) == 14
    assert sum(span['words'] for span in layout['spans']['scalar']) == 267
    assert len(layout['branch_fixups']) == 63
    assert all(not span['changes'] for group in layout['spans'].values() for span in group)
    sites = (
        ('0xfffffe000a639340', 'b.eq', '0xfffffe000a639348'),
        ('0xfffffe000a639374', 'b.eq', '0xfffffe000a63937c'),
        ('0xfffffe000a638c14', 'b.ne', '0xfffffe000a63abdc'),
        ('0xfffffe000a63abe4', 'b.eq', '0xfffffe000a63ac3c'),
        ('0xfffffe000a63abf0', 'b.eq', '0xfffffe000a63ac3c'),
    )
    layout['direct_branches'] = {}
    for site, mnemonic, target in sites:
        pc = shifted(site)
        assert image.branch(pc, mnemonic) == shifted(target)
        layout['direct_branches'][hex(pc)] = dict(mnemonic=mnemonic, target=hex(shifted(target)))
    return layout, spans + reused


class ScalarReplay(SearchReplay):
    def step(self, word):
        if word.mnemonic == 'csel':
            dest, first, second = word.operands[:3]
            condition = word.op_str.rsplit(',', 1)[1].strip()
            source = first if self.condition(condition) else second
            self.set(word.reg_name(dest.reg), self.reg(word.reg_name(source.reg)))
            return self.pc + 4
        if word.mnemonic == 'bfi':
            dest, source, shift, count = word.operands
            name = word.reg_name(dest.reg)
            mask = ((1 << count.imm) - 1) << shift.imm
            value = (self.reg(name) & ~mask) | ((self.reg(word.reg_name(source.reg)) << shift.imm) & mask)
            self.set(name, value)
            return self.pc + 4
        return super().step(word)

    def scalar(self, spans, raw, protected):
        S, C, H, J, Z = (int(cut['result'], 16) for cut in self.cuts)
        F = self.sp
        tag, kind, length = FRAME_HEADER.unpack_from(raw)
        extent = len(raw)
        assert extent == length + FRAME_HEADER.size == len(protected) == self.value(J+0x10, 4)
        assert kind in (0x9777, 0x8485, 0x50db) and tag == RAW_KEY
        scalar = kind == 0x9777
        assert not scalar or length == 4
        output = int.from_bytes(raw[10:14], 'big') if scalar else None
        assert self.pc == BRIDGE and self.value(F+0xbd0, 8) == self.value(F+0xaa8, 8) == 0
        assert self.value(C+0x5f0, 8) == S+0xbc4 and self.value(S+0xbc4, 4) == 0
        assert self.value(C+0x560, 8) == Z
        allowed = {shifted(word['pc']) for span in spans for word in span['instructions']}
        allowed.add(BRIDGE_BRANCH)
        decoded = {
            DECODER_RETURN: (22, tag ^ SUCCESS),
            shifted('0xfffffe000a63a2b0'): (8, kind ^ 0x365e),
            shifted('0xfffffe000a638b84'): (22, length ^ SUCCESS),
        }
        if scalar:
            decoded[shifted('0xfffffe000a63ac18')] = (22, output ^ SUCCESS)
        observed = {}
        first_load, first_store, first_edge = len(self.record_loads), len(self.publication_stores), len(self.edges)
        visits = 0
        while self.pc not in (SUCCESS_PC, ERROR_PC):
            assert visits < 2 * len(allowed) and self.pc in allowed, hex(self.pc)
            if self.pc in decoded:
                reg, want = decoded[self.pc]
                mask = 0xffff if reg == 8 else 0xffffffff
                value = self.g[reg] & mask
                assert value == want, (hex(self.pc), hex(value), hex(want))
                observed[hex(self.pc)] = hex(value)
            self.ix += 1
            word, = self.cs.disasm(self.image.read(self.pc, 4), self.pc)
            self.pc = self.step(word)
            visits += 1
        assert len(observed) == len(decoded)
        expected_result = (SUCCESS_PC, SUCCESS) if scalar else (ERROR_PC, TYPE_ERROR)
        assert (self.pc, self.g[23]) == expected_result
        assert self.value(F+0xaa8, 8) == self.value(S+0xad8, 8) == extent
        assert self.value(H, 8) == self.value(H+8, 8) == J and self.value(J, 16) == 0
        assert self.value(C+0x710, 8) == J and self.value(J+0x18, 8) == Z
        assert self.value(J+0x10, 4) == extent and self.value(Z, extent) == int.from_bytes(protected, 'little')
        assert self.value(S+0xbc4, 4) == (output if scalar else 0)
        loads = [(pc, offset) for offset, pc in enumerate(WORD_LOADS)]
        loads.extend([('0xfffffe000a639348', 4), ('0xfffffe000a639380', 5)])
        for base in ((6, 10) if scalar else (6,)):
            loads.extend((pc, base + offset) for offset, pc in enumerate(WORD_LOADS))
        assert self.record_loads[first_load:] == [(shifted(pc), Z+offset) for pc, offset in loads]
        stores = [('0xfffffe000a63a2d4', S+0xc70, 2, kind ^ 0x365e),
                  ('0xfffffe000a638bac', S+0xad8, 8, extent)]
        if scalar:
            stores.append(('0xfffffe000a63ac24', S+0xb64, 4, output ^ SUCCESS))
        stores.append(('0xfffffe000a63ac58', F+0xaa8, 8, extent))
        if scalar:
            stores.append(('0xfffffe000a63acb8', S+0xbc4, 4, output))
        actual = self.publication_stores[first_store:]
        assert actual == [(hex(shifted(pc)), hex(address), width, hex(value))
                          for pc, address, width, value in stores]
        assert all(address + width <= Z or Z + extent <= address for _, address, width, _ in stores)
        transfers = [('0xfffffe000a637138', 0xf930), ('0xfffffe000a638e68', 0xb745),
                     ('0xfffffe000a63930c', 0x9c55), ('0xfffffe000a63a2b0', 0x1086),
                     ('0xfffffe000a637128', 0x266f), ('0xfffffe000a637138', 0xf930),
                     ('0xfffffe000a638b84', 0xb745), ('0xfffffe000a638c04', 0x9247)]
        if scalar:
            transfers.extend([('0xfffffe000a638c50', 0x9247), ('0xfffffe000a637128', 0x266f),
                              ('0xfffffe000a637138', 0xf930), ('0xfffffe000a63ac18', 0xb745),
                              ('0xfffffe000a63ac38', 0x50a4), ('0xfffffe000a63ac94', 0x3751)])
        transfers.extend([('0xfffffe000a661e40', 0x3751), ('0xfffffe000a636728', 0x415f),
                          ('0xfffffe000a63677c' if scalar else '0xfffffe000a641c1c', 0xd4c)])
        edges = self.edges[first_edge:]
        assert [(edge['kind'], edge['target'], edge['modifier64']) for edge in edges] == [
            ('braa', hex(shifted(target)), hex(modifier)) for target, modifier in transfers
        ]
        return dict(raw_type16=hex(kind), body_size_bytes=length, instruction_visits=visits,
                    output32=output, raw_status32=hex(self.g[23]), committed_cursor_bytes=extent,
                    final_target=hex(self.pc), decoded=observed, logical_edges=edges, stores=actual,
                    record_loads=[dict(pc=hex(shifted(pc)), offset_bytes=offset) for pc, offset in loads])


def replay_cases(image, checks, prior, search_spans, scalar_spans):
    installed = receipt('live_fairplay_schema_search_audit', INSTALLED_SEARCH)
    search = receipt('userclient_schema_search_audit', SEARCH_AUDIT)
    payload = receipt('userclient_early_payload_audit', WRITER_AUDITS['early_payload'])
    data = receipt('userclient_early_data_checks', DATA_CHECKS['early_data'])
    assert installed['identity'] == list(IDENTITIES[1]) and installed['historical_audit_sha256'] == SEARCH_AUDIT
    certificate = prior['ADID_field_certificate']
    original = search['ADID_field_certificate']
    for field in ('source_predecessor_case_index', 'raw_record_hex', 'protected_record_hex'):
        assert certificate[field] == original[field]
    witness_index = certificate['source_predecessor_case_index']
    witness_bytes = bytes.fromhex(certificate['protected_record_hex'])
    witness_raw = bytes.fromhex(certificate['raw_record_hex'])
    witness_Z = data['cases'][witness_index]['input']['data_result_fixture']
    states = {row['predecessor_case_index']: row for row in checks['predecessor_states']}
    payloads = {row['predecessor_case_index']: row for row in payload['partial_state_evaluations']}
    historical = {row['predecessor_case_index']: row for row in prior['partial_state_evaluations']}
    installed_match, = (row for row in installed['cases'] if row['found'])
    cases = []
    fixtures = (('adid_field', witness_index), ('u32_nonzero', 5), ('u64', 7),
                ('span_zero', 1), ('span_nonzero', 3))
    for name, index in fixtures:
        row = data['cases'][index]
        state = states[index]
        assert row['input'] == state['input'] and row['input']['data_result_fixture'] == witness_Z
        if name == 'adid_field':
            raw, protected = witness_raw, witness_bytes
        else:
            raw = witness_raw[:4] + bytes.fromhex(row['input']['input_fixture_hex'])[4:]
            protected = witness_bytes[:4] + bytes.fromhex(payloads[index]['protected_record_hex'])[4:]
        replay = replay_derived_prefix(ScalarReplay, image, row, state, raw, checks)
        lookup = replay.search(state, search_spans, protected, witness=True)
        if name == 'adid_field':
            lookup['stores'] = [list(store) for store in lookup['stores']]
            assert lookup == installed_match
        result = replay.scalar(scalar_spans, raw, protected)
        reference = certificate if name == 'adid_field' else historical[index]
        end = reference['saved_caller_success_target'] if name == 'adid_field' else reference['final_target']
        assert result['raw_status32'] == reference['raw_status32'] and result['final_target'] == hex(shifted(end))
        value = reference['decoded_output32'] if name == 'adid_field' else reference['output32']
        assert (result['output32'] if result['output32'] is not None else 0) == value
        cases.append(dict(fixture=name, case_index=index, result=result,
                          protected_record_sha256=lookup['protected_input_sha256']))
    return cases


def audit(path):
    build = command('sw_vers', '-buildVersion').strip().decode()
    assert build == '26C5035r' and sysctl('kern.uuid').lower() == IDENTITIES[1][1]
    image = Collection(path, IDENTITIES[1])
    checks = receipt('userclient_schema_scalar_checks', CHECKS)
    prior = receipt('userclient_schema_scalar_audit', AUDIT)
    search = receipt('userclient_schema_search_checks', SEARCH_CHECKS)
    assert checks['kernel_collection_sha256'] == prior['kernel_collection_sha256'] == IDENTITIES[0][0]
    assert prior['checks_sha256'] == CHECKS and prior['conditional_schema_u32_decoding_established']
    assert checks['lookup_source'] == search['source'] and checks['publication_source'] == search['publication_source']
    _, search_spans = check_source(image, search)
    layout, scalar_spans = check_scalar_layout(image, checks)
    cases = replay_cases(image, checks, prior, search_spans, scalar_spans)
    assert len(prior['source_proofs']) == 15 and len(cases) == 5
    with ThreadPoolExecutor(max_workers=4) as workers:
        proofs = list(workers.map(partial(replay_proof, timeout_seconds=PROOF_TIMEOUT_SECONDS),
                                  prior['source_proofs']))
    return dict(build=build, identity=IDENTITIES[1], layout=layout, cases=cases, source_proofs=proofs,
                historical_checks_sha256=CHECKS, historical_audit_sha256=AUDIT,
                installed_search_audit_sha256=INSTALLED_SEARCH, proof_timeout_seconds=PROOF_TIMEOUT_SECONDS,
                continuous_writer_execution=False, native_transaction_observed=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    print(json.dumps(audit(parser.parse_args().collection), indent=2))
