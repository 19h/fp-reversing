#!/usr/bin/env python3
"""Trace installed exhausted-input state to the first schema-key lookup."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from hashlib import sha256
import json
from pathlib import Path
from struct import Struct

from audit_daemon_iokit_native_registry import command, sysctl
from audit_live_fairplay_context_lifecycle import TABLE, replay_proof
from audit_live_fairplay_early_data import CHECKS as DATA_CHECKS
from audit_live_fairplay_early_publication import (
    CHECKS as PUB_CHECKS, EXHAUSTED, PROOF_TIMEOUT_SECONDS, PublicationReplay,
)
from audit_live_fairplay_early_header import SUCCESS
from audit_live_fairplay_entry import shifted, verify_layout
from audit_live_fairplay_uidlist import receipt
from audit_live_kext_selector26 import Collection, IDENTITIES

CHECKS = '3bc245c5e60310a11bfa695d1a5f4587391778f88622d6b35ea9ad74b8da3cf4'
AUDIT = 'c5e7a1556d6ea45ba01a97b14ed4cf8ffbd659dc87931e443ae390ed89286d2d'
PUB_AUDIT = '62b4772ca72a74b0663711a8ee68554777d402a9959771541ae40f6df5cb2a7b'
PACKET_CHECKS = '4c3348768ff2da19ca81ea7144c48928e4e16f5a4b0c8d34411f0e2785efd9db'
PACKET_SHA = 'fb8563f814c1534bf411f71cba2ee7ce87e5fb8aeb4b5e1016e258b9fca7eda8'
RAW_KEY = 0xfa834112
ENCODED_KEY = RAW_KEY ^ SUCCESS
ACTION = 0x1830b7ce
FRAME_HEADER = Struct('>IHI')
HELPER = 0xfffffe000a695408
LOOKUP = 0xfffffe000a6a3c44
NONNULL = 0xfffffe000a6a3d70
COMPARES = {
    '0xfffffe000a660bb4': (0x89f25623, 'b.eq', '0xfffffe000a66128c'),
    '0xfffffe000a660bc4': (0xfbb3f478, 'b.eq', '0xfffffe000a661144'),
    '0xfffffe000a660bd4': (ACTION, 'b.ne', '0xfffffe000a636310'),
}


def check_layout(image, checks):
    shared = checks['publication_source']
    spans = [span for span in shared['spans'] if span['label'] == 'search_entry']
    layout = verify_layout(image, {'schema': checks['source'], 'shared': dict(shared, spans=spans)})
    assert all(not span['changes'] for spans in layout['spans'].values() for span in spans)
    assert len(layout['spans']['schema']) == 16
    assert sum(span['words'] for span in layout['spans']['schema']) == 139
    assert sum(span['words'] for span in layout['spans']['shared']) == 19
    assert len(layout['branch_fixups']) == 39
    layout['direct_branches'] = {}
    for site, (value, mnemonic, old_target) in COMPARES.items():
        pc = shifted(site)
        target = image.branch(pc, mnemonic)
        assert target == shifted(old_target)
        layout['direct_branches'][hex(pc)] = dict(mnemonic=mnemonic, target=hex(target), value=hex(value))
    return layout


class SchemaReplay(PublicationReplay):
    def schema(self, historical, spans):
        S, C, H, J, Z = (int(cut['result'], 16) for cut in self.cuts)
        F = self.sp
        cursor = self.value(S + 0xa10, 8)
        assert self.pc == EXHAUSTED and self.g[23] == SUCCESS and cursor == self.extent
        roots = dict(F=F, C=C, S=S, H=H)
        cells = {}
        for cell in historical['additional_source_defined_cells']:
            root, offset, width = cell['root'], int(cell['offset'], 16), cell['size_bytes']
            value = self.value(roots[root] + offset, width)
            assert value.to_bytes(width, 'little').hex() == cell['reconstructed_bytes_hex']
            cells[f'{root}+{offset:#x}'] = hex(value)
        assert len(cells) == 9
        allowed = {shifted(word['pc']) for span in spans for word in span['instructions']}
        comparisons = {shifted(site): value for site, (value, _, _) in COMPARES.items()}
        first_edge = len(self.edges)
        first_load = len(self.private_reads)
        first_store = len(self.publication_stores)
        visits = 0
        compared = []
        while self.pc != NONNULL:
            assert visits < len(allowed) and self.pc in allowed, hex(self.pc)
            self.ix += 1
            word, = self.cs.disasm(self.image.read(self.pc, 4), self.pc)
            target = self.step(word)
            if self.pc in comparisons:
                assert (self.g[8], self.g[9], target) == (ACTION, comparisons[self.pc], self.pc + 4)
                compared.append(dict(pc=hex(self.pc), literal=hex(self.g[9]), taken=False))
            if target == HELPER:
                assert (self.g[22], self.g[9], self.g[11], self.g[8]) == (H, ENCODED_KEY, S+0xbc4, 0xf6)
            if target == LOOKUP:
                assert (self.g[22], self.g[9], self.g[10], self.g[8]) == (H, ENCODED_KEY, C+0x710, 0x7f)
                assert (self.g[2], self.g[4], self.g[7]) == (C, S, TABLE)
            self.pc = target
            visits += 1
        assert len(compared) == 3
        exact_stores = (
            ('0xfffffe000a660b4c', S+0xc94, 4, SUCCESS),
            ('0xfffffe000a660b70', C+0x418, 8, H),
            ('0xfffffe000a654294', C+0x4d0, 8, shifted('0xfffffe000a636728')),
            ('0xfffffe000a654298', C+0x5f0, 8, S+0xbc4),
            ('0xfffffe000a65429c', C+0x710, 8, 0),
            ('0xfffffe000a6542a0', S+0xb64, 4, SUCCESS),
            ('0xfffffe000a6542a4', F+0xaa8, 8, 0),
            ('0xfffffe000a662ac8', C+0xc8, 8, shifted('0xfffffe000a661c34')),
            ('0xfffffe000a662acc', S, 4, ENCODED_KEY),
            ('0xfffffe000a662ad0', C+0x758, 8, C+0x710),
        )
        stores = self.publication_stores[first_store:]
        assert stores == [(hex(shifted(pc)), hex(address), width, hex(value))
                          for pc, address, width, value in exact_stores]
        assert all(address + width <= Z or Z + cursor <= address for _, address, width, _ in exact_stores)
        assert self.value(H, 8) == self.value(H+8, 8) == J
        assert self.value(C+0x418, 8) == H and self.value(S+0xa10, 8) == cursor
        assert self.value(C+0x50, 8) == self.value(S+0xbc4, 4) == 0
        loads = ((C+0xb0, 8), (C+0x170, 8), (S+0x1e0, 4), (F+0x908, 8),
                 (C+0x418, 8), (F+0x648, 8), (F+0x708, 8), (F+0xa48, 8))
        assert self.private_reads[first_load:] == [(address, width, False) for address, width in loads]
        transfers = (
            ('0xfffffe000a660b64', 0x8ef5), ('0xfffffe000a660b88', 0x1fcb),
            ('0xfffffe000a6366e0', 0x64d8), ('0xfffffe000a654278', 0x2d2b),
            ('0xfffffe000a6542d4', 0x3751), ('0xfffffe000a662ab4', 0x0ee9),
            ('0xfffffe000a662be0', 0x7250),
        )
        edges = self.edges[first_edge:]
        assert [(edge['kind'], edge['target'], edge['modifier64']) for edge in edges] == [
            ('braa', hex(shifted(target)), hex(modifier)) for target, modifier in transfers
        ]
        return dict(case_index=historical['predecessor_case_index'], instruction_visits=visits,
                    additional_cells=cells, comparisons=compared, cursor_bytes=cursor,
                    private_loads=[dict(address=hex(address), size_bytes=width) for address, width in loads],
                    stores=stores, logical_edges=edges, final_target=hex(self.pc))


def find_record(data, start, end, key):
    """Walk one complete bounded container and return the unique direct match."""
    assert 0 <= start <= end <= len(data)
    match = None
    while start < end:
        assert start + FRAME_HEADER.size <= end
        tag, kind, length = FRAME_HEADER.unpack_from(data, start)
        body = start + FRAME_HEADER.size
        stop = body + length
        assert stop <= end
        if tag == key:
            assert match is None
            match = dict(offset=start, key32=tag, type16=kind, length32=length,
                         body_offset=body, end_exclusive=stop)
        start = stop
    return match


def check_packet_key(archive):
    packets = receipt('adid_avp_packet_checks', PACKET_CHECKS)['source_built_followup_packets']
    rows = []
    for packet, historical in zip(packets, archive, strict=True):
        data = bytes.fromhex(packet['bytes320'])
        assert len(data) == 320 and sha256(data).hexdigest() == PACKET_SHA
        assert packet['label'] == historical['label']
        assert find_record(data, 0, len(data), RAW_KEY) is None
        assert FRAME_HEADER.unpack_from(data) == (0x6125a127, 0x8485, 8)
        start, end = 0, len(data)
        path = []
        for key, kind in ((0xfd2821c7, 0x50db), (0x351bdea7, 0x50db),
                          (0xfd2821c7, 0x50db), (RAW_KEY, 0x9777)):
            match = find_record(data, start, end, key)
            assert match is not None and match['type16'] == kind
            path.append(match)
            start, end = match['body_offset'], match['end_exclusive']
        assert path == historical['containment_path']
        assert path[-2]['body_offset'] == path[-1]['offset'] == 118 and path[-2]['length32'] == 128
        assert (start, end) == (128, 132) and data[start:end] == bytes(4)
        rows.append(dict(label=packet['label'], matching_path=path, found_at_top_level=False))
    assert len(rows) == 12
    return dict(source_checks_sha256=PACKET_CHECKS, packet_sha256=PACKET_SHA,
                source_built_packet_size_bytes=320, first_top_level_record_size_bytes=18,
                innermost_container_size_bytes=128, first_innermost_record_size_bytes=14, rows=rows)


def audit(path):
    build = command('sw_vers', '-buildVersion').strip().decode()
    assert build == '26C5035r' and sysctl('kern.uuid').lower() == IDENTITIES[1][1]
    image = Collection(path, IDENTITIES[1])
    checks = receipt('userclient_early_schema_checks', CHECKS)
    prior = receipt('userclient_early_schema_audit', AUDIT)
    publication = receipt('userclient_early_publication_checks', PUB_CHECKS)
    installed = receipt('live_fairplay_early_publication_audit', PUB_AUDIT)
    assert prior['checks_sha256'] == CHECKS and prior['conditional_exhaustion_to_schema_lookup_established']
    assert checks['kernel_collection_sha256'] == prior['kernel_collection_sha256'] == IDENTITIES[0][0]
    assert installed['checks_sha256'] == PUB_CHECKS and installed['identity'] == list(IDENTITIES[1])
    assert checks['publication_source'] == publication['source']
    layout = check_layout(image, checks)
    packet = check_packet_key(checks['adid_evidence']['packets'])
    data = receipt('userclient_early_data_checks', DATA_CHECKS['early_data'])
    states = {row['predecessor_case_index']: row for row in checks['predecessor_states']}
    spans = checks['source']['spans'] + [span for span in publication['source']['spans']
                                       if span['label'] == 'search_entry']
    cases = []
    for expected in installed['cases']:
        index = expected['case_index']
        state = states[index]
        replay = SchemaReplay(image, data['cases'][index])
        assert replay.input == state['input'] and replay.input['declared_size64'] <= 0xffffffff
        replay.replay()
        previous = replay.publication(state, publication['source'])
        previous['stores'] = [list(store) for store in previous['stores']]
        assert previous == expected
        cases.append(replay.schema(state, spans))
    assert len(cases) == 24
    assert len(prior['source_proofs']) == 13
    with ThreadPoolExecutor(max_workers=4) as workers:
        proofs = list(workers.map(partial(replay_proof, timeout_seconds=PROOF_TIMEOUT_SECONDS),
                                  prior['source_proofs']))
    return dict(build=build, identity=IDENTITIES[1], layout=layout, cases=cases,
                historical_checks_sha256=CHECKS, historical_audit_sha256=AUDIT,
                installed_publication_audit_sha256=PUB_AUDIT, packet=packet, source_proofs=proofs,
                proof_timeout_seconds=PROOF_TIMEOUT_SECONDS, requested_raw_key32=hex(RAW_KEY),
                transport_identity_established=False, native_transaction_observed=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    print(json.dumps(audit(parser.parse_args().collection), indent=2))
