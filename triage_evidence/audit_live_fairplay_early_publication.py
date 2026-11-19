#!/usr/bin/env python3
"""Check installed first-node publication from the serialized-record frontier."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from functools import partial
import json
from pathlib import Path

from audit_daemon_iokit_native_registry import command, sysctl
from audit_live_fairplay_connection_retirement import verify_fixup
from audit_live_fairplay_context_lifecycle import POOL, POOL_ROOTS, TABLE, read_descriptor, replay_proof
from audit_live_fairplay_early_data import CHECKS as DATA_CHECKS, DataReplay, FREE_TYPE
from audit_live_fairplay_early_header import NODE_TYPE, SUCCESS
from audit_live_fairplay_early_writer import CHECKS as WRITER_CHECKS
from audit_live_fairplay_entry import CONTROLLERS, shifted, verify_layout
from audit_live_fairplay_uidlist import receipt
from audit_live_kext_selector26 import Collection, IDENTITIES

CHECKS = 'f0d3a605400d34ce4e79a92a09ec583f33e3bd726fc058578d3c7fa74bbb3c26'
AUDIT = 'e4f5500b71e6b6b45d91b649d0b5fb71029f3f3eddc0cbee0c9fa7d9ae318743'
WRITER_AUDIT = '402615870a644e07d9721e93d22b9851c437c6db01e3ef73a18616400af3baf2'
ENTRY = 0xfffffe000a696e44
EXHAUSTED = 0xfffffe000a6a1cbc
NEXT_HEADER = 0xfffffe000a6a1db8
DESCRIPTOR = 0xfffffe0008492780
MISS = 0xce515bda
CONTROL = 0x886a1ca3
MASK_WORD = 0x4dae26df20976138
PROOF_TIMEOUT_SECONDS = 115


def check_layout(image, source):
    result = verify_layout(image, {'publication': source})
    spans = result['spans']['publication']
    assert len(spans) == 15 and sum(span['words'] for span in spans) == 186
    assert len(result['branch_fixups']) == 30
    relocated = [change for span in spans for change in span['changes']]
    assert len(relocated) == 2
    page, add = relocated
    assert (page['address'], page['mnemonic'], page['operands']) == (
        '0xfffffe000a6a3cdc', 'adrp', 'x10, #0xfffffe0008488000')
    assert (add['address'], add['mnemonic'], add['operands']) == (
        '0xfffffe000a6a3ce0', 'add', 'x10, x10, #0x9a0')
    assert 0xfffffe0008488000 + 0x9a0 == POOL
    direct = {}
    for site, branch in source['direct_branches'].items():
        pc = shifted(site)
        target = image.branch(pc, branch['mnemonic'])
        assert target == shifted(branch['target'])
        direct[hex(pc)] = dict(mnemonic=branch['mnemonic'], target=hex(target))
    assert len(direct) == 2
    result['direct_branches'] = direct
    return result


def check_bank(image, source):
    arrays, fixups = {}, {}
    for offset in (0x458, 0x638, 0x840):
        target, label, bias = POOL_ROOTS[offset]
        fixups[label] = verify_fixup(image, POOL + offset, target)
        if label in source['banks']:
            raw = image.read(target + bias, 256)
            assert raw.hex() == source['banks'][label]['bytes_hex']
            arrays[label] = raw
    left, right = arrays['FL'], arrays['FR']
    rule = source['bank_rule']
    key, offset = (int(rule[name], 16) for name in ('key', 'additive'))
    constant, = {i ^ right[left[i] ^ key] for i in range(256)}
    index = constant + offset
    assert constant == int(rule['constant'], 16) == 0xdf
    assert index == int(rule['index'], 16) == 0x4c
    assert int(rule['bias'], 16) == (1 << 64) - 4
    fixup = verify_fixup(image, POOL + 8 * index, DESCRIPTOR + 4)
    descriptor = read_descriptor(image, DESCRIPTOR, 'site.FPTTLVNode', '1121', 32)
    assert image.read(NODE_TYPE, 64) == image.read(FREE_TYPE, 64) == image.read(DESCRIPTOR, 64)
    return dict(input_cases=256, key=hex(key), constant=hex(constant), index=hex(index),
                root_fixups=fixups, selected_fixup=fixup, descriptor=descriptor,
                alloc_and_free_descriptor_images_match=True)


class PublicationReplay(DataReplay):
    publication_stores = None

    def store(self, address, width, value):
        super().store(address, width, value)
        if self.publication_stores is not None:
            self.publication_stores.append((hex(self.pc), hex(address), width,
                                            hex(value % (1 << (8 * width)))))

    def check_cells(self, historical, roots):
        relocated = {
            ('F', 0xa30): CONTROLLERS[0], ('F', 0xa38): CONTROLLERS[1],
            ('F', 0xa48): 0xfffffe0007954090, ('F', 0xa00): 0xfffffe0007939f80,
            ('F', 0xa20): 0xfffffe00079434b0, ('C', 0x260): shifted('0xfffffe000a661ba0'),
        }
        cells = {}
        for cell in historical['source_defined_cells']:
            root, offset, width = cell['root'], int(cell['offset'], 16), cell['size_bytes']
            old = int.from_bytes(bytes.fromhex(cell['reconstructed_bytes_hex']), 'little')
            value = self.value(roots[root] + offset, width)
            assert value == relocated.get((root, offset), old)
            cells[f'{root}+{offset:#x}'] = dict(value=hex(value), size_bytes=width)
        assert len(cells) == 16
        return cells

    def publication(self, historical, source):
        S, C, H, J, Z = (int(cut['result'], 16) for cut in self.cuts)
        roots = dict(F=self.sp, S=S, C=C, H=H, J=J)
        assert H == int(historical['original_container'], 16)
        cells = self.check_cells(historical, roots)
        assert (self.value(self.sp + 0xa08, 8), self.value(self.sp + 0xa28, 8)) == (S, C)
        length = self.input['wire_length32']
        cursor = historical['cursor64']
        assert cursor == length + 10 == self.extent == historical['outer_size32']
        tag = self.input['wire_tag32'] ^ SUCCESS
        code = {shifted(word['pc']) for span in source['spans'] for word in span['instructions']}
        # The checked lookup request projects X0 into X20, and adds W20
        # to 0x7795e3ce-5 to produce return index 0x6c. X21 is its table base.
        # These are the only incoming GPR values consumed by this suffix.
        self.g = [None] * 31
        self.g[0], self.g[20], self.g[21] = MASK_WORD, CONTROL, TABLE
        self.nzcv = None
        self.pc = ENTRY
        first_edge = len(self.edges)
        first_read = len(self.private_reads)
        self.publication_stores = []
        visits = 0
        while self.pc not in (EXHAUSTED, NEXT_HEADER):
            assert visits < len(code) and self.pc in code, hex(self.pc)
            self.ix += 1
            word, = self.cs.disasm(self.image.read(self.pc, 4), self.pc)
            target = self.step(word)
            if target == shifted('0xfffffe000a662ab4'):
                assert (self.g[2], self.g[4], self.g[7], self.g[22]) == (C, S, TABLE, H)
                assert (self.g[9], self.g[10], self.g[8]) == (tag, C+0x50, 0x6c)
            if target == shifted('0xfffffe000a662b64'):
                assert (self.g[22], self.g[23], self.value(C + 0x50, 8)) == (DESCRIPTOR, MISS, 0)
            self.pc = target
            visits += 1
        assert self.pc == EXHAUSTED and self.g[23] == SUCCESS
        assert self.value(H, 8) == self.value(H + 8, 8) == self.value(C + 0x58, 8) == J
        assert self.value(J, 16) == self.value(C + 0x50, 8) == 0
        assert self.value(J + 0x10, 4) == self.value(S + 0xa10, 8) == cursor
        assert self.value(J + 0x18, 8) == Z
        F = roots['F']
        loads = (
            (F+0xa28, 8), (C+0x20, 8), (F+0xa08, 8), (S+0x1d0, 4), (F+0x348, 8),
            (F+0xa30, 8), (F+0xa48, 8), (F+0xa00, 8), (H, 8), (C+0x758, 8),
            (C+0xc8, 8), (F+0xa38, 8), (F+0xa20, 8), (C+0x20, 8), (H+8, 8),
            (C+0x58, 8), (C+0x260, 8), (F+0xa00, 8), (S+0xa10, 8), (S+0xb5c, 4),
        )
        assert self.private_reads[first_read:] == [(address, width, False) for address, width in loads]
        expected = (
            ('0xfffffe000a655ccc', C+0x50, 8, 0), ('0xfffffe000a662ac8', C+0xc8, 8, shifted('0xfffffe000a662b64')),
            ('0xfffffe000a662acc', S, 4, tag), ('0xfffffe000a662ad0', C+0x758, 8, C+0x50),
            ('0xfffffe000a662c18', C+0x2b0, 8, 0), ('0xfffffe000a662c4c', C+0x50, 8, 0),
            ('0xfffffe000a662bc8', H, 8, J), ('0xfffffe000a662bc8', H+8, 8, J),
        )
        assert self.publication_stores == [(hex(shifted(pc)), hex(address), width, hex(value))
                                           for pc, address, width, value in expected]
        assert all(address + width <= Z or Z + cursor <= address for _, address, width, _ in expected)
        edges = self.edges[first_edge:]
        transfers = (
            ('0xfffffe000a662ab4', 0x0ee9), ('0xfffffe000a662be0', 0x7250),
            ('0xfffffe000a662c00', 0xed3d), ('0xfffffe000a662c44', 0xb5a8),
            ('0xfffffe000a662b00', 0x7250), ('0xfffffe000a662b64', 0x8d28),
            ('0xfffffe000a662bc4', 0xd5cf), ('0xfffffe000a664218', 0x7250),
            ('0xfffffe000a661ba0', 0xf596), ('0xfffffe000a660af4', 0xc9dc),
            ('0xfffffe000a660b2c', 0x2f10),
        )
        assert [(edge['kind'], edge['target'], edge['modifier64']) for edge in edges] == [
            ('braa', hex(shifted(target)), hex(modifier)) for target, modifier in transfers
        ]
        return dict(case_index=historical['predecessor_case_index'], profile=self.input['profile'],
                    cursor_bytes=cursor, projection_cells=cells, instruction_visits=visits,
                    published_head=hex(J), published_tail=hex(J), final_target=hex(self.pc),
                    private_loads=[dict(address=hex(address), size_bytes=width) for address, width in loads],
                    stores=self.publication_stores, logical_edges=edges)


def audit(path):
    build = command('sw_vers', '-buildVersion').strip().decode()
    assert build == '26C5035r' and sysctl('kern.uuid').lower() == IDENTITIES[1][1]
    image = Collection(path, IDENTITIES[1])
    checks = receipt('userclient_early_publication_checks', CHECKS)
    prior = receipt('userclient_early_publication_audit', AUDIT)
    payload = receipt('userclient_early_payload_checks', WRITER_CHECKS['early_payload'])
    assert checks['kernel_collection_sha256'] == prior['kernel_collection_sha256'] == IDENTITIES[0][0]
    assert prior['checks_sha256'] == CHECKS and prior['conditional_first_record_publication_established']
    assert checks['header_source'] == payload['header_source'] and checks['payload_source'] == payload['source']
    layout = check_layout(image, checks['source'])
    bank = check_bank(image, checks['source'])
    verified_prefix = receipt('live_fairplay_early_writer_audit', WRITER_AUDIT)
    assert verified_prefix['identity'] == list(IDENTITIES[1])
    prefixes = {row['case_index']: row['prefix'] for row in verified_prefix['cases']}
    data = receipt('userclient_early_data_checks', DATA_CHECKS['early_data'])
    cases = []
    for state in checks['predecessor_states']:
        index = state['predecessor_case_index']
        if index not in prefixes:
            assert state['input']['declared_size64'] > 0xffffffff
            continue
        replay = PublicationReplay(image, data['cases'][index])
        assert replay.input == state['input']
        assert replay.replay() == prefixes[index]
        cases.append(replay.publication(state, checks['source']))
    assert len(cases) == len(prefixes) == 24
    assert len(prior['source_proofs']) == 18
    with ThreadPoolExecutor(max_workers=4) as workers:
        proofs = list(workers.map(partial(replay_proof, timeout_seconds=PROOF_TIMEOUT_SECONDS),
                                  prior['source_proofs']))
    return dict(build=build, identity=IDENTITIES[1], checks_sha256=CHECKS, audit_sha256=AUDIT,
                writer_audit_sha256=WRITER_AUDIT, layout=layout, bank=bank,
                cases=cases, source_proofs=proofs, proof_timeout_seconds=PROOF_TIMEOUT_SECONDS,
                serialization_frontier=hex(ENTRY),
                continuous_writer_execution=False, native_transaction_observed=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    print(json.dumps(audit(parser.parse_args().collection), indent=2))
