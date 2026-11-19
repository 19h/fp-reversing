#!/usr/bin/env python3
"""Bind archived early serialization obligations to the installed collection."""

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path

from audit_daemon_iokit_native_registry import command, sysctl
from audit_live_fairplay_context_lifecycle import TABLE, replay_proof
from audit_live_fairplay_early_data import CHECKS as DATA_CHECKS, DataReplay, WRITER_CUT
from audit_live_fairplay_entry import shifted, verify_layout
from audit_live_fairplay_uidlist import receipt
from audit_live_kext_selector26 import Collection, IDENTITIES

CHECKS = {
    'early_writer': '759215006af5fe74e734b270d0e64e6b80e5973963a33074a2dab93872cf8ddf',
    'early_payload': '6ed7378f51320046bf9d7ffea2470759ddbaf0b08dd290571147a7ba7fe504d0',
}
AUDITS = {
    'early_writer': '07d13d8e0b1a89a40028bbff209460a49c33e8fb2a7eb5973244446be95f76d8',
    'early_payload': '422eb0a76e182e8870f0870adfcea3de534268d178b9a77a0c383c29625d27d4',
}
HANDOFF = 0xfffffe000a6a2a78
PROJECTED = (0, 1, 3, 11, 14, 16, 17, 22, 23, 24, 25)


class WriterHandoffReplay(DataReplay):
    def step(self, instruction):
        if self.pc == HANDOFF:
            assert not hasattr(self, 'handoff')
            self.handoff = self.g.copy(), self.sp, self.nzcv
        return super().step(instruction)


def check_cases(image, writer, payload):
    data = receipt('userclient_early_data_checks', DATA_CHECKS['early_data'])
    assert data['kernel_collection_sha256'] == IDENTITIES[0][0]
    results = []
    for header, body in zip(writer['predecessor_handoffs'], payload['predecessor_states'], strict=True):
        index = header['predecessor_case_index']
        assert index == body['predecessor_case_index']
        row = data['cases'][index]
        assert row['input'] == header['input'] == body['input']
        assert row['input']['data_result_fixture']
        if row['input']['declared_size64'] > 0xffffffff:
            continue
        replay = WriterHandoffReplay(image, row)
        result = replay.replay()
        assert replay.pc == WRITER_CUT == shifted(header['stopped_boundary']['pc'])
        assert HANDOFF == shifted(header['handoff_PC'])
        assert header['handoff_state'] == body['handoff_state']
        assert replay.edges[-1]['pc'] == hex(HANDOFF)
        registers, frame, flags = replay.handoff
        old = header['handoff_state']
        assert frame == int(header['frame_base_SP'], 16) == int(body['frame_base_SP'], 16)
        assert flags == int(old['NZCV'], 16)
        projection = {}
        for reg in PROJECTED:
            assert registers[reg] == int(old['registers31'][reg], 16), (index, reg)
            projection[f'X{reg}'] = hex(registers[reg])
        assert registers[21] == TABLE
        roots = dict(F=frame, S=registers[3], C=registers[11])
        for cell in header['writer_input_cells']:
            address = roots[cell['root']] + int(cell['offset'], 16)
            for j, (known, value) in enumerate(zip(bytes.fromhex(cell['known_mask_hex']),
                                                   bytes.fromhex(cell['bytes_hex']), strict=True)):
                if known:
                    assert replay.value(address + j, 1) == value
                else:
                    assert address + j not in replay.state
        cells = {}
        for cell in body['source_defined_cells']:
            label = cell['root'] + '+' + cell['offset']
            address = roots[cell['root']] + int(cell['offset'], 16)
            width = cell['size_bytes']
            assert address == int(cell['last_exact_store']['address'], 16)
            assert all(address + j in replay.state for j in range(width))
            previous = int.from_bytes(bytes.fromhex(cell['reconstructed_bytes_hex']), 'little')
            value = replay.value(address, width)
            if label == 'F+0xa60':
                assert previous == 0xfffffe0008472f20 and value == TABLE
            else:
                assert value == previous
            cells[label] = dict(width_bytes=width, value=hex(value))
        assert len(cells) == 7 and len(projection) == 11
        results.append(dict(case_index=index, profile=row['input']['profile'],
                            projection=projection, payload_cells=cells, prefix=result))
    assert len(results) == 24
    return results


def audit(path):
    build = command('sw_vers', '-buildVersion').strip().decode()
    assert build == '26C5035r' and sysctl('kern.uuid').lower() == IDENTITIES[1][1]
    image = Collection(path, IDENTITIES[1])
    checks = {name: receipt(f'userclient_{name}_checks', digest) for name, digest in CHECKS.items()}
    writer, payload = checks['early_writer'], checks['early_payload']
    assert all(row['kernel_collection_sha256'] == IDENTITIES[0][0] for row in checks.values())
    assert payload['header_source'] == writer['source']
    layout = verify_layout(image, {name: row['source'] for name, row in checks.items()})
    assert all(not span['changes'] for spans in layout['spans'].values() for span in spans)
    word_counts = {name: sum(span['words'] for span in spans) for name, spans in layout['spans'].items()}
    assert word_counts == dict(early_writer=227, early_payload=352)
    direct = {}
    for site, branch in payload['source']['direct_branches'].items():
        pc = shifted(site)
        target = image.branch(pc, branch['mnemonic'])
        assert target == shifted(branch['target'])
        direct[hex(pc)] = dict(mnemonic=branch['mnemonic'], target=hex(target))
    assert len(direct) == 3
    cases = check_cases(image, writer, payload)
    audits = {name: receipt(f'userclient_{name}_audit', digest) for name, digest in AUDITS.items()}
    assert all(audits[name]['checks_sha256'] == CHECKS[name] for name in CHECKS)
    assert [len(audits[name]['source_proofs']) for name in CHECKS] == [14, 15]
    with ThreadPoolExecutor(max_workers=4) as workers:
        proofs = list(workers.map(replay_proof, (proof for name in CHECKS
                                                 for proof in audits[name]['source_proofs'])))
    return dict(build=build, identity=IDENTITIES[1], historical_checks=CHECKS,
                historical_audits=AUDITS, layout=layout, word_counts=word_counts,
                direct_branches=direct, profiles=dict(Counter(row['profile'] for row in cases)),
                cases=cases, source_proofs=proofs, installed_writer_executed=False,
                missing_cells_bound_to_concrete_values=0, native_transaction_observed=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    print(json.dumps(audit(parser.parse_args().collection), indent=2))
