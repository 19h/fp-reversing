#!/usr/bin/env python3
"""Recheck the RPC 502 filename lineage and archived worker resource journals."""

import argparse
import base64
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import zlib

from audit_live_fairplay_rpc_abi import Daemon, PINNED_DAEMON_SHA
from audit_live_fairplay_cf_receive import assert_instructions
from rpc502_startup_tools import journals, unpack

ROOT = Path(__file__).resolve().parent
PAGE = 0x70001000
PAGE_BYTES = 4096
OPEN = 0x100d94494
STATUS = 0x100023ad4
LINEAGE = (
    (0x1000238e8, 'stp', 'x1, x3, [sp, #0x30]'),
    (0x1007fc58c, 'ldp', 'x8, x9, [x19, #8]'),
    (0x1007fc594, 'str', 'x8, [sp, #0x998]'),
    (0x1004b9ad4, 'ldr', 'x14, [sp, #0x998]'),
    (0x1004b9ad8, 'str', 'x14, [sp, #0x5650]'),
    (0x1005c6780, 'ldr', 'x13, [sp, #0x5650]'),
    (0x1005c6784, 'ldrb', 'w15, [x13, x9]'),
    (0x10083ec3c, 'ldrb', 'w17, [x24, w6, uxtw]'),
    (0x10083ec44, 'strb', 'w17, [x20, x10]'),
    (0x100d94494, 'blraa', 'x8, x17'),
    (0x100023ad4, 'eor', 'w0, w8, w9'),
)
RELEASE = {'_free', '_munmap', '_vm_deallocate', '_mig_deallocate', '_mach_vm_deallocate', '_mach_msg_destroy'}


def source_artifact(name):
    raw = subprocess.check_output(['zstd', '-qdc', str(ROOT / (name + '.json.zst'))])
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


def restore(row):
    encoded = row['payload_zlib_base64']
    count = encoded.count('/___/')
    if count:
        # Case-insensitive path redaction touched three opaque Base64 symbols.
        # This keeps the repair limited to the identified checksum-valid record.
        assert count == 1 and row['case']['label'] == 'C128_selector1'
        encoded = encoded.replace('/___/', bytes.fromhex('2f494e542f').decode('ascii'))
    assert len(encoded) == len(row['payload_zlib_base64'])
    return unpack(dict(payload_zlib_base64=encoded)), 3 * count


def early_reads(trace):
    expected = {
        0x100422edc: range(0, 1), 0x10008a958: range(1, 23),
        0x1005c6784: range(6, 23), 0x10074cbf4: range(6, 22),
        0x10083ec3c: range(6, 23),
    }
    offsets = {pc: [] for pc in expected}
    for entry in trace['source_filename_reads']:
        assert entry['size'] == 1
        offsets[int(entry['pc'], 16)].append(int(entry['address'], 16) - PAGE)
    assert offsets == {pc: list(run) for pc, run in expected.items()}
    assert bytes.fromhex(trace['original_filename_after_hex']).index(0) == 22
    return offsets


def audit_case(old, reference, pool, sites, ledger):
    assert old['case'] == reference['case']
    result, repairs = restore(old)
    fresh, fresh_repairs = restore(reference)
    assert result == fresh
    del fresh
    assert result['source_sha256'] == PINNED_DAEMON_SHA
    assert result['startup_returned'] and result['stop_reason'] == 'returned_to_fixture'
    assert result['records'][-1]['result'] == ledger['worker_status_u32'] == '0xffff5bd9'
    assert not result['native_target_executed'] and not result['target_host_ipc_files_or_system_calls_executed']
    assert (int(result['stack_base'], 16) + 0x1000) == PAGE
    release_events = []
    visits = 0
    positions = {a: [] for a in sites}
    for chunk in journals(result):
        raw = zlib.decompress(base64.b64decode(chunk['source_visits_zlib_base64']))
        assert len(raw) == 8 * chunk['source_visit_count']
        digest = hashlib.sha256()
        for offset, (pc,) in enumerate(struct.iter_unpack('<Q', raw)):
            digest.update(pool[pc])
            if pc in positions:
                positions[pc].append(visits + offset)
        assert digest.hexdigest() == chunk['ordered_source_bytes_sha256']
        visits += chunk['source_visit_count']
        for event in chunk['records']:
            name = event.get('name', '')
            if name.split('/')[-1] in RELEASE:
                args = event.get('args_x0_x7') or event['args']
                site = hex(int(event['return_pc'], 16) - 4)
                release_events.append((name, site, args))
    assert visits == ledger['source_visits']
    assert release_events == [(e['name'], e['site'], e['args']) for e in ledger['events']
                              if e['name'].split('/')[-1] in RELEASE]
    assert Counter(e[0] for e in release_events) == {'libSystem/_free': 6, 'libSystem/_munmap': 1}
    for name, _, args in release_events:
        va = int(args[0], 16)
        length = int(args[1], 16) if name.endswith('/_munmap') else 1
        assert va + length <= PAGE or va >= PAGE + PAGE_BYTES
    opens = []
    for event in result['source_open_observations']:
        raw = bytes.fromhex(event['path_hex'])
        suffix = next(s for s in ('.sinf', '.v5.supf') if raw.endswith(s.encode()))
        assert int(event['path_pointer'], 16) >= PAGE + PAGE_BYTES and event['flags_u32'] == 0
        opens.append(dict(pc=event['site'], address=event['path_pointer'], extent_bytes=len(raw),
                          suffix=suffix, sha256=hashlib.sha256(raw).hexdigest()))
    assert [(row['suffix'], row['extent_bytes']) for row in opens] == [('.sinf', 35), ('.v5.supf', 38)]
    assert opens[0]['address'] == opens[1]['address'] == '0x700734c0'
    first, second = positions[OPEN]
    status, = positions[STATUS]
    assert first < second < status
    tail_visits = positions[0x10083ec3c]
    assert sum(index < first for index in tail_visits) == 17
    assert sum(first < index < second for index in tail_visits) == 17
    assert tail_visits[-1] < second
    for pc, count in ((0x100422edc, 1), (0x10008a958, 22), (0x1005c6784, 23), (0x10074cbf4, 22)):
        assert len(positions[pc]) == count and positions[pc][-1] < first
    pointer_chain = [0x1000238e8, 0x1007fc58c, 0x1007fc594, 0x1004b9ad4, 0x1004b9ad8]
    transfers = [positions[pc][0] for pc in pointer_chain]
    assert transfers == sorted(transfers) and transfers[-1] < positions[0x1005c6784][0]
    return dict(label=old['case']['label'], visits=visits, model_status=ledger['worker_status_u32'],
                first_and_second_open=opens, observed_release_arguments=release_events,
                selected_instruction_visits={hex(a): offsets for a, offsets in positions.items()},
                restored_base64_symbols=[repairs, fresh_repairs])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('daemon', type=Path)
    args = parser.parse_args()
    daemon = Daemon(args.daemon)
    assert hashlib.sha256(daemon.data).hexdigest() == PINNED_DAEMON_SHA
    baseline, baseline_sha = source_artifact('rpc502_padding_profiles')
    reference, reference_sha = source_artifact('rpc502_padding_replays')
    trace, trace_sha = source_artifact('rpc502_sidecar_byte_trace')
    ledger, ledger_sha = source_artifact('rpc502_ownership_checks')
    assert {x['source_sha256'] for x in (baseline, reference, trace, ledger)} == {PINNED_DAEMON_SHA}
    assert baseline['original_instruction_pool'] == reference['original_instruction_pool']
    pool = {}
    for row in baseline['original_instruction_pool']:
        pc = int(row['ea'], 16)
        data = daemon.read(pc, 4)
        assert data.hex() == row['bytes']
        pool[pc] = struct.pack('<Q', pc) + data
    prefix_offsets = early_reads(trace)
    sites = set(prefix_offsets) | {pc for pc, _, _ in LINEAGE}
    assert len(baseline['cases']) == len(reference['cases']) == len(ledger['case_summaries']) == 2
    cases = [audit_case(a, b, pool, sites, l)
             for a, b, l in zip(baseline['cases'], reference['cases'], ledger['case_summaries'])]
    print(json.dumps(dict(
        daemon_sha256=PINNED_DAEMON_SHA, source_instructions=len(pool),
        dependency_sha256=dict(baseline=baseline_sha, reference=reference_sha,
                               early_trace=trace_sha, owner_ledger=ledger_sha),
        lineage=assert_instructions(daemon.read, LINEAGE),
        early_filename_read_offsets={hex(k): v for k, v in prefix_offsets.items()},
        cases=cases, fresh_worker_certified=False, native_transaction_observed=False,
    ), indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
