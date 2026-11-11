#!/usr/bin/env python3
"""Verify clock-completion certificates, original inputs, manifest and path scrub."""
from hashlib import sha256
import json
from pathlib import Path
import subprocess

from compression import zstd
import z3

from verify_daemon_reader_record_payloads_publication import read, sha, size
from verify_lskd_vector_origin_publication import path_hygiene

ROOT = Path(__file__).resolve().parent
BASE = ROOT.parent
PREVIOUS = '798022c6a06d339f3e15258092657eea82f2f4f5'
MANIFEST = 'triage_evidence/interface_manifest.json'
CHANGED = {
    'lskd_secure_time_report.md', 'lskd_lock_origin_report.md',
    'lskd_continuations_report.md', 'lskd_start_lock_flow_report.md',
    'foundational_triage_report.md', 'interface_abi_report.md',
    'interface_investigation_status.md', 'triage_evidence/validate_rpc502_sidecar_delivery.py',
}
ADDED = {
    'lskd_clock_completion_report.md', 'triage_evidence/lskd_clock_completion_checks.json',
    'triage_evidence/recover_lskd_clock_completion.py',
    'triage_evidence/verify_lskd_clock_completion_publication.py',
}
ARCHIVES = {MANIFEST, 'triage_evidence/lskd_clock_completion_checks.json'}
OWNED = ((CHANGED | ADDED) - ARCHIVES) | {name + '.zst' for name in ARCHIVES}


def check_query(query):
    solver = z3.Solver()
    solver.set(timeout=10000)
    solver.from_string(query)
    assert solver.check() == z3.unsat


def main():
    raw = zstd.decompress(subprocess.check_output(
        ['git', 'show', PREVIOUS + ':' + MANIFEST + '.zst'], cwd=BASE))
    assert sha256(raw).hexdigest() == 'c424a34113bea3d9c3f204ced26ab01c65d293b96affe396f29734903600c262'
    previous = json.loads(raw)
    current = json.loads(read(BASE / MANIFEST))
    old = {row['path']: row for row in previous['files']}
    new = {row['path']: row for row in current['files']}
    assert len(old) == len(previous['files']) == 8038
    assert len(new) == len(current['files']) == 8042
    assert not old.keys() - new.keys() and new.keys() - old.keys() == ADDED
    assert {name for name in old if old[name] != new[name]} == CHANGED
    assert current['inputs_preserved'] == previous['inputs_preserved']
    for row in current['inputs_preserved']:
        path = BASE / row['path']
        assert sha(path) == row['sha256'] and size(path) == row['size_bytes']
    for name in CHANGED | ADDED:
        path = BASE / name
        assert sha(path) == new[name]['sha256'] and size(path) == new[name]['size_bytes']
    report = read(BASE / 'lskd_clock_completion_report.md')
    assert all(f'| CC{j} |' in report for j in range(1, 9))
    assert all(f'**QG{j}**' in report for j in range(1, 8))
    evidence = json.loads(read(ROOT / 'lskd_clock_completion_checks.json'))
    assert evidence['generator_sha256'] == sha(ROOT / 'recover_lskd_clock_completion.py')
    for name, digest in evidence['dependencies'].items():
        assert sha(ROOT / name) == digest
    assert len(evidence['proofs']) == 17
    for proof in evidence['proofs'].values():
        assert proof['result'] == 'unsat'
        check_query(proof['query'])
    prior_proofs = json.loads(read(ROOT / 'lskd_continuations_proofs.json'))
    selected = [p for p in prior_proofs['proofs'] if p['name'] in {
        'unlock_record_selector', 'unlock_explicit_pointer_gate', 'unlock_cached_pointer_gate'}]
    assert len(selected) == 3
    for proof in selected:
        path = ROOT / proof['original_file']
        assert sha(path) == proof['original_sha256'] and proof['result'] == 'unsat'
        check_query(read(path))
    assert len(evidence['kext_spans']) == 2 and len(evidence['provider_functions']) == 5
    for row in evidence['kext_spans'] + evidence['provider_functions']:
        data = bytes.fromhex(row['bytes_hex'])
        assert len(data) == int(row['end'], 16) - int(row['start'], 16)
        assert len(row['instructions'])*4 == len(data)
        if 'sha256' in row:
            assert sha256(data).hexdigest() == row['sha256']
    assert len(evidence['OIDs']) == 3 and len(evidence['nominal_vtable_bindings']) == 2
    assert [oid['strings']['0x28'] for oid in evidence['OIDs']] == [
        'monotonicclock', 'monotonicclock_usecs', 'monotonicclock_rate_usecs']
    assert [oid['strings']['0x38'] for oid in evidence['OIDs']] == ['IU', 'Q', 'Q']
    assert all(not oid['native_registration_observed'] and oid['handler_exact_symbols']
               for oid in evidence['OIDs'])
    assert all(not slot['runtime_vptr_matched'] for slot in evidence['nominal_vtable_bindings'])
    audit = evidence['source_status_audit']
    assert not audit['incoming_sysctl_status_reads_before_overwrite']
    assert not audit['returned_length_reloads'] and not audit['conditional_branches_before_unlock']
    assert audit['X0_writes_before_unlock'] == ['0xfffffe000a51c170']
    covered = set()
    for row in evidence['new_object_stores']:
        covered.update(range(row['offset_B'], row['offset_B'] + row['width_B']))
    contract = evidence['selected_contract']
    assert len(covered) == contract['newly_written_object_B'] == 28
    covered.update(range(16))
    covered.update(range(24, 32))
    assert len(covered) == contract['combined_explicit_object_write_B'] == 52
    assert set(range(64)) - covered == set(range(36, 48))
    assert contract['object_declared_B'] == 64
    assert contract['seconds_output_B'] == 4 and contract['seconds_tick_bits_inclusive'] == [15, 46]
    assert contract['ticks_shift'] == 15 and contract['microseconds_factor'] == 1000000
    assert not contract['provider_native_availability_established']
    assert not contract['physical_tick_calibration_measured']
    assert not contract['native_lock_balance_established']
    assert not contract['SecureTime_object_free_recovered'] and not contract['daemon_reply_established']
    sdk = evidence['SDK_comparison']
    assert sdk['compiler_exit'] == 0 and sdk['assertions'] == 11
    assert sdk['probe_source'].count('static_assert(') == 11
    sdk_root = Path(subprocess.check_output(['xcrun', '--show-sdk-path'], text=True).strip())
    header = sdk['primary_header']
    assert header['path'].startswith('installed SDK:')
    assert sha(sdk_root / header['path'].split(':', 1)[1]) == header['sha256']
    assert not evidence['new_target_execution'] and not evidence['native_epoch_matched']
    assert not evidence['new_IDA_access'] and not evidence['full_goal_complete']
    counts = evidence['verified_counts']
    assert counts['kext_instructions'] == 87 and counts['provider_instructions'] == 841
    assert counts['source_lifted_instances'] == 79
    assert current['validation']['lskd_clock_completion_increment_checks'] == counts
    assert current['validation']['lskd_clock_completion_static_scope'] == evidence['scope']
    assert current['validation']['unavailable_external_primary_references'] == previous['validation']['unavailable_external_primary_references']
    assert current['goal_status'] == 'active'
    for name in ARCHIVES:
        assert not (BASE / name).exists()
    assert len(OWNED) == 13
    for name in OWNED:
        path_hygiene((BASE / name).read_bytes())
    print(json.dumps({'unchanged_manifest_entries': len(old) - len(CHANGED),
        'owned_physical_files': len(OWNED), 'original_inputs_preserved': 3,
        'new_queries_rechecked': 17, 'original_unlock_queries_rechecked': len(selected),
        'provider_instructions_retained': 841, 'SDK_assertions': 11,
        'analyst_path_literals_absent': True, 'all_checks_pass': True}))


if __name__ == '__main__':
    main()
