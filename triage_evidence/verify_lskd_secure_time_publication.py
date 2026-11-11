#!/usr/bin/env python3
"""Verify SecureTime source certificates, publication delta and path hygiene."""
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
PREVIOUS = '579ee04d0525c9eec91bca1a25fd8c40bf017bce'
MANIFEST = 'triage_evidence/interface_manifest.json'
CHANGED = {
    'lskd_element_population_report.md', 'lskd_lock_origin_report.md',
    'lskd_continuations_report.md', 'lskd_start_lock_flow_report.md',
    'foundational_triage_report.md', 'interface_abi_report.md',
    'interface_investigation_status.md', 'triage_evidence/validate_rpc502_sidecar_delivery.py',
}
ADDED = {
    'lskd_secure_time_report.md', 'triage_evidence/lskd_secure_time_checks.json',
    'triage_evidence/recover_lskd_secure_time.py',
    'triage_evidence/verify_lskd_secure_time_publication.py',
}
ARCHIVES = {MANIFEST, 'triage_evidence/lskd_secure_time_checks.json'}
OWNED = ((CHANGED | ADDED) - ARCHIVES) | {name + '.zst' for name in ARCHIVES}


def recheck(proofs):
    for proof in proofs.values():
        assert proof['result'] == 'unsat'
        solver = z3.Solver()
        solver.set(timeout=10000)
        solver.from_string(proof['query'])
        assert solver.check() == z3.unsat
    return len(proofs)


def main():
    previous_raw = zstd.decompress(subprocess.check_output(
        ['git', 'show', PREVIOUS + ':' + MANIFEST + '.zst'], cwd=BASE))
    assert sha256(previous_raw).hexdigest() == 'fa83028fa1b8f00987523a8c82f2b5090eeecd3c6f86c972c3f3df47836472d5'
    previous = json.loads(previous_raw)
    current = json.loads(read(BASE / MANIFEST))
    old = {row['path']: row for row in previous['files']}
    new = {row['path']: row for row in current['files']}
    assert len(old) == len(previous['files']) == 8034
    assert len(new) == len(current['files']) == 8038
    assert not old.keys() - new.keys() and new.keys() - old.keys() == ADDED
    assert {name for name in old if old[name] != new[name]} == CHANGED
    assert current['inputs_preserved'] == previous['inputs_preserved']
    for row in current['inputs_preserved']:
        path = BASE / row['path']
        assert sha(path) == row['sha256'] and size(path) == row['size_bytes']
    for name in CHANGED | ADDED:
        path = BASE / name
        assert sha(path) == new[name]['sha256'] and size(path) == new[name]['size_bytes']
    report = read(BASE / 'lskd_secure_time_report.md')
    assert all(f'| ST{j} |' in report for j in range(1, 9))
    assert all(f'**QG{j}**' in report for j in range(1, 8))
    evidence = json.loads(read(ROOT / 'lskd_secure_time_checks.json'))
    assert evidence['generator_sha256'] == sha(ROOT / 'recover_lskd_secure_time.py')
    for name, digest in evidence['dependencies'].items():
        assert sha(ROOT / name) == digest
    for source in evidence['supplied_reference_excerpts']:
        path = BASE / source['path']
        assert sha(path) == source['sha256']
        lines = path.read_text().splitlines(keepends=True)
        assert ''.join(lines[source['first_line'] - 1:source['last_line']]) == source['text']
    assert len(evidence['proofs']) == 19
    checked = recheck(evidence['proofs'])
    constructor = json.loads(read(ROOT / 'lskd_lock_origin_checks.json'))
    assert len(constructor['proofs']) == 18
    checked += recheck(constructor['proofs'])
    assert constructor['selected_contract']['decoded_child_phase32'] == '0x90d'
    assert constructor['selected_contract']['success_status32'] == '0x0'
    assert constructor['selected_contract']['null_allocation_status32'] == '0xffff5964'
    fn = evidence['completion_compiler_function']
    assert int(fn['end'], 16) - int(fn['start'], 16) == 8
    assert fn['bytes_hex'] == '5f2403d5c0035fd6'
    assert sha256(bytes.fromhex(fn['bytes_hex'])).hexdigest() == fn['sha256']
    assert [i['mnemonic'] for i in fn['instructions']] == ['bti', 'ret']
    typed = evidence['typed_view']
    assert typed['site_name'] == 'site.LSKDSecureTime'
    assert typed['declared_size_B'] == 64 and typed['flags32'] == '0x64'
    assert not typed['runtime_metadata_initialization_established']
    assert len(evidence['retained_frames']) == 13
    assert all(len(frame['fields']) == 18 and not frame['new_target_execution']
               for frame in evidence['retained_frames'])
    assert len(evidence['banks']) == 7 and len(evidence['control_slots']) == 6
    assert all(rule['inputs_checked'] == 256 for rule in evidence['banks'].values())
    contract = evidence['selected_contract']
    assert contract['embedded_RW_offset_B'] + 8 <= contract['declared_size_B'] == 64
    assert contract['allocation_null_returns_raw_success']
    assert contract['constructor_nonzero_returns_raw_success']
    assert not contract['full_initialization_implied_by_raw_success']
    assert contract['selected_seed_qword_offset_B'] == 152
    assert contract['selected_seed_word_indices'] == [38, 39]
    assert not set(range(0, 64, 4)) & set(contract['selected_seed_word_indices'])
    assert contract['random_request_B'] == contract['clock_requested_output_B'] == 4
    assert contract['clock_new_pointer64'] == contract['clock_new_length64'] == 0
    assert contract['clock_name'] == 'kern.monotonicclock'
    assert contract['next_source_target'] == '0xfffffe000a51c0e0'
    assert contract['completion_noop_semantics_known']
    assert not contract['completion_record_consumed_by_selected_callee']
    assert not contract['embedded_lock_retirement_known']
    assert not contract['native_initialization_observed']
    assert not evidence['new_target_execution'] and not evidence['native_epoch_matched']
    assert not evidence['new_IDA_access'] and not evidence['full_goal_complete']
    counts = evidence['verified_counts']
    assert counts['instructions'] == 348 and counts['source_lifted_instances'] == 159
    assert counts['operand_anchors'] == 28
    assert current['validation']['lskd_secure_time_increment_checks'] == counts
    assert current['validation']['lskd_secure_time_static_scope'] == evidence['scope']
    assert current['validation']['unavailable_external_primary_references'] == previous['validation']['unavailable_external_primary_references']
    assert current['goal_status'] == 'active'
    for name in ARCHIVES:
        assert not (BASE / name).exists()
    assert len(OWNED) == 13
    for name in OWNED:
        path_hygiene((BASE / name).read_bytes())
    print(json.dumps({'unchanged_manifest_entries': len(old) - len(CHANGED),
        'owned_physical_files': len(OWNED), 'original_inputs_preserved': 3,
        'serialized_queries_rechecked': checked, 'new_source_queries': 19,
        'source_instructions': 348, 'completion_noop_B': 8,
        'analyst_path_literals_absent': True, 'all_checks_pass': True}))


if __name__ == '__main__':
    main()
