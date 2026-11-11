#!/usr/bin/env python3
"""Verify element-population publication, original inputs and serialized queries."""
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
PREVIOUS = 'ba1b7d4106472c13cdd621a40f24e15acd90d18c'
MANIFEST = 'triage_evidence/interface_manifest.json'
CHANGED = {
    'lskd_vector_origin_report.md', 'lskd_objects_report.md', 'lskd_continuations_report.md',
    'lskd_start_lock_flow_report.md', 'foundational_triage_report.md', 'interface_abi_report.md',
    'interface_investigation_status.md', 'triage_evidence/validate_rpc502_sidecar_delivery.py',
}
ADDED = {
    'lskd_element_population_report.md', 'triage_evidence/lskd_element_population_checks.json',
    'triage_evidence/recover_lskd_element_population.py',
    'triage_evidence/verify_lskd_element_population_publication.py',
}
ARCHIVES = {MANIFEST, 'triage_evidence/lskd_element_population_checks.json'}
OWNED = ((CHANGED | ADDED) - ARCHIVES) | {name + '.zst' for name in ARCHIVES}


def main():
    previous_raw = zstd.decompress(subprocess.check_output(
        ['git', 'show', PREVIOUS + ':' + MANIFEST + '.zst'], cwd=BASE))
    assert sha256(previous_raw).hexdigest() == 'dcba265d27bb72e25ffa282d5e58a4997b4b3a79a27fb949acb80f0de2e3ad5d'
    previous = json.loads(previous_raw)
    current = json.loads(read(BASE / MANIFEST))
    old = {row['path']: row for row in previous['files']}
    new = {row['path']: row for row in current['files']}
    assert len(old) == len(previous['files']) == 8030
    assert len(new) == len(current['files']) == 8034
    assert not old.keys() - new.keys() and new.keys() - old.keys() == ADDED
    assert {name for name in old if old[name] != new[name]} == CHANGED
    assert current['inputs_preserved'] == previous['inputs_preserved']
    for row in current['inputs_preserved']:
        path = BASE / row['path']
        assert sha(path) == row['sha256'] and size(path) == row['size_bytes']
    for name in CHANGED | ADDED:
        path = BASE / name
        assert sha(path) == new[name]['sha256'] and size(path) == new[name]['size_bytes']
    report = read(BASE / 'lskd_element_population_report.md')
    assert all(f'| EP{j} |' in report for j in range(1, 10))
    assert all(f'**QG{j}**' in report for j in range(1, 8))
    evidence = json.loads(read(ROOT / 'lskd_element_population_checks.json'))
    assert evidence['generator_sha256'] == sha(ROOT / 'recover_lskd_element_population.py')
    for name, digest in evidence['dependencies'].items():
        assert sha(ROOT / name) == digest
    for source in evidence['supplied_reference_excerpts']:
        path = BASE / source['path']
        assert sha(path) == source['sha256']
        lines = path.read_text().splitlines(keepends=True)
        assert ''.join(lines[source['first_line'] - 1:source['last_line']]) == source['text']
    assert len(evidence['proofs']) == 22
    for proof in evidence['proofs'].values():
        assert proof['result'] == 'unsat'
        solver = z3.Solver()
        solver.set(timeout=10000)
        solver.from_string(proof['query'])
        assert solver.check() == z3.unsat
    assert len(evidence['retained_frames']) == 13
    assert all(len(frame['fields']) == 11 and not frame['new_target_execution']
               for frame in evidence['retained_frames'])
    contract = evidence['selected_contract']
    assert contract['SIMD_iterations'] * contract['SIMD_store_B_per_iteration'] == contract['element_extent_B'] == 512
    assert contract['shuffle_iterations'] == contract['shuffle_qword_count'] - 1 == 63
    assert contract['outer_iterations'] == 1024
    assert contract['conditional_element_declared_total_B'] == 1024 * 512 == 524288
    assert contract['conditional_combined_declared_B'] == contract['vector_declared_B'] + 524288 == 532480
    assert not contract['pointer_codec_fully_proved'] and not contract['completion_helper_semantics_known']
    assert not contract['native_population_observed']
    audit = evidence['source_register_write_audit']
    assert not set(audit['written']) & set(audit['preserved'])
    assert audit['prefix_counter_writes'] == ['0xfffffe000a51b9dc']
    assert audit['footer_phase_writes'] == ['0xfffffe000a51bafc']
    assert len(evidence['SIMD_source_reads']) == 6
    assert sum('bytes_hex' in row for row in evidence['SIMD_source_reads']) == 5
    assert evidence['verified_counts']['SIMD_body_instructions'] == 42
    assert not evidence['new_target_execution'] and not evidence['native_epoch_matched']
    assert not evidence['new_IDA_access'] and not evidence['full_goal_complete']
    assert current['validation']['lskd_element_population_increment_checks'] == evidence['verified_counts']
    assert current['validation']['lskd_element_population_static_scope'] == evidence['scope']
    assert current['validation']['unavailable_external_primary_references'] == previous['validation']['unavailable_external_primary_references']
    assert current['goal_status'] == 'active'
    for name in ARCHIVES:
        assert not (BASE / name).exists()
    assert len(OWNED) == 13
    for name in OWNED:
        path_hygiene((BASE / name).read_bytes())
    print(json.dumps({'unchanged_manifest_entries': len(old) - len(CHANGED),
                      'owned_physical_files': len(OWNED), 'original_inputs_preserved': 3,
                      'serialized_queries_rechecked': len(evidence['proofs']),
                      'source_SIMD_body_instructions': 42, 'analyst_path_literals_absent': True,
                      'all_checks_pass': True}))


if __name__ == '__main__':
    main()
