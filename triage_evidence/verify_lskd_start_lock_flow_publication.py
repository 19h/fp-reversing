#!/usr/bin/env python3
"""Verify the start-flow publication delta, original inputs and retained queries."""
from hashlib import sha256
import json
from pathlib import Path
import subprocess

from compression import zstd
import z3

from verify_daemon_reader_record_payloads_publication import read, sha, size
from verify_username_paths_history import inspect

ROOT = Path(__file__).resolve().parent
BASE = ROOT.parent
PREVIOUS = 'ffc1b3f5d50c1c3e0447c0e046396ad0df17aea0'
MANIFEST = 'triage_evidence/interface_manifest.json'
CHANGED = {
    'lskd_lock_origin_report.md', 'lskd_handlers_report.md', 'lskd_consumer_report.md',
    'lskd_continuations_report.md', 'foundational_triage_report.md', 'interface_abi_report.md',
    'interface_investigation_status.md', 'triage_evidence/validate_rpc502_sidecar_delivery.py',
}
ADDED = {
    'lskd_start_lock_flow_report.md', 'triage_evidence/lskd_start_lock_flow_checks.json',
    'triage_evidence/recover_lskd_start_lock_flow.py',
    'triage_evidence/verify_lskd_start_lock_flow_publication.py',
}
ARCHIVES = {MANIFEST, 'triage_evidence/lskd_start_lock_flow_checks.json'}
OWNED = ((CHANGED | ADDED) - ARCHIVES) | {name + '.zst' for name in ARCHIVES}


def main():
    previous_raw = zstd.decompress(subprocess.check_output(
        ['git', 'show', PREVIOUS + ':' + MANIFEST + '.zst'], cwd=BASE))
    assert sha256(previous_raw).hexdigest() == '648b9cb0452d38c0d9a045ee477621ce2812a52140d8e976cc5687ae73f0cd86'
    previous = json.loads(previous_raw)
    current = json.loads(read(BASE / MANIFEST))
    old = {row['path']: row for row in previous['files']}
    new = {row['path']: row for row in current['files']}
    assert len(old) == len(previous['files']) == 8022
    assert len(new) == len(current['files']) == 8026
    assert not old.keys() - new.keys() and new.keys() - old.keys() == ADDED
    assert {name for name in old if old[name] != new[name]} == CHANGED
    assert current['inputs_preserved'] == previous['inputs_preserved']
    for row in current['inputs_preserved']:
        path = BASE / row['path']
        assert sha(path) == row['sha256'] and size(path) == row['size_bytes']
    for name in CHANGED | ADDED:
        path = BASE / name
        assert sha(path) == new[name]['sha256'] and size(path) == new[name]['size_bytes']
    report = read(BASE / 'lskd_start_lock_flow_report.md')
    assert all(f'| SL{index} |' in report for index in range(1, 9))
    assert all(f'**QG{index}**' in report for index in range(1, 8))
    evidence = json.loads(read(ROOT / 'lskd_start_lock_flow_checks.json'))
    assert evidence['generator_sha256'] == sha(ROOT / 'recover_lskd_start_lock_flow.py')
    for name, digest in evidence['dependencies'].items():
        assert sha(ROOT / name) == digest
    for source in evidence['supplied_reference_excerpts']:
        path = BASE / source['path']
        assert sha(path) == source['sha256']
        lines = path.read_text().splitlines(keepends=True)
        assert ''.join(lines[source['first_line'] - 1:source['last_line']]) == source['text']
    assert len(evidence['proofs']) == 18
    for proof in evidence['proofs'].values():
        assert proof['result'] == 'unsat'
        solver = z3.Solver()
        solver.set(timeout=10000)
        solver.from_string(proof['query'])
        assert solver.check() == z3.unsat
    assert len(evidence['retained_start_frames']) == 13
    assert all(len(frame['frame_fields']) == 17 and not frame['new_target_execution']
               for frame in evidence['retained_start_frames'])
    seed = evidence['seed_region']
    assert seed['extent_B'] == 512 and seed['u32_words'] == 128
    assert seed['mix_written_word_indices'] == list(range(0, 64, 4))
    assert not seed['runtime_values_known'] and not evidence['new_target_execution']
    assert not evidence['native_epoch_matched'] and not evidence['new_IDA_access']
    assert current['validation']['lskd_start_lock_flow_increment_checks'] == evidence['verified_counts']
    assert current['validation']['lskd_start_lock_flow_static_scope'] == evidence['scope']
    assert current['goal_status'] == 'active' and not evidence['full_goal_complete']
    for name in ARCHIVES:
        assert not (BASE / name).exists()
    assert len(OWNED) == 13
    for name in OWNED:
        _, _, findings = inspect((BASE / name).read_bytes(), Path.home().name)
        assert not findings, name
    print(json.dumps({'unchanged_manifest_entries': len(old) - len(CHANGED),
                      'owned_physical_files': len(OWNED), 'original_inputs_preserved': 3,
                      'serialized_queries_rechecked': len(evidence['proofs']),
                      'username_path_scan_pass': True, 'all_checks_pass': True}))


if __name__ == '__main__':
    main()
