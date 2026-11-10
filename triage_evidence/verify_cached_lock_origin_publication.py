#!/usr/bin/env python3
"""Check the cached-lock report's owned delta against the previous publication."""
from hashlib import sha256
import json
from pathlib import Path
import subprocess

from compression import zstd
from verify_daemon_reader_record_payloads_publication import read, sha, size
from verify_username_paths_history import inspect

ROOT = Path(__file__).resolve().parent
BASE = ROOT.parent
PREVIOUS = 'cf3acd365d043007f2a87a8be043b1e2c67ace3e'
MANIFEST = 'triage_evidence/interface_manifest.json'
CHANGED = {
    'aes_cleanup_epoch_report.md', 'foundational_triage_report.md',
    'interface_investigation_status.md', 'iolib_group_report.md',
    'rw_lifecycle_report.md', 'sample_lock_report.md',
    'triage_evidence/validate_rpc502_sidecar_delivery.py',
}
ADDED = {
    'cached_lock_origin_report.md', 'triage_evidence/cached_lock_origin_checks.json',
    'triage_evidence/recover_cached_lock_origin.py',
    'triage_evidence/verify_cached_lock_origin_publication.py',
}


def main():
    previous_raw = zstd.decompress(subprocess.check_output(
        ['git', 'show', PREVIOUS + ':' + MANIFEST + '.zst'], cwd=BASE))
    assert sha256(previous_raw).hexdigest() == 'e1633a3cceaad3dc200f973daf16adca7cb3020bb22ba290fc547b998957a479'
    previous = json.loads(previous_raw)
    current = json.loads(read(BASE / MANIFEST))
    old = {row['path']: row for row in previous['files']}
    new = {row['path']: row for row in current['files']}
    assert len(old) == len(previous['files']) == 8014
    assert len(new) == len(current['files']) == 8018
    assert not old.keys() - new.keys() and new.keys() - old.keys() == ADDED
    assert {name for name in old if old[name] != new[name]} == CHANGED
    assert current['inputs_preserved'] == previous['inputs_preserved']
    for row in current['inputs_preserved']:
        path = BASE / row['path']
        assert sha(path) == row['sha256'] and size(path) == row['size_bytes']
    for name in CHANGED | ADDED:
        path = BASE / name
        assert sha(path) == new[name]['sha256'] and size(path) == new[name]['size_bytes']
    report = read(BASE / 'cached_lock_origin_report.md')
    assert all(f'| CL{index} |' in report for index in range(1, 7))
    assert all(f'**QG{index}**' in report for index in range(1, 8))
    evidence = json.loads(read(ROOT / 'cached_lock_origin_checks.json'))
    assert evidence['generator_sha256'] == sha(ROOT / 'recover_cached_lock_origin.py')
    assert all(proof['result'] == 'unsat' for proof in evidence['proofs'].values())
    assert current['validation']['cached_lock_origin_increment_checks'] == evidence['verified_counts']
    assert current['validation']['cached_lock_origin_static_scope'] == evidence['scope']
    assert current['goal_status'] == 'active' and not evidence['full_goal_complete']
    archive_names = {MANIFEST, 'triage_evidence/cached_lock_origin_checks.json'}
    owned = ((CHANGED | ADDED) - archive_names) | {name + '.zst' for name in archive_names}
    for name in archive_names:
        assert not (BASE / name).exists()
    for name in owned:
        _, _, findings = inspect((BASE / name).read_bytes(), Path.home().name)
        assert not findings, name
    print(json.dumps({'unchanged_manifest_entries': len(old) - len(CHANGED),
                      'owned_physical_files': len(owned), 'original_inputs_preserved': 3,
                      'username_path_scan_pass': True, 'all_checks_pass': True}))


if __name__ == '__main__':
    main()
