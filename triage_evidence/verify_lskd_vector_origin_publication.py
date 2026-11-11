#!/usr/bin/env python3
"""Verify the vector-origin publication delta, retained queries and path hygiene."""
from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess

from compression import zstd
import z3

from verify_daemon_reader_record_payloads_publication import read, sha, size
from verify_username_paths_history import inspect

ROOT = Path(__file__).resolve().parent
BASE = ROOT.parent
PREVIOUS = '33afaf1120d19f9c40032e62234fe7c79e7338a3'
MANIFEST = 'triage_evidence/interface_manifest.json'
CHANGED = {
    'lskd_objects_report.md', 'lskd_state_report.md', 'lskd_continuations_report.md',
    'lskd_start_lock_flow_report.md', 'foundational_triage_report.md', 'interface_abi_report.md',
    'interface_investigation_status.md', 'triage_evidence/validate_rpc502_sidecar_delivery.py',
}
ADDED = {
    'lskd_vector_origin_report.md', 'triage_evidence/lskd_vector_origin_checks.json',
    'triage_evidence/recover_lskd_vector_origin.py',
    'triage_evidence/verify_lskd_vector_origin_publication.py',
}
ARCHIVES = {MANIFEST, 'triage_evidence/lskd_vector_origin_checks.json'}
OWNED = ((CHANGED | ADDED) - ARCHIVES) | {name + '.zst' for name in ARCHIVES}


def path_hygiene(raw):
    _, _, username_found = inspect(raw, Path.home().name)
    decoded = zstd.decompress(raw) if raw.startswith(bytes.fromhex('28b52ffd')) else raw
    # Shared target-state paths are recovered ABI, not analyst-machine locations.
    pattern = rb'/(?:Users/(?!Shared(?:/|\b))|home/|tmp/|private/|Library[/]Developer/|opt[/]homebrew/)'
    assert not username_found and not re.search(pattern, decoded)


def main():
    previous_raw = zstd.decompress(subprocess.check_output(
        ['git', 'show', PREVIOUS + ':' + MANIFEST + '.zst'], cwd=BASE))
    assert sha256(previous_raw).hexdigest() == '969bd5a39a88f888122d3f1b4016eac79a1ea40602e946004fe3b08ab54811bc'
    previous = json.loads(previous_raw)
    current = json.loads(read(BASE / MANIFEST))
    old = {row['path']: row for row in previous['files']}
    new = {row['path']: row for row in current['files']}
    assert len(old) == len(previous['files']) == 8026
    assert len(new) == len(current['files']) == 8030
    assert not old.keys() - new.keys() and new.keys() - old.keys() == ADDED
    assert {name for name in old if old[name] != new[name]} == CHANGED
    assert current['inputs_preserved'] == previous['inputs_preserved']
    for row in current['inputs_preserved']:
        path = BASE / row['path']
        assert sha(path) == row['sha256'] and size(path) == row['size_bytes']
    for name in CHANGED | ADDED:
        path = BASE / name
        assert sha(path) == new[name]['sha256'] and size(path) == new[name]['size_bytes']
    report = read(BASE / 'lskd_vector_origin_report.md')
    assert all(f'| VO{j} |' in report for j in range(1, 9))
    assert all(f'**QG{j}**' in report for j in range(1, 8))
    evidence = json.loads(read(ROOT / 'lskd_vector_origin_checks.json'))
    assert evidence['generator_sha256'] == sha(ROOT / 'recover_lskd_vector_origin.py')
    for name, digest in evidence['dependencies'].items():
        assert sha(ROOT / name) == digest
    for source in evidence['supplied_reference_excerpts']:
        path = BASE / source['path']
        assert sha(path) == source['sha256']
        lines = path.read_text().splitlines(keepends=True)
        assert ''.join(lines[source['first_line'] - 1:source['last_line']]) == source['text']
    assert len(evidence['proofs']) == 16
    for proof in evidence['proofs'].values():
        assert proof['result'] == 'unsat'
        solver = z3.Solver()
        solver.set(timeout=10000)
        solver.from_string(proof['query'])
        assert solver.check() == z3.unsat
    assert len(evidence['retained_frames']) == 13
    assert all(len(frame['frame_fields']) == 20 and not frame['new_target_execution']
               for frame in evidence['retained_frames'])
    assert [(v['site_name'], v['size32_B']) for v in evidence['typed_views']] == [
        ('site.KDDecryptParamsArray_t', 8192), ('site.KDDecryptParams', 512)]
    layout = evidence['element_initialization']
    assert len(layout['stores']) == layout['store_count'] == 47
    covered = set()
    for store in layout['stores']:
        covered.update(range(store['offset_B'], store['offset_B'] + store['width_B']))
    assert len(covered) == layout['unique_written_B'] == 164
    assert max(covered) + 1 == layout['exclusive_end_B'] == 508
    assert not layout['full_object_initialized'] and layout['declared_size_B'] == 512
    assert not evidence['new_target_execution'] and not evidence['native_epoch_matched']
    assert not evidence['new_IDA_access'] and not evidence['full_goal_complete']
    assert current['validation']['lskd_vector_origin_increment_checks'] == evidence['verified_counts']
    assert current['validation']['lskd_vector_origin_static_scope'] == evidence['scope']
    external = current['validation']['unavailable_external_primary_references']
    assert len(external) == 1
    assert external[0]['historical_sha256'] == previous['validation']['unavailable_external_primary_references'][0]['historical_sha256']
    assert external[0]['installed_comparison_sha256'] == previous['validation']['unavailable_external_primary_references'][0]['installed_comparison_sha256']
    assert external[0]['path'] == 'historical SDK:usr/include/mach/port.h'
    assert external[0]['installed_comparison_path'] == 'installed SDK:usr/include/mach/port.h'
    assert current['goal_status'] == 'active'
    for name in ARCHIVES:
        assert not (BASE / name).exists()
    assert len(OWNED) == 13
    for name in OWNED:
        path_hygiene((BASE / name).read_bytes())
    print(json.dumps({'unchanged_manifest_entries': len(old) - len(CHANGED),
                      'owned_physical_files': len(OWNED), 'original_inputs_preserved': 3,
                      'serialized_queries_rechecked': len(evidence['proofs']),
                      'source_element_write_union_B': len(covered),
                      'analyst_path_literals_absent': True, 'all_checks_pass': True}))


if __name__ == '__main__':
    main()
