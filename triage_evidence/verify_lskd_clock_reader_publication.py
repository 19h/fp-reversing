#!/usr/bin/env python3
"""Verify conditional clock-reader publication, source certificates and scrub."""
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
PREVIOUS = 'd8db926982ff1a47d2b5cd578223562c9d750e69'
MANIFEST = 'triage_evidence/interface_manifest.json'
CHANGED = {
    'lskd_clock_completion_report.md', 'lskd_secure_time_report.md',
    'lskd_continuations_report.md', 'foundational_triage_report.md',
    'interface_abi_report.md', 'interface_investigation_status.md',
    'triage_evidence/validate_rpc502_sidecar_delivery.py',
}
ADDED = {
    'lskd_clock_reader_report.md', 'triage_evidence/lskd_clock_reader_checks.json',
    'triage_evidence/recover_lskd_clock_reader.py',
    'triage_evidence/verify_lskd_clock_reader_publication.py',
}
ARCHIVES = {MANIFEST, 'triage_evidence/lskd_clock_reader_checks.json'}
OWNED = ((CHANGED | ADDED) - ARCHIVES) | {name + '.zst' for name in ARCHIVES}


def check_query(query, expected=z3.unsat):
    solver = z3.Solver()
    solver.set(timeout=10000)
    solver.from_string(query)
    assert solver.check() == expected


def main():
    raw = zstd.decompress(subprocess.check_output(
        ['git', 'show', PREVIOUS + ':' + MANIFEST + '.zst'], cwd=BASE))
    assert sha256(raw).hexdigest() == '73ff06e29d9697ab158f3f4f5b33d3749464ceda72d35da8800e8f22a7e29e01'
    previous = json.loads(raw)
    current = json.loads(read(BASE / MANIFEST))
    old = {r['path']: r for r in previous['files']}
    new = {r['path']: r for r in current['files']}
    assert len(old) == len(previous['files']) == 8042
    assert len(new) == len(current['files']) == 8046
    assert not old.keys() - new.keys() and new.keys() - old.keys() == ADDED
    assert {name for name in old if old[name] != new[name]} == CHANGED
    assert current['inputs_preserved'] == previous['inputs_preserved']
    for row in current['inputs_preserved']:
        path = BASE / row['path']
        assert sha(path) == row['sha256'] and size(path) == row['size_bytes']
    for name in CHANGED | ADDED:
        assert sha(BASE / name) == new[name]['sha256'] and size(BASE / name) == new[name]['size_bytes']
    report = read(BASE / 'lskd_clock_reader_report.md')
    assert all(f'| CR{j} |' in report for j in range(1, 9))
    assert all(f'**QG{j}**' in report for j in range(1, 8))
    evidence = json.loads(read(ROOT / 'lskd_clock_reader_checks.json'))
    assert evidence['generator_sha256'] == sha(ROOT / 'recover_lskd_clock_reader.py')
    for name, digest in evidence['dependencies'].items():
        assert sha(ROOT / name) == digest
    assert len(evidence['proofs']) == 15 and len(evidence['negative_controls']) == 2
    for proof in evidence['proofs'].values():
        assert proof['result'] == 'unsat'
        check_query(proof['query'])
    for control in evidence['negative_controls'].values():
        assert control['result'] == 'sat' and control['model']
        check_query(control['query'], z3.sat)
    writer = json.loads(read(ROOT / 'lskd_clock_completion_checks.json'))
    check_query(writer['proofs']['clock_field_30_and_zero_38']['query'])
    preceding = json.loads(read(ROOT / 'lskd_continuations_proofs.json'))
    adapter_proofs = [p for p in preceding['proofs'] if p['name'] in {
        'acquire_record_selector', 'acquire_explicit_pointer_gate'}]
    assert len(adapter_proofs) == 2
    for proof in adapter_proofs:
        path = ROOT / proof['original_file']
        assert sha(path) == proof['original_sha256'] and proof['result'] == 'unsat'
        check_query(read(path))
    assert len(evidence['spans']) == 5 and len(evidence['control_slots']) == 5
    for row in evidence['spans']:
        data = bytes.fromhex(row['bytes_hex'])
        assert len(data) == int(row['end'], 16) - int(row['start'], 16)
        assert len(row['instructions'])*4 == len(data)
    for index, slot in evidence['control_slots'].items():
        assert int(slot['slot'], 16) == 0xfffffe000846c420 + 8*int(index, 16)
        assert slot['chain_membership_verified'] and slot['authenticated']
        assert slot['target'] in report and slot['slot'] in report
    assert len(evidence['literal_clock_call_census']) == 10
    source = evidence['supplied_reference']
    path = BASE / source['path']
    assert sha(path) == source['sha256']
    lines = read(path).splitlines(keepends=True)
    assert source['text'] == ''.join(lines[source['first_line']-1:source['last_line']])
    literal_lines = [i for i, text in enumerate(lines, 1)
        if 'strcpy(' in text and '"kern.monotonicclock"' in text]
    assert literal_lines == [r['literal_copy_line'] for r in evidence['literal_clock_call_census']]
    for row in evidence['literal_clock_call_census']:
        assert row['text'] == ''.join(lines[row['first_excerpt_line']-1:row['last_excerpt_line']])
        assert row['function_heading'] == lines[row['function_heading_line']-1].rstrip()
        assert str(row['literal_copy_line']) in report
    audit = evidence['source_status_audit']
    assert not audit['incoming_sysctl_status_reads_before_overwrite'] and not audit['returned_length_reloads']
    assert audit['X0_overwrites'] == ['0xfffffe000a517834']
    contract = evidence['selected_contract']
    assert contract['conditional_incoming_phase32'] == '0x6e3'
    assert contract['record_required_alignment_B'] == 2
    assert contract['fresh_clock_B'] == 4 and contract['stored_relation_width_B'] == 8
    assert contract['seed_offsets_B'] == [216, 16, 160]
    assert not any(contract[k] for k in ['actual_incoming_phase_proven', 'actual_reader_frame_roots_proven',
        'helper_bank_roots_recovered', 'upstream_request_recovered', 'daemon_reply_recovered', 'native_epoch_matched'])
    assert not evidence['new_target_execution'] and not evidence['new_IDA_access'] and not evidence['full_goal_complete']
    counts = evidence['verified_counts']
    assert counts['instructions'] == 840 and counts['code_B'] == 3360
    assert counts['source_lifted_instances'] == 220 and counts['queries_unsat'] == 15
    assert counts['negative_controls_sat'] == 2 and counts['operand_anchors'] == 16
    assert counts['captured_only_followon_spans'] == 2
    assert current['validation']['lskd_clock_reader_increment_checks'] == counts
    assert current['validation']['lskd_clock_reader_static_scope'] == evidence['scope']
    assert current['validation']['unavailable_external_primary_references'] == previous['validation']['unavailable_external_primary_references']
    assert current['goal_status'] == 'active'
    for name in ARCHIVES:
        assert not (BASE / name).exists()
    assert len(OWNED) == 12
    for name in OWNED:
        path_hygiene((BASE / name).read_bytes())
    print(json.dumps({'unchanged_manifest_entries': len(old) - len(CHANGED),
        'owned_physical_files': len(OWNED), 'original_inputs_preserved': 3,
        'new_queries_rechecked': 15, 'SAT_controls_rechecked': 2,
        'predecessor_queries_rechecked': 3, 'literal_clock_call_sites': 10,
        'source_instructions_retained': 840, 'analyst_path_literals_absent': True,
        'all_checks_pass': True}))


if __name__ == '__main__':
    main()
