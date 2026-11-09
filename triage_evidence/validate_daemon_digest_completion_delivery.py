#!/usr/bin/env python3
"""Seal context overwrite, decoded copy, completion marker and producer contracts.
O(owned bytes+report links) time, O(largest artifact+manifest) space.
"""
import ast
import json
import re
from pathlib import Path
from validate_daemon_digest_completion_preservation import ROOT, BASE, BASELINE_SHA, ALLOWED, sha


def read(name):
    return json.loads((ROOT/name).read_text())


def checked(name, generator):
    result = read(name)
    assert result['generator_sha256'] == sha(ROOT/generator)
    assert not result['full_goal_complete']
    for dependency, digest in result.get('dependencies', {}).items():
        assert sha(ROOT/dependency) == digest, (name, dependency)
    return result


def main():
    pairs = [
        ('daemon_digest_completion_contracts.json', 'recover_daemon_digest_completion.py'),
        ('daemon_digest_completion_proofs.json', 'prove_daemon_digest_completion.py'),
        ('daemon_digest_completion_profiles.json', 'probe_daemon_digest_completion.py'),
        ('daemon_digest_completion_checks.json', 'validate_daemon_digest_completion.py'),
        ('daemon_digest_completion_preservation.json', 'validate_daemon_digest_completion_preservation.py'),
    ]
    contracts, proofs, profiles, checks, preservation = [checked(n, g) for n, g in pairs]
    assert checks['all_checks_pass'] and preservation['all_checks_pass']
    expected = {'original_source_spans': 21, 'unique_observed_instructions': 253, 'original_fixups_checked': 15, 'live_IDB_ranges': 19, 'live_IDB_bytes': 1404, 'bounded_scalar_writer_sites': 17, 'byte_function_inputs': 256, 'normalized_SMT_equivalences_unsat': 24, 'source_obligations_rebuilt_unsat': 24, 'SMT_artifacts_verified': 48, 'nonempty_loop_domains': 2, 'source_lift_visits': 329, 'completion_defined_source_visits': 480460, 'completion_ordered_reads': 31712, 'completion_ordered_writes': 27432, 'completion_modeled_BRAA_edges': 15888, 'complete_context_overwrites': 140, 'decoded_destination_bytes': 1392, 'completion_byte_stores': 140, 'cases_freshly_recomputed': 396, 'conditional_canonical_SHA1_matches': 12, 'overwrite_iteration_defined_source_visits': 8704, 'overwrite_iteration_ordered_writes': 512, 'overwrite_iteration_ordered_reads': 512, 'overwrite_iteration_modeled_BRAA_edges': 256, 'single_overwrite_iterations': 256, 'tracked_read_effects': 3456, 'tracked_write_effects': 1728, 'retained_short_cases': 288, 'retained_effects_inspected': 74400}
    assert checks['verified_counts'] == expected
    assert len(proofs['proofs']) == 24
    assert len(list(ROOT.glob('daemon_digest_completion_*.smt2'))) == 48
    assert len(profiles['cases']) == 396 and contracts['trace_totals']['completion_cases'] == 140 and contracts['trace_totals']['overwrite_iteration_cases'] == 256
    assert not checks['new_port_emission_established']
    assert not checks['native_cache_or_driver_link_established']
    assert sha(ROOT/'daemon_digest_completion_prior_manifest.json') == BASELINE_SHA
    old = read('daemon_digest_completion_prior_manifest.json')
    changed = {row['path']: row for row in preservation['allowed_existing_changes']}
    assert len(old['files']) == 4217 and preservation['unchanged_prior_artifacts'] == 4211
    assert set(changed) == ALLOWED
    for row in old['files']:
        expected_hash = changed[row['path']]['current_sha256'] if row['path'] in changed else row['sha256']
        assert sha(BASE/row['path']) == expected_hash, row['path']
    for row in old['inputs_preserved']:
        path = BASE/row['path']
        assert path.stat().st_size == row['size_bytes'] and sha(path) == row['sha256']
    source = Path('/Users/___/Downloads/zut/fairplayd.arm64e')
    assert sha(source) == contracts['source_sha256'] == '4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    reports = ['daemon_digest_completion_report.md', 'obfuscated_routines_report.md',
               'mach_ports_report.md', 'foundational_triage_report.md',
               'interface_abi_report.md', 'interface_investigation_status.md']
    links = 0
    for name in reports:
        for raw in re.findall(r'\[[^\]]*\]\(([^)]+)\)', (BASE/name).read_text()):
            raw = raw.strip('<>')
            if raw.startswith('#') or re.match(r'^[a-zA-Z][\w+.-]*://', raw):
                continue
            path = Path(raw.split('#', 1)[0])
            path = path if path.is_absolute() else BASE/path
            assert path.exists() or path == ROOT/'daemon_digest_completion_quality_gates.json', (name, raw)
            links += 1
    report = (BASE/reports[0]).read_text()
    assert report.isascii()
    for term in ['GC12', 'QG7', '489,164', '473,020', '16,144', 'F+0x3650', '0x32E8', '0x98', '1,392', 'unknown', 'full daemon/kext/deeper-interface investigation remains active']:
        assert term in report, term

    scripts = list(ROOT.glob('*daemon_digest_completion*.py'))
    assert len(scripts) == 8
    for path in scripts:
        ast.parse(path.read_text(), filename=str(path))
    evidence = ['Factual original-source analysis of context overwrite, decoded output and completion marker.', 'GC1-GC12 specify image, nonoverlapping owners, phase registers, opaque-root independence, dispatcher constants, preserved fields, copy count/owners, cursor/restores, marker semantics, prior models, auxiliary producer and cache/transport boundaries with probes.', 'Overwrite/copy/cursor/marker phase and local pointer producers covered; broad native daemon/kext/deeper objective remains active.', 'Explicit byte extents, endian output, u32/u64 modular arithmetic, eight phase GPRs and source-versus-modeled-dispatch instruction counts.', 'Universal local identities, frozen saved-field views and separately declared component compositions remain distinct from native barrier traversal, cache publication and driver IPC joins.', '21 source spans,15 fixups,1404 IDB bytes,24 rebuilt source obligations,48 hashed SMT artifacts with24 normalization equivalences,396 fresh cases,288 saved-field views and12 conditional canonical SHA-1 outputs verified.', 'Impact-ranked decoded sink, marker/readers/next owner, root/auxiliary continuity, cache/IPC joins, overwrite purpose and phase-specific field reuse bounded.']
    out = {
        'scope': __doc__, 'generator_sha256': sha(Path(__file__)),
        **{f'QG{i}': {'status': 'pass_for_increment' if i == 3 else 'pass', 'evidence': item}
           for i, item in enumerate(evidence, 1)},
        'verified_counts': expected, 'independent_A64_totals': checks['independent_A64_totals'],
        'new_validation_outputs': {n: sha(ROOT/n) for n, g in pairs},
        'report_sha256': {n: sha(BASE/n) for n in reports},
        'source_sha256': sha(source), 'source_lift_counts': proofs['source_lift_counts'],
        'prior_artifacts_checked': 4217, 'unchanged_prior_artifacts': 4211,
        'checked_report_links': links, 'new_python_files_syntax_checked': len(scripts),
        'inputs_preserved': old['inputs_preserved'],
        'new_port_emission_established': False,
        'native_cache_or_driver_link_established': False,
        'native_target_executed': False, 'idb_mutated': False, 'full_goal_complete': False,
    }
    (ROOT/'daemon_digest_completion_quality_gates.json').write_text(json.dumps(out, indent=2)+'\n')
    print(json.dumps({'scoped_gates_pass': True, 'proof_pairs': 24, 'checked_links': links,
                      'goal_status': 'active'}), flush=True)


if __name__ == '__main__':
    main()
