#!/usr/bin/env python3
"""Seal paired digest ABI contracts with explicit retained/native boundaries.
O(owned bytes+report links) time, O(largest artifact+manifest) space.
"""
import ast
import json
import re
from pathlib import Path
from validate_daemon_digest_conventions_preservation import ROOT, BASE, BASELINE_SHA, ALLOWED, sha


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
        ('daemon_digest_conventions_contracts.json', 'recover_daemon_digest_conventions.py'),
        ('daemon_digest_conventions_proofs.json', 'prove_daemon_digest_conventions.py'),
        ('daemon_digest_conventions_profiles.json', 'probe_daemon_digest_conventions.py'),
        ('daemon_digest_conventions_checks.json', 'validate_daemon_digest_conventions.py'),
        ('daemon_digest_conventions_preservation.json', 'validate_daemon_digest_conventions_preservation.py'),
    ]
    contracts, proofs, profiles, checks, preservation = [checked(n, g) for n, g in pairs]
    assert checks['all_checks_pass'] and preservation['all_checks_pass']
    expected = {
        'original_source_spans': 13, 'original_fixups_checked': 17,
        'live_IDB_ranges': 8, 'live_IDB_bytes': 596,
        'exhaustive_allocator_bank_inputs': 256,
        'rebuilt_source_obligations_unsat': 12,
        'SMT_files_unsat_and_formula_matched': 24, 'source_lift_visits': 181,
        'ordered_source_reads_checked': 516, 'ordered_source_writes_checked': 972,
        'encoded_update_fragments_checked': 98,
        'persisted_A64_cases': 377, 'freshly_recomputed_A64_cases': 377,
        'source_visits_checked': 8326,
        'wrapped_padding_fragments_checked': 128, 'inline_padding_fragments_checked': 128,
        'wrapped_finalize_entries_checked': 4, 'new_context_finalize_callers_checked': 2,
        'fixed20_update_callers_checked': 2, 'saved_context_finalize_callers_checked': 2,
        'identity_output_reservations_checked': 4,
        'post_finalize_three_value_gates_checked': 8,
        'malloc1028_argument_fragments_checked': 1,
        'retained_distinct_output_cache_owners_checked': 288,
        'retained_encoded_call_frame_captures_checked': 480,
        'retained_encoded_update_entry_edges': 480,
        'retained_identity_inline_finalize_paths': 288,
        'retained_distinct_context_output_views': 288,
        'retained_retained_cases_checked': 480,
        'retained_retained_visits_inspected': 3357408,
        'retained_retained_effects_inspected': 404448,
        'retained_long_update_frontiers': 192,
    }
    assert checks['verified_counts'] == expected
    assert len(proofs['proofs']) == 12
    assert len(list(ROOT.glob('daemon_digest_conventions_*.smt2'))) == 24
    assert len(profiles['cases']) == 377 and len(contracts['retained_identity_cases']) == 480
    assert not checks['new_port_emission_established']
    assert not checks['completed_digest_or_cache_content_established']
    assert sha(ROOT/'daemon_digest_conventions_prior_manifest.json') == BASELINE_SHA
    old = read('daemon_digest_conventions_prior_manifest.json')
    changed = {row['path']: row for row in preservation['allowed_existing_changes']}
    assert len(old['files']) == 3970 and preservation['unchanged_prior_artifacts'] == 3964
    assert set(changed) == ALLOWED
    for row in old['files']:
        expected_hash = changed[row['path']]['current_sha256'] if row['path'] in changed else row['sha256']
        assert sha(BASE/row['path']) == expected_hash, row['path']
    for row in old['inputs_preserved']:
        path = BASE/row['path']
        assert path.stat().st_size == row['size_bytes'] and sha(path) == row['sha256']
    source = Path('/Users/___/Downloads/zut/fairplayd.arm64e')
    assert sha(source) == contracts['source_sha256'] == '4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    reports = ['daemon_digest_conventions_report.md', 'obfuscated_routines_report.md',
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
            assert path.exists() or path == ROOT/'daemon_digest_conventions_quality_gates.json', (name, raw)
            links += 1
    report = (BASE/reports[0]).read_text()
    assert report.isascii()
    for term in ['DC12', 'QG7', '8,326', '3,357,408', 'signed32(P)',
                 'C+0x64 (100 bytes)', 'C+0x70 (112 bytes)', '1,028 bytes',
                 'word cells', 'unknown', 'full daemon/kext/deeper-interface investigation remains active']:
        assert term in report, term
    scripts = list(ROOT.glob('*daemon_digest_conventions*.py'))
    assert len(scripts) == 6
    for path in scripts:
        ast.parse(path.read_text(), filename=str(path))
    evidence = [
        'Factual original-source and process-local ABI analysis.',
        'DC1-DC12 register source, nonaliasing, roots, mode, owners, retained API models, saved return, local equivalence, output/cache and scope premises with probes.',
        'Paired update/finalization contracts, actual retained identity output distinction, fixed20 slice and conditional allocation covered; full objective remains active.',
        'Explicit hexadecimal offsets, decimal byte extents, signed indices, u32/u64 modular identities and finite/universal counts.',
        'Local identities and finite retained effects are distinguished from native continuity, alias completeness, completed digest/cache and transport.',
        '13 original spans,17 fixups,12 rebuilt proof pairs,377 fresh isolated A64 cases,596 IDB bytes,256 bank inputs and480 inspected retained cases verified.',
        'Impact-bounded frame, owner, output/cache, allocation-consumer and transport questions retained.',
    ]
    out = {
        'scope': __doc__, 'generator_sha256': sha(Path(__file__)),
        **{f'QG{i}': {'status': 'pass_for_increment' if i == 3 else 'pass', 'evidence': item}
           for i, item in enumerate(evidence, 1)},
        'verified_counts': expected, 'independent_A64_totals': checks['independent_A64_totals'],
        'new_validation_outputs': {n: sha(ROOT/n) for n, g in pairs},
        'report_sha256': {n: sha(BASE/n) for n in reports},
        'source_sha256': sha(source), 'source_lift_counts': proofs['source_lift_counts'],
        'prior_artifacts_checked': 3970, 'unchanged_prior_artifacts': 3964,
        'checked_report_links': links, 'new_python_files_syntax_checked': len(scripts),
        'inputs_preserved': old['inputs_preserved'],
        'new_port_emission_established': False,
        'completed_digest_or_cache_content_established': False,
        'native_target_executed': False, 'idb_mutated': False, 'full_goal_complete': False,
    }
    (ROOT/'daemon_digest_conventions_quality_gates.json').write_text(json.dumps(out, indent=2)+'\n')
    print(json.dumps({'scoped_gates_pass': True, 'proof_pairs': 12, 'checked_links': links,
                      'goal_status': 'active'}), flush=True)


if __name__ == '__main__':
    main()
