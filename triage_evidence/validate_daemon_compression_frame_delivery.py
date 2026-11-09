#!/usr/bin/env python3
"""Seal compression frame, selector and local copy/return contracts.
O(owned bytes+report links) time, O(largest artifact+manifest) space.
"""
import ast
import json
import re
from pathlib import Path
from validate_daemon_compression_frame_preservation import ROOT, BASE, BASELINE_SHA, ALLOWED, sha


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
        ('daemon_compression_frame_contracts.json', 'recover_daemon_compression_frame.py'),
        ('daemon_compression_frame_proofs.json', 'prove_daemon_compression_frame.py'),
        ('daemon_compression_frame_profiles.json', 'probe_daemon_compression_frame.py'),
        ('daemon_compression_frame_checks.json', 'validate_daemon_compression_frame.py'),
        ('daemon_compression_frame_preservation.json', 'validate_daemon_compression_frame_preservation.py'),
    ]
    contracts, proofs, profiles, checks, preservation = [checked(n, g) for n, g in pairs]
    assert checks['all_checks_pass'] and preservation['all_checks_pass']
    expected = {'original_source_spans': 17, 'direct_SP_accesses_checked': 13, 'original_fixups_checked': 15, 'live_IDB_ranges': 10, 'live_IDB_bytes': 880, 'rebuilt_source_obligations_unsat': 12, 'SMT_files_unsat_and_formula_matched': 24, 'nonempty_arithmetic_premises_checked': 2, 'source_lift_visits': 181, 'ordered_source_reads_checked': 14460, 'ordered_source_writes_checked': 7082, 'logical_dispatch_edges_checked': 6092, 'complete_first_block_copy_cases_checked': 128, 'encoded_copy_bytes_checked': 4160, 'freshly_recomputed_A64_cases': 716, 'persisted_A64_cases': 716, 'compact_selector_leaf_cases_checked': 512, 'selector_dispatch_cases_checked': 512, 'shared_frame_layouts_checked': 8, 'short_compression_callers_checked': 2, 'next_block_gate_cases_checked': 64, 'compression_return_cases_checked': 2, 'exhaustive_selector_bytes_checked': 256, 'audited_short_frontiers': 288, 'audited_retained_visits_inspected': 3357408, 'audited_retained_effects_inspected': 404448, 'audited_retained_cases_checked': 480, 'audited_long_frontiers': 192}
    assert checks['verified_counts'] == expected
    assert len(proofs['proofs']) == 12
    assert len(list(ROOT.glob('daemon_compression_frame_*.smt2'))) == 24
    assert len(profiles['cases']) == 716 and len(contracts['retained_cases']) == 480
    assert not checks['new_port_emission_established']
    assert not checks['completed_digest_or_cache_content_established']
    assert sha(ROOT/'daemon_compression_frame_prior_manifest.json') == BASELINE_SHA
    old = read('daemon_compression_frame_prior_manifest.json')
    changed = {row['path']: row for row in preservation['allowed_existing_changes']}
    assert len(old['files']) == 4009 and preservation['unchanged_prior_artifacts'] == 4003
    assert set(changed) == ALLOWED
    for row in old['files']:
        expected_hash = changed[row['path']]['current_sha256'] if row['path'] in changed else row['sha256']
        assert sha(BASE/row['path']) == expected_hash, row['path']
    for row in old['inputs_preserved']:
        path = BASE/row['path']
        assert path.stat().st_size == row['size_bytes'] and sha(path) == row['sha256']
    source = Path('/Users/___/Downloads/zut/fairplayd.arm64e')
    assert sha(source) == contracts['source_sha256'] == '4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    reports = ['daemon_compression_frame_report.md', 'obfuscated_routines_report.md',
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
            assert path.exists() or path == ROOT/'daemon_compression_frame_quality_gates.json', (name, raw)
            links += 1
    report = (BASE/reports[0]).read_text()
    assert report.isascii()
    for term in ['CF12', 'QG7', '114,390', '108,298', '6,092', '3,357,408', 'signed32(P)', '0x100A361B0', 'N >= L+64', 'separated word cells', 'unknown', 'full daemon/kext/deeper-interface investigation remains active']:
        assert term in report, term
    scripts = list(ROOT.glob('*daemon_compression_frame*.py'))
    assert len(scripts) == 6
    for path in scripts:
        ast.parse(path.read_text(), filename=str(path))
    evidence = ['Factual original-source and process-local frame/copy/selector/return analysis.', 'CF1-CF12 register source, separated owners, entry modes, input extents, retained models, ambient state, signed continuation, full-body preservation, next-block and scope premises with probes.', 'First-chunk copy, common frame, compact selector, continuation epilogue and next-block increment covered; full objective remains active.', 'Explicit hexadecimal offsets, decimal byte extents, signed indices, modular widths, satisfiable arithmetic premises and modeled versus executed instruction counts.', 'Local identities and exhaustive selector mapping remain distinct from continuous native body/caller, arbitrary aliasing, completed digest/cache and transport.', '17 original spans,15 fixups,13 exact direct SP accesses,12 rebuilt proof pairs,716 fresh isolated compositions,880 IDB bytes and480 inspected retained cases verified.', 'Impact-bounded selector2 core semantics, ambient data flow, repeated-block progression, output/cache publication and driver IPC questions retained.']
    out = {
        'scope': __doc__, 'generator_sha256': sha(Path(__file__)),
        **{f'QG{i}': {'status': 'pass_for_increment' if i == 3 else 'pass', 'evidence': item}
           for i, item in enumerate(evidence, 1)},
        'verified_counts': expected, 'independent_A64_totals': checks['independent_A64_totals'],
        'new_validation_outputs': {n: sha(ROOT/n) for n, g in pairs},
        'report_sha256': {n: sha(BASE/n) for n in reports},
        'source_sha256': sha(source), 'source_lift_counts': proofs['source_lift_counts'],
        'prior_artifacts_checked': 4009, 'unchanged_prior_artifacts': 4003,
        'checked_report_links': links, 'new_python_files_syntax_checked': len(scripts),
        'inputs_preserved': old['inputs_preserved'],
        'new_port_emission_established': False,
        'completed_digest_or_cache_content_established': False,
        'native_target_executed': False, 'idb_mutated': False, 'full_goal_complete': False,
    }
    (ROOT/'daemon_compression_frame_quality_gates.json').write_text(json.dumps(out, indent=2)+'\n')
    print(json.dumps({'scoped_gates_pass': True, 'proof_pairs': 12, 'checked_links': links,
                      'goal_status': 'active'}), flush=True)


if __name__ == '__main__':
    main()
