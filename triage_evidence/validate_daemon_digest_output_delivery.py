#!/usr/bin/env python3
"""Seal digest serializers, conditional value compositions and unresolved root contracts.
O(owned bytes+report links) time, O(largest artifact+manifest) space.
"""
import ast
import json
import re
from pathlib import Path
from validate_daemon_digest_output_preservation import ROOT, BASE, BASELINE_SHA, ALLOWED, sha


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
        ('daemon_digest_output_contracts.json', 'recover_daemon_digest_output.py'),
        ('daemon_digest_output_proofs.json', 'prove_daemon_digest_output.py'),
        ('daemon_digest_output_profiles.json', 'probe_daemon_digest_output.py'),
        ('daemon_digest_output_checks.json', 'validate_daemon_digest_output.py'),
        ('daemon_digest_output_preservation.json', 'validate_daemon_digest_output_preservation.py'),
    ]
    contracts, proofs, profiles, checks, preservation = [checked(n, g) for n, g in pairs]
    assert checks['all_checks_pass'] and preservation['all_checks_pass']
    expected = {'original_source_spans': 15, 'unique_observed_serializer_instructions': 383, 'original_fixups_checked': 15, 'live_IDB_ranges': 15, 'live_IDB_bytes': 1792, 'exact_SP3050_scalar_accesses': 8, 'shift_access_records_checked': 3, 'independent_shift_instruction_cases': 36, 'source_obligations_rebuilt_unsat': 22, 'SMT_artifacts_formula_matched': 44, 'nonempty_helper_domains': 4, 'source_lift_visits': 403, 'cases_defined_source_visits': 15440, 'cases_ordered_reads': 1184, 'cases_ordered_writes': 640, 'cases_modeled_BRAA_edges': 400, 'cases_defined_output_bytes': 576, 'helper_ABI_configurations_checked': 64, 'cases_freshly_recomputed': 64, 'decision_cases_defined_source_visits': 25948, 'decision_cases_ordered_reads': 3084, 'decision_cases_ordered_writes': 512, 'decision_cases_modeled_BRAA_edges': 1540, 'decision_cases_defined_output_bytes': 0, 'decision_cases_freshly_recomputed': 512, 'pipeline_serializer_defined_source_visits': 2562, 'pipeline_serializer_ordered_reads': 180, 'pipeline_serializer_ordered_writes': 126, 'pipeline_serializer_modeled_BRAA_edges': 54, 'pipeline_serializer_defined_output_bytes': 120, 'conditional_pipelines_freshly_recomputed': 6, 'conditional_pipeline_hashlib_oracles': 6, 'retained_prepared_inputs_value_matched': 288, 'retained_short_cases_checked': 288, 'retained_visits_inspected': 401568, 'retained_effects_inspected': 74400, 'distinct_prepared_messages': 3}
    assert checks['verified_counts'] == expected
    assert len(proofs['proofs']) == 22
    assert len(list(ROOT.glob('daemon_digest_output_*.smt2'))) == 44
    assert len(profiles['cases']) == 64 and contracts['trace_totals']['cases_count'] == 64
    assert len(profiles['decision_cases']) == 512 and len(profiles['conditional_pipelines']) == 6
    assert not checks['new_port_emission_established']
    assert not checks['native_identity_or_cache_publication_established']
    assert sha(ROOT/'daemon_digest_output_prior_manifest.json') == BASELINE_SHA
    old = read('daemon_digest_output_prior_manifest.json')
    changed = {row['path']: row for row in preservation['allowed_existing_changes']}
    assert len(old['files']) == 4156 and preservation['unchanged_prior_artifacts'] == 4150
    assert set(changed) == ALLOWED
    for row in old['files']:
        expected_hash = changed[row['path']]['current_sha256'] if row['path'] in changed else row['sha256']
        assert sha(BASE/row['path']) == expected_hash, row['path']
    for row in old['inputs_preserved']:
        path = BASE/row['path']
        assert path.stat().st_size == row['size_bytes'] and sha(path) == row['sha256']
    source = Path('/Users/___/Downloads/zut/fairplayd.arm64e')
    assert sha(source) == contracts['source_sha256'] == '4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    reports = ['daemon_digest_output_report.md', 'obfuscated_routines_report.md',
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
            assert path.exists() or path == ROOT/'daemon_digest_output_quality_gates.json', (name, raw)
            links += 1
    report = (BASE/reports[0]).read_text()
    assert report.isascii()
    for term in ['DO12', 'QG7', '141,948', '138,958', '2,990', 'SP+0x3050', '0x2FE0', '0x98', '3101a6aedf9e19f222a6bde9e0c85af404484005', 'unknown', 'full daemon/kext/deeper-interface investigation remains active']:
        assert term in report, term

    scripts = list(ROOT.glob('*daemon_digest_output*.py'))
    assert len(scripts) == 8
    for path in scripts:
        ast.parse(path.read_text(), filename=str(path))
    evidence = ['Factual original-source analysis of encoded digest serialization and saved-root contracts.', 'DO1-DO12 register image, owner/nonoverlap, mode, selector/size, encoding, instruction-access, retained models, component composition, geometry, root provenance, saved fields and publication premises with probes.', 'Selector routing, both declared serializers, zero-size paths, local root producers and finite retained-input value compositions covered; full objective remains active.', 'Explicit byte/word units, endian maps, 32/64-bit modular arithmetic, minimal incoming registers and source versus modeled-branch instruction counts.', 'Local universal source equations and finite independent component compositions remain distinct from native caller continuity, root identity, cache publication and driver transport.', '15 source spans,15 original fixups,1792 current IDB bytes,22 rebuilt obligations,44 matched SMT artifacts,64 serializers,512 decisions,6 fresh source component pairs,288 retained inputs and36 architectural access checks verified.', 'Impact-ranked continuation-root provenance, encoded output consumers, cache/driver linkage, selector1 classification, phase-specific cells and access-metadata opportunities bounded.']
    out = {
        'scope': __doc__, 'generator_sha256': sha(Path(__file__)),
        **{f'QG{i}': {'status': 'pass_for_increment' if i == 3 else 'pass', 'evidence': item}
           for i, item in enumerate(evidence, 1)},
        'verified_counts': expected, 'independent_A64_totals': checks['independent_A64_totals'],
        'component_A64_totals': checks['component_A64_totals'],
        'new_validation_outputs': {n: sha(ROOT/n) for n, g in pairs},
        'report_sha256': {n: sha(BASE/n) for n in reports},
        'source_sha256': sha(source), 'source_lift_counts': proofs['source_lift_counts'],
        'prior_artifacts_checked': 4156, 'unchanged_prior_artifacts': 4150,
        'checked_report_links': links, 'new_python_files_syntax_checked': len(scripts),
        'inputs_preserved': old['inputs_preserved'],
        'new_port_emission_established': False,
        'native_identity_or_cache_publication_established': False,
        'native_target_executed': False, 'idb_mutated': False, 'full_goal_complete': False,
    }
    (ROOT/'daemon_digest_output_quality_gates.json').write_text(json.dumps(out, indent=2)+'\n')
    print(json.dumps({'scoped_gates_pass': True, 'proof_pairs': 22, 'checked_links': links,
                      'goal_status': 'active'}), flush=True)


if __name__ == '__main__':
    main()
