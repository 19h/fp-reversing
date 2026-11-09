#!/usr/bin/env python3
"""Seal selector2 SHA-1 source helpers, complete isolated cores and publication limits.
O(owned bytes+report links) time, O(largest artifact+manifest) space.
"""
import ast
import json
import re
from pathlib import Path
from validate_daemon_sha1_core_preservation import ROOT, BASE, BASELINE_SHA, ALLOWED, sha


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
        ('daemon_sha1_core_contracts.json', 'recover_daemon_sha1_core.py'),
        ('daemon_sha1_core_proofs.json', 'prove_daemon_sha1_core.py'),
        ('daemon_sha1_core_profiles.json', 'probe_daemon_sha1_core.py'),
        ('daemon_sha1_core_checks.json', 'validate_daemon_sha1_core.py'),
        ('daemon_sha1_core_preservation.json', 'validate_daemon_sha1_core_preservation.py'),
    ]
    contracts, proofs, profiles, checks, preservation = [checked(n, g) for n, g in pairs]
    assert checks['all_checks_pass'] and preservation['all_checks_pass']
    expected = {'original_source_spans': 13, 'unique_original_instructions': 1467, 'original_fixups_checked': 16, 'live_IDB_ranges': 10, 'live_IDB_bytes': 5376, 'certified_source_obligations_rebuilt_unsat': 44, 'original_normalized_SMT_artifacts_matched': 88, 'certified_source_register_rewrites': 26, 'nonempty_helper_index_domains': 6, 'source_lift_visits': 1302, 'helper_ABI_configurations_checked': 288, 'GPR_defined_source_visits_checked': 783984, 'ordered_reads_checked': 28224, 'ordered_writes_checked': 5040, 'modeled_BRAA_edges_checked': 7968, 'encoded_schedule_words_checked': 3840, 'round_entry_states_checked': 3840, 'round_exit_states_checked': 3840, 'complete_encoded_context_results_checked': 48, 'hashlib_message_oracles_checked': 16, 'freshly_recomputed_core_cases': 48, 'hashlib_model_tail_oracles_checked': 16}
    assert checks['verified_counts'] == expected
    assert len(proofs['proofs']) == 44
    assert len(list(ROOT.glob('daemon_sha1_core_*.smt2'))) == 88
    assert len(profiles['cases']) == 48 and contracts['trace_totals']['cases'] == 48
    assert not checks['new_port_emission_established']
    assert not checks['identity_digest_or_cache_publication_established']
    assert sha(ROOT/'daemon_sha1_core_prior_manifest.json') == BASELINE_SHA
    old = read('daemon_sha1_core_prior_manifest.json')
    changed = {row['path']: row for row in preservation['allowed_existing_changes']}
    assert len(old['files']) == 4049 and preservation['unchanged_prior_artifacts'] == 4043
    assert set(changed) == ALLOWED
    for row in old['files']:
        expected_hash = changed[row['path']]['current_sha256'] if row['path'] in changed else row['sha256']
        assert sha(BASE/row['path']) == expected_hash, row['path']
    for row in old['inputs_preserved']:
        path = BASE/row['path']
        assert path.stat().st_size == row['size_bytes'] and sha(path) == row['sha256']
    source = Path('/Users/___/Downloads/zut/fairplayd.arm64e')
    assert sha(source) == contracts['source_sha256'] == '4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    reports = ['daemon_sha1_core_report.md', 'obfuscated_routines_report.md',
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
            assert path.exists() or path == ROOT/'daemon_sha1_core_quality_gates.json', (name, raw)
            links += 1
    report = (BASE/reports[0]).read_text()
    assert report.isascii()
    for term in ['SC12','QG7','783,984','776,016','7,968','0x8B3DC651','0xF4F92DF7','a9993e364706816aba3e25717850c26c9cd0d89d','F+0x3D00','F+0x3E40','unknown','full daemon/kext/deeper-interface investigation remains active']:
        assert term in report, term
    audit=read('daemon_sha1_core_solver_audit.json')
    assert sha(ROOT/audit['initial_round0_query_file'])==audit['initial_round0_query_sha256']
    assert all(a['result']=='unknown' for a in audit['initial_attempts'])
    assert audit['rejected_sum_abstraction']['result']=='sat' and not audit['rejected_sum_abstraction']['accepted_for_proof']
    scripts = list(ROOT.glob('*daemon_sha1_core*.py'))
    assert len(scripts) == 7
    for path in scripts:
        ast.parse(path.read_text(), filename=str(path))
    evidence = ['Factual original-source analysis of an encoded SHA-1 compression primitive.', 'SC1-SC12 register source, nonaliasing cells, mode/owners, original targets, helper premises, certified algebra, reference model, state/output distinction, geometry and transport scope with probes.', 'Selector2 decoder, schedule, four round groups and five state accumulations covered; full objective remains active.', 'Explicit word/byte units, endianness, 32/64-bit modular arithmetic, seven incoming registers and modeled versus executed instruction counts.', 'Local universal identities and finite complete cores remain distinct from universal cross-helper/native caller invariants and digest/cache/driver publication; exploratory SAT/unknown methods rejected.', '13 original spans,1467 unique instructions,16 fixups,44 rebuilt source obligations with26 certified rewrites,48 fresh complete cores,5376 IDB bytes,3840 schedule words and3840 entry/exit round states verified.', 'Impact-bounded finalizer formatting, ambient frame provenance, cache publication, driver IPC and other-selector classification retained.']
    out = {
        'scope': __doc__, 'generator_sha256': sha(Path(__file__)),
        **{f'QG{i}': {'status': 'pass_for_increment' if i == 3 else 'pass', 'evidence': item}
           for i, item in enumerate(evidence, 1)},
        'verified_counts': expected, 'independent_A64_totals': checks['independent_A64_totals'],
        'new_validation_outputs': {n: sha(ROOT/n) for n, g in pairs},
        'report_sha256': {n: sha(BASE/n) for n in reports},
        'source_sha256': sha(source), 'source_lift_counts': proofs['source_lift_counts'],
        'prior_artifacts_checked': 4049, 'unchanged_prior_artifacts': 4043,
        'checked_report_links': links, 'new_python_files_syntax_checked': len(scripts),
        'inputs_preserved': old['inputs_preserved'],
        'new_port_emission_established': False,
        'identity_digest_or_cache_publication_established': False,
        'native_target_executed': False, 'idb_mutated': False, 'full_goal_complete': False,
    }
    (ROOT/'daemon_sha1_core_quality_gates.json').write_text(json.dumps(out, indent=2)+'\n')
    print(json.dumps({'scoped_gates_pass': True, 'proof_pairs': 44, 'checked_links': links,
                      'goal_status': 'active'}), flush=True)


if __name__ == '__main__':
    main()
