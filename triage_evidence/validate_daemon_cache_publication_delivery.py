#!/usr/bin/env python3
"""Seal declared identity cache population, recovery, cleanup and next-input contracts.
O(owned bytes+report links) time, O(largest artifact+manifest) space.
"""
import ast
import json
import re
from pathlib import Path
from validate_daemon_cache_publication_preservation import ROOT, BASE, BASELINE_SHA, ALLOWED, sha


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
    pairs = [('daemon_cache_publication_context.json', 'capture_daemon_cache_publication.py'), ('daemon_cache_publication_contracts.json', 'recover_daemon_cache_publication.py'), ('daemon_cache_publication_proofs.json', 'prove_daemon_cache_publication.py'), ('daemon_cache_publication_profiles.json', 'probe_daemon_cache_publication_fast.py'), ('daemon_cache_publication_checks.json', 'validate_daemon_cache_publication.py'), ('daemon_cache_publication_interfaces.json', 'sample_daemon_cache_publication.py'), ('daemon_cache_publication_executor_comparison.json', 'compare_daemon_cache_publication_executors.py'), ('daemon_cache_relocation_profiles.json', 'probe_daemon_cache_relocation.py'), ('daemon_cache_relocation_checks.json', 'validate_daemon_cache_relocation.py'), ('daemon_cache_publication_preservation.json', 'validate_daemon_cache_publication_preservation.py')]
    context, contracts, proofs, profiles, checks, samples, comparison, relocated, relocation, preservation = [checked(n, g) for n, g in pairs]
    assert checks['all_checks_pass'] and preservation['all_checks_pass']
    expected = {'retained_source_visits': 401568, 'retained_API_summaries': 1728, 'retained_ordered_writes': 28224, 'retained_ordered_reads': 46176, 'restored_component_contexts': 288, 'FP_named_spans_checked': 66, 'source_inventory_spans_checked': 102, 'unique_source_words_checked': 14736, 'original_fixups_checked': 139, 'live_IDB_ranges': 28, 'live_IDB_bytes': 4288, 'sampled_ABI_entries_checked': 80, 'SDK_signature_compile_checked': 1, 'source_obligations_rebuilt_unsat': 11, 'normalized_SMT_equivalences_unsat': 11, 'SMT_artifacts_verified': 22, 'nonempty_loop_domains': 2, 'source_lift_visits': 161, 'legacy_full_stream_comparisons_checked': 12, 'defined_source_visits_checked': 42068736, 'ordered_source_reads_checked': 6151680, 'ordered_source_writes_checked': 1550016, 'void_API_summaries_checked': 4608, 'independent_MT_word_updates_checked': 1078272, 'complete_MT_twists_checked': 1728, 'padding_sampler_stores_checked': 6912, 'padding_zero_retries': 0, 'sampler_readbacks_checked': 6912, 'defined_cache_read_bytes': 18432, 'codec_lookup_addresses_checked': 11520, 'independent_codec_byte_values_checked': 11520, 'cases_byte_ledgers_checked': 576, 'volatile_register_reads_before_overwrite': 0, 'fresh_context_initializers_checked': 576, 'fresh_decoder_ABI_entries_checked': 11520, 'fresh_prefix_copy_ABI_entries_checked': 11520, 'fresh_complete_A64_cases_recomputed': 576}
    assert checks['verified_counts'] == expected
    assert len(proofs['proofs']) == 11
    assert len(list(ROOT.glob('daemon_cache_publication_*.smt2'))) == 22
    assert len(profiles['cases']) == 576 and contracts['totals']['cases'] == 576
    assert len(context['contexts']) == 288 and len(comparison['cases']) == 12
    assert relocation['all_checks_pass'] and relocation['verified_counts']['controlled_cache_only_relocations'] == 6
    assert relocation['verified_counts']['fresh_complete_cases_recomputed'] == 9
    assert checks['volatile_reads_requiring_further_interpretation'] == []
    audit=read('daemon_cache_publication_legacy_sweep_audit.json')
    assert audit['terminal_observed'] and audit['terminal_exit_code'] == 130 and not audit['legacy_profile_published']
    assert audit['replacement_case_count'] == 576 and audit['selected_full_stream_comparisons_passed'] == 12
    assert not checks['new_port_emission_established']
    assert not checks['native_cache_or_driver_continuity_established']
    assert sha(ROOT/'daemon_cache_publication_prior_manifest.json') == BASELINE_SHA
    old = read('daemon_cache_publication_prior_manifest.json')
    changed = {row['path']: row for row in preservation['allowed_existing_changes']}
    assert len(old['files']) == 4282 and preservation['unchanged_prior_artifacts'] == 4276
    assert set(changed) == ALLOWED
    for row in old['files']:
        expected_hash = changed[row['path']]['current_sha256'] if row['path'] in changed else row['sha256']
        assert sha(BASE/row['path']) == expected_hash, row['path']
    for row in old['inputs_preserved']:
        path = BASE/row['path']
        assert path.stat().st_size == row['size_bytes'] and sha(path) == row['sha256']
    source = Path('/Users/___/Downloads/zut/fairplayd.arm64e')
    assert sha(source) == contracts['source_sha256'] == '4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    reports = ['daemon_cache_publication_report.md', 'obfuscated_routines_report.md',
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
            assert path.exists() or path == ROOT/'daemon_cache_publication_quality_gates.json', (name, raw)
            links += 1
    report = (BASE/reports[0]).read_text()
    assert report.isascii()
    for term in ['CP16', 'QG7', '42,073,344', '40,808,448', '1,260,288', '4,608', '0x238', '588', '0x150', 'unknown', 'full daemon/kext/deeper-interface investigation remains active']:
        assert term in report, term

    scripts = list(ROOT.glob('*daemon_cache_publication*.py'))+list(ROOT.glob('*daemon_cache_relocation*.py'))
    assert len(scripts) == 14
    for path in scripts:
        ast.parse(path.read_text(), filename=str(path))
    evidence = ['Factual original-source analysis of cache population/consumption, void-call cleanup and a following record-input boundary.', 'CP1-CP16 register source identity, CF models, nine phase registers/FP, value composition, void ABI, runtime state, owners, finite bulk transforms, local byte-codec premises, marker order, B layout, foreign input, relocation, SDK and native/IPC scope with probes.', 'Current source data-flow increment covered; complete native daemon/kext/deeper-interface objective remains active and unproved.', 'Byte/word extents, endianness, u32/u64 modular arithmetic, counter order, 568+20=588 range and modeled-versus-emulated counts explicit.', 'Local universal identities, 576 finite component cases, controlled private relocations, unchanged original frontiers and unresolved native callers/owners/transport remain distinct.', '139 original fixups,4288 IDB bytes,11 rebuilt source obligations,22 SMT artifacts,576 fresh audited replays,1078272 generator updates,11520 codec values/ABI entries,SDK void signatures and nine fresh relocation runs verified.', 'Impact-ranked registry-field ownership, bulk-transform semantics, storage-address dependence, marker readers, native transport, B owner and separate runtime facilities retained.']
    out = {
        'scope': __doc__, 'generator_sha256': sha(Path(__file__)),
        **{f'QG{i}': {'status': 'pass_for_increment' if i == 3 else 'pass', 'evidence': item}
           for i, item in enumerate(evidence, 1)},
        'verified_counts': expected, 'independent_A64_totals': checks['independent_A64_totals'],
        'relocation_verified_counts': relocation['verified_counts'], 'relocation_A64_totals': relocation['independent_A64_totals'],
        'new_validation_outputs': {n: sha(ROOT/n) for n, g in pairs},
        'report_sha256': {n: sha(BASE/n) for n in reports},
        'source_sha256': sha(source), 'source_lift_counts': proofs['source_lift_counts'],
        'prior_artifacts_checked': 4282, 'unchanged_prior_artifacts': 4276,
        'checked_report_links': links, 'new_python_files_syntax_checked': len(scripts),
        'inputs_preserved': old['inputs_preserved'],
        'new_port_emission_established': False,
        'native_cache_or_driver_continuity_established': False,
        'native_target_executed': False, 'idb_mutated': False, 'full_goal_complete': False,
    }
    (ROOT/'daemon_cache_publication_quality_gates.json').write_text(json.dumps(out, indent=2)+'\n')
    print(json.dumps({'scoped_gates_pass': True, 'proof_pairs': 11, 'checked_links': links,
                      'goal_status': 'active'}), flush=True)


if __name__ == '__main__':
    main()
