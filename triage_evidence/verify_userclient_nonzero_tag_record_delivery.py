#!/usr/bin/env python3
"""Rebuild first-record receipts and verify the publication delta."""
import json
from compression import zstd
from hashlib import sha256

import audit_userclient_nonzero_tag_record as A
import recover_userclient_nonzero_tag_record as R
from kext_port_tools import ROOT, SOURCE
from verify_daemon_payload_mix_publication import BASE, git, hygiene, path_hygiene
from verify_daemon_reader_record_payloads_publication import read, sha, size
from verify_kernel_magazine_bootstrap_delivery import nested_hygiene
from verify_userclient_message_initialization_delivery import equivalent_queries

PREVIOUS = '8ae014681050133ff8b0778fca7340efb4e8f5f4'
BASELINE_SHA = '642a7fba930648f0a8d8adb95f8b67f992153139794d06f11d67a05eb38bfda0'
MANIFEST = 'triage_evidence/interface_manifest.json'
REPORT = R.P + '_report.md'
CHECKS = 'triage_evidence/' + R.P + '_checks.json'
AUDIT = 'triage_evidence/' + R.P + '_audit.json'
ADDED = {
    REPORT, CHECKS, AUDIT,
    'triage_evidence/recover_' + R.P + '.py',
    'triage_evidence/audit_' + R.P + '.py',
    'triage_evidence/verify_' + R.P + '_delivery.py',
}
CHANGED = set(["foundational_triage_report.md","interface_abi_report.md","interface_investigation_status.md","mach_ports_report.md","obfuscated_routines_report.md","userclient_fallback_metadata_report.md","userclient_record_nodes_report.md","userclient_record_writer_report.md","userclient_record_publication_report.md","userclient_zero_tag_provider_report.md","triage_evidence/validate_rpc502_sidecar_delivery.py"])
ARCHIVES = {MANIFEST, CHECKS, AUDIT}
OWNED = {p + '.zst' if p in ARCHIVES else p for p in ADDED | CHANGED | {MANIFEST}}
COUNTS = {
    'source_spans': 30, 'captured_words': 730, 'prefix_words': 14,
    'bank_rules': 3, 'bank_inputs_checked': 768, 'original_pointer_observations': 33,
    'prefix_states': 30, 'reconstructed_prefix_cells': 90,
    'reconstructed_prefix_bytes': 600, 'protected_input_extent_bytes': 14,
    'header_bytes': 10, 'body_lengths_checked': 5, 'new_node_bytes': 32,
    'container_bytes': 16, 'native_target_calls': 0, 'input_content_bytes_supplied': 0,
}
TOTALS = {
    'new_source_queries_unsat': 182, 'continuation_and_setup_queries_unsat': 22,
    'projection_queries_unsat': 148, 'domain_queries_unsat': 2,
    'geometry_queries_unsat': 10, 'prior_queries_unsat': 205,
    'actual_cut_admissions_sat': 30, 'negative_source_controls': 3,
    'profile_instruction_instances': 10161, 'access_instances': 1645,
    'combined_source_words': 1020, 'live_register_views': 19,
    'live_initial_cells': 35, 'normal_pointer_guards': 22,
    'initial_parent_pointer_guards': 11, 'new_allocation_pointer_guards': 11,
}


def compare_queries(old, new, field):
    assert len(old) == len(new)
    for saved, fresh in zip(old, new):
        saved, fresh = dict(saved), dict(fresh)
        equivalent_queries(saved.pop(field), fresh.pop(field))
        assert saved == fresh


def receipts(*, rebuild=True):
    evidence = json.loads(read(BASE / CHECKS))
    saved = json.loads(read(BASE / AUDIT))
    assert evidence == R.build()
    assert saved['auditor_sha256'] == sha(A.__file__)
    if rebuild:
        fresh = A.audit(evidence)
        old, new = dict(saved), dict(fresh)
        for key in ('source_proofs', 'actual_cut_admissions'):
            compare_queries(old.pop(key), new.pop(key), 'query')
        key = 'negative_source_controls'
        compare_queries(old.pop(key), new.pop(key), 'satisfiable_violation_query')
        assert old == new
    assert saved['checks_sha256'] == sha(BASE / CHECKS)
    assert saved['verified_counts'] == evidence['verified_counts'] == COUNTS
    assert saved['independent_totals'] == TOTALS
    assert saved['all_checks_pass']
    assert len(saved['source_proofs']) == 182 and all(
        p['result'] == 'unsat' and p['premises_nonvacuous'] for p in saved['source_proofs'])
    assert len(saved['rechecked_prior_proofs']) == 205 and all(
        p['result'] == 'unsat' for p in saved['rechecked_prior_proofs'])
    assert len(saved['actual_cut_admissions']) == 30 and all(
        p['result'] == 'sat' and not p['native_allocation_outcomes_or_reachability_established']
        for p in saved['actual_cut_admissions'])
    assert [p['record_bytes_written'] for p in saved['access_footprint']['successful_record_write_profiles']] == list(range(10,15))
    assert evidence['source_sha256'] == saved['source_sha256'] == sha(SOURCE)
    assert evidence['kernel_collection_sha256'] == saved['kernel_collection_sha256']
    for artifact in (evidence, saved):
        hygiene(artifact)
        nested_hygiene(artifact)
        assert artifact['conditional_nonzero_tag_record_established'] is True
        assert all(artifact[k] is False for k in R.FALSE)
    report = read(BASE / REPORT)
    assert sha(BASE / CHECKS) in report and sha(BASE / AUDIT) in report
    assert all(f'**QG{j}** passed' in report for j in range(1,8))
    assert all(f'| NZ{j} |' in report and f'| NZ-A{j}.' in report for j in range(1,8))
    for path in CHANGED:
        if path.endswith('.md'):
            assert REPORT in read(BASE / path)
    print(json.dumps({'receipts_verified': True, 'queries_rebuilt_here': rebuild, **TOTALS}), flush=True)
    return evidence, saved


def publication(evidence, audit):
    data = zstd.decompress(git('show', PREVIOUS + ':' + MANIFEST + '.zst'))
    assert sha256(data).hexdigest() == BASELINE_SHA
    old, new = json.loads(data), json.loads(read(BASE / MANIFEST))
    before, after = ({r['path']:r for r in m['files']} for m in (old,new))
    assert len(before) == 9793 and len(after) == 9799
    assert not before.keys() - after.keys() and after.keys() - before.keys() == ADDED
    assert {p for p in before if before[p] != after[p]} == CHANGED
    assert old['inputs_preserved'] == new['inputs_preserved'] and len(new['inputs_preserved']) == 3
    for row in new['inputs_preserved']:
        path = row['path']
        assert sha(BASE / path) == row['sha256'] and size(BASE / path) == row['size_bytes']
        if git('ls-files','--',path).strip():
            assert sha256(git('show',PREVIOUS+':'+path)).hexdigest() == row['sha256']
    for path in CHANGED | ADDED:
        assert sha(BASE / path) == after[path]['sha256'] and size(BASE / path) == after[path]['size_bytes']
    validation = new['validation']
    expected = {
        'increment_checks': evidence['verified_counts'], 'static_scope': evidence['scope'],
        'independent_checks': audit['independent_totals'], 'new_source_queries_unsat': 182,
        'prior_queries_unsat': 205, 'negative_source_controls': 3,
    }
    for suffix,value in expected.items():
        assert validation[R.P+'_'+suffix] == value
    assert validation['reports'] == old['validation']['reports'] + 1 == 665
    assert new['goal_status'] == 'active'
    assert validation['unavailable_external_primary_references'] == old['validation']['unavailable_external_primary_references']
    for path in ARCHIVES:
        assert not (BASE / path).exists()
    blobs = {}
    for path in sorted(OWNED):
        raw = (BASE / path).read_bytes()
        path_hygiene(raw)
        decoded = zstd.decompress(raw) if path.endswith('.zst') else raw
        path_hygiene(decoded)
        if path.endswith('.json.zst'):
            obj = json.loads(decoded)
            hygiene(obj)
            nested_hygiene(obj)
        blobs[path] = sha256(raw).hexdigest()
    delta = set(git('diff','--name-only',PREVIOUS).decode().splitlines())
    delta.update(git('ls-files','--others','--exclude-standard').decode().splitlines())
    assert delta == OWNED, delta ^ OWNED
    print(json.dumps({
        'owned_physical_sha256': blobs, 'logical_manifest_files': len(after),
        'manifest_sha256': sha(BASE / MANIFEST), 'reports': validation['reports'],
        'local_markdown_links': validation['local_markdown_links'],
        'original_inputs_preserved': 3, 'path_hygiene_passed': True,
    }), flush=True)


if __name__ == '__main__':
    publication(*receipts())
