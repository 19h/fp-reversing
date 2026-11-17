#!/usr/bin/env python3
"""Rebuild parser completion receipts and check the exact publication delta."""
import json

from compression import zstd

import audit_userclient_nonzero_tag_completion as audit
import recover_userclient_nonzero_tag_completion as source
from verify_daemon_payload_mix_publication import BASE, git, hygiene, path_hygiene
from verify_daemon_reader_record_payloads_publication import read, sha, size
from verify_kernel_magazine_bootstrap_delivery import nested_hygiene
from verify_userclient_nonzero_tag_record_delivery import compare_queries

PREVIOUS = '52d5a741bc11b0677d4329539145a9fa45d09532'
MANIFEST = 'triage_evidence/interface_manifest.json'
REPORT = source.NAME + '_report.md'
CHECKS = 'triage_evidence/' + source.NAME + '_checks.json'
AUDIT = 'triage_evidence/' + source.NAME + '_audit.json'
ADDED = {
    REPORT, CHECKS, AUDIT,
    'triage_evidence/recover_' + source.NAME + '.py',
    'triage_evidence/audit_' + source.NAME + '.py',
    'triage_evidence/verify_' + source.NAME + '_delivery.py',
}
CHANGED = {
    'foundational_triage_report.md', 'interface_abi_report.md', 'interface_investigation_status.md',
    'mach_ports_report.md', 'obfuscated_routines_report.md', 'userclient_nonzero_tag_record_report.md',
    'userclient_parser_cleanup_report.md', 'triage_evidence/validate_rpc502_sidecar_delivery.py',
}
ARCHIVES = {MANIFEST, CHECKS, AUDIT}
OWNED = {path + '.zst' if path in ARCHIVES else path for path in ADDED | CHANGED | {MANIFEST}}


def receipts():
    checks = json.loads(read(BASE / CHECKS))
    saved = json.loads(read(BASE / AUDIT))
    assert checks == source.build()
    fresh = audit.audit(checks)
    for field, count in (('source_proofs', 11), ('negative_source_controls', 2)):
        assert len(saved[field]) == count
        compare_queries(saved.pop(field), fresh.pop(field), 'query')
    assert fresh == saved and saved['all_checks_pass']
    assert not saved['native_target_executed'] and not saved['full_goal_complete']
    profiles = saved['profiles']
    assert [(p['body_bytes'], p['suffix_bytes']) for p in profiles] == [(n, 4 - n) for n in range(5)]
    assert [p['terminal_target'] for p in profiles] == ['0xfffffe000a65f358'] * 4 + ['0xfffffe000a662ab4']
    assert [len(p['ordinary_retirement_returns']) for p in profiles] == [3, 3, 3, 3, 0]
    assert len(checks['prefix_receipts']) == 30 and all(len(row['cells']) == 7 for row in checks['prefix_receipts'])
    report = read(BASE / REPORT)
    assert sha(BASE / CHECKS) in report and sha(BASE / AUDIT) in report
    assert all(f'**QG{gate}** passed' in report for gate in range(1, 8))
    for path in CHANGED:
        if path.endswith('.md'):
            assert REPORT in read(BASE / path)


def publication():
    old = json.loads(zstd.decompress(git('show', PREVIOUS + ':' + MANIFEST + '.zst')))
    new = json.loads(read(BASE / MANIFEST))
    before, after = ({r['path']: r for r in m['files']} for m in (old, new))
    assert not before.keys() - after.keys() and after.keys() - before.keys() == ADDED
    assert {path for path in before if before[path] != after[path]} == CHANGED
    assert old['inputs_preserved'] == new['inputs_preserved']
    for row in new['inputs_preserved']:
        artifact = BASE / row['path']
        assert sha(artifact) == row['sha256'] and size(artifact) == row['size_bytes']
    for path in ADDED | CHANGED:
        artifact = BASE / path
        assert sha(artifact) == after[path]['sha256'] and size(artifact) == after[path]['size_bytes']
    for path in OWNED:
        payload = (BASE / path).read_bytes()
        path_hygiene(payload)
        if path.endswith('.json.zst'):
            decoded = zstd.decompress(payload)
            path_hygiene(decoded)
            obj = json.loads(decoded)
            hygiene(obj)
            nested_hygiene(obj)
    assert all(not (BASE / path).exists() for path in ARCHIVES)
    delta = set(git('diff', '--name-only', PREVIOUS).decode().splitlines())
    delta.update(git('ls-files', '--others', '--exclude-standard').decode().splitlines())
    assert delta == OWNED, delta ^ OWNED
    assert new['validation']['reports'] == old['validation']['reports'] + 1
    assert new['goal_status'] == 'active'
    print(json.dumps({'publication_verified': True, 'owned_files': len(OWNED), 'manifest_entries': len(after),
                      'manifest_decoded_sha256': sha(BASE / MANIFEST), 'reports': new['validation']['reports'],
                      'links': new['validation']['local_markdown_links']}), flush=True)


if __name__ == '__main__':
    receipts()
    publication()
