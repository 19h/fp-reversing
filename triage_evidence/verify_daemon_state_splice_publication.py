#!/usr/bin/env python3
"""Fresh complete-state-format audit and exact publication custody.
O(receipts + source DAGs + audit + owned bytes + proof DAG) time/space;
solver search additional. No native target, IDB action or history rewrite.
"""
import json
from hashlib import sha256
from compression import zstd
import z3
from daemon_receive_tools import ROOT, SOURCE
from verify_daemon_reader_record_payloads_publication import read, sha, size
from verify_daemon_payload_mix_publication import BASE, git, hygiene, path_hygiene
from verify_daemon_second_mix_publication import canonical_expression
import recover_daemon_state_splice as R
import audit_daemon_state_splice as A

PREVIOUS = 'a0d18ccbfaad1c41b904440318627fe45d1424b2'
BASELINE_SHA = '13f79d4bf5cba131db82c351b66f27a25359aea8192aba946da6bcd57657819c'
CHECKS_SHA = '850a325d4f00433f9dc33bafb04344c95e2887b09e048f9c90aaa1adf900b066'
AUDIT_SHA = '96bcc09acbe63d071a6363a9cf6e666b6826710febeba1ac68dde8cb4d736161'
MANIFEST = 'triage_evidence/interface_manifest.json'
CHANGED = {'interface_investigation_status.md', 'foundational_triage_report.md', 'interface_abi_report.md',
           'obfuscated_routines_report.md', 'mach_ports_report.md', 'corefp_client_paths_report.md',
           'daemon_record_input_origin_report.md', 'daemon_core_cipher_report.md',
           'daemon_record_extension_report.md', 'daemon_record_banks_report.md', 'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED = {'daemon_state_splice_report.md', 'triage_evidence/recover_daemon_state_splice.py',
         'triage_evidence/audit_daemon_state_splice.py', 'triage_evidence/daemon_state_splice_kernel.py',
         'triage_evidence/verify_daemon_state_splice_publication.py',
         'triage_evidence/daemon_state_splice_checks.json', 'triage_evidence/daemon_state_splice_audit.json'}
ARCHIVES = {MANIFEST, 'triage_evidence/daemon_state_splice_checks.json', 'triage_evidence/daemon_state_splice_audit.json'}
OWNED = ((CHANGED | ADDED)-ARCHIVES) | {p+'.zst' for p in ARCHIVES}
COUNTS = {'retained_contexts': 2, 'source_chunks': 24, 'source_visits': 468, 'word_epochs': 10,
          'state_reuse_byte_stores': 40, 'retained_frontier_values_checked': 608,
          'new_target_intervals': 0, 'new_root_bytes': 0}
TOTALS = {'source_visits': 468, 'GP_SP_values': 15744, 'NZCV_frames': 492, 'reads': 54, 'writes': 92,
          'chunks': 24, 'logical_edges': 2, 'word_epoch_bytes_checked': 40, 'state_reuse_bytes_checked': 40,
          'output_pointer_epoch_bytes_checked': 16, 'retained_frontier_exports_checked': 608,
          'complete_format_vectors_checked': 196, 'source_serializer_words_checked': 980,
          'source_formatter_bytes_checked': 3920, 'host_AES_roundtrip_blocks_checked': 196,
          'edge_bit_controls_checked': 32, 'middle_bit_controls_checked': 128,
          'source_queries_unsat': 4, 'formatter_alias_controls_checked': 2}


def receipts():
    assert sha(ROOT/(R.P+'_checks.json')) == CHECKS_SHA and sha(ROOT/(R.P+'_audit.json')) == AUDIT_SHA
    evidence = json.loads(read(ROOT/(R.P+'_checks.json'))); audit = json.loads(read(ROOT/(R.P+'_audit.json')))
    assert evidence == R.build(); fresh = A.audit()
    old_proofs, fresh_proofs = audit.pop('source_proofs'), fresh.pop('source_proofs')
    assert audit == fresh and evidence['verified_counts'] == COUNTS and audit['independent_totals'] == TOTALS
    assert evidence['source_sha256'] == audit['source_sha256'] == sha(SOURCE) == '4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert len(old_proofs) == len(fresh_proofs) == 4
    for old, new in zip(old_proofs, fresh_proofs):
        x, y = dict(old), dict(new); p, q = z3.parse_smt2_string(x.pop('query')), z3.parse_smt2_string(y.pop('query'))
        assert x == y and x['premises_nonvacuous'] and x['result'] == 'unsat'
        assert len(p) == len(q) > 0 and all(canonical_expression(i) == canonical_expression(j) for i, j in zip(p, q))
        solver = z3.SolverFor('QF_UFBV'); solver.set(timeout=30000); solver.add(*p); assert solver.check() == z3.unsat
    audit['source_proofs'] = old_proofs
    assert len({p['label'] for p in old_proofs}) == 4
    report = read(BASE/'daemon_state_splice_report.md')
    assert all('| SS'+str(j)+' |' in report and '| SS-A'+str(j)+':' in report for j in range(1, 7))
    assert all('**QG'+str(j)+'**' in report for j in range(1, 8)) and CHECKS_SHA in report and AUDIT_SHA in report
    for case in evidence['cases']:
        for field in ['key16_hex', 'decoded20_hex', 'AES_plaintext16_hex', 'AES_ciphertext16_hex',
                      'serialized20_hex', 'record_input20_hex']:
            assert case[field] in report
        for row in case['word_epochs']:
            for field in ['writer_pc', 'encoded32', 'decoded32']:
                assert row[field].removeprefix('0x') in report
            assert str(row['writer_visit']) in report and str(row['reader_visit']) in report
    hygiene(evidence); hygiene(audit)
    for receipt in [evidence, audit]:
        assert receipt['conditional_state_format_established'] is True
        for field in ['digest_message_identity_established', 'native_API_executed', 'native_daemon_kext_pairing_established', 'full_goal_complete']: assert receipt[field] is False
    for p in CHANGED:
        if p.endswith(('_report.md', '_status.md')): assert 'daemon_state_splice_report.md' in read(BASE/p)
    return evidence, audit


def publication(evidence, audit):
    raw = zstd.decompress(git('show', PREVIOUS+':'+MANIFEST+'.zst')); assert sha256(raw).hexdigest() == BASELINE_SHA
    old, new = json.loads(raw), json.loads(read(BASE/MANIFEST))
    before, after = ({r['path']: r for r in m['files']} for m in [old, new])
    assert len(before) == 9083 and len(after) == 9090
    assert not before.keys()-after.keys() and after.keys()-before.keys() == ADDED
    assert {p for p in before if before[p] != after[p]} == CHANGED
    assert new['inputs_preserved'] == old['inputs_preserved'] and len(new['inputs_preserved']) == 3
    for r in new['inputs_preserved']:
        p = r['path']; assert sha(BASE/p) == r['sha256'] and size(BASE/p) == r['size_bytes']
        if git('ls-files', '--', p).decode().strip(): assert sha256(git('show', PREVIOUS+':'+p)).hexdigest() == r['sha256']
    for p in CHANGED | ADDED: assert sha(BASE/p) == after[p]['sha256'] and size(BASE/p) == after[p]['size_bytes']
    for key, value in [('increment_checks', evidence['verified_counts']), ('static_scope', evidence['scope']),
                       ('independent_checks', audit['independent_totals']), ('source_queries_unsat', 4),
                       ('format_contract', evidence['format_contract']), ('host_reference', audit['host_reference'])]:
        assert new['validation'][R.P+'_'+key] == value
    assert new['validation']['reports'] == old['validation']['reports']+1 == 560
    assert new['validation']['unavailable_external_primary_references'] == old['validation']['unavailable_external_primary_references']
    assert new['goal_status'] == 'active'
    for p in ARCHIVES: assert not (BASE/p).exists()
    for p in OWNED:
        path_hygiene((BASE/p).read_bytes()); path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    path_hygiene(git('show', '-s', '--format=fuller', 'HEAD'))
    delta = set(git('diff', '--name-only', PREVIOUS).decode().splitlines()) | set(git('ls-files', '--others', '--exclude-standard').decode().splitlines())
    assert delta == OWNED, delta ^ OWNED
    print(json.dumps({'owned_physical_files': len(OWNED), 'logical_manifest_files': len(after), 'reports': 560,
                      'original_inputs_preserved': 3, **COUNTS, **TOTALS,
                      'conditional_state_format_established': True, 'analyst_paths_absent': True, 'all_checks_pass': True}), flush=True)


if __name__ == '__main__': publication(*receipts())
