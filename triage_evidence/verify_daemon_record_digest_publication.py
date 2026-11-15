#!/usr/bin/env python3
"""Fresh retained-message audit and exact publication custody.
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
import recover_daemon_record_digest as R
import audit_daemon_record_digest as A

PREVIOUS = '78e9199c713de80a1f4f1e8c43b8c2038e1bfb7c'
BASELINE_SHA = '76e5180f6df47f9dd1973c598efd0da1129583e80a331c734454756013ab5304'
CHECKS_SHA = '34ac5df9c9e8652805299b78578beec6487bdf4b6cf734a8cbc4a9a3b06239f4'
AUDIT_SHA = 'a431060e47f25bd562afe90e795d4c8d762ad767787eec3dc3bf99a1eb060244'
MANIFEST = 'triage_evidence/interface_manifest.json'
CHANGED = {'interface_investigation_status.md', 'foundational_triage_report.md', 'interface_abi_report.md',
           'obfuscated_routines_report.md', 'mach_ports_report.md', 'corefp_client_paths_report.md',
           'daemon_record_input_origin_report.md', 'daemon_core_cipher_report.md',
           'daemon_record_extension_report.md', 'daemon_record_banks_report.md', 'daemon_state_splice_report.md',
           'daemon_sha1_core_report.md', 'daemon_record_spans_report.md', 'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED = {'daemon_record_digest_report.md', 'triage_evidence/recover_daemon_record_digest.py',
         'triage_evidence/audit_daemon_record_digest.py',
         'triage_evidence/verify_daemon_record_digest_publication.py',
         'triage_evidence/daemon_record_digest_checks.json', 'triage_evidence/daemon_record_digest_audit.json'}
ARCHIVES = {MANIFEST, 'triage_evidence/daemon_record_digest_checks.json', 'triage_evidence/daemon_record_digest_audit.json'}
OWNED = ((CHANGED | ADDED)-ARCHIVES) | {p+'.zst' for p in ARCHIVES}
COUNTS = {'retained_contexts': 2, 'complete_compression_blocks': 4, 'message_bytes_per_context': 67, 'source_chunks': 262, 'source_visits': 76000, 'source_round_entries': 320, 'source_schedule_words': 320, 'input_byte_epoch_links': 256, 'message_byte_stores': 134, 'padding_byte_stores': 122, 'new_target_intervals': 0, 'new_root_bytes': 0}
TOTALS = {'source_visits': 76000, 'logical_edges': 668, 'GP_SP_values': 2440384, 'NZCV_frames': 76262, 'reads': 2846, 'writes': 612, 'chunks': 262, 'input_byte_origins_last_writer_bytes_checked': 256, 'input_byte_origins_incoming_or_image_bytes_separate': 0, 'core_read_origins_last_writer_bytes_checked': 5908, 'core_read_origins_incoming_or_image_bytes_separate': 5312, 'copy_read_origins_last_writer_bytes_checked': 768, 'copy_read_origins_incoming_or_image_bytes_separate': 422, 'original_image_message_codec_read_bytes_checked': 326, 'body_codec_bytes_checked': 96, 'body_codec_mask_rows_checked': 32, 'inherited_body_fixture_bytes_checked': 96, 'expanded_schedule_input_reads_checked': 1024, 'round_schedule_input_reads_checked': 320, 'complete_compression_blocks_checked': 4, 'source_schedule_words_checked': 320, 'source_round_entries_checked': 320, 'final_working_words_checked': 20, 'initial_IV_words_checked': 10, 'message_bytes_checked': 134, 'padded_bytes_checked': 256, 'host_SHA1_implementations_checked': 4, 'host_AES_compositions_checked': 2, 'domain_encoding_negative_controls_checked': 8, 'source_queries_unsat': 6}


def receipts():
    assert sha(ROOT/(R.P+'_checks.json')) == CHECKS_SHA and sha(ROOT/(R.P+'_audit.json')) == AUDIT_SHA
    evidence = json.loads(read(ROOT/(R.P+'_checks.json'))); audit = json.loads(read(ROOT/(R.P+'_audit.json')))
    assert evidence == R.build(); fresh = A.audit()
    old_proofs, fresh_proofs = audit.pop('source_proofs'), fresh.pop('source_proofs')
    assert audit == fresh and evidence['verified_counts'] == COUNTS and audit['independent_totals'] == TOTALS
    assert evidence['source_sha256'] == audit['source_sha256'] == sha(SOURCE) == '4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert len(old_proofs) == len(fresh_proofs) == 6
    for old, new in zip(old_proofs, fresh_proofs):
        x, y = dict(old), dict(new); p, q = z3.parse_smt2_string(x.pop('query')), z3.parse_smt2_string(y.pop('query'))
        assert x == y and x['premises_nonvacuous'] and x['result'] == 'unsat'
        assert len(p) == len(q) > 0 and all(canonical_expression(i) == canonical_expression(j) for i, j in zip(p, q))
        solver = z3.SolverFor('QF_BV'); solver.set(timeout=30000); solver.add(*p); assert solver.check() == z3.unsat
    audit['source_proofs'] = old_proofs
    assert len({p['label'] for p in old_proofs}) == 6
    report = read(BASE/'daemon_record_digest_report.md')
    assert all('| RD'+str(j)+' |' in report and '| RD-A'+str(j)+':' in report for j in range(1, 7))
    assert all('**QG'+str(j)+'**' in report for j in range(1, 8)) and CHECKS_SHA in report and AUDIT_SHA in report
    for case in evidence['cases']:
        for field in ['message67_hex', 'digest20_hex', 'record_input20_hex']:
            assert case[field] in report
        codec=case['body_codec']
        for field in ['input48_hex','decoded48_hex','mask16_hex']:
            assert codec[field] in report
        for bank in codec['fixed_bank_slices']:
            assert bank['start'] in report and bank['bytes16_hex'] in report
        for block in case['blocks']:
            assert str(block['start_visit']) in report and str(block['end_visit_exclusive']) in report
            assert all(f'{word:08x}' in report for word in block['initial_state5']+block['final_state5'])
    hygiene(evidence); hygiene(audit)
    for receipt in [evidence, audit]:
        assert receipt['retained_digest_message_identity_established'] is True
        for field in ['universal_new_compression_equivalence_established', 'native_API_executed', 'native_daemon_kext_pairing_established', 'full_goal_complete']: assert receipt[field] is False
    for p in CHANGED:
        if p.endswith(('_report.md', '_status.md')): assert 'daemon_record_digest_report.md' in read(BASE/p)
    return evidence, audit


def publication(evidence, audit):
    raw = zstd.decompress(git('show', PREVIOUS+':'+MANIFEST+'.zst')); assert sha256(raw).hexdigest() == BASELINE_SHA
    old, new = json.loads(raw), json.loads(read(BASE/MANIFEST))
    before, after = ({r['path']: r for r in m['files']} for m in [old, new])
    assert len(before) == 9090 and len(after) == 9096
    assert not before.keys()-after.keys() and after.keys()-before.keys() == ADDED
    assert {p for p in before if before[p] != after[p]} == CHANGED
    assert new['inputs_preserved'] == old['inputs_preserved'] and len(new['inputs_preserved']) == 3
    for r in new['inputs_preserved']:
        p = r['path']; assert sha(BASE/p) == r['sha256'] and size(BASE/p) == r['size_bytes']
        if git('ls-files', '--', p).decode().strip(): assert sha256(git('show', PREVIOUS+':'+p)).hexdigest() == r['sha256']
    for p in CHANGED | ADDED: assert sha(BASE/p) == after[p]['sha256'] and size(BASE/p) == after[p]['size_bytes']
    for key, value in [('increment_checks', evidence['verified_counts']), ('static_scope', evidence['scope']),
                       ('independent_checks', audit['independent_totals']), ('source_queries_unsat', 6),
                       ('retained_message67_hex', evidence['cases'][0]['message67_hex']), ('host_reference', audit['host_reference']),
                       ('retained_digest_message_identity_established', True)]:
        assert new['validation'][R.P+'_'+key] == value
    assert new['validation']['reports'] == old['validation']['reports']+1 == 561
    assert new['validation']['unavailable_external_primary_references'] == old['validation']['unavailable_external_primary_references']
    assert new['goal_status'] == 'active'
    for p in ARCHIVES: assert not (BASE/p).exists()
    for p in OWNED:
        path_hygiene((BASE/p).read_bytes()); path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    path_hygiene(git('show', '-s', '--format=fuller', 'HEAD'))
    delta = set(git('diff', '--name-only', PREVIOUS).decode().splitlines()) | set(git('ls-files', '--others', '--exclude-standard').decode().splitlines())
    assert delta == OWNED, delta ^ OWNED
    print(json.dumps({'owned_physical_files': len(OWNED), 'logical_manifest_files': len(after), 'reports': 561,
                      'original_inputs_preserved': 3, **COUNTS, **TOTALS,
                      'retained_digest_message_identity_established': True, 'analyst_paths_absent': True, 'all_checks_pass': True}), flush=True)


if __name__ == '__main__': publication(*receipts())
