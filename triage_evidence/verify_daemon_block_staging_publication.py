#!/usr/bin/env python3
"""Fresh extraction/replay/proofs and exact staged/publication custody.
O(receipts + selected replay + owned bytes + proof DAG) time/space;
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
import recover_daemon_block_staging as R
import audit_daemon_block_staging as A

PREVIOUS = '43daf83cfde87671f4d45be6976b2437be97d9ac'
BASELINE_SHA = 'ed0074d9d4b86d04a4394ebe91c4bdf35c81ebf72d1d410e03387c117044bf11'
CHECKS_SHA = 'f544501de6a7ceefa17c5bba23a8f1de5137bbf8cd53d812e66b8e5e5a0e00a6'
AUDIT_SHA = '32c63b8e3feb6e3b780522f721ce65e1033e4a079f8aa7e1f74bc49b39cdeb89'
MANIFEST = 'triage_evidence/interface_manifest.json'
CHANGED = {'interface_investigation_status.md', 'foundational_triage_report.md', 'interface_abi_report.md',
           'obfuscated_routines_report.md', 'mach_ports_report.md', 'corefp_client_paths_report.md',
           'daemon_record_input_origin_report.md', 'daemon_record_banks_report.md',
           'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED = {'daemon_block_staging_report.md', 'triage_evidence/recover_daemon_block_staging.py',
         'triage_evidence/audit_daemon_block_staging.py', 'triage_evidence/verify_daemon_block_staging_publication.py',
         'triage_evidence/daemon_block_staging_checks.json', 'triage_evidence/daemon_block_staging_audit.json'}
ARCHIVES = {MANIFEST, 'triage_evidence/daemon_block_staging_checks.json', 'triage_evidence/daemon_block_staging_audit.json'}
OWNED = ((CHANGED | ADDED)-ARCHIVES) | {p+'.zst' for p in ARCHIVES}
COUNTS = {'retained_classes': 2, 'selected_chunks': 68, 'source_visits': 4580, 'staged_input_bytes': 32,
          'staged_output_bytes': 32, 'core_word_table_reads': 320, 'mask_bank_bytes_checked': 192,
          'immutable_word_banks': 8, 'immutable_word_rows': 2048, 'immutable_word_bytes': 8192,
          'immutable_mask_windows': 6, 'immutable_mask_bytes': 96, 'new_target_intervals': 0, 'new_root_bytes': 0}
TOTALS = {'source_visits': 4580, 'GP_SP_values': 148736, 'NZCV_frames': 4648, 'reads': 1360,
          'writes': 102, 'chunks': 68, 'logical_edges': 64, 'core_table_reads_checked': 320,
          'immutable_mask_window_bytes_checked': 192, 'original_mask_bank_bytes_checked': 192,
          'mask_byte_involution_controls': 16384, 'immutable_word_bytes_checked': 8192}


def receipts():
    assert sha(ROOT/(R.P+'_checks.json')) == CHECKS_SHA and sha(ROOT/(R.P+'_audit.json')) == AUDIT_SHA
    e = json.loads(read(ROOT/(R.P+'_checks.json'))); a = json.loads(read(ROOT/(R.P+'_audit.json')))
    assert e == R.build(); fresh = A.audit()
    old_proofs, fresh_proofs = a.pop('source_proofs'), fresh.pop('source_proofs')
    assert a == fresh and e['verified_counts'] == COUNTS and a['independent_totals'] == TOTALS
    assert e['source_sha256'] == a['source_sha256'] == sha(SOURCE) == '4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert len(old_proofs) == len(fresh_proofs) == a['source_queries_unsat'] == 15
    for old, new in zip(old_proofs, fresh_proofs):
        x, y = dict(old), dict(new); p, q = z3.parse_smt2_string(x.pop('query')), z3.parse_smt2_string(y.pop('query'))
        assert x == y and x['premises_nonvacuous'] and x['result'] == 'unsat'
        assert len(p) == len(q) > 0 and all(canonical_expression(i) == canonical_expression(j) for i, j in zip(p, q))
        s = z3.Solver(); s.set(timeout=30000); s.add(*p); assert s.check() == z3.unsat
    a['source_proofs'] = old_proofs
    names = {p['label'] for p in old_proofs}; assert len(names) == 15
    assert len(a['certified_rewrites']) == 3 and all(p['qualifying_proof'] in names for p in a['certified_rewrites'])
    derived = a['derived_key_equivalence']; assert set(derived['qualifying_proofs']) <= names
    assert int(derived['multiplier32'], 16)*int(derived['inverse32'], 16) % (1 << 32) == 1
    assert len(a['controls']['alignment_cases']) == 16 and sum(c['roundtrip_matches'] for c in a['controls']['alignment_cases']) == 4
    hygiene(e); hygiene(a)
    for receipt in [e, a]:
        for field in ['native_API_executed', 'native_daemon_kext_pairing_established',
                      'transform_algorithm_established', 'full_goal_complete']: assert receipt[field] is False
    report = read(BASE/'daemon_block_staging_report.md')
    assert all('| BS'+str(j)+' |' in report and '| BS-A'+str(j)+':' in report for j in range(1, 7))
    assert all('**QG'+str(j)+'**' in report for j in range(1, 8)) and CHECKS_SHA in report and AUDIT_SHA in report
    for c in e['cases']:
        assert all(value in report for value in c['vectors'].values())
        assert all(value in report for value in c['mask16_hex'].values())
    assert a['controls']['relocation_without_rekey_counterexample']['wrong_decoded_index32'] in report
    for p in CHANGED:
        if p.endswith(('_report.md', '_status.md')): assert 'daemon_block_staging_report.md' in read(BASE/p)
    return e, a


def publication(e, a):
    raw = zstd.decompress(git('show', PREVIOUS+':'+MANIFEST+'.zst')); assert sha256(raw).hexdigest() == BASELINE_SHA
    old, new = json.loads(raw), json.loads(read(BASE/MANIFEST))
    before, after = ({r['path']: r for r in m['files']} for m in [old, new])
    assert len(before) == 9049 and len(after) == 9055
    assert not before.keys()-after.keys() and after.keys()-before.keys() == ADDED
    assert {p for p in before if before[p] != after[p]} == CHANGED
    assert new['inputs_preserved'] == old['inputs_preserved'] and len(new['inputs_preserved']) == 3
    for r in new['inputs_preserved']:
        p = r['path']; assert sha(BASE/p) == r['sha256'] and size(BASE/p) == r['size_bytes']
        if git('ls-files', '--', p).decode().strip(): assert sha256(git('show', PREVIOUS+':'+p)).hexdigest() == r['sha256']
    for p in CHANGED | ADDED: assert sha(BASE/p) == after[p]['sha256'] and size(BASE/p) == after[p]['size_bytes']
    for key, value in [('increment_checks', e['verified_counts']), ('static_scope', e['scope']),
                       ('independent_checks', a['independent_totals']), ('source_queries_unsat', 15),
                       ('certified_rewrites', a['certified_rewrites']), ('derived_key_equivalence', a['derived_key_equivalence']),
                       ('controls', a['controls'])]: assert new['validation'][R.P+'_'+key] == value
    assert new['validation']['reports'] == old['validation']['reports']+1 == 555
    assert new['validation']['unavailable_external_primary_references'] == old['validation']['unavailable_external_primary_references']
    assert new['goal_status'] == 'active'
    for p in ARCHIVES: assert not (BASE/p).exists()
    for p in OWNED:
        path_hygiene((BASE/p).read_bytes()); path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    path_hygiene(git('show', '-s', '--format=fuller', 'HEAD'))
    delta = set(git('diff', '--name-only', PREVIOUS).decode().splitlines()) | set(git('ls-files', '--others', '--exclude-standard').decode().splitlines())
    assert delta == OWNED, delta ^ OWNED
    print(json.dumps({'owned_physical_files': len(OWNED), 'logical_manifest_files': len(after), 'reports': 555,
                      'original_inputs_preserved': 3, **COUNTS, 'source_queries_unsat': 15,
                      'certified_rewrites': 3, 'analyst_paths_absent': True, 'all_checks_pass': True}), flush=True)


if __name__ == '__main__': publication(*receipts())
