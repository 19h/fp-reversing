#!/usr/bin/env python3
"""Fresh alternative-header composition, retained custody and publication audit.
O(receipt bytes + selected replay + owned bytes + proof DAG) time/space,
excluding solver search. No target operation or Git-history rewrite.
"""
import contextlib
import io
import json
from hashlib import sha256
from compression import zstd
import z3
from daemon_receive_tools import ROOT, SOURCE, IMAGE
from verify_daemon_reader_record_payloads_publication import read, sha, size
from verify_daemon_payload_mix_publication import BASE, git, hygiene, path_hygiene
from verify_daemon_second_mix_publication import canonical_expression
import recover_daemon_alternative_header as R
import audit_daemon_alternative_header as A

PREVIOUS = 'dcb6c1a4b1dde41c58174aa5f041f432f92dff46'
BASELINE_SHA = 'ce0644a2fb63b6cf982beb885f8bf52c9df8c21245c8a22c9fd0ff0b479a2dfe'
CHECKS_SHA = 'bc940ef031d5713c79d7cb4142e35463b72a0db2725a393aac339a1d3c7001e5'
AUDIT_SHA = 'fb3011f32a7a663b209de9cf2765b430dd4713edc470017a94691a9870cbdc8b'
MANIFEST = 'triage_evidence/interface_manifest.json'
CHANGED = {'corefp_client_paths_report.md', 'foundational_triage_report.md', 'interface_abi_report.md',
           'interface_investigation_status.md', 'mach_ports_report.md', 'obfuscated_routines_report.md',
           'daemon_alternative_fill_report.md', 'daemon_storage_flag_report.md', 'daemon_alternate_word_report.md',
           'daemon_record_storage_report.md', 'daemon_record_selection_report.md', 'daemon_constructor_gate_report.md',
           'daemon_state_container_construction_report.md', 'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED = {'daemon_alternative_header_report.md', 'triage_evidence/recover_daemon_alternative_header.py',
         'triage_evidence/audit_daemon_alternative_header.py', 'triage_evidence/verify_daemon_alternative_header_publication.py',
         'triage_evidence/daemon_alternative_header_checks.json', 'triage_evidence/daemon_alternative_header_audit.json'}
ARCHIVES = {MANIFEST, 'triage_evidence/daemon_alternative_header_checks.json', 'triage_evidence/daemon_alternative_header_audit.json'}
OWNED = ((CHANGED | ADDED)-ARCHIVES) | {p+'.zst' for p in ARCHIVES}
COUNTS = {'source_instructions': 739, 'source_spans': 15, 'dispatch_routes': 14,
          'retained_clear_snapshots': 76, 'saved_cells_checked': 456, 'coordinate_copy_slices': 76,
          'selected_replay_slices': 228, 'clear_U_views': 4, 'composed_source_visits': 1524,
          'caller_followup_source_instructions': 56}
INDEPENDENT = {'GP_SP_values_checked': 21888, 'Q_values_checked': 21888, 'NZCV_frames_checked': 684,
               'source_visits_checked': 456, 'read_events_checked': 0, 'write_events_checked': 304, 'slices_checked': 228}
COMPOSITION = {'source_visits': 1524, 'loads': 84, 'stores': 21, 'buffer_byte_stores': 12, 'U_field_stores': 7,
               'U_bytes_written': 40, 'U_bytes_not_written': 8, 'parent_pointer_stores': 1, 'cursor_stores': 1,
               'branches': 12, 'word_writer_invocations': 3}


def receipts():
    assert sha(ROOT/(R.P+'_checks.json')) == CHECKS_SHA
    assert sha(ROOT/(R.P+'_audit.json')) == AUDIT_SHA
    e = json.loads(read(ROOT/(R.P+'_checks.json')))
    old = json.loads(read(ROOT/(R.P+'_audit.json')))
    with contextlib.redirect_stdout(io.StringIO()):
        fresh = A.audit()
    for key, n in [('source_proofs', 36), ('scalar_controls', 5)]:
        before, after = old.pop(key), fresh.pop(key)
        assert len(before) == len(after) == n
        for x, y in zip(before, after):
            if 'query' in x:
                a, b = z3.parse_smt2_string(x.pop('query')), z3.parse_smt2_string(y.pop('query'))
                assert len(a) == len(b) > 0
                assert all(canonical_expression(c) == canonical_expression(d) for c, d in zip(a, b))
                s = z3.Solver();s.set(timeout=30000);s.add(*a)
                assert str(s.check()) == x['result']
            assert x == y
    assert old == fresh
    a = json.loads(read(ROOT/(R.P+'_audit.json')))
    assert e['generator_sha256'] == a['generator_sha256'] == sha(R.__file__)
    assert a['auditor_sha256'] == sha(A.__file__)
    assert e['dependencies'] == {p: sha(ROOT/p) for p in R.DEPS}
    assert a['dependencies'] == {p: sha(ROOT/p) for p in A.DEPS}
    assert e['source_sha256'] == a['source_sha256'] == sha(SOURCE)
    for row in e['source_spans']:
        start, end = int(row['start'], 16), int(row['end_exclusive'], 16)
        assert row['bytes_hex'] == IMAGE.read(start, end-start).hex()
    assert e['verified_counts'] == COUNTS and a['independent_totals'] == INDEPENDENT
    assert a['proof_cut_lemmas'] == 15 and a['proof_cut_applications'] == 60
    assert set(a['proof_cut_contexts_verified']) == {'generic', 'composition'}
    assert len(a['proof_cut_contexts_verified']['generic']) == 15
    assert len(a['proof_cut_contexts_verified']['composition']) == 45
    assert a['composition'] == COMPOSITION and a['target_instruction_rewrites'] == 0
    assert a['source_alternative_header_publication_contract_established']
    assert not any(a[k] for k in ['alternative_constructor_observed', 'native_cache_epoch_established',
                                  'native_parent_epoch_established', 'new_port_emission_established'])
    assert all(c['source_scalar_model_only'] and not c['native_admission_established'] for c in a['scalar_controls'])
    assert len(e['retained_clear_snapshots']) == 76 and len(e['slices']) == 228 and len(e['clear_U_views']) == 4
    assert all(s['W22_equals_saved_coordinate_at_pending_allocation'] for s in e['retained_clear_snapshots'])
    assert all(s['derived_second_word32'] == '0x7365616e' for s in e['retained_clear_snapshots'])
    assert (0x7365616e).to_bytes(4, 'big').decode('ascii') == 'sean'
    for x in [e, a]:
        assert x['new_target_intervals'] == x['new_guest_input_bytes'] == x['new_API_return_premises'] == 0
        assert not x['native_target_executed'] and not x['full_goal_complete'] and not x['prior_admissions_rerun']
        hygiene(x)
    report = read(BASE/'daemon_alternative_header_report.md')
    assert all('| AH'+str(j)+' |' in report for j in range(1,7))
    assert all('| AH-A'+str(j)+':' in report for j in range(1,9))
    assert all('**QG'+str(j)+'**' in report for j in range(1,8))
    for route in e['routes']:
        assert f"| `{route['index32']}` | `{route['target']}` | `{route['IA_modifier']}` |" in report
    assert '0x36cad8b3' in report and '0x8b3dc651' in report
    assert 'no alternative execution or native publication is observed' in report
    assert '0x100762e48' in report and 'SP+0xaf18' in report and 'SP+0xaf20' in report
    for p in CHANGED:
        if p.endswith('_report.md') or p.endswith('_status.md'):
            assert 'daemon_alternative_header_report.md' in read(BASE/p)
    return e,a


def publication(e,a):
    raw = zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest() == BASELINE_SHA
    old,new = json.loads(raw),json.loads(read(BASE/MANIFEST))
    before,after = ({r['path']:r for r in m['files']} for m in [old,new])
    assert len(before) == 9007 and len(after) == 9013
    assert not before.keys()-after.keys() and after.keys()-before.keys() == ADDED
    assert {p for p in before if before[p] != after[p]} == CHANGED
    assert new['inputs_preserved'] == old['inputs_preserved'] and len(new['inputs_preserved']) == 3
    for row in new['inputs_preserved']:
        p = row['path']
        assert sha(BASE/p) == row['sha256'] and size(BASE/p) == row['size_bytes']
        if git('ls-files','--',p).decode().strip():
            assert sha256(git('show',PREVIOUS+':'+p)).hexdigest() == row['sha256']
    for p in CHANGED | ADDED:
        assert sha(BASE/p) == after[p]['sha256'] and size(BASE/p) == after[p]['size_bytes']
    for key,value in [('increment_checks',COUNTS),('static_scope',e['scope']),('independent_checks',INDEPENDENT),
                       ('source_queries_unsat',36),('scalar_controls',5),('proof_cut_contexts',60),('composition',COMPOSITION),('new_target_intervals',0)]:
        assert new['validation'][R.P+'_'+key] == value
    assert new['validation']['reports'] == old['validation']['reports']+1 == 548
    assert new['validation']['unavailable_external_primary_references'] == old['validation']['unavailable_external_primary_references']
    assert new['goal_status'] == 'active'
    for p in ARCHIVES:
        assert not (BASE/p).exists()
    for p in OWNED:
        path_hygiene((BASE/p).read_bytes())
        path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta = set(git('diff','--name-only',PREVIOUS).decode().splitlines()) | set(git('ls-files','--others','--exclude-standard').decode().splitlines())
    assert delta == OWNED,delta ^ OWNED
    print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':548,
        'original_inputs_preserved':3,**COUNTS,'source_queries_unsat':36,'scalar_controls':5,
        'proof_cut_contexts':60,'new_target_intervals':0,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)


if __name__=='__main__':
    publication(*receipts())
