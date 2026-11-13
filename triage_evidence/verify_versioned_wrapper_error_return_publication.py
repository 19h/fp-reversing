#!/usr/bin/env python3
"""Audit wrapper return, byte epochs, result component and publication delta.

O(receipt+owned decoded bytes+manifest) time/space plus 30 s/query. Source
reproduction is separate from the independent byte/provenance audit. No native
API, guest execution, IDA mutation or Git-history rewrite is performed.
"""
import json
import subprocess
from collections import Counter
from hashlib import sha256
from pathlib import Path
from compression import zstd
import z3
from verify_daemon_reader_record_payloads_publication import read, sha, size
from verify_lskd_vector_origin_publication import path_hygiene
from verify_versioned_stream_initialization_publication import no_queries
from recover_kext_cold_init import pointer
from kernel_native_reader import Kernel
from kext_port_tools import IMAGE
import verify_corefp_late_preparation_publication as H
import verify_versioned_error_release_publication as A
import recover_versioned_wrapper_error_return as R

ROOT = Path(__file__).resolve().parent
BASE = ROOT.parent
PREVIOUS = '95d5b2fc48a54a825951d566396ad370ab6a055a'
BASELINE_SHA = '1187004aec7793460a090f24c2421c62e1c8320c59e01639d87a61c18a3345e1'
CHECKS_SHA = '745b927fe59d20ae447a18c49d99656dc0096a7ab37a7220dbe6126e772d0ae4'
MANIFEST = 'triage_evidence/interface_manifest.json'
CHANGED = {'corefp_client_paths_report.md', 'foundational_triage_report.md',
           'interface_abi_report.md', 'interface_investigation_status.md',
           'mach_ports_report.md', 'obfuscated_routines_report.md',
           'versioned_error_release_report.md', 'versioned_request_abi_report.md',
           'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED = {'versioned_wrapper_error_return_report.md',
         'triage_evidence/recover_versioned_wrapper_error_return.py',
         'triage_evidence/verify_versioned_wrapper_error_return_publication.py',
         'triage_evidence/versioned_wrapper_error_return_checks.json'}
ARCHIVES = {MANIFEST, 'triage_evidence/versioned_wrapper_error_return_checks.json'}
OWNED = ((CHANGED | ADDED) - ARCHIVES) | {p + '.zst' for p in ARCHIVES}
COUNTS = {'parent_cases': 8, 'retained_intervals': 24,
          'separate_UserClient_components': 8, 'component_source_visits': 24,
          'source_queries_unsat': 3, 'source_lift_instructions': 8,
          'source_branch_instructions_checked': 1,
          'source_visits': 584, 'authenticated_transfers': 0, 'source_returns': 16,
          'unique_observables_proved': 0, 'source_read_bytes': 1968,
          'source_write_bytes': 32}

def git(*args):
    return subprocess.check_output(['git', *args], cwd=BASE)

def snapshot(snap, state, known):
    a, n = int(snap['address'], 16), snap['size_bytes']
    assert snap['known_mask_hex'] == bytes(int(j in known) for j in range(a, a+n)).hex()
    for j, term in enumerate(snap['terms'], a):
        expected = ({'origin': 'unspecified byte; no source definition in retained epoch'}
                    if j not in known else {'bytes_hex': bytes([state[j]]).hex()}
                    if isinstance(state[j], int) else {'expression': state[j]})
        assert term == expected
    return n

def receipts(fresh=True):
    assert sha(ROOT / (R.P + '_checks.json')) == CHECKS_SHA
    e = json.loads(read(ROOT / (R.P + '_checks.json')))
    if fresh:
        assert no_queries(R.build()) == no_queries(e)
    assert e['verified_counts'] == COUNTS and e['generator_sha256'] == sha(R.__file__)
    assert e['dependencies'] == {n: sha(ROOT/n) for n in e['dependencies']}
    assert e['parent_checks_sha256'] == R.PIN == sha(ROOT/'versioned_error_release_checks.json')
    for q in e['source_proofs']:
        solver = z3.Solver(); solver.set(timeout=30000); solver.from_string(q['query'])
        assert q['result'] == 'unsat' and q['premises_nonvacuous'] and solver.check() == z3.unsat
    k = Kernel()
    assert k.sha256 == e['kernel_collection_sha256']
    for name in ['wrapper_source', 'UserClient_source', 'provider_adapter_source']:
        f = e[name]; a, z = int(f['start'], 16), int(f['end'], 16)
        assert k.read(a, z-a).hex() == IMAGE.read(a, z-a).hex() == f['bytes_hex']
        assert sha256(bytes.fromhex(f['bytes_hex'])).hexdigest() == f['sha256']
    assert e['workspace_free_source'] == k.function(0xfffffe000c4b9a24)
    assert e['workspace_free_symbols'] == k.symbols([0xfffffe000c4b9a24])
    assert any(s['name'] == '_IOFreeAligned' for s in e['workspace_free_symbols']['0xfffffe000c4b9a24'])
    adapter = e['provider_adapter_source']['instructions']
    assert len(adapter) == 13 and adapter[-1] == {'ea': '0xfffffe000a504ed0', 'mnemonic': 'b', 'operands': '#0xfffffe000a5a2bac'}
    hand = json.loads(read(ROOT/'versioned_lock_handoff_checks.json'))
    ha = json.loads(read(ROOT/'versioned_hardware_admission_checks.json'))
    parent = json.loads(read(ROOT/'versioned_error_release_checks.json'))
    prep = json.loads(read(ROOT/'versioned_core_preparation_checks.json'))
    count = Counter()
    for case in e['cases']:
        ix = case['parent_case_index']; p = prep['cases'][ix]
        state, known, ap, _ = A.A.base_state(ix, hand, k)
        h = next(c for c in ha['cases'] if c['parent_case_index'] == ix)
        for name in ['strict_initializer_prefix', 'arbitrary_readiness_origin', 'cold_matching_request', 'matching_return', 'wait_return', 'provider_absent']:
            state, known, _ = A.A.epochs(h['branches'][name], state, known, k)
        h1 = int(ap['input_stream_at_boundary']['address'], 16); h2 = h1+0x200
        h3 = int(ap['declared_distinct_object'], 16); retired = []
        old = next(c for c in parent['cases'] if c['parent_case_index'] == ix)
        assert case['configuration'] == old['configuration'] and case['operand_profile'] == old['operand_profile']
        for name in ['fresh_release_origin', 'release_wrapper_prefix', 'explicit_null', 'fresh_cached_origin', 'cached_null', 'parameter_retirement_return', 'output_retirement_return', 'input_retirement_return']:
            if name == 'parameter_retirement_return': retired.append((h3, h3+104))
            if name == 'output_retirement_return': retired.append((h2, h2+32))
            if name == 'input_retirement_return': retired.append((h1, h1+32))
            state, known, _ = A.epochs(old['branches'][name], state, known, k, retired)
        b = case['branches']
        assert list(b) == ['dispatcher_epilogue_and_count', 'auxiliary_retirement_return', 'workspace_retirement_return']
        F = int(p['frame_SP'], 16); entry = int(p['entry_SP'], 16)
        assert entry-F == 256
        for (name, row), visits in zip(b.items(), [44, 18, 11]):
            if name == 'auxiliary_retirement_return': retired.append((R.GUEST+0xc000, R.GUEST+0xd000))
            if name == 'workspace_retirement_return': retired.append((R.GUEST+0x4000, R.GUEST+0x8000))
            assert row['logical_retired_spans'] == [{'start': hex(a), 'end': hex(z)} for a,z in retired]
            assert len(row['source_trace']) == visits
            state, known, c = A.epochs(row, state, known, k, retired); count.update(c)
            for field in ['mutable_count_at_boundary', 'wrapper_count_local']:
                count['extra_snapshot_bytes_checked'] += snapshot(row[field], state, known)
                assert row[field]['terms'] == [{'bytes_hex': f'{v:02x}'} for v in (512).to_bytes(4, 'little')]
            assert row['mutable_count_at_boundary']['address'] == hex(R.GUEST+0x2000)
            assert row['wrapper_count_local']['address'] == hex(F+0x88)
        d, aux, work = b.values()
        join = d['original_dispatcher_call_join']; call = join['source_call']; origin = join['source_pointer_read']
        assert call in p['source_calls'] and origin in p['source_reads'] and origin['visit'] < call['visit']
        assert call['pc'] == hex(R.DISPATCH_CALL) and call['target'] == '0xfffffe000a5a5470' and call['modifier'] == '0x1e46'
        assert origin['size_bytes'] == 8 and int.from_bytes(bytes.fromhex(origin['bytes_hex']), 'little') == int(call['target'],16)
        ptr = pointer(k, int(origin['address'],16))
        assert join['original_pointer'] == ptr and ptr['target'] == call['target'] and ptr['diversity'] == call['modifier'] and ptr['authenticated']
        assert join['entry_SP'] == p['frame_SP'] and join['root_entry_premise'] == {'pc':'declared_core_wrapper_entry', 'target':hex(R.ENTRY), 'SP':p['entry_SP'], 'return_pc':hex(R.HALT), 'entry_premise':True}
        count['original_dispatcher_call_joins_checked'] += 1
        for row, pc, target, slot, div, x0, x1 in [
            (d, R.AUX_FREE, 0xfffffe000c4ba368, 0xfffffe000847a878, '0x4d6a', 0xfffffe000847ba60, R.GUEST+0xc000),
            (aux, R.WORK_FREE, 0xfffffe000c4b9a24, 0xfffffe000847a848, '0x84ff', R.GUEST+0x4000, 16384)]:
            event = row['boundary']; ptr = pointer(k, slot)
            assert event['pc'] == hex(pc) and event['target'] == hex(target) and event['modifier'] == div
            assert event['original_pointer'] == ptr and ptr['target'] == hex(target) and ptr['diversity'] == div and ptr['authenticated']
            assert event['X0'] == {'bytes_hex': x0.to_bytes(8,'little').hex()} and event['X1'] == {'bytes_hex': x1.to_bytes(8,'little').hex()}
            assert event['SP'] == p['frame_SP'] and not event['instruction_executed']
            count['pending_free_pointer_joins_checked'] += 1
        for row, pending, kind in [(aux, d['boundary'], 'auxiliary'), (work, aux['boundary'], 'workspace')]:
            assert row['ordinary_void_return_premise'] == {'pending_call':pending, 'registers_clobbered':list(range(19)), 'model_memory_effects':0, 'logical_retirement_only':kind, 'native_API_executed':False}
        writes = [w for row in b.values() for w in row['source_writes']]
        assert len(writes) == 1 and writes[0]['pc'] == '0xfffffe000a5a2f5c' and writes[0]['address'] == hex(R.GUEST+0x2000) and writes[0]['bytes_hex'] == '00020000'
        assert work['boundary'] == {'kind':'returned_to_declared_core_caller', 'pc':hex(R.HALT), 'X0':{'bytes_hex':'5e5affff00000000'}, 'SP':p['entry_SP'], 'instruction_executed':False}
        assert work['outer_SP'] == p['entry_SP']
        # The original prologue defines each saved register slot; validate the
        # source encoding and compare the final value with that actual store.
        for j in range(19,30):
            match = []
            for w in p['source_writes']:
                pc = int(w['pc'],16)
                if not 0xfffffe000a5a2bb4 <= pc <= 0xfffffe000a5a2bc8: continue
                ins = next(R.DC.disasm(k.read(pc,4),pc)); assert ins.mnemonic == 'stp'
                regs = [{'fp':'x29', 'lr':'x30'}.get(ins.reg_name(o.reg), ins.reg_name(o.reg)) for o in ins.operands[:2]]
                if 'x'+str(j) in regs:
                    at = F+ins.operands[2].mem.disp+8*regs.index('x'+str(j))
                    if int(w['address'],16) == at: match.append(w)
            assert len(match) == 1 and work['outer_registers'][str(j)] == {'bytes_hex':match[0]['after_hex']}, (ix, j, match)
            count['restored_callee_saved_registers_checked'] += 1
        component = case['UserClient_result_component']
        assert component == R.result_component(k, 0xffff5a5e)
        assert component['relative_output_writes'] == [{'pc':'0xfffffe000a5050a0', 'offset_bytes':548, 'size_bytes':4, 'bytes_hex':'5e5affff'}]
        assert not component['count_field_at_0x220_written'] and component['method_outer_status32'] == 0
        for word in component['source_trace']:
            pc = int(word['pc'],16)
            assert word['bytes_hex'] == k.read(pc,4).hex() == IMAGE.read(pc,4).hex()
            count['separate_UserClient_source_words_checked'] += 1
    for a,b in [('source_words_checked','source_visits'), ('read_bytes_checked','source_read_bytes'), ('write_bytes_checked','source_write_bytes')]:
        assert count[a] == COUNTS[b]
    assert not e['native_target_executed'] and not e['full_goal_complete']
    report = read(BASE/'versioned_wrapper_error_return_report.md')
    assert all(f'| WR{j} |' in report for j in range(1,8)) and all(f'**QG{j}**' in report for j in range(1,8))
    return e, count

def main():
    e, count = receipts()
    raw = zstd.decompress(git('show', PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest() == BASELINE_SHA
    old, new = json.loads(raw), json.loads(read(BASE/MANIFEST))
    before = {r['path']:r for r in old['files']}; after = {r['path']:r for r in new['files']}
    assert len(before) == 8635 and len(after) == 8639 and not before.keys()-after.keys() and after.keys()-before.keys() == ADDED
    assert {p for p in before if before[p] != after[p]} == CHANGED
    assert new['inputs_preserved'] == old['inputs_preserved'] and len(new['inputs_preserved']) == 3
    for row in new['inputs_preserved']:
        assert sha(BASE/row['path']) == row['sha256'] and size(BASE/row['path']) == row['size_bytes']
    for p in CHANGED | ADDED:
        assert sha(BASE/p) == after[p]['sha256'] and size(BASE/p) == after[p]['size_bytes']
    assert new['validation']['versioned_wrapper_error_return_increment_checks'] == COUNTS
    assert new['validation']['versioned_wrapper_error_return_static_scope'] == e['scope']
    assert new['validation']['reports'] == old['validation']['reports']+1 == 487 and new['goal_status'] == 'active'
    assert new['validation']['unavailable_external_primary_references'] == old['validation']['unavailable_external_primary_references']
    for p in ARCHIVES: assert not (BASE/p).exists()
    for p in OWNED: path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    path_hygiene(json.dumps(H.paths_in_typed_payloads(e)).encode())
    fields, extent = H.hex_hygiene(e); path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta = set(git('diff','--name-only',PREVIOUS).decode().splitlines()) | set(git('ls-files','--others','--exclude-standard').decode().splitlines())
    assert delta == OWNED, delta ^ OWNED
    print(json.dumps({'unchanged_manifest_entries':8626, 'owned_physical_files':len(OWNED), 'original_inputs_preserved':3, 'reports':487, 'source_queries_unsat':3, 'independent_byte_epochs':dict(count), 'decoded_hex_fields_path_checked':fields, 'decoded_hex_bytes_path_checked':extent, 'native_API_executed':False, 'analyst_paths_absent':True, 'all_checks_pass':True}), flush=True)

if __name__ == '__main__': main()
