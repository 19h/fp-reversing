#!/usr/bin/env python3
"""Pin the independently audited shift evidence and exact publication delta.

No instruction replay or native effects. O(owned bytes + manifest + decoded
RAM) time; O(largest artifact + decoded RAM) space. Reference correspondence
is pinned by the fresh audit receipt; reference binaries are not published.
"""
from hashlib import sha256
import json,subprocess
from pathlib import Path
from compression import zstd
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene
from verify_fpsd1200_process_publication import paths_in_typed_payloads

ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='9e593e98759e3f842b9dd9b9028b27a3a8f06d78'
BASELINE_MANIFEST_SHA='0410ffbbf2c82855d5a78700515ef2edf9d1a1c43097c0ebde537d829686b21f'
AUDIT_SHA='518869e607fc12f5b60e12a548385c50ceb82997aebd11e1050730205f0a9d63'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','daemon_receive_interface_report.md','foundational_triage_report.md',
 'fpsd1201_operand_report.md','interface_abi_report.md','interface_investigation_status.md',
 'mach_ports_report.md','obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'fpsd1201_shift_report.md','triage_evidence/recover_fpsd1201_shift.py',
 'triage_evidence/audit_fpsd1201_shift.py','triage_evidence/verify_fpsd1201_shift_publication.py',
 'triage_evidence/fpsd1201_shift_checks.json','triage_evidence/fpsd1201_shift_audit.json','triage_evidence/fpsd1201_shift_ida_readback.json'}
ARCHIVES={'triage_evidence/fpsd1201_shift_checks.json','triage_evidence/fpsd1201_shift_audit.json',
 'triage_evidence/fpsd1201_shift_ida_readback.json',MANIFEST}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'profiles':144,'nested_profiles':8,'isolated_profiles':136,'source_visits':168717,'source_reads':25418,
 'source_writes':6815,'PAC_models':5871,'shift_points':862,'fresh_IDA_spans':5,'fresh_IDA_bytes':5700,
 'source_code_bytes':19552,'local_queries_unsat':15}
SOURCE={'fresh_IDA_spans':5,'fresh_IDA_bytes':5700,'compiler_bounded_bodies':5,'total_selected_code_bytes':19552,
 'retained_queries_unsat':15,'independent_source_queries_unsat':5,'exact_source_instructions_checked':9,
 'complete_algorithm_universally_proved':False,'source_lifters_use_distinct_operand_decoders':True}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_MANIFEST_SHA
    previous,current=json.loads(raw),json.loads(read(BASE/MANIFEST));old={r['path']:r for r in previous['files']};new={r['path']:r for r in current['files']}
    assert len(old)==len(previous['files'])==8269 and len(new)==len(current['files'])==8276
    assert not old.keys()-new.keys()and new.keys()-old.keys()==ADDED and {p for p in old if old[p]!=new[p]}==CHANGED
    assert current['inputs_preserved']==previous['inputs_preserved']
    for r in current['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==new[p]['sha256']and size(BASE/p)==new[p]['size_bytes']
    report=read(BASE/'fpsd1201_shift_report.md');assert all(f'| SH{i} |'in report for i in range(1,9))and all(f'**QG{i}**'in report for i in range(1,8))
    e=json.loads(read(ROOT/'fpsd1201_shift_checks.json'));assert e['verified_counts']==COUNTS and sha(ROOT/'recover_fpsd1201_shift.py')==e['generator_sha256']
    for n,h in e['dependencies'].items():assert sha(ROOT/n)==h
    assert not any(e[k]for k in ['whole_parent_replayed','native_target_executed','IDB_edit_operations_requested','full_goal_complete'])
    assert sha(ROOT/'fpsd1201_shift_audit.json')==AUDIT_SHA
    receipt=json.loads(read(ROOT/'fpsd1201_shift_audit.json'));assert receipt['fresh_replay_completed']and receipt['process_exit_code']==0 and not receipt['native_target_executed']
    assert receipt['auditor_sha256']==sha(ROOT/'audit_fpsd1201_shift.py')and receipt['checks_sha256']==sha(ROOT/'fpsd1201_shift_checks.json')
    assert receipt['IDA_readback_sha256']==e['IDA_readback_sha256']==sha(ROOT/'fpsd1201_shift_ida_readback.json')and receipt['dependencies']==e['dependencies']
    r=receipt['result'];assert r['all_checks_pass']and r['source']==SOURCE
    assert(r['profiles'],r['nested_profiles'],r['isolated_profiles'],r['next_callee_targets'])==(144,8,136,['0x649430'])
    assert r['candidate_inline128_reads_or_writes']==0 and not any(r[k]for k in ['whole_parent_replayed','complete_operand_child_return_established','native_target_executed','full_goal_complete'])
    totals=r['fresh_replay'];assert totals['complete_shift_integer_oracles_checked']==144 and totals['shift_CPU_points_checked']==862
    assert totals['original_visits_checked']==168717 and totals['complete_final_RAM_bytes_checked']==21823488
    assert(totals['left_route_records_checked'],totals['right_route_records_checked'],totals['zero_query_returns_checked'],totals['sign_query_returns_checked'])==(71,73,144,71)
    assert len(e['profiles'])==144 and len(e['proofs'])==15 and all(p['result']=='unsat'for p in e['proofs'])
    for j,p in enumerate(e['profiles']):
        assert not p['native_effects']and p['configuration']['mode']==('nested'if j<8 else'isolated')
        assert p['stop_reason']==('unretained_callee'if j<8 else'returned')
        assert p['shift_points'][0]['pc']=='0x5a600c'and p['shift_points'][-1]['pc']==('0x14f940c'if j<8 else'0x7f000000')
        if j<8:
            assert p['frontier']['pc']=='0x14f94c4'and p['frontier']['target']=='0x649430'and p['frontier']['original_slot']=='0x1d039b8'and not p['frontier']['instruction_executed']
            assert p['final_status_u32']=='0xa5a5a5a5'and p['final_delta_cell_u64']==hex(p['configuration']['seed_u64'])
        else:assert p['frontier']is None
    f=e['reference_file_check'];assert f['logical_reference_name']=='CoreFP'and f['selected_slice_size_B']==30797904
    assert(f['original_fixup_words_checked'],f['code_bytes_checked'],f['earlier_parent_bytes_checked'],f['bank_bytes_checked'])==(79512,19552,85464,3072)
    att=json.loads(read(ROOT/'fpsd1201_shift_ida_readback.json'));assert not att['IDB_mutated']and not att['native_target_executed']and len(att['spans'])==5
    assert sum(s['size_B']for s in att['spans'])==5700 and all(s['current_equals_IDA_original_bytes']for s in att['spans'])
    assert current['validation']['fpsd1201_shift_increment_checks']==COUNTS and current['validation']['fpsd1201_shift_static_scope']==e['scope']
    assert current['validation']['reports']==previous['validation']['reports']+1==426
    assert current['validation']['unavailable_external_primary_references']==previous['validation']['unavailable_external_primary_references']
    assert current['goal_status']=='active'and len(OWNED)==17
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        if p=='triage_evidence/fpsd1201_shift_checks.json.zst':path_hygiene(json.dumps(paths_in_typed_payloads(e)).encode())
        else:path_hygiene(read(BASE/(p[:-4]if p.endswith('.zst')else p)).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED
    print(json.dumps({'unchanged_manifest_entries':len(old)-len(CHANGED),'owned_physical_files':len(OWNED),'original_inputs_preserved':3,
      'reports':426,'complete_private_shift_oracles':144,'isolated_profiles':136,'continued_caller_profiles':8,
      'new_source_queries_unsat':15,'independent_source_constructor_queries_unsat':5,
      'publication_does_not_replay_instructions':True,'native_target_executed':False,'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
