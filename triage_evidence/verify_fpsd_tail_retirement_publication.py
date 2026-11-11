#!/usr/bin/env python3
"""Pin the successful tail-frontier audit and exact publication delta.

Decode typed RAM before path checking. No instructions are replayed here.
O(owned bytes + manifest + decoded RAM) time, O(largest artifact + RAM) space.
"""
from hashlib import sha256
import json
from pathlib import Path
import subprocess
from compression import zstd
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene
from verify_fpsd1200_process_publication import paths_in_typed_payloads

ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='a393f483d04c8aa3ee2b6ebd835bacd715243558'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'fpsd1200_process_report.md','daemon_receive_interface_report.md','mach_ports_report.md',
 'foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md',
 'obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'fpsd_tail_retirement_report.md','triage_evidence/recover_fpsd_tail_retirement.py',
 'triage_evidence/audit_fpsd_tail_retirement.py','triage_evidence/verify_fpsd_tail_retirement_publication.py',
 'triage_evidence/fpsd_tail_retirement_checks.json','triage_evidence/fpsd_tail_retirement_reference.json',
 'triage_evidence/fpsd_tail_retirement_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/fpsd_tail_retirement_checks.json',
 'triage_evidence/fpsd_tail_retirement_reference.json','triage_evidence/fpsd_tail_retirement_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'profiles': 9, 'original_visits': 37834, 'source_reads': 4608, 'source_writes': 4084, 'imports': 95, 'tail_CPU_points': 33, 'object_stores': 4, 'source_spans': 39, 'source_instructions': 3617, 'static_additional_intervals': 5, 'local_proofs': 2, 'pointer_records': 7}
REPLAY={'complete_CPU_frames_checked': 607, 'declared_full_state_component_entries_checked': 9, 'original_instruction_visits_checked': 37834, 'original_writes_checked': 4084, 'original_reads_checked': 4608, 'external_ABI_and_declared_effect_contracts_recomputed': 95, 'complete_final_mutable_RAM_bytes_checked': 21970944, 'complete_final_pool_bytes_checked': 589824, 'complete_final_defined_mask_bytes_checked': 589824, 'process_point_CPU_frames_checked': 357, 'complete_diagnostic_backing_bytes_checked': 589824, 'tail_CPU_frames_checked': 33}
CASES=[{'case': 'null_tails', 'visits': 7088, 'boundary': 'original_return_to_declared_caller', 'pending_read': None, 'tail_loads_in_order': [[888, 8], [880, 8]], 'object_stores': 0, 'pool_stores': 52, 'CF_requests': ['CoreFoundation/_CFMachPortInvalidate', 'CoreFoundation/_CFRelease'], 'final_marker_u32': '0x4577df49', 'final_CF_reference': '0x0'}, {'case': 'tail880', 'visits': 5205, 'boundary': 'before_unproven_tail_object_read', 'pending_read': {'tail_offset_B': 880, 'object_base': '0x78000000', 'address': '0x7800006c', 'offset_B': 108, 'size_B': 4, 'instruction_bytes_hex': '6b6d40b9', 'object_allocation_extent_known': False}, 'tail_loads_in_order': [[888, 8], [880, 8]], 'object_stores': 0, 'pool_stores': 52, 'CF_requests': ['CoreFoundation/_CFMachPortInvalidate', 'CoreFoundation/_CFRelease'], 'final_marker_u32': '0x4577df49', 'final_CF_reference': '0x0'}, {'case': 'tail888', 'visits': 3057, 'boundary': 'before_unproven_tail_object_read', 'pending_read': {'tail_offset_B': 888, 'object_base': '0x78001000', 'address': '0x78001000', 'offset_B': 0, 'size_B': 8, 'instruction_bytes_hex': '8f0240f9', 'object_allocation_extent_known': False}, 'tail_loads_in_order': [[888, 8]], 'object_stores': 1, 'pool_stores': 0, 'CF_requests': [], 'final_marker_u32': '0x4577df4b', 'final_CF_reference': '0x77001000'}, {'case': 'both', 'visits': 3057, 'boundary': 'before_unproven_tail_object_read', 'pending_read': {'tail_offset_B': 888, 'object_base': '0x78001000', 'address': '0x78001000', 'offset_B': 0, 'size_B': 8, 'instruction_bytes_hex': '8f0240f9', 'object_allocation_extent_known': False}, 'tail_loads_in_order': [[888, 8]], 'object_stores': 1, 'pool_stores': 0, 'CF_requests': [], 'final_marker_u32': '0x4577df4b', 'final_CF_reference': '0x77001000'}, {'case': 'different_PID', 'visits': 4045, 'boundary': 'original_return_to_declared_caller', 'pending_read': None, 'tail_loads_in_order': [], 'object_stores': 0, 'pool_stores': 0, 'CF_requests': [], 'final_marker_u32': '0x4577df4b', 'final_CF_reference': '0x77001000'}, {'case': 'inactive_marker', 'visits': 3999, 'boundary': 'original_return_to_declared_caller', 'pending_read': None, 'tail_loads_in_order': [], 'object_stores': 0, 'pool_stores': 0, 'CF_requests': [], 'final_marker_u32': '0x4577df49', 'final_CF_reference': '0x77001000'}, {'case': 'marker4d', 'visits': 3057, 'boundary': 'before_unproven_tail_object_read', 'pending_read': {'tail_offset_B': 888, 'object_base': '0x78001000', 'address': '0x78001000', 'offset_B': 0, 'size_B': 8, 'instruction_bytes_hex': '8f0240f9', 'object_allocation_extent_known': False}, 'tail_loads_in_order': [[888, 8]], 'object_stores': 1, 'pool_stores': 0, 'CF_requests': [], 'final_marker_u32': '0x4577df4d', 'final_CF_reference': '0x77001000'}, {'case': 'index1_both', 'visits': 3089, 'boundary': 'before_unproven_tail_object_read', 'pending_read': {'tail_offset_B': 888, 'object_base': '0x78001000', 'address': '0x78001000', 'offset_B': 0, 'size_B': 8, 'instruction_bytes_hex': '8f0240f9', 'object_allocation_extent_known': False}, 'tail_loads_in_order': [[888, 8]], 'object_stores': 1, 'pool_stores': 0, 'CF_requests': [], 'final_marker_u32': '0x4577df4b', 'final_CF_reference': '0x77001000'}, {'case': 'index1_tail880', 'visits': 5237, 'boundary': 'before_unproven_tail_object_read', 'pending_read': {'tail_offset_B': 880, 'object_base': '0x78000000', 'address': '0x7800006c', 'offset_B': 108, 'size_B': 4, 'instruction_bytes_hex': '6b6d40b9', 'object_allocation_extent_known': False}, 'tail_loads_in_order': [[888, 8], [880, 8]], 'object_stores': 0, 'pool_stores': 52, 'CF_requests': ['CoreFoundation/_CFMachPortInvalidate', 'CoreFoundation/_CFRelease'], 'final_marker_u32': '0x4577df49', 'final_CF_reference': '0x0'}]
LIFT={'source_queries_unsat': 2, 'tail888_PHASE_W19': '0x9686', 'tail880_PHASE_W19': '0x6ad8', 'targets': {'0x96c1': '0x10025bc54', '0x9686': '0x100406d5c', '0x6ad8': '0x100353458', '0x6af5': '0x1001faa0c'}}


def git(*args):return subprocess.check_output(["git",*args],cwd=BASE)


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest()=='1be16d74938cc9a1d3460fb90fe4dc602835e5c4dc5447b3b81c411b9fdbed18'
    previous,current=json.loads(raw),json.loads(read(BASE/MANIFEST))
    old={r['path']:r for r in previous['files']};new={r['path']:r for r in current['files']}
    assert len(old)==len(previous['files'])==8227 and len(new)==len(current['files'])==8234
    assert not old.keys()-new.keys()and new.keys()-old.keys()==ADDED
    assert {p for p in old if old[p]!=new[p]}==CHANGED
    assert current['inputs_preserved']==previous['inputs_preserved']
    for r in current['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==new[p]['sha256']and size(BASE/p)==new[p]['size_bytes']
    report=read(BASE/'fpsd_tail_retirement_report.md')
    assert all(f'| FT{i} |'in report for i in range(1,9))and all(f'**QG{i}**'in report for i in range(1,8))
    e=json.loads(read(ROOT/'fpsd_tail_retirement_checks.json'))
    assert e['verified_counts']==COUNTS and sha(ROOT/'recover_fpsd_tail_retirement.py')==e['generator_sha256']
    for n,h in e['dependencies'].items():assert sha(ROOT/n)==h
    assert not any(e[k]for k in ['native_target_executed','IDB_edit_operations_requested','full_goal_complete'])
    receipt=json.loads(read(ROOT/'fpsd_tail_retirement_audit.json'))
    assert receipt['fresh_replay_completed']and receipt['process_exit_code']==0 and not receipt['native_target_executed']
    assert receipt['auditor_sha256']==sha(ROOT/'audit_fpsd_tail_retirement.py')
    assert receipt['checks_sha256']==sha(ROOT/'fpsd_tail_retirement_checks.json')
    assert receipt['reference_sha256']==sha(ROOT/'fpsd_tail_retirement_reference.json')
    assert receipt['daemon_sha256']==e['daemon_sha256']and receipt['dependencies']==e['dependencies']
    r=receipt['result'];assert r['all_checks_pass']and r['profiles']==9 and r['fresh_replay']==REPLAY
    assert r['cases']==CASES and r['independent_source_lift']==LIFT and r['retained_queries_unsat']==2
    assert r['source_spans_under_retained_IDA_extent']==39 and r['retained_IDA_extent_bytes']==14851048
    assert r['format12_rebases']==99 and r['format12_bindings']==11 and r['source_pointer_words']==7
    assert r['opaque_object_bytes_consumed']==0 and not r['new_live_IDA_byte_readback_completed']
    assert not r['native_target_executed']and not r['session_prefix_freshly_replayed']and not r['full_goal_complete']
    assert [p['configuration']['label']for p in e['profiles']]==[p['case']for p in CASES]
    assert [len(p['source_visits'])for p in e['profiles']]==[p['visits']for p in CASES]
    att=json.loads(read(ROOT/'fpsd_tail_retirement_reference.json'))
    assert not att['new_live_source_byte_readback_completed']and not att['new_IDB_edit_operations_requested']
    assert not att['current_bridge_available_at_last_check']
    locator=att['completed_read_only_IDA_locator']
    assert not locator['IDB_mutated']and locator['input_sha256']=='4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7'
    oldatt=json.loads(read(ROOT/'fpsd1201_session_ida_readback.json'))
    assert att['retained_IDA_code_extent']['sha256']==oldatt['census_extent_SHA256']=='1463b16f028bda1abb76d52edcf5236c3bd11bbece4a7a6b46f8029ff511236b'
    for n,h in att['retained_artifacts'].items():assert sha(ROOT/n)==h
    assert len(att['SDK_context']['headers'])==4 and att['SDK_context']['compile_only']['exit_code']==0
    assert current['validation']['fpsd_tail_retirement_increment_checks']==COUNTS
    assert current['validation']['fpsd_tail_retirement_static_scope']==e['scope']
    assert current['validation']['reports']==previous['validation']['reports']+1==420
    assert current['validation']['unavailable_external_primary_references']==previous['validation']['unavailable_external_primary_references']
    assert current['goal_status']=='active'and len(OWNED)==16
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        if p=='triage_evidence/fpsd_tail_retirement_checks.json.zst':path_hygiene(json.dumps(paths_in_typed_payloads(e)).encode())
        else:path_hygiene(read(BASE/(p[:-4]if p.endswith('.zst')else p)).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    print(json.dumps({'unchanged_manifest_entries':len(old)-len(CHANGED),'owned_physical_files':len(OWNED),
      'original_inputs_preserved':3,'reports':420,'profiles':9,'pinned_new_original_visits':37834,
      'publication_does_not_replay_instructions':True,'new_live_IDA_byte_readback_completed':False,
      'native_target_executed':False,'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
