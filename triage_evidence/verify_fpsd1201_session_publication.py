#!/usr/bin/env python3
"""Verify the exact publication delta and the completed independent audit receipt.

Packed profile JSON and typed RAM are decoded before path checking. This verifier
pins the fresh replay; it does not replay instructions. O(owned bytes + manifest
+ decoded profiles) time, O(largest artifact + decoded profile) space.
"""
import base64
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import zlib
from compression import zstd
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene
from verify_fpsd1200_process_publication import paths_in_typed_payloads

ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='fbfeabb51ef8509c51045bf5438ba95133ac3726'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'fpsd1200_process_report.md','daemon_receive_interface_report.md','mach_ports_report.md',
 'foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md',
 'obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'fpsd1201_session_report.md','triage_evidence/recover_fpsd1201_session.py',
 'triage_evidence/audit_fpsd1201_session.py','triage_evidence/verify_fpsd1201_session_publication.py',
 'triage_evidence/fpsd1201_session_checks.json','triage_evidence/fpsd1201_session_ida_readback.json',
 'triage_evidence/fpsd1201_session_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/fpsd1201_session_checks.json',
 'triage_evidence/fpsd1201_session_ida_readback.json','triage_evidence/fpsd1201_session_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'profiles':10,'original_visits':1942885,'imports':79,'source_reads':291532,
 'source_writes':65982,'session_CPU_points':202,'heap_accesses':18548,
 'callback_join_visits':3999,'source_spans':320,'source_instructions':21540}
CASES=[('matching_zero',480680,-42185,128,53,'49'),
 ('other_word',480680,-42185,128,53,'49'),('other_matching_name',480680,-42185,128,53,'49'),
 ('different_name',4518,8,0,0,'4b'),('allocation_NULL',6675,-42028,0,53,'49'),
 ('complex_request',37,-304,0,0,'4b'),('wrong_size',40,-304,0,0,'4b'),
 ('live_slot_index1',480713,-42185,128,53,'49'),('marker4c',4431,8,0,0,'4c'),('marker4d',4431,8,0,0,'4d')]


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def checked_profile(p):
    r=json.loads(zlib.decompress(base64.b64decode(p['payload_zlib_base64'],validate=True)))
    assert p['label']==r['configuration']['label']and p['visits']==len(r['source_visits'])
    path_hygiene(json.dumps(paths_in_typed_payloads(r)).encode())
    return {k:('decoded profile and typed RAM independently path checked'if k=='payload_zlib_base64'else v)for k,v in p.items()}


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest()=='0f0e5a1556b1610a0d1879c31adb1fab4fa8f380ce0c2f69fc4e34fb5dfc5d4c'
    previous,current=json.loads(raw),json.loads(read(BASE/MANIFEST))
    old={r['path']:r for r in previous['files']};new={r['path']:r for r in current['files']}
    assert len(old)==len(previous['files'])==8206 and len(new)==len(current['files'])==8213
    assert not old.keys()-new.keys()and new.keys()-old.keys()==ADDED
    assert {p for p in old if old[p]!=new[p]}==CHANGED
    assert current['inputs_preserved']==previous['inputs_preserved']
    for r in current['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==new[p]['sha256']and size(BASE/p)==new[p]['size_bytes']
    report=read(BASE/'fpsd1201_session_report.md')
    assert all(f'| FS{i} |'in report for i in range(1,9))and all(f'**QG{i}**'in report for i in range(1,8))
    e=json.loads(read(ROOT/'fpsd1201_session_checks.json'))
    assert e['verified_counts']==COUNTS and sha(ROOT/'recover_fpsd1201_session.py')==e['generator_sha256']
    for n,h in e['dependencies'].items():assert sha(ROOT/n)==h
    assert not any(e[k]for k in ['native_target_executed','IDB_edit_operations_requested',
      'automatic_IDB_analysis_side_effects_measured','full_goal_complete'])
    receipt=json.loads(read(ROOT/'fpsd1201_session_audit.json'))
    assert receipt['fresh_replay_completed']and receipt['process_exit_code']==0 and not receipt['native_target_executed']
    assert receipt['auditor_sha256']==sha(ROOT/'audit_fpsd1201_session.py')
    assert receipt['checks_sha256']==sha(ROOT/'fpsd1201_session_checks.json')
    assert receipt['IDA_SDK_readback_sha256']==sha(ROOT/'fpsd1201_session_ida_readback.json')
    assert receipt['daemon_sha256']==e['daemon_sha256']and receipt['dependencies']==e['dependencies']
    r=receipt['result'];q=r['request_replay'];cb=r['callback_join_replay']
    assert r['all_checks_pass']and r['profiles']==10 and r['source_IDA_spans']==320
    assert r['format12_rebases']==529 and r['format12_bindings']==14
    assert r['retained_query_unsat']and all(r['independent_source_lift'].values())
    assert not r['native_target_executed']and not r['session_prefix_freshly_replayed']
    assert q=={'complete_CPU_frames_checked':400,'declared_full_state_component_entries_checked':10,
      'original_instruction_visits_checked':1942885,'original_reads_checked':291532,'original_writes_checked':65982,
      'external_ABI_and_declared_effect_contracts_recomputed':79,'complete_final_mutable_RAM_bytes_checked':24412160,
      'complete_extra_region_pool_and_mask_bytes_checked':3276800,'session_CPU_point_frames_checked':202,
      'heap_owner_accesses_checked':18548}
    assert cb=={'complete_CPU_frames_checked':121,'declared_full_state_component_entries_checked':1,
      'original_instruction_visits_checked':3999,'original_writes_checked':358,'original_reads_checked':491,
      'external_ABI_and_declared_effect_contracts_recomputed':9,'complete_final_mutable_RAM_bytes_checked':2441216,
      'complete_final_pool_bytes_checked':65536,'complete_final_defined_mask_bytes_checked':65536,
      'process_point_CPU_frames_checked':100}
    assert r['joins']['cases']==[{'case':label,'visits':visits,'status_s32':status,'body_bytes_read':body,
      'pool_store_events':stores,'final_marker_hex':marker+'df7745','CF_reference_retained':True}
      for label,visits,status,body,stores,marker in CASES]
    assert r['joins']['post_failure_callback_pool_bytes_identical']and r['joins']['post_failure_callback_skips_marker49']
    assert not r['joins']['new_native_ownership_effects_established']
    assert r['literal_offset_census']=={'decoded_B':14851048,'skipped_words':0,'candidates':862}
    att=json.loads(read(ROOT/'fpsd1201_session_ida_readback.json'))
    assert not att['byte_readback_IDB_mutated']and not att['IDB_edit_operations_requested']
    assert not att['automatic_IDB_analysis_side_effects_measured']
    assert att['spans']==[{'start':s['start'],'size_B':int(s['end'],16)-int(s['start'],16),'sha256':s['sha256']}for s in e['spans']]
    assert att['census_extent_SHA256']==e['tail_census']['sha256']
    assert len(att['additional_source_ranges'])==8 and len(att['SDK_context']['headers'])==4
    assert att['SDK_context']['compile_only']['exit_code']==0
    assert [(p['label'],p['visits'],p['status'])for p in e['profiles']]==[v[:3]for v in CASES]
    assert current['validation']['fpsd1201_session_increment_checks']==COUNTS
    assert current['validation']['fpsd1201_session_static_scope']==e['scope']
    assert current['validation']['reports']==previous['validation']['reports']+1==417
    assert current['validation']['unavailable_external_primary_references']==previous['validation']['unavailable_external_primary_references']
    assert current['goal_status']=='active'and len(OWNED)==16
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        if p=='triage_evidence/fpsd1201_session_checks.json.zst':
            cleaned={**e,'profiles':[checked_profile(p)for p in e['profiles']]}
            path_hygiene(json.dumps(paths_in_typed_payloads(cleaned)).encode())
        else:path_hygiene((BASE/p).read_bytes())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    print(json.dumps({'unchanged_manifest_entries':len(old)-len(CHANGED),'owned_physical_files':len(OWNED),
      'original_inputs_preserved':3,'reports':417,'profiles':10,'pinned_new_original_visits':1946884,
      'publication_does_not_replay_instructions':True,'native_target_executed':False,
      'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
