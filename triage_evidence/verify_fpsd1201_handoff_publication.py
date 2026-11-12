#!/usr/bin/env python3
"""Verify exact handoff publication, preservation, compressed storage and hygiene.

No instruction replay. O(owned bytes + manifest + decoded RAM) time and
O(largest artifact + decoded RAM) space. No target or IDB operations.
"""
import json,subprocess
from pathlib import Path
from hashlib import sha256
from compression import zstd
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene
from verify_fpsd1200_process_publication import paths_in_typed_payloads

ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='0e42386500f6582ad61eedcbc379ca9b7b7ac050'
BASELINE_SHA='ee94d75c5c992a6a4488886f8bb5dcfa01b4a7bef68ab5b37dbb5a10fcd26380'
CHECKS_SHA='bffc0071b81fc7502db504fdbf1d87ca355cad0e006732fe811cd52df7f62ace'
AUDIT_SHA='7d517b76a3629d2e410e1f99abb7b7c95e5513b1011fc7fd990f542f41819f63'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','daemon_receive_interface_report.md','foundational_triage_report.md','fpsd1201_caller_report.md',
 'fpsd1201_record_report.md','fpsd1201_export_report.md','interface_abi_report.md','interface_investigation_status.md','mach_ports_report.md',
 'obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'fpsd1201_handoff_report.md','triage_evidence/recover_fpsd1201_handoff.py','triage_evidence/audit_fpsd1201_handoff.py',
 'triage_evidence/verify_fpsd1201_handoff_publication.py','triage_evidence/fpsd1201_handoff_checks.json','triage_evidence/fpsd1201_handoff_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/fpsd1201_handoff_checks.json','triage_evidence/fpsd1201_handoff_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'profiles':27,'source_visits':37699,'source_reads':6741,'source_writes':3473,'PAC_models':3036,'CPU_points':142,
 'builder_pre_import_stops':21,'scalar_skip_stops':2,'root_mismatch_stops':4,'original_pointer_rows':7,'local_queries_unsat':2}
TOTALS={'complete_CPU_frames_checked':3259,'restored_RAM_bytes_checked':4423680,'explicit_memory_bindings_checked':382,
 'initial_RAM_bytes_checked':4423680,'builder_argument_frames_checked':21,'XOR_byte_oracles_checked':2944,'serialized_payload_bytes_checked':2688,
 'pre_import_serializations_checked':21,'short_export_still_staged_controls':2,'final_RAM_bytes_checked':4423680,'original_visits_checked':37699,
 'original_reads_checked':6741,'original_writes_checked':3473,'PAC_models_checked':3036,'CPU_points_checked':142,'candidate_preservation_profiles_checked':27}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,current=json.loads(raw),json.loads(read(BASE/MANIFEST));prev={r['path']:r for r in old['files']};new={r['path']:r for r in current['files']}
    assert len(prev)==len(old['files'])==8325 and len(new)==len(current['files'])==8331
    assert not prev.keys()-new.keys()and new.keys()-prev.keys()==ADDED and {p for p in prev if prev[p]!=new[p]}==CHANGED
    assert current['inputs_preserved']==old['inputs_preserved']and len(current['inputs_preserved'])==3
    for r in current['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==new[p]['sha256']and size(BASE/p)==new[p]['size_bytes']
    report=read(BASE/'fpsd1201_handoff_report.md');assert all(f'| HF{i} |'in report for i in range(1,8))and all(f'**QG{i}**'in report for i in range(1,8))
    assert sha(ROOT/'fpsd1201_handoff_checks.json')==CHECKS_SHA and sha(ROOT/'fpsd1201_handoff_audit.json')==AUDIT_SHA
    e=json.loads(read(ROOT/'fpsd1201_handoff_checks.json'));a=json.loads(read(ROOT/'fpsd1201_handoff_audit.json'))
    assert e['generator_sha256']==sha(ROOT/'recover_fpsd1201_handoff.py')and a['auditor_sha256']==sha(ROOT/'audit_fpsd1201_handoff.py')
    for p,h in e['dependencies'].items():assert sha(ROOT/p)==h
    assert a['dependencies']==e['dependencies']and a['checks_sha256']==CHECKS_SHA
    assert a['fresh_replay_completed']and a['process_exit_code']==0 and a['result']['all_checks_pass']
    assert e['verified_counts']==a['result']['verified_counts']==COUNTS and a['result']['fresh_replay']==TOTALS
    assert a['result']['source']['source_bytes_checked']==86380 and a['result']['source']['original_fixup_words_checked']==79512
    assert a['result']['source']['exact_source_instructions_checked']==25 and a['result']['source']['request_bank_cases_checked']==256
    assert e['prefix_instructions_rerun']==0 and a['result']['explicit_parent_bindings_required']
    assert not any(e[k]for k in ['whole_parent_replayed','native_target_executed','IDB_edit_operations_requested','full_goal_complete'])
    assert current['validation']['fpsd1201_handoff_increment_checks']==COUNTS and current['validation']['fpsd1201_handoff_static_scope']==e['scope']
    assert current['validation']['reports']==old['validation']['reports']+1==434 and current['goal_status']=='active'
    assert current['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']and len(OWNED)==18
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        logical=p[:-4]if p.endswith('.zst')else p
        if logical=='triage_evidence/fpsd1201_handoff_checks.json':path_hygiene(json.dumps(paths_in_typed_payloads(e)).encode())
        else:path_hygiene(read(BASE/logical).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED
    print(json.dumps({'unchanged_manifest_entries':len(prev)-len(CHANGED),'owned_physical_files':len(OWNED),'original_inputs_preserved':3,
      'reports':434,'profiles':27,'pre_import_serializations':21,'serialized_payload_bytes':2688,'short_export_staged_controls':2,
      'publication_does_not_replay_instructions':True,'native_target_executed':False,'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
