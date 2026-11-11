#!/usr/bin/env python3
"""Pin the record audit and exact publication delta without target replay.

O(owned bytes + manifest + decoded RAM) time; O(largest artifact + RAM)
space. Typed RAM is decoded before analyst-path checks. No native effects.
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
PREVIOUS='5d8390b823ee8c044ccff067368ea00b00ae8d4d'
BASELINE_MANIFEST_SHA='c31d4a52a858ca44943219dc8b8e7d81f254cf06fffd60e56fe4e2f5c769406c'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','daemon_receive_interface_report.md','foundational_triage_report.md',
 'fpsd1201_caller_report.md','interface_abi_report.md','interface_investigation_status.md',
 'mach_ports_report.md','obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'fpsd1201_record_report.md','triage_evidence/recover_fpsd1201_record.py',
 'triage_evidence/audit_fpsd1201_record.py','triage_evidence/verify_fpsd1201_record_publication.py',
 'triage_evidence/fpsd1201_record_checks.json','triage_evidence/fpsd1201_record_audit.json',
 'triage_evidence/fpsd1201_record_ida_readback.json'}
ARCHIVES={'triage_evidence/fpsd1201_record_checks.json','triage_evidence/fpsd1201_record_audit.json',
 'triage_evidence/fpsd1201_record_ida_readback.json','triage_evidence/interface_manifest.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'profiles':24,'source_visits':10296,'source_reads':2020,'source_writes':1300,
 'PAC_models':184,'completed_rejections':16,'callee_frontiers':8,'fresh_IDA_spans':2,
 'fresh_IDA_bytes':3368,'source_code_bytes_including_constructor':4108,'local_queries_unsat':4}
SOURCE={'fresh_IDA_spans':2,'fresh_IDA_bytes':3368,'compiler_bounded_bodies':2,
 'exact_source_instructions_checked':54,'exhaustive_bank_inputs':2048,'retained_queries_unsat':4,
 'independent_local_queries_unsat':4,'unaligned_pointer_counterexamples':1}
REPLAY={'complete_CPU_frames_checked':332,'original_pointer_profile_associations_checked':392,
 'complete_final_RAM_bytes_checked':3637248,'original_visits_checked':10296,'original_reads_checked':2020,
 'original_writes_checked':1300,'PAC_models_checked':184,'cursor_checkpoints_checked':48,
 'selected_65537_initializers_checked':4}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest()==BASELINE_MANIFEST_SHA
    previous,current=json.loads(raw),json.loads(read(BASE/MANIFEST))
    old={r['path']:r for r in previous['files']};new={r['path']:r for r in current['files']}
    assert len(old)==len(previous['files'])==8248 and len(new)==len(current['files'])==8255
    assert not old.keys()-new.keys()and new.keys()-old.keys()==ADDED
    assert {p for p in old if old[p]!=new[p]}==CHANGED
    assert current['inputs_preserved']==previous['inputs_preserved']
    for row in current['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==new[p]['sha256']and size(BASE/p)==new[p]['size_bytes']
    report=read(BASE/'fpsd1201_record_report.md')
    assert all(f'| PR{i} |'in report for i in range(1,9))and all(f'**QG{i}**'in report for i in range(1,8))
    e=json.loads(read(ROOT/'fpsd1201_record_checks.json'))
    assert e['verified_counts']==COUNTS and sha(ROOT/'recover_fpsd1201_record.py')==e['generator_sha256']
    for n,h in e['dependencies'].items():assert sha(ROOT/n)==h
    assert e['entry_register_and_context_fixtures_are_declared']and not any(e[k]for k in ['whole_parent_replayed','native_target_executed','IDB_edit_operations_requested','full_goal_complete'])
    receipt=json.loads(read(ROOT/'fpsd1201_record_audit.json'))
    assert receipt['fresh_replay_completed']and receipt['process_exit_code']==0 and not receipt['native_target_executed']
    assert receipt['auditor_sha256']==sha(ROOT/'audit_fpsd1201_record.py')and receipt['checks_sha256']==sha(ROOT/'fpsd1201_record_checks.json')
    assert receipt['IDA_readback_sha256']==e['IDA_readback_sha256']==sha(ROOT/'fpsd1201_record_ida_readback.json')and receipt['dependencies']==e['dependencies']
    r=receipt['result'];assert r['all_checks_pass']and r['profiles']==24 and r['source']==SOURCE and r['fresh_replay']==REPLAY
    assert r['completed_rejections']==16 and r['unretained_call_frontiers']==8 and r['candidate_inline128_reads_or_writes']==0
    assert not any(r[k]for k in ['whole_parent_replayed','complete_as_staged_return_established','native_target_executed','full_goal_complete'])
    assert len(e['profiles'])==24
    for p in e['profiles']:
        complete=p['configuration']['control']not in ['as_staged','null_auxiliary']
        assert p['stop_reason']==('returned'if complete else'unretained_callee')and not p['native_effects']
        assert p['final_delta_cell_u64']==('0x0'if complete else hex(p['configuration']['seed_u64']))
        assert p['final_status_u32']==('0x45e2a202'if complete else'0xa5a5a5a5')
        if not complete:assert p['frontier']['target']=='0x17bbb8'and not p['frontier']['instruction_executed']
    att=json.loads(read(ROOT/'fpsd1201_record_ida_readback.json'))
    assert not att['IDB_mutated']and not att['native_target_executed']and len(att['spans'])==2
    assert sum(s['size_B']for s in att['spans'])==3368 and all(s['current_equals_IDA_original_bytes']for s in att['spans'])
    assert current['validation']['fpsd1201_record_increment_checks']==COUNTS and current['validation']['fpsd1201_record_static_scope']==e['scope']
    assert current['validation']['reports']==previous['validation']['reports']+1==423
    assert current['validation']['unavailable_external_primary_references']==previous['validation']['unavailable_external_primary_references']
    assert current['goal_status']=='active'and len(OWNED)==17
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        if p=='triage_evidence/fpsd1201_record_checks.json.zst':path_hygiene(json.dumps(paths_in_typed_payloads(e)).encode())
        else:path_hygiene(read(BASE/(p[:-4]if p.endswith('.zst')else p)).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
    assert delta==OWNED
    print(json.dumps({'unchanged_manifest_entries':len(old)-len(CHANGED),'owned_physical_files':len(OWNED),
      'original_inputs_preserved':3,'reports':423,'private_profiles':24,'complete_rejections':16,
      'unretained_callee_frontiers':8,'pinned_fresh_visits':10296,'publication_does_not_replay_instructions':True,
      'native_target_executed':False,'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
