#!/usr/bin/env python3
"""Exact workspace publication, predecessor preservation and path audit.

No instruction replay. O(owned bytes + manifest + decoded RAM) time/space.
No target, native API or IDB operation is performed.
"""
import json,subprocess
from pathlib import Path
from hashlib import sha256
from compression import zstd
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene
from verify_fpsd1200_process_publication import paths_in_typed_payloads

ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='25acb75158012854fc46b579320fdcaa5c207d97'
BASELINE_SHA='bcf72925b8a4cf70cb7c52cfbc4ef23f09830f51b218d89b491dc860bd9756a8'
CHECKS_SHA='0d91ecfd69eda183763025fdddfb4382108e342fad7540efecbf20b1e2c444fa'
AUDIT_SHA='c6a5b1b1850dae03b7f13f63c2c60697bbb62826f8501fc7cea2c5eabe6f2763'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','daemon_receive_interface_report.md','foundational_triage_report.md','fpsd1201_caller_report.md',
 'fpsd1201_record_report.md','fpsd1201_handoff_report.md','fpsd1200_certificate_report.md','interface_abi_report.md','interface_investigation_status.md',
 'mach_ports_report.md','obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'fpsd1201_workspace_report.md','triage_evidence/recover_fpsd1201_workspace.py','triage_evidence/audit_fpsd1201_workspace.py',
 'triage_evidence/verify_fpsd1201_workspace_publication.py','triage_evidence/fpsd1201_workspace_checks.json','triage_evidence/fpsd1201_workspace_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/fpsd1201_workspace_checks.json','triage_evidence/fpsd1201_workspace_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'profiles':35,'constructor_profiles':10,'pre_helper_gate_profiles':25,'record_staging_stops':5,'source_visits':1345,'source_reads':170,
 'source_writes':225,'PAC_models':60,'local_queries_unsat':6,'local_wrap_control_sat':1,'server_witnesses':2}
TOTALS={'complete_CPU_frames_checked':155,'initial_RAM_bytes_checked':5304320,'source_prefix_store_bytes_checked':90,'context_pointer_producers_checked':10,
 'final_RAM_bytes_checked':5304320,'original_visits_checked':1345,'original_reads_checked':170,'original_writes_checked':225,'PAC_models_checked':60,
 'context_prefix_preservation_profiles_checked':35,'restored_constructor_RAM_bytes_checked':3788800,'complete_record_stagings_checked':5,'record_bytes_checked':400}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,current=json.loads(raw),json.loads(read(BASE/MANIFEST));prev={r['path']:r for r in old['files']};new={r['path']:r for r in current['files']}
    assert len(prev)==len(old['files'])==8331 and len(new)==len(current['files'])==8337
    assert not prev.keys()-new.keys()and new.keys()-prev.keys()==ADDED and {p for p in prev if prev[p]!=new[p]}==CHANGED
    assert current['inputs_preserved']==old['inputs_preserved']and len(current['inputs_preserved'])==3
    for r in current['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==new[p]['sha256']and size(BASE/p)==new[p]['size_bytes']
    report=read(BASE/'fpsd1201_workspace_report.md');assert all(f'| WS{i} |'in report for i in range(1,8))and all(f'**QG{i}**'in report for i in range(1,8))
    assert sha(ROOT/'fpsd1201_workspace_checks.json')==CHECKS_SHA and sha(ROOT/'fpsd1201_workspace_audit.json')==AUDIT_SHA
    e=json.loads(read(ROOT/'fpsd1201_workspace_checks.json'));a=json.loads(read(ROOT/'fpsd1201_workspace_audit.json'))
    assert e['generator_sha256']==sha(ROOT/'recover_fpsd1201_workspace.py')and a['auditor_sha256']==sha(ROOT/'audit_fpsd1201_workspace.py')
    for p,h in e['dependencies'].items():assert sha(ROOT/p)==h
    assert a['dependencies']==e['dependencies']and a['checks_sha256']==CHECKS_SHA and a['fresh_replay_completed']and a['process_exit_code']==0 and a['result']['all_checks_pass']
    assert e['verified_counts']==a['result']['verified_counts']==COUNTS and a['result']['fresh_replay']==TOTALS
    assert a['result']['source']['original_parent_bytes_checked']==85464 and a['result']['source']['original_fixup_words_checked']==79512
    assert a['result']['source']['exact_source_instructions_checked']==20 and a['result']['source']['retained_queries_unsat']==a['result']['source']['independent_queries_unsat']==6
    assert a['result']['sealed_daemon_witnesses']['representative_bytes_checked']==256 and a['result']['sealed_daemon_witnesses']['daemon_prefix_instructions_rerun']==0
    assert not any(e[k]for k in ['whole_parent_replayed','new_IDA_access','native_target_executed','IDB_edit_operations_requested','full_goal_complete'])
    assert current['validation']['fpsd1201_workspace_increment_checks']==COUNTS and current['validation']['fpsd1201_workspace_static_scope']==e['scope']
    assert current['validation']['reports']==old['validation']['reports']+1==435 and current['goal_status']=='active'
    assert current['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']and len(OWNED)==19
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        logical=p[:-4]if p.endswith('.zst')else p
        if logical=='triage_evidence/fpsd1201_workspace_checks.json':path_hygiene(json.dumps(paths_in_typed_payloads(e)).encode())
        else:path_hygiene(read(BASE/logical).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED
    print(json.dumps({'unchanged_manifest_entries':len(prev)-len(CHANGED),'owned_physical_files':len(OWNED),'original_inputs_preserved':3,'reports':435,
      'profiles':35,'record_stagings':5,'shared_prefix_B':9,'sealed_daemon_witnesses':2,'publication_does_not_replay_instructions':True,
      'native_target_executed':False,'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
