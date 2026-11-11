#!/usr/bin/env python3
"""Pin the caller audit and exact owned publication delta without replay.

Decode typed RAM before path checks. O(owned bytes + manifest + decoded RAM)
time; O(largest artifact + RAM) space. Native execution remains absent.
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
PREVIOUS='9e829c0826d70b7834fbf809035f4702ba64486e'
BASELINE_MANIFEST_SHA='23131977cc9a8cb5b144ba0ce64fd5dfcbacfe35758103ae20f6386063024979'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','daemon_receive_interface_report.md',
 'foundational_triage_report.md','fpsd1201_client_report.md','interface_abi_report.md',
 'interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md',
 'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'fpsd1201_caller_report.md','triage_evidence/recover_fpsd1201_caller.py',
 'triage_evidence/audit_fpsd1201_caller.py','triage_evidence/verify_fpsd1201_caller_publication.py',
 'triage_evidence/fpsd1201_caller_checks.json','triage_evidence/fpsd1201_caller_audit.json',
 'triage_evidence/fpsd1201_caller_ida_readback.json'}
ARCHIVES={'triage_evidence/fpsd1201_caller_checks.json','triage_evidence/fpsd1201_caller_audit.json',
 'triage_evidence/fpsd1201_caller_ida_readback.json','triage_evidence/interface_manifest.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'profiles':12,'original_visits':18920,'original_reads':3212,'original_writes':1560,
 'PAC_models':1548,'banks_exhaustive_256':3,'SMT_unsat':3,'source_parent_instructions':21366,
 'fresh_IDA_spans':30,'fresh_IDA_bytes_including_overlap':89092,'original_pointer_words':10}
SOURCE={'exact_source_instructions_checked':68,'parent_instructions_scanned':21366,'SP_writes':11,
 'original_pointer_words_decoded':10,'exhaustive_bank_inputs':768,'fresh_IDA_spans':30,'fresh_IDA_bytes_including_overlap':89092}
REPLAY={'complete_CPU_frames_checked':1572,'complete_final_RAM_bytes_checked':983040,
 'original_visits_checked':18920,'original_reads_checked':3212,'original_writes_checked':1560,'PAC_models_checked':1548}
PROOFS={'retained_queries_unsat':3,'independent_local_queries_unsat':2,'original_delta_suffix_cases':20,'original_delta_suffix_instructions':80}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest()==BASELINE_MANIFEST_SHA
    previous,current=json.loads(raw),json.loads(read(BASE/MANIFEST))
    old={r['path']:r for r in previous['files']};new={r['path']:r for r in current['files']}
    assert len(old)==len(previous['files'])==8241 and len(new)==len(current['files'])==8248
    assert not old.keys()-new.keys()and new.keys()-old.keys()==ADDED
    assert {p for p in old if old[p]!=new[p]}==CHANGED
    assert current['inputs_preserved']==previous['inputs_preserved']
    for row in current['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==new[p]['sha256']and size(BASE/p)==new[p]['size_bytes']
    report=read(BASE/'fpsd1201_caller_report.md')
    assert all(f'| CA{i} |'in report for i in range(1,9))and all(f'**QG{i}**'in report for i in range(1,8))
    e=json.loads(read(ROOT/'fpsd1201_caller_checks.json'))
    assert e['verified_counts']==COUNTS and sha(ROOT/'recover_fpsd1201_caller.py')==e['generator_sha256']
    for n,h in e['dependencies'].items():assert sha(ROOT/n)==h
    assert e['entry_is_declared_fragment_not_whole_parent']and not any(e[k]for k in ['zero_delta_between_requests_established','native_port_identity_established','native_target_executed','IDB_edit_operations_requested','full_goal_complete'])
    receipt=json.loads(read(ROOT/'fpsd1201_caller_audit.json'))
    assert receipt['fresh_replay_completed']and receipt['process_exit_code']==0 and not receipt['native_target_executed']
    assert receipt['auditor_sha256']==sha(ROOT/'audit_fpsd1201_caller.py')and receipt['checks_sha256']==sha(ROOT/'fpsd1201_caller_checks.json')
    assert receipt['IDA_readback_sha256']==e['IDA_readback_sha256']==sha(ROOT/'fpsd1201_caller_ida_readback.json')and receipt['dependencies']==e['dependencies']
    r=receipt['result'];assert r['all_checks_pass']and r['profiles']==12
    assert r['source']==SOURCE and r['fresh_fragment_replay']==REPLAY and r['proofs']==PROOFS
    assert not any(r[k]for k in ['whole_parent_replayed','zero_delta_or_native_endpoint_identity_established','native_target_executed','full_goal_complete'])
    assert len(e['profiles'])==12
    assert sum(p['terminal']['pc']=='0x8f3838'for p in e['profiles'])==8
    assert sum(p['terminal']['pc']=='0x8f389c'for p in e['profiles'])==4
    assert all(not p['native_effects']for p in e['profiles'])
    att=json.loads(read(ROOT/'fpsd1201_caller_ida_readback.json'))
    assert not att['IDB_mutated']and not att['native_target_executed']and att['input_sha256']==e['reference_universal_sha256']
    assert len(att['spans'])==30 and sum(s['size_B']for s in att['spans'])==89092
    assert len(att['code_and_bank_patch_checks'])==6 and all(s['current_equals_IDA_original_bytes']for s in att['code_and_bank_patch_checks'])
    assert current['validation']['fpsd1201_caller_increment_checks']==COUNTS and current['validation']['fpsd1201_caller_static_scope']==e['scope']
    assert current['validation']['reports']==previous['validation']['reports']+1==422
    assert current['validation']['unavailable_external_primary_references']==previous['validation']['unavailable_external_primary_references']
    assert current['goal_status']=='active'and len(OWNED)==17
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        if p=='triage_evidence/fpsd1201_caller_checks.json.zst':path_hygiene(json.dumps(paths_in_typed_payloads(e)).encode())
        else:path_hygiene(read(BASE/(p[:-4]if p.endswith('.zst')else p)).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
    assert delta==OWNED
    print(json.dumps({'unchanged_manifest_entries':len(old)-len(CHANGED),'owned_physical_files':len(OWNED),
      'original_inputs_preserved':3,'reports':422,'fragment_profiles':12,'pinned_fresh_fragment_visits':18920,
      'pinned_original_delta_suffix_cases':20,'publication_does_not_replay_instructions':True,
      'native_target_executed':False,'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
