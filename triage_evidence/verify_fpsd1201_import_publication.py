#!/usr/bin/env python3
"""Pin independently audited importer evidence and the exact publication delta.

No instruction replay or native effects. O(owned bytes + manifest + decoded
RAM) time; O(largest artifact + decoded RAM) space. Source correspondence is
pinned by the fresh audit receipt; the reference binary is not published.
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
PREVIOUS='0d263693dbd62a0a7fdd43cef29c677995d60172'
BASELINE_MANIFEST_SHA='aa470ca6896e63a7e4b240038b807feadeb412c0c72e50a854424e44e124a3a1'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','daemon_receive_interface_report.md','foundational_triage_report.md',
 'fpsd1201_record_report.md','interface_abi_report.md','interface_investigation_status.md',
 'mach_ports_report.md','obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'fpsd1201_import_report.md','triage_evidence/recover_fpsd1201_import.py',
 'triage_evidence/audit_fpsd1201_import.py','triage_evidence/verify_fpsd1201_import_publication.py',
 'triage_evidence/fpsd1201_import_checks.json','triage_evidence/fpsd1201_import_audit.json',
 'triage_evidence/fpsd1201_import_ida_readback.json'}
ARCHIVES={'triage_evidence/fpsd1201_import_checks.json','triage_evidence/fpsd1201_import_audit.json',
 'triage_evidence/fpsd1201_import_ida_readback.json','triage_evidence/interface_manifest.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'profiles':68,'isolated_profiles':60,'nested_profiles':8,'source_visits':204945,
 'source_reads':23954,'source_writes':2815,'PAC_models':11335,'import_CPU_points':136,
 'fresh_IDA_spans':1,'fresh_IDA_bytes':1240,'source_code_bytes':5348,'local_queries_unsat':2}
SOURCE={'fresh_IDA_spans':1,'fresh_IDA_bytes':1240,'original_file_code_bytes':5348,
 'earlier_parent_file_bytes':85464,'original_file_bank_bytes':3072,'original_file_fixup_words':79512,
 'compiler_function_starts':1602,'exact_source_instructions_checked':19,'retained_queries_unsat':2,
 'independent_local_queries_unsat':2}
PRIOR_SOURCE={'fresh_IDA_spans':2,'fresh_IDA_bytes':3368,'compiler_bounded_bodies':2,
 'exact_source_instructions_checked':54,'exhaustive_bank_inputs':2048,'retained_queries_unsat':4,
 'independent_local_queries_unsat':4,'unaligned_pointer_counterexamples':1}
REPLAY={'complete_CPU_frames_checked':11643,'limb_values_checked':1075,'input_bytes_checked':4231,
 'importer_outcomes_checked':68,'complete_final_RAM_bytes_checked':10305536,
 'original_pointer_profile_associations_checked':1075,'original_visits_checked':204945,
 'original_reads_checked':23954,'original_writes_checked':2815,'PAC_models_checked':11335,
 'cursor_checkpoints_checked':16,'selected_65537_initializers_checked':4}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest()==BASELINE_MANIFEST_SHA
    previous,current=json.loads(raw),json.loads(read(BASE/MANIFEST))
    old={r['path']:r for r in previous['files']};new={r['path']:r for r in current['files']}
    assert len(old)==len(previous['files'])==8255 and len(new)==len(current['files'])==8262
    assert not old.keys()-new.keys()and new.keys()-old.keys()==ADDED
    assert {p for p in old if old[p]!=new[p]}==CHANGED
    assert current['inputs_preserved']==previous['inputs_preserved']
    for row in current['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==new[p]['sha256']and size(BASE/p)==new[p]['size_bytes']
    report=read(BASE/'fpsd1201_import_report.md')
    assert all(f'| BI{i} |'in report for i in range(1,9))and all(f'**QG{i}**'in report for i in range(1,8))
    e=json.loads(read(ROOT/'fpsd1201_import_checks.json'))
    assert e['verified_counts']==COUNTS and sha(ROOT/'recover_fpsd1201_import.py')==e['generator_sha256']
    for n,h in e['dependencies'].items():assert sha(ROOT/n)==h
    assert not any(e[k]for k in ['whole_parent_replayed','native_target_executed','IDB_edit_operations_requested','full_goal_complete'])
    receipt=json.loads(read(ROOT/'fpsd1201_import_audit.json'))
    assert receipt['fresh_replay_completed']and receipt['process_exit_code']==0 and not receipt['native_target_executed']
    assert receipt['auditor_sha256']==sha(ROOT/'audit_fpsd1201_import.py')and receipt['checks_sha256']==sha(ROOT/'fpsd1201_import_checks.json')
    assert receipt['IDA_readback_sha256']==e['IDA_readback_sha256']==sha(ROOT/'fpsd1201_import_ida_readback.json')and receipt['dependencies']==e['dependencies']
    r=receipt['result'];assert r['all_checks_pass']and r['source']==SOURCE and r['pinned_predecessor_source']==PRIOR_SOURCE and r['fresh_replay']==REPLAY
    assert(r['profiles'],r['isolated_profiles'],r['nested_profiles'],r['next_unretained_target'])==(68,60,8,'0x14fac64')
    assert not any(r[k]for k in ['whole_parent_replayed','native_target_executed','full_goal_complete'])
    assert len(e['profiles'])==68
    for p in e['profiles']:
        nested=p['configuration']['mode']=='nested';assert not p['native_effects']and len(p['import_points'])==2
        assert p['stop_reason']==('unretained_callee'if nested else'returned')
        status=int.from_bytes(bytes.fromhex(p['import_points'][-1]['record32_hex'])[24:28],'little')
        assert status==(0xba1df9db if nested or p['configuration']['length_u32']<=256 else 0x45e2a205)
        if nested:
            assert p['frontier']['pc']=='0x98189c'and p['frontier']['target']=='0x14fac64'and not p['frontier']['instruction_executed']
            assert p['final_delta_cell_u64']==hex(p['configuration']['seed_u64'])and p['final_status_u32']=='0xa5a5a5a5'
    f=e['reference_file_check'];assert f['logical_reference_name']=='CoreFP'and f['selected_slice_size_B']==30797904
    assert f['original_fixup_words_checked']==79512 and f['code_bytes_checked']==5348 and f['earlier_parent_bytes_checked']==85464 and f['bank_bytes_checked']==3072
    att=json.loads(read(ROOT/'fpsd1201_import_ida_readback.json'))
    assert not att['IDB_mutated']and not att['native_target_executed']and len(att['spans'])==1
    assert att['spans'][0]['size_B']==1240 and att['spans'][0]['current_equals_IDA_original_bytes']
    assert current['validation']['fpsd1201_import_increment_checks']==COUNTS and current['validation']['fpsd1201_import_static_scope']==e['scope']
    assert current['validation']['reports']==previous['validation']['reports']+1==424
    assert current['validation']['unavailable_external_primary_references']==previous['validation']['unavailable_external_primary_references']
    assert current['goal_status']=='active'and len(OWNED)==17
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        if p=='triage_evidence/fpsd1201_import_checks.json.zst':path_hygiene(json.dumps(paths_in_typed_payloads(e)).encode())
        else:path_hygiene(read(BASE/(p[:-4]if p.endswith('.zst')else p)).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
    assert delta==OWNED
    print(json.dumps({'unchanged_manifest_entries':len(old)-len(CHANGED),'owned_physical_files':len(OWNED),
      'original_inputs_preserved':3,'reports':424,'private_profiles':68,'nested_next_callee_frontiers':8,
      'pinned_fresh_visits':204945,'publication_does_not_replay_instructions':True,
      'native_target_executed':False,'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
