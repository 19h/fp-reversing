#!/usr/bin/env python3
"""Pin independently audited operand evidence and the exact publication delta.

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
PREVIOUS='ea8dde586699c980862fc8faf2544bd664cb4d0c'
BASELINE_MANIFEST_SHA='5536d957a0420ecf8dfb3050468d924c9e6e5862d94121439d9a948ff95ab5d0'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','daemon_receive_interface_report.md','foundational_triage_report.md',
 'fpsd1201_import_report.md','interface_abi_report.md','interface_investigation_status.md',
 'mach_ports_report.md','obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'fpsd1201_operand_report.md','triage_evidence/recover_fpsd1201_operand.py',
 'triage_evidence/audit_fpsd1201_operand.py','triage_evidence/verify_fpsd1201_operand_publication.py',
 'triage_evidence/fpsd1201_operand_checks.json','triage_evidence/fpsd1201_operand_audit.json',
 'triage_evidence/fpsd1201_operand_ida_readback.json'}
ARCHIVES={'triage_evidence/fpsd1201_operand_checks.json','triage_evidence/fpsd1201_operand_audit.json',
 'triage_evidence/fpsd1201_operand_ida_readback.json','triage_evidence/interface_manifest.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'profiles': 36, 'unbacked_context_frontiers': 8, 'backed_operand_prefixes': 28, 'source_visits': 306543, 'source_reads': 32696, 'source_writes': 6162, 'PAC_models': 13607, 'fresh_IDA_spans': 2, 'fresh_IDA_bytes': 8504, 'source_code_bytes': 13852, 'local_queries_unsat': 40}
SOURCE={'fresh_IDA_spans': 2, 'fresh_IDA_bytes': 8504, 'compiler_bounded_bodies': 2, 'original_file_new_code_bytes': 8504, 'original_file_total_selected_code_bytes': 13852, 'exact_source_instructions_checked': 27, 'retained_queries_unsat': 40, 'independent_local_queries_unsat': 40, 'exhaustive_bank_inputs': 1280, 'selected_binding_roles': 15, 'source_lifters_use_distinct_operand_decoders': True}
PRIOR_SOURCE={'fresh_IDA_spans': 2, 'fresh_IDA_bytes': 3368, 'compiler_bounded_bodies': 2, 'exact_source_instructions_checked': 54, 'exhaustive_bank_inputs': 2048, 'retained_queries_unsat': 4, 'independent_local_queries_unsat': 4, 'unaligned_pointer_counterexamples': 1}
PINNED_IMPORT_SOURCE={'fresh_IDA_spans': 1, 'fresh_IDA_bytes': 1240, 'original_file_code_bytes': 5348, 'earlier_parent_file_bytes': 85464, 'original_file_bank_bytes': 3072, 'original_file_fixup_words': 79512, 'compiler_function_starts': 1602, 'exact_source_instructions_checked': 19, 'retained_queries_unsat': 2, 'independent_local_queries_unsat': 2}
REPLAY={'complete_CPU_frames_checked': 15001, 'limb_values_checked': 1152, 'input_bytes_checked': 4608, 'importer_outcomes_checked': 36, 'operand_CPU_points_checked': 1088, 'second_cursor_checkpoints_checked': 72, 'original_pointer_profile_associations_checked': 1684, 'complete_final_RAM_bytes_checked': 5455872, 'original_visits_checked': 306543, 'original_reads_checked': 32696, 'original_writes_checked': 6162, 'PAC_models_checked': 13607, 'selected_65537_initializers_checked': 18, 'source_recurrence_steps_checked': 868, 'odd_inverse_oracles_checked': 24, 'selected_scalar_one_initializers_checked': 28, 'even_noninverse_controls_checked': 4}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_MANIFEST_SHA
    previous,current=json.loads(raw),json.loads(read(BASE/MANIFEST));old={r['path']:r for r in previous['files']};new={r['path']:r for r in current['files']}
    assert len(old)==len(previous['files'])==8262 and len(new)==len(current['files'])==8269
    assert not old.keys()-new.keys()and new.keys()-old.keys()==ADDED and {p for p in old if old[p]!=new[p]}==CHANGED
    assert current['inputs_preserved']==previous['inputs_preserved']
    for row in current['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==new[p]['sha256']and size(BASE/p)==new[p]['size_bytes']
    report=read(BASE/'fpsd1201_operand_report.md');assert all(f'| OP{i} |'in report for i in range(1,9))and all(f'**QG{i}**'in report for i in range(1,8))
    e=json.loads(read(ROOT/'fpsd1201_operand_checks.json'));assert e['verified_counts']==COUNTS and sha(ROOT/'recover_fpsd1201_operand.py')==e['generator_sha256']
    for n,h in e['dependencies'].items():assert sha(ROOT/n)==h
    assert not any(e[k]for k in ['whole_parent_replayed','native_target_executed','IDB_edit_operations_requested','full_goal_complete'])
    receipt=json.loads(read(ROOT/'fpsd1201_operand_audit.json'));assert receipt['fresh_replay_completed']and receipt['process_exit_code']==0 and not receipt['native_target_executed']
    assert receipt['auditor_sha256']==sha(ROOT/'audit_fpsd1201_operand.py')and receipt['checks_sha256']==sha(ROOT/'fpsd1201_operand_checks.json')
    assert receipt['IDA_readback_sha256']==e['IDA_readback_sha256']==sha(ROOT/'fpsd1201_operand_ida_readback.json')and receipt['dependencies']==e['dependencies']
    r=receipt['result'];assert r['all_checks_pass']and r['source']==SOURCE and r['pinned_predecessor_source']==PRIOR_SOURCE and r['pinned_import_source']==PINNED_IMPORT_SOURCE and r['fresh_replay']==REPLAY
    assert(r['profiles'],r['unbacked_context_frontiers'],r['backed_operand_prefixes'],r['next_callee_targets'])==(36,8,28,['0x5a600c'])
    assert r['candidate_inline128_reads_or_writes']==0 and not any(r[k]for k in ['whole_parent_replayed','complete_operand_child_return_established','native_target_executed','full_goal_complete'])
    assert len(e['profiles'])==36 and len(e['proofs'])==40 and len(e['bindings']['selected_bindings'])==15
    for p in e['profiles']:
        backed=p['configuration']['backed'];assert not p['native_effects']and len(p['import_points'])==2
        assert p['stop_reason']==('callee_boundary'if backed else'unbacked_context_payload')and len(p['operand_points'])==(38 if backed else 3)
        assert len(p['operand_controls'])==(3 if backed else 0)and not p['frontier']['instruction_executed']
        if backed:assert p['frontier']['pc']=='0x14f9408'and p['frontier']['target']=='0x5a600c'and p['frontier']['original_slot']=='0x1d03860'
        else:assert p['frontier']=={'pc':'0x14f8edc','instruction_executed':False,'read_address':'0xa5a5a5a5a5a5a5a5','read_size_B':4}
        assert p['final_delta_cell_u64']==hex(p['configuration']['seed_u64'])and p['final_status_u32']=='0xa5a5a5a5'
    f=e['reference_file_check'];assert f['logical_reference_name']=='CoreFP'and f['selected_slice_size_B']==30797904
    assert f['original_fixup_words_checked']==79512 and f['code_bytes_checked']==13852 and f['earlier_parent_bytes_checked']==85464 and f['bank_bytes_checked']==3072
    att=json.loads(read(ROOT/'fpsd1201_operand_ida_readback.json'));assert not att['IDB_mutated']and not att['native_target_executed']and len(att['spans'])==2
    assert sum(s['size_B']for s in att['spans'])==8504 and all(s['current_equals_IDA_original_bytes']for s in att['spans'])
    assert current['validation']['fpsd1201_operand_increment_checks']==COUNTS and current['validation']['fpsd1201_operand_static_scope']==e['scope']
    assert current['validation']['reports']==previous['validation']['reports']+1==425
    assert current['validation']['unavailable_external_primary_references']==previous['validation']['unavailable_external_primary_references']
    assert current['goal_status']=='active'and len(OWNED)==17
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        if p=='triage_evidence/fpsd1201_operand_checks.json.zst':path_hygiene(json.dumps(paths_in_typed_payloads(e)).encode())
        else:path_hygiene(read(BASE/(p[:-4]if p.endswith('.zst')else p)).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED
    print(json.dumps({'unchanged_manifest_entries':len(old)-len(CHANGED),'owned_physical_files':len(OWNED),'original_inputs_preserved':3,
      'reports':425,'private_profiles':36,'unbacked_context_frontiers':8,'backed_operand_prefixes':28,'odd_inverse_oracles':24,
      'even_noninverse_controls':4,'scalar_one_initializers':28,'pinned_fresh_visits':306543,'new_source_queries_unsat':40,
      'publication_does_not_replay_instructions':True,'native_target_executed':False,'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
