#!/usr/bin/env python3
"""Pin independently audited comparison evidence and exact publication delta.

No instruction replay or native effects. O(owned bytes + manifest + decoded
RAM) time; O(largest artifact + decoded RAM) space. Reference correspondence
is pinned by the fresh audit receipt; reference binaries are not published.
"""
import json,subprocess
from hashlib import sha256
from pathlib import Path
from compression import zstd
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene
from verify_fpsd1200_process_publication import paths_in_typed_payloads

ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='bff1c2400bf56b32a359893605585f9bcfdd9d6a'
BASELINE_MANIFEST_SHA='0099bafe6f8ee8b735670bea19eaa55d5a417ae3e4f5694d28c151fbfe8bb42c'
AUDIT_SHA='b71b8b393d25ec84391ed715e9460e1518cef03f377c7d4e4092b349bf887fdf'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','daemon_receive_interface_report.md','foundational_triage_report.md',
 'fpsd1201_shift_report.md','interface_abi_report.md','interface_investigation_status.md',
 'mach_ports_report.md','obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'fpsd1201_comparison_report.md','triage_evidence/recover_fpsd1201_comparison.py',
 'triage_evidence/audit_fpsd1201_comparison.py','triage_evidence/verify_fpsd1201_comparison_publication.py',
 'triage_evidence/fpsd1201_comparison_checks.json','triage_evidence/fpsd1201_comparison_audit.json','triage_evidence/fpsd1201_comparison_ida_readback.json'}
ARCHIVES={'triage_evidence/fpsd1201_comparison_checks.json','triage_evidence/fpsd1201_comparison_audit.json',
 'triage_evidence/fpsd1201_comparison_ida_readback.json',MANIFEST}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'profiles':243,'nested_profiles':8,'isolated_copy_profiles':104,'isolated_compare_profiles':131,
 'source_visits':176644,'source_reads':20274,'source_writes':5377,'PAC_models':6012,'copy_points':224,
 'compare_points':294,'limb_points':1644,'fresh_IDA_spans':2,'fresh_IDA_bytes':1976,'source_code_bytes':21528,'local_queries_unsat':23}
SOURCE={'fresh_IDA_spans':2,'fresh_IDA_bytes':1976,'compiler_bounded_bodies':2,'total_selected_code_bytes':21528,
 'retained_queries_unsat':23,'independent_source_queries_unsat':20,'source_limb_biases':['0xe538f10e','0xe538f10e'],
 'exact_source_instructions_checked':18,'source_lifters_use_distinct_operand_decoders':True,'complete_algorithm_universally_proved':False}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_MANIFEST_SHA
    previous,current=json.loads(raw),json.loads(read(BASE/MANIFEST));old={r['path']:r for r in previous['files']};new={r['path']:r for r in current['files']}
    assert len(old)==len(previous['files'])==8276 and len(new)==len(current['files'])==8283
    assert not old.keys()-new.keys()and new.keys()-old.keys()==ADDED and {p for p in old if old[p]!=new[p]}==CHANGED
    assert current['inputs_preserved']==previous['inputs_preserved']
    for r in current['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==new[p]['sha256']and size(BASE/p)==new[p]['size_bytes']
    report=read(BASE/'fpsd1201_comparison_report.md');assert all(f'| CP{i} |'in report for i in range(1,9))and all(f'**QG{i}**'in report for i in range(1,8))
    e=json.loads(read(ROOT/'fpsd1201_comparison_checks.json'));assert e['verified_counts']==COUNTS and sha(ROOT/'recover_fpsd1201_comparison.py')==e['generator_sha256']
    for n,h in e['dependencies'].items():assert sha(ROOT/n)==h
    assert not any(e[k]for k in ['whole_parent_replayed','native_target_executed','IDB_edit_operations_requested','full_goal_complete'])
    assert sha(ROOT/'fpsd1201_comparison_audit.json')==AUDIT_SHA
    receipt=json.loads(read(ROOT/'fpsd1201_comparison_audit.json'));assert receipt['fresh_replay_completed']and receipt['process_exit_code']==0 and not receipt['native_target_executed']
    assert receipt['auditor_sha256']==sha(ROOT/'audit_fpsd1201_comparison.py')and receipt['checks_sha256']==sha(ROOT/'fpsd1201_comparison_checks.json')
    assert receipt['IDA_readback_sha256']==e['IDA_readback_sha256']==sha(ROOT/'fpsd1201_comparison_ida_readback.json')and receipt['dependencies']==e['dependencies']
    r=receipt['result'];assert r['all_checks_pass']and r['source']==SOURCE
    assert(r['profiles'],r['nested_profiles'],r['isolated_copy_profiles'],r['isolated_compare_profiles'],r['next_callee_targets'])==(243,8,104,131,['0x5e8158'])
    assert r['candidate_inline128_reads_or_writes']==0 and not any(r[k]for k in ['whole_parent_replayed','complete_operand_child_return_established','native_target_executed','full_goal_complete'])
    totals=r['fresh_replay'];assert totals['original_visits_checked']==176644 and totals['complete_final_RAM_bytes_checked']==36827136
    assert(totals['complete_copy_oracles_checked'],totals['complete_compare_oracles_checked'],totals['signed_integer_comparison_oracles_checked'],totals['noncanonical_numeric_zero_counterexamples_checked'])==(112,147,143,4)
    assert(totals['same_descriptor_bypasses_checked'],totals['zero_count_no_limb_access_checked'],totals['raw_limb_copies_checked'],totals['seed_dependent_stack_geometries_checked'])==(52,5,1019,8)
    assert len(e['profiles'])==243 and len(e['proofs'])==23 and all(p['result']=='unsat'for p in e['proofs'])
    for j,p in enumerate(e['profiles']):
        assert not p['native_effects']and p['configuration']['mode']==('nested'if j<8 else'copy'if j<112 else'compare')
        assert p['stop_reason']==('unretained_callee'if j<8 else'returned')
        assert len(p['copy_points'])==(2 if j<112 else 0)and len(p['compare_points'])==(4 if j<8 else 0 if j<112 else 2)
        if j<8:
            assert p['frontier']['pc']=='0x14f9d74'and p['frontier']['target']=='0x5e8158'and p['frontier']['original_slot']=='0x1d03920'and not p['frontier']['instruction_executed']
            assert p['final_status_u32']=='0xa5a5a5a5'and p['final_delta_cell_u64']==hex(p['configuration']['seed_u64'])
        else:assert p['frontier']is None and p['terminal']['pc']=='0x7f000000'
    f=e['reference_file_check'];assert f['logical_reference_name']=='CoreFP'and f['selected_slice_size_B']==30797904
    assert(f['original_fixup_words_checked'],f['code_bytes_checked'],f['earlier_parent_bytes_checked'],f['bank_bytes_checked'])==(79512,21528,85464,3072)
    att=json.loads(read(ROOT/'fpsd1201_comparison_ida_readback.json'));assert not att['IDB_mutated']and not att['native_target_executed']and len(att['spans'])==2
    assert sum(s['size_B']for s in att['spans'])==1976 and all(s['current_equals_IDA_original_bytes']for s in att['spans'])
    assert current['validation']['fpsd1201_comparison_increment_checks']==COUNTS and current['validation']['fpsd1201_comparison_static_scope']==e['scope']
    assert current['validation']['reports']==previous['validation']['reports']+1==427
    assert current['validation']['unavailable_external_primary_references']==previous['validation']['unavailable_external_primary_references']
    assert current['goal_status']=='active'and len(OWNED)==17
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        if p=='triage_evidence/fpsd1201_comparison_checks.json.zst':path_hygiene(json.dumps(paths_in_typed_payloads(e)).encode())
        else:path_hygiene(read(BASE/(p[:-4]if p.endswith('.zst')else p)).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED
    print(json.dumps({'unchanged_manifest_entries':len(old)-len(CHANGED),'owned_physical_files':len(OWNED),'original_inputs_preserved':3,
      'reports':427,'private_profiles':243,'complete_copy_oracles':112,'complete_compare_oracles':147,'noncanonical_zero_controls':4,
      'new_source_queries_unsat':23,'independent_source_queries_unsat':20,
      'publication_does_not_replay_instructions':True,'native_target_executed':False,'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
