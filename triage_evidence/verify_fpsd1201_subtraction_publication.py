#!/usr/bin/env python3
"""Pin independently audited subtraction evidence and exact publication delta.

O(owned bytes + manifest + decoded RAM) time and O(largest artifact + decoded
RAM) space. No instruction replay or native effects. Reference correspondence
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
PREVIOUS='07c69b260af2fdd03246aad9aeb80f30d5a0f67f'
BASELINE_MANIFEST_SHA='e0a95b2fae9329773df64b9105991cc6bede6614d4c3f032dfbe2f6ba1aac05d'
AUDIT_SHA='79a198ffc83f8182d7803904ab696b21702bac9937adab342dcc7fea62b37dc6'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','daemon_receive_interface_report.md','foundational_triage_report.md',
 'fpsd1201_comparison_report.md','interface_abi_report.md','interface_investigation_status.md',
 'mach_ports_report.md','obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'fpsd1201_subtraction_report.md','triage_evidence/recover_fpsd1201_subtraction.py',
 'triage_evidence/audit_fpsd1201_subtraction.py','triage_evidence/verify_fpsd1201_subtraction_publication.py',
 'triage_evidence/fpsd1201_subtraction_checks.json','triage_evidence/fpsd1201_subtraction_audit.json','triage_evidence/fpsd1201_subtraction_ida_readback.json'}
ARCHIVES={'triage_evidence/fpsd1201_subtraction_checks.json','triage_evidence/fpsd1201_subtraction_audit.json',
 'triage_evidence/fpsd1201_subtraction_ida_readback.json',MANIFEST}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'profiles':197,'nested_profiles':8,'isolated_root_profiles':141,'isolated_difference_profiles':24,'isolated_addition_profiles':24,
 'source_visits':252548,'source_reads':42868,'source_writes':11501,'PAC_models':9822,'arithmetic_points':841,'dependency_points':712,
 'carry_points':2676,'fresh_IDA_spans':3,'fresh_IDA_bytes':4608,'source_code_bytes':26136,'local_queries_unsat':11}
SOURCE={'fresh_IDA_spans':3,'fresh_IDA_bytes':4608,'compiler_bounded_bodies':3,'total_selected_code_bytes':26136,
 'retained_queries_unsat':11,'independent_word_queries_unsat':10,'exact_source_instructions_checked':23,'complete_algorithm_universally_proved':False}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_MANIFEST_SHA
    previous,current=json.loads(raw),json.loads(read(BASE/MANIFEST));old={r['path']:r for r in previous['files']};new={r['path']:r for r in current['files']}
    assert len(old)==len(previous['files'])==8283 and len(new)==len(current['files'])==8290
    assert not old.keys()-new.keys()and new.keys()-old.keys()==ADDED and {p for p in old if old[p]!=new[p]}==CHANGED
    assert current['inputs_preserved']==previous['inputs_preserved']
    for r in current['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==new[p]['sha256']and size(BASE/p)==new[p]['size_bytes']
    report=read(BASE/'fpsd1201_subtraction_report.md');assert all(f'| SU{i} |'in report for i in range(1,9))and all(f'**QG{i}**'in report for i in range(1,8))
    e=json.loads(read(ROOT/'fpsd1201_subtraction_checks.json'));assert e['verified_counts']==COUNTS and sha(ROOT/'recover_fpsd1201_subtraction.py')==e['generator_sha256']
    for n,h in e['dependencies'].items():assert sha(ROOT/n)==h
    assert not any(e[k]for k in ['whole_parent_replayed','native_target_executed','IDB_edit_operations_requested','full_goal_complete'])
    assert sha(ROOT/'fpsd1201_subtraction_audit.json')==AUDIT_SHA
    receipt=json.loads(read(ROOT/'fpsd1201_subtraction_audit.json'));assert receipt['fresh_replay_completed']and receipt['process_exit_code']==0 and not receipt['native_target_executed']
    assert receipt['auditor_sha256']==sha(ROOT/'audit_fpsd1201_subtraction.py')and receipt['checks_sha256']==sha(ROOT/'fpsd1201_subtraction_checks.json')
    assert receipt['IDA_readback_sha256']==e['IDA_readback_sha256']==sha(ROOT/'fpsd1201_subtraction_ida_readback.json')and receipt['dependencies']==e['dependencies']
    r=receipt['result'];assert r['all_checks_pass']and r['source']==SOURCE
    assert(r['profiles'],r['nested_profiles'],r['isolated_root_profiles'],r['isolated_difference_profiles'],r['isolated_addition_profiles'])==(197,8,141,24,24)
    assert r['continued_caller_stop_pc']=='0x14f9d78'and r['candidate_inline128_reads_or_writes']==0
    assert not any(r[k]for k in ['whole_parent_replayed','complete_operand_child_return_established','native_target_executed','full_goal_complete'])
    totals=r['fresh_replay']
    for k,v in {'original_visits_checked':252548,'original_reads_checked':42868,'original_writes_checked':11501,'PAC_models_checked':9822,
      'complete_CPU_frames_checked':14903,'complete_final_RAM_bytes_checked':29855744,'canonical_integer_outcomes_checked':196,
      'zero_first_null_second_bypasses_checked':1,'complete_nested_subtraction_returns_checked':8,'complete_isolated_root_returns_checked':141,
      'complete_direct_difference_returns_checked':24,'complete_direct_addition_returns_checked':24,'self_subtraction_zero_outcomes_checked':11,
      'common_limb_carry_and_store_steps_checked':475,'arithmetic_sign_query_returns_checked':173,'arithmetic_zero_query_returns_checked':173,
      'zero_second_raw_copy_returns_checked':10,'preserved_nonoutput_inputs_checked':201,'seed_dependent_stack_geometries_checked':8}.items():assert totals[k]==v
    assert len(e['profiles'])==197 and len(e['proofs'])==11 and all(p['result']=='unsat'for p in e['proofs'])
    calls={'0x14f9d74':('0x5e8158','0x1d03920','0x6144'),'0x5e8428':('0x649430','0x1d039b8','0x8dc5'),
      '0x5e8558':('0x1ec40','0x1d03f90','0xc137'),'0x5e8600':('0x443bf4','0x1d04af8','0x6693'),
      '0x1eea0':('0x624ff0','0x1d04610','0x9c78'),'0x443e3c':('0x624ff0','0x1d04610','0x9c78')};seen=set()
    max_output=0
    for j,p in enumerate(e['profiles']):
        assert not p['native_effects']and p['configuration']['mode']==('nested'if j<8 else'root'if j<149 else'leaf_sub'if j<173 else'leaf_add')
        assert p['stop_reason']==('after_subtraction_return'if j<8 else'returned')
        assert p['arithmetic_points'][-1]['pc']==('0x14f9d78'if j<8 else'0x7f000000')
        if j<8:
            assert p['frontier']=={'pc':'0x14f9d78','instruction_executed':False,'completed_callee':'0x5e8158'}
            assert p['final_status_u32']=='0xa5a5a5a5'and p['final_delta_cell_u64']==hex(p['configuration']['seed_u64'])
        else:assert p['frontier']is None
        for q in p['PAC_models']:
            if q['pc']in calls:
                assert(q['target'],q['original_slot'],q['modifier'])==calls[q['pc']];seen.add(q['pc'])
        out=p['arithmetic_points'][-1]['output']
        if out:
            n=(int.from_bytes(bytes.fromhex(out['descriptor16_hex'])[4:8],'little')-0x4b0cf050)&0xffffffff
            n=n-(1<<32)if n>>31 else n;max_output=max(max_output,abs(n))
    assert seen==calls.keys()and max_output==65
    f=e['reference_file_check'];assert f['logical_reference_name']=='CoreFP'and f['selected_slice_size_B']==30797904
    assert(f['original_fixup_words_checked'],f['code_bytes_checked'],f['earlier_parent_bytes_checked'],f['bank_bytes_checked'])==(79512,26136,85464,3072)
    att=json.loads(read(ROOT/'fpsd1201_subtraction_ida_readback.json'));assert not att['IDB_mutated']and not att['native_target_executed']and len(att['spans'])==3
    assert sum(s['size_B']for s in att['spans'])==4608 and all(s['current_equals_IDA_original_bytes']for s in att['spans'])
    assert current['validation']['fpsd1201_subtraction_increment_checks']==COUNTS and current['validation']['fpsd1201_subtraction_static_scope']==e['scope']
    assert current['validation']['reports']==previous['validation']['reports']+1==428
    assert current['validation']['unavailable_external_primary_references']==previous['validation']['unavailable_external_primary_references']
    assert current['goal_status']=='active'and len(OWNED)==17
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        if p=='triage_evidence/fpsd1201_subtraction_checks.json.zst':path_hygiene(json.dumps(paths_in_typed_payloads(e)).encode())
        else:path_hygiene(read(BASE/(p[:-4]if p.endswith('.zst')else p)).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED
    print(json.dumps({'unchanged_manifest_entries':len(old)-len(CHANGED),'owned_physical_files':len(OWNED),'original_inputs_preserved':3,
      'reports':428,'private_profiles':197,'canonical_integer_outcomes':196,'zero_first_null_second_bypasses':1,
      'new_source_queries_unsat':11,'independent_word_queries_unsat':10,'maximum_output_limbs':max_output,
      'publication_does_not_replay_instructions':True,'native_target_executed':False,'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
