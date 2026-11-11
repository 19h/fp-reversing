#!/usr/bin/env python3
"""Pin independently replayed precomputation and the exact publication delta.

O(owned bytes + manifest + decoded RAM) time, O(largest artifact + decoded
RAM) space. No instruction replay or native effects. Reference correspondence
is pinned by the audit receipt; reference binaries are not published.
"""
import json,subprocess
from hashlib import sha256
from pathlib import Path
from compression import zstd
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene
from verify_fpsd1200_process_publication import paths_in_typed_payloads

ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='64c9b5654591abd0644a06543c88cb81a0f2f45f'
BASELINE_MANIFEST_SHA='15a0e7796fd35a28eae18e020e7b443cec58e0029f0ce47411ec9c2cc552507b'
AUDIT_SHA='40264eef84f86e6fdf9de0a480b6e46b88ffcc3f9168db976600e6bc818ca2e0'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','daemon_receive_interface_report.md','foundational_triage_report.md',
 'fpsd1201_subtraction_report.md','interface_abi_report.md','interface_investigation_status.md',
 'mach_ports_report.md','obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'fpsd1201_reduction_report.md','triage_evidence/recover_fpsd1201_reduction.py',
 'triage_evidence/audit_fpsd1201_reduction.py','triage_evidence/verify_fpsd1201_reduction_publication.py',
 'triage_evidence/fpsd1201_reduction_checks.json','triage_evidence/fpsd1201_reduction_audit.json','triage_evidence/fpsd1201_reduction_ida_readback.json'}
ARCHIVES={'triage_evidence/fpsd1201_reduction_checks.json','triage_evidence/fpsd1201_reduction_audit.json','triage_evidence/fpsd1201_reduction_ida_readback.json',MANIFEST}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'profiles':13,'complete_child_profiles':12,'bounded_zero_profiles':1,'source_visits':1163611,'source_reads':185439,
 'source_writes':61248,'PAC_models':35672,'family_points':4752,'subtraction_returns':318,'fresh_IDA_spans':2,'fresh_IDA_bytes':4904,'source_code_bytes':31040,'local_queries_unsat':5}
SOURCE={'fresh_IDA_spans':2,'fresh_IDA_bytes':4904,'compiler_bounded_bodies':2,'total_selected_code_bytes':31040,
 'retained_queries_unsat':5,'independent_cursor_queries_unsat':5,'exact_source_instructions_checked':23,'complete_algorithm_universally_proved':False}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def number(d):
    r=bytes.fromhex(d['descriptor16_hex']);n=(int.from_bytes(r[4:8],'little')-0x4b0cf050)&0xffffffff;n=n-(1<<32)if n>>31 else n
    b=bytes.fromhex(d['payload512_hex']);v=sum((int.from_bytes(b[j*4:j*4+4],'little')^0x1ac70ef2)<<(32*j)for j in range(abs(n)))
    return -v if n<0 else v


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_MANIFEST_SHA
    previous,current=json.loads(raw),json.loads(read(BASE/MANIFEST));old={r['path']:r for r in previous['files']};new={r['path']:r for r in current['files']}
    assert len(old)==len(previous['files'])==8290 and len(new)==len(current['files'])==8297
    assert not old.keys()-new.keys()and new.keys()-old.keys()==ADDED and {p for p in old if old[p]!=new[p]}==CHANGED
    assert current['inputs_preserved']==previous['inputs_preserved']
    for r in current['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==new[p]['sha256']and size(BASE/p)==new[p]['size_bytes']
    report=read(BASE/'fpsd1201_reduction_report.md');assert all(f'| RF{i} |'in report for i in range(1,9))and all(f'**QG{i}**'in report for i in range(1,8))
    e=json.loads(read(ROOT/'fpsd1201_reduction_checks.json'));assert e['verified_counts']==COUNTS and sha(ROOT/'recover_fpsd1201_reduction.py')==e['generator_sha256']
    for n,h in e['dependencies'].items():assert sha(ROOT/n)==h
    assert not any(e[k]for k in ['whole_parent_replayed','native_target_executed','IDB_edit_operations_requested','full_goal_complete'])
    assert sha(ROOT/'fpsd1201_reduction_audit.json')==AUDIT_SHA
    receipt=json.loads(read(ROOT/'fpsd1201_reduction_audit.json'));assert receipt['fresh_replay_completed']and receipt['process_exit_code']==0 and not receipt['native_target_executed']
    assert receipt['auditor_sha256']==sha(ROOT/'audit_fpsd1201_reduction.py')and receipt['checks_sha256']==sha(ROOT/'fpsd1201_reduction_checks.json')
    assert receipt['IDA_readback_sha256']==e['IDA_readback_sha256']==sha(ROOT/'fpsd1201_reduction_ida_readback.json')and receipt['dependencies']==e['dependencies']
    r=receipt['result'];assert r['all_checks_pass']and r['source']==SOURCE
    assert(r['profiles'],r['complete_child_profiles'],r['bounded_zero_profiles'],r['next_callee_targets'])==(13,12,1,['0x1142c08'])
    assert r['candidate_inline128_reads_or_writes']==0 and not any(r[k]for k in ['whole_parent_replayed','native_target_executed','full_goal_complete'])
    totals=r['fresh_replay']
    expected={'original_visits_checked':1163611,'original_reads_checked':185439,'original_writes_checked':61248,'PAC_models_checked':35672,
      'complete_CPU_frames_checked':41365,'complete_final_RAM_bytes_checked':1970176,'continued_final_RAM_bytes_checked':1970176,
      'complete_arithmetic_child_returns_checked':12,'one_word_REDC_square_oracles_checked':60,'odd_Montgomery_square_oracles_checked':45,
      'even_noninverse_square_controls_checked':15,'odd_complete_R_and_R2_oracles_checked':9,'even_complete_first_remainder_controls_checked':3,
      'square_seed_frame_geometries_checked':60,'square_child_cursor_restores_checked':60,'square_wrapper_zero_adjustments_checked':60,
      'outer_wrapper_zero_adjustments_checked':12,'outer_wrapper_child_returns_checked':12,'zero_control_stable_numeric_checkpoints':64,
      'complete_continued_shift_oracles_checked':468,'complete_continued_copy_oracles_checked':127,'complete_continued_comparison_oracles_checked':1148,
      'complete_continued_subtraction_oracles_checked':323}
    for k,v in expected.items():assert totals[k]==v
    assert len(e['profiles'])==13 and len(e['proofs'])==5 and all(p['result']=='unsat'for p in e['proofs'])
    values=[1,3,5,7,0,2,0x80000000,0xfffffffe,17,65537,0xffffffff,0x80000001,0x7fffffff]
    iterations=[33,45,43,39,64,32,2,1,39,16,1,1,2]
    calls={'0x14fa518':('0x9dd7e4','0x1d04298','0xb7d3'),'0x9dd9d4':('0x9dc6d4','0x1d05a30','0xde9d')};seen=set()
    for p,n,count,s in zip(e['profiles'],values,iterations,r['profile_summaries']):
        assert p['configuration']['operand_u32']==s['operand_u32']==n and p['subtraction_returns']==s['subtraction_returns']==count
        assert not p['native_effects']and p['final_status_u32']=='0xa5a5a5a5'and p['final_delta_cell_u64']==hex(p['configuration']['seed_u64'])
        squares=[q for q in p['family_points']if q['pc']=='0x9dc6d4'];ends=[q for q in p['family_points']if q['pc']=='0x14f99e0']
        if n:
            assert p['stop_reason']=='unretained_callee'and p['frontier']['pc']=='0x9819c4'and p['frontier']['target']=='0x1142c08'and not p['frontier']['instruction_executed']
            assert len(squares)==s['square_returns']==5 and len(ends)==1 and not p['pending_family_entries']
            assert number(squares[0]['views']['input'])==((1<<33)%n)
            assert number(ends[0]['views']['pair_first'])==(1<<32)%n
            if n&1:assert number(ends[0]['views']['pair_second'])==(1<<64)%n
            if n==0xfffffffe:assert number(ends[0]['views']['pair_second'])==0x140aa03d!=(1<<64)%n
        else:
            assert not squares and not ends and s['square_returns']==0 and p['pending_family_entries']==['0x14f8d28']
            assert p['stop_reason']=='zero_control_iteration_limit'and p['frontier']=={'pc':'0x14f9d78','instruction_executed':False,'completed_subtraction_returns':64}
        for q in p['PAC_models']:
            if q['pc']in calls:assert(q['target'],q['original_slot'],q['modifier'])==calls[q['pc']];seen.add(q['pc'])
    assert seen==calls.keys()
    f=e['reference_file_check'];assert f['logical_reference_name']=='CoreFP'and f['selected_slice_size_B']==30797904
    assert(f['original_fixup_words_checked'],f['code_bytes_checked'],f['earlier_parent_bytes_checked'],f['bank_bytes_checked'])==(79512,31040,85464,3072)
    att=json.loads(read(ROOT/'fpsd1201_reduction_ida_readback.json'));assert not att['IDB_mutated']and not att['native_target_executed']and len(att['spans'])==2
    assert sum(s['size_B']for s in att['spans'])==4904 and all(s['current_equals_IDA_original_bytes']for s in att['spans'])
    assert current['validation']['fpsd1201_reduction_increment_checks']==COUNTS and current['validation']['fpsd1201_reduction_static_scope']==e['scope']
    assert current['validation']['reports']==previous['validation']['reports']+1==429
    assert current['validation']['unavailable_external_primary_references']==previous['validation']['unavailable_external_primary_references']
    assert current['goal_status']=='active'and len(OWNED)==17
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        if p=='triage_evidence/fpsd1201_reduction_checks.json.zst':path_hygiene(json.dumps(paths_in_typed_payloads(e)).encode())
        else:path_hygiene(read(BASE/(p[:-4]if p.endswith('.zst')else p)).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED
    print(json.dumps({'unchanged_manifest_entries':len(old)-len(CHANGED),'owned_physical_files':len(OWNED),'original_inputs_preserved':3,'reports':429,
      'profiles':13,'complete_child_returns':12,'bounded_zero_controls':1,'REDC_square_oracles':60,'odd_R_and_R2_oracles':9,
      'publication_does_not_replay_instructions':True,'native_target_executed':False,'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
