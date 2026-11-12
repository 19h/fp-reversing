#!/usr/bin/env python3
"""Verify exact auxiliary/consumer publication without instruction replay.

Time O(owned bytes + manifest + decoded RAM); space O(largest artifact +
decoded RAM). Original inputs and all prior unowned artifacts are preserved.
"""
import json,subprocess
from pathlib import Path
from hashlib import sha256
from compression import zstd
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene
from verify_fpsd1200_process_publication import paths_in_typed_payloads

ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='9f868e957ce1a2d3d9fd88782859354c45c09e09'
BASELINE_MANIFEST_SHA='e2be7ac24c3a8c6644ca2bf9bb43899d481b3db63c4a6bcddbea949952e0c809'
AUDIT_SHA='623b257cc3ccb1e670cad46a50615f43d21cf6e0abbad4ae9cb80c7f0ea80084'
CHECKS_SHA='74b33c02eed2bf8d7368ea04478e7bb5489b8eedc8922d74936f18aa09ad95c6'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','daemon_receive_interface_report.md','foundational_triage_report.md',
 'fpsd1201_product_report.md','interface_abi_report.md','interface_investigation_status.md',
 'mach_ports_report.md','obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'fpsd1201_auxiliary_report.md','triage_evidence/recover_fpsd1201_auxiliary.py','triage_evidence/audit_fpsd1201_auxiliary.py',
 'triage_evidence/verify_fpsd1201_auxiliary_publication.py','triage_evidence/fpsd1201_auxiliary_checks.json',
 'triage_evidence/fpsd1201_auxiliary_audit.json','triage_evidence/fpsd1201_auxiliary_ida_readback.json'}
ARCHIVES={MANIFEST,'triage_evidence/fpsd1201_auxiliary_checks.json','triage_evidence/fpsd1201_auxiliary_audit.json','triage_evidence/fpsd1201_auxiliary_ida_readback.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'profiles':210,'prefix_instructions_rerun':0,'source_visits':427091,'source_reads':66724,'source_writes':25205,
 'PAC_models':13710,'helper_points':778,'consumer_points':48,'fresh_IDA_spans':2,'fresh_IDA_bytes':912,'source_code_bytes':40412,'local_queries_unsat':3}
SOURCE={'fresh_IDA_spans':2,'fresh_IDA_bytes':912,'compiler_bounded_bodies':2,'total_selected_code_bytes':40412,
 'original_fixup_words_checked':79512,'compiler_starts_checked':1602,'retained_queries_unsat':3,'independent_queries_unsat':3,'exact_source_instructions_checked':17,'universal_consumer_algorithm_proof':False}
TOTALS={'restored_RAM_bytes_checked':31825920,'checkpoint_reaching_loads_checked':24,'complete_CPU_frames_checked':14956,'initial_RAM_bytes_checked':31825920,
 'helper_points_checked':778,'bounded_unbacked_payload_frontiers_checked':8,'original_pointer_profile_associations_checked':2070,'final_RAM_bytes_checked':31825920,
 'original_visits_checked':427091,'original_reads_checked':66724,'original_writes_checked':25205,'PAC_models_checked':13710,'bit_length_oracles_checked':56,'bit_selection_oracles_checked':329,
 'final_scalar_one_initializers_checked':16,'consumer_loop_call_sequences_checked':16,'consumer_loop_squares_checked':183,'consumer_loop_products_checked':55,
 'modular_exponentiation_oracles_checked':14,'complete_consumer_child_returns_checked':16,'complete_consumer_wrapper_returns_checked':16,'consumer_caller_resumes_checked':16,
 'consumer_stack_emission_stores_checked':16,'even_consumer_controls_checked':2,'isolated_helper_returns_checked':186,'null_payload_no_reads_checked':4,'signed_minimum_count_zero_results':2}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_MANIFEST_SHA
    old,current=json.loads(raw),json.loads(read(BASE/MANIFEST));previous={r['path']:r for r in old['files']};new={r['path']:r for r in current['files']}
    assert len(previous)==len(old['files'])==8311 and len(new)==len(current['files'])==8318
    assert not previous.keys()-new.keys()and new.keys()-previous.keys()==ADDED and {p for p in previous if previous[p]!=new[p]}==CHANGED
    assert current['inputs_preserved']==old['inputs_preserved']and len(current['inputs_preserved'])==3
    for r in current['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==new[p]['sha256']and size(BASE/p)==new[p]['size_bytes']
    report=read(BASE/'fpsd1201_auxiliary_report.md');assert all(f'| AX{i} |'in report for i in range(1,8))and all(f'**QG{i}**'in report for i in range(1,8))
    assert sha(ROOT/'fpsd1201_auxiliary_checks.json')==CHECKS_SHA
    e=json.loads(read(ROOT/'fpsd1201_auxiliary_checks.json'));assert e['verified_counts']==COUNTS and e['generator_sha256']==sha(ROOT/'recover_fpsd1201_auxiliary.py')
    for n,h in e['dependencies'].items():assert sha(ROOT/n)==h
    assert not any(e[k]for k in ['whole_parent_replayed','native_target_executed','IDB_edit_operations_requested','full_goal_complete'])
    assert sha(ROOT/'fpsd1201_auxiliary_audit.json')==AUDIT_SHA
    a=json.loads(read(ROOT/'fpsd1201_auxiliary_audit.json'));assert a['fresh_replay_completed']and a['process_exit_code']==0 and not a['native_target_executed']
    assert a['auditor_sha256']==sha(ROOT/'audit_fpsd1201_auxiliary.py')and a['checks_sha256']==CHECKS_SHA and a['dependencies']==e['dependencies']
    assert a['IDA_readback_sha256']==e['IDA_readback_sha256']==sha(ROOT/'fpsd1201_auxiliary_ida_readback.json')=='894f1bec15525fd91b2b4e719050d6d34dd3d7f69011af5ac09f47cf35bb301b'
    r=a['result'];assert r['source']==SOURCE and r['fresh_replay']==TOTALS and r['all_checks_pass']and r['profiles']==210
    assert r['modes']=={'retained':12,'exponent':12,'length':40,'bit':146}and r['next_callee_targets']==['0x32f628']
    assert r['prior_replay_receipt_sha256']==sha(ROOT/'fpsd1201_product_audit.json')=='219fd7b1a149580151b1fe9475f25652cf2990e526c7ce872d3bf53bec57ca7e'
    assert not any(r[k]for k in ['nested_candidate_inline128_reads_or_writes','prefix_instructions_rerun','whole_parent_replayed','native_target_executed','full_goal_complete'])
    assert len(e['profiles'])==len(r['profile_summaries'])==210 and len(e['proofs'])==3 and all(q['result']=='unsat'for q in e['proofs'])
    counts={'returned':0,'unbacked_auxiliary_payload':0,'unretained_callee':0};odd=even=0
    for p,s in zip(e['profiles'],r['profile_summaries']):
        counts[p['stop_reason']]+=1;assert not p['native_effects']
        if p['configuration']['mode']in ['length','bit']:assert p['stop_reason']=='returned'and p['frontier']is None and p['terminal']['pc']=='0x7f000000'
        elif p['stop_reason']=='unbacked_auxiliary_payload':
            assert p['frontier']=={'pc':'0x59f650','read_address':'0xa5a5a5a710087af5','size_B':4,'instruction_executed':False}and not p['consumer_points']
        else:
            assert p['stop_reason']=='unretained_callee'and p['frontier']['pc']=='0x981bc8'and p['frontier']['target']=='0x32f628'and not p['frontier']['instruction_executed']
            assert [q['pc']for q in p['consumer_points']]==['0x1142874','0x1142e2c','0x9819c8']
            if int(s['modulus_hex'],16)&1:assert s['pow_oracle_matches']is True;odd+=1
            else:assert s['pow_oracle_matches']is None;even+=1
    assert counts=={'returned':186,'unbacked_auxiliary_payload':8,'unretained_callee':16}and(odd,even)==(14,2)
    f=e['reference_file_check'];assert(f['original_fixup_words_checked'],f['code_bytes_checked'],f['earlier_parent_bytes_checked'],f['bank_bytes_checked'])==(79512,40412,85464,3072)
    att=json.loads(read(ROOT/'fpsd1201_auxiliary_ida_readback.json'));assert not att['IDB_mutated']and not att['native_target_executed']and len(att['spans'])==2
    assert sum(s['size_B']for s in att['spans'])==912 and all(s['current_equals_IDA_original_bytes']for s in att['spans'])
    assert current['validation']['fpsd1201_auxiliary_increment_checks']==COUNTS and current['validation']['fpsd1201_auxiliary_static_scope']==e['scope']
    assert current['validation']['reports']==old['validation']['reports']+1==432 and current['goal_status']=='active'
    assert current['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']and len(OWNED)==17
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        logical=p[:-4]if p.endswith('.zst')else p
        if logical=='triage_evidence/fpsd1201_auxiliary_checks.json':path_hygiene(json.dumps(paths_in_typed_payloads(e)).encode())
        else:path_hygiene(read(BASE/logical).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED
    print(json.dumps({'unchanged_manifest_entries':len(previous)-len(CHANGED),'owned_physical_files':len(OWNED),'original_inputs_preserved':3,'reports':432,
      'profiles':210,'bit_length_oracles':56,'bit_selection_oracles':329,'modular_exponentiation_oracles':14,'even_consumer_controls':2,'complete_consumer_returns':16,
      'prefix_instructions_rerun':0,'publication_does_not_replay_instructions':True,'native_target_executed':False,'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
