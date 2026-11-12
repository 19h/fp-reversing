#!/usr/bin/env python3
"""Pin complete product replay, classified arithmetic and exact publication.

O(owned bytes + manifest + decoded RAM) time, O(largest artifact + decoded
RAM) space. No instruction replay or native effects. Retained counterexamples
remain explicit; the full interface investigation remains active.
"""
import json,subprocess
from pathlib import Path
from hashlib import sha256
from compression import zstd
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene
from verify_fpsd1200_process_publication import paths_in_typed_payloads

ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='379f8d66b8e4888a4b2eebc7677a5f6573b2c774'
BASELINE_MANIFEST_SHA='fe46b80f68c745a8c6d0056c7d49a69ad80e83957a583663016e71194f37bcf4'
AUDIT_SHA='219fd7b1a149580151b1fe9475f25652cf2990e526c7ce872d3bf53bec57ca7e'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','daemon_receive_interface_report.md','foundational_triage_report.md',
 'fpsd1201_consumer_report.md','interface_abi_report.md','interface_investigation_status.md',
 'mach_ports_report.md','obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'fpsd1201_product_report.md','triage_evidence/recover_fpsd1201_product.py','triage_evidence/audit_fpsd1201_product.py',
 'triage_evidence/verify_fpsd1201_product_publication.py','triage_evidence/fpsd1201_product_checks.json',
 'triage_evidence/fpsd1201_product_audit.json','triage_evidence/fpsd1201_product_ida_readback.json'}
ARCHIVES={MANIFEST,'triage_evidence/fpsd1201_product_checks.json','triage_evidence/fpsd1201_product_audit.json','triage_evidence/fpsd1201_product_ida_readback.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'profiles':96,'retained_checkpoint_profiles':12,'canonicalized_checkpoint_profiles':12,'isolated_product_profiles':72,'prefix_instructions_rerun':0,
 'source_visits':1684168,'source_reads':255310,'source_writes':79914,'PAC_models':59842,'product_points':3320,'caller_points':216,
 'fresh_IDA_spans':2,'fresh_IDA_bytes':5168,'source_code_bytes':39500,'local_queries_unsat':6}
SOURCE={'fresh_IDA_spans':2,'fresh_IDA_bytes':5168,'compiler_bounded_bodies':2,'total_selected_code_bytes':39500,
 'original_fixup_words_checked':79512,'compiler_starts_checked':1602,'retained_queries_unsat':6,'independent_queries_unsat':6,
 'exact_source_instructions_checked':22,'complete_algorithm_universally_proved':False}
TOTALS={'restored_RAM_bytes_checked':14548992,'checkpoint_reaching_pointer_loads_checked':24,'complete_CPU_frames_checked':63570,'initial_RAM_bytes_checked':14548992,
 'product_family_points_checked':3320,'product_frame_geometries_checked':96,'caller_points_checked':216,'early_child_cursor_restores_checked':96,'retained_odd_matches':3,
 'complete_product_child_returns_checked':96,'complete_product_wrapper_returns_checked':96,'copy_oracles_checked':180,'original_pointer_profile_associations_checked':5261,
 'final_RAM_bytes_checked':14548992,'original_visits_checked':1684168,'original_reads_checked':255310,'original_writes_checked':79914,'PAC_models_checked':59842,
 'comparison_oracles_checked':787,'subtraction_oracles_checked':219,'shift_oracles_checked':282,'retained_odd_counterexamples':6,'retained_even_controls_checked':3,
 'canonical_Montgomery_product_oracles_checked':81,'canonical_even_literal_REDC_controls_checked':3}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_MANIFEST_SHA
    old,current=json.loads(raw),json.loads(read(BASE/MANIFEST));previous={r['path']:r for r in old['files']};new={r['path']:r for r in current['files']}
    assert len(previous)==len(old['files'])==8304 and len(new)==len(current['files'])==8311
    assert not previous.keys()-new.keys()and new.keys()-previous.keys()==ADDED and {p for p in previous if previous[p]!=new[p]}==CHANGED
    assert current['inputs_preserved']==old['inputs_preserved']
    for r in current['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==new[p]['sha256']and size(BASE/p)==new[p]['size_bytes']
    report=read(BASE/'fpsd1201_product_report.md');assert all(f'| PF{i} |'in report for i in range(1,9))and all(f'**QG{i}**'in report for i in range(1,8))
    e=json.loads(read(ROOT/'fpsd1201_product_checks.json'));assert e['verified_counts']==COUNTS and e['generator_sha256']==sha(ROOT/'recover_fpsd1201_product.py')
    for n,h in e['dependencies'].items():assert sha(ROOT/n)==h
    assert not any(e[k]for k in ['whole_parent_replayed','native_target_executed','IDB_edit_operations_requested','full_goal_complete'])
    assert sha(ROOT/'fpsd1201_product_audit.json')==AUDIT_SHA
    a=json.loads(read(ROOT/'fpsd1201_product_audit.json'));assert a['fresh_replay_completed']and a['process_exit_code']==0 and not a['native_target_executed']
    assert a['auditor_sha256']==sha(ROOT/'audit_fpsd1201_product.py')and a['checks_sha256']==sha(ROOT/'fpsd1201_product_checks.json')and a['dependencies']==e['dependencies']
    assert a['IDA_readback_sha256']==e['IDA_readback_sha256']==sha(ROOT/'fpsd1201_product_ida_readback.json')
    r=a['result'];assert r['source']==SOURCE and r['fresh_replay']==TOTALS and r['all_checks_pass']and r['profiles']==96 and r['next_callee_targets']==['0x59f4e8']
    assert r['prior_replay_receipt_sha256']==sha(ROOT/'fpsd1201_consumer_audit.json')=='fb318e7c9c39e3943b58ca281ca7975d9a545e83cc1029c4f636f2645e1a7e71'
    assert not any(r[k]for k in ['nested_candidate_inline128_reads_or_writes','prefix_instructions_rerun','complete_consumer_return_established','whole_parent_replayed','native_target_executed','full_goal_complete'])
    assert(r['retained_checkpoint_profiles'],r['canonicalized_checkpoint_profiles'],r['isolated_product_profiles'])==(12,12,72)
    assert len(e['profiles'])==len(r['profile_summaries'])==96 and len(e['proofs'])==6 and all(q['result']=='unsat'for q in e['proofs'])
    prior=json.loads(read(ROOT/'fpsd1201_consumer_checks.json'));widths=set();aliases=set();matched=counter=0
    for j,(p,s)in enumerate(zip(e['profiles'],r['profile_summaries'])):
        mode='nested_retained'if j<12 else'nested_canonical'if j<24 else'direct';assert p['configuration']['product_mode']==s['mode']==mode and not p['native_effects']
        if j<24:
            assert p['prior_profile_index']==j%12 and p['configuration']=={**prior['profiles'][j%12]['configuration'],'product_mode':mode}and p['initial']==prior['profiles'][j%12]['terminal']
            assert len(p['operand_controls'])==(0 if j<12 else 2)and p['stop_reason']=='unretained_callee'and p['frontier']['pc']=='0x11425bc'and p['frontier']['target']=='0x59f4e8'and not p['frontier']['instruction_executed']
            if j<12:
                assert p['initial_RAM']==prior['profiles'][j]['final_RAM']
                if s['modular_oracle_matches']is True:matched+=1
                elif s['modular_oracle_matches']is False:counter+=1
            elif int(s['modulus_hex'],16)&1:assert s['modular_oracle_matches']
        else:
            assert p['stop_reason']=='returned'and p['frontier']is None and p['terminal']['pc']=='0x7f000000'and s['modular_oracle_matches']
            widths.add(s['modulus_width_limbs']);aliases.add(p['direct_configuration']['alias'])
        ends=[q for q in p['product_points']if q['pc']=='0x74ff34'];children=[q for q in p['product_points']if q['pc']=='0x74f7e0'];assert len(ends)==len(children)==1 and ends[0]['cursor_u64']=='0x0'
        calls=[q for q in p['PAC_models']if q['pc']=='0x74ff10'];assert len(calls)==1 and(calls[0]['target'],calls[0]['original_slot'],calls[0]['modifier'])==('0x74eb08','0x1d04d38','0x9ad6')
    assert(matched,counter)==(3,6)and widths=={1,2,4,8,16,32,64}and aliases=={'distinct','first','second'}
    f=e['reference_file_check'];assert(f['original_fixup_words_checked'],f['code_bytes_checked'],f['earlier_parent_bytes_checked'],f['bank_bytes_checked'])==(79512,39500,85464,3072)
    att=json.loads(read(ROOT/'fpsd1201_product_ida_readback.json'));assert not att['IDB_mutated']and not att['native_target_executed']and len(att['spans'])==2
    assert sum(s['size_B']for s in att['spans'])==5168 and all(s['current_equals_IDA_original_bytes']for s in att['spans'])
    assert current['validation']['fpsd1201_product_increment_checks']==COUNTS and current['validation']['fpsd1201_product_static_scope']==e['scope']
    assert current['validation']['reports']==old['validation']['reports']+1==431 and current['goal_status']=='active'
    assert current['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']and len(OWNED)==17
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        logical=p[:-4]if p.endswith('.zst')else p
        if logical=='triage_evidence/fpsd1201_product_checks.json':path_hygiene(json.dumps(paths_in_typed_payloads(e)).encode())
        else:path_hygiene(read(BASE/logical).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED
    print(json.dumps({'unchanged_manifest_entries':len(previous)-len(CHANGED),'owned_physical_files':len(OWNED),'original_inputs_preserved':3,
      'reports':431,'profiles':96,'canonical_Montgomery_oracles':81,'retained_odd_counterexamples':6,'complete_product_wrapper_returns':96,
      'prefix_instructions_rerun':0,'publication_does_not_replay_instructions':True,'native_target_executed':False,'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
