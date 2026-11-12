#!/usr/bin/env python3
"""Pin coherent caller/cold receipts, exact manifest delta and path hygiene.

No source replay, native operation, IDA access or history rewrite.
O(owned content + manifest + decoded RAM) time/space.
"""
import json,subprocess
from pathlib import Path
from hashlib import sha256
from compression import zstd
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene
from verify_fpsd1200_process_publication import paths_in_typed_payloads

ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='02efeca8184cad571bbafd1deed012f708b6878b'
BASELINE_SHA='3a022cccda1d10efa7c6dbd6f837ac1a0bae7eebfcb634e027657cada4cfe9d4'
CHECKS_SHA='d173789f17b86f6331425206846e5380e40ecd12047ce0fa637d4d6031c7e4bc'
AUDIT_SHA='58196347312f4b9449d29ffea886aeca5fbba3aee2406264b06530398333eda4'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','corefp_root_ingress_report.md','corefp_ingress_callers_report.md','corefp_vm_lifecycle_report.md',
 'corefp_cold_seed_report.md','foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md',
 'mach_ports_report.md','obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'corefp_caller_cold_report.md','triage_evidence/recover_corefp_caller_cold.py','triage_evidence/audit_corefp_caller_cold.py',
 'triage_evidence/verify_corefp_caller_cold_publication.py','triage_evidence/corefp_caller_cold_checks.json','triage_evidence/corefp_caller_cold_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/corefp_caller_cold_checks.json','triage_evidence/corefp_caller_cold_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'profiles':5,'visits':161155,'reads':25930,'writes':17715,'PAC_models':9255,'models':105,'points':30,
 'metadata_returns':0,'daemon_children':0,'handoffs':10,'lock_events':5,'transactions':0,'certificate_events':10,
 'constructor_points':40,'caller_points':55,'vm_points':30,'flow_points':40,'metadata_allocation_attempts':5,
 'vm_allocate_calls':5,'vm_deallocate_calls':0,'free_calls':0,'buffer_iterations':0,'metadata_iterations':0,
 'bootstrap_calls':10,'certificate_allocation_attempts':5,'entropy_calls':15,'clock_calls':5,'seed_iterations':3115}
TOTALS={'initial_CPU_frames_checked':5,'initial_RAM_B_checked':1884160,'visits_checked':161155,'reads_checked':25930,
 'writes_checked':17715,'PAC_models_checked':9255,'models_checked':105,'caller_points_checked':55,'vm_points_checked':30,
 'flow_points_checked':40,'constructor_points_checked':40,'certificate_events_checked':10,'entropy_returns_checked':15,
 'clock_returns_checked':5,'seed_iterations_checked':3115,'final_RAM_B_checked':1884160}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==len(old['files'])==8425 and len(after)==len(new['files'])==8431
    assert not before.keys()-after.keys()and after.keys()-before.keys()==ADDED and {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
    for row in new['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
    assert sha(ROOT/'corefp_caller_cold_checks.json')==CHECKS_SHA and sha(ROOT/'corefp_caller_cold_audit.json')==AUDIT_SHA
    e=json.loads(read(ROOT/'corefp_caller_cold_checks.json'));a=json.loads(read(ROOT/'corefp_caller_cold_audit.json'))
    assert e['generator_sha256']==sha(ROOT/'recover_corefp_caller_cold.py')and a['auditor_sha256']==sha(ROOT/'audit_corefp_caller_cold.py')
    assert a['checks_sha256']==CHECKS_SHA and a['dependencies']==e['dependencies']
    for n,h in e['dependencies'].items():assert sha(ROOT/n)==h
    for n,h in a['frozen_contract_modules'].items():assert sha(ROOT/n)==h
    r=a['result'];assert a['fresh_replay_completed']and a['process_exit_code']==0 and r['all_checks_pass']
    assert r['verified_counts']==e['verified_counts']==COUNTS and r['independent_client_replay']==TOTALS
    assert len(a['oracles'])==r['compact_oracle_profiles']==5 and r['client_source_spans']==len(e['source_spans'])==22
    assert r['client_source_B_checked']==116392 and r['oracle_seed_words_checked']==3120
    assert r['source_queries_unsat']==sum(len(a[k]['proofs'])for k in ['seed_source_contracts','route_source_contracts'])==8
    assert all(x['result']=='unsat'for k in ['seed_source_contracts','route_source_contracts']for x in a[k]['proofs'])
    assert r['exact_instructions_checked']==63 and r['SDK_compile_exit']==a['SDK_assertions']['exit_code']==0
    assert a['zero_definition_original']=={'address':'0x8ea890','bytes_hex':'0d0080d2','instruction':'mov x13, #0'}
    assert not any(a[k]for k in ['semantic_annotations_used_as_proof','full_daemon_CPU_RAM_replayed','new_live_IDA_claim','full_goal_complete'])
    assert not any(e[k]for k in ['source_PC_gap','restored_parent_frame','root_record_patched','native_target_executed','native_API_executed','IDB_mutated','full_goal_complete'])
    comparison=a['prior_fixture_comparison'];assert comparison['prior_profiles_receipt_pinned_not_replayed']==9
    assert comparison['certificate_allocate_free_already_present_in_all_prior_profiles']and comparison['constructor_SP_change_B']==-576
    assert not comparison['single_mode_field_causal_experiment']
    for p,o in zip(e['profiles'],a['oracles']):
        assert len(p['visits'])==32231 and p['frontier']['reason']=='before_optional_input_word_read'and p['parent_return']is None
        assert p['frontier']['address']=='0x4'and p['frontier']['CPU']['PC']=='0x5008eba44'and p['frontier']['held_lock_model']=='0x64000000'
        assert [o[k]for k in ['root_record','root_mode_u32','root_operation_u32','root_field16_u32']]==['0x62017ea0','0x114e4318','0xc1f7','0x484c46a']
        assert o['source_context_prefix_B']==9 and o['context_suffix_without_source_store_B']==119 and o['oracle_seed_words_checked']==624
        assert o['root_SP']=='0x62015f50'and o['context_pointer']=='0x62017290'and o['tuple_pointer']=='0x62017980'
        assert o['zero_definition_to_store_source_visits']==23 and o['optional_zero_definition']=='0x8ea890'and o['optional_input_store']=='0x8eb7a4'
        assert o['optional_input_pointer']=='0x0'and o['next_read_address']=='0x4'and not o['next_read_executed']
        assert not any(o[k]for k in ['source_PC_gap','root_record_patched','VM_metadata_cleanup_reached','native_lifetime_established','native_target_executed'])
        assert o['AUX_reads']==0 and o['certificate_DER_B']==756
        assert o['certificate_DER_sha256']=='a0caace76b0db1214f92e89225458e5040d3b92837c03270274ea1a1b359e2de'
        assert o['initial_stack_fill_u8']==('0x5a'if p['configuration']['label']=='caller_stack_5a_clock_error'else '0xa5')
    report=read(BASE/'corefp_caller_cold_report.md');assert all(f'| CC{i} |'in report for i in range(1,7))and all(f'**QG{i}**'in report for i in range(1,8))
    assert new['validation']['corefp_caller_cold_increment_checks']==COUNTS and new['validation']['corefp_caller_cold_static_scope']==e['scope']
    assert new['validation']['reports']==old['validation']['reports']+1==449 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']and len(OWNED)==18
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        logical=p[:-4]if p.endswith('.zst')else p;path_hygiene(read(BASE/logical).encode())
        if logical=='triage_evidence/corefp_caller_cold_checks.json':path_hygiene(json.dumps(paths_in_typed_payloads(e)).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,(delta^OWNED)
    print(json.dumps({'unchanged_manifest_entries':len(before)-len(CHANGED),'owned_physical_files':len(OWNED),'original_inputs_preserved':3,'reports':449,
      'coherent_cold_prefixes':5,'source_visits':161155,'seed_oracle_words':3120,'source_queries_unsat':8,'exact_instructions_checked':63,
      'next_optional_read_executed':False,'native_target_executed':False,'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
