#!/usr/bin/env python3
"""Pin coherent VM lifecycle receipts, manifest delta and path hygiene.

No source replay, IDA access, native operation or history rewrite.
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
PREVIOUS='9e66feb2cf6a658b9237a5f1748bf7f3c6f3dc2a'
BASELINE_SHA='9a0f897c65966364b64e6716f4923a608fe2b01a2d2c047680e918ba85376ac5'
CHECKS_SHA='2b83f3f4f00a84d69619810024b805260c5241c962bd7ef090f1eaab7e60011b'
AUDIT_SHA='36f9a961d25a56a0562718a96ae9df55923da4f0821ebfa35317591b50026b78'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','corefp_root_ingress_report.md','corefp_ingress_callers_report.md','foundational_triage_report.md',
 'interface_abi_report.md','interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'corefp_vm_lifecycle_report.md','triage_evidence/recover_corefp_vm_lifecycle.py','triage_evidence/audit_corefp_vm_lifecycle.py',
 'triage_evidence/verify_corefp_vm_lifecycle_publication.py','triage_evidence/corefp_vm_lifecycle_checks.json','triage_evidence/corefp_vm_lifecycle_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/corefp_vm_lifecycle_checks.json','triage_evidence/corefp_vm_lifecycle_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'profiles':6,'complete_outer_returns':6,'coherent_ingress_calls':4,'visits':273798,'reads':21819,'writes':35431,'PAC_models':17036,
 'models':91,'points':24,'metadata_returns':3,'daemon_children':3,'handoffs':16,'lock_events':8,'caller_points':72,'vm_points':80,
 'metadata_allocation_attempts':6,'vm_allocate_calls':6,'vm_deallocate_calls':6,'free_calls':6,'buffer_iterations':16384,'metadata_iterations':192,
 'bootstrap_calls':4,'certificate_allocation_attempts':3}
TOTALS={'initial_CPU_frames_checked':6,'initial_RAM_B_checked':1814528,'visits_checked':273798,'reads_checked':21819,'writes_checked':35431,
 'PAC_models_checked':17036,'models_checked':91,'caller_points_checked':72,'vm_points_checked':80,'metadata_allocation_attempts_checked':6,
 'buffer_iterations_checked':16384,'metadata_iterations_checked':192,'final_RAM_B_checked':1814528}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==len(old['files'])==8419 and len(after)==len(new['files'])==8425
    assert not before.keys()-after.keys()and after.keys()-before.keys()==ADDED and {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
    for row in new['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
    assert sha(ROOT/'corefp_vm_lifecycle_checks.json')==CHECKS_SHA and sha(ROOT/'corefp_vm_lifecycle_audit.json')==AUDIT_SHA
    e=json.loads(read(ROOT/'corefp_vm_lifecycle_checks.json'));a=json.loads(read(ROOT/'corefp_vm_lifecycle_audit.json'))
    assert e['generator_sha256']==sha(ROOT/'recover_corefp_vm_lifecycle.py')and a['auditor_sha256']==sha(ROOT/'audit_corefp_vm_lifecycle.py')
    assert a['checks_sha256']==CHECKS_SHA and a['dependencies']==e['dependencies']
    for n,h in e['dependencies'].items():assert sha(ROOT/n)==h
    for n,h in a['frozen_contract_modules'].items():assert sha(ROOT/n)==h
    r=a['result'];assert a['fresh_replay_completed']and a['process_exit_code']==0 and r['all_checks_pass']
    assert r['verified_counts']==e['verified_counts']==COUNTS and r['independent_client_replay']==TOTALS and len(a['oracles'])==r['compact_oracle_profiles']==6
    assert r['client_source_spans']==len(e['source_spans'])==27 and r['client_source_B_checked']==119156
    assert not a['semantic_annotations_used_as_proof']and not a['full_daemon_CPU_RAM_replayed']and not a['full_goal_complete']
    src=a['source_contracts'];assert len(src['proofs'])==r['source_queries_unsat']==8 and all(v['result']=='unsat'for v in src['proofs'])
    assert r['exact_instructions_checked']==src['exact_instructions_checked']==len(src['exact_original_instructions'])==48
    assert not src['equation_proofs_are_original_instruction_lifts']and src['release_extent_phase_assumption_u32']=='0x37da'
    assert r['buffer_oracle_bytes_checked']==16384 and r['metadata_oracle_bytes_checked']==192 and r['daemon_source_visits_fresh_checked']==111
    assert not any(e[k]for k in ['source_PC_gap','restored_parent_frame','root_record_patched','native_target_executed','native_API_executed','IDB_mutated','full_goal_complete'])
    assert e['declared_VM_backing']=={'address':'0x66000000','size_B':4096,'initial_fill_u8':0,'native_allocation':False,'retained_after_declared_deallocation':True}
    for p,o in zip(e['profiles'],a['oracles']):
        failed=bool(p['configuration']['vm_status_u32']);assert p['frontier']['reason']=='parent_return'and p['parent_return']is not None
        assert not o['root_record_patched']and not o['native_lifetime_established']and o['retained_private_backing']and o['coherent_ingress_reached']==(not failed)
        assert o['VM_overwrite_B']==o['VM_deallocate_requested_B']==(0 if failed else 4096)and o['metadata_overwrite_B']==32
        assert o['metadata_seed_u64']=='0x62017e80'and o['metadata_pattern_sha256']=='779caff0f70308cec34b740e35e9aa936d7acd96a05a41248f356e39f354b785'
        assert o['residual_X0_u64']==hex(p['configuration']['free_residual_X0_u64'])
        if not failed:
            assert [o['root_record'],o['root_mode_u32'],o['root_field16_u32'],o['root_operation_u32']]==['0x62017ea0','0x114e4318','0x484c46a','0xc1f7']
            assert o['VM_pattern_seed_u64']=='0x62017e78'and o['VM_pattern_sha256']=='7b875aa72113715dab0f73de30713253cb368cc9e707e0f64ced2acef04d4571'
            assert o['staged_VM_prefix_B']==20 and o['metadata_span_word_minus_bias_u32']=='0x14'
            assert o['source_staged_VM_prefix20_hex']==('9ae57a32bababab600a74371babababad9bab6ba'if o['label']=='payload_16'else '9ae57a32bababab600a74361babababad9bab6ba')
    assert a['oracles'][-1]['AUX_pattern_reads']==0
    report=read(BASE/'corefp_vm_lifecycle_report.md');assert all(f'| VL{i} |'in report for i in range(1,9))and all(f'**QG{i}**'in report for i in range(1,8))
    assert new['validation']['corefp_vm_lifecycle_increment_checks']==COUNTS and new['validation']['corefp_vm_lifecycle_static_scope']==e['scope']
    assert new['validation']['reports']==old['validation']['reports']+1==448 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']and len(OWNED)==16
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        logical=p[:-4]if p.endswith('.zst')else p;path_hygiene(read(BASE/logical).encode())
        if logical=='triage_evidence/corefp_vm_lifecycle_checks.json':path_hygiene(json.dumps(paths_in_typed_payloads(e)).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,(delta^OWNED)
    print(json.dumps({'unchanged_manifest_entries':len(before)-len(CHANGED),'owned_physical_files':len(OWNED),'original_inputs_preserved':3,'reports':448,
      'complete_outer_returns':6,'coherent_nonzero_mode_ingress_calls':4,'source_visits':273798,'equation_queries_unsat':8,'exact_instructions_checked':48,
      'buffer_oracle_B':16384,'metadata_oracle_B':192,'native_target_executed':False,'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
