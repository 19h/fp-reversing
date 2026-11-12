#!/usr/bin/env python3
"""Pin caller/VM receipts, manifest delta, preserved inputs and path hygiene.

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
PREVIOUS='da86d267159d70038b21951161fb020b4eeb57dc'
BASELINE_SHA='ddafca0efe4266bb00220dc61c1864f958bf713d8a919bbcd21f00273b83278b'
CHECKS_SHA='b5470710374f3a9b1c2ea3992fccc60a6734e9dae360f539fb44fae1102be2f8'
AUDIT_SHA='8369d838c7efddbd77aa41bc63dbd885e46feb4092b89f3dc7faa7ec545c09e2'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','corefp_root_ingress_report.md','foundational_triage_report.md','interface_abi_report.md',
 'interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'corefp_ingress_callers_report.md','triage_evidence/recover_corefp_ingress_callers.py','triage_evidence/audit_corefp_ingress_callers.py',
 'triage_evidence/verify_corefp_ingress_callers_publication.py','triage_evidence/corefp_ingress_callers_checks.json','triage_evidence/corefp_ingress_callers_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/corefp_ingress_callers_checks.json','triage_evidence/corefp_ingress_callers_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'profiles':9,'complete_early_returns':4,'vm_frontiers':5,'visits':6939,'reads':1265,'writes':712,'PAC_models':109,'models':6,
 'caller_points':72,'metadata_allocation_attempts':6}
TOTALS={'initial_CPU_frames_checked':9,'initial_RAM_B_checked':1196032,'visits_checked':6939,'reads_checked':1265,'writes_checked':712,
 'PAC_models_checked':109,'models_checked':6,'caller_points_checked':72,'metadata_allocation_attempts_checked':6,'final_RAM_B_checked':1196032}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==len(old['files'])==8413 and len(after)==len(new['files'])==8419
    assert not before.keys()-after.keys()and after.keys()-before.keys()==ADDED and {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
    for row in new['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
    assert sha(ROOT/'corefp_ingress_callers_checks.json')==CHECKS_SHA and sha(ROOT/'corefp_ingress_callers_audit.json')==AUDIT_SHA
    e=json.loads(read(ROOT/'corefp_ingress_callers_checks.json'));a=json.loads(read(ROOT/'corefp_ingress_callers_audit.json'))
    assert e['generator_sha256']==sha(ROOT/'recover_corefp_ingress_callers.py')and a['auditor_sha256']==sha(ROOT/'audit_corefp_ingress_callers.py')
    assert a['checks_sha256']==CHECKS_SHA and a['dependencies']==e['dependencies']
    for n,h in e['dependencies'].items():assert sha(ROOT/n)==h
    for n,h in a['frozen_contract_modules'].items():assert sha(ROOT/n)==h
    r=a['result'];assert a['fresh_replay_completed']and a['process_exit_code']==0 and r['all_checks_pass']
    assert r['verified_counts']==e['verified_counts']==COUNTS and r['independent_client_replay']==TOTALS and len(a['oracles'])==r['compact_oracle_profiles']==9
    assert r['client_source_spans']==len(e['source_spans'])==10 and r['client_source_B_checked']==20876
    assert not a['semantic_annotations_used_as_proof']and not a['full_daemon_CPU_RAM_replayed']and not a['full_goal_complete']
    src=a['source_contracts'];assert len(src['proofs'])==r['source_queries_unsat']==44 and all(v['result']=='unsat'for v in src['proofs'])
    assert len(src['alignment_counterexamples'])==r['alignment_controls_sat']==1
    sat=src['alignment_counterexamples'][0];assert sat['result']=='sat'and sat['record_address']=='0x6a7e4cf'
    assert [sat['original_key_u32'],sat['canonical_key_u32']]==['0x9f3265f4','0x8a01f1fe']
    assert r['lifted_original_sites_checked']==src['lifted_sites_checked']==sum(len(v['original_lifted_sites'])for v in src['callers'])==113
    assert r['bank_lifted_original_sites_checked']==src['bank_lifted_sites_checked']==sum(len(v['original_sites'])for v in src['original_bank_lifts'])==71
    assert src['exact_instructions_checked']==56 and r['prior_ingress_queries_rechecked']==len(src['prior_ingress_source_contracts_rechecked']['proofs'])==11
    assert [(v['decoded_root_operation_addend_u32'],v['current_tag_for_operation_c1f7'])for v in src['callers']]==[
      ('0x758a','0x4c6d'),('0x94fb','0x2cfc'),('0x6855','0x59a2')]
    assert [v['key_domain']for v in src['callers']]==['all u64 record addresses','all u64 record addresses','record_address & 1 == 0']
    assert all(v['decoded_root_mode_u32']=='0x114e4318'and not v['whole_function_executed_to_call']and not v['runtime_state_restored_for_symbolic_cut']for v in src['callers'])
    assert r['conditional_banks_exhaustive_inputs_checked']==sum(v['inputs_checked']for v in src['conditional_bank_checks'])==1024
    assert [(v['slot'],v['target'])for v in src['conditional_bank_checks']]==[('0x1d03c60','0x5f4584')]*3+[('0x1d03e60','0x2233c8')]
    assert all(v['seed_domain_bits']==32 and v['table_pair_lemma_checked_inputs']==256 for v in src['original_bank_lifts'])
    assert r['literal_candidates_checked']==len(e['ingress_literal_census']['candidates'])==src['literal_candidates_checked']==20
    assert src['literal_candidates_not_locally_classified']==16 and src['local_ingress_targets']==3 and src['distinct_same_diversity_targets']==4
    assert r['numeric_scalar_oracles_checked']==len(src['numeric_scalar_oracles'])==5
    assert [(v['scalar_preimage_u32'],v['decoded_root_field16_u32'])for v in src['numeric_scalar_oracles']]==[
      ('0x72ceb203','0x7c9bb44b'),('0x2a3b089e','0xe0dd53c8'),('0x1f03fdec','0x484c46a'),('0xbfb18293','0x5994b43b'),('0xf2c062ba','0x290d078c')]
    assert not any(e[k]for k in ['source_PC_gap','restored_parent_frame','native_target_executed','native_API_executed','IDB_mutated','full_goal_complete'])
    for p,o in zip(e['profiles'],a['oracles']):
        assert not o['ingress_reached']and not o['native_target_executed']and p['bootstrap_calls']==p['allocations_attempted']==p['certificate_allocation_attempts']==0
        assert not any(p[k]for k in ['handoffs','lock_events','daemon_children','metadata_returns'])
        if o['early_return']:assert p['parent_return']is not None and p['frontier']['reason']=='parent_return'
        else:
            assert p['parent_return']is None and p['frontier']['reason']=='before_vm_allocate'
            assert o['task_global_pointer_slot']=='0x1d14310'and o['VM_function_pointer_slot']=='0x1d04758'and o['VM_callsite']=='0x1ca598'
            assert o['VM_requested_B']==4096 and o['VM_flags_u32']==1 and o['VM_output_pointer']=='0x62017d70'and not o['VM_API_executed']
            assert o['native_right_identity']=='unknown'and o['metadata_bytes_defined']==28 and o['metadata_padding_retains_fill']
    report=read(BASE/'corefp_ingress_callers_report.md');assert all(f'| IC{i} |'in report for i in range(1,9))and all(f'**QG{i}**'in report for i in range(1,8))
    assert new['validation']['corefp_ingress_callers_increment_checks']==COUNTS and new['validation']['corefp_ingress_callers_static_scope']==e['scope']
    assert new['validation']['reports']==old['validation']['reports']+1==447 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']and len(OWNED)==15
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        logical=p[:-4]if p.endswith('.zst')else p
        path_hygiene(read(BASE/logical).encode())
        if logical=='triage_evidence/corefp_ingress_callers_checks.json':path_hygiene(json.dumps(paths_in_typed_payloads(e)).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,(delta^OWNED)
    print(json.dumps({'unchanged_manifest_entries':len(before)-len(CHANGED),'owned_physical_files':len(OWNED),'original_inputs_preserved':3,'reports':447,
      'early_returns':4,'VM_frontiers':5,'source_visits':6939,'source_queries_unsat':44,'alignment_controls_sat':1,'record_sites_lifted':113,'bank_sites_lifted':71,
      'conditional_bank_inputs':1024,'unclassified_literal_candidates':16,'native_target_executed':False,'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
