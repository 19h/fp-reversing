#!/usr/bin/env python3
"""Pin caller receipts, manifest delta, original inputs and decoded path hygiene.

O(owned content + manifest + decoded RAM) time/space; SMT bounded to 30 s.
No target/API/IPC, IDA access or history rewrite.
"""
import json,subprocess
from pathlib import Path
from hashlib import sha256
from compression import zstd
import z3
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene
from verify_fpsd1200_process_publication import paths_in_typed_payloads
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='53afbdeaae45c71e480b20c28adb754d72de6751'
BASELINE_SHA='ed897af59d9ae6569259e77f4d323ff6853dcfc36045f24ba65eed5a678634c8'
CHECKS_SHA='28f602de391d775471f3416165726f82919acece49de4a8f1d9ae1e9be2eeb52'
AUDIT_SHA='a361455a68ffe40482d91d263005be30ce234531cf7fc905c5232f2082ddd2a6'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','corefp_pool_allocator_report.md','foundational_triage_report.md',
 'interface_abi_report.md','interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'corefp_pool_caller_report.md','triage_evidence/recover_corefp_pool_caller.py','triage_evidence/audit_corefp_pool_caller.py',
 'triage_evidence/verify_corefp_pool_caller_publication.py','triage_evidence/corefp_pool_caller_checks.json','triage_evidence/corefp_pool_caller_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/corefp_pool_caller_checks.json','triage_evidence/corefp_pool_caller_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'profiles':17,'visits':171865,'reads':28772,'writes':15810,'PAC_models':7777,'models':51,'points':164,'allocations':7,'child_entries':44}
TOTALS={'initial_CPU_frames_checked':17,'initial_RAM_B_checked':3436544,'visits_checked':171865,'reads_checked':28772,'writes_checked':15810,
 'PAC_models_checked':7777,'models_checked':51,'points_checked':164,'final_RAM_B_checked':3436544}
LABELS=['length_0','length_1','length_15','length_16','length_32','selector_two','selector_255','malloc_null_16','malloc_null_32',
 'backed_16','backed_32','backed_clobber','forward_16','overlap_reverse_16','overlap_forward_16','busy_token','raw_holder_frontier']
VISITS=[1325,1397,2209,3204,4132,3204,3204,4152,5080,42491,43419,42491,3497,3204,3497,2469,2890]


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==len(old['files'])==8449 and len(after)==len(new['files'])==8455
    assert not before.keys()-after.keys()and after.keys()-before.keys()==ADDED and {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
    for row in new['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
    assert sha(ROOT/'corefp_pool_caller_checks.json')==CHECKS_SHA and sha(ROOT/'corefp_pool_caller_audit.json')==AUDIT_SHA
    e=json.loads(read(ROOT/'corefp_pool_caller_checks.json'));a=json.loads(read(ROOT/'corefp_pool_caller_audit.json'))
    assert e['generator_sha256']==sha(ROOT/'recover_corefp_pool_caller.py')and a['auditor_sha256']==sha(ROOT/'audit_corefp_pool_caller.py')
    assert a['checks_sha256']==CHECKS_SHA and a['dependencies']==e['dependencies']
    for n,h in e['dependencies'].items():assert sha(ROOT/n)==h
    for n,h in a['frozen_auditor_dependencies'].items():assert sha(ROOT/n)==h
    r=a['result'];assert a['fresh_replay_completed']and a['process_exit_code']==0 and r['all_checks_pass']
    assert r['verified_counts']==e['verified_counts']==COUNTS and r['independent_replay']==TOTALS
    assert len(a['oracles'])==r['compact_oracle_profiles']==17 and r['source_B_checked']==59120 and len(e['source_spans'])==r['source_spans']==3
    assert [(v['start'],v['end'])for v in e['source_spans']]==[('0x1af6b8','0x1bc12c'),('0x1bc12c','0x1bd1b8'),('0x5c87d4','0x5c93c4')]
    src=a['source_checks'];frozen=a['frozen_pool_source_checks']
    assert r['new_source_queries_unsat']==len(src['proofs'])==8 and r['frozen_pool_queries_unsat']==len(frozen['proofs'])==1
    for proof in src['proofs']+frozen['proofs']:
        assert proof['result']=='unsat';q=z3.Solver();q.set(timeout=30000);q.from_string(proof['query']);assert q.check()==z3.unsat
    assert r['exact_instructions_checked']==82 and r['bank_inputs_checked']==5632 and r['arena_oracle_B']==24576
    assert r['SDK_compile_exit']==a['SDK_assertions']['exit_code']==0 and not a['SDK_assertions']['emitted_artifact']
    assert not any(a[k]for k in ['native_API_executed','IDB_mutated','new_live_IDA_claim','full_goal_complete'])and not r['native_target_executed']
    assert not any(e[k]for k in ['source_PC_gap','child_record_patched','native_target_executed','native_API_executed','IDB_mutated','full_goal_complete'])
    assert [p['configuration']['label']for p in e['profiles']]==[o['label']for o in a['oracles']]==LABELS and [len(p['visits'])for p in e['profiles']]==VISITS
    for j,(p,o)in enumerate(zip(e['profiles'],a['oracles'])):
        assert o['entry_operation_u32']=='0x7f48'and o['allocation_operation_u32']=='0x2b9b'and o['cleanup_operation_u32']=='0x88cd'
        assert o['child_record_source_produced']and o['diagnostic_OUT_unchanged']and not o['native_ownership_established']and not o['successful_processing_established']
        reason='before_second_CASAL'if j==15 else 'before_unbacked_node_read'if j==16 else 'before_transform_body'if j in [9,10,11]else 'ordinary_return'
        assert o['frontier']==p['frontier']['reason']==reason
        assert all(v.get('name','_malloc')=='_malloc'for v in p['models'])
        assert o['source_child_requests_B']==([]if j<3 else [1027]if j>=15 else [1027,1031])
        assert o['null_cleanup_calls']==(2 if reason=='ordinary_return'and j>=3 else 0)
        if reason=='ordinary_return':assert o['outer_marker_u32']=='0x45e2a203'
        if j in [9,10,11]:
            assert o['allocation_pair_u64']==['0x64002f60','0x64002b34']and o['arena_oracle_B']==8192 and len(p['allocations'])==1
            assert not any(v['pc']=='0x1b0270'for v in p['visits'])
        if j==16:assert not any(v['pc']=='0x1bca38'for v in p['visits'])
    assert sum(o['source_transformed_B']for o in a['oracles'])==288
    assert sum(len(p['allocations'])for p in e['profiles'])==7 and sum(v['pointer']!='0x0'for p in e['profiles']for v in p['allocations'])==3
    assert sum(p['child_entries'].count('0x1bc12c')for p in e['profiles'])==26 and sum(p['child_entries'].count('0x5c87d4')for p in e['profiles'])==18
    assert src['byte_mask16_hex']=='064c76251492cc1a6593e6d6c53d5042'and src['byte_cases_checked']==8192
    assert src['new_established_callers']==['0x1affb0','0x1b0080']and src['new_established_cleanup_calls']==['0x1b0168','0x1b01e8']
    assert src['unresolved_literal_candidates_after_this_increment']==533 and src['whole_transform_algorithm']=='unknown'
    banks={v['label']:v for v in src['banks']}
    for n in ['allocation_first','allocation_second']:assert banks[n]['pointer_row']['address']=='0x1d037d0'and banks[n]['pointer_row']['target']=='0x1bc12c'
    for n in ['cleanup_first','cleanup_second']:assert banks[n]['pointer_row']['address']=='0x1d036a8'and banks[n]['pointer_row']['target']=='0x5c87d4'
    assert frozen['literal_candidates_count']==len(frozen['literal_call_candidates'])==537 and frozen['literal_candidate_functions']==65
    report=read(BASE/'corefp_pool_caller_report.md');assert all(f'| PC{i} |'in report for i in range(1,7))and all(f'**QG{i}**'in report for i in range(1,8))
    assert new['validation']['corefp_pool_caller_increment_checks']==COUNTS and new['validation']['corefp_pool_caller_static_scope']==e['scope']
    assert new['validation']['reports']==old['validation']['reports']+1==453 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']and len(OWNED)==15
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        logical=p[:-4]if p.endswith('.zst')else p;path_hygiene(read(BASE/logical).encode())
        if logical=='triage_evidence/corefp_pool_caller_checks.json':path_hygiene(json.dumps(paths_in_typed_payloads(e)).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,(delta^OWNED)
    print(json.dumps({'unchanged_manifest_entries':len(before)-len(CHANGED),'owned_physical_files':len(OWNED),'original_inputs_preserved':3,'reports':453,
      'independent_profiles':17,'source_visits':171865,'source_queries_unsat':9,'bank_inputs_checked':5632,'byte_cases_checked':8192,'complete_returns':12,
      'backed_prefixes':3,'boundary_stops':2,'literal_call_candidates':537,'native_target_executed':False,'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
