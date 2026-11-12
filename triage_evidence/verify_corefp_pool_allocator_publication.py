#!/usr/bin/env python3
"""Pin pool receipts, manifest delta, original inputs and decoded path hygiene.

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
PREVIOUS='9a2f296fa398861106f0f2b423d0e916f77f1a77'
BASELINE_SHA='d8c3996b8b129be339c23011cb1e493a84b6dc34c40ee6e7358d2c8dd9cb1432'
CHECKS_SHA='609660e9e6e891ce93dd0830e6ac11b9f43ed764f75b76b37f398f8b04ab7d6c'
AUDIT_SHA='482f9786d0fa2d3ff4cc45a3e1dc316bba6c3d70f2653e83e447037feeb7dbe7'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','corefp_optional_reset_report.md','fpsd1201_key_routes_report.md','foundational_triage_report.md',
 'interface_abi_report.md','interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'corefp_pool_allocator_report.md','triage_evidence/recover_corefp_pool_allocator.py','triage_evidence/audit_corefp_pool_allocator.py',
 'triage_evidence/verify_corefp_pool_allocator_publication.py','triage_evidence/corefp_pool_allocator_checks.json','triage_evidence/corefp_pool_allocator_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/corefp_pool_allocator_checks.json','triage_evidence/corefp_pool_allocator_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'profiles':15,'visits':20573,'reads':2633,'writes':1940,'PAC_models':854,'models':25,'points':118,'allocations':10}
TOTALS={'initial_CPU_frames_checked':15,'initial_RAM_B_checked':2056192,'visits_checked':20573,'reads_checked':2633,'writes_checked':1940,
 'PAC_models_checked':854,'models_checked':25,'points_checked':118,'final_RAM_B_checked':2056192}
LABELS=['selector_zero','selector_two','selector_255','busy_token','raw_holder_frontier','malloc_null_32','malloc_null_0',
 'malloc_null_4799','malloc_null_4800','malloc_null_5000','arena_0','arena_1','arena_32','arena_128','arena_32_clobber']
VISITS=[193,193,193,158,579,653,653,653,653,653,2668,2668,3008,4640,3008]


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==len(old['files'])==8443 and len(after)==len(new['files'])==8449
    assert not before.keys()-after.keys()and after.keys()-before.keys()==ADDED and {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
    for row in new['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
    assert sha(ROOT/'corefp_pool_allocator_checks.json')==CHECKS_SHA and sha(ROOT/'corefp_pool_allocator_audit.json')==AUDIT_SHA
    e=json.loads(read(ROOT/'corefp_pool_allocator_checks.json'));a=json.loads(read(ROOT/'corefp_pool_allocator_audit.json'))
    assert e['generator_sha256']==sha(ROOT/'recover_corefp_pool_allocator.py')and a['auditor_sha256']==sha(ROOT/'audit_corefp_pool_allocator.py')
    assert a['checks_sha256']==CHECKS_SHA and a['dependencies']==e['dependencies']
    for n,h in e['dependencies'].items():assert sha(ROOT/n)==h
    for n,h in a['frozen_auditor_dependencies'].items():assert sha(ROOT/n)==h
    r=a['result'];assert a['fresh_replay_completed']and a['process_exit_code']==0 and r['all_checks_pass']
    assert r['verified_counts']==e['verified_counts']==COUNTS and r['independent_replay']==TOTALS
    assert len(a['oracles'])==r['compact_oracle_profiles']==15 and r['source_B_checked']==4236 and len(e['source_spans'])==1
    assert r['source_queries_unsat']==len(a['source_checks']['proofs'])==1
    for proof in a['source_checks']['proofs']:
        assert proof['result']=='unsat';q=z3.Solver();q.set(timeout=30000);q.from_string(proof['query']);assert q.check()==z3.unsat
    assert r['exact_instructions_checked']==33 and r['bank_inputs_checked']==2048 and r['SDK_compile_exit']==a['SDK_assertions']['exit_code']==0
    assert not a['SDK_assertions']['emitted_artifact']and not any(a[k]for k in ['native_API_executed','IDB_mutated','new_live_IDA_claim','full_goal_complete'])
    assert not any(e[k]for k in ['source_PC_gap','native_target_executed','native_API_executed','IDB_mutated','full_goal_complete'])
    assert [p['configuration']['label']for p in e['profiles']]==[o['label']for o in a['oracles']]==LABELS and [len(p['visits'])for p in e['profiles']]==VISITS
    for j,(p,o)in enumerate(zip(e['profiles'],a['oracles'])):
        assert o['operation_u32']=='0x2b9b'and not o['selector_changed']and not o['native_ownership_established']and o['external_reachability']=='unknown'
        assert o['frontier']==p['frontier']['reason']==('before_second_CASAL'if j==3 else 'before_unbacked_node_read'if j==4 else 'ordinary_return')
        assert all(v.get('name','_malloc')=='_malloc'for v in p['models'])
        assert not any(v['pc']=='0x1bca38'for v in p['visits'])if j==4 else True
    assert sum(len(p['allocations'])for p in e['profiles'])==10 and sum(v['pointer']!='0x0'for p in e['profiles']for v in p['allocations'])==5
    by={o['label']:o for o in a['oracles']};assert by['malloc_null_4799']['malloc_requests_B']==[5000]and by['malloc_null_4800']['malloc_requests_B']==[5001]
    assert [by[n]['result_pointer']for n in ['arena_0','arena_1','arena_32','arena_128']]==['0x64001354','0x64001354','0x64001340','0x640012e0']
    for field in ['record32_hex','holder88_hex','selector_u8','token_u32']:assert e['profiles'][12]['final_state'][field]==e['profiles'][14]['final_state'][field]
    assert e['profiles'][12]['final_RAM']==e['profiles'][14]['final_RAM']
    src=a['source_checks'];assert src['entry_row']['address']=='0x1d037d0'and src['entry_row']['target']=='0x1bc12c'
    assert src['literal_candidates_count']==len(src['literal_call_candidates'])==537 and src['literal_candidate_functions']==65
    assert len({v['target']for v in src['same_diversity_rows']})==4 and all(not v['target_established']for v in src['literal_call_candidates'])
    banks={v['label']:v for v in src['banks']};assert banks['malloc']['pointer_row']['import']['name']=='_malloc'and banks['cleanup_free']['pointer_row']['import']['name']=='_free'
    report=read(BASE/'corefp_pool_allocator_report.md');assert all(f'| PA{i} |'in report for i in range(1,7))and all(f'**QG{i}**'in report for i in range(1,8))
    assert new['validation']['corefp_pool_allocator_increment_checks']==COUNTS and new['validation']['corefp_pool_allocator_static_scope']==e['scope']
    assert new['validation']['reports']==old['validation']['reports']+1==452 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']and len(OWNED)==16
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        logical=p[:-4]if p.endswith('.zst')else p;path_hygiene(read(BASE/logical).encode())
        if logical=='triage_evidence/corefp_pool_allocator_checks.json':path_hygiene(json.dumps(paths_in_typed_payloads(e)).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,(delta^OWNED)
    print(json.dumps({'unchanged_manifest_entries':len(before)-len(CHANGED),'owned_physical_files':len(OWNED),'original_inputs_preserved':3,'reports':452,
      'independent_profiles':15,'source_visits':20573,'source_queries_unsat':1,'bank_inputs_checked':2048,'complete_returns':13,
      'literal_call_candidates':537,'native_target_executed':False,'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
