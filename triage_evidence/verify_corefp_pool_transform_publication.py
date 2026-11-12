#!/usr/bin/env python3
"""Pin whole-caller receipts, manifest delta and decoded path hygiene.

O(owned content + manifest + decoded RAM) time/space; SMT 30 s/query.
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
PREVIOUS='91c52d62d942391fefc1694687bc0ff810fb660f'
BASELINE_SHA='9529fadb99dc5bcf64a6c1bd9b412172673d8c5e788370599bddde2e26c98d4c'
CHECKS_SHA='8d81699130e8fb7480cac2c9395a7dabfc635a5b4b6ed71c35dc46f26ca61795'
AUDIT_SHA='5b815b80f8c720f3ec76ae23604347067856ef119cf8c9f48dbc19f7513a93f9'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','corefp_pool_caller_report.md','fpsd1201_predicates_report.md','foundational_triage_report.md',
 'interface_abi_report.md','interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'corefp_pool_transform_report.md','triage_evidence/recover_corefp_pool_transform.py','triage_evidence/audit_corefp_pool_transform.py',
 'triage_evidence/verify_corefp_pool_transform_publication.py','triage_evidence/corefp_pool_transform_checks.json','triage_evidence/corefp_pool_transform_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/corefp_pool_transform_checks.json','triage_evidence/corefp_pool_transform_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'profiles':8,'visits':629751,'reads':82153,'writes':53068,'PAC_models':27212,'models':38,'points':212,'allocations':8,'child_entries':30}
TOTALS={'initial_CPU_frames_checked':8,'initial_RAM_B_checked':4333568,'visits_checked':629751,'reads_checked':82153,'writes_checked':53068,
 'PAC_models_checked':27212,'models_checked':38,'points_checked':212,'final_RAM_B_checked':4333568}
LABELS=['original_context_zero','context_ramp_16','context_ramp_32','context_clobber','context_zero_bytes','context_changed_byte','context_offset8','context_offset16']
VISITS=[66019,79896,84356,79896,79896,79896,79896,79896]


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==len(old['files'])==8455 and len(after)==len(new['files'])==8461
    assert not before.keys()-after.keys()and after.keys()-before.keys()==ADDED and {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
    for row in new['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
    assert sha(ROOT/'corefp_pool_transform_checks.json')==CHECKS_SHA and sha(ROOT/'corefp_pool_transform_audit.json')==AUDIT_SHA
    e=json.loads(read(ROOT/'corefp_pool_transform_checks.json'));a=json.loads(read(ROOT/'corefp_pool_transform_audit.json'))
    assert e['generator_sha256']==sha(ROOT/'recover_corefp_pool_transform.py')and a['auditor_sha256']==sha(ROOT/'audit_corefp_pool_transform.py')
    assert a['checks_sha256']==CHECKS_SHA and a['dependencies']==e['dependencies']
    for n,h in e['dependencies'].items():assert sha(ROOT/n)==h
    for n,h in a['frozen_auditor_dependencies'].items():assert sha(ROOT/n)==h
    r=a['result'];assert a['fresh_replay_completed']and a['process_exit_code']==0 and r['all_checks_pass']
    assert r['verified_counts']==e['verified_counts']==COUNTS and r['independent_replay']==TOTALS
    assert len(a['oracles'])==r['compact_oracle_profiles']==8 and r['source_B_checked']==59120 and len(e['source_spans'])==r['source_spans']==3
    src=a['source_checks'];frozen=a['frozen_caller_source_checks'];pool=a['frozen_pool_source_checks']
    assert r['new_queries_unsat']==len(src['proofs'])==3 and r['frozen_queries_unsat']==len(frozen['proofs'])+len(pool['proofs'])==9
    for proof in src['proofs']+frozen['proofs']+pool['proofs']:
        assert proof['result']=='unsat';q=z3.Solver();q.set(timeout=30000);q.from_string(proof['query']);assert q.check()==z3.unsat
    assert len(src['seven_ARX_constants'])==7 and len(src['exact_instructions'])==37
    assert r['bank_inputs_checked']==5632 and r['arena_oracle_B']==180224 and r['cleanup_fill_B_checked']==5824 and r['ARX_rounds_checked']==56
    assert r['SDK_compile_exit']==a['SDK_assertions']['exit_code']==0 and not a['SDK_assertions']['emitted_artifact']
    assert not any(a[k]for k in ['native_API_executed','IDB_mutated','new_live_IDA_claim','source_context_initializer_established','full_goal_complete'])and not r['native_target_executed']
    assert not any(e[k]for k in ['source_PC_gap','child_record_patched','native_target_executed','native_API_executed','IDB_mutated','source_context_initializer_established','full_goal_complete'])
    assert e['whole_transform_algorithm']==a['whole_transform_algorithm']=='unknown'
    assert [p['configuration']['label']for p in e['profiles']]==[o['label']for o in a['oracles']]==LABELS and [len(p['visits'])for p in e['profiles']]==VISITS
    for j,(p,o)in enumerate(zip(e['profiles'],a['oracles'])):
        assert o['requests_B']==[1027,1031]and o['backing_B']==5000 and o['workspace_words']==512
        assert o['frontier']==p['frontier']['reason']==('before_uninitialized_context_read'if j==0 else 'ordinary_return')
        assert not o['native_context_initialization_established']and o['whole_transform_algorithm']=='unknown'
        assert len(p['allocations'])==1 and p['allocations'][0]=={'pointer':'0x64002000','size_B':5000}
        assert all(v.get('name','_malloc')=='_malloc'for v in p['models'])
        assert o['context_reads']==(0 if j==0 else 6 if j==2 else 3)
        if j==0:
            assert not any(v['pc']=='0x1bafd8'for v in p['visits'])and o['retirement_order_u64']==[]and o['outer_marker_u32']is None
        else:
            assert o['retirement_order_u64']==['0x64002b34','0x64002f60']and o['outer_marker_u32']=='0xba1df9db'
            assert o['arena_oracle_B']==24576 and o['cleanup_fill_B_checked']==832
    by={o['label']:o for o in a['oracles']}
    assert by['context_ramp_16']['output_hex']==by['context_clobber']['output_hex']=='732780382ca3157581b95dc50e78053a'
    assert by['context_offset8']['context_read_addresses']==['0x64004000','0x64004008','0x64004000']
    assert by['context_offset16']['context_read_addresses']==['0x64004000','0x64004000','0x64004010']
    assert len({by[n]['output_hex']for n in ['context_ramp_16','context_zero_bytes','context_changed_byte']})==3
    assert src['context_base_row']['target']=='0x1d45f60'and src['context_offset_row']['target']=='0x1d44440'
    report=read(BASE/'corefp_pool_transform_report.md');assert all(f'| PT{i} |'in report for i in range(1,7))and all(f'**QG{i}**'in report for i in range(1,8))
    assert new['validation']['corefp_pool_transform_increment_checks']==COUNTS and new['validation']['corefp_pool_transform_static_scope']==e['scope']
    assert new['validation']['reports']==old['validation']['reports']+1==454 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']and len(OWNED)==16
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        logical=p[:-4]if p.endswith('.zst')else p;path_hygiene(read(BASE/logical).encode())
        if logical=='triage_evidence/corefp_pool_transform_checks.json':path_hygiene(json.dumps(paths_in_typed_payloads(e)).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,(delta^OWNED)
    print(json.dumps({'unchanged_manifest_entries':len(before)-len(CHANGED),'owned_physical_files':len(OWNED),'original_inputs_preserved':3,'reports':454,
      'independent_profiles':8,'source_visits':629751,'source_queries_unsat':12,'bank_inputs_checked':5632,'ARX_rounds_checked':56,'complete_returns':7,
      'uninitialized_context_stops':1,'nonzero_retirements':14,'native_target_executed':False,'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
