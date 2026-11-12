#!/usr/bin/env python3
"""Pin reset receipts, exact manifest delta, preserved inputs and path hygiene.

O(owned content + manifest + decoded RAM) time/space. No source replay,
native operation, IDA access or history rewrite.
"""
import json,subprocess
from pathlib import Path
from hashlib import sha256
from compression import zstd
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene
from verify_fpsd1200_process_publication import paths_in_typed_payloads

ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='2d6c35974c7afe4ffc6c1e9cd39d8384b58fea97'
BASELINE_SHA='c6fafc5ba5ab3a37183c69046da63d8a446422c09ba5768c48d97a9c7eb2ddde'
CHECKS_SHA='f6d5430fc3df9f0f5aab3b6bbeaeb2199964fd9b555f506c5c6588adb5e16994'
AUDIT_SHA='ebd875649e92b63379c5f5fc13575a1f6c2d43b6732901b979190adc0ca21ab1'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','corefp_caller_cold_report.md','corefp_cold_seed_report.md',
 'corefp_lookup_initialization_report.md','fpsd1201_key_routes_report.md','foundational_triage_report.md',
 'interface_abi_report.md','interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md',
 'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'corefp_optional_reset_report.md','triage_evidence/recover_corefp_optional_reset.py','triage_evidence/audit_corefp_optional_reset.py',
 'triage_evidence/verify_corefp_optional_reset_publication.py','triage_evidence/corefp_optional_reset_checks.json','triage_evidence/corefp_optional_reset_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/corefp_optional_reset_checks.json','triage_evidence/corefp_optional_reset_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'profiles':11,'visits':3278,'reads':717,'writes':311,'PAC_models':73,'models':15,'points':54,'private_free_pointers':4}
TOTALS={'initial_CPU_frames_checked':11,'initial_RAM_B_checked':1261568,'visits_checked':3278,'reads_checked':717,'writes_checked':311,
 'PAC_models_checked':73,'models_checked':15,'points_checked':54,'final_RAM_B_checked':1261568}
LABELS=['original_selector_zero','selector_two','selector_255','empty','one_null','three_null','one_backed','backed_clobber','mixed_three',
 'original_slot_free_frontier','busy_token']
VISITS=[185,185,185,223,315,499,350,350,569,270,147]


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==len(old['files'])==8431 and len(after)==len(new['files'])==8437
    assert not before.keys()-after.keys()and after.keys()-before.keys()==ADDED and {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
    for row in new['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
    assert sha(ROOT/'corefp_optional_reset_checks.json')==CHECKS_SHA and sha(ROOT/'corefp_optional_reset_audit.json')==AUDIT_SHA
    e=json.loads(read(ROOT/'corefp_optional_reset_checks.json'));a=json.loads(read(ROOT/'corefp_optional_reset_audit.json'))
    assert e['generator_sha256']==sha(ROOT/'recover_corefp_optional_reset.py')and a['auditor_sha256']==sha(ROOT/'audit_corefp_optional_reset.py')
    assert a['checks_sha256']==CHECKS_SHA and a['dependencies']==e['dependencies']
    for n,h in e['dependencies'].items():assert sha(ROOT/n)==h
    for n,h in a['frozen_auditor_dependencies'].items():assert sha(ROOT/n)==h
    r=a['result'];assert a['fresh_replay_completed']and a['process_exit_code']==0 and r['all_checks_pass']
    assert r['verified_counts']==e['verified_counts']==COUNTS and r['independent_replay']==TOTALS
    assert len(a['oracles'])==r['compact_oracle_profiles']==11 and r['source_B_checked']==1400 and r['additional_root_reference_B_checked']==8
    assert len(e['source_spans'])==1 and e['source_spans'][0]['start']=='0x1f530c'and e['source_spans'][0]['end']=='0x1f5884'
    assert r['source_queries_unsat']==len(a['source_checks']['proofs'])==4 and all(x['result']=='unsat'for x in a['source_checks']['proofs'])
    assert r['exact_instructions_checked']==len(a['source_checks']['exact_instructions'])==32
    assert r['common_reset_lifted_instructions']==a['source_checks']['common_reset_lifted_instructions']==33
    assert len(a['source_checks']['banks'])==8 and r['bank_inputs_checked']==a['source_checks']['bank_inputs_checked']==2048
    assert sum(x['enumerated_inputs']for x in a['source_checks']['banks'])==2048
    assert sum(x['size_B']for x in a['source_checks']['common_reset_stores'])==80
    assert r['SDK_compile_exit']==a['SDK_assertions']['exit_code']==0 and not a['SDK_assertions']['emitted_artifact']
    assert a['source_checks']['root_preparation_field']=='0x1d32e18'and a['source_checks']['free_field']=='0x1d32dd8'
    assert not any(a[k]for k in ['native_API_executed','IDB_mutated','new_live_IDA_claim','full_goal_complete'])
    assert not any(e[k]for k in ['source_PC_gap','native_target_executed','native_API_executed','IDB_mutated','full_goal_complete'])
    assert 'unavailable'in e['live_IDA_status']and 'no live evidence returned'in e['live_IDA_status']
    assert [p['configuration']['label']for p in e['profiles']]==[o['label']for o in a['oracles']]==LABELS
    assert [len(p['visits'])for p in e['profiles']]==VISITS
    for j,(p,o)in enumerate(zip(e['profiles'],a['oracles'])):
        assert o['decoded_operation_u32']=='0xf7a5'and o['record_unchanged']and not o['native_ownership_established']
        assert o['residual_X0_semantics']=='unknown'
        assert p['frontier']['reason']==o['frontier']==('ordinary_return'if j<9 else 'before_unbacked_free'if j==9 else 'before_second_CASAL')
        assert o['token_final_u32']==('0x5d96'if j<9 else '0xa94ef')
        assert all(m.get('name')in [None,'_free']for m in p['models'])
        assert sum(m['kind']=='declared_sequential_CASAL'for m in p['models'])==1
    raw_profile=e['profiles'][9];assert raw_profile['frontier']['pointer']=='0x614a2fa7'and raw_profile['frontier']['callsite']=='0x1f5854'
    assert not raw_profile['frontier']['native_free_executed']and raw_profile['private_free_pointers']==[]
    assert [o['reset_slots']for o in a['oracles']]==[0,0,0,0,1,3,1,1,3,0,0]
    assert sum(o['common_reset_written_B']for o in a['oracles'])==720 and sum(o['post_free_written_B']for o in a['oracles'])==32
    report=read(BASE/'corefp_optional_reset_report.md');assert all(f'| OR{i} |'in report for i in range(1,7))and all(f'**QG{i}**'in report for i in range(1,8))
    assert new['validation']['corefp_optional_reset_increment_checks']==COUNTS and new['validation']['corefp_optional_reset_static_scope']==e['scope']
    assert new['validation']['reports']==old['validation']['reports']+1==450 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']and len(OWNED)==18
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        logical=p[:-4]if p.endswith('.zst')else p;path_hygiene(read(BASE/logical).encode())
        if logical=='triage_evidence/corefp_optional_reset_checks.json':path_hygiene(json.dumps(paths_in_typed_payloads(e)).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,(delta^OWNED)
    print(json.dumps({'unchanged_manifest_entries':len(before)-len(CHANGED),'owned_physical_files':len(OWNED),'original_inputs_preserved':3,'reports':450,
      'independent_profiles':11,'source_visits':3278,'bank_inputs_checked':2048,'source_queries_unsat':4,'common_reset_stores_B':720,
      'native_target_executed':False,'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
