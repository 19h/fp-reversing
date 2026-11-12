#!/usr/bin/env python3
"""Pin caller/reader receipts, manifest delta, preserved inputs and path hygiene.

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
PREVIOUS='6c8f8b06edda42c3a0ad3117adeaa0c9ff523d44'
BASELINE_SHA='e08bba900dab625ff96b399453d744f7668cfe5d9151c9491eb817d76c48bd72'
CHECKS_SHA='d0e9f9e8e9eb17e240a466b17abcb00863ed060b089ef8b56471a4e97f643fd9'
AUDIT_SHA='7ab11be671c2a9c1ef75854132b1955ccd4743d4138f549539cd94e39cb6ed2b'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','corefp_optional_reset_report.md','fpsd1201_key_routes_report.md','foundational_triage_report.md',
 'interface_abi_report.md','interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'corefp_reset_caller_report.md','triage_evidence/recover_corefp_reset_caller.py','triage_evidence/audit_corefp_reset_caller.py',
 'triage_evidence/verify_corefp_reset_caller_publication.py','triage_evidence/corefp_reset_caller_checks.json','triage_evidence/corefp_reset_caller_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/corefp_reset_caller_checks.json','triage_evidence/corefp_reset_caller_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'profiles':19,'visits':20854,'reads':5219,'writes':2038,'PAC_models':459,'models':134,'points':60,'private_free_pointers':1,
 'caller_points':186,'CF_events':58,'version_allocation_attempts':3}
TOTALS={'initial_CPU_frames_checked':19,'initial_RAM_B_checked':3776512,'visits_checked':20854,'reads_checked':5219,'writes_checked':2038,
 'PAC_models_checked':459,'models_checked':134,'reset_points_checked':60,'caller_points_checked':186,'CF_events_checked':58,
 'version_allocation_attempts_checked':3,'final_RAM_B_checked':3776512}
LABELS=['url_null','url_null_clobber','stream_null','open_false','plist_null','key_null','cached_tuple','cache_minor_zero','cache_patch_zero',
 'direct_three','direct_partial','direct_invalid','copy_malloc_null','copy_false','copy_three','null_slot','backed_slot_clobber','busy_token','raw_slot_frontier']
VISITS=[790,790,1031,1130,1172,1256,707,790,790,1360,1360,1360,1373,1455,1496,920,1525,713,836]


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==len(old['files'])==8437 and len(after)==len(new['files'])==8443
    assert not before.keys()-after.keys()and after.keys()-before.keys()==ADDED and {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
    for row in new['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
    assert sha(ROOT/'corefp_reset_caller_checks.json')==CHECKS_SHA and sha(ROOT/'corefp_reset_caller_audit.json')==AUDIT_SHA
    e=json.loads(read(ROOT/'corefp_reset_caller_checks.json'));a=json.loads(read(ROOT/'corefp_reset_caller_audit.json'))
    assert e['generator_sha256']==sha(ROOT/'recover_corefp_reset_caller.py')and a['auditor_sha256']==sha(ROOT/'audit_corefp_reset_caller.py')
    assert a['checks_sha256']==CHECKS_SHA and a['dependencies']==e['dependencies']
    for n,h in e['dependencies'].items():assert sha(ROOT/n)==h
    for n,h in a['frozen_auditor_dependencies'].items():assert sha(ROOT/n)==h
    r=a['result'];assert a['fresh_replay_completed']and a['process_exit_code']==0 and r['all_checks_pass']
    assert r['verified_counts']==e['verified_counts']==COUNTS and r['independent_replay']==TOTALS
    assert len(a['oracles'])==r['compact_oracle_profiles']==19 and r['source_B_checked']==23376 and r['source_spans']==len(e['source_spans'])==4
    assert r['new_source_queries_unsat']==len(a['source_checks']['proofs'])==4 and r['frozen_reset_queries_unsat']==len(a['frozen_reset_source_checks']['proofs'])==4
    assert all(x['result']=='unsat'for key in ['source_checks','frozen_reset_source_checks']for x in a[key]['proofs'])
    assert r['exact_instructions_checked']==56 and r['bank_inputs_checked']==2304 and r['common_reset_lifted_instructions']==33
    assert r['SDK_compile_exit']==a['SDK_assertions']['exit_code']==0 and not a['SDK_assertions']['emitted_artifact']
    assert not any(a[k]for k in ['native_API_executed','native_file_read','IDB_mutated','new_live_IDA_claim','full_goal_complete'])
    assert not any(e[k]for k in ['source_PC_gap','child_record_patched','native_target_executed','native_API_executed','native_file_read','IDB_mutated','full_goal_complete'])
    assert [p['configuration']['label']for p in e['profiles']]==[o['label']for o in a['oracles']]==LABELS and [len(p['visits'])for p in e['profiles']]==VISITS
    for j,(p,o)in enumerate(zip(e['profiles'],a['oracles'])):
        assert [o[k]for k in ['entry_operation_u32','version_operation_u32','reset_operation_u32','child_record','output']]==['0x84ee','0x9a6b','0xf7a5','0x62017f38','0x62017e90']
        assert o['reset_record_source_store']=='0x9aa700'and o['reset_incoming_call']=='0x9aa74c'and o['cursor_final_u64']==64 and not o['native_ownership_established']
        assert o['frontier']==p['frontier']['reason']==('ordinary_return'if j<17 else 'before_second_CASAL'if j==17 else 'before_unbacked_free')
        assert sum(x['label']=='reset_entry'for x in p['caller_points'])==1
        assert not any(x.get('name')in ['_mach_msg','_vm_allocate','_mach_port_allocate']for x in p['models'])
    by={o['label']:o for o in a['oracles']}
    assert by['cached_tuple']['version_cache_hit']and by['cached_tuple']['version_tuple_u64']==[17,8,9]
    assert by['direct_partial']['version_tuple_u64']==[26,0,9]and by['direct_partial']['scanf_conversions']==2
    assert by['direct_invalid']['version_tuple_u64']==[0,8,9]and by['direct_invalid']['scanf_conversions']==0
    assert by['direct_partial']['version_marker_u8']==by['direct_invalid']['version_marker_u8']=='0x40'
    assert sum(len(o['scanf_result_def_use_checks'])for o in a['oracles'])==5
    assert all(not q['result_read']for o in a['oracles']for q in o['scanf_result_def_use_checks'])
    assert sum(x['kind']=='declared_create'for p in e['profiles']for x in p['CF_events'])==29
    assert sum(x['kind']=='declared_release'for p in e['profiles']for x in p['CF_events'])==29
    report=read(BASE/'corefp_reset_caller_report.md');assert all(f'| RC{i} |'in report for i in range(1,7))and all(f'**QG{i}**'in report for i in range(1,8))
    assert new['validation']['corefp_reset_caller_increment_checks']==COUNTS and new['validation']['corefp_reset_caller_static_scope']==e['scope']
    assert new['validation']['reports']==old['validation']['reports']+1==451 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']and len(OWNED)==16
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        logical=p[:-4]if p.endswith('.zst')else p;path_hygiene(read(BASE/logical).encode())
        if logical=='triage_evidence/corefp_reset_caller_checks.json':path_hygiene(json.dumps(paths_in_typed_payloads(e)).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,(delta^OWNED)
    print(json.dumps({'unchanged_manifest_entries':len(before)-len(CHANGED),'owned_physical_files':len(OWNED),'original_inputs_preserved':3,'reports':451,
      'independent_profiles':19,'source_visits':20854,'source_queries_unsat':8,'bank_inputs_checked':2304,'complete_outer_returns':17,
      'native_target_executed':False,'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
