#!/usr/bin/env python3
"""Pin seed publication, predecessor preservation and decoded-RAM path audit.

No instruction replay or reference download. O(owned bytes + manifest + RAM)
time/space. No native target/IPC/IDB operation; no history rewrite.
"""
import json,subprocess
from pathlib import Path
from hashlib import sha256
from compression import zstd
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene
from verify_fpsd1200_process_publication import paths_in_typed_payloads

ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='f1858f9352c828cd7998d8a14f084d8a06acd429'
BASELINE_SHA='1194d732df0eb9227c233f58f0c586e5e5e2b7a9f84f9bee88519ae655c88c82'
CHECKS_SHA='05f265a5a9a3f04b379c83535bc353f51c93411b5c7a870d78dd271c36729ccf'
AUDIT_SHA='4f798f3a82df17360a8bd2541c0b0524399e95c8073402ffbfa45fd4d5ac575b'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','foundational_triage_report.md','fpsd1201_predicates_report.md','fpsd1201_workspace_report.md',
 'interface_abi_report.md','interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md',
 'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'fpsd1201_seed_report.md','triage_evidence/recover_fpsd1201_seed.py','triage_evidence/audit_fpsd1201_seed.py',
 'triage_evidence/verify_fpsd1201_seed_publication.py','triage_evidence/fpsd1201_seed_checks.json','triage_evidence/fpsd1201_seed_audit.json',
 'triage_evidence/fpsd1201_seed_ida_readback.json','triage_evidence/fpsd1201_seed_primary_references.json'}
ARCHIVES={MANIFEST,'triage_evidence/fpsd1201_seed_checks.json','triage_evidence/fpsd1201_seed_audit.json',
 'triage_evidence/fpsd1201_seed_ida_readback.json','triage_evidence/fpsd1201_seed_primary_references.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'profiles':12,'prefix_original_visits_per_profile':19717,'visits':70836,'reads':5232,'writes':5051,'PAC_models':5035,
 'models':32,'points':16,'complete_seed_expansions':8,'atomic_failures':3,'queries_unsat':4}
TOTALS={'initial_RAM_B_checked':573440,'visits_checked':70836,'reads_checked':5232,'writes_checked':5051,'PAC_models_checked':5035,
 'models_checked':32,'points_checked':16,'final_RAM_B_checked':573440,'oracle_state_words_checked':4992}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,current=json.loads(raw),json.loads(read(BASE/MANIFEST));previous={r['path']:r for r in old['files']};new={r['path']:r for r in current['files']}
    assert len(previous)==len(old['files'])==8343 and len(new)==len(current['files'])==8351
    assert not previous.keys()-new.keys()and new.keys()-previous.keys()==ADDED and {p for p in previous if previous[p]!=new[p]}==CHANGED
    assert current['inputs_preserved']==old['inputs_preserved']and len(current['inputs_preserved'])==3
    for r in current['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==new[p]['sha256']and size(BASE/p)==new[p]['size_bytes']
    report=read(BASE/'fpsd1201_seed_report.md');assert all(f'| SE{i} |'in report for i in range(1,8))and all(f'**QG{i}**'in report for i in range(1,8))
    assert sha(ROOT/'fpsd1201_seed_checks.json')==CHECKS_SHA and sha(ROOT/'fpsd1201_seed_audit.json')==AUDIT_SHA
    e=json.loads(read(ROOT/'fpsd1201_seed_checks.json'));a=json.loads(read(ROOT/'fpsd1201_seed_audit.json'))
    assert e['generator_sha256']==sha(ROOT/'recover_fpsd1201_seed.py')and a['auditor_sha256']==sha(ROOT/'audit_fpsd1201_seed.py')
    for p,h in e['dependencies'].items():assert sha(ROOT/p)==h
    assert a['dependencies']==e['dependencies']and a['checks_sha256']==CHECKS_SHA and a['fresh_replay_completed']and a['process_exit_code']==0 and a['result']['all_checks_pass']
    assert e['verified_counts']==a['result']['verified_counts']==COUNTS and a['result']['fresh_continuation']==TOTALS
    assert a['result']['fresh_prefix_original_visits']==19717 and a['result']['independent_source_queries_unsat']==len(a['source']['proofs'])==5
    assert a['result']['exact_source_instructions_checked']==21 and a['source']['original_parent_B_checked']==85464
    assert a['result']['primary_reference_fingerprints_refreshed']==len(a['primary_reference_receipts'])==2
    assert not any(e[k]for k in ['request1200_gap_executed','native_target_executed','IDB_mutated','full_goal_complete'])and e['new_IDA_read_only']
    assert sha(ROOT/'fpsd1201_seed_ida_readback.json')=='7fe7a0600b4f920bf9d0509cc03a70b00bd9f35464b67a64e0bef60e300f55eb'
    assert sha(ROOT/'fpsd1201_seed_primary_references.json')=='2093675f0b93f2c812c7f3dd2a19184b33d6352d4a7f607a16446311c5a4c86e'
    assert current['validation']['fpsd1201_seed_increment_checks']==COUNTS and current['validation']['fpsd1201_seed_static_scope']==e['scope']
    assert current['validation']['reports']==old['validation']['reports']+1==437 and current['goal_status']=='active'
    assert current['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']and len(OWNED)==18
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        logical=p[:-4]if p.endswith('.zst')else p
        if logical=='triage_evidence/fpsd1201_seed_checks.json':path_hygiene(json.dumps(paths_in_typed_payloads(e)).encode())
        else:path_hygiene(read(BASE/logical).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED
    print(json.dumps({'unchanged_manifest_entries':len(previous)-len(CHANGED),'owned_physical_files':len(OWNED),'original_inputs_preserved':3,'reports':437,
      'profiles':12,'complete_seed_expansions':8,'oracle_words_checked':4992,'source_queries_unsat':9,'publication_does_not_replay_instructions':True,
      'native_target_executed':False,'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
