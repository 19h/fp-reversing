#!/usr/bin/env python3
"""Pin key-route evidence, manifest preservation and decoded-RAM path scrub.

No instruction replay, IDB inspection or reference download. O(owned content +
manifest + decoded RAM) time/space. No native target/IPC or history rewrite.
"""
import json,subprocess
from pathlib import Path
from hashlib import sha256
from compression import zstd
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene
from verify_fpsd1200_process_publication import paths_in_typed_payloads
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='773b61f31cae9cb6eaca29247e5259fc2c70ba28'
BASELINE_SHA='575537f98ad3f8cc2f0b23cef7825e6d86d331dc17df1c8cea87859bee5c59ed'
CHECKS_SHA='ba0081033a88104908799656e170c7b041e8b61198b978b66b0fe851e622ece0'
AUDIT_SHA='e5ef60d7164df4ea08d4b908505a925c06cad0ef41fb22087ae2ea9bfd99e975'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','foundational_triage_report.md','fpsd1201_seed_report.md','interface_abi_report.md',
 'interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'fpsd1201_key_routes_report.md','triage_evidence/recover_fpsd1201_key_routes.py','triage_evidence/audit_fpsd1201_key_routes.py',
 'triage_evidence/verify_fpsd1201_key_routes_publication.py','triage_evidence/fpsd1201_key_routes_checks.json',
 'triage_evidence/fpsd1201_key_routes_audit.json','triage_evidence/fpsd1201_key_routes_ida_availability.json'}
ARCHIVES={MANIFEST,'triage_evidence/fpsd1201_key_routes_checks.json','triage_evidence/fpsd1201_key_routes_audit.json',
 'triage_evidence/fpsd1201_key_routes_ida_availability.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'profiles':8,'post_tuple_profiles':4,'selector_profiles':4,'prefix_original_visits_per_refresh':19717,
 'visits':1728,'reads':278,'writes':102,'PAC_models':48,'models':4,'points':46}
TOTALS={'initial_RAM_B_checked':454656,'visits_checked':1728,'reads_checked':278,'writes_checked':102,'PAC_models_checked':48,
 'models_checked':4,'points_checked':46,'final_RAM_B_checked':454656}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==len(old['files'])==8351 and len(after)==len(new['files'])==8358
    assert not before.keys()-after.keys()and after.keys()-before.keys()==ADDED and {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
    assert sha(ROOT/'fpsd1201_key_routes_checks.json')==CHECKS_SHA and sha(ROOT/'fpsd1201_key_routes_audit.json')==AUDIT_SHA
    e=json.loads(read(ROOT/'fpsd1201_key_routes_checks.json'));a=json.loads(read(ROOT/'fpsd1201_key_routes_audit.json'))
    assert e['generator_sha256']==sha(ROOT/'recover_fpsd1201_key_routes.py')and a['auditor_sha256']==sha(ROOT/'audit_fpsd1201_key_routes.py')
    for p,h in e['dependencies'].items():assert sha(ROOT/p)==h
    assert a['dependencies']==e['dependencies']and a['checks_sha256']==CHECKS_SHA and a['fresh_replay_completed']and a['process_exit_code']==0 and a['result']['all_checks_pass']
    assert e['verified_counts']==a['result']['verified_counts']==COUNTS and a['result']['fresh_continuation']==TOTALS
    assert a['result']['fresh_prefix_original_visits']==19717 and a['result']['independent_leaf_cases']==len(a['leaf_cases'])==128
    assert a['result']['source_lifted_leaf_proofs_unsat']==len(a['leaf_proof']['proofs'])==2 and a['leaf_proof']['source_instructions_lifted']==35
    assert a['result']['source_route_proofs_unsat']==len(a['source_route_contracts']['proofs'])==3 and a['source_route_contracts']['exact_instructions_checked']==41
    assert len(a['source_route_contracts']['dispatch_rows'])==4 and len(a['helper_calls'])==8 and len(a['first_mixes'])==4
    assert all(p['result']=='unsat'for p in a['leaf_proof']['proofs']+a['source_route_contracts']['proofs'])
    assert not any(e[k]for k in ['request1200_gap_executed','native_target_executed','new_target_IDA_access','IDB_mutated','full_goal_complete'])
    d=json.loads(read(ROOT/'fpsd1201_key_routes_ida_availability.json'));assert not d['target_database_available']and not d['IDB_mutated']
    assert sha(ROOT/'fpsd1201_key_routes_ida_availability.json')=='d6009238da5d459d1d6c2ecb648bc82b524b5e00c9df78be1b8a3e8f1ec79f42'
    report=read(BASE/'fpsd1201_key_routes_report.md');assert all(f'| KR{i} |'in report for i in range(1,9))and all(f'**QG{i}**'in report for i in range(1,8))
    assert new['validation']['fpsd1201_key_routes_increment_checks']==COUNTS and new['validation']['fpsd1201_key_routes_static_scope']==e['scope']
    assert new['validation']['reports']==old['validation']['reports']+1==438 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']and len(OWNED)==16
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        logical=p[:-4]if p.endswith('.zst')else p
        if logical=='triage_evidence/fpsd1201_key_routes_checks.json':path_hygiene(json.dumps(paths_in_typed_payloads(e)).encode())
        else:path_hygiene(read(BASE/logical).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED
    print(json.dumps({'unchanged_manifest_entries':len(before)-len(CHANGED),'owned_physical_files':len(OWNED),'original_inputs_preserved':3,'reports':438,
      'profiles':8,'source_visits':1728,'independent_leaf_cases':128,'queries_unsat':5,'publication_does_not_replay_instructions':True,
      'native_target_executed':False,'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
