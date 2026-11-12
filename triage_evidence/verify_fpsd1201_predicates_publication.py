#!/usr/bin/env python3
"""Exact publication, predecessor preservation and decoded payload path audit.

No instructions replay. O(owned bytes + manifest + decoded RAM) time/space.
No target, native API or IDB operation executes; history is not rewritten.
"""
import json,subprocess
from pathlib import Path
from hashlib import sha256
from compression import zstd
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene
from verify_fpsd1200_process_publication import paths_in_typed_payloads

ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='6f4c46465640263f7a04ba291f0e9b00ea66486d'
BASELINE_SHA='e84fe25bb5d9fc2cf3783c0ba1d49e006c102c2a04b4fb28d5d5684aa1646cc5'
CHECKS_SHA='3e2b88c3d9b6b7d1766e75cb9fba56b7ca7ebc17e55ec53a1613f1bbeda99988'
AUDIT_SHA='31c95fb3e5a569dace380e5df920253c72cf50f7e220a2b57fc37fd11c0a1e1e'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','foundational_triage_report.md','fpsd1201_caller_report.md','fpsd1201_workspace_report.md',
 'interface_abi_report.md','interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md',
 'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'fpsd1201_predicates_report.md','triage_evidence/recover_fpsd1201_predicates.py','triage_evidence/audit_fpsd1201_predicates.py',
 'triage_evidence/verify_fpsd1201_predicates_publication.py','triage_evidence/fpsd1201_predicates_checks.json','triage_evidence/fpsd1201_predicates_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/fpsd1201_predicates_checks.json','triage_evidence/fpsd1201_predicates_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'prefix_engine_steps':19723,'prefix_original_visits':19717,'profiles':4,'visits':41357,'reads':7913,'writes':2077,'PAC_models':1911,
 'record_points':14,'queries_unsat':6,'ordering_countermodels_sat':1,'atomic_stops':1,'uninitialized_pointer_stops':3}
TOTALS={'initial_RAM_B_checked':450560,'visits_checked':41357,'reads_checked':7913,'writes_checked':2077,'PAC_models_checked':1911,'final_RAM_B_checked':450560}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,current=json.loads(raw),json.loads(read(BASE/MANIFEST));previous={r['path']:r for r in old['files']};new={r['path']:r for r in current['files']}
    assert len(previous)==len(old['files'])==8337 and len(new)==len(current['files'])==8343
    assert not previous.keys()-new.keys()and new.keys()-previous.keys()==ADDED and {p for p in previous if previous[p]!=new[p]}==CHANGED
    assert current['inputs_preserved']==old['inputs_preserved']and len(current['inputs_preserved'])==3
    for r in current['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==new[p]['sha256']and size(BASE/p)==new[p]['size_bytes']
    report=read(BASE/'fpsd1201_predicates_report.md');assert all(f'| PR{i} |'in report for i in range(1,8))and all(f'**QG{i}**'in report for i in range(1,8))
    assert sha(ROOT/'fpsd1201_predicates_checks.json')==CHECKS_SHA and sha(ROOT/'fpsd1201_predicates_audit.json')==AUDIT_SHA
    e=json.loads(read(ROOT/'fpsd1201_predicates_checks.json'));a=json.loads(read(ROOT/'fpsd1201_predicates_audit.json'))
    assert e['generator_sha256']==sha(ROOT/'recover_fpsd1201_predicates.py')and a['auditor_sha256']==sha(ROOT/'audit_fpsd1201_predicates.py')
    for p,h in e['dependencies'].items():assert sha(ROOT/p)==h
    assert a['dependencies']==e['dependencies']and a['checks_sha256']==CHECKS_SHA and a['fresh_replay_completed']and a['process_exit_code']==0 and a['result']['all_checks_pass']
    assert e['verified_counts']==a['result']['verified_counts']==COUNTS and a['result']['fresh_continuation']==TOTALS
    assert a['result']['fresh_prefix_original_visits']==19717 and a['result']['fresh_prefix_engine_steps']==19723
    assert a['result']['original_leaf_bytes_checked']==308 and a['result']['independent_leaf_cases']==len(a['leaf_cases'])==256
    assert a['result']['source_lifted_leaf_proofs_unsat']==len(a['source_lifted_leaf_proofs'])==2
    assert [p['source_instructions_lifted']for p in a['source_lifted_leaf_proofs']]==[41,36]
    assert not any(e[k]for k in ['request1200_gap_executed','native_target_executed','new_IDA_access','IDB_mutated','full_goal_complete'])
    assert current['validation']['fpsd1201_predicates_increment_checks']==COUNTS and current['validation']['fpsd1201_predicates_static_scope']==e['scope']
    assert current['validation']['reports']==old['validation']['reports']+1==436 and current['goal_status']=='active'
    assert current['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']and len(OWNED)==16
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        logical=p[:-4]if p.endswith('.zst')else p
        if logical=='triage_evidence/fpsd1201_predicates_checks.json':path_hygiene(json.dumps(paths_in_typed_payloads(e)).encode())
        else:path_hygiene(read(BASE/logical).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED
    print(json.dumps({'unchanged_manifest_entries':len(previous)-len(CHANGED),'owned_physical_files':len(OWNED),'original_inputs_preserved':3,'reports':436,
      'profiles':4,'source_lifted_leaf_proofs_unsat':2,'leaf_cases':256,'publication_does_not_replay_instructions':True,
      'native_target_executed':False,'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
