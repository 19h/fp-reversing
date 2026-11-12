#!/usr/bin/env python3
"""Pin registry/cache evidence, manifest preservation and decoded-RAM path scrub.

No instruction replay, IDB inspection, reference download or history rewrite.
O(owned content + manifest + decoded RAM) time/space. No native target or IPC.
"""
import json,subprocess
from pathlib import Path
from hashlib import sha256
from compression import zstd
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene
from verify_fpsd1200_process_publication import paths_in_typed_payloads
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='a12fed8a18689e6f08750ea9dab9e842607c96c7'
BASELINE_SHA='601f30c879a6074646bc1b234c2a2a0e38a1a097c84d8a298c1b3a687811001e'
CHECKS_SHA='556a427b9611f80159569a4598f7c1afc3548b89321d8f6b5bbce7c4e6e7ee31'
AUDIT_SHA='720931a1b5cd310a5b039d178cb7027125c20c713e4d783b6c422aa78af4086b'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','foundational_triage_report.md','fpsd1201_key_routes_report.md',
 'interface_abi_report.md','interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md',
 'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'corefp_network_identity_report.md','triage_evidence/recover_corefp_network_identity.py',
 'triage_evidence/audit_corefp_network_identity.py','triage_evidence/verify_corefp_network_identity_publication.py',
 'triage_evidence/corefp_network_identity_checks.json','triage_evidence/corefp_network_identity_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/corefp_network_identity_checks.json','triage_evidence/corefp_network_identity_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'profiles':27,'cold':18,'warm':9,'visits':3547,'reads':804,'writes':361,'PAC_models':266,'models':287}
TOTALS={'initial_CPU_frames_checked':27,'initial_RAM_B_checked':548864,'visits_checked':3547,'reads_checked':804,
 'writes_checked':361,'PAC_models_checked':266,'models_checked':287,'getter_returns_checked':30,'final_RAM_B_checked':548864}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==len(old['files'])==8358 and len(after)==len(new['files'])==8364
    assert not before.keys()-after.keys()and after.keys()-before.keys()==ADDED and {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
    assert sha(ROOT/'corefp_network_identity_checks.json')==CHECKS_SHA and sha(ROOT/'corefp_network_identity_audit.json')==AUDIT_SHA
    e=json.loads(read(ROOT/'corefp_network_identity_checks.json'));a=json.loads(read(ROOT/'corefp_network_identity_audit.json'))
    assert e['generator_sha256']==sha(ROOT/'recover_corefp_network_identity.py')and a['auditor_sha256']==sha(ROOT/'audit_corefp_network_identity.py')
    for p,h in e['dependencies'].items():assert sha(ROOT/p)==h
    assert a['dependencies']==e['dependencies']and a['checks_sha256']==CHECKS_SHA and a['fresh_replay_completed']and a['process_exit_code']==0
    result=a['result'];assert result['all_checks_pass']and e['verified_counts']==result['verified_counts']==COUNTS
    assert result['independent_replay']==TOTALS and result['compact_oracle_profiles']==len(a['oracles'])==27
    assert result['source_B_checked']==784 and result['exact_instructions_checked']==a['source_proofs']['exact_instructions_checked']==14
    assert result['queries_unsat']==len(a['source_proofs']['proofs'])==3 and all(p['result']=='unsat'for p in a['source_proofs']['proofs'])
    ext=a['external_checks'];assert result['ABI_compile_exit']==ext['ABI_compile']['exit_code']==0
    assert len(ext['ABI_compile']['headers'])==3 and not ext['ABI_compile']['emitted_artifact']
    assert sha256(ext['ABI_compile']['source'].encode()).hexdigest()==ext['ABI_compile']['source_sha256']
    assert len(ext['primary_references'])==3 and all(not p['body_retained']and p['size_B']>0 and len(p['sha256'])==64 for p in ext['primary_references'])
    assert not any(e[k]for k in ['native_target_executed','native_API_executed','IDB_mutated','full_goal_complete'])and not result['native_target_executed']
    assert len(e['source']['stubs'])==11 and len(e['source']['strings'])==3 and e['source']['block']['invoke']['target']=='0x8754'
    assert sum('repeat_capacity_u64'in p['configuration']for p in e['profiles'])==3
    assert sum(len(p['getter_returns'])for p in e['profiles'])==30
    report=read(BASE/'corefp_network_identity_report.md');assert all(f'| NI{i} |'in report for i in range(1,11))and all(f'**QG{i}**'in report for i in range(1,8))
    assert new['validation']['corefp_network_identity_increment_checks']==COUNTS and new['validation']['corefp_network_identity_static_scope']==e['scope']
    assert new['validation']['reports']==old['validation']['reports']+1==439 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']and len(OWNED)==15
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        logical=p[:-4]if p.endswith('.zst')else p
        if logical=='triage_evidence/corefp_network_identity_checks.json':path_hygiene(json.dumps(paths_in_typed_payloads(e)).encode())
        else:path_hygiene(read(BASE/logical).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED
    print(json.dumps({'unchanged_manifest_entries':len(before)-len(CHANGED),'owned_physical_files':len(OWNED),
      'original_inputs_preserved':3,'reports':439,'profiles':27,'source_visits':3547,'getter_returns':30,'queries_unsat':3,
      'publication_does_not_replay_instructions':True,'native_target_executed':False,'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
