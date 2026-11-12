#!/usr/bin/env python3
"""Pin cold lookup evidence, manifest preservation and decoded-RAM path scrub.

No replay, IDB access, native target/IPC, reference download or history rewrite.
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
PREVIOUS='6b1af87a668b63569118727c7ab61d52fa8b18e1'
BASELINE_SHA='7fa00fb0318d999bc112cb7d01f64492af0e79ac4b028420f8fd123ba5670a9e'
CHECKS_SHA='7b24185f02fa41136ebbbaa78bd335c656b3803129e11c90056ba65fb53c3c63'
AUDIT_SHA='87811231a5e994ae79156808a5ef89ca1dceb597e247f3ec8890437c5ab8e6fc'
IDA_SHA='b3175a3832aea0be6bbc87300073a4a149070d24566093d183635781b32c543a'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','corefp_network_identity_report.md','foundational_triage_report.md','interface_abi_report.md',
 'interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'corefp_lookup_initialization_report.md','triage_evidence/recover_corefp_lookup_initialization.py','triage_evidence/audit_corefp_lookup_initialization.py',
 'triage_evidence/verify_corefp_lookup_initialization_publication.py','triage_evidence/corefp_lookup_initialization_checks.json',
 'triage_evidence/corefp_lookup_initialization_audit.json','triage_evidence/corefp_lookup_initialization_ida.json'}
ARCHIVES={MANIFEST,'triage_evidence/corefp_lookup_initialization_checks.json','triage_evidence/corefp_lookup_initialization_audit.json','triage_evidence/corefp_lookup_initialization_ida.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'profiles':14,'visits':19528,'reads':4776,'writes':1817,'PAC_models':287,'models':110,'points':84}
TOTALS={'initial_CPU_frames_checked':14,'initial_RAM_B_checked':2088960,'visits_checked':19528,'reads_checked':4776,'writes_checked':1817,
 'PAC_models_checked':287,'models_checked':110,'points_checked':84,'final_RAM_B_checked':2088960}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==len(old['files'])==8364 and len(after)==len(new['files'])==8371
    assert not before.keys()-after.keys()and after.keys()-before.keys()==ADDED and {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
    for name,h in [('checks',CHECKS_SHA),('audit',AUDIT_SHA),('ida',IDA_SHA)]:assert sha(ROOT/('corefp_lookup_initialization_'+name+'.json'))==h
    e=json.loads(read(ROOT/'corefp_lookup_initialization_checks.json'));a=json.loads(read(ROOT/'corefp_lookup_initialization_audit.json'));d=json.loads(read(ROOT/'corefp_lookup_initialization_ida.json'))
    assert e['generator_sha256']==sha(ROOT/'recover_corefp_lookup_initialization.py')and a['auditor_sha256']==sha(ROOT/'audit_corefp_lookup_initialization.py')
    for p,h in e['dependencies'].items():assert sha(ROOT/p)==h
    assert a['dependencies']==e['dependencies']and a['checks_sha256']==CHECKS_SHA and a['IDA_readback_sha256']==IDA_SHA
    assert a['fresh_replay_completed']and a['process_exit_code']==0 and a['result']['all_checks_pass']
    r=a['result'];assert e['verified_counts']==r['verified_counts']==COUNTS and r['independent_replay']==TOTALS and r['compact_oracle_profiles']==len(a['oracles'])==14
    assert r['source_B_checked']==6924 and len(e['source_spans'])==7 and r['live_B_checked']==a['live_checks']['live_B_checked']==4976
    assert r['queries_unsat']==len(a['source_checks']['proofs'])==2 and all(v['result']=='unsat'for v in a['source_checks']['proofs'])
    assert r['exact_instructions_checked']==a['source_checks']['exact_instructions_checked']==19
    assert r['ABI_compile_exit']==a['source_checks']['ABI_compile']['exit_code']==0 and not a['source_checks']['ABI_compile']['emitted_artifact']
    assert len(a['source_checks']['ABI_compile']['headers'])==2 and r['constructor_status_reads_checked']==0 and r['outer_initializer_paths_identical']
    f=a['source_checks']['fallback_lock'];assert f['address']=='0x1d27bf0'and f['size_B']==200 and SHA(bytes.fromhex(f['bytes_hex']))==f['sha256']
    assert len(a['original_global_store_sites'])==20
    assert sum(v['frontier']['reason']=='before__bootstrap_look_up'for v in e['profiles'])==3
    assert len(d['database_list'])==10 and {'CoreFP','fairplayd','com.apple.driver.FairPlayIOKit'}<={v['binary']for v in d['database_list']}
    assert d['target']=='c3d025e56a86'and not any(d[k]for k in ['IDB_mutated','native_target_executed'])
    assert not any(e[k]for k in ['native_target_executed','native_API_executed','IDB_mutated','full_goal_complete'])and not r['native_target_executed']
    report=read(BASE/'corefp_lookup_initialization_report.md');assert all(f'| LI{i} |'in report for i in range(1,11))and all(f'**QG{i}**'in report for i in range(1,8))
    assert new['validation']['corefp_lookup_initialization_increment_checks']==COUNTS and new['validation']['corefp_lookup_initialization_static_scope']==e['scope']
    assert new['validation']['reports']==old['validation']['reports']+1==440 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']and len(OWNED)==16
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        logical=p[:-4]if p.endswith('.zst')else p
        if logical=='triage_evidence/corefp_lookup_initialization_checks.json':path_hygiene(json.dumps(paths_in_typed_payloads(e)).encode())
        else:path_hygiene(read(BASE/logical).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED
    print(json.dumps({'unchanged_manifest_entries':len(before)-len(CHANGED),'owned_physical_files':len(OWNED),'original_inputs_preserved':3,'reports':440,
      'profiles':14,'source_visits':19528,'constructor_records':28,'queries_unsat':2,'live_B_checked':4976,'publication_does_not_replay_instructions':True,
      'native_target_executed':False,'analyst_path_literals_absent':True,'all_checks_pass':True}))


SHA=lambda b:sha256(b).hexdigest()
if __name__=='__main__':main()
