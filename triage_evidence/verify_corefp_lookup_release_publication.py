#!/usr/bin/env python3
"""Pin caller-release evidence, manifest preservation and decoded-RAM scrub.

No instruction replay, IDA access, native operation or history rewrite.
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
PREVIOUS='022ec41360228eb2600c03a186262015adf8ca9d'
BASELINE_SHA='8a3cfe481ab3878226e1de19440a3d1e6461b984fb67fccb597e5438c8bdfb7f'
CHECKS_SHA='5e48a8808cdb3c5640cf336414de4b6fb1ba04817b7caf44be27f3a7bf6037e7'
AUDIT_SHA='7e7f548ebd84b7901423305f1578c3a29bfc03700e407010b251363da24492c6'
IDA_SHA='f7da7f2438f814b5b066863491fbf31738f163d7c95d0d5808bce6674b984db3'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','corefp_cold_metadata_report.md','corefp_lookup_initialization_report.md','corefp_lookup_report.md',
 'foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md',
 'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'corefp_lookup_release_report.md','triage_evidence/recover_corefp_lookup_release.py','triage_evidence/audit_corefp_lookup_release.py',
 'triage_evidence/verify_corefp_lookup_release_publication.py','triage_evidence/corefp_lookup_release_checks.json',
 'triage_evidence/corefp_lookup_release_audit.json','triage_evidence/corefp_lookup_release_ida.json'}
ARCHIVES={MANIFEST,'triage_evidence/corefp_lookup_release_checks.json','triage_evidence/corefp_lookup_release_audit.json','triage_evidence/corefp_lookup_release_ida.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'profiles':7,'visits':22812,'reads':4954,'writes':2539,'PAC_models':363,'models':113,'points':42,
 'metadata_returns':4,'daemon_children':4,'handoffs':28,'lock_events':14,'bootstrap_calls':9,'certificate_allocation_attempts':5}
TOTALS={'initial_CPU_frames_checked':7,'initial_RAM_B_checked':1654784,'visits_checked':22812,'reads_checked':4954,'writes_checked':2539,
 'PAC_models_checked':363,'models_checked':113,'points_checked':42,'handoffs_checked':28,'lock_events_checked':14,'metadata_returns_checked':4,
 'daemon_children_fresh_checked':4,'bootstrap_calls_checked':9,'certificate_allocation_attempts_checked':5,'parent_returns_checked':7,'final_RAM_B_checked':1654784}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==len(old['files'])==8378 and len(after)==len(new['files'])==8385
    assert not before.keys()-after.keys()and after.keys()-before.keys()==ADDED and {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
    for name,h in [('checks',CHECKS_SHA),('audit',AUDIT_SHA),('ida',IDA_SHA)]:assert sha(ROOT/('corefp_lookup_release_'+name+'.json'))==h
    e=json.loads(read(ROOT/'corefp_lookup_release_checks.json'));a=json.loads(read(ROOT/'corefp_lookup_release_audit.json'));d=json.loads(read(ROOT/'corefp_lookup_release_ida.json'))
    assert e['generator_sha256']==sha(ROOT/'recover_corefp_lookup_release.py')and a['auditor_sha256']==sha(ROOT/'audit_corefp_lookup_release.py')
    for n,h in e['dependencies'].items():assert sha(ROOT/n)==h
    assert a['dependencies']==e['dependencies']and a['checks_sha256']==CHECKS_SHA and a['IDA_readback_sha256']==IDA_SHA
    r=a['result'];assert a['fresh_replay_completed']and a['process_exit_code']==0 and r['all_checks_pass']
    assert r['verified_counts']==e['verified_counts']==COUNTS and r['independent_client_replay']==TOTALS and r['compact_oracle_profiles']==len(a['oracles'])==7
    assert r['client_source_spans']==len(e['source_spans'])==18 and r['client_source_B_checked']==106600
    assert sum(v.get('kind')=='complete_import_stub_16B'for v in e['source_spans'])==4
    assert r['daemon_source_visits_fresh_checked']==148 and r['daemon_steps_including_return']==152
    assert not a['full_daemon_CPU_RAM_replayed']and not a['semantic_annotations_used_as_proof']
    source=a['source_checks'];assert r['queries_unsat']==len(source['proofs'])==2 and all(p['result']=='unsat'for p in source['proofs'])
    assert r['unaligned_counterexamples_sat']==1 and source['outside_alignment_counterexample']['result']=='sat'
    assert r['exact_instructions_checked']==source['exact_instructions_checked']==14 and r['ABI_compile_exit']==source['ABI_compile']['exit_code']==0
    assert not source['ABI_compile']['emitted_artifact']and source['ABI_compile']['header']['SDK_relative_header']=='usr/include/pthread.h'
    assert r['live_B_checked']==1792 and len(a['live_byte_ranges'])==2
    assert d['target']=='c3d025e56a86'and d['requests']['recall']=={'query':'rwlock','scope':'all','limit':12}
    assert d['requests']['xrefs']['max_results']==1000 and d['requests']['bytes']['size']==896
    assert d['recall']['count']==0 and not d['recall']['truncated']and not d['IDB_mutated']and not d['native_target_executed']
    assert not any(e[k]for k in ['native_target_executed','native_API_executed','IDB_mutated','full_goal_complete'])and not r['native_target_executed']
    for p,o in zip(e['profiles'],a['oracles']):
        assert len(p['lock_events'])==2 and p['lock_events'][0]['pointer']==p['lock_events'][1]['pointer']and len(p['handoffs'])==4
        assert o['decoded_cleanup_wrapper_control_u32']=='0x97413dbe'and o['decoded_unlock_control_u32']=='0x4cfa'and o['unlock_record_accessed_extent_B']==12
        assert p['parent_return']['cursor_u64']==o['caller_u64_word_after']=='0x100'and not o['caller_word_restored_on_failure']and not o['native_unlock_success_established']
        assert p['parent_return']['CPU']['X31'][0]==o['final_X0']==hex(p['configuration']['unlock_status_u32'])
        assert p['parent_return']['held_lock_model']==(p['lock_events'][0]['pointer']if p['configuration']['unlock_status_u32']else None)
    report=read(BASE/'corefp_lookup_release_report.md');assert all(f'| LR{i} |'in report for i in range(1,11))and all(f'**QG{i}**'in report for i in range(1,8))
    assert new['validation']['corefp_lookup_release_increment_checks']==COUNTS and new['validation']['corefp_lookup_release_static_scope']==e['scope']
    assert new['validation']['reports']==old['validation']['reports']+1==442 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']and len(OWNED)==18
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        logical=p[:-4]if p.endswith('.zst')else p
        if logical=='triage_evidence/corefp_lookup_release_checks.json':path_hygiene(json.dumps(paths_in_typed_payloads(e)).encode())
        else:path_hygiene(read(BASE/logical).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED
    print(json.dumps({'unchanged_manifest_entries':len(before)-len(CHANGED),'owned_physical_files':len(OWNED),'original_inputs_preserved':3,'reports':442,
      'client_profiles':7,'client_source_visits':22812,'parent_returns':7,'lock_events':14,'queries_unsat':2,'unaligned_counterexamples_sat':1,
      'daemon_source_visits_fresh_checked':148,'live_B_checked':1792,'publication_does_not_replay_instructions':True,
      'native_target_executed':False,'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
