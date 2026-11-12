#!/usr/bin/env python3
"""Pin cold metadata/re-entry receipts, manifest preservation and path scrub.

Publication checks do not replay instructions, access IDA, execute native target
operations or rewrite history. O(owned content + manifest + decoded RAM).
"""
import json,subprocess
from pathlib import Path
from hashlib import sha256
from compression import zstd
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene
from verify_fpsd1200_process_publication import paths_in_typed_payloads

ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='dadaa7454f05f906b5ff3cb0e396ef784c7af8bf'
BASELINE_SHA='558127c7ed1d3c420d72bb46cd2c6ae83ead7db758e75287b388328d2e965e63'
CHECKS_SHA='765d86bf783f8a777cb0fedd754f0d4df87c6ce9da09fc65d8171358d3c57034'
AUDIT_SHA='219eacd29fd00c04b67130f8c5ce73bfc5993eb69f4660abfe76cca34bdb1144'
IDA_SHA='5453766c5b2ddfaf3c61db831acab3dcbcadf7fe3ee245350a58609d6d640955'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','corefp_lookup_initialization_report.md','corefp_lookup_report.md','foundational_triage_report.md','interface_abi_report.md',
 'interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'corefp_cold_metadata_report.md','triage_evidence/recover_corefp_cold_metadata.py','triage_evidence/audit_corefp_cold_metadata.py',
 'triage_evidence/verify_corefp_cold_metadata_publication.py','triage_evidence/corefp_cold_metadata_checks.json',
 'triage_evidence/corefp_cold_metadata_audit.json','triage_evidence/corefp_cold_metadata_ida.json'}
ARCHIVES={MANIFEST,'triage_evidence/corefp_cold_metadata_checks.json','triage_evidence/corefp_cold_metadata_audit.json','triage_evidence/corefp_cold_metadata_ida.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'profiles':6,'visits':13345,'reads':3541,'writes':1267,'PAC_models':227,'models':100,'points':36,
        'lookup_returns':12,'metadata_returns':3,'daemon_children':3,'bootstrap_calls':11}
TOTALS={'initial_CPU_frames_checked':6,'initial_RAM_B_checked':1044480,'visits_checked':13345,'reads_checked':3541,'writes_checked':1267,
 'PAC_models_checked':227,'models_checked':100,'points_checked':36,'final_RAM_B_checked':1044480,'lookup_returns_checked':12,
 'metadata_returns_checked':3,'daemon_children_fresh_checked':3,'bootstrap_calls_checked':11}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==len(old['files'])==8371 and len(after)==len(new['files'])==8378
    assert not before.keys()-after.keys()and after.keys()-before.keys()==ADDED and {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
    for name,h in [('checks',CHECKS_SHA),('audit',AUDIT_SHA),('ida',IDA_SHA)]:assert sha(ROOT/('corefp_cold_metadata_'+name+'.json'))==h
    e=json.loads(read(ROOT/'corefp_cold_metadata_checks.json'));a=json.loads(read(ROOT/'corefp_cold_metadata_audit.json'));d=json.loads(read(ROOT/'corefp_cold_metadata_ida.json'))
    assert e['generator_sha256']==sha(ROOT/'recover_corefp_cold_metadata.py')and a['auditor_sha256']==sha(ROOT/'audit_corefp_cold_metadata.py')
    for n,h in e['dependencies'].items():assert sha(ROOT/n)==h
    assert a['dependencies']==e['dependencies']and a['checks_sha256']==CHECKS_SHA and a['IDA_readback_sha256']==IDA_SHA
    r=a['result'];assert a['fresh_replay_completed']and a['process_exit_code']==0 and r['all_checks_pass']
    assert r['verified_counts']==e['verified_counts']==COUNTS and r['independent_client_replay']==TOTALS and r['compact_oracle_profiles']==len(a['oracles'])==6
    assert r['client_source_spans']==len(e['source_spans'])==12 and r['client_source_B_checked']==7372
    assert sum(v.get('kind')=='complete_import_stub_16B'for v in e['source_spans'])==4
    assert r['daemon_source_B_checked']==604 and r['daemon_visits_fresh_checked']==111 and r['daemon_steps_including_return']==114
    assert not a['full_daemon_CPU_RAM_replayed']and not a['semantic_annotations_used_as_proof']
    assert len(a['postmetadata_continuation'])==6 and r['live_B_checked']==1536 and len(a['live_byte_ranges'])==3
    assert a['daemon_used_fixups']['records'][0]['decoded_target']=='0x100004918'and a['daemon_NDR_source_binding']['import_name']=='_NDR_record'
    assert not a['daemon_NDR_source_binding']['authenticated']and a['daemon_NDR_source_binding']['total_addend']==0
    assert d['requests']['CoreFP_bytes']['target']=='c3d025e56a86'and d['requests']['daemon_bytes']['target']=='70f8437872ac'
    assert d['requests']['daemon_recall']=={'target':'70f8437872ac','query':'metadata','scope':'all','limit':12}
    assert d['daemon_recall']['count']==0 and not d['daemon_recall']['truncated']and not d['IDB_mutated']and not d['native_target_executed']
    assert not any(e[k]for k in ['native_target_executed','native_API_executed','IDB_mutated','full_goal_complete'])and not r['native_target_executed']
    for p in e['profiles']:
        assert len(p['lookup_returns'])==2 and sum(v.get('name')=='_pthread_rwlock_wrlock'for v in p['models'])==2
        invocations=[v for v in p['models']if v['kind']=='declared_second_invocation'];assert len(invocations)==1 and invocations[0]['memory']==[]
        for child in p['daemon_children']:assert child['reply_status_signed32']==-304 and child['reply_size_bytes']==36 and not child['native_message_delivered']
    report=read(BASE/'corefp_cold_metadata_report.md');assert all(f'| CM{i} |'in report for i in range(1,11))and all(f'**QG{i}**'in report for i in range(1,8))
    assert new['validation']['corefp_cold_metadata_increment_checks']==COUNTS and new['validation']['corefp_cold_metadata_static_scope']==e['scope']
    assert new['validation']['reports']==old['validation']['reports']+1==441 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']and len(OWNED)==17
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        logical=p[:-4]if p.endswith('.zst')else p
        if logical=='triage_evidence/corefp_cold_metadata_checks.json':path_hygiene(json.dumps(paths_in_typed_payloads(e)).encode())
        else:path_hygiene(read(BASE/logical).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED
    print(json.dumps({'unchanged_manifest_entries':len(before)-len(CHANGED),'owned_physical_files':len(OWNED),'original_inputs_preserved':3,'reports':441,
      'client_profiles':6,'client_source_visits':13345,'lookup_returns':12,'daemon_source_visits_fresh_checked':111,'live_B_checked':1536,
      'publication_does_not_replay_instructions':True,'native_target_executed':False,'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
