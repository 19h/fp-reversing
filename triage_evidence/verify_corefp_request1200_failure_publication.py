#!/usr/bin/env python3
"""Pin cold request1200/fallback receipts, manifest preservation and path scrub.

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
PREVIOUS='21d41b3e418945e8bfe9a063831e568ac36f158f'
BASELINE_SHA='e8f75eb06c21ac52599155592e9b807dfdb47c9c4cf8608469276134266ad294'
CHECKS_SHA='9278dc280cf65be8b3fbdc37c6cd9b025fe575e89a0ff802bc459e77f6fc3311'
AUDIT_SHA='fe60a1b918ad69df5a384392f052c5f9c73c7161459247a7b59f56681825ae4a'
IDA_SHA='7d147a01d6782ec58ec546db374c92740882cde4a29584dab78423f5bd52a6d3'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','corefp_cold_metadata_report.md','corefp_lookup_initialization_report.md','corefp_lookup_report.md',
 'corefp_lookup_release_report.md','fpsd1201_predicates_report.md','fpsd1201_seed_report.md','foundational_triage_report.md','interface_abi_report.md',
 'interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'corefp_request1200_failure_report.md','triage_evidence/recover_corefp_request1200_failure.py','triage_evidence/audit_corefp_request1200_failure.py',
 'triage_evidence/verify_corefp_request1200_failure_publication.py','triage_evidence/corefp_request1200_failure_checks.json',
 'triage_evidence/corefp_request1200_failure_audit.json','triage_evidence/corefp_request1200_failure_ida.json'}
ARCHIVES={MANIFEST,'triage_evidence/corefp_request1200_failure_checks.json','triage_evidence/corefp_request1200_failure_audit.json','triage_evidence/corefp_request1200_failure_ida.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'profiles':6,'visits':129002,'reads':25318,'writes':16387,'PAC_models':7186,'models':129,'points':36,'metadata_returns':5,'daemon_children':5,
 'handoffs':22,'lock_events':11,'transactions':5,'certificate_events':12,'bootstrap_calls':7,'certificate_allocation_attempts':6}
TOTALS={'initial_CPU_frames_checked':6,'initial_RAM_B_checked':1835008,'visits_checked':129002,'reads_checked':25318,'writes_checked':16387,'PAC_models_checked':7186,
 'models_checked':129,'points_checked':36,'handoffs_checked':22,'lock_events_checked':11,'metadata_returns_checked':5,'daemon_children_fresh_checked':5,
 'bootstrap_calls_checked':7,'certificate_allocation_attempts_checked':6,'parent_returns_checked':5,'final_RAM_B_checked':1835008,'transactions_checked':5,
 'certificate_events_checked':12,'fallback_entropy_frontiers_checked':1}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==len(old['files'])==8385 and len(after)==len(new['files'])==8392
    assert not before.keys()-after.keys()and after.keys()-before.keys()==ADDED and {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
    for name,h in [('checks',CHECKS_SHA),('audit',AUDIT_SHA),('ida',IDA_SHA)]:assert sha(ROOT/('corefp_request1200_failure_'+name+'.json'))==h
    e=json.loads(read(ROOT/'corefp_request1200_failure_checks.json'));a=json.loads(read(ROOT/'corefp_request1200_failure_audit.json'));d=json.loads(read(ROOT/'corefp_request1200_failure_ida.json'))
    assert e['generator_sha256']==sha(ROOT/'recover_corefp_request1200_failure.py')and a['auditor_sha256']==sha(ROOT/'audit_corefp_request1200_failure.py')
    for n,h in e['dependencies'].items():assert sha(ROOT/n)==h
    assert a['dependencies']==e['dependencies']and a['checks_sha256']==CHECKS_SHA and a['IDA_readback_sha256']==IDA_SHA
    r=a['result'];assert a['fresh_replay_completed']and a['process_exit_code']==0 and r['all_checks_pass']
    assert r['verified_counts']==e['verified_counts']==COUNTS and r['independent_client_replay']==TOTALS and r['compact_oracle_profiles']==len(a['oracles'])==6
    assert r['client_source_spans']==len(e['source_spans'])==23 and r['client_source_B_checked']==108844
    assert sum(v.get('kind')=='complete_import_stub_16B'for v in e['source_spans'])==6
    assert r['daemon_source_visits_fresh_checked']==185 and r['daemon_steps_including_return']==190
    assert not a['full_daemon_CPU_RAM_replayed']and not a['semantic_annotations_used_as_proof']and a['foreign_IDA_memories_used_as_leads_only']
    source=a['source_checks'];assert r['queries_unsat']==len(source['proofs'])==2 and all(p['result']=='unsat'for p in source['proofs'])
    assert r['exact_instructions_checked']==source['exact_instructions_checked']==37 and r['ABI_compile_exit']==source['ABI_compile']['exit_code']==0
    assert not source['ABI_compile']['emitted_artifact']and source['ABI_compile']['header']['SDK_relative_header']=='usr/include/mach/message.h'
    assert [v['slot']for v in source['dispatch_reference_rows']]==['0x1cc99c8','0x1cc99f0']
    catalog=source['daemon_catalog'];assert(catalog['start_id'],catalog['end_id_exclusive'],catalog['declared_max_reply_B'],catalog['client_receive_capacity_B'],catalog['capacity_difference_B'])==(1200,1205,212,220,8)
    assert catalog['difference_semantics']=='unknown'and not catalog['request1200_delivered']
    assert [v['decoded_target']for v in catalog['used_fixups']['records']]==['0x1000044fc','0x100004530']
    assert r['live_B_checked']==1824 and len(a['live_byte_ranges'])==3
    assert d['requests']['bytes']=={'target':'c3d025e56a86','addresses':['0x8ae0','0x8ea830','0x249334'],'size':608}
    for key,target,count in [('CoreFP_recall','c3d025e56a86',0),('daemon_recall','70f8437872ac',2)]:
        assert d['requests'][key]=={'target':target,'query':'1200','scope':'all','limit':12}and d[key]['count']==count and not d[key]['truncated']
    assert not any(d[k]for k in ['IDB_mutated','native_target_executed'])
    assert not any(e[k]for k in ['native_target_executed','native_API_executed','IDB_mutated','full_goal_complete'])and not r['native_target_executed']
    for p,o in zip(e['profiles'],a['oracles']):
        assert len(p['certificate_events'])==2 and len(p['transactions'])==o['request1200_transactions']
        assert o['DER_sha256']=='a0caace76b0db1214f92e89225458e5040d3b92837c03270274ea1a1b359e2de'and not o['native_transport_or_ownership_established']
        if p['parent_return']is None:
            assert p['configuration']['label']=='fallback_entropy_frontier'and p['frontier']['reason']=='before_fallback_entropy'
            assert p['frontier']['callsite']=='0x8eb800'and p['frontier']['token4_hex']=='965d0000'and p['frontier']['held_lock_model']=='0x64000000'
            assert len(p['lock_events'])==1 and len(p['handoffs'])==2 and not o['parent_returned']and not o['lock_released_by_model']
        else:
            assert len(p['lock_events'])==2 and p['lock_events'][0]['pointer']==p['lock_events'][1]['pointer']and len(p['handoffs'])==4
            assert p['parent_return']['CPU']['X31'][0]==hex(p['configuration']['unlock_status_u32'])and p['parent_return']['cursor_u64']=='0x100'
            assert p['parent_return']['held_lock_model']==(p['lock_events'][0]['pointer']if p['configuration']['unlock_status_u32']else None)
        assert all(not t['native_message_emitted']for t in p['transactions'])
    report=read(BASE/'corefp_request1200_failure_report.md');assert all(f'| RF{i} |'in report for i in range(1,11))and all(f'**QG{i}**'in report for i in range(1,8))
    assert new['validation']['corefp_request1200_failure_increment_checks']==COUNTS and new['validation']['corefp_request1200_failure_static_scope']==e['scope']
    assert new['validation']['reports']==old['validation']['reports']+1==443 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']and len(OWNED)==21
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        logical=p[:-4]if p.endswith('.zst')else p
        if logical=='triage_evidence/corefp_request1200_failure_checks.json':path_hygiene(json.dumps(paths_in_typed_payloads(e)).encode())
        else:path_hygiene(read(BASE/logical).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED
    print(json.dumps({'unchanged_manifest_entries':len(before)-len(CHANGED),'owned_physical_files':len(OWNED),'original_inputs_preserved':3,'reports':443,
      'client_profiles':6,'client_source_visits':129002,'parent_returns':5,'fallback_entropy_frontiers':1,'request1200_transactions':5,'queries_unsat':2,
      'daemon_source_visits_fresh_checked':185,'live_B_checked':1824,'publication_does_not_replay_instructions':True,
      'native_target_executed':False,'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
