#!/usr/bin/env python3
"""Pin coherent cold seed/context receipts, manifest preservation and path scrub.

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
PREVIOUS='9306fde820d71dc150260b7931ca178cee8aa14e'
BASELINE_SHA='f2c566555cf6ea2d681545b696e710448b89fde83e9409759c80e4b050eb8c68'
CHECKS_SHA='97ae3e7c83429e2c02889080cd2e8a6e0dee4377088d271b16f6e4264f7cf40a'
AUDIT_SHA='c2e4c95f4b386099bd1aa883495e4d8de24b246c78b72ad451092233626eab29'
IDA_SHA='ec3c5d68168870c808f0d4ec69ce6c2c9de8bb46296dc367f7c9446dc3872ecc'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_request1200_failure_report.md','corefp_client_paths_report.md','corefp_cold_metadata_report.md','corefp_lookup_initialization_report.md',
 'foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md',
 'fpsd1201_predicates_report.md','fpsd1201_seed_report.md','fpsd1201_key_routes_report.md','fpsd1201_workspace_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'corefp_cold_seed_report.md','triage_evidence/recover_corefp_cold_seed.py','triage_evidence/audit_corefp_cold_seed.py','triage_evidence/verify_corefp_cold_seed_publication.py',
 'triage_evidence/corefp_cold_seed_checks.json','triage_evidence/corefp_cold_seed_audit.json','triage_evidence/corefp_cold_seed_ida.json'}
ARCHIVES={MANIFEST,'triage_evidence/corefp_cold_seed_checks.json','triage_evidence/corefp_cold_seed_audit.json','triage_evidence/corefp_cold_seed_ida.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'profiles':9,'visits':272877,'reads':43684,'writes':30415,'PAC_models':16370,'models':170,'points':54,'metadata_returns':0,'daemon_children':0,
 'handoffs':18,'lock_events':9,'transactions':0,'certificate_events':18,'constructor_points':72,'bootstrap_calls':18,'certificate_allocation_attempts':9,
 'entropy_calls':27,'clock_calls':9,'seed_iterations':5607}
TOTALS={'initial_CPU_frames_checked':9,'initial_RAM_B_checked':2879488,'visits_checked':272877,'reads_checked':43684,'writes_checked':30415,
 'PAC_models_checked':16370,'models_checked':170,'points_checked':54,'handoffs_checked':18,'lock_events_checked':9,'constructor_points_checked':72,
 'certificate_events_checked':18,'entropy_returns_checked':27,'clock_returns_checked':9,'seed_iterations_checked':5607,'final_RAM_B_checked':2879488,'oracle_seed_words_checked':5616}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==len(old['files'])==8392 and len(after)==len(new['files'])==8399
    assert not before.keys()-after.keys()and after.keys()-before.keys()==ADDED and {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
    for name,h in [('checks',CHECKS_SHA),('audit',AUDIT_SHA),('ida',IDA_SHA)]:assert sha(ROOT/('corefp_cold_seed_'+name+'.json'))==h
    e=json.loads(read(ROOT/'corefp_cold_seed_checks.json'));a=json.loads(read(ROOT/'corefp_cold_seed_audit.json'));d=json.loads(read(ROOT/'corefp_cold_seed_ida.json'))
    assert e['generator_sha256']==sha(ROOT/'recover_corefp_cold_seed.py')and a['auditor_sha256']==sha(ROOT/'audit_corefp_cold_seed.py')
    for n,h in e['dependencies'].items():assert sha(ROOT/n)==h
    for n,h in a['frozen_contract_modules'].items():assert sha(ROOT/n)==h
    assert a['dependencies']==e['dependencies']and a['checks_sha256']==CHECKS_SHA and a['IDA_readback_sha256']==IDA_SHA
    r=a['result'];assert a['fresh_replay_completed']and a['process_exit_code']==0 and r['all_checks_pass']
    assert r['verified_counts']==e['verified_counts']==COUNTS and r['independent_client_replay']==TOTALS and r['compact_oracle_profiles']==len(a['oracles'])==9
    assert r['client_source_spans']==len(e['source_spans'])==14 and r['client_source_B_checked']==105044 and all('kind'not in v for v in e['source_spans'])
    assert not a['semantic_annotations_used_as_proof']
    src,routes=a['source_contracts'],a['source_route_contracts'];proofs=src['proofs']+routes['proofs']
    assert len(src['proofs'])==5 and len(routes['proofs'])==3 and r['source_queries_unsat']==len(proofs)==8 and all(v['result']=='unsat'for v in proofs)
    assert r['exact_instructions_checked']==src['exact_instructions_checked']+routes['exact_instructions_checked']==62
    sdk=a['SDK_assertions'];assert r['SDK_compile_exit']==sdk['exit_code']==0 and not sdk['emitted_artifact']and len(sdk['headers'])==2
    assert [v['SDK_relative_header']for v in sdk['headers']]==['usr/include/sys/time.h','usr/include/stdlib.h']
    assert r['live_B_checked']==1024 and len(a['live_byte_ranges'])==3
    assert a['IDA_reads_without_backing_bytes']==[{'address':'0x1d44409','size_requested_B':1,'size_read_B':0,'original_image_byte_hex':'00'}]
    assert d['requests']['bytes']=={'target':'c3d025e56a86','items':[{'address':'0x8eb800','size':512},{'address':'0x8eb9b4','size':256},{'address':'0x8ebe90','size':256},{'address':'0x1d44409','size':1}],'format':'hex'}
    for key,target in [('CoreFP_recall','c3d025e56a86'),('daemon_recall','70f8437872ac')]:
        assert d['requests'][key]=={'target':target,'query':'seed','scope':'all','limit':12}and d[key]['count']==0 and not d[key]['truncated']
    assert not any(d[k]for k in ['IDB_mutated','native_target_executed'])
    assert not any(e[k]for k in ['source_PC_gap','restored_parent_frame','native_target_executed','native_API_executed','IDB_mutated','full_goal_complete'])
    assert not a['source_PC_gap']and not a['restored_parent_frame']and not r['native_target_executed']
    assert sum(o['exact_prior_cold_prefix_compared']for o in a['oracles'])==5
    fills=set()
    for p,o in zip(e['profiles'],a['oracles']):
        assert len(p['lock_events'])==1 and len(p['handoffs'])==2 and len(p['certificate_events'])==2 and len(p['constructor_points'])==8
        assert p['parent_return']is None and p['caller_word_u64']=='0x100'and not p['transactions']and not p['metadata_returns']and not p['daemon_children']
        assert(p['entropy_calls'],p['clock_calls'],p['seed_iterations'])==(3,1,623)and p['frontier']['reason']=='before_optional_input_word_read'
        assert p['frontier']['CPU']['PC']=='0x5008eba44'and p['frontier']['address']=='0x4'and p['frontier']['token4_hex']=='965d0000'
        assert p['frontier']['held_lock_model']==p['lock_events'][0]['pointer']
        assert o['source_context_prefix_B']==9 and o['context_suffix_without_source_store_B']==119 and o['oracle_seed_words_checked']==624
        assert o['same_epoch_optional_input_pointer']=='0x0'and o['next_read_address']=='0x4'and not o['next_read_executed']and not o['native_target_executed']
        fill=int(o['initial_stack_fill_u8'],16);fills.add(fill);t=next(v for v in p['constructor_points']if v['label']=='tuple_complete')
        assert t['context128_hex']=='006664706300000001'+bytes([fill]*119).hex()
        assert [v['decoded']['result_u32']for v in o['predicate_calls']]==[0x245a,0x252a]and [v['output_offset_B']for v in o['predicate_calls']]==[32,0]
    assert fills=={0,0x5a,0xa5}
    report=read(BASE/'corefp_cold_seed_report.md');assert all(f'| CE{i} |'in report for i in range(1,11))and all(f'**QG{i}**'in report for i in range(1,8))
    assert new['validation']['corefp_cold_seed_increment_checks']==COUNTS and new['validation']['corefp_cold_seed_static_scope']==e['scope']
    assert new['validation']['reports']==old['validation']['reports']+1==444 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']and len(OWNED)==22
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        logical=p[:-4]if p.endswith('.zst')else p
        if logical=='triage_evidence/corefp_cold_seed_checks.json':path_hygiene(json.dumps(paths_in_typed_payloads(e)).encode())
        else:path_hygiene(read(BASE/logical).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED
    print(json.dumps({'unchanged_manifest_entries':len(before)-len(CHANGED),'owned_physical_files':len(OWNED),'original_inputs_preserved':3,'reports':444,
      'client_profiles':9,'client_source_visits':272877,'oracle_seed_words':5616,'source_queries_unsat':8,'context_prefix_B':9,'context_unwritten_suffix_B':119,
      'live_B_checked':1024,'IDA_reads_without_backing_bytes':1,'publication_does_not_replay_instructions':True,
      'native_target_executed':False,'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
