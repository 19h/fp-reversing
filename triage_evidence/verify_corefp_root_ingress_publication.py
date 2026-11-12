#!/usr/bin/env python3
"""Pin ingress receipts, proof composition, manifest delta and path hygiene.

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
PREVIOUS='d213d581155c380e564fd53b3c6f49032a2554bd'
BASELINE_SHA='865978acbe5b6c4abeb06967c104ac90a91220ac19bbbc21cd9b363f6babad4d'
CHECKS_SHA='7c440398191d62b5de070dce2a90ef0ed19e173b46fbaff24cd36842b93d0eb0'
AUDIT_SHA='c9f68f37aaeb47a1441f3a5209b12ec64b6c9b9325f88260145be74a6ff19b80'
IDA_SHA='d3692c8e4ab0dc7f3a4ef2a114571437fb95ea8c9b7888ad649f3e51f15176c2'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','corefp_lookup_release_report.md','corefp_root_adapter_report.md','foundational_triage_report.md',
 'interface_abi_report.md','interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'corefp_root_ingress_report.md','triage_evidence/recover_corefp_root_ingress.py','triage_evidence/audit_corefp_root_ingress.py',
 'triage_evidence/verify_corefp_root_ingress_publication.py','triage_evidence/corefp_root_ingress_checks.json',
 'triage_evidence/corefp_root_ingress_audit.json','triage_evidence/corefp_root_ingress_ida.json'}
ARCHIVES={MANIFEST,'triage_evidence/corefp_root_ingress_checks.json','triage_evidence/corefp_root_ingress_audit.json','triage_evidence/corefp_root_ingress_ida.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'profiles':13,'complete_ingress_returns':12,'other_adapter_prefixes':1,'visits':45629,'reads':9753,'writes':4949,'PAC_models':683,
 'models':203,'points':72,'metadata_returns':9,'daemon_children':9,'handoffs':48,'lock_events':24,'ingress_points':86,'bootstrap_calls':14,'certificate_allocation_attempts':10}
TOTALS={'initial_CPU_frames_checked':13,'initial_RAM_B_checked':3047424,'visits_checked':45629,'reads_checked':9753,'writes_checked':4949,
 'PAC_models_checked':683,'models_checked':203,'points_checked':72,'handoffs_checked':48,'lock_events_checked':24,'metadata_returns_checked':9,
 'daemon_children_fresh_checked':9,'ingress_points_checked':86,'bootstrap_calls_checked':14,'certificate_allocation_attempts_checked':10,
 'outer_returns_checked':12,'other_callee_frontiers_checked':1,'final_RAM_B_checked':3047424}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==len(old['files'])==8406 and len(after)==len(new['files'])==8413
    assert not before.keys()-after.keys()and after.keys()-before.keys()==ADDED and {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
    for name,h in [('checks',CHECKS_SHA),('audit',AUDIT_SHA),('ida',IDA_SHA)]:assert sha(ROOT/('corefp_root_ingress_'+name+'.json'))==h
    e=json.loads(read(ROOT/'corefp_root_ingress_checks.json'));a=json.loads(read(ROOT/'corefp_root_ingress_audit.json'));d=json.loads(read(ROOT/'corefp_root_ingress_ida.json'))
    assert e['generator_sha256']==sha(ROOT/'recover_corefp_root_ingress.py')and a['auditor_sha256']==sha(ROOT/'audit_corefp_root_ingress.py')
    for n,h in e['dependencies'].items():assert sha(ROOT/n)==h
    for n,h in a['frozen_contract_modules'].items():assert sha(ROOT/n)==h
    assert a['dependencies']==e['dependencies']and a['checks_sha256']==CHECKS_SHA and a['IDA_attempt_sha256']==IDA_SHA
    r=a['result'];assert a['fresh_replay_completed']and a['process_exit_code']==0 and r['all_checks_pass']
    assert r['verified_counts']==e['verified_counts']==COUNTS and r['independent_client_replay']==TOTALS and r['compact_oracle_profiles']==len(a['oracles'])==13
    assert r['client_source_spans']==len(e['source_spans'])==23 and r['client_source_B_checked']==122472
    assert not a['semantic_annotations_used_as_proof']and not a['full_daemon_CPU_RAM_replayed']and not a['full_goal_complete']
    src=a['source_contracts'];assert len(src['proofs'])==r['source_queries_unsat']==11 and all(v['result']=='unsat'for v in src['proofs'])
    assert r['lifted_original_sites_checked']==src['lifted_sites_checked']==len(src['lifted_original_sites'])==88
    assert r['exact_instructions_checked']==src['exact_instructions_checked']==50
    assert src['field_theorems_quantify_independent_u32_keys']and not src['runtime_frames_restored_for_symbolic_cuts']
    assert src['symbolic_key_cutpoints']==[{'after_address':'0x5f46c4','symbol':'verified_ingress_key32','validated_by':'ingress_key_all64'},
      {'after_address':'0x5f47b8','symbol':'verified_root_key32','validated_by':'root_key_all64'}]
    assert src['monolithic_trial_not_a_certificate']=={'query_label':'decoded_operation_all_fields','timeout_ms':30000,'result':'unknown'}
    assert r['conditional_banks_exhaustive_inputs_checked']==512 and len(src['conditional_bank_checks'])==2
    assert [(v['pointer_slot'],v['target'])for v in src['conditional_bank_checks']]==[('0x1d050e0','0x656b80'),('0x1d04ed8','0x59fb30')]
    assert all(v['conditional_on_original_cached_roots_and_dispatch_base']and not v['whole_function_executed']for v in src['conditional_bank_checks'])
    assert r['adapter_literal_candidates']==src['adapter_literal_candidates_checked']==len(e['adapter_literal_census']['candidates'])==12
    assert r['adapter_literal_candidates_unresolved']==src['remaining_adapter_call_candidates_unresolved']==11
    assert r['live_source_B_checked']==0 and r['IDA_byte_read_connection_closed']and r['daemon_source_visits_fresh_checked']==333
    assert a['nonexecuted_frontier_fetch_backing']=={'address':'0x779ff0','size_B':4,'bytes_hex':'7f2303d5','instruction_executed':False}
    assert d['requests']['bytes']=={'target':'c3d025e56a86','items':[{'address':'0x5f4584','size':900},{'address':'0x1d04e20','size':8},
      {'address':'0x9d401c','size':76},{'address':'0x11741b4','size':116}],'format':'hex'}
    assert [v['query']for v in d['requests']['recalls']]==['9d34d4','1173af0']and all(v['target']=='c3d025e56a86'for v in d['requests']['recalls'])
    assert len(d['recalls'])==2 and all(v['count']==0 and not v['truncated']for v in d['recalls'])
    attempt=d['bytes_attempt'];assert attempt['isError']and attempt['tool_may_have_run']and not attempt['response_bytes_available']and not attempt['repeated']and 'connection closed'in attempt['error']
    assert not any(d[k]for k in ['IDB_mutated','native_target_executed'])and not any(e[k]for k in ['native_target_executed','native_API_executed','IDB_mutated','full_goal_complete'])
    for p,o in zip(e['profiles'][:-1],a['oracles'][:-1]):
        assert len(p['ingress_points'])==7 and len(p['handoffs'])==4 and len(p['lock_events'])==2 and p['frontier']['reason']=='parent_return'
        assert o['adapter_output_u64']=='0x0'and o['ingress_output_offset_B']==32 and o['source_seed_u64']=='0x94a2bbf66116513d'
        assert not o['root_record_patched']and not o['native_target_executed']
    prefix=e['profiles'][-1];assert prefix['frontier']['reason']=='before_other_callee_body'and prefix['parent_return']is None
    assert a['oracles'][-1]['target']=='0x779ff0'and not a['oracles'][-1]['callee_body_executed']
    report=read(BASE/'corefp_root_ingress_report.md');assert all(f'| RI{i} |'in report for i in range(1,9))and all(f'**QG{i}**'in report for i in range(1,8))
    assert new['validation']['corefp_root_ingress_increment_checks']==COUNTS and new['validation']['corefp_root_ingress_static_scope']==e['scope']
    assert new['validation']['reports']==old['validation']['reports']+1==446 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']and len(OWNED)==17
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        logical=p[:-4]if p.endswith('.zst')else p
        if logical=='triage_evidence/corefp_root_ingress_checks.json':path_hygiene(json.dumps(paths_in_typed_payloads(e)).encode())
        else:path_hygiene(read(BASE/logical).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED
    print(json.dumps({'unchanged_manifest_entries':len(before)-len(CHANGED),'owned_physical_files':len(OWNED),'original_inputs_preserved':3,'reports':446,
      'complete_ingress_returns':12,'stopped_sibling_prefixes':1,'client_source_visits':45629,'source_queries_unsat':11,'lifted_sites_checked':88,
      'conditional_bank_inputs':512,'adapter_literal_candidates_unresolved':11,'live_source_B_checked':0,'IDA_byte_read_connection_closed':True,
      'native_target_executed':False,'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
