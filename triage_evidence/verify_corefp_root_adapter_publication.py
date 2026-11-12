#!/usr/bin/env python3
"""Pin adapter receipts, manifest preservation, archives and path hygiene.

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
PREVIOUS='aa34c069c6dfd11d189391a5226e710a98434c70'
BASELINE_SHA='efc147b4e208716178abcb0083006b31b722ff231903f3da21e14829592a6ad2'
CHECKS_SHA='eb4765df6f9661cd57465e770513dd412f1bbd93424e0df23c6ce5bf400826cc'
AUDIT_SHA='680c9e80907fbdedc4bdebc28789a1ca310fd2fb180d2a1598cdb842ca7c91bb'
IDA_SHA='9e3a6730441b8ae21b36ad73cb2b01c4ca384ddc5a7554892e84b2f300ef717a'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','corefp_lookup_release_report.md','foundational_triage_report.md','interface_abi_report.md',
 'interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'corefp_root_adapter_report.md','triage_evidence/recover_corefp_root_adapter.py','triage_evidence/audit_corefp_root_adapter.py',
 'triage_evidence/verify_corefp_root_adapter_publication.py','triage_evidence/corefp_root_adapter_checks.json',
 'triage_evidence/corefp_root_adapter_audit.json','triage_evidence/corefp_root_adapter_ida.json'}
ARCHIVES={MANIFEST,'triage_evidence/corefp_root_adapter_checks.json','triage_evidence/corefp_root_adapter_audit.json','triage_evidence/corefp_root_adapter_ida.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'profiles':25,'visits':92184,'reads':19505,'writes':10374,'PAC_models':1450,'models':437,'points':150,
 'metadata_returns':22,'daemon_children':22,'handoffs':100,'lock_events':50,'adapter_points':100,'bootstrap_calls':27,'certificate_allocation_attempts':23}
TOTALS={'initial_CPU_frames_checked':25,'initial_RAM_B_checked':6328320,'visits_checked':92184,'reads_checked':19505,'writes_checked':10374,
 'PAC_models_checked':1450,'models_checked':437,'points_checked':150,'handoffs_checked':100,'lock_events_checked':50,'metadata_returns_checked':22,
 'daemon_children_fresh_checked':22,'adapter_points_checked':100,'bootstrap_calls_checked':27,'certificate_allocation_attempts_checked':23,
 'outer_returns_checked':25,'final_RAM_B_checked':6328320}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==len(old['files'])==8399 and len(after)==len(new['files'])==8406
    assert not before.keys()-after.keys()and after.keys()-before.keys()==ADDED and {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
    for name,h in [('checks',CHECKS_SHA),('audit',AUDIT_SHA),('ida',IDA_SHA)]:assert sha(ROOT/('corefp_root_adapter_'+name+'.json'))==h
    e=json.loads(read(ROOT/'corefp_root_adapter_checks.json'));a=json.loads(read(ROOT/'corefp_root_adapter_audit.json'));d=json.loads(read(ROOT/'corefp_root_adapter_ida.json'))
    assert e['generator_sha256']==sha(ROOT/'recover_corefp_root_adapter.py')and a['auditor_sha256']==sha(ROOT/'audit_corefp_root_adapter.py')
    for n,h in e['dependencies'].items():assert sha(ROOT/n)==h
    for n,h in a['frozen_contract_modules'].items():assert sha(ROOT/n)==h
    assert a['dependencies']==e['dependencies']and a['checks_sha256']==CHECKS_SHA and a['IDA_readback_sha256']==IDA_SHA
    r=a['result'];assert a['fresh_replay_completed']and a['process_exit_code']==0 and r['all_checks_pass']
    assert r['verified_counts']==e['verified_counts']==COUNTS and r['independent_client_replay']==TOTALS and r['compact_oracle_profiles']==len(a['oracles'])==25
    assert r['client_source_spans']==len(e['source_spans'])==22 and r['client_source_B_checked']==121572
    assert not a['semantic_annotations_used_as_proof']and not a['full_daemon_CPU_RAM_replayed']and not a['full_goal_complete']
    src=a['source_contracts'];assert len(src['proofs'])==r['source_queries_unsat']==6 and all(v['result']=='unsat'for v in src['proofs'])
    assert r['exact_instructions_checked']==src['exact_instructions_checked']==28 and src['adapter_no_X0_write_instructions_checked']==143
    assert r['dynamic_padding_values_covered']==16 and r['confirmed_adapter_root_calls']==25 and r['daemon_source_visits_fresh_checked']==814
    assert r['live_source_B_checked']==828 and r['live_decoded_pointer_B_checked']==8 and len(a['live_byte_ranges'])==3
    assert [v['kind']for v in a['live_byte_ranges']]==['original_source_bytes','IDA_decoded_rebase_target','original_source_bytes']
    pointer=a['live_byte_ranges'][1];assert pointer['original_chained_word_hex']=='c8818e00d4410880'and pointer['original_pointer_row']['target']=='0x8e81c8'
    assert d['requests']=={'bytes':{'target':'c3d025e56a86','items':[{'address':'0x8fcfa0','size':576},{'address':'0x1d05150','size':8},{'address':'0x9d3f70','size':252}],'format':'hex'},
      'xrefs':{'target':'c3d025e56a86','addresses':['0x8e81c8','0x1d05150'],'direction':'to','max_results':1000},
      'recall':{'target':'c3d025e56a86','query':'8e81c8','scope':'all','limit':12}}
    assert d['recall']['count']==0 and not d['recall']['truncated']and not any(d[k]for k in ['IDB_mutated','native_target_executed'])
    assert not any(e[k]for k in ['native_target_executed','native_API_executed','IDB_mutated','full_goal_complete'])
    census=e['census'];assert len(census['literal_call_candidates'])==len(census['same_diversity_rebase_rows'])==4
    assert len(census['root_reference_rows'])==1 and not census['root_is_exported']and not census['adapter_is_exported']
    assert census['literal_call_candidates']==src['literal_call_candidates']and not src['zero_output_is_injective']
    assert {o['dynamic_padding_B']for o in a['oracles']}==set(range(16,257,16))
    for p,o in zip(e['profiles'],a['oracles']):
        assert len(p['adapter_points'])==4 and len(p['handoffs'])==4 and len(p['lock_events'])==2
        assert p['frontier']['reason']=='parent_return'and p['parent_return']['cursor_u64']==o['external_output_u64']=='0x0'
        assert not o['native_target_executed']and not o['record_is_upstream_native_input']and o['root_source_slot']=='0x1d05150'
        assert o['seed_u64']==o['child_output_u64']==p['configuration']['seed_u64']
    report=read(BASE/'corefp_root_adapter_report.md');assert all(f'| RA{i} |'in report for i in range(1,9))and all(f'**QG{i}**'in report for i in range(1,8))
    assert new['validation']['corefp_root_adapter_increment_checks']==COUNTS and new['validation']['corefp_root_adapter_static_scope']==e['scope']
    assert new['validation']['reports']==old['validation']['reports']+1==445 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']and len(OWNED)==16
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        logical=p[:-4]if p.endswith('.zst')else p
        if logical=='triage_evidence/corefp_root_adapter_checks.json':path_hygiene(json.dumps(paths_in_typed_payloads(e)).encode())
        else:path_hygiene(read(BASE/logical).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED
    print(json.dumps({'unchanged_manifest_entries':len(before)-len(CHANGED),'owned_physical_files':len(OWNED),'original_inputs_preserved':3,'reports':445,
      'client_profiles':25,'client_source_visits':92184,'source_queries_unsat':6,'dynamic_padding_values':16,'literal_call_candidates':4,
      'live_source_B_checked':828,'live_decoded_pointer_B_checked':8,'publication_does_not_replay_instructions':True,
      'native_target_executed':False,'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
