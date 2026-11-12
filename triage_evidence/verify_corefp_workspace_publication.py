#!/usr/bin/env python3
"""Pin workspace receipts, source queries, manifest delta and decoded hygiene.

O(owned content + manifest + decoded RAM) time/space; SMT 30 s/query.
No target/API/IPC, IDA access or history rewrite.
"""
import json,subprocess
from pathlib import Path
from hashlib import sha256
from compression import zstd
import z3
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene
from verify_fpsd1200_process_publication import paths_in_typed_payloads
ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='992861715672fd52953e33406f9fe4b35b152306'
BASELINE_SHA='0e57e3fd25acf68481a7807ecd7f76d5197672ca3b06fce016d7ff328299901b'
CHECKS_SHA='fc31687bcb81fb5611bccd1e928efdce657767a84218f6d91e47a027d69076b6'
AUDIT_SHA='9e1d67b6d637f17b18d8653e23d12400581e20afb7d2e6e4d4fa27faa246ba07'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','corefp_pool_caller_report.md','corefp_pool_transform_report.md','foundational_triage_report.md',
 'interface_abi_report.md','interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'corefp_workspace_report.md','triage_evidence/recover_corefp_workspace.py','triage_evidence/audit_corefp_workspace.py',
 'triage_evidence/verify_corefp_workspace_publication.py','triage_evidence/corefp_workspace_checks.json','triage_evidence/corefp_workspace_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/corefp_workspace_checks.json','triage_evidence/corefp_workspace_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'profiles':6,'visits':488136,'reads':63394,'writes':40562,'PAC_models':21086,'models':30,'points':182,'allocations':6,'child_entries':24}
TOTALS={'initial_CPU_frames_checked':6,'initial_RAM_B_checked':3313664,'visits_checked':488136,'reads_checked':63394,'writes_checked':40562,
 'PAC_models_checked':21086,'models_checked':30,'points_checked':182,'final_RAM_B_checked':3313664}
LABELS=['separate_ramp16','separate_zero16','separate_flip16','separate_ramp32','separate_zero32','separate_clobber']
VISITS=[79896,79816,79896,84356,84276,79896]
PHASES=[(0x73737373,5,0x0c,0x848cefeb,0x79283b95),(0x72727272,4,0x23,0xcab51e42,0x3711ca3c),
 (0x4f4f4f4f,6,0xda,0x1ba90a62,0xe60dde1c),(0x7d7d7d7d,0,0xb7,0xa8ae57e6,0x550a8398),
 (0x7c7c7c7c,1,0x98,0xe697a64f,0x1b337231),(0x73737373,5,0x0c,0x848cefeb,0x79283b95)]
COLUMNS=[0x0c87f872,0x109f32bf,0x55294a32,0xa6bac3d7,0x80b55471,0xc4596bd6,0xb175e165,0xdac764f9]
OUTPUTS=['732780382ca3157581b95dc50e78053a','7326823b28a6137289b057ce02750b35','f32780382ca3157581b95dc50e78053a',
 '732780382ca3157581b95dc50e78053ac5b7fff067cc57fe31ab3e8518dc03f3','7326823b28a6137289b057ce02750b35c5b7fff067cc57fe31ab3e8518dc03f3',
 '732780382ca3157581b95dc50e78053a']


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==len(old['files'])==8461 and len(after)==len(new['files'])==8467
    assert not before.keys()-after.keys()and after.keys()-before.keys()==ADDED and {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
    for row in new['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
    assert sha(ROOT/'corefp_workspace_checks.json')==CHECKS_SHA and sha(ROOT/'corefp_workspace_audit.json')==AUDIT_SHA
    e=json.loads(read(ROOT/'corefp_workspace_checks.json'));a=json.loads(read(ROOT/'corefp_workspace_audit.json'))
    assert e['generator_sha256']==sha(ROOT/'recover_corefp_workspace.py')and a['auditor_sha256']==sha(ROOT/'audit_corefp_workspace.py')
    assert a['checks_sha256']==CHECKS_SHA and a['dependencies']==e['dependencies']
    for n,h in e['dependencies'].items():assert sha(ROOT/n)==h
    for n,h in a['frozen_auditor_dependencies'].items():assert sha(ROOT/n)==h
    r=a['result'];assert a['fresh_replay_completed']and a['process_exit_code']==0 and r['all_checks_pass']
    assert r['verified_counts']==e['verified_counts']==COUNTS and r['independent_replay']==TOTALS
    expected={'source_B_checked':59120,'source_spans':3,'workspace_words_checked':3072,'source_constructor_instructions':36,'phase_classes':5,
      'new_queries_unsat':16,'frozen_queries_unsat':12,'preparation_byte_cases_checked':4096,'canonical_permutation_B':256,'canonical_expansion_B':37,
      'reference_family_members':512,'reference_family_matches':0,'differential_pairs_checked':65280,'SDK_compile_exit':0}
    assert all(r[k]==v for k,v in expected.items())and len(e['source_spans'])==3
    src=a['source_checks'];proofs=src['proofs']+[p for f in a['frozen_source_checks']for p in f['proofs']]
    assert len(src['proofs'])==16 and len(proofs)==28 and src['constructor_instruction_count']==len(src['source_constructor_instructions'])==36 and src['phase_classes']==5
    for proof in proofs:
        assert proof['result']=='unsat';q=z3.Solver();q.set(timeout=30000);q.from_string(proof['query']);assert q.check()==z3.unsat
    assert r['SDK_compile_exit']==a['SDK_assertions']['exit_code']==0 and not a['SDK_assertions']['emitted_artifact']
    assert not any(a[k]for k in ['native_API_executed','IDB_mutated','new_live_IDA_claim','source_context_initializer_established','full_goal_complete'])and not r['native_target_executed']
    assert not any(e[k]for k in ['source_PC_gap','child_record_patched','native_target_executed','native_API_executed','IDB_mutated','source_context_initializer_established','full_goal_complete'])
    assert e['whole_transform_algorithm']==a['whole_transform_algorithm']=='unknown'
    assert [p['configuration']['label']for p in e['profiles']]==[o['label']for o in a['oracles']]==LABELS and [len(p['visits'])for p in e['profiles']]==VISITS
    assert len(a['workspace_oracles'])==len(a['preparation_oracles'])==len(e['workspace_constructions'])==6
    for j,(p,o,w,b)in enumerate(zip(e['profiles'],a['oracles'],a['workspace_oracles'],a['preparation_oracles'])):
        assert o['requests_B']==[1027,1031]and o['backing_B']==5000 and o['workspace_words']==512 and o['frontier']==p['frontier']['reason']=='ordinary_return'
        assert not o['native_context_initialization_established']and o['whole_transform_algorithm']=='unknown'
        assert p['allocations']==[{'pointer':'0x64002000','size_B':5000}]and len(p['models'])==5 and len(p['child_entries'])==4
        assert all(v.get('name','_malloc')=='_malloc'for v in p['models'])and o['output_hex']==OUTPUTS[j]
        assert o['context_reads']==(6 if j in [3,4]else 3)and set(o['context_read_addresses'])=={'0x64004000'}
        assert o['retirement_order_u64']==['0x64002b34','0x64002f60']and o['outer_marker_u32']=='0xba1df9db'
        assert o['arena_oracle_B']==24576 and o['cleanup_fill_B_checked']==832
        assert w['label']==LABELS[j]and w['source_loop_iterations']==256 and w['workspace_words_checked']==512 and w['source_table_B']==1536
        assert (int(w['mask_u32'],16),w['rotate_per_byte'],int(w['index_xor_u8'],16),int(w['first_xor_u32'],16),int(w['second_xor_u32'],16))==PHASES[j]
        g=bytes.fromhex(w['canonical_permutation_hex']);assert len(g)==len(set(g))==256 and sha256(g).hexdigest()=='d5c79b57d35ed544ad0bfc85109f8ba7116cdfb4b697fd9f1e3b7e575d17fd83'
        assert int(w['affine_offset_u32'],16)==0x1fc44805 and list(map(lambda x:int(x,16),w['affine_columns_u32']))==COLUMNS
        assert b['mask16_hex']=='9c5ddd036790f68bf47bdb66585cad41'and b['byte_cases_checked']==4096 and b['input_pointer']=='0x64000300'and b['prepared_pointer']=='0x62017f68'
        assert bytes.fromhex(b['prepared16_hex'])==bytes(x^y for x,y in zip(bytes.fromhex(b['input16_hex']),bytes.fromhex(b['mask16_hex'])))
    ref=a['reference_comparison'];doc=ref['reference']
    assert doc['DOI']=='10.6028/NIST.FIPS.197-upd1'and doc['URL']=='https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf'
    assert doc['PDF_B']==1184436 and doc['PDF_sha256']=='62c86eb567f13edb8f71826e985da870b04ef6381634f303cdb16e84d47becd1'
    assert doc['generated_values_checked']==len(bytes.fromhex(doc['table256_hex']))==256 and not doc['PDF_freshly_fetched_by_this_auditor']
    assert ref['family_members']==len(ref['counterexamples'])==512 and not ref['matches']and not ref['general_affine_input_equivalence_tested']
    assert ref['differential_pairs_checked']==65280 and ref['nonzero_differential_histogram']=={'2':32130,'4':255}and ref['maximum_nonzero_differential_count']==4
    assert len({(c['reference'],c['input_xor'])for c in ref['counterexamples']})==512 and all(c['expected_G']!=c['affine_prediction']for c in ref['counterexamples'])
    report=read(BASE/'corefp_workspace_report.md');assert all(f'| WS{i} |'in report for i in range(1,7))and all(f'**QG{i}**'in report for i in range(1,8))
    assert new['validation']['corefp_workspace_increment_checks']==COUNTS and new['validation']['corefp_workspace_static_scope']==e['scope']
    assert new['validation']['reports']==old['validation']['reports']+1==455 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']and len(OWNED)==16
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        logical=p[:-4]if p.endswith('.zst')else p;path_hygiene(read(BASE/logical).encode())
        if logical=='triage_evidence/corefp_workspace_checks.json':path_hygiene(json.dumps(paths_in_typed_payloads(e)).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,(delta^OWNED)
    print(json.dumps({'unchanged_manifest_entries':len(before)-len(CHANGED),'owned_physical_files':len(OWNED),'original_inputs_preserved':3,'reports':455,
      'independent_profiles':6,'source_visits':488136,'source_queries_unsat':28,'workspace_words_checked':3072,'canonical_data_B':293,
      'complete_returns':6,'nonzero_retirements':12,'native_target_executed':False,'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
