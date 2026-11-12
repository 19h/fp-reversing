#!/usr/bin/env python3
"""Pin output-packing evidence, manifest delta, and decoded path hygiene.

O(owned decoded content + manifest) time/space; 30 s/SMT query.
No target/API/IPC, IDA access, native pointer access or history rewrite.
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
PREVIOUS='d2e1c34ef99c86ab2fb980c964b11f40259c21cd'
BASELINE_SHA='a414a0bf291cffcf7b26a47c5d6982f809bd77971e7e71ec6735b4a6556926a7'
CHECKS_SHA='8dfc45f135b908cf15c4ccc09744d758881ee27fdd84cdb87760fa55703fd7ac'
AUDIT_SHA='7a98b7fd8afff9080684a1c2a75fb548cf2a6fb8d8e86bdd23123cec42dbe1b7'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','corefp_workspace_report.md','corefp_workspace_consumers_report.md','foundational_triage_report.md',
 'interface_abi_report.md','interface_investigation_status.md','mach_ports_report.md','obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'corefp_output_packing_report.md','triage_evidence/recover_corefp_output_packing.py','triage_evidence/audit_corefp_output_packing.py',
 'triage_evidence/verify_corefp_output_packing_publication.py','triage_evidence/corefp_output_packing_checks.json','triage_evidence/corefp_output_packing_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/corefp_output_packing_checks.json','triage_evidence/corefp_output_packing_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'profiles':6,'blocks':8,'packing_instructions':659,'packing_source_B':2636,'regional_visits':5272,'regional_reads':816,'regional_writes':136,'output_bytes':128,
 'source_table_reads':128,'complete_byte_cases':32768,'new_queries_unsat':257,'gap_instructions':515,'gap_source_B':2060}
TOTALS={'initial_CPU_frames_checked':6,'initial_RAM_B_checked':3313664,'visits_checked':488136,'reads_checked':63394,'writes_checked':40562,
 'PAC_models_checked':21086,'models_checked':30,'points_checked':182,'final_RAM_B_checked':3313664}
LABELS=['separate_ramp16','separate_zero16','separate_flip16','separate_ramp32','separate_ramp32','separate_zero32','separate_zero32','separate_clobber']
ORDINALS=[0,0,0,0,1,0,1,0]
PINS={'corefp_workspace_checks.json':'fc31687bcb81fb5611bccd1e928efdce657767a84218f6d91e47a027d69076b6',
 'corefp_workspace_audit.json':'9e1d67b6d637f17b18d8653e23d12400581e20afb7d2e6e4d4fa27faa246ba07',
 'corefp_workspace_consumers_checks.json':'5f976ce1950bfcea57f1852576bd61d4e62f92f3fd3efb7cd0005624f18779ea',
 'corefp_workspace_consumers_audit.json':'adb5603bc9624068bd09c45981d628e8997079c349309648429bb5bd9e5c9a19'}
COLS=[188,68,53,125,218,204,191,255];PERM=[9,7,1,5,15,10,13,12,3,11,0,4,14,6,2,8]
STORES=[0x1bb950,0x1bbd44,0x1bbb40,0x1bbb04,0x1bbbc0,0x1bbff0,0x1bba70,0x1bbad8,0x1bbce0,0x1bbbf8,0x1bb7e8,0x1bbb90,0x1bbd08,0x1bbdb8,0x1bbd84,0x1bbde4]
SLOTS=[0x318,0x3d8,0x380,0x378,0x3c0,0x3e0,0x3a0,0x390,0x3c8,0x368,0x370,0x3d0,0x3b8,0x388,0x3a8,0x3b0]
WRITERS=[0x1bb0d0,0x1b9d08,0x1b9de8,0x1b9e1c,0x1b9c98,0x1b9c6c,0x1b9bdc,0x1b9ce0,0x1b9d54,0x1b9f14,0x1b9b84,0x1b9c24,0x1b9db0,0x1b9f5c,0x1b9e58,0x1b9ea8]
BIASES=['dc015a0bb2eab1c3d1294b89c42c5765','dc005808b6efb7c4d9204182c821596a','5c015a0bb2eab1c3d1294b89c42c5765',
 'dc015a0bb2eab1c3d1294b89c42c5765','3c39c227779679eb06ed46e4d9860085','dc005808b6efb7c4d9204182c821596a','3c39c227779679eb06ed46e4d9860085','dc015a0bb2eab1c3d1294b89c42c5765']


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def h8(x):
    value=0
    for k,column in enumerate(COLS):
        if x>>k&1:value^=column
    return value


def receipts():
    assert sha(ROOT/'corefp_output_packing_checks.json')==CHECKS_SHA and sha(ROOT/'corefp_output_packing_audit.json')==AUDIT_SHA
    e=json.loads(read(ROOT/'corefp_output_packing_checks.json'));a=json.loads(read(ROOT/'corefp_output_packing_audit.json'));r=a['result']
    assert e['generator_sha256']==a['generator_sha256']==sha(ROOT/'recover_corefp_output_packing.py')and a['auditor_sha256']==sha(ROOT/'audit_corefp_output_packing.py')
    assert a['checks_sha256']==CHECKS_SHA and a['dependencies']==e['dependencies']and e['parent_pins']==a['parent_pins']==PINS
    for name,h in {**e['dependencies'],**PINS}.items():assert sha(ROOT/name)==h
    assert e['thin_sha256']=='8bf6f7a563cc804522cbd7b3f6a063c479cd2abc6e0b2d996f1eac1eda6cf28c'
    assert a['fresh_replay_completed']and a['process_exit_code']==0 and r['all_checks_pass']and r['verified_counts']==e['verified_counts']==COUNTS
    assert r['independent_replay']==TOTALS and e['replay_totals']=={k:v for k,v in TOTALS.items()if not k.startswith('initial_')}
    assert r['independent_interpreter']=={'instructions':5272,'reads':816,'writes':136,'stack_final_B':10496}
    for k,v in {'finite_machine_cases':32768,'finite_machine_instructions':21594112,'finite_machine_output_B':524288,'actual_machine_frames':8,
      'gap_result_values_checked':128,'scalar_field_origins_checked':96,'output_pointer_origins_checked':128,'H_complete_cases':256,'frozen_queries_unsat':363,'total_queries_unsat':620}.items():assert r[k]==v
    assert len(e['instructions'])==659 and len(bytes.fromhex(e['source_bytes_hex']))==2636
    assert b''.join(bytes.fromhex(i['bytes_hex'])for i in e['instructions'])==bytes.fromhex(e['source_bytes_hex'])
    assert [int(i['pc'],16)for i in e['instructions']]==list(range(0x1bb5a8,0x1bbff4,4))
    gap=e['gap_census'];assert gap['instructions']==515 and gap['source_B']==len(bytes.fromhex(gap['source_bytes_hex']))==2060 and gap['result_registers_and_slots_preserved']
    assert gap['stores'][0]['pc']=='0x1bb0d0'and len(gap['stores'])==1 and gap['stores'][0]['instruction']=='str x26, [sp, #0x318]'
    assert e['common_H_columns_u8']==COLS and e['common_output_permutation']==PERM and sorted(h8(x)for x in range(256))==list(range(256))
    assert e['common_inverse_proof']['inverse_columns_u8']==[39,102,194,204,148,117,192,238]
    ce=json.loads(read(ROOT/'corefp_workspace_consumers_checks.json'));pa=json.loads(read(ROOT/'corefp_workspace_audit.json'));ca=json.loads(read(ROOT/'corefp_workspace_consumers_audit.json'))
    new=[e['common_inverse_proof']]+[p for m in e['transfer_models']for p in m['proofs']]
    frozen=ce['source_model']['proofs']+ce['canonical_phase_proofs']+pa['source_checks']['proofs']+[p for f in pa['frozen_source_checks']for p in f['proofs']]
    assert len(new)==257 and len(frozen)==363
    for p in new+frozen:
        assert p['result']=='unsat';q=z3.Solver();q.set(timeout=30000);q.from_string(p['query']);assert q.check()==z3.unsat,p['label']
    assert len(e['blocks'])==len(e['transfer_models'])==len(a['interpreter_oracles'])==len(a['machine_oracles'])==len(a['origin_oracles'])==8
    assert [b['label']for b in e['blocks']]==LABELS and [b['block_index']for b in e['blocks']]==ORDINALS
    assert [m['bias16_hex']for m in e['transfer_models']]==BIASES
    report=read(BASE/'corefp_output_packing_report.md');assert e['thin_sha256']in report and all(f'| PK{i} |'in report for i in range(1,7))and all(f'**QG{i}**'in report for i in range(1,8))
    for j in range(16):assert f'| {j} | {PERM[j]} | q{144+PERM[j]} | `{hex(STORES[j])}` | `[SP+{hex(SLOTS[j])}]` | `{hex(WRITERS[j])}` |'in report
    for n,(b,m,i,t,o)in enumerate(zip(e['blocks'],e['transfer_models'],a['interpreter_oracles'],a['machine_oracles'],a['origin_oracles'])):
        assert m['label']==t['label']==b['label']and m['block_index']==t['block_index']==b['block_index']
        assert b['end']['source_visit']-b['entry']['source_visit']==659 and len(b['reads'])==102 and len(b['writes'])==17
        assert i=={'instructions':659,'reads':102,'writes':17,'stack_final_B':1312,'all_CPU_fields_match':True}
        assert o=={'scalar_fields':12,'output_pointer_slots':16,'provenance':'last reaching writes only'}
        assert t['actual_frame_cases']==1 and t['finite_cases']==4096 and t['finite_instructions']==2699264 and t['finite_output_B']==65536 and t['source_bytes_preserved']and len(t['ordered_outputs_sha256'])==64
        actual=bytes.fromhex(ca['block_oracles'][n]['canonical_final16_hex']);bias=bytes.fromhex(m['bias16_hex'])
        assert bytes(h8(actual[PERM[j]])^bias[j]for j in range(16)).hex()==b['end']['output16_hex']
        assert len(m['proofs'])==32 and len(m['symbolic_tables'])==16 and m['byte_cases_checked']==4096 and m['source_reads_checked']==102 and m['all_GPRs_and_stack_match']
        assert len(b['initial_word_origins'])==12 and len(b['output_pointer_origins'])==16
        for j,(ptr,row)in enumerate(zip(b['output_pointer_origins'],m['byte_mappings'])):
            assert ptr['output_index']==row['output_index']==j and row['source_g_index']==PERM[j]and row['store_pc']==ptr['store_pc']==hex(STORES[j])
            assert ptr['pointer_load_pc']==hex(STORES[j]-4)and ptr['stack_slot_offset']==SLOTS[j]and [w['pc']for w in ptr['reaching_stores']]==[hex(WRITERS[j])]
    flags=['native_API_executed','IDB_mutated','new_live_IDA_claim','source_context_initializer_established','general_preparation_contract_established','full_goal_complete']
    assert not any(e[k]or a[k]for k in flags)and not e['native_target_executed']and not r['native_target_executed']
    assert e['whole_transform_algorithm']==a['whole_transform_algorithm']=='unknown'
    return e


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==len(old['files'])==8473 and len(after)==len(new['files'])==8479
    assert not before.keys()-after.keys()and after.keys()-before.keys()==ADDED and {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved']and len(new['inputs_preserved'])==3
    for row in new['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256']and size(BASE/p)==after[p]['size_bytes']
    e=receipts()
    assert new['validation']['corefp_output_packing_increment_checks']==COUNTS and new['validation']['corefp_output_packing_static_scope']==e['scope']
    assert new['validation']['reports']==old['validation']['reports']+1==457 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']and len(OWNED)==16
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        logical=p[:-4]if p.endswith('.zst')else p;path_hygiene(read(BASE/logical).encode())
        if logical=='triage_evidence/corefp_output_packing_checks.json':path_hygiene(json.dumps(paths_in_typed_payloads(e)).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,(delta^OWNED)
    print(json.dumps({'unchanged_manifest_entries':len(before)-len(CHANGED),'owned_physical_files':len(OWNED),'original_inputs_preserved':3,'reports':457,
      'complete_profiles':6,'regional_blocks':8,'source_visits':488136,'queries_unsat':620,'finite_machine_cases':32768,'finite_machine_instructions':21594112,
      'output_pointer_origins_checked':128,'native_target_executed':False,'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
