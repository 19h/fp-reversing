#!/usr/bin/env python3
"""Pin the successful session-path audit and exact publication delta.

Decode typed RAM before path checking. No instructions are replayed here.
O(owned bytes + manifest + decoded RAM) time, O(largest artifact + RAM) space.
"""
from hashlib import sha256
import json
from pathlib import Path
import subprocess
from compression import zstd
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene
from verify_fpsd1200_process_publication import paths_in_typed_payloads

ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='4db82d367215cfef07b8eabb4881fd6664ac1ac8'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'fpsd1202_ool_report.md','daemon_receive_interface_report.md','mach_ports_report.md',
 'foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md',
 'obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'fpsd1202_session_report.md','triage_evidence/recover_fpsd1202_session.py',
 'triage_evidence/audit_fpsd1202_session.py','triage_evidence/verify_fpsd1202_session_publication.py',
 'triage_evidence/fpsd1202_session_checks.json','triage_evidence/fpsd1202_session_ida_readback.json',
 'triage_evidence/fpsd1202_session_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/fpsd1202_session_checks.json',
 'triage_evidence/fpsd1202_session_ida_readback.json','triage_evidence/fpsd1202_session_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'profiles':13,'original_visits':251460,'imports':104,'source_reads':31029,
 'source_writes':10032,'session_CPU_points':146,'source_spans':133,'source_instructions':7941}
REPLAY={'complete_CPU_frames_checked':649,'declared_full_state_component_entries_checked':13,
 'original_instruction_visits_checked':251460,'original_reads_checked':31029,'original_writes_checked':10032,
 'external_ABI_and_declared_effect_contracts_recomputed':104,'complete_final_mutable_RAM_bytes_checked':31735808,
 'complete_final_pool_bytes_checked':851968,'complete_final_defined_mask_bytes_checked':851968,
 'process_point_CPU_frames_checked':0,'extra_final_private_bytes_checked':851968,
 'ABI_CPU_point_frames_checked':243,'selected_session_CPU_point_frames_checked':146}
LABELS=['word0','word1','word2','word3','word4','word_ffffffff','different_session_name',
 'live_slot_index1','wordB_zero','wordC_zero','OOL_zero','OOL_reverse','inline_zero']
VISITS=[3162,29298,29298,3162,3162,3162,4399,29327,29298,29298,29298,29298,29298]


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest()=='be4c7b2e3d3d56b8d665a096d0fea98d327e57e90d12c20333c8b8a654457ec8'
    previous,current=json.loads(raw),json.loads(read(BASE/MANIFEST))
    old={r['path']:r for r in previous['files']};new={r['path']:r for r in current['files']}
    assert len(old)==len(previous['files'])==8220 and len(new)==len(current['files'])==8227
    assert not old.keys()-new.keys()and new.keys()-old.keys()==ADDED
    assert {p for p in old if old[p]!=new[p]}==CHANGED
    assert current['inputs_preserved']==previous['inputs_preserved']
    for r in current['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==new[p]['sha256']and size(BASE/p)==new[p]['size_bytes']
    report=read(BASE/'fpsd1202_session_report.md')
    assert all(f'| FS{i} |'in report for i in range(1,9))and all(f'**QG{i}**'in report for i in range(1,8))
    e=json.loads(read(ROOT/'fpsd1202_session_checks.json'))
    assert e['verified_counts']==COUNTS and sha(ROOT/'recover_fpsd1202_session.py')==e['generator_sha256']
    for n,h in e['dependencies'].items():assert sha(ROOT/n)==h
    assert not any(e[k]for k in ['native_target_executed','IDB_edit_operations_requested','full_goal_complete'])
    receipt=json.loads(read(ROOT/'fpsd1202_session_audit.json'))
    assert receipt['fresh_replay_completed']and receipt['process_exit_code']==0 and not receipt['native_target_executed']
    assert receipt['auditor_sha256']==sha(ROOT/'audit_fpsd1202_session.py')
    assert receipt['checks_sha256']==sha(ROOT/'fpsd1202_session_checks.json')
    assert receipt['IDA_SDK_readback_sha256']==sha(ROOT/'fpsd1202_session_ida_readback.json')
    assert receipt['daemon_sha256']==e['daemon_sha256']and receipt['dependencies']==e['dependencies']
    r=receipt['result'];assert r['all_checks_pass']and r['profiles']==13 and r['fresh_replay']==REPLAY
    assert r['source_IDA_spans']==133 and r['format12_rebases']==281 and r['format12_bindings']==10
    assert r['retained_queries_unsat']==3 and r['independent_source_lift']=={
      'independently_lifted_source_queries_unsat':3,'operation12_target':'0x10059b5c4',
      'other_operation_target':'0x100528dd8','signed_LE_overflow_semantics_checked':True,
      'scope':'Freshly checked local CPU phases; all-u32 scalar values.'}
    assert not r['native_target_executed']and not r['session_and_registration_prefixes_freshly_replayed']and not r['full_goal_complete']
    assert [p['configuration']['label']for p in e['profiles']]==[p['case']for p in r['cases']]==LABELS
    assert [len(p['source_visits'])for p in e['profiles']]==[p['visits']for p in r['cases']]==VISITS
    assert [p['original_application_status_u32']for p in r['cases']]==[0,8,8,0,0,0,5,8,8,8,8,8,8]
    assert [p['reply_size_B']for p in r['cases']]==[72,36,36,72,72,72,36,36,36,36,36,36,36]
    assert [p['OOL_input_bytes_read']for p in r['cases']]==[0,16,16,0,0,0,0,16,16,16,16,16,16]
    assert [p['inline_input_bytes_read']for p in r['cases']]==[0,1,1,0,0,0,0,1,1,1,1,1,1]
    assert [p['pool_stores']for p in r['cases']]==[1,3,3,1,1,1,0,3,3,3,3,3,3]
    assert all(p['tail_bytes_read']==0 for p in r['cases'])
    algorithms=r['algorithm_oracles']
    assert algorithms['profiles']==8 and algorithms['distinct_AES_tuples']==5 and algorithms['known_vector_matches']
    assert len(algorithms['rows'])==8 and all(p['stored_key_known_bytes']==0 and p['reference_matches']and p['CLI_matches']for p in algorithms['rows'])
    att=json.loads(read(ROOT/'fpsd1202_session_ida_readback.json'))
    assert not att['IDB_mutated']and att['input_sha256']=='4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7'
    assert att['spans']==[{'start':s['start'],'size_B':int(s['end'],16)-int(s['start'],16),'sha256':s['sha256']}for s in e['spans']]
    assert len(att['SDK_context']['headers'])==5 and att['SDK_context']['compile_only']['exit_code']==0
    assert current['validation']['fpsd1202_session_increment_checks']==COUNTS
    assert current['validation']['fpsd1202_session_static_scope']==e['scope']
    assert current['validation']['reports']==previous['validation']['reports']+1==419
    assert current['validation']['unavailable_external_primary_references']==previous['validation']['unavailable_external_primary_references']
    assert current['goal_status']=='active'and len(OWNED)==16
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        if p=='triage_evidence/fpsd1202_session_checks.json.zst':path_hygiene(json.dumps(paths_in_typed_payloads(e)).encode())
        else:path_hygiene(read(BASE/(p[:-4]if p.endswith('.zst')else p)).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    print(json.dumps({'unchanged_manifest_entries':len(old)-len(CHANGED),'owned_physical_files':len(OWNED),
      'original_inputs_preserved':3,'reports':419,'profiles':13,'pinned_new_original_visits':251460,
      'publication_does_not_replay_instructions':True,'native_target_executed':False,
      'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
