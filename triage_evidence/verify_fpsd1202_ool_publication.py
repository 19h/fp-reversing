#!/usr/bin/env python3
"""Pin the successful FPSD1202 independent audit and exact publication delta.

Decodes typed RAM before path checking. No instructions are replayed here.
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
PREVIOUS='317b699c9aaecbd9002c1ce2ec9b7fcee4c40bf5'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'fpsd1201_session_report.md','daemon_receive_interface_report.md','mach_ports_report.md',
 'foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md',
 'obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'fpsd1202_ool_report.md','triage_evidence/recover_fpsd1202_ool.py',
 'triage_evidence/audit_fpsd1202_ool.py','triage_evidence/verify_fpsd1202_ool_publication.py',
 'triage_evidence/fpsd1202_ool_checks.json','triage_evidence/fpsd1202_ool_ida_readback.json',
 'triage_evidence/fpsd1202_ool_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/fpsd1202_ool_checks.json',
 'triage_evidence/fpsd1202_ool_ida_readback.json','triage_evidence/fpsd1202_ool_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'profiles':15,'original_visits':20990,'imports':29,'application_controls':2,
 'source_reads':4583,'source_writes':2642,'source_spans':37,'source_instructions':3140,'ABI_CPU_points':172}
REPLAY={'complete_CPU_frames_checked':294,'declared_full_state_component_entries_checked':15,
 'original_instruction_visits_checked':20990,'original_reads_checked':4583,'original_writes_checked':2642,
 'external_ABI_and_declared_effect_contracts_recomputed':29,'complete_final_mutable_RAM_bytes_checked':36618240,
 'complete_final_pool_bytes_checked':983040,'complete_final_defined_mask_bytes_checked':983040,
 'process_point_CPU_frames_checked':0,'extra_final_private_bytes_checked':983040,
 'ABI_CPU_point_frames_checked':172,'declared_application_return_contracts_checked':2}
LABELS=['source_word0','source_word1','source_word2','source_word3','source_session_name',
 'source_marker4d','source_moved_session','source_no_registration','stub_success','stub_error',
 'guard_simple','guard_descriptor_count','guard_size','guard_descriptor_type','guard_repeated_count']
VISITS=[2296,2296,2390,2296,4332,2544,2296,2133,100,91,37,40,43,46,50]


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest()=='aba4c3ef30d1f12deb9d4e513e89880294b403b8aa88033354997b68a4b3cb0e'
    previous,current=json.loads(raw),json.loads(read(BASE/MANIFEST))
    old={r['path']:r for r in previous['files']};new={r['path']:r for r in current['files']}
    assert len(old)==len(previous['files'])==8213 and len(new)==len(current['files'])==8220
    assert not old.keys()-new.keys()and new.keys()-old.keys()==ADDED
    assert {p for p in old if old[p]!=new[p]}==CHANGED
    assert current['inputs_preserved']==previous['inputs_preserved']
    for r in current['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==new[p]['sha256']and size(BASE/p)==new[p]['size_bytes']
    report=read(BASE/'fpsd1202_ool_report.md')
    assert all(f'| FO{i} |'in report for i in range(1,9))and all(f'**QG{i}**'in report for i in range(1,8))
    e=json.loads(read(ROOT/'fpsd1202_ool_checks.json'))
    assert e['verified_counts']==COUNTS and sha(ROOT/'recover_fpsd1202_ool.py')==e['generator_sha256']
    for n,h in e['dependencies'].items():assert sha(ROOT/n)==h
    assert not any(e[k]for k in ['native_target_executed','IDB_edit_operations_requested','full_goal_complete'])
    receipt=json.loads(read(ROOT/'fpsd1202_ool_audit.json'))
    assert receipt['fresh_replay_completed']and receipt['process_exit_code']==0 and not receipt['native_target_executed']
    assert receipt['auditor_sha256']==sha(ROOT/'audit_fpsd1202_ool.py')
    assert receipt['checks_sha256']==sha(ROOT/'fpsd1202_ool_checks.json')
    assert receipt['IDA_SDK_readback_sha256']==sha(ROOT/'fpsd1202_ool_ida_readback.json')
    assert receipt['daemon_sha256']==e['daemon_sha256']and receipt['dependencies']==e['dependencies']
    r=receipt['result'];assert r['all_checks_pass']and r['profiles']==15 and r['fresh_replay']==REPLAY
    assert r['source_IDA_spans']==37 and r['format12_rebases']==170 and r['format12_bindings']==10
    assert r['retained_queries_unsat']==2 and r['independent_source_lift']=={
      'independently_lifted_source_queries_unsat':2,'marker_match_target':'0x1004a07b4','marker_other_target':'0x1005bec24'}
    assert not r['native_target_executed']and not r['session_and_registration_prefixes_freshly_replayed']and not r['full_goal_complete']
    assert [p['configuration']['label']for p in e['profiles']]==[p['case']for p in r['cases']]==LABELS
    assert [len(p['source_visits'])for p in e['profiles']]==[p['visits']for p in r['cases']]==VISITS
    assert [p['application_status']for p in[p['configuration']for p in e['profiles']]]==[None]*8+[0,8]+[None]*5
    assert all(p['OOL_body_bytes_read']==0 for p in r['cases'])
    assert [p['pool_reads']for p in r['cases']]==[0,0,0,0,50,2,0,0,0,0,0,0,0,0,0]
    assert [p['reply_size_B']for p in r['cases']]==[36,36,36,36,36,None,36,None,72,36,36,36,36,36,36]
    assert [p['simple_reply_status_s32']for p in r['cases']]==[5,5,5,5,5,None,5,None,None,8,-304,-304,-304,-300,-300]
    att=json.loads(read(ROOT/'fpsd1202_ool_ida_readback.json'))
    assert not att['IDB_mutated']and att['input_sha256']=='4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7'
    assert att['spans']==[{'start':s['start'],'size_B':int(s['end'],16)-int(s['start'],16),'sha256':s['sha256']}for s in e['spans']]
    assert len(att['SDK_context']['headers'])==5 and att['SDK_context']['compile_only']['exit_code']==0
    assert current['validation']['fpsd1202_ool_increment_checks']==COUNTS
    assert current['validation']['fpsd1202_ool_static_scope']==e['scope']
    assert current['validation']['reports']==previous['validation']['reports']+1==418
    assert current['validation']['unavailable_external_primary_references']==previous['validation']['unavailable_external_primary_references']
    assert current['goal_status']=='active'and len(OWNED)==16
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        if p=='triage_evidence/fpsd1202_ool_checks.json.zst':path_hygiene(json.dumps(paths_in_typed_payloads(e)).encode())
        else:path_hygiene((BASE/p).read_bytes())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    print(json.dumps({'unchanged_manifest_entries':len(old)-len(CHANGED),'owned_physical_files':len(OWNED),
      'original_inputs_preserved':3,'reports':418,'profiles':15,'pinned_new_original_visits':20990,
      'publication_does_not_replay_instructions':True,'native_target_executed':False,
      'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
