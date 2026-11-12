#!/usr/bin/env python3
"""Pin exact export/status-flow publication; no instruction replay.

Time O(owned bytes + manifest + decoded RAM); space O(largest artifact +
decoded RAM). Original input files and prior unowned artifacts are preserved.
"""
import json,subprocess
from pathlib import Path
from hashlib import sha256
from compression import zstd
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene
from verify_fpsd1200_process_publication import paths_in_typed_payloads

ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='60c2e90fb59f8389349aac1bbd76dda3ea2a8dc8'
BASELINE_SHA='19b1936184bdd92da3c78d2a34e756d465929ebb3f0bfdb94cf5b30e1ee4fca9'
AUDIT_SHA='d55c04ca84d34b0d6ae04f1d4e45a8eb72e4fdb43e0ab64e68d9a5465a9ab8da'
CHECKS_SHA='e69211620dde7b07114a314849f0f786852d8fb75c146e45bd8fa557293a906b'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','daemon_receive_interface_report.md','foundational_triage_report.md','fpsd1201_auxiliary_report.md',
 'fpsd1201_record_report.md','fpsd1201_caller_report.md','interface_abi_report.md','interface_investigation_status.md',
 'mach_ports_report.md','obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'fpsd1201_export_report.md','triage_evidence/recover_fpsd1201_export.py','triage_evidence/audit_fpsd1201_export.py',
 'triage_evidence/verify_fpsd1201_export_publication.py','triage_evidence/fpsd1201_export_checks.json','triage_evidence/fpsd1201_export_audit.json','triage_evidence/fpsd1201_export_ida_readback.json'}
ARCHIVES={MANIFEST,'triage_evidence/fpsd1201_export_checks.json','triage_evidence/fpsd1201_export_audit.json','triage_evidence/fpsd1201_export_ida_readback.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'profiles':132,'prefix_instructions_rerun':0,'source_visits':306357,'source_reads':33249,'source_writes':10213,'PAC_models':20104,'export_points':264,'root_points':108,
 'fresh_IDA_spans':1,'fresh_IDA_bytes':812,'source_code_bytes':41224,'local_queries_unsat':4}
TOTALS={'restored_RAM_bytes_checked':20004864,'checkpoint_reaching_loads_checked':18,'complete_CPU_frames_checked':20740,'initial_RAM_bytes_checked':20004864,'writer_byte_oracles_checked':8179,
 'complete_export_returns_checked':132,'admitted_exports_checked':84,'root_points_checked':108,'complete_root_helper_returns_checked':18,'original_pointer_profile_associations_checked':805,
 'final_RAM_bytes_checked':20004864,'unread_export_statuses_checked':18,'root_publication_stores_checked':54,'original_visits_checked':306357,'original_reads_checked':33249,
 'original_writes_checked':10213,'PAC_models_checked':20104,'rejected_without_payload_read':48,'rejected_exports_checked':48,'short_export_status_nonpropagation_controls':2}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,current=json.loads(raw),json.loads(read(BASE/MANIFEST));previous={r['path']:r for r in old['files']};new={r['path']:r for r in current['files']}
    assert len(previous)==len(old['files'])==8318 and len(new)==len(current['files'])==8325
    assert not previous.keys()-new.keys()and new.keys()-previous.keys()==ADDED and {p for p in previous if previous[p]!=new[p]}==CHANGED
    assert current['inputs_preserved']==old['inputs_preserved']and len(current['inputs_preserved'])==3
    for r in current['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==new[p]['sha256']and size(BASE/p)==new[p]['size_bytes']
    report=read(BASE/'fpsd1201_export_report.md');assert all(f'| EX{i} |'in report for i in range(1,8))and all(f'**QG{i}**'in report for i in range(1,8))
    assert sha(ROOT/'fpsd1201_export_checks.json')==CHECKS_SHA and sha(ROOT/'fpsd1201_export_audit.json')==AUDIT_SHA
    e=json.loads(read(ROOT/'fpsd1201_export_checks.json'));a=json.loads(read(ROOT/'fpsd1201_export_audit.json'));assert e['verified_counts']==COUNTS and e['generator_sha256']==sha(ROOT/'recover_fpsd1201_export.py')
    for n,h in e['dependencies'].items():assert sha(ROOT/n)==h
    assert a['fresh_replay_completed']and a['process_exit_code']==0 and a['auditor_sha256']==sha(ROOT/'audit_fpsd1201_export.py')and a['checks_sha256']==CHECKS_SHA and a['dependencies']==e['dependencies']
    assert a['IDA_readback_sha256']==e['IDA_readback_sha256']==sha(ROOT/'fpsd1201_export_ida_readback.json')=='f6bf46580c49225d929af7e873b2afac1d70f90cbd3df9cbb9d820cc39e15019'
    r=a['result'];assert r['fresh_replay']==TOTALS and r['all_checks_pass']and r['profiles']==132 and r['modes']=={'retained':16,'short_export':2,'isolated':112,'minimum_count':2}
    assert r['source']=={'fresh_IDA_spans':1,'fresh_IDA_bytes':812,'compiler_bounded_bodies':1,'total_selected_code_bytes':41224,'original_fixup_words_checked':79512,'compiler_starts_checked':1602,
      'retained_queries_unsat':4,'independent_queries_unsat':4,'exact_source_instructions_checked':24,'prior_saved_count_profiles_checked':36,
      'prior_saved_count_checks_sha256':sha(ROOT/'fpsd1201_operand_checks.json'),'prior_saved_count_audit_sha256':sha(ROOT/'fpsd1201_operand_audit.json'),'native_admission_established':False}
    assert r['prior_replay_receipt_sha256']==sha(ROOT/'fpsd1201_auxiliary_audit.json')=='623b257cc3ccb1e670cad46a50615f43d21cf6e0abbad4ae9cb80c7f0ea80084'
    assert not any(e[k]for k in ['whole_parent_replayed','native_target_executed','IDB_edit_operations_requested','full_goal_complete'])and not a['native_target_executed']
    assert not any(r[k]for k in ['native_parent_continuation_replayed','prefix_instructions_rerun','whole_parent_replayed','native_target_executed','full_goal_complete'])
    assert len(e['profiles'])==len(r['profile_summaries'])==132 and len(e['proofs'])==4 and all(q['result']=='unsat'for q in e['proofs'])
    for p,s in zip(e['profiles'],r['profile_summaries']):
        assert p['stop_reason']=='returned'and p['frontier']is None and p['terminal']['pc']=='0x7f000000'and not p['native_effects']and len(p['export_points'])==2
        if p['configuration']['mode']in ['retained','short_export']:
            assert len(p['root_points'])==6 and p['root_points'][-1]['count_u32']==8 and p['root_points'][-1]['delta_cell_u64']=='0x0'
            assert s['root_success_despite_export_rejection']==(p['configuration']['mode']=='short_export')
        else:assert not p['root_points']
    assert sum(s['accepted']for s in r['profile_summaries'])==84 and sum(s['exported_bytes']for s in r['profile_summaries'])==8179
    assert sum(s.get('root_success_despite_export_rejection',False)for s in r['profile_summaries'])==2
    f=e['reference_file_check'];assert(f['original_fixup_words_checked'],f['code_bytes_checked'],f['earlier_parent_bytes_checked'],f['bank_bytes_checked'])==(79512,41224,85464,3072)
    att=json.loads(read(ROOT/'fpsd1201_export_ida_readback.json'));assert not att['IDB_mutated']and not att['native_target_executed']and len(att['spans'])==1 and att['spans'][0]['size_B']==812 and att['spans'][0]['current_equals_IDA_original_bytes']
    assert current['validation']['fpsd1201_export_increment_checks']==COUNTS and current['validation']['fpsd1201_export_static_scope']==e['scope']
    assert current['validation']['reports']==old['validation']['reports']+1==433 and current['goal_status']=='active'
    assert current['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']and len(OWNED)==19
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        logical=p[:-4]if p.endswith('.zst')else p
        if logical=='triage_evidence/fpsd1201_export_checks.json':path_hygiene(json.dumps(paths_in_typed_payloads(e)).encode())
        else:path_hygiene(read(BASE/logical).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED
    print(json.dumps({'unchanged_manifest_entries':len(previous)-len(CHANGED),'owned_physical_files':len(OWNED),'original_inputs_preserved':3,'reports':433,'profiles':132,'complete_export_returns':132,
      'writer_byte_oracles':8179,'complete_root_helper_returns':18,'local_status_nonpropagation_controls':2,'prior_saved_count_profiles':36,'prefix_instructions_rerun':0,
      'publication_does_not_replay_instructions':True,'native_target_executed':False,'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
