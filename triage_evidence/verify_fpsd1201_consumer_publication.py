#!/usr/bin/env python3
"""Pin audited consumer evidence, scrubbed paths and exact publication delta.

O(owned bytes + manifest + decoded RAM) time, O(largest artifact + decoded
RAM) space. No instruction replay or native effects. Prefix replay is pinned
by the prior receipt; this increment's fresh replay covers only continuation.
"""
import json,subprocess
from pathlib import Path
from hashlib import sha256
from compression import zstd
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene
from verify_fpsd1200_process_publication import paths_in_typed_payloads

ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='bca9d544ed9652648f4ce5a904170342bd157850'
BASELINE_MANIFEST_SHA='6034860edc387797bfa74a2e6af6e1294ce8d9abb7f1b1fc7d959b34e1e42efd'
AUDIT_SHA='fb318e7c9c39e3943b58ca281ca7975d9a545e83cc1029c4f636f2645e1a7e71'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md','daemon_receive_interface_report.md','foundational_triage_report.md',
 'fpsd1201_reduction_report.md','interface_abi_report.md','interface_investigation_status.md',
 'mach_ports_report.md','obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'fpsd1201_consumer_report.md','triage_evidence/recover_fpsd1201_consumer.py','triage_evidence/audit_fpsd1201_consumer.py',
 'triage_evidence/verify_fpsd1201_consumer_publication.py','triage_evidence/fpsd1201_consumer_checks.json',
 'triage_evidence/fpsd1201_consumer_audit.json','triage_evidence/fpsd1201_consumer_ida_readback.json'}
ARCHIVES={MANIFEST,'triage_evidence/fpsd1201_consumer_checks.json','triage_evidence/fpsd1201_consumer_audit.json','triage_evidence/fpsd1201_consumer_ida_readback.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'profiles':12,'audited_checkpoints_resumed':12,'prefix_instructions_rerun':0,'source_visits':3888,'source_reads':828,
 'source_writes':516,'PAC_models':48,'consumer_points':72,'fresh_IDA_spans':2,'fresh_IDA_bytes':3292,'source_code_bytes':34332,'local_queries_unsat':5}
SOURCE={'fresh_IDA_spans':2,'fresh_IDA_bytes':3292,'compiler_bounded_bodies':2,'total_selected_code_bytes':34332,
 'original_fixup_words_checked':79512,'compiler_starts_checked':1602,'retained_queries_unsat':5,'independent_queries_unsat':5,
 'exact_source_instructions_checked':17,'complete_algorithm_universally_proved':False}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_MANIFEST_SHA
    old,current=json.loads(raw),json.loads(read(BASE/MANIFEST));previous={r['path']:r for r in old['files']};new={r['path']:r for r in current['files']}
    assert len(previous)==len(old['files'])==8297 and len(new)==len(current['files'])==8304
    assert not previous.keys()-new.keys()and new.keys()-previous.keys()==ADDED and {p for p in previous if previous[p]!=new[p]}==CHANGED
    assert current['inputs_preserved']==old['inputs_preserved']
    for r in current['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==new[p]['sha256']and size(BASE/p)==new[p]['size_bytes']
    report=read(BASE/'fpsd1201_consumer_report.md');assert all(f'| CF{i} |'in report for i in range(1,9))and all(f'**QG{i}**'in report for i in range(1,8))
    e=json.loads(read(ROOT/'fpsd1201_consumer_checks.json'));assert e['verified_counts']==COUNTS and e['generator_sha256']==sha(ROOT/'recover_fpsd1201_consumer.py')
    for n,h in e['dependencies'].items():assert sha(ROOT/n)==h
    assert not any(e[k]for k in ['new_operand_controls_supplied','whole_parent_replayed','native_target_executed','IDB_edit_operations_requested','full_goal_complete'])
    assert sha(ROOT/'fpsd1201_consumer_audit.json')==AUDIT_SHA
    a=json.loads(read(ROOT/'fpsd1201_consumer_audit.json'));assert a['fresh_replay_completed']and a['process_exit_code']==0 and not a['native_target_executed']
    assert a['auditor_sha256']==sha(ROOT/'audit_fpsd1201_consumer.py')and a['checks_sha256']==sha(ROOT/'fpsd1201_consumer_checks.json')and a['dependencies']==e['dependencies']
    assert a['IDA_readback_sha256']==e['IDA_readback_sha256']==sha(ROOT/'fpsd1201_consumer_ida_readback.json')
    r=a['result'];assert r['source']==SOURCE and r['all_checks_pass']and r['profiles']==12 and r['prefix_instructions_rerun']==0 and r['next_callee_targets']==['0x74fd0c']
    assert r['prior_full_replay_receipt_sha256']==sha(ROOT/'fpsd1201_reduction_audit.json')=='40264eef84f86e6fdf9de0a480b6e46b88ffcc3f9168db976600e6bc818ca2e0'
    assert not any(r[k]for k in ['candidate_inline128_reads_or_writes','auxiliary_or_input_limb_reads_or_writes','complete_consumer_return_established','whole_parent_replayed','native_target_executed','full_goal_complete'])
    totals=r['fresh_replay'];expected={'checkpoint_RAM_bytes_checked':1818624,'complete_CPU_frames_checked':144,'checkpoint_reaching_pointer_loads_checked':12,
      'consumer_record_checkpoints_checked':72,'consumer_wrapper_frame_geometries_checked':12,'consumer_child_cursor_restores_checked':12,
      'outgoing_record_contracts_checked':12,'original_pointer_profile_associations_checked':180,'final_RAM_bytes_checked':1818624,
      'original_visits_checked':3888,'original_reads_checked':828,'original_writes_checked':516,'PAC_models_checked':48};assert totals==expected
    assert len(e['profiles'])==12 and len(e['proofs'])==5 and all(q['result']=='unsat'for q in e['proofs'])
    indices=[0,1,2,3,5,6,7,8,9,10,11,12];calls={'0x9819c4':('0x1142c08','0x1d056a0','0x4032'),'0x1142e08':('0x1142154','0x1d04098','0x33f2')}
    prior=json.loads(read(ROOT/'fpsd1201_reduction_checks.json'))
    for p,j in zip(e['profiles'],indices):
        assert p['prior_profile_index']==j and p['configuration']==prior['profiles'][j]['configuration']and p['initial']==prior['profiles'][j]['terminal']and p['initial_RAM']==prior['profiles'][j]['final_RAM']
        assert p['stop_reason']=='unretained_callee'and p['frontier']['pc']=='0x114245c'and p['frontier']['target']=='0x74fd0c'and not p['frontier']['instruction_executed']
        assert len(p['source_visits'])==324 and len(p['source_reads'])==69 and len(p['source_writes'])==43 and len(p['PAC_models'])==4 and len(p['consumer_points'])==6
        assert p['final_status_u32']=='0xa5a5a5a5'and p['final_delta_cell_u64']==hex(p['configuration']['seed_u64'])and not p['native_effects']
        found=set()
        for q in p['PAC_models']:
            if q['pc']in calls:assert(q['target'],q['original_slot'],q['modifier'])==calls[q['pc']];found.add(q['pc'])
        assert found==calls.keys()
    f=e['reference_file_check'];assert(f['original_fixup_words_checked'],f['code_bytes_checked'],f['earlier_parent_bytes_checked'],f['bank_bytes_checked'])==(79512,34332,85464,3072)
    att=json.loads(read(ROOT/'fpsd1201_consumer_ida_readback.json'));assert not att['IDB_mutated']and not att['native_target_executed']and len(att['spans'])==2
    assert sum(s['size_B']for s in att['spans'])==3292 and all(s['current_equals_IDA_original_bytes']for s in att['spans'])
    assert current['validation']['fpsd1201_consumer_increment_checks']==COUNTS and current['validation']['fpsd1201_consumer_static_scope']==e['scope']
    assert current['validation']['reports']==old['validation']['reports']+1==430 and current['goal_status']=='active'
    assert current['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
    assert len(OWNED)==17
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        logical=p[:-4]if p.endswith('.zst')else p
        if logical=='triage_evidence/fpsd1201_consumer_checks.json':path_hygiene(json.dumps(paths_in_typed_payloads(e)).encode())
        else:path_hygiene(read(BASE/logical).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED
    print(json.dumps({'unchanged_manifest_entries':len(previous)-len(CHANGED),'owned_physical_files':len(OWNED),'original_inputs_preserved':3,
      'reports':430,'profiles':12,'new_original_visits':3888,'prefix_instructions_rerun':0,'publication_does_not_replay_instructions':True,
      'native_target_executed':False,'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
