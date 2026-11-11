#!/usr/bin/env python3
"""Verify exact owned publication and pin the successful independent receipt.

Does not replay instructions. Typed compressed RAM is decoded and path checked
before its binary Base64 spelling is excluded from outer metadata path checks.
O(owned bytes + manifest + decoded RAM) time; O(largest artifact + RAM) space.
"""
import base64
from hashlib import sha256
import json
from pathlib import Path
import struct
import subprocess
import zlib
from compression import zstd
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene

ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='5f5c68ca5184ca2cd8a57bd089446372be512be6'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'fpsd1200_lifetime_report.md','daemon_receive_interface_report.md','mach_ports_report.md',
 'foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md',
 'obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'fpsd1200_process_report.md','triage_evidence/recover_fpsd1200_process.py',
 'triage_evidence/audit_fpsd1200_process.py','triage_evidence/verify_fpsd1200_process_publication.py',
 'triage_evidence/fpsd1200_process_checks.json','triage_evidence/fpsd1200_process_ida_readback.json',
 'triage_evidence/fpsd1200_process_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/fpsd1200_process_checks.json',
 'triage_evidence/fpsd1200_process_ida_readback.json','triage_evidence/fpsd1200_process_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'profiles':8,'callback_original_visits':44440,'imports':96,'pool_store_events':208,
 'pool_read_events':422,'complete_process_CPU_frames':836,'source_spans':34,
 'source_instructions':3501,'queries_unsat':3}
CALLBACK={'complete_CPU_frames_checked':1052,'declared_full_state_component_entries_checked':8,
 'original_instruction_visits_checked':44440,'original_writes_checked':3688,'original_reads_checked':5734,
 'external_ABI_and_declared_effect_contracts_recomputed':96,'complete_final_mutable_RAM_bytes_checked':19529728,
 'complete_final_pool_bytes_checked':524288,'complete_final_defined_mask_bytes_checked':524288,
 'process_point_CPU_frames_checked':836}
ORIGIN={'complete_CPU_frames_checked':34,'declared_full_state_component_entries_checked':2,
 'original_instruction_visits_checked':22599,'original_writes_checked':1083,'original_reads_checked':2809,
 'external_ABI_and_declared_effect_contracts_recomputed':14,'complete_final_mutable_RAM_bytes_checked':4882432}
LABELS=['matching_audit_PID','different_PID','diagnostic_word_changed','inactive_marker',
 'reserved_marker','other_marker','encoded_PID_changed','live_slot_index1']


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def decode(d):
    b=zlib.decompress(base64.b64decode(d['zlib_base64'],validate=True))
    assert len(b)==d['size_bytes']and sha256(b).hexdigest()==d['sha256'];return b


def paths_in_typed_payloads(obj):
    if isinstance(obj,list):return [paths_in_typed_payloads(v)for v in obj]
    if not isinstance(obj,dict):return obj
    if 'zlib_base64'in obj:
        assert {'size_bytes','sha256'}<=obj.keys()
        path_hygiene(decode(obj))
        return {k:('decoded typed RAM independently path checked'if k=='zlib_base64'else paths_in_typed_payloads(v))for k,v in obj.items()}
    return {k:paths_in_typed_payloads(v)for k,v in obj.items()}


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest()=='c10d6f880ff0e86bd4f28e303ae3d63ccce717e59af02ec576ccbf899744d701'
    previous,current=json.loads(raw),json.loads(read(BASE/MANIFEST))
    old={r['path']:r for r in previous['files']};new={r['path']:r for r in current['files']}
    assert len(old)==len(previous['files'])==8199 and len(new)==len(current['files'])==8206
    assert not old.keys()-new.keys()and new.keys()-old.keys()==ADDED
    assert {p for p in old if old[p]!=new[p]}==CHANGED
    assert current['inputs_preserved']==previous['inputs_preserved']
    for r in current['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==new[p]['sha256']and size(BASE/p)==new[p]['size_bytes']
    report=read(BASE/'fpsd1200_process_report.md')
    assert all(f'| FP{i} |'in report for i in range(1,9))and all(f'**QG{i}**'in report for i in range(1,8))
    e=json.loads(read(ROOT/'fpsd1200_process_checks.json'))
    assert e['verified_counts']==COUNTS and sha(ROOT/'recover_fpsd1200_process.py')==e['generator_sha256']
    for n,h in e['dependencies'].items():assert sha(ROOT/n)==h
    assert e['new_IDA_access']and not any(e[k]for k in ['new_IDB_mutations','new_native_execution','full_goal_complete'])
    receipt=json.loads(read(ROOT/'fpsd1200_process_audit.json'))
    assert receipt['fresh_replay_completed']and receipt['process_exit_code']==0 and not receipt['native_target_executed']
    assert receipt['auditor_sha256']==sha(ROOT/'audit_fpsd1200_process.py')
    assert receipt['checks_sha256']==sha(ROOT/'fpsd1200_process_checks.json')
    assert receipt['IDA_SDK_readback_sha256']==sha(ROOT/'fpsd1200_process_ida_readback.json')
    assert receipt['daemon_sha256']==e['daemon_sha256']and receipt['dependencies']==e['dependencies']
    result=receipt['result']
    assert result['callback_replay']==CALLBACK and result['initializer_setup_replay']==ORIGIN
    assert result['profiles']==8 and result['queries_unsat']==3 and result['source_IDA_spans']==34
    assert result['original_format12_rebases']==94 and result['original_format12_binds']==11
    assert result['frozen_session_predecessor_receipt_pinned']and not result['session_prefix_freshly_replayed']
    assert not result['native_target_executed']and result['all_checks_pass']
    assert result['independent_source_lift']=={'source_lifted_queries_unsat':3,
      'writer_shift1_phase_conditional':True,'reader_phases_checked_by_full_CPU_replay':True}
    att=json.loads(read(ROOT/'fpsd1200_process_ida_readback.json'))
    assert not att['IDB_mutated']and att['spans']==[{'start':s['start'],'size_B':int(s['end'],16)-int(s['start'],16),'sha256':s['sha256']}for s in e['spans']]
    assert att['SDK_context']['compile_only']['exit_code']==0 and len(att['SDK_context']['headers'])==4
    assert len(att['additional_source_ranges'])==1
    assert [p['configuration']['label']for p in e['profiles']]==LABELS
    for index,p in enumerate(e['profiles']):
        c=p['configuration'];slot=896*c['slot_index'];b=decode(p['final_pool'])
        assert c['event_result']==1 and c['filter']==-5 and not c['event_seed']
        assert p['composition']['header_after_hex']==struct.pack('<QQ',0x74000000,50).hex()
        assert not p['composition']['native_temporal_continuity_established']
        retired=index in(0,2,5,7)
        assert len(p['pool_defined_writes'])==(52 if retired else 0)
        if retired:
            assert b[slot:slot+8]==bytes(8)and b[slot+876:slot+880]==bytes.fromhex('49df7745')
            assert b[slot+820:slot+868]==bytes.fromhex('f8a4aa56b468661a90bc224e4c80de12')*3
        names=[m['name']for m in p['imports']]
        assert names.count('CoreFoundation/_CFMachPortInvalidate')==names.count('CoreFoundation/_CFRelease')==int(retired)
    assert current['validation']['fpsd1200_process_increment_checks']==COUNTS
    assert current['validation']['fpsd1200_process_static_scope']==e['scope']
    assert current['validation']['reports']==previous['validation']['reports']+1==416
    assert current['validation']['unavailable_external_primary_references']==previous['validation']['unavailable_external_primary_references']
    assert current['goal_status']=='active'and len(OWNED)==16
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        if p=='triage_evidence/fpsd1200_process_checks.json.zst':
            path_hygiene(json.dumps(paths_in_typed_payloads(e)).encode())
        else:path_hygiene((BASE/p).read_bytes())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    print(json.dumps({'unchanged_manifest_entries':len(old)-len(CHANGED),'owned_physical_files':len(OWNED),
      'original_inputs_preserved':3,'reports':416,'pinned_fresh_callback_visits':44440,
      'pinned_fresh_origin_visits':22599,'profiles':8,'independent_source_lift_queries':3,
      'publication_does_not_replay_instructions':True,'native_temporal_continuity_established':False,
      'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
