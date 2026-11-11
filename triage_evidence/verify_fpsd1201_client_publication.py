#!/usr/bin/env python3
"""Pin the successful client/server audit and exact publication delta.

No instructions replay here. Decode typed RAM before path checking.
O(owned bytes + manifest + decoded RAM) time and O(largest artifact + RAM) space.
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
PREVIOUS='cfac5dc0008c63d0db0ffb2c658578085cd54058'
BASELINE_MANIFEST_SHA='1253fd5c1b9571d0f82dbdc9c47bc0721df3a2ad8133794099eb4a1f194f2085'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_client_paths_report.md',
 'daemon_receive_interface_report.md',
 'foundational_triage_report.md',
 'fpsd1201_session_report.md',
 'interface_abi_report.md',
 'interface_investigation_status.md',
 'mach_ports_report.md',
 'obfuscated_routines_report.md',
 'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'fpsd1201_client_report.md',
 'triage_evidence/audit_fpsd1201_client.py',
 'triage_evidence/fpsd1201_client_audit.json',
 'triage_evidence/fpsd1201_client_checks.json',
 'triage_evidence/fpsd1201_client_ida_readback.json',
 'triage_evidence/recover_fpsd1201_client.py',
 'triage_evidence/verify_fpsd1201_client_publication.py'}
ARCHIVES={'triage_evidence/fpsd1201_client_audit.json',
 'triage_evidence/fpsd1201_client_checks.json',
 'triage_evidence/fpsd1201_client_ida_readback.json',
 'triage_evidence/interface_manifest.json'}
COUNTS={'PAC_models': 136,
 'imports': 82,
 'literal_bytes': 8,
 'local_proofs': 1,
 'original_visits': 2389,
 'profiles': 27,
 'source_body_bytes': 404,
 'source_reads': 954,
 'source_writes': 729,
 'stub_bytes': 112}
CLIENT_REPLAY={'PAC_models_checked': 136,
 'complete_CPU_frames_checked': 218,
 'complete_final_RAM_bytes_checked': 2322432,
 'external_contracts_checked': 82,
 'original_reads_checked': 954,
 'original_visits_checked': 2389,
 'original_writes_checked': 729}
SERVER_JOIN={'application_return_u32': '0xffff5b37',
 'client_to_server_body_bytes_equal': 140,
 'fresh_original_server_replay': {'complete_CPU_frames_checked': 40,
                                  'complete_extra_region_pool_and_mask_bytes_checked': 327680,
                                  'complete_final_mutable_RAM_bytes_checked': 2441216,
                                  'declared_full_state_component_entries_checked': 1,
                                  'external_ABI_and_declared_effect_contracts_recomputed': 14,
                                  'heap_owner_accesses_checked': 4637,
                                  'original_instruction_visits_checked': 480680,
                                  'original_reads_checked': 71922,
                                  'original_writes_checked': 16162,
                                  'session_CPU_point_frames_checked': 8},
 'full_received_request_bytes_compared': 164,
 'native_temporal_or_endpoint_identity_established': False,
 'original_bindings_checked': 11,
 'original_rebases_checked': 515,
 'receive_header_conversion_is_declared': True,
 'server_to_client_reply_bytes_compared': 36,
 'session_prefix_freshly_replayed': False,
 'source_spans_compared_with_retained_IDA': 320}
CASES=[{'case': 'source_failure_join',
  'cleanup': ['_mach_msg_destroy'],
  'native_effects': False,
  'return_u32': '0xffff5b37',
  'visits': 93,
  'voucher_model': 'absent'},
 {'case': 'parser_status0',
  'cleanup': [],
  'native_effects': False,
  'return_u32': '0x0',
  'visits': 88,
  'voucher_model': 'absent'},
 {'case': 'parser_status8',
  'cleanup': ['_mach_msg_destroy'],
  'native_effects': False,
  'return_u32': '0x8',
  'visits': 93,
  'voucher_model': 'absent'},
 {'case': 'parser_status_ffffffff',
  'cleanup': ['_mach_msg_destroy'],
  'native_effects': False,
  'return_u32': '0xffffffff',
  'visits': 93,
  'voucher_model': 'absent'},
 {'case': 'parser_status_80000000',
  'cleanup': ['_mach_msg_destroy'],
  'native_effects': False,
  'return_u32': '0x80000000',
  'visits': 93,
  'voucher_model': 'absent'},
 {'case': 'parser_status_7fffffff',
  'cleanup': ['_mach_msg_destroy'],
  'native_effects': False,
  'return_u32': '0x7fffffff',
  'visits': 93,
  'voucher_model': 'absent'},
 {'case': 'complex_reply',
  'cleanup': ['_mach_msg_destroy'],
  'native_effects': False,
  'return_u32': '0xfffffed4',
  'visits': 86,
  'voucher_model': 'absent'},
 {'case': 'short_size',
  'cleanup': ['_mach_msg_destroy'],
  'native_effects': False,
  'return_u32': '0xfffffed4',
  'visits': 89,
  'voucher_model': 'absent'},
 {'case': 'long_size',
  'cleanup': ['_mach_msg_destroy'],
  'native_effects': False,
  'return_u32': '0xfffffed4',
  'visits': 89,
  'voucher_model': 'absent'},
 {'case': 'nonzero_remote',
  'cleanup': ['_mach_msg_destroy'],
  'native_effects': False,
  'return_u32': '0xfffffed4',
  'visits': 91,
  'voucher_model': 'absent'},
 {'case': 'server_died_id',
  'cleanup': ['_mach_msg_destroy'],
  'native_effects': False,
  'return_u32': '0xfffffecc',
  'visits': 83,
  'voucher_model': 'absent'},
 {'case': 'wrong_reply_id',
  'cleanup': ['_mach_msg_destroy'],
  'native_effects': False,
  'return_u32': '0xfffffed3',
  'visits': 84,
  'voucher_model': 'absent'},
 {'case': 'NDR_changed',
  'cleanup': ['_mach_msg_destroy'],
  'native_effects': False,
  'return_u32': '0xffff5b37',
  'visits': 93,
  'voucher_model': 'absent'},
 {'case': 'local_reserved_changed',
  'cleanup': ['_mach_msg_destroy'],
  'native_effects': False,
  'return_u32': '0xffff5b37',
  'visits': 93,
  'voucher_model': 'absent'},
 {'case': 'wire_scalar_bytes',
  'cleanup': ['_mach_msg_destroy'],
  'native_effects': False,
  'return_u32': '0xffff5b37',
  'visits': 93,
  'voucher_model': 'absent'},
 {'case': 'zero_reply_name',
  'cleanup': ['_mach_msg_destroy'],
  'native_effects': False,
  'return_u32': '0xffff5b37',
  'visits': 93,
  'voucher_model': 'absent'},
 {'case': 'max_names',
  'cleanup': ['_mach_msg_destroy'],
  'native_effects': False,
  'return_u32': '0xffff5b37',
  'visits': 93,
  'voucher_model': 'absent'},
 {'case': 'voucher_noop',
  'cleanup': ['_mach_msg_destroy'],
  'native_effects': False,
  'return_u32': '0xffff5b37',
  'visits': 100,
  'voucher_model': 'noop'},
 {'case': 'voucher_header_write',
  'cleanup': ['_mach_msg_destroy'],
  'native_effects': False,
  'return_u32': '0xffff5b37',
  'visits': 100,
  'voucher_model': 'header_write'},
 {'case': 'transport_0x10000002',
  'cleanup': ['_mig_put_reply_port'],
  'native_effects': False,
  'return_u32': '0x10000002',
  'visits': 83,
  'voucher_model': 'absent'},
 {'case': 'transport_0x10000003',
  'cleanup': ['_mig_put_reply_port'],
  'native_effects': False,
  'return_u32': '0x10000003',
  'visits': 83,
  'voucher_model': 'absent'},
 {'case': 'transport_0x10000010',
  'cleanup': ['_mig_put_reply_port'],
  'native_effects': False,
  'return_u32': '0x10000010',
  'visits': 83,
  'voucher_model': 'absent'},
 {'case': 'transport_0x1',
  'cleanup': ['_mig_dealloc_reply_port'],
  'native_effects': False,
  'return_u32': '0x1',
  'visits': 79,
  'voucher_model': 'absent'},
 {'case': 'transport_0x4',
  'cleanup': ['_mig_dealloc_reply_port'],
  'native_effects': False,
  'return_u32': '0x4',
  'visits': 79,
  'voucher_model': 'absent'},
 {'case': 'transport_0x10000001',
  'cleanup': ['_mig_dealloc_reply_port'],
  'native_effects': False,
  'return_u32': '0x10000001',
  'visits': 79,
  'voucher_model': 'absent'},
 {'case': 'transport_0x10000004',
  'cleanup': ['_mig_dealloc_reply_port'],
  'native_effects': False,
  'return_u32': '0x10000004',
  'visits': 84,
  'voucher_model': 'absent'},
 {'case': 'transport_0x10004003',
  'cleanup': ['_mig_dealloc_reply_port'],
  'native_effects': False,
  'return_u32': '0x10004003',
  'visits': 79,
  'voucher_model': 'absent'}]
PROOFS={'independently_source_lifted_queries_unsat': 1,
 'put_reply_port_results': ['0x10000002', '0x10000003', '0x10000010'],
 'retained_queries_unsat': 1}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest()==BASELINE_MANIFEST_SHA
    previous,current=json.loads(raw),json.loads(read(BASE/MANIFEST))
    old={r['path']:r for r in previous['files']};new={r['path']:r for r in current['files']}
    assert len(old)==len(previous['files'])==8234 and len(new)==len(current['files'])==8241
    assert not old.keys()-new.keys()and new.keys()-old.keys()==ADDED
    assert {p for p in old if old[p]!=new[p]}==CHANGED
    assert current['inputs_preserved']==previous['inputs_preserved']
    for row in current['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==new[p]['sha256']and size(BASE/p)==new[p]['size_bytes']
    report=read(BASE/'fpsd1201_client_report.md')
    assert all(f'| CL{i} |'in report for i in range(1,9))and all(f'**QG{i}**'in report for i in range(1,8))
    e=json.loads(read(ROOT/'fpsd1201_client_checks.json'))
    assert e['verified_counts']==COUNTS and sha(ROOT/'recover_fpsd1201_client.py')==e['generator_sha256']
    for n,h in e['dependencies'].items():assert sha(ROOT/n)==h
    assert not any(e[k]for k in ['native_target_executed','IDB_edit_operations_requested','full_goal_complete'])
    receipt=json.loads(read(ROOT/'fpsd1201_client_audit.json'))
    assert receipt['fresh_replay_completed']and receipt['process_exit_code']==0 and not receipt['native_target_executed']
    assert receipt['auditor_sha256']==sha(ROOT/'audit_fpsd1201_client.py')and receipt['checks_sha256']==sha(ROOT/'fpsd1201_client_checks.json')
    assert receipt['IDA_SDK_readback_sha256']==sha(ROOT/'fpsd1201_client_ida_readback.json')and receipt['dependencies']==e['dependencies']
    r=receipt['result'];assert r['all_checks_pass']and r['profiles']==27
    assert r['client_fresh_replay']==CLIENT_REPLAY and r['joined_server']==SERVER_JOIN and r['source_lift']==PROOFS and r['cases']==CASES
    assert not r['native_target_executed']and not r['full_goal_complete']
    assert r['fresh_CoreFP_IDA_spans']==9 and r['fresh_CoreFP_IDA_bytes']==524 and r['SDK_headers_checked']==4 and r['original_CoreFP_pointer_words_decoded']==11
    assert [p['configuration']['label']for p in e['profiles']]==[p['case']for p in CASES]
    assert [len(p['source_visits'])for p in e['profiles']]==[p['visits']for p in CASES]
    assert [hex(p['return_u32'])for p in e['profiles']]==[p['return_u32']for p in CASES]
    att=json.loads(read(ROOT/'fpsd1201_client_ida_readback.json'))
    assert not att['IDB_mutated']and not att['native_target_executed']and att['input_sha256']==e['reference_universal_sha256']=='68d2f0a29c63b442f60622f539357db91d4e2a4b1d775e136c40fd8effc5aa2f'
    assert len(att['spans'])==9 and sum(s['size_B']for s in att['spans'])==524
    assert att['builder_xrefs']==[{'from':'0x1d03f08','type':1,'code':False}]
    assert len(att['SDK_context']['headers'])==4 and att['SDK_context']['compile_only']['exit_code']==0
    assert current['validation']['fpsd1201_client_increment_checks']==COUNTS and current['validation']['fpsd1201_client_static_scope']==e['scope']
    assert current['validation']['reports']==previous['validation']['reports']+1==421
    assert current['validation']['unavailable_external_primary_references']==previous['validation']['unavailable_external_primary_references']
    assert current['goal_status']=='active'and len(OWNED)==17
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        if p=='triage_evidence/fpsd1201_client_checks.json.zst':path_hygiene(json.dumps(paths_in_typed_payloads(e)).encode())
        else:path_hygiene(read(BASE/(p[:-4]if p.endswith('.zst')else p)).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    print(json.dumps({'unchanged_manifest_entries':len(old)-len(CHANGED),'owned_physical_files':len(OWNED),
      'original_inputs_preserved':3,'reports':421,'client_profiles':27,'pinned_fresh_client_visits':2389,
      'pinned_fresh_server_visits':480680,'publication_does_not_replay_instructions':True,
      'native_target_executed':False,'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
