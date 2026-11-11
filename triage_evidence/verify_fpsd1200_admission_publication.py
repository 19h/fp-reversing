#!/usr/bin/env python3
"""Verify the owned publication delta, source replay, archives and path hygiene.

O(owned bytes + manifest entries + bounded replay visits) time; memory bounded
by loaded evidence and the private image. No native target or IPC executes.
"""
from hashlib import sha256
import json
from pathlib import Path
import subprocess
from compression import zstd
from audit_fpsd1200_admission import audit
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene

ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='eef3a43bdf9840fdf9f72e528b3d70383a651b45'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'fpsd1200_contract_report.md','daemon_receive_interface_report.md','mach_ports_report.md',
 'foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md',
 'obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'fpsd1200_admission_report.md','triage_evidence/recover_fpsd1200_admission.py',
 'triage_evidence/audit_fpsd1200_admission.py','triage_evidence/verify_fpsd1200_admission_publication.py',
 'triage_evidence/fpsd1200_admission_checks.json','triage_evidence/fpsd1200_admission_ida_readback.json'}
ARCHIVES={MANIFEST,'triage_evidence/fpsd1200_admission_checks.json','triage_evidence/fpsd1200_admission_ida_readback.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'profiles':27,'returned_error_replies':16,'audit_PID_boundaries':11,'source_spans':51,
 'source_instructions':4346,'source_visits':108443,'copy_calls':200,'format12_rebases':182,
 'format12_bindings':21,'queries_unsat':8,'controls_sat':2,'bank_identities':17,'bank_inputs':4352,
 'bank_pair_uses':2296,'unpaired_byte_bank_reads':864}
FINITE={'profiles':27,'returned_error_replies':16,'audit_PID_boundaries':11,'source_visits':108443,
 'import_events':405,'GP_SP_NZCV_checkpoints':513,'original_copy_calls':200,
 'terminal_stack_private_bytes_checked':15925248,'queries_unsat':8,'controls_sat':2,
 'bank_identities':17,'bank_inputs':4352,'bank_pair_uses':2296,'unpaired_byte_bank_reads':864,'all_checks_pass':True}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest()=='37f94da7901efe90b0734ede1910cb8ba34521581a30d281f6c25eb2cbb99ba9'
    previous,current=json.loads(raw),json.loads(read(BASE/MANIFEST))
    old={r['path']:r for r in previous['files']};new={r['path']:r for r in current['files']}
    assert len(old)==len(previous['files'])==8147 and len(new)==len(current['files'])==8153
    assert not old.keys()-new.keys()and new.keys()-old.keys()==ADDED
    assert {p for p in old if old[p]!=new[p]}==CHANGED
    assert current['inputs_preserved']==previous['inputs_preserved']
    for r in current['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==new[p]['sha256']and size(BASE/p)==new[p]['size_bytes']
    report=read(BASE/'fpsd1200_admission_report.md')
    assert all(f'| FA{i} |'in report for i in range(1,9))and all(f'**QG{i}**'in report for i in range(1,8))
    e=json.loads(read(ROOT/'fpsd1200_admission_checks.json'))
    assert e['verified_counts']==COUNTS and sha(ROOT/'recover_fpsd1200_admission.py')==e['generator_sha256']
    for n,h in e['dependencies'].items():assert sha(ROOT/n)==h
    att=json.loads(read(ROOT/'fpsd1200_admission_ida_readback.json'))
    assert att['input_sha256']=='4c91eccb3c7e2dd39360986544afbf29f5a32dc638c760173cc1676b965be5a7'
    assert att['image_base']=='0x100000000'and len(att['spans'])==51
    assert att['spans']==[{'start':r['start'],'size_B':int(r['end'],16)-int(r['start'],16),'sha256':r['sha256']}for r in e['spans']]
    sdk=Path(subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip())
    header=(sdk/'System/Library/Frameworks/Security.framework/Headers/SecTask.h').read_bytes()
    assert sha256(header).hexdigest()==e['SDK_context']['sha256']=='f10e7bc0490568fef3e542d10fd0a8b4d0d657f090d5841782e325faecb4bd68'
    assert all(d in header.decode()for d in e['SDK_context']['declarations'])and len(e['SDK_context']['declarations'])==2
    assert e['new_IDA_access']and not any(e[k]for k in ['new_IDB_mutations','new_native_execution','full_goal_complete'])
    finite=audit();assert finite==FINITE
    assert current['validation']['fpsd1200_admission_increment_checks']==COUNTS
    assert current['validation']['fpsd1200_admission_static_scope']==e['scope']
    assert current['validation']['reports']==previous['validation']['reports']+1==408
    assert current['validation']['unavailable_external_primary_references']==previous['validation']['unavailable_external_primary_references']
    assert current['goal_status']=='active'and len(OWNED)==15
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:path_hygiene((BASE/p).read_bytes())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    print(json.dumps({'unchanged_manifest_entries':len(old)-len(CHANGED),'owned_physical_files':len(OWNED),
      'original_inputs_preserved':3,'source_IDA_span_comparisons':51,'SDK_declarations':2,
      'independent_audit':finite,'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
