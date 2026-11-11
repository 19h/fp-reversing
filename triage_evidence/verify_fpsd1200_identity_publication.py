#!/usr/bin/env python3
"""Verify exact owned publication, source/private replay and path hygiene.
O(owned bytes + manifest entries + bounded replay visits) time; bounded private
image/evidence memory. No native target, credential query or IPC executes.
"""
from hashlib import sha256
import json
from pathlib import Path
import subprocess
from compression import zstd
from audit_fpsd1200_identity import audit
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene

ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='0b9f347ef8846f94588cc7cd759ad7ab5798559a'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'fpsd1200_admission_report.md','daemon_receive_interface_report.md','mach_ports_report.md',
 'foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md',
 'obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'fpsd1200_identity_report.md','triage_evidence/recover_fpsd1200_identity.py',
 'triage_evidence/audit_fpsd1200_identity.py','triage_evidence/verify_fpsd1200_identity_publication.py',
 'triage_evidence/fpsd1200_identity_checks.json','triage_evidence/fpsd1200_identity_ida_readback.json'}
ARCHIVES={MANIFEST,'triage_evidence/fpsd1200_identity_checks.json','triage_evidence/fpsd1200_identity_ida_readback.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'profiles':25,'source_spans':78,'source_instructions_including_guards':6468,
 'daemon_visits':137986,'library_visits':475,'library_calls':25,'original_copy_calls':250,
 'unmapped_read_guards':15,'import_boundaries':10,'original_once_callbacks':4,'provider_profiles':10,
 'provider_reads':70,'queries_unsat':5,'format12_rebases':218,'format12_bindings':26,
 'bank_identities':17,'bank_inputs':4352,'bank_pair_uses':2842,'unpaired_byte_bank_reads':800}
FINITE={'profiles':25,'original_instruction_visits':138461,'daemon_visits':137986,'library_visits':475,
 'import_events':564,'admission_checkpoints':425,'identity_checkpoints':311,'original_copy_calls':250,
 'unmapped_read_guards':15,'original_once_callbacks':4,'provider_reads':70,
 'terminal_stack_private_bytes_checked':14745600,'queries_unsat':5,'source_IDA_spans':78,'bank_inputs':4352,'all_checks_pass':True}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest()=='06ec7b07d213af2fcc8287680fa4928c83d2e82e127ed44de2ade0876548176d'
    previous,current=json.loads(raw),json.loads(read(BASE/MANIFEST))
    old={r['path']:r for r in previous['files']};new={r['path']:r for r in current['files']}
    assert len(old)==len(previous['files'])==8153 and len(new)==len(current['files'])==8159
    assert not old.keys()-new.keys()and new.keys()-old.keys()==ADDED
    assert {p for p in old if old[p]!=new[p]}==CHANGED
    assert current['inputs_preserved']==previous['inputs_preserved']
    for r in current['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==new[p]['sha256']and size(BASE/p)==new[p]['size_bytes']
    report=read(BASE/'fpsd1200_identity_report.md')
    assert all(f'| FI{i} |'in report for i in range(1,9))and all(f'**QG{i}**'in report for i in range(1,8))
    e=json.loads(read(ROOT/'fpsd1200_identity_checks.json'))
    assert e['verified_counts']==COUNTS and sha(ROOT/'recover_fpsd1200_identity.py')==e['generator_sha256']
    for n,h in e['dependencies'].items():assert sha(ROOT/n)==h
    assert len(e['unretired_guard_sites'])==3 and len(e['constant_strings'])==3 and len(e['SDK_context'])==3
    assert e['new_IDA_access']and not any(e[k]for k in ['new_IDB_mutations','new_native_execution','full_goal_complete'])
    finite=audit();assert finite==FINITE
    assert current['validation']['fpsd1200_identity_increment_checks']==COUNTS
    assert current['validation']['fpsd1200_identity_static_scope']==e['scope']
    assert current['validation']['reports']==previous['validation']['reports']+1==409
    assert current['validation']['unavailable_external_primary_references']==previous['validation']['unavailable_external_primary_references']
    assert current['goal_status']=='active'and len(OWNED)==15
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:path_hygiene((BASE/p).read_bytes())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    print(json.dumps({'unchanged_manifest_entries':len(old)-len(CHANGED),'owned_physical_files':len(OWNED),
      'original_inputs_preserved':3,'independent_audit':finite,'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
