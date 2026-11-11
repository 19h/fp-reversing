#!/usr/bin/env python3
"""Exact owned delta, source/ABI replay, compressed storage and path audit.

O(owned artifact bytes + manifest entries + bounded private visits) time;
space bounded by the loaded evidence/private image. No native IPC executes.
"""
from hashlib import sha256
import json
from pathlib import Path
import subprocess
from compression import zstd
from audit_fpsd1200_contract import audit
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene

ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='abeb6fe7cea2fa088b47f63c345bf59ca42756a9'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'corefp_exports_report.md','daemon_receive_interface_report.md','mach_ports_report.md',
 'foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md',
 'obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'fpsd1200_contract_report.md','triage_evidence/recover_fpsd1200_contract.py',
 'triage_evidence/audit_fpsd1200_contract.py','triage_evidence/verify_fpsd1200_contract_publication.py',
 'triage_evidence/fpsd1200_ida_readback.json','triage_evidence/fpsd1200_contract_checks.json'}
ARCHIVES={MANIFEST,'triage_evidence/fpsd1200_ida_readback.json','triage_evidence/fpsd1200_contract_checks.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'bank_uses':6,'bank_inputs':1536,'format12_words':15,'server_cases':13,'client_cases':22,
 'server_source_visits':3025,'client_source_visits':522}
FINITE={'server_cases':13,'client_cases':22,'application_entries':6,'successful_fixture_replies':4,
 'full_payload104_comparisons':6,'request_guard_cases':7,'bank_inputs':1536,'original_fixup_words':15,
 'source_IDA_range_comparisons':11,'all_checks_pass':True}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest()=='2419ca9e67a62fa451bfa6be2cef306c6cb1627a73488569badc4ebe99486842'
    previous,current=json.loads(raw),json.loads(read(BASE/MANIFEST))
    old={r['path']:r for r in previous['files']};new={r['path']:r for r in current['files']}
    assert len(old)==len(previous['files'])==8141 and len(new)==len(current['files'])==8147
    assert not old.keys()-new.keys()and new.keys()-old.keys()==ADDED
    assert {p for p in old if old[p]!=new[p]}==CHANGED
    assert current['inputs_preserved']==previous['inputs_preserved']
    for r in current['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==new[p]['sha256']and size(BASE/p)==new[p]['size_bytes']
    report=read(BASE/'fpsd1200_contract_report.md')
    assert all(f'| FC{i} |'in report for i in range(1,9))and all(f'**QG{i}**'in report for i in range(1,8))
    e=json.loads(read(ROOT/'fpsd1200_contract_checks.json'))
    assert e['verified_counts']==COUNTS and e['source_attestation']=={
      'daemon_live_ranges_match_original':7,'CoreFP_live_ranges_match_retained_original':4,
      'installed_CoreFP_sha256_observed':'94e00fac067f28543a969b14f1d463e623e624b32cae1a9367e14131e64f99cb','installed_CoreFP_matches_reference':False}
    assert e['new_IDA_access']and not any(e[k]for k in ['new_IDB_mutations','new_native_execution','protected_core_executed','full_goal_complete'])
    finite=audit();assert finite==FINITE
    assert current['validation']['fpsd1200_contract_increment_checks']==COUNTS
    assert current['validation']['fpsd1200_contract_static_scope']==e['scope']
    assert current['validation']['reports']==previous['validation']['reports']+1==407
    assert current['validation']['unavailable_external_primary_references']==previous['validation']['unavailable_external_primary_references']
    assert current['goal_status']=='active'and len(OWNED)==15
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:path_hygiene((BASE/p).read_bytes())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    print(json.dumps({'unchanged_manifest_entries':len(old)-len(CHANGED),'owned_physical_files':len(OWNED),
      'original_inputs_preserved':3,'independent_audit':finite,'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
