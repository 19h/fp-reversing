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
from audit_fpsd1200_context import audit
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene

ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='97d6b8343c883b9a83864f669dea3618235256d2'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'fpsd1200_arena_report.md','daemon_receive_interface_report.md','mach_ports_report.md',
 'foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md',
 'obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'fpsd1200_context_report.md','triage_evidence/recover_fpsd1200_context.py',
 'triage_evidence/audit_fpsd1200_context.py','triage_evidence/verify_fpsd1200_context_publication.py',
 'triage_evidence/fpsd1200_context_checks.json','triage_evidence/fpsd1200_context_ida_readback.json'}
ARCHIVES={MANIFEST,'triage_evidence/fpsd1200_context_checks.json','triage_evidence/fpsd1200_context_ida_readback.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={
 "profiles": 19,
 "source_spans": 594,
 "source_instructions_including_guards": 28519,
 "daemon_visits": 7245454,
 "library_visits": 361,
 "original_copy_calls": 190,
 "returned_replies": 5,
 "environment_guards": 3,
 "later_atomic_guards": 5,
 "later_atomic_fixtures": 3,
 "random_fixtures": 16,
 "seed_snapshots": 8,
 "OOL_read_events": 11529,
 "self_text_reads": 3538,
 "startup_owner_reads": 1343,
 "startup_owner_writes": 3995,
 "queries_unsat": 1,
 "format12_rebases": 820,
 "format12_bindings": 29,
 "bank_identities": 17,
 "bank_inputs": 4352,
 "bank_pair_uses": 14344,
 "unpaired_byte_bank_reads": 615
}
FINITE={
 "profiles": 19,
 "original_instruction_visits": 7245815,
 "import_events": 621,
 "admission_checkpoints": 343,
 "source_IDA_spans": 594,
 "seed_words_checked": 4992,
 "OOL_byte_reads_checked": 11529,
 "self_text_reads_checked": 3538,
 "startup_owner_reads_checked": 1343,
 "startup_owner_writes_checked": 3995,
 "terminal_stack_private_heap_bytes_checked": 12451840,
 "queries_unsat": 1,
 "bank_inputs": 4352,
 "all_checks_pass": True
}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest()=='020c4127174379364dca6c3e4b28032ca20d9c393eefe585ef40c77aaa267c32'
    previous,current=json.loads(raw),json.loads(read(BASE/MANIFEST))
    old={r['path']:r for r in previous['files']};new={r['path']:r for r in current['files']}
    assert len(old)==len(previous['files'])==8165 and len(new)==len(current['files'])==8171
    assert not old.keys()-new.keys()and new.keys()-old.keys()==ADDED
    assert {p for p in old if old[p]!=new[p]}==CHANGED
    assert current['inputs_preserved']==previous['inputs_preserved']
    for r in current['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==new[p]['sha256']and size(BASE/p)==new[p]['size_bytes']
    report=read(BASE/'fpsd1200_context_report.md')
    assert all(f'| FX{i} |'in report for i in range(1,9))and all(f'**QG{i}**'in report for i in range(1,8))
    e=json.loads(read(ROOT/'fpsd1200_context_checks.json'))
    assert e['verified_counts']==COUNTS and sha(ROOT/'recover_fpsd1200_context.py')==e['generator_sha256']
    for n,h in e['dependencies'].items():assert sha(ROOT/n)==h
    assert len(e['unretired_guard_sites'])==5 and len(e['proofs'])==1
    assert e['new_IDA_access']and not any(e[k]for k in ['new_IDB_mutations','new_native_execution','full_goal_complete'])
    finite=audit();assert finite==FINITE
    assert current['validation']['fpsd1200_context_increment_checks']==COUNTS
    assert current['validation']['fpsd1200_context_static_scope']==e['scope']
    assert current['validation']['reports']==previous['validation']['reports']+1==411
    assert current['validation']['unavailable_external_primary_references']==previous['validation']['unavailable_external_primary_references']
    assert current['goal_status']=='active'and len(OWNED)==15
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:path_hygiene((BASE/p).read_bytes())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    print(json.dumps({'unchanged_manifest_entries':len(old)-len(CHANGED),'owned_physical_files':len(OWNED),
      'original_inputs_preserved':3,'independent_audit':finite,'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
