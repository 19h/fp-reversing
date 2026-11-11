#!/usr/bin/env python3
"""Exact source, private instruction and publication delta audit.

O(source+owned bytes+private visits) time/space; SMT cost separate. No native
queue, scheduler, atomic, clock, IPC or IDB operation executes.
"""
from hashlib import sha256
import json
from pathlib import Path
import subprocess
from compression import zstd
import z3
from kernel_native_reader import Kernel
from audit_aes_uncached_context_queue import audit
from verify_daemon_reader_record_payloads_publication import read, sha, size
from verify_lskd_vector_origin_publication import path_hygiene

ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='a4517ca839593e97e888fe059a331c36cd2b1ff5'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'aes_cached_class_queue_report.md','aes_runqueue_membership_report.md',
 'kernel_waitq_receiver_report.md','foundational_triage_report.md','interface_abi_report.md',
 'interface_investigation_status.md','obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'aes_uncached_context_queue_report.md','triage_evidence/recover_aes_uncached_context_queue.py',
 'triage_evidence/aes_uncached_context_queue_checks.json','triage_evidence/audit_aes_uncached_context_queue.py',
 'triage_evidence/verify_aes_uncached_context_queue_publication.py'}
ARCHIVES={MANIFEST,'triage_evidence/aes_uncached_context_queue_checks.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'queries_unsat':25,'controls_sat':3,'source_pieces':20,'source_lifted_instances':90,
 'spans':11,'instructions':1348,'code_B':5392}
FINITE={'first_context_canvases':1620,'lane_selector_paths':16,'second_thread_canvases':216,
 'context_score_changes':54,'unchanged_score_returns':162,
 'source_instruction_visits':1941220,'atomic_observations':8928,'all_checks_pass':True}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def check(query,expected):
    solver=z3.Solver();solver.set(timeout=15000);solver.from_string(query);result=solver.check()
    assert result==expected,(str(result),solver.reason_unknown())


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest()=='4e58b71997778e5ef58f10c923271ff8afe71a787aec5cdeed70ce6217e9ef96'
    previous,current=json.loads(raw),json.loads(read(BASE/MANIFEST))
    old={r['path']:r for r in previous['files']};new={r['path']:r for r in current['files']}
    assert len(old)==len(previous['files'])==8131 and len(new)==len(current['files'])==8136
    assert not old.keys()-new.keys()and new.keys()-old.keys()==ADDED
    assert {p for p in old if old[p]!=new[p]}==CHANGED and current['inputs_preserved']==previous['inputs_preserved']
    for r in current['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==new[p]['sha256']and size(BASE/p)==new[p]['size_bytes']
    report=read(BASE/'aes_uncached_context_queue_report.md')
    assert all(f'| UC{i} |'in report for i in range(1,9))and all(f'**QG{i}**'in report for i in range(1,8))
    e=json.loads(read(ROOT/'aes_uncached_context_queue_checks.json'))
    assert e['generator_sha256']==sha(ROOT/'recover_aes_uncached_context_queue.py')and e['verified_counts']==COUNTS
    for p,digest in e['dependencies'].items():assert sha(ROOT/p)==digest
    assert len(e['proofs'])==25 and len(e['negative_controls'])==3
    assert len(e['source_pieces'])==20 and sum(r['instructions']for r in e['source_pieces'].values())==90
    for r in e['proofs'].values():assert r['result']=='unsat';check(r['query'],z3.unsat)
    for r in e['negative_controls'].values():assert r['result']=='sat';check(r['query'],z3.sat)
    priors=[json.loads(read(ROOT/p))for p in ['aes_cached_class_queue_checks.json','aes_runqueue_membership_checks.json']]
    assert[len(p['proofs'])for p in priors]==[30,24]
    for prior in priors:
        for r in prior['proofs'].values():assert r['result']=='unsat';check(r['query'],z3.unsat)
    extra=json.loads(read(ROOT/'aes_event_wake_selection_checks.json'))
    k=Kernel();assert e['kernel_collection_sha256']==k.sha256;code={};spans=e['spans']
    assert len(spans)==11 and sum(len(r['instructions'])for r in spans)==1348
    seen={}
    for r in spans+[s for p in priors+[extra]for s in p['spans']]:
        start=int(r['start'],16)
        if start in seen:assert seen[start]==r['bytes_hex'];continue
        f=k.function(start)
        assert(f['end'],f['bytes'],f['sha256'],f['instructions'])==(r['end'],r['bytes_hex'],r['sha256'],r['instructions'])
        seen[start]=r['bytes_hex'];code.update({int(i['ea'],16):i for i in r['instructions']})
    assert k.symbols(int(r['start'],16)for r in spans)==e['exact_symbols']and all(not v for v in e['exact_symbols'].values())
    def at(a,m,o):assert(code[a]['mnemonic'],code[a]['operands'])==(m,o),(hex(a),code[a])
    for a,m,o in [
      (0xfffffe000bd20aec,'umull','x9, w9, w10'),(0xfffffe000bd20b24,'add','x21, x8, #0x20'),
      (0xfffffe000bd20b58,'str','xzr, [x25, #0x60]!'),(0xfffffe000bd20c64,'strb','w19, [x24, #0x18]'),
      (0xfffffe000bd20d24,'ldr','x8, [x22]'),(0xfffffe000bd20d28,'ldp','x0, x1, [x8, #0x30]!'),
      (0xfffffe000bd20d40,'casp','x4, x5, x6, x7, [x8]'),(0xfffffe000bd20db4,'b','#0xfffffe000bd1ea3c'),
      (0xfffffe000bd1ea60,'bl','#0xfffffe000bd1ec40'),(0xfffffe000bd1ec04,'bl','#0xfffffe000bd1ee74'),
      (0xfffffe000bd1ecfc,'ldrb','w0, [x10, #0x40]'),(0xfffffe000bd1ee10,'add','w19, w9, w0'),
      (0xfffffe000bd1ee2c,'and','w0, w19, #0xff'),(0xfffffe000bd1ef30,'bl','#0xfffffe000bd1efa8'),
      (0xfffffe000c48bb60,'sxth','x10, w9'),(0xfffffe000c48b454,'csel','x0, x1, x0, gt')]:at(a,m,o)
    finite=audit();assert finite==FINITE
    assert current['validation']['aes_uncached_context_queue_increment_checks']==COUNTS
    assert current['validation']['aes_uncached_context_queue_static_scope']==e['scope']
    assert current['validation']['reports']==previous['validation']['reports']+1==405
    assert current['validation']['unavailable_external_primary_references']==previous['validation']['unavailable_external_primary_references']
    assert current['goal_status']=='active'and not any(e[n]for n in ['new_IDA_access','new_native_execution','new_IDB_mutations','full_goal_complete'])
    assert len(OWNED)==14
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:path_hygiene((BASE/p).read_bytes())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    print(json.dumps({'unchanged_manifest_entries':len(old)-len(CHANGED),'owned_physical_files':len(OWNED),
      'original_inputs_preserved':3,'new_UNSAT_queries_rechecked':25,'prior_UNSAT_queries_rechecked':54,'SAT_controls_rechecked':3,
      'independent_interpretation':finite,'analyst_path_literals_absent':True,'all_checks_pass':True}),flush=True)


if __name__=='__main__':main()
