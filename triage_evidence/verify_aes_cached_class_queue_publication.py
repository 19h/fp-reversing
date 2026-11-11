#!/usr/bin/env python3
"""Exact original-source, private interpretation and publication delta audit.

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
from audit_aes_cached_class_queue import audit
from verify_daemon_reader_record_payloads_publication import read, sha, size
from verify_lskd_vector_origin_publication import path_hygiene

ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='4448f3540de9e9fb4b600e434a407f114f751e3d'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'aes_runqueue_membership_report.md','aes_block_wake_handshake_report.md',
 'kernel_waitq_receiver_report.md','foundational_triage_report.md','interface_abi_report.md',
 'interface_investigation_status.md','obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'aes_cached_class_queue_report.md','triage_evidence/recover_aes_cached_class_queue.py',
 'triage_evidence/aes_cached_class_queue_checks.json','triage_evidence/audit_aes_cached_class_queue.py',
 'triage_evidence/verify_aes_cached_class_queue_publication.py'}
ARCHIVES={MANIFEST,'triage_evidence/aes_cached_class_queue_checks.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'queries_unsat':30,'controls_sat':4,'source_pieces':21,'source_lifted_instances':100,
 'spans':8,'instructions':1372,'code_B':5488}
FINITE={'initializer_canvases':9,'paired_constructor_canvases':6,'constructor_cached_backend_cases':1152,
 'deadline_heap_compositions':320,'heap_merge_canvases':288,'heap_null_identity_cases':6,
 'cached_priority_summary_cases':256,'source_instruction_visits':900921,'all_checks_pass':True}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def check(query,expected):
    solver=z3.Solver();solver.set(timeout=15000);solver.from_string(query);result=solver.check()
    assert result==expected,(str(result),solver.reason_unknown())


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest()=='df93064e48c59f08a5a017c3d05a069e5868258ce2851405b777f49f60768cdb'
    previous,current=json.loads(raw),json.loads(read(BASE/MANIFEST))
    old={r['path']:r for r in previous['files']};new={r['path']:r for r in current['files']}
    assert len(old)==len(previous['files'])==8126 and len(new)==len(current['files'])==8131
    assert not old.keys()-new.keys()and new.keys()-old.keys()==ADDED
    assert {p for p in old if old[p]!=new[p]}==CHANGED and current['inputs_preserved']==previous['inputs_preserved']
    for r in current['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==new[p]['sha256']and size(BASE/p)==new[p]['size_bytes']
    report=read(BASE/'aes_cached_class_queue_report.md')
    assert all(f'| CQ{i} |'in report for i in range(1,9))and all(f'**QG{i}**'in report for i in range(1,8))
    e=json.loads(read(ROOT/'aes_cached_class_queue_checks.json'))
    assert e['generator_sha256']==sha(ROOT/'recover_aes_cached_class_queue.py')and e['verified_counts']==COUNTS
    for p,digest in e['dependencies'].items():assert sha(ROOT/p)==digest
    assert len(e['proofs'])==30 and len(e['negative_controls'])==4
    assert len(e['source_pieces'])==21 and sum(r['instructions']for r in e['source_pieces'].values())==100
    assert len(e['initializer_stores'])==51
    covered={j for s in e['initializer_stores']for j in range(s['offset_B'],s['offset_B']+s['size_B'])}
    assert covered==set(range(4))|set(range(8,0x320))and len(covered)==796
    for r in e['proofs'].values():assert r['result']=='unsat';check(r['query'],z3.unsat)
    for r in e['negative_controls'].values():assert r['result']=='sat';check(r['query'],z3.sat)
    priors=[json.loads(read(ROOT/p))for p in ['aes_runqueue_membership_checks.json','aes_block_wake_handshake_checks.json']]
    assert[len(p['proofs'])for p in priors]==[24,34]
    for prior in priors:
        for r in prior['proofs'].values():assert r['result']=='unsat';check(r['query'],z3.unsat)
    extra=json.loads(read(ROOT/'aes_event_wake_selection_checks.json'))
    k=Kernel();assert e['kernel_collection_sha256']==k.sha256;code={};spans=e['spans']
    assert len(spans)==8 and sum(len(r['instructions'])for r in spans)==1372
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
      (0xfffffe000bd17508,'b.eq','#0xfffffe000bd17514'),(0xfffffe000bd17510,'bl','#0xfffffe000bd2d3cc'),
      (0xfffffe000c63a9c8,'bl','#0xfffffe000bd2d3cc'),(0xfffffe000bd21418,'bl','#0xfffffe000bd2d3cc'),
      (0xfffffe000bd21444,'cmp','x19, #6'),(0xfffffe000bd21448,'b.ne','#0xfffffe000bd21370'),
      (0xfffffe000bd2d440,'stp','q0, q0, [x0, #0x300]'),(0xfffffe000bd2d444,'ret',''),
      (0xfffffe000bd209d8,'bl','#0xfffffe000bd2d5cc'),(0xfffffe000bd209e0,'strb','w8, [x20, #0x50]'),
      (0xfffffe000bd20a94,'bl','#0xfffffe000bd1ee74'),(0xfffffe000bd2102c,'bl','#0xfffffe000c48b7c0'),
      (0xfffffe000bd21030,'str','x0, [x24, x19]'),(0xfffffe000bd21134,'cset','w0, gt'),
      (0xfffffe000bd1ef94,'strh','w8, [x19]'),(0xfffffe000c48b7e4,'csel','x0, x0, x1, lo'),
      (0xfffffe000c48b7f0,'asr','x9, x9, #0x10'),(0xfffffe000c48b810,'bfi','x9, x8, #0x10, #0x30')]:at(a,m,o)
    finite=audit();assert finite==FINITE
    assert current['validation']['aes_cached_class_queue_increment_checks']==COUNTS
    assert current['validation']['aes_cached_class_queue_static_scope']==e['scope']
    assert current['validation']['reports']==previous['validation']['reports']+1==404
    assert current['validation']['unavailable_external_primary_references']==previous['validation']['unavailable_external_primary_references']
    assert current['goal_status']=='active'and not any(e[n]for n in ['new_IDA_access','new_native_execution','new_IDB_mutations','full_goal_complete'])
    assert len(OWNED)==14
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:path_hygiene((BASE/p).read_bytes())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    print(json.dumps({'unchanged_manifest_entries':len(old)-len(CHANGED),'owned_physical_files':len(OWNED),
      'original_inputs_preserved':3,'new_UNSAT_queries_rechecked':30,'prior_UNSAT_queries_rechecked':58,'SAT_controls_rechecked':4,
      'independent_interpretation':finite,'analyst_path_literals_absent':True,'all_checks_pass':True}),flush=True)


if __name__=='__main__':main()
