#!/usr/bin/env python3
"""Exact source, private interpretation and owned publication delta audit.

O(source+owned bytes+private visits) time/space; SMT cost separate. No native
scheduler, queue, atomic, interrupt, IPC or IDB operation executes.
"""
from hashlib import sha256
import json
from pathlib import Path
import subprocess
from compression import zstd
import z3
from kernel_native_reader import Kernel
from audit_aes_runqueue_membership import audit
from verify_daemon_reader_record_payloads_publication import read, sha, size
from verify_lskd_vector_origin_publication import path_hygiene

ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='a9211b3f17aeefb41ecd9ec72db64c42e2e93251'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'aes_block_wake_handshake_report.md','kernel_waitq_receiver_report.md',
 'foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md',
 'obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'aes_runqueue_membership_report.md','triage_evidence/recover_aes_runqueue_membership.py',
 'triage_evidence/aes_runqueue_membership_checks.json','triage_evidence/audit_aes_runqueue_membership.py',
 'triage_evidence/verify_aes_runqueue_membership_publication.py'}
ARCHIVES={MANIFEST,'triage_evidence/aes_runqueue_membership_checks.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'queries_unsat':24,'controls_sat':3,'source_pieces':16,'source_lifted_instances':72,
 'spans':4,'instructions':1556,'code_B':6224}
FINITE={'complete_enqueue_cases':4096,'zero_return_insertions':3064,'reciprocity_rejections':2,
 'generic_class_suffix_cases':12,'invalid_class_frontiers':2,'record_layout_cases':18,
 'complete_bound_placement_cases':12,'source_instruction_visits':133006,'all_checks_pass':True}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def check(query,expected):
    solver=z3.Solver();solver.set(timeout=15000);solver.from_string(query);result=solver.check()
    assert result==expected,(str(result),solver.reason_unknown())


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest()=='e6ce843b607b243c4f137762c3f245442e7095d092aec1374135a51e089c8d4d'
    previous,current=json.loads(raw),json.loads(read(BASE/MANIFEST))
    old={r['path']:r for r in previous['files']};new={r['path']:r for r in current['files']}
    assert len(old)==len(previous['files'])==8121 and len(new)==len(current['files'])==8126
    assert not old.keys()-new.keys()and new.keys()-old.keys()==ADDED
    assert {p for p in old if old[p]!=new[p]}==CHANGED and current['inputs_preserved']==previous['inputs_preserved']
    for r in current['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==new[p]['sha256']and size(BASE/p)==new[p]['size_bytes']
    report=read(BASE/'aes_runqueue_membership_report.md')
    assert all(f'| RQ{i} |'in report for i in range(1,9))and all(f'**QG{i}**'in report for i in range(1,8))
    e=json.loads(read(ROOT/'aes_runqueue_membership_checks.json'))
    assert e['generator_sha256']==sha(ROOT/'recover_aes_runqueue_membership.py')and e['verified_counts']==COUNTS
    for p,digest in e['dependencies'].items():assert sha(ROOT/p)==digest
    assert len(e['proofs'])==24 and len(e['negative_controls'])==3
    assert len(e['source_pieces'])==16 and sum(r['instructions']for r in e['source_pieces'].values())==72
    for r in e['proofs'].values():assert r['result']=='unsat';check(r['query'],z3.unsat)
    for r in e['negative_controls'].values():assert r['result']=='sat';check(r['query'],z3.sat)
    priors=[json.loads(read(ROOT/p))for p in ['aes_block_wake_handshake_checks.json','aes_event_wake_selection_checks.json']]
    assert[len(p['proofs'])for p in priors]==[34,20]
    for prior in priors:
        for r in prior['proofs'].values():assert r['result']=='unsat';check(r['query'],z3.unsat)
    k=Kernel();assert e['kernel_collection_sha256']==k.sha256;code={};spans=e['spans']
    assert len(spans)==4 and sum(len(r['instructions'])for r in spans)==1556
    seen={}
    for r in spans+[s for p in priors for s in p['spans']]:
        start=int(r['start'],16)
        if start in seen:assert seen[start]==r['bytes_hex'];continue
        f=k.function(start)
        assert(f['end'],f['bytes'],f['sha256'],f['instructions'])==(r['end'],r['bytes_hex'],r['sha256'],r['instructions'])
        seen[start]=r['bytes_hex']
        code.update({int(i['ea'],16):i for i in r['instructions']})
    assert k.symbols(int(r['start'],16)for r in spans)==e['exact_symbols']and all(not v for v in e['exact_symbols'].values())
    def at(a,m,o):assert(code[a]['mnemonic'],code[a]['operands'])==(m,o),(hex(a),code[a])
    for a,m,o in [
      (0xfffffe000bd20818,'str','x19, [x20, #0x20]'),(0xfffffe000bd20820,'cbz','x8, #0xfffffe000bd20854'),
      (0xfffffe000bd20850,'b','#0xfffffe000bd2d5cc'),(0xfffffe000bd209d8,'bl','#0xfffffe000bd2d5cc'),
      (0xfffffe000bd2d5d4,'ldrsh','x12, [x1, #0x214]'),(0xfffffe000bd2d5ec,'tbnz','w2, #0, #0xfffffe000bd2d650'),
      (0xfffffe000bd2d604,'str','x1, [x11, x12, lsl #3]'),(0xfffffe000bd2d60c,'stp','x1, x1, [x1]'),
      (0xfffffe000bd2d640,'b.ge','#0xfffffe000bd2d668'),(0xfffffe000bd2d658,'stp','x10, x8, [x1]'),
      (0xfffffe000bd2d690,'str','w8, [x0, #0x1c]'),(0xfffffe000bd2d69c,'str','w8, [x0, #0x18]'),
      (0xfffffe000bd2d6a0,'mov','x0, x9'),(0xfffffe000bd21778,'ands','x8, x9, x8'),
      (0xfffffe000bd2177c,'b.eq','#0xfffffe000bd21984'),(0xfffffe000bd27644,'bl','#0xfffffe000bd207c4'),
      (0xfffffe000bd27650,'bl','#0xfffffe000bd2173c'),(0xfffffe000bd2781c,'b','#0xfffffe000bd0b348')]:at(a,m,o)
    for j in range(6):
        at(0xfffffe000bd208c0+12*j,'add',('x9'if j==5 else'x8')+', x26, #'+hex(0xae8+2*j))
    finite=audit();assert finite==FINITE
    assert current['validation']['aes_runqueue_membership_increment_checks']==COUNTS
    assert current['validation']['aes_runqueue_membership_static_scope']==e['scope']
    assert current['validation']['reports']==previous['validation']['reports']+1==403
    assert current['validation']['unavailable_external_primary_references']==previous['validation']['unavailable_external_primary_references']
    assert current['goal_status']=='active'and not any(e[n]for n in ['new_IDA_access','new_native_execution','new_IDB_mutations','full_goal_complete'])
    assert len(OWNED)==13
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:path_hygiene((BASE/p).read_bytes())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    print(json.dumps({'unchanged_manifest_entries':len(old)-len(CHANGED),'owned_physical_files':len(OWNED),
      'original_inputs_preserved':3,'new_UNSAT_queries_rechecked':24,'prior_UNSAT_queries_rechecked':54,'SAT_controls_rechecked':3,
      'independent_interpretation':finite,'analyst_path_literals_absent':True,'all_checks_pass':True}),flush=True)


if __name__=='__main__':main()
