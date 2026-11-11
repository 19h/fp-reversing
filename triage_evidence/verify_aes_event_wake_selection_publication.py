#!/usr/bin/env python3
"""Read-only exact source, certificate, private interpretation and delivery audit.

O(source+owned bytes+private visits) time/space; SMT cost separate. No target,
native scheduler, atomic, IPC or IDB operation executes.
"""
from hashlib import sha256
import json
from pathlib import Path
import subprocess
from compression import zstd
import z3
from kernel_native_reader import Kernel
from audit_aes_event_wake_selection import audit
from verify_daemon_reader_record_payloads_publication import read, sha, size
from verify_lskd_vector_origin_publication import path_hygiene

ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='b718610befd43a448e412e379a83cfd210b2c08e'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'aes_event_registration_report.md','event_wait_table_report.md','foundational_triage_report.md','interface_abi_report.md',
 'interface_investigation_status.md','obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'aes_event_wake_selection_report.md','triage_evidence/recover_aes_event_wake_selection.py',
 'triage_evidence/aes_event_wake_selection_checks.json','triage_evidence/audit_aes_event_wake_selection.py',
 'triage_evidence/verify_aes_event_wake_selection_publication.py'}
ARCHIVES={MANIFEST,'triage_evidence/aes_event_wake_selection_checks.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'queries_unsat':20,'controls_sat':3,'source_pieces':13,'source_lifted_instances':39,'spans':7,'instructions':878,'code_B':3512}
FINITE={'complete_wake_cases':1152,'selector_limit_cases':64,'summary_miss_cases':352,'summary_false_positive_cases':464,
 'immediate_scheduler_models':208,'deferred_scheduler_models':208,'source_instruction_visits':287461,'foreign_identity_cases':32,'all_checks_pass':True}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def check(query,expected):
    solver=z3.Solver();solver.set(timeout=15000);solver.from_string(query);result=solver.check()
    assert result==expected,(str(result),solver.reason_unknown())


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest()=='46ded750587a9c33b2d96ba71c0f378d6c4a94b9a4a2360c98b3c8fe04c0ac06'
    previous,current=json.loads(raw),json.loads(read(BASE/MANIFEST))
    old={r['path']:r for r in previous['files']};new={r['path']:r for r in current['files']}
    assert len(old)==len(previous['files'])==8111 and len(new)==len(current['files'])==8116
    assert not old.keys()-new.keys()and new.keys()-old.keys()==ADDED
    assert {p for p in old if old[p]!=new[p]}==CHANGED and current['inputs_preserved']==previous['inputs_preserved']
    for r in current['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==new[p]['sha256']and size(BASE/p)==new[p]['size_bytes']
    report=read(BASE/'aes_event_wake_selection_report.md')
    assert all(f'| WS{i} |'in report for i in range(1,8))and all(f'**QG{i}**'in report for i in range(1,8))
    e=json.loads(read(ROOT/'aes_event_wake_selection_checks.json'))
    assert e['generator_sha256']==sha(ROOT/'recover_aes_event_wake_selection.py')and e['verified_counts']==COUNTS
    for p,digest in e['dependencies'].items():assert sha(ROOT/p)==digest
    assert len(e['proofs'])==20 and len(e['negative_controls'])==3
    assert len(e['source_pieces'])==13 and sum(r['instructions']for r in e['source_pieces'].values())==39
    for r in e['proofs'].values():assert r['result']=='unsat';check(r['query'],z3.unsat)
    for r in e['negative_controls'].values():assert r['result']=='sat';check(r['query'],z3.sat)
    prior=json.loads(read(ROOT/'aes_event_registration_checks.json'));assert len(prior['proofs'])==47
    for r in prior['proofs'].values():assert r['result']=='unsat';check(r['query'],z3.unsat)
    k=Kernel();assert e['kernel_collection_sha256']==k.sha256;code={}
    spans={r['label']:r for r in e['spans']};assert len(spans)==7 and sum(len(r['instructions'])for r in spans.values())==878
    for r in spans.values():
        f=k.function(int(r['start'],16))
        assert(f['end'],f['bytes'],f['sha256'],f['instructions'])==(r['end'],r['bytes_hex'],r['sha256'],r['instructions'])
        code.update({int(i['ea'],16):i for i in r['instructions']})
    assert k.symbols([int(r['start'],16)for r in spans.values()])==e['exact_symbols']and all(not v for v in e['exact_symbols'].values())
    for r in prior['spans']:
        matched=[s for s in spans.values()if s['start']==r['start']]
        if matched:assert matched[0]['bytes_hex']==r['bytes_hex']and matched[0]['sha256']==r['sha256']
    receiver=json.loads(read(ROOT/'kernel_waitq_receiver_source.json'))
    for label in ['select','fifo','stage']:
        r=spans[label];f=next(f for f in receiver['functions']if f['start']==r['start'])
        assert f['bytes']==r['bytes_hex']and f['end']==r['end']
    def at(a,m,o):assert(code[a]['mnemonic'],code[a]['operands'])==(m,o),(hex(a),code[a])
    for a,m,o in [
      (0xfffffe000bd6bcec,'mov','x28, x25'),(0xfffffe000bd6bd88,'mov','x28, x19'),
      (0xfffffe000bd6bec4,'orr','w8, w8, w28, lsl #5'),(0xfffffe000bd6bec8,'str','w8, [x24]'),
      (0xfffffe000bd6c7e0,'bl','#0xfffffe000bd6ce44'),(0xfffffe000bd6c830,'tst','w9, w8, lsr #5'),
      (0xfffffe000bd6c834,'b.ne','#0xfffffe000bd6c7e4'),(0xfffffe000bd6c884,'b.hs','#0xfffffe000bd6c7e4'),
      (0xfffffe000bd6c888,'bfi','w8, w0, #5, #0x1b'),(0xfffffe000bd6c9a8,'and','w8, w8, #0x1f'),
      (0xfffffe000bd6ce9c,'cmp','x8, x21'),(0xfffffe000bd6ceac,'cmp','x9, x10'),
      (0xfffffe000bd6cf1c,'stp','xzr, xzr, [x1]'),(0xfffffe000bd6cf28,'bl','#0xfffffe000bd6cbcc'),
      (0xfffffe000bd6cf48,'tbnz','w8, #5, #0xfffffe000bd6ce80'),(0xfffffe000bd6cf70,'strb','w8, [x19, #0x15]'),
      (0xfffffe000bd6cc40,'tbnz','w9, #0, #0xfffffe000bd6cc90'),(0xfffffe000bd6cc44,'tbz','w8, #2, #0xfffffe000bd6cc90'),
      (0xfffffe000bd6cc78,'bl','#0xfffffe000bd26ba8'),(0xfffffe000bd6bb84,'bl','#0xfffffe000bd26ba8'),
      (0xfffffe000bd6c618,'bl','#0xfffffe000bd0ab18'),(0xfffffe000bd6c63c,'bl','#0xfffffe000bd6bad0')]:at(a,m,o)
    finite=audit();assert finite==FINITE
    assert current['validation']['aes_event_wake_selection_increment_checks']==COUNTS
    assert current['validation']['aes_event_wake_selection_static_scope']==e['scope']
    assert current['validation']['reports']==previous['validation']['reports']+1==401
    assert current['validation']['unavailable_external_primary_references']==previous['validation']['unavailable_external_primary_references']
    assert current['goal_status']=='active'and not any(e[n]for n in ['new_IDA_access','new_native_execution','new_IDB_mutations','full_goal_complete'])
    assert len(OWNED)==13
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:path_hygiene((BASE/p).read_bytes())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    print(json.dumps({'unchanged_manifest_entries':len(old)-len(CHANGED),'owned_physical_files':len(OWNED),
      'original_inputs_preserved':3,'new_UNSAT_queries_rechecked':20,'prior_UNSAT_queries_rechecked':47,'SAT_controls_rechecked':3,
      'independent_interpretation':finite,'analyst_path_literals_absent':True,'all_checks_pass':True}),flush=True)


if __name__=='__main__':main()
