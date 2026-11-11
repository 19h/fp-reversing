#!/usr/bin/env python3
"""Exact original-source, private interpretation and publication audit.

O(source+owned bytes+private visits) time/space; SMT cost separate. No native
scheduler, switch, atomic, IPC, clock or IDB operation executes.
"""
from hashlib import sha256
import json
from pathlib import Path
import subprocess
from compression import zstd
import z3
from kernel_native_reader import Kernel
from audit_aes_block_wake_handshake import audit
from verify_daemon_reader_record_payloads_publication import read, sha, size
from verify_lskd_vector_origin_publication import path_hygiene

ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='0c2d7fa48731ace4cd107a828237ed37c6847360'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'aes_event_wake_selection_report.md','aes_event_registration_report.md','kernel_waitq_receiver_report.md',
 'foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md',
 'obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'aes_block_wake_handshake_report.md','triage_evidence/recover_aes_block_wake_handshake.py',
 'triage_evidence/aes_block_wake_handshake_checks.json','triage_evidence/audit_aes_block_wake_handshake.py',
 'triage_evidence/verify_aes_block_wake_handshake_publication.py'}
ARCHIVES={MANIFEST,'triage_evidence/aes_block_wake_handshake_checks.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'queries_unsat':34,'controls_sat':4,'source_pieces':15,'source_lifted_instances':58,'spans':10,'instructions':2651,'code_B':10604}
FINITE={'complete_wake_state_cases':180,'counter_pair_cases':24,'atomic_mismatch_cases':4,'post_switch_wake_order_cases':8,
 'placement_prefix_cases':6,'callback_argument_cases':2,'elapsed_guard_cases':3,'source_instruction_visits':77149,
 'atomic_observations':279,'readonly_owner_models':188,'all_checks_pass':True}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def check(query,expected):
    solver=z3.Solver();solver.set(timeout=15000);solver.from_string(query);result=solver.check()
    assert result==expected,(str(result),solver.reason_unknown())


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest()=='d305c656030048a9857bb83de14efbe1c9c87a825339ceaf6ba6bd3e25941868'
    previous,current=json.loads(raw),json.loads(read(BASE/MANIFEST))
    old={r['path']:r for r in previous['files']};new={r['path']:r for r in current['files']}
    assert len(old)==len(previous['files'])==8116 and len(new)==len(current['files'])==8121
    assert not old.keys()-new.keys()and new.keys()-old.keys()==ADDED
    assert {p for p in old if old[p]!=new[p]}==CHANGED and current['inputs_preserved']==previous['inputs_preserved']
    for r in current['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==new[p]['sha256']and size(BASE/p)==new[p]['size_bytes']
    report=read(BASE/'aes_block_wake_handshake_report.md')
    assert all(f'| BH{i} |'in report for i in range(1,9))and all(f'**QG{i}**'in report for i in range(1,8))
    e=json.loads(read(ROOT/'aes_block_wake_handshake_checks.json'))
    assert e['generator_sha256']==sha(ROOT/'recover_aes_block_wake_handshake.py')and e['verified_counts']==COUNTS
    for p,digest in e['dependencies'].items():assert sha(ROOT/p)==digest
    assert len(e['proofs'])==34 and len(e['negative_controls'])==4
    assert len(e['source_pieces'])==15 and sum(r['instructions']for r in e['source_pieces'].values())==58
    for r in e['proofs'].values():assert r['result']=='unsat';check(r['query'],z3.unsat)
    for r in e['negative_controls'].values():assert r['result']=='sat';check(r['query'],z3.sat)
    priors={p:json.loads(read(ROOT/p))for p in ['aes_event_wake_selection_checks.json','aes_event_registration_checks.json']}
    assert [len(p['proofs'])for p in priors.values()]==[20,47]
    for prior in priors.values():
        for r in prior['proofs'].values():assert r['result']=='unsat';check(r['query'],z3.unsat)
    k=Kernel();assert e['kernel_collection_sha256']==k.sha256;code={};spans={r['label']:r for r in e['spans']}
    assert len(spans)==10 and sum(len(r['instructions'])for r in spans.values())==2651
    for r in spans.values():
        f=k.function(int(r['start'],16))
        assert(f['end'],f['bytes'],f['sha256'],f['instructions'])==(r['end'],r['bytes_hex'],r['sha256'],r['instructions'])
        code.update({int(i['ea'],16):i for i in r['instructions']})
    assert k.symbols(int(r['start'],16)for r in spans.values())==e['exact_symbols']and all(not v for v in e['exact_symbols'].values())
    for prior in priors.values():
        for r in prior['spans']:
            matched=[s for s in spans.values()if s['start']==r['start']]
            if matched:assert matched[0]['bytes_hex']==r['bytes_hex']and matched[0]['sha256']==r['sha256']
    def at(a,m,o):assert(code[a]['mnemonic'],code[a]['operands'])==(m,o),(hex(a),code[a])
    for a,m,o in [
      (0xfffffe000bd26c40,'str','w8, [x19, #0x1f8]'),(0xfffffe000bd26c44,'tbz','w23, #2, #0xfffffe000bd26c58'),
      (0xfffffe000bd26c94,'b.hi','#0xfffffe000bd27024'),(0xfffffe000bd26cc0,'bl','#0xfffffe000bd22370'),
      (0xfffffe000bd26cb8,'blraa','x8, x17'),(0xfffffe000bd2ad28,'blraa','x8, x17'),
      (0xfffffe000bd26ef8,'mov','x0, x22'),(0xfffffe000bd2ab80,'tbnz','w8, #0, #0xfffffe000bd2ac88'),
      (0xfffffe000bd2abdc,'bl','#0xfffffe000bd27054'),(0xfffffe000bd2acb8,'str','w28, [x21, #0x1f8]'),
      (0xfffffe000bd2accc,'bl','#0xfffffe000bd1e688'),(0xfffffe000bd22380,'ldadd','w9, w8, [x8]'),
      (0xfffffe000bd1e698,'ldadd','w9, w8, [x8]'),(0xfffffe000bd223dc,'casp','x4, x5, x6, x7, [x10]'),
      (0xfffffe000bd1e710,'casp','x4, x5, x2, x3, [x12]'),(0xfffffe000bd29030,'bl','#0xfffffe000bd29140'),
      (0xfffffe000bd29040,'bl','#0xfffffe000bd2a064'),(0xfffffe000bd29044,'cbz','w0, #0xfffffe000bd29024'),
      (0xfffffe000bd29054,'ldr','w0, [x19, #0xd8]'),(0xfffffe000bd2a33c,'bl','#0xfffffe000bd2a8b8'),
      (0xfffffe000bd2a534,'bl','#0xfffffe000bd2a8b8'),(0xfffffe000bd27644,'bl','#0xfffffe000bd207c4')]:at(a,m,o)
    finite=audit();assert finite==FINITE
    assert current['validation']['aes_block_wake_handshake_increment_checks']==COUNTS
    assert current['validation']['aes_block_wake_handshake_static_scope']==e['scope']
    assert current['validation']['reports']==previous['validation']['reports']+1==402
    assert current['validation']['unavailable_external_primary_references']==previous['validation']['unavailable_external_primary_references']
    assert current['goal_status']=='active'and not any(e[n]for n in ['new_IDA_access','new_native_execution','new_IDB_mutations','full_goal_complete'])
    assert len(OWNED)==14
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:path_hygiene((BASE/p).read_bytes())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    print(json.dumps({'unchanged_manifest_entries':len(old)-len(CHANGED),'owned_physical_files':len(OWNED),
      'original_inputs_preserved':3,'new_UNSAT_queries_rechecked':34,'prior_UNSAT_queries_rechecked':67,'SAT_controls_rechecked':4,
      'independent_interpretation':finite,'analyst_path_literals_absent':True,'all_checks_pass':True}),flush=True)


if __name__=='__main__':main()
