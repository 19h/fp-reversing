#!/usr/bin/env python3
"""Exact binary/public-source provenance, interpretation and publication audit.

O(source+owned bytes+private visits) time/space; SMT cost separate. Pinned
public source is fetched read-only. No native queue, scheduler, atomic, clock,
IPC or IDB operation executes.
"""
from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess
from urllib.request import urlopen
from compression import zstd
import z3
from kernel_native_reader import Kernel
from audit_aes_context_score_policy import audit
from verify_daemon_reader_record_payloads_publication import read, sha, size
from verify_lskd_vector_origin_publication import path_hygiene

ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='40213dff7a0f335df5f1189440dafc9194829242'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'aes_uncached_context_queue_report.md','aes_block_wake_handshake_report.md',
 'kernel_waitq_receiver_report.md','foundational_triage_report.md','interface_abi_report.md',
 'interface_investigation_status.md','obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'aes_context_score_policy_report.md','triage_evidence/recover_aes_context_score_policy.py',
 'triage_evidence/aes_context_score_policy_checks.json','triage_evidence/audit_aes_context_score_policy.py',
 'triage_evidence/verify_aes_context_score_policy_publication.py'}
ARCHIVES={MANIFEST,'triage_evidence/aes_context_score_policy_checks.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'queries_unsat':32,'controls_sat':4,'source_pieces':29,'source_lifted_instances':102,
 'spans':6,'instructions':1129,'code_B':4516}
FINITE={'full_score_canvases':3520,'empty_context_canvases':4,'period_boundary_canvases':40,
 'controlled_retry_canvases':9,'wake_then_score_canvases':18,'policy_backend_compositions':60,
 'configuration_canvases':30,'source_instruction_visits':368889,'pair_observations':4245,'score_instructions_visited':129,
 'controlled_pair_mismatches':{'0xfffffe000bd1ecd4':4,'0xfffffe000bd1ed88':3,'0xfffffe000bd1edf8':4},'all_checks_pass':True}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def check(query,expected):
    s=z3.Solver();s.set(timeout=15000);s.from_string(query);r=s.check()
    assert r==expected,(str(r),s.reason_unknown())


def public_source(e):
    ref=e['public_source_reference']
    assert ref['url']=='https://raw.githubusercontent.com/apple-oss-distributions/xnu/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/sched_clutch.c'
    raw=urlopen(ref['url'],timeout=30).read()
    assert len(raw)==ref['size_B']==241161 and sha256(raw).hexdigest()==ref['sha256']=='0a4c7c24704ebc0dc1f3e950103b3896a4a6308ccee31d2783818f53e6b405c0'
    text=raw.decode();observations={int(r['address'],16):bytes.fromhex(r['bytes_hex'])for r in e['file_global_observations']}
    arrays={'sched_clutch_root_bucket_wcel_us':0xfffffe000ca90690,
      'sched_clutch_root_bucket_warp_us':0xfffffe000ca906a8,
      'sched_clutch_thread_quantum_us':0xfffffe000ca906c0,
      'sched_clutch_bucket_group_pending_delta_us':0xfffffe000ca906d8}
    for name,address in arrays.items():
        body=re.search(r'static uint32_t '+name+r'\[[^]]+\]\s*=\s*\{([^}]+)\}',text).group(1)
        body=re.sub(r'/\*.*?\*/','',body,flags=re.S);values=[]
        for token in body.split(','):
            token=token.strip()
            if token:values.append(0xffffffff if token=='SCHED_CLUTCH_INVALID_TIME_32'else int(token))
        assert len(values)==6 and b''.join(v.to_bytes(4,'little')for v in values)==observations[address]
    for name in ['sched_clutch_bucket_pri_calculate','sched_clutch_bucket_update','sched_clutch_processor_enqueue','sched_clutch_init','sched_clutch_us_to_abstime']:
        assert re.search(r'\n'+name+r'\(',text)
    return {'pinned_public_source_sha256':ref['sha256'],'matching_input_tables':4,'candidate_names_present':5,
      'exact_binary_revision_identified':False}


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest()=='81304ae12159cfbb51550572a7246c3358d401038798b35accb1d2235ccf74c0'
    previous,current=json.loads(raw),json.loads(read(BASE/MANIFEST))
    old={r['path']:r for r in previous['files']};new={r['path']:r for r in current['files']}
    assert len(old)==len(previous['files'])==8136 and len(new)==len(current['files'])==8141
    assert not old.keys()-new.keys()and new.keys()-old.keys()==ADDED
    assert {p for p in old if old[p]!=new[p]}==CHANGED and current['inputs_preserved']==previous['inputs_preserved']
    for r in current['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256']and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==new[p]['sha256']and size(BASE/p)==new[p]['size_bytes']
    report=read(BASE/'aes_context_score_policy_report.md')
    assert all(f'| SP{i} |'in report for i in range(1,9))and all(f'**QG{i}**'in report for i in range(1,8))
    e=json.loads(read(ROOT/'aes_context_score_policy_checks.json'))
    assert e['generator_sha256']==sha(ROOT/'recover_aes_context_score_policy.py')and e['verified_counts']==COUNTS
    for p,digest in e['dependencies'].items():assert sha(ROOT/p)==digest
    assert len(e['proofs'])==32 and len(e['negative_controls'])==4
    assert len(e['source_pieces'])==29 and sum(r['instructions']for r in e['source_pieces'].values())==102
    for r in e['proofs'].values():assert r['result']=='unsat';check(r['query'],z3.unsat)
    for r in e['negative_controls'].values():assert r['result']=='sat';check(r['query'],z3.sat)
    priors=[json.loads(read(ROOT/p))for p in ['aes_uncached_context_queue_checks.json','aes_block_wake_handshake_checks.json']]
    assert[len(p['proofs'])for p in priors]==[25,34]
    for prior in priors:
        for r in prior['proofs'].values():assert r['result']=='unsat';check(r['query'],z3.unsat)
    extra=json.loads(read(ROOT/'aes_event_wake_selection_checks.json'))
    k=Kernel();assert e['kernel_collection_sha256']==k.sha256;code={};spans=e['spans']
    assert len(spans)==6 and sum(len(r['instructions'])for r in spans)==1129
    seen={}
    for r in spans+[s for p in priors+[extra]for s in p['spans']]:
        start=int(r['start'],16)
        if start in seen:assert seen[start]==r['bytes_hex'];continue
        f=k.function(start)
        assert(f['end'],f['bytes'],f['sha256'],f['instructions'])==(r['end'],r['bytes_hex'],r['sha256'],r['instructions'])
        seen[start]=r['bytes_hex'];code.update({int(i['ea'],16):i for i in r['instructions']})
    assert k.symbols(int(r['start'],16)for r in spans)==e['exact_symbols']and all(not v for v in e['exact_symbols'].values())
    assert len(e['file_global_observations'])==11
    for r in e['file_global_observations']:assert k.read(int(r['address'],16),r['size_B']).hex()==r['bytes_hex']
    assert k.read(0xfffffe000704ec40,42)==b'sched_clutch_bucket_group_interactive_pri\0'
    def at(a,m,o):assert(code[a]['mnemonic'],code[a]['operands'])==(m,o),(hex(a),code[a])
    for a,m,o in [
      (0xfffffe000bd20818,'str','x19, [x20, #0x20]'),(0xfffffe000bd20824,'add','x0, x19, #0x2a0'),
      (0xfffffe000bd1ec84,'sxtw','x12, w12'),(0xfffffe000bd1ecb8,'udiv','x15, x15, x16'),
      (0xfffffe000bd1ecc0,'madd','x5, x17, x16, x3'),(0xfffffe000bd1ed18,'mov','x14, #-0x3333333333333334'),
      (0xfffffe000bd1ed1c,'movk','x14, #0xcccd'),(0xfffffe000bd1edf8,'casp','x4, x5, x0, x1, [x12]'),
      (0xfffffe000bd2243c,'ldadd','x10, x9, [x9]'),(0xfffffe000bd24cc4,'bl','#0xfffffe000c5e48a4'),
      (0xfffffe000bd24cd4,'strb','w8, [x9, #0x68c]'),(0xfffffe000bd24d2c,'str','x8, [x9, #0x868]'),
      (0xfffffe000bd24d48,'b','#0xfffffe000bd21468'),(0xfffffe000bd214dc,'mov','x12, #-1')]:at(a,m,o)
    reference=public_source(e);finite=audit();assert finite==FINITE
    assert current['validation']['aes_context_score_policy_increment_checks']==COUNTS
    assert current['validation']['aes_context_score_policy_static_scope']==e['scope']
    assert current['validation']['reports']==previous['validation']['reports']+1==406
    assert current['validation']['unavailable_external_primary_references']==previous['validation']['unavailable_external_primary_references']
    assert current['goal_status']=='active'and not any(e[n]for n in ['new_IDA_access','new_native_execution','new_IDB_mutations','full_goal_complete'])
    assert len(OWNED)==14
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:path_hygiene((BASE/p).read_bytes())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    print(json.dumps({'unchanged_manifest_entries':len(old)-len(CHANGED),'owned_physical_files':len(OWNED),
      'original_inputs_preserved':3,'new_UNSAT_queries_rechecked':32,'prior_UNSAT_queries_rechecked':59,'SAT_controls_rechecked':4,
      'public_source_comparison':reference,'independent_interpretation':finite,'analyst_path_literals_absent':True,'all_checks_pass':True}),flush=True)


if __name__=='__main__':main()
