#!/usr/bin/env python3
"""Read-only source, fixup, interpretation and exact-publication audit.

O(source+owned bytes+private visits) time/space plus separate SMT cost.
No native boot, callback, PAC, allocator, IPC or IDB operation executes.
"""
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import struct
import subprocess
from compression import zstd
import z3
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from audit_startup_dispatch import audit
from verify_daemon_reader_record_payloads_publication import read, sha, size
from verify_lskd_vector_origin_publication import path_hygiene

ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='de2753c65db76c4bff5d1ca747452c773571b606'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'event_wait_table_report.md','kernel_zone_startup_report.md','foundational_triage_report.md','interface_abi_report.md',
         'interface_investigation_status.md','obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'startup_dispatch_report.md','triage_evidence/recover_startup_dispatch.py','triage_evidence/startup_dispatch_checks.json',
       'triage_evidence/audit_startup_dispatch.py','triage_evidence/verify_startup_dispatch_publication.py'}
ARCHIVES={MANIFEST,'triage_evidence/startup_dispatch_checks.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'queries_unsat':13,'source_pieces':11,'source_lifted_instances':23,'spans':6,'instructions':3026,
        'startup_records':3519,'startup_fixups':6950,'phase_names':17,'code_B':12104}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def check(query):
    solver=z3.Solver();solver.set(timeout=15000);solver.from_string(query);result=solver.check()
    assert result==z3.unsat,(str(result),solver.reason_unknown())


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest()=='030248c15dabe2e7456219fc152e56c7f870ba28708407ddeb7d3763226de7b2'
    previous,current=json.loads(raw),json.loads(read(BASE/MANIFEST));old={r['path']:r for r in previous['files']};new={r['path']:r for r in current['files']}
    assert len(old)==len(previous['files'])==8106 and len(new)==len(current['files'])==8111
    assert not old.keys()-new.keys()and new.keys()-old.keys()==ADDED
    assert {p for p in old if old[p]!=new[p]}==CHANGED and current['inputs_preserved']==previous['inputs_preserved']
    for row in current['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==new[p]['sha256']and size(BASE/p)==new[p]['size_bytes']
    report=read(BASE/'startup_dispatch_report.md')
    assert all(f'| SD{i} |'in report for i in range(1,8))and all(f'**QG{i}**'in report for i in range(1,8))
    e=json.loads(read(ROOT/'startup_dispatch_checks.json'));assert e['generator_sha256']==sha(ROOT/'recover_startup_dispatch.py')and e['verified_counts']==COUNTS
    for p,digest in e['dependencies'].items():assert sha(ROOT/p)==digest
    assert len(e['proofs'])==13 and len(e['source_pieces'])==11 and sum(r['instructions']for r in e['source_pieces'].values())==23
    for proof in e['proofs'].values():assert proof['result']=='unsat';check(proof['query'])
    prior=json.loads(read(ROOT/'event_wait_table_checks.json'));assert len(prior['proofs'])==91
    for proof in prior['proofs'].values():assert proof['result']=='unsat';check(proof['query'])
    k=Kernel();assert e['kernel_collection_sha256']==k.sha256;code={};spans={r['label']:r for r in e['spans']}
    assert len(spans)==6 and sum(len(r['instructions'])for r in spans.values())==3026
    for r in spans.values():
        original=k.function(int(r['start'],16));assert original['bytes']==r['bytes_hex']and original['end']==r['end']and original['sha256']==r['sha256']and original['instructions']==r['instructions']
        code.update({int(i['ea'],16):i for i in r['instructions']})
    assert e['exact_symbols']==k.symbols([int(r['start'],16)for r in spans.values()])and all(not v for v in e['exact_symbols'].values())
    section=next(s for s in k.kernel['sections']if s['section']=='__init_entry_set');assert e['startup_section']==section
    assert section['size']==84456 and section['size']//24==3519 and len(e['records'])==3519
    logical=bytearray();hist=Counter();fixups=0
    for j,row in enumerate(e['records']):
        a=section['address']+24*j;raw=k.read(a,24);assert row['address']==hex(a)and row['bytes_hex']==raw.hex()
        assert struct.unpack_from('<II',raw)==(row['phase32'],row['rank32']);hist[row['phase32']]+=1;normalized=bytearray(raw)
        expected=[]
        for off in [8,16]:
            if raw[off:off+8]!=bytes(8):
                p=pointer(k,a+off);expected.append(p);normalized[off:off+8]=int(p['target'],16).to_bytes(8,'little');fixups+=1
                if off==8:assert p['authenticated']and p['diversity']=='0x2abe'and(int(p['word'],16)>>48)&7==0
        assert row['fixups']==expected and row['logical_bytes_hex']==normalized.hex();logical.extend(normalized)
    assert fixups==6950 and e['logical_table_bytes_hex']==logical.hex()
    assert e['phase_histogram']=={str(p):n for p,n in sorted(hist.items())}
    peers=[r for r in e['records']if r['phase32']==14];assert Counter(r['rank32']for r in peers)=={0:42,0xffffffff:3}
    assert e['cursor_initial_pointer']==pointer(k,0xfffffe000cbc9a48)and int(e['cursor_initial_pointer']['target'],16)==section['address']
    for row in e['phase_names']:
        p=pointer(k,0xfffffe0007e64530+8*row['phase32']);assert row['pointer']==p
        raw=bytes.fromhex(row['bytes_hex']);assert k.read(int(p['target'],16),len(raw))==raw==row['text'].encode()+b'\0'
    assert {r['phase32']:r['text']for r in e['phase_names']}[14]=='mach_ipc'
    for row in e['data'].values():assert k.read(int(row['address'],16),len(bytes.fromhex(row['bytes_hex']))).hex()==row['bytes_hex']
    assert bytes.fromhex(e['data']['diagnostic_name']['bytes_hex'])==b'kernel_startup_initialize_upto\0'
    def at(a,m,o):assert(code[a]['mnemonic'],code[a]['operands'])==(m,o),(hex(a),code[a])
    for a,m,o in [(0xfffffe000c630260,'b','#0xfffffe000c6302c4'),(0xfffffe000c630320,'b.hi','#0xfffffe000c630384'),
      (0xfffffe000c63035c,'str','w8, [x21, #0x5f0]'),(0xfffffe000c630364,'bl','#0xfffffe000bd3ad04'),
      (0xfffffe000c630370,'blraa','x8, x17'),(0xfffffe000c630378,'str','x24, [x23, #0xa48]'),
      (0xfffffe000c630388,'bl','#0xfffffe000bd3ad04'),(0xfffffe000c6303b4,'str','w19, [x21, #0x5f0]'),
      (0xfffffe000c6308cc,'bl','#0xfffffe000c6302c4'),(0xfffffe000c630bfc,'bl','#0xfffffe000c6302c4')]:at(a,m,o)
    result=audit()
    assert result['all_checks_pass']and result['sort_instruction_visits']==231961 and result['sort_source_calls']==4215
    assert result['sort_records']==3519 and result['dispatch_instruction_visits']==56717 and result['dispatch_callback_models']==3519
    assert result['comparator_cases']==400 and result['selected_wait_callback_sorted_index']==1335 and result['sort_guard_bytes']==128
    assert result['sorted_table_sha256']=='59fee911ef4245c47031c68d965e88ca030f22f1876d525aeaaf6d1f83249e2c'
    assert [r['callbacks']for r in result['dispatch_thresholds']]==[1029,1,4,13,136,114,45,9,2152,15,1]
    assert [r['target32']for r in result['dispatch_thresholds']]==[3,4,5,6,7,13,14,15,16,19,0xffffffff]
    assert current['validation']['startup_dispatch_increment_checks']==COUNTS and current['validation']['startup_dispatch_static_scope']==e['scope']
    assert current['validation']['reports']==previous['validation']['reports']+1==400
    assert current['validation']['unavailable_external_primary_references']==previous['validation']['unavailable_external_primary_references']
    assert current['goal_status']=='active'and not any(e[n]for n in ['new_IDA_access','new_native_execution','new_IDB_mutations','full_goal_complete'])
    assert len(OWNED)==13
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:path_hygiene((BASE/p).read_bytes())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    print(json.dumps({'unchanged_manifest_entries':len(old)-len(CHANGED),'owned_physical_files':len(OWNED),'original_inputs_preserved':3,
          'new_UNSAT_queries_rechecked':13,'prior_UNSAT_queries_rechecked':91,'source_instructions':3026,'startup_records':3519,
          'startup_fixups':6950,'independent_interpretation':result,'analyst_path_literals_absent':True,'all_checks_pass':True}),flush=True)


if __name__=='__main__':main()
