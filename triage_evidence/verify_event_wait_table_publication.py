#!/usr/bin/env python3
"""Read-only original-source and exact-publication audit of wait-table startup.

O(source+owned bytes+finite visits) time/space plus separate SMT cost.
No new target, allocator, parser, scheduler or IDB operation executes.
"""
from hashlib import sha256
import json
from pathlib import Path
import struct
import subprocess
from compression import zstd
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
import z3
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from audit_event_wait_table import audit
from verify_daemon_reader_record_payloads_publication import read, sha, size
from verify_lskd_vector_origin_publication import path_hygiene

ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='1afb78be9f61963a9ce8ea0793335158c659a86d'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'aes_event_registration_report.md','foundational_triage_report.md','interface_abi_report.md',
         'interface_investigation_status.md','obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'event_wait_table_report.md','triage_evidence/recover_event_wait_table.py','triage_evidence/event_wait_table_checks.json',
       'triage_evidence/audit_event_wait_table.py','triage_evidence/verify_event_wait_table_publication.py'}
ARCHIVES={MANIFEST,'triage_evidence/event_wait_table_checks.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'queries_unsat':91,'source_pieces':14,'source_lifted_instances':65,'spans':5,'instructions':1022,
        'startup_entries':1,'writer_locator_candidates':2,'code_B':4088}
ORACLES={'default_budget_cases':263,'budget_geometry_cases':367,'option_return_routes':27,
         'whole_allocation_canvases':12,'initialized_records':1198,'wrapper_validity_routes':6,
         'allocator_return_pairs':9,'special_queue_canvases':3}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def check(query):
    solver=z3.Solver();solver.set(timeout=15000);solver.from_string(query);result=solver.check()
    assert result==z3.unsat,(str(result),solver.reason_unknown())


def main():
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest()=='4d78850eee1f09cd85e6173e255941f228ca0044141575c44dafd2755fad0c4d'
    previous,current=json.loads(raw),json.loads(read(BASE/MANIFEST))
    old={r['path']:r for r in previous['files']};new={r['path']:r for r in current['files']}
    assert len(old)==len(previous['files'])==8101 and len(new)==len(current['files'])==8106
    assert not old.keys()-new.keys()and new.keys()-old.keys()==ADDED
    assert {p for p in old if old[p]!=new[p]}==CHANGED
    assert current['inputs_preserved']==previous['inputs_preserved']
    for row in current['inputs_preserved']:assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==new[p]['sha256']and size(BASE/p)==new[p]['size_bytes']
    report=read(BASE/'event_wait_table_report.md')
    assert all(f'| ET{i} |'in report for i in range(1,8))and all(f'**QG{i}**'in report for i in range(1,8))
    e=json.loads(read(ROOT/'event_wait_table_checks.json'))
    assert e['generator_sha256']==sha(ROOT/'recover_event_wait_table.py')and e['verified_counts']==COUNTS
    for p,digest in e['dependencies'].items():assert sha(ROOT/p)==digest
    assert len(e['proofs'])==91
    for proof in e['proofs'].values():assert proof['result']=='unsat';check(proof['query'])
    prior=json.loads(read(ROOT/'aes_event_registration_checks.json'));assert len(prior['proofs'])==47
    for proof in prior['proofs'].values():assert proof['result']=='unsat';check(proof['query'])
    k=Kernel();assert e['kernel_collection_sha256']==k.sha256
    cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
    spans={r['label']:r for r in e['spans']};assert len(spans)==5
    code={}
    for row in spans.values():
        a,z=int(row['start'],16),int(row['end'],16);original=k.function(a)
        assert original['end']==row['end']and original['bytes']==row['bytes_hex']and original['sha256']==row['sha256']
        raw=bytes.fromhex(row['bytes_hex']);assert len(raw)==z-a==4*len(row['instructions'])
        assert original['instructions']==row['instructions']
        ins=list(cs.disasm(raw,a));assert len(ins)*4==len(raw);code.update({i.address:i for i in ins})
    assert sum(len(r['instructions'])for r in spans.values())==1022
    assert int(spans['startup']['end'],16)-int(spans['startup']['start'],16)==440
    assert len(e['source_pieces'])==14 and sum(r['instructions']for r in e['source_pieces'].values())==65
    for piece in e['source_pieces'].values():
        a,z=int(piece['start'],16),int(piece['end'],16)
        assert piece['instructions']==(z-a)//4
        assert all(pc in code and code[pc].mnemonic not in ['bl','blr','retab','ret','b']and not code[pc].mnemonic.startswith('b.')for pc in range(a,z,4))
    for label in ['registration_wrapper','wake_wrapper']:
        frozen=next(r for r in prior['spans']if r['start']==spans[label]['start'])
        assert frozen['bytes_hex']==spans[label]['bytes_hex']and frozen['end']==spans[label]['end']
    entry=e['startup_entry'];section=next(s for s in k.kernel['sections']if s['section']=='__init_entry_set')
    assert entry['section']==section and entry['address']=='0xfffffe000cbebbf8'
    a=int(entry['address'],16);assert section['address']<=a<a+24<=section['address']+section['size']and(a-section['address'])%24==0
    raw=k.read(a,24);assert raw.hex()==entry['bytes_hex']and struct.unpack_from('<II',raw)==(14,0)and raw[16:]==bytes(8)
    assert entry['phase32']==14 and entry['rank32']==0 and entry['argument64']==0
    assert entry['callback']==pointer(k,a+8)and entry['callback']['target']==spans['startup']['start']and entry['callback']['authenticated']
    assert len(e['slots'])==2
    for a,row in e['slots'].items():assert row==pointer(k,int(a,16))and row['chain_membership_verified']
    assert e['slots']['0xfffffe0007e66df8']['target']=='0xfffffe000cbca628'
    for name,row in e['data'].items():assert k.read(int(row['address'],16),len(bytes.fromhex(row['bytes_hex']))).hex()==row['bytes_hex']
    assert e['data']['option_name']['bytes_hex']==b'wqsize\0'.hex()
    assert e['data']['record_seed']['bytes_hex']=='0900000000000000'
    assert e['data']['special_seed']['bytes_hex']=='0c00000000000000'
    assert e['data']['parameter_file_word']['bytes_hex']=='000a0000'
    addresses=[int(r['start'],16)for r in spans.values()]+[0xfffffe0007f860a8]
    assert e['exact_symbols']==k.symbols(addresses)
    assert [r['name']for r in e['exact_symbols']['0xfffffe0007f860a8']]==['_kernel_map']
    for label in ['startup','option_reader','allocator']:assert not e['exact_symbols'][spans[label]['start']]
    def at(a,m,op):assert(code[a].mnemonic,code[a].op_str)==(m,op),(hex(a),code[a].mnemonic,code[a].op_str)
    for a,m,op in [(0xfffffe000c631a1c,'bl','#0xfffffe000c5e48a4'),
      (0xfffffe000c631a20,'cbz','w0, #0xfffffe000c631a2c'),
      (0xfffffe000c631a24,'ldr','x8, [sp, #8]'),(0xfffffe000c631a28,'b','#0xfffffe000c631a58'),
      (0xfffffe000c631a78,'str','w9, [x19, #0xe00]'),(0xfffffe000c631ab0,'bl','#0xfffffe000bdc08e0'),
      (0xfffffe000c631ab8,'str','x1, [x8, #0xdf8]'),(0xfffffe000c631ac0,'cbz','w9, #0xfffffe000c631b0c'),
      (0xfffffe000c631ae8,'b.eq','#0xfffffe000c631af0'),(0xfffffe000c631aec,'movk','x13, #0xc8a2, lsl #48'),
      (0xfffffe000c631af0,'str','d0, [x13]'),(0xfffffe000c631af4,'stp','xzr, xzr, [x13, #8]'),
      (0xfffffe000c631af8,'str','w10, [x13, #4]'),(0xfffffe000c631b08,'b.lo','#0xfffffe000c631ad4'),
      (0xfffffe000bd6e004,'ldrb','w8, [x0, #5]'),(0xfffffe000bd6e008,'tbz','w8, #0, #0xfffffe000bd6e0f4'),
      (0xfffffe000bd6e24c,'ldrb','w8, [x0, #5]'),(0xfffffe000bd6e250,'tbz','w8, #0, #0xfffffe000bd6e30c')]:at(a,m,op)
    for pc in range(0xfffffe000c631ab4,0xfffffe000c631b0c,4):
        reads,_=code[pc].regs_access();assert not {'x0','w0'}&{code[pc].reg_name(r)for r in reads}
    locator=e['writer_locators'];assert locator['window_B']==192 and len(locator['candidates'])==2
    assert {r['candidate_store']for r in locator['candidates']}=={'0xfffffe000c631a78','0xfffffe000c631ab8'}
    assert [r['segment']for r in locator['scans']]==['__TEXT_EXEC','__TEXT_BOOT_EXEC','__KLD']
    for scan in locator['scans']:
        s=next(s for s in k.kernel['segments']if s['name']==scan['segment'])
        assert scan['start']==hex(s['address'])and scan['bytes']==s['file_size']and scan['aligned_words']==s['file_size']//4
    for row in locator['candidates']:
        ins=code[int(row['adrp'],16)];assert ins.mnemonic=='adrp'and ins.operands[1].imm&((1<<64)-1)==0xfffffe0007e66000
        assert 0<int(row['candidate_store'],16)-ins.address<192
        at(int(row['candidate_store'],16),row['mnemonic'],row['operands'])
    assert audit()==ORACLES
    assert sum(v for n,v in ORACLES.items()if n!='initialized_records')==687
    assert current['validation']['event_wait_table_increment_checks']==COUNTS
    assert current['validation']['event_wait_table_static_scope']==e['scope']
    assert current['validation']['reports']==previous['validation']['reports']+1==399
    assert current['validation']['unavailable_external_primary_references']==previous['validation']['unavailable_external_primary_references']
    assert current['goal_status']=='active'and not any(e[n]for n in ['new_IDA_access','new_native_execution','new_IDB_mutations','full_goal_complete'])
    assert len(OWNED)==12
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:path_hygiene((BASE/p).read_bytes())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    print(json.dumps({'unchanged_manifest_entries':len(old)-len(CHANGED),'owned_physical_files':len(OWNED),'original_inputs_preserved':3,
          'new_UNSAT_queries_rechecked':91,'prior_UNSAT_queries_rechecked':47,'source_instructions':1022,'startup_entries':1,
          'independent_interpretation':ORACLES,'finite_cases':687,'analyst_path_literals_absent':True,'all_checks_pass':True}),flush=True)


if __name__=='__main__':main()
