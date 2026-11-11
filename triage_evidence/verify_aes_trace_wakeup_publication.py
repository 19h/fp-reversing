#!/usr/bin/env python3
"""Read-only original-source and exact-delta audit for AES trace/wakeup.

O(source+owned bytes+path visits) time/space plus finite interpretation and
separate SMT cost. No native target or IDB operation executes.
"""
import bisect
from hashlib import sha256
import json
from pathlib import Path
import subprocess

from compression import zstd
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_MEM
import z3

from kernel_native_reader import Kernel
from recover_kext_aes_handoff import starts
from recover_kext_cold_init import pointer
from audit_aes_trace_wakeup import audit
from verify_daemon_reader_record_payloads_publication import read, sha, size
from verify_lskd_vector_origin_publication import path_hygiene

ROOT=Path(__file__).resolve().parent
BASE=ROOT.parent
PREVIOUS='ff7adc71e6c0f3119f05e7a503a286f5f2270036'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'aes_configuration_commands_report.md','aes_quantum_binding_report.md','aes_carrier_initialization_report.md',
         'foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md',
         'obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'aes_trace_wakeup_report.md','triage_evidence/recover_aes_trace_wakeup.py','triage_evidence/aes_trace_wakeup_checks.json',
       'triage_evidence/audit_aes_trace_wakeup.py','triage_evidence/verify_aes_trace_wakeup_publication.py'}
ARCHIVES={MANIFEST,'triage_evidence/aes_trace_wakeup_checks.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'queries_unsat':68,'controls_sat':2,'source_pieces':43,'source_lifted_instances':183,'record_writers':8,
        'interrupt_paths_sat':7,'spans':19,'instructions':2107,'code_B':8428,'original_slots':8,
        'census_instructions':4445,'literal_cursor_reads':7,'literal_cursor_stores':8}
ORACLES={'ring_full_canvas_cases':12288,'interrupt_snapshot_cases':4480,'cursor_values_per_record':256,
         'record_sites':8,'record_extent_B':8,'provider_prefix_B':2560}
H=0xfffffe0009d40000


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def check(query,expected):
    solver=z3.Solver();solver.set(timeout=15000);solver.from_string(query);result=solver.check()
    assert result==expected,(str(result),str(expected),solver.reason_unknown())


def main():
    previous_raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(previous_raw).hexdigest()=='90386193157b6730c743715596bd24b5805bbda7a25af5caed9b733f1a148e02'
    previous,current=json.loads(previous_raw),json.loads(read(BASE/MANIFEST))
    old={r['path']:r for r in previous['files']};new={r['path']:r for r in current['files']}
    assert len(old)==len(previous['files'])==8091 and len(new)==len(current['files'])==8096
    assert not old.keys()-new.keys() and new.keys()-old.keys()==ADDED
    assert {p for p in old if old[p]!=new[p]}==CHANGED
    assert current['inputs_preserved']==previous['inputs_preserved']
    for row in current['inputs_preserved']:
        assert sha(BASE/row['path'])==row['sha256'] and size(BASE/row['path'])==row['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==new[p]['sha256'] and size(BASE/p)==new[p]['size_bytes']
    report=read(BASE/'aes_trace_wakeup_report.md')
    assert all(f'| TW{i} |'in report for i in range(1,9))and all(f'**QG{i}**'in report for i in range(1,8))
    e=json.loads(read(ROOT/'aes_trace_wakeup_checks.json'))
    assert e['generator_sha256']==sha(ROOT/'recover_aes_trace_wakeup.py')
    for p,digest in e['dependencies'].items():assert sha(ROOT/p)==digest
    assert e['verified_counts']==COUNTS and len(e['proofs'])==68 and len(e['negative_controls'])==2
    for proof in e['proofs'].values():assert proof['result']=='unsat';check(proof['query'],z3.unsat)
    for control in e['negative_controls'].values():assert control['result']=='sat';check(control['query'],z3.sat)
    prior=json.loads(read(ROOT/'aes_configuration_commands_checks.json'))
    assert len(prior['proofs'])==56
    for proof in prior['proofs'].values():assert proof['result']=='unsat';check(proof['query'],z3.unsat)
    k=Kernel();assert e['kernel_collection_sha256']==k.sha256
    hw=next(r for r in k.entries if r['name']=='com.apple.driver.AppleS8000AES')
    cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
    spans={r['label']:r for r in e['spans']};assert len(spans)==19
    ranges=sorted((int(r['start'],16),int(r['end'],16))for r in spans.values())
    assert all(z<=a for(_,z),(a,_)in zip(ranges,ranges[1:]))
    code={}
    for row in spans.values():
        a,z=int(row['start'],16),int(row['end'],16);raw=bytes.fromhex(row['bytes_hex'])
        assert len(raw)==z-a==4*len(row['instructions'])and k.read(a,len(raw))==raw
        ins=list(cs.disasm(raw,a));assert len(ins)*4==len(raw)
        assert row['instructions']==[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ins]
        code.update({i.address:(i.mnemonic,i.op_str)for i in ins})
        if 'sha256'in row:assert row['sha256']==sha256(raw).hexdigest()
        if 'entry'in row:
            entry=next(x for x in k.entries if x['name']==row['entry']);catalog=starts(k,entry)
        elif row['label'] in ['typed_new','gate_wakeup']:catalog=k.starts
        else:assert len(raw)==16 and row['label'].endswith('_stub');continue
        assert a in catalog and catalog[catalog.index(a)+1]==z
    assert sum(len(r['instructions'])for r in spans.values())==2107
    assert sum(len(bytes.fromhex(r['bytes_hex']))for r in spans.values())==8428
    for label in ['configure','push']:
        old_row=next(r for r in prior['spans']if r['label']==label)
        assert spans[label]['bytes_hex']==old_row['bytes_hex']and spans[label]['end']==old_row['end']
    assert len(e['slots'])==8
    for a,row in e['slots'].items():assert row==pointer(k,int(a,16))and row['chain_membership_verified']
    addresses={int(r['start'],16)for r in spans.values()if 'entry'in r or r['label']in ['typed_new','gate_wakeup']}
    addresses|={int(r['target'],16)for r in e['slots'].values()}|{0xfffffe00082fe4e8}
    assert e['exact_symbols']==k.symbols(addresses)
    names={a:{r['name']for r in rows}for a,rows in e['exact_symbols'].items()}
    assert names['0xfffffe000c4458c4']=={'_OSObject_typed_operator_new'}
    assert names['0xfffffe000c51e19c']=={'__ZN13IOCommandGate13commandWakeupEPvb'}
    assert names['0xfffffe000c51e1d4']=={'__ZN13IOCommandGate12commandSleepEPvj'}
    assert e['slots']['0xfffffe0007f3fdb8']['diversity']=='0xf36c'
    view=e['typed_view'];assert view['address']=='0xfffffe00082fe4e8'and view['size_low24']==2560
    raw=k.read(int(view['address'],16),64);assert raw.hex()==view['bytes_hex']
    assert int.from_bytes(raw[0x2c:0x30],'little')&0xffffff==2560
    name_addr=int(e['slots']['0xfffffe00082fe4f8']['target'],16)
    assert bytes.fromhex(view['name_bytes_hex'])==k.read(name_addr,30)==b'site.AppleS8000AESAccelerator\0'
    const=e['startup_constant'];assert const['address']=='0xfffffe000771c5f8'
    assert bytes.fromhex(const['bytes_hex'])==k.read(int(const['address'],16),8)==bytes.fromhex('0100000002000000')
    old_zero=json.loads(read(ROOT/'aes_carrier_initialization_source.json'))['separately_versioned_reference']
    assert e['separately_versioned_zero_flag_reference']==old_zero
    assert old_zero['sha256']=='3a7bcfed6b5062574a33ac59e15dd97fc8c8a80cc45b37c67f52f5f112c739d9'
    assert not old_zero['matched_collection_source_revision_established']
    census=e['cursor_census'];section=next(s for s in hw['sections']if s['section']=='__text')
    a,n=section['address'],section['size'];raw=k.read(a,n);ins=list(cs.disasm(raw,a))
    assert census['entry']==hw['name']and census['entry_uuid']==hw['uuid']
    assert int(census['start'],16)==a and census['size_bytes']==n==17780 and census['instructions']==len(ins)==4445
    assert raw.hex()==census['bytes_hex']and sha256(raw).hexdigest()==census['sha256']
    catalog=starts(k,hw);hits=[]
    for i in ins:
        if any(o.type==ARM64_OP_MEM and o.mem.disp==0x9fc for o in i.operands):
            ix=bisect.bisect_right(catalog,i.address)-1
            hits.append({'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str,
                         'compiler_start':hex(catalog[ix]),'compiler_end':hex(catalog[ix+1])})
    assert census['literal_0x9fc_memory_operands']==hits and not census['alias_or_indirect_writer_closure_established']
    stores={r['pc']for r in hits if r['mnemonic']=='str'}
    assert len(stores)==8 and sum(r['mnemonic']=='ldr'for r in hits)==7
    assert stores=={r['cursor_store']for r in e['record_writers']}
    expected_records=[('start_enter',1,1),('start_leave',1,2),('enable_enter',1,1),('disable_enter',1,3),
                      ('state_leave',1,None),('completion_status',3,None),('completion_progress',4,None),('command_word',2,None)]
    assert [(r['name'],r['tag32'],r['fixed_payload32'])for r in e['record_writers']]==expected_records
    assert len(e['source_pieces'])==43 and sum(e['source_lift_counts'].values())==183
    for name,cut in e['source_pieces'].items():
        a,z=int(cut['start'],16),int(cut['end'],16)
        assert cut['instructions']==e['source_lift_counts'][name]==(z-a)//4 and any(l<=a<z<=r for l,r in ranges)
        assert not any(i.mnemonic.startswith('b.')or i.mnemonic in ['b','bl','blr','blraa','cbz','cbnz','tbz','tbnz']for i in cs.disasm(k.read(a,z-a),a))
    assert len(e['interrupt_paths'])==7
    for row in e['interrupt_paths']:
        path=[int(a,16)for a in row['path']];frontier=int(row['frontier'],16)
        assert path[0]==H+0xf570 and frontier in {H+0xf5c4,H+0xf5f8,H+0xf608,H+0xf62c,H+0xf630}
        assert len(set(path))==len(path)and row['declared_snapshot_feasibility']=='sat';check(row['feasibility_query'],z3.sat)
        for pc,successor in zip(path,path[1:]+[frontier]):
            i=next(cs.disasm(k.read(pc,4),pc));m=i.mnemonic
            if m.startswith('b.')or m in ['tbz','tbnz']:
                assert successor in [pc+4,i.operands[-1].imm&((1<<64)-1)]
            else:
                assert m in ['mov','ldr','ldrb','str','strb','movk','add','cmp','csel','tst','and']and successor==pc+4
    def at(offset,m,op):assert code[H+offset]==(m,op),(hex(H+offset),code[H+offset])
    for off,m,op in [(0xf584,'str','w20, [x8, #0x18]'),(0xf5b4,'str','w9, [x8, #0x1c]'),
                     (0xf5c0,'strb','wzr, [x19, #0x150]'),(0xf5c4,'ldr','x0, [x19, #0x1c8]'),
                     (0xf5d8,'mov','x17, #0x208'),(0xf5ec,'movk','x16, #0xf36c, lsl #48'),
                     (0xf5f0,'blraa','x8, x16'),(0xf5f4,'tbnz','w20, #5, #0xfffffe0009d4f608'),
                     (0xf628,'b','#0xfffffe0009d5153c'),(0x1157c,'ldr','w8, [x9, #0x30]'),
                     (0x11580,'tst','w8, #0xff00'),(0x11584,'b.ne','#0xfffffe0009d5157c'),
                     (0xfadc,'b','#0xfffffe0009d4fb6c')]:at(off,m,op)
    assert code[0xfffffe000c44590c]==('bl','#0xfffffe000bcfeb8c')
    assert code[0xfffffe000c51e1a0]==('ldr','x0, [x0, #0x30]')
    assert code[0xfffffe000c51e1b4]==('mov','x17, #0x1b8')
    sites=[(0xfeec,0xff28),(0xffa8,0xffe8),(0x10228,0x10268),(0x102b4,0x102f4),
           (0x10334,0x10370),(0x1044c,0x1048c),(0x105d4,0x10610),(0x106bc,0x106fc)]
    assert e['configuration_sleep_sites']==[{'wait_byte_store':hex(H+s),'sleep_call':hex(H+c)}for s,c in sites]
    for store,call in sites:
        assert code[H+store][0]=='strb'and code[H+store][1].endswith('[x19, #0x150]')
        at(call,'blraa','x8, x16');at(call-4,'movk','x16, #0x6db9, lsl #48')
        assert ('ldr','x0, [x19, #0x1c8]')in [code[a]for a in range(H+store,H+call,4)]
    assert audit()==ORACLES
    assert current['validation']['aes_trace_wakeup_increment_checks']==COUNTS
    assert current['validation']['aes_trace_wakeup_static_scope']==e['scope']
    assert current['validation']['reports']==previous['validation']['reports']+1==397
    assert current['validation']['unavailable_external_primary_references']==previous['validation']['unavailable_external_primary_references']
    assert current['goal_status']=='active'and not any(e[n]for n in ['new_IDA_access','new_native_execution','new_IDB_mutations','full_goal_complete'])
    assert len(OWNED)==14
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:path_hygiene((BASE/p).read_bytes())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    print(json.dumps({'unchanged_manifest_entries':len(old)-len(CHANGED),'owned_physical_files':len(OWNED),
          'original_inputs_preserved':3,'new_UNSAT_queries_rechecked':68,'prior_UNSAT_queries_rechecked':56,
          'interrupt_paths_SAT':7,'SAT_premise_controls':2,'source_instructions':2107,'census_instructions':4445,
          'original_pointer_slots':8,'independent_interpretation':ORACLES,'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
