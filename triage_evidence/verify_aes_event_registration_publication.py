#!/usr/bin/env python3
"""Read-only original-source, path and exact-publication audit for AES events.

O(source+owned bytes+path visits) time/space plus finite interpretation and
separate SMT cost. No native target or IDB operation executes.
"""
from hashlib import sha256
import json
from pathlib import Path
import subprocess
from compression import zstd
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
import z3

from kernel_native_reader import Kernel
from recover_kext_aes_handoff import starts
from recover_kext_cold_init import pointer
from audit_aes_event_registration import audit
from verify_daemon_reader_record_payloads_publication import read, sha, size
from verify_lskd_vector_origin_publication import path_hygiene

ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='516e36c06ea71785dbb0331bf4ab343d83c4c3c6'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'aes_trace_wakeup_report.md','aes_synchronous_wait_report.md','kernel_waitq_enqueue_report.md',
         'foundational_triage_report.md','interface_abi_report.md','interface_investigation_status.md',
         'obfuscated_routines_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'aes_event_registration_report.md','triage_evidence/recover_aes_event_registration.py',
       'triage_evidence/aes_event_registration_checks.json','triage_evidence/audit_aes_event_registration.py',
       'triage_evidence/verify_aes_event_registration_publication.py'}
ARCHIVES={MANIFEST,'triage_evidence/aes_event_registration_checks.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst'for p in ARCHIVES}
COUNTS={'queries_unsat':47,'controls_sat':3,'source_pieces':20,'source_lifted_instances':130,'mark_source_paths':5,
        'sleep_source_paths':2,'feasible_source_paths':7,'untested_configuration_sleep_returns':8,
        'spans':14,'instructions':1563,'code_B':6252,'original_slots':5}
ORACLES={'hash_pair_cases':3132,'mark_wait_cases':125,'wait_publication_cases':99,'mutex_result_cases':6,
         'unlock_RMW_cases':96,'relock_RMW_cases':48,'counter_pair_cases':5,'empty_membership_cases':261,'wake_translation_cases':5}


def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)


def check(query,expected):
    solver=z3.Solver();solver.set(timeout=15000);solver.from_string(query);result=solver.check()
    assert result==expected,(str(result),str(expected),solver.reason_unknown())


def main():
    previous_raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(previous_raw).hexdigest()=='51ac0d35851d9e49c597b908cfd193605a2b6e886822ed821cf90c809ab5060b'
    previous,current=json.loads(previous_raw),json.loads(read(BASE/MANIFEST))
    old={r['path']:r for r in previous['files']};new={r['path']:r for r in current['files']}
    assert len(old)==len(previous['files'])==8096 and len(new)==len(current['files'])==8101
    assert not old.keys()-new.keys() and new.keys()-old.keys()==ADDED
    assert {p for p in old if old[p]!=new[p]}==CHANGED
    assert current['inputs_preserved']==previous['inputs_preserved']
    for row in current['inputs_preserved']:
        assert sha(BASE/row['path'])==row['sha256']and size(BASE/row['path'])==row['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==new[p]['sha256']and size(BASE/p)==new[p]['size_bytes']
    report=read(BASE/'aes_event_registration_report.md')
    assert all(f'| ER{i} |'in report for i in range(1,9))and all(f'**QG{i}**'in report for i in range(1,8))
    e=json.loads(read(ROOT/'aes_event_registration_checks.json'))
    assert e['generator_sha256']==sha(ROOT/'recover_aes_event_registration.py')
    for p,digest in e['dependencies'].items():assert sha(ROOT/p)==digest
    assert e['verified_counts']==COUNTS and len(e['proofs'])==47 and len(e['negative_controls'])==3
    for proof in e['proofs'].values():assert proof['result']=='unsat';check(proof['query'],z3.unsat)
    for control in e['negative_controls'].values():assert control['result']=='sat';check(control['query'],z3.sat)
    prior=json.loads(read(ROOT/'aes_trace_wakeup_checks.json'));assert len(prior['proofs'])==68
    for proof in prior['proofs'].values():assert proof['result']=='unsat';check(proof['query'],z3.unsat)
    k=Kernel();assert e['kernel_collection_sha256']==k.sha256
    cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True
    spans={r['label']:r for r in e['spans']};assert len(spans)==14
    ranges=sorted((int(r['start'],16),int(r['end'],16))for r in spans.values())
    assert all(z<=a for(_,z),(a,_)in zip(ranges,ranges[1:]))
    code={}
    for row in spans.values():
        a,z=int(row['start'],16),int(row['end'],16);raw=bytes.fromhex(row['bytes_hex'])
        assert len(raw)==z-a==4*len(row['instructions'])and k.read(a,len(raw))==raw
        assert sha256(raw).hexdigest()==row['sha256']
        ins=list(cs.disasm(raw,a));assert len(ins)*4==len(raw)
        assert row['instructions']==[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ins]
        code.update({i.address:i for i in ins})
        catalog=starts(k,next(x for x in k.entries if x['name']==row['entry']))if 'entry'in row else k.starts
        assert a in catalog and catalog[catalog.index(a)+1]==z
    assert sum(len(r['instructions'])for r in spans.values())==1563
    assert sum(len(bytes.fromhex(r['bytes_hex']))for r in spans.values())==6252
    frozen=json.loads(read(ROOT/'aes_synchronous_wait_source.json'))['functions']
    for label in ['gate_sleep','gate_wake','event_sleep','loop_sleep','loop_wake','mutex_sleep','wake_primitive']:
        row=spans[label];old_row=next(r for r in frozen if r['start']==row['start'])
        assert row['end']==old_row['end']and row['bytes_hex']==old_row['bytes']
    frozen=json.loads(read(ROOT/'kernel_waitq_enqueue_source.json'))['functions']
    for label in ['mark_wait','register_core']:
        row=spans[label];old_row=next(r for r in frozen if r['start']==row['start'])
        assert row['end']==old_row['end']and row['bytes_hex']==old_row['bytes']
    assert len(e['slots'])==5
    for a,row in e['slots'].items():assert row==pointer(k,int(a,16))and row['chain_membership_verified']
    addresses={int(r['start'],16)for label,r in spans.items()if label!='configure'}|{int(r['target'],16)for r in e['slots'].values()}
    assert e['exact_symbols']==k.symbols(addresses)
    for label,name in [('mutex_sleep','_lck_mtx_sleep'),('assert_wait','_assert_wait'),('wake_primitive','_thread_wakeup_prim')]:
        assert [r['name']for r in e['exact_symbols'][spans[label]['start']]]==[name]
    for label in ['register_wrapper','wake_wrapper','register_core','mark_wait','counter_cleanup']:
        # mark_wait and cleanup entries are analytical roles in this build.
        if label=='mark_wait':assert e['exact_symbols'][spans[label]['start']]==[]
        elif label!='counter_cleanup':assert e['exact_symbols'][spans[label]['start']]==[]
    for field,n in [('file_table_count',4),('file_table_prefix',24),('file_policy',4)]:
        row=e[field];assert k.read(int(row['address'],16),n).hex()==row['bytes_hex']
    assert e['slots']['0xfffffe0007e66df8']['target']=='0xfffffe000cbca628'
    assert e['file_table_count']=={'address':'0xfffffe0007e66e00','bytes_hex':'01000000'}
    assert e['file_table_prefix']=={'address':'0xfffffe000cbca628','bytes_hex':'00'*24}
    assert e['file_policy']=={'address':'0xfffffe000cb0bc50','bytes_hex':'00000000'}
    assert len(e['source_pieces'])==20 and sum(e['source_lift_counts'].values())==130
    for name,cut in e['source_pieces'].items():
        a,z=int(cut['start'],16),int(cut['end'],16)
        assert cut['instructions']==e['source_lift_counts'][name]==(z-a)//4 and any(l<=a<z<=r for l,r in ranges)
        assert not any(i.mnemonic.startswith('b.')or i.mnemonic in ['b','bl','blr','blraa','cbz','cbnz','tbz','tbnz']for i in cs.disasm(k.read(a,z-a),a))
    assert set(e['source_paths'])=={'mark','sleep'}
    for label,root,stops,count in [('mark',0xfffffe000bd282a0,{0xfffffe000bd282e4,0xfffffe000bd282f0},5),
                                  ('sleep',0xfffffe000bd0c944,{0xfffffe000bd0c990,0xfffffe000bd0ca70},2)]:
        assert len(e['source_paths'][label])==count
        for row in e['source_paths'][label]:
            path=[int(a,16)for a in row['path']];frontier=int(row['frontier'],16)
            assert path[0]==root and frontier in stops and len(set(path))==len(path)
            assert row['feasibility']=='sat';check(row['feasibility_query'],z3.sat)
            for pc,successor in zip(path,path[1:]+[frontier]):
                i=code[pc];m=i.mnemonic
                if m=='b':assert successor==i.operands[0].imm&((1<<64)-1)
                elif m.startswith('b.')or m in ['tbz','tbnz','cbz','cbnz']:
                    assert successor in [pc+4,i.operands[-1].imm&((1<<64)-1)]
                else:assert m in ['mov','ldr','ldrh','and','cmp','cmn','ccmp','csel','str']and successor==pc+4
    def at(a,m,op):assert(code[a].mnemonic,code[a].op_str)==(m,op),(hex(a),code[a].mnemonic,code[a].op_str)
    for a,m,op in [(0xfffffe000bd283a8,'cbz','x0, #0xfffffe000bd2844c'),
      (0xfffffe000bd28434,'mov','x3, #0'),(0xfffffe000bd28448,'b','#0xfffffe000bd6dfdc'),
      (0xfffffe000bd6e008,'tbz','w8, #0, #0xfffffe000bd6e0f4'),(0xfffffe000bd6e080,'bl','#0xfffffe000bd6bc48'),
      (0xfffffe000bd6bd9c,'bl','#0xfffffe000bd28280'),(0xfffffe000bd6bda8,'b.ne','#0xfffffe000bd6becc'),
      (0xfffffe000bd28308,'cbz','x8, #0xfffffe000bd28338'),(0xfffffe000bd2b520,'bl','#0xfffffe000bd6e22c'),
      (0xfffffe000bd0c940,'bl','#0xfffffe000bd28394'),(0xfffffe000bd0c9a8,'casl','w2, wzr, [x9]'),
      (0xfffffe000bd0c9c4,'bl','#0xfffffe000bd28f6c'),(0xfffffe000bd0c9e8,'casa','x2, x9, [x10]'),
      (0xfffffe000bd0ca78,'bl','#0xfffffe000bd561fc'),(0xfffffe000c519b34,'bl','#0xfffffe000bd0c8f4')]:at(a,m,op)
    # Check every CFG successor until the first X0/W0 overwrite after each sleep.
    cfg=spans['configure'];lo,hi=int(cfg['start'],16),int(cfg['end'],16)
    rows=e['configuration_sleep_returns'];assert len(rows)==8
    assert {r['sleep_call']for r in rows}=={r['sleep_call']for r in prior['configuration_sleep_sites']}
    for row in rows:
        root=int(row['sleep_call'],16)+4;seen=set();pending=[root];overwrites=[]
        while pending:
            pc=pending.pop()
            if pc in seen:continue
            seen.add(pc);assert lo<=pc<hi;i=code[pc];reads,writes=i.regs_access()
            assert not{'x0','w0'}&{i.reg_name(r)for r in reads}
            if {'x0','w0'}&{i.reg_name(r)for r in writes}:overwrites.append(hex(pc));continue
            assert i.mnemonic not in ['bl','blr','blraa','braa','ret','retab']
            if i.mnemonic=='b':pending.append(i.operands[0].imm&((1<<64)-1))
            elif i.mnemonic.startswith('b.')or i.mnemonic in ['cbz','cbnz','tbz','tbnz']:
                pending.extend([pc+4,i.operands[-1].imm&((1<<64)-1)])
            else:pending.append(pc+4)
        assert row['visited']==[hex(a)for a in sorted(seen)]and row['first_return_register_overwrites']==sorted(overwrites)
        assert row['reads_before_overwrite']==0
    assert audit()==ORACLES and sum(ORACLES.values())==3777
    assert current['validation']['aes_event_registration_increment_checks']==COUNTS
    assert current['validation']['aes_event_registration_static_scope']==e['scope']
    assert current['validation']['reports']==previous['validation']['reports']+1==398
    assert current['validation']['unavailable_external_primary_references']==previous['validation']['unavailable_external_primary_references']
    assert current['goal_status']=='active'and not any(e[n]for n in ['new_IDA_access','new_native_execution','new_IDB_mutations','full_goal_complete'])
    assert len(OWNED)==14
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:path_hygiene((BASE/p).read_bytes())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    print(json.dumps({'unchanged_manifest_entries':len(old)-len(CHANGED),'owned_physical_files':len(OWNED),'original_inputs_preserved':3,
          'new_UNSAT_queries_rechecked':47,'prior_UNSAT_queries_rechecked':68,'source_paths_SAT':7,'SAT_premise_controls':3,
          'untested_configuration_sleep_returns':8,'source_instructions':1563,'original_slots':5,
          'independent_interpretation':ORACLES,'analyst_path_literals_absent':True,'all_checks_pass':True}))


if __name__=='__main__':main()
