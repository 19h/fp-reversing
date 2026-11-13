#!/usr/bin/env python3
"""Verify notification failure evidence, original source and owned publication.

O(receipts+owned bytes+manifest+source+queries) time/space excluding solver
cost; 30 s/query. No native API/IPC, allocation/free, PAC or IDA mutation.
"""
import json,subprocess
from collections import Counter
from pathlib import Path
from hashlib import sha256
from compression import zstd
import z3
from daemon_receive_tools import SOURCE,IMAGE,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene
from verify_daemon_iokit_result_publication import decoded_hex_hygiene
import verify_corefp_late_preparation_publication as H
import recover_daemon_notification_failure as R
import audit_daemon_notification_failure as A

ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='8274c30e61df6cc70b455d60d4cc4cfb3d14d026'
BASELINE_SHA='90ec327cd50f573c9fd0d39baabdf7b486a693679c93fee7b24c343c676b29c8'
CHECKS_SHA='43ccf071ac4cfa7074d991ef7667d48383a5d93ba25fd8e8ca5e5ee0cf596d9c'
AUDIT_SHA='d600bd67ce77206c8bd2b21dde226b0ba712514ee699be6c33697131ab02498c'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'interface_investigation_status.md','interface_abi_report.md','foundational_triage_report.md',
         'mach_ports_report.md','obfuscated_routines_report.md','corefp_client_paths_report.md',
         'daemon_environment_outputs_report.md','daemon_notification_registration_report.md',
         'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'daemon_notification_failure_report.md','triage_evidence/recover_daemon_notification_failure.py',
       'triage_evidence/audit_daemon_notification_failure.py','triage_evidence/verify_daemon_notification_failure_publication.py',
       'triage_evidence/daemon_notification_failure_checks.json','triage_evidence/daemon_notification_failure_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/daemon_notification_failure_checks.json','triage_evidence/daemon_notification_failure_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'cases':84,'registration_return_premises':204,'free_return_premises':72,'intervals':612,
        'source_visits':45972,'read_events':11952,'write_events':4764,'logical_edges':1008}
INDEPENDENT={'register_values_checked':2981376,'NZCV_values_checked':93168,'write_bytes_checked':70752,
             'source_visits':91944,'read_bytes_checked':144096,'original_authenticated_edges_checked':1680}

def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)

def receipts():
    assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
    e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
    assert e['generator_sha256']==a['generator_sha256']==sha(R.__file__) and a['auditor_sha256']==sha(A.__file__)
    assert a['checks_sha256']==CHECKS_SHA and e['dependencies']==a['dependencies']=={n:sha(ROOT/n) for n in e['dependencies']}
    assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert e['source_regions']==R.source() and e['bank_rules']==R.banks()
    assert len(e['bank_rules'])==4 and sum(r['inputs_checked'] for r in e['bank_rules'])==1024
    assert all(len(set(r['XOR_outputs_256']))==1 and r['target']=='libSystem/_free' for r in e['bank_rules'])
    assert len(e['source_pool'])==848
    for pc,row in e['source_pool'].items():
        i=next(A.RegAudit.Parent.DEC.disasm(IMAGE.read(int(pc,16),4),int(pc,16)))
        assert row=={'pc':pc,'bytes_hex':bytes(i.bytes).hex(),'mnemonic':i.mnemonic,'operands':i.op_str}
    used={int(x['address'],16) for c in e['cases'] for row in R.intervals(c) for x in row['source_reads']
          if x['size_bytes']==8 and int(x['address'],16) in FIXUPS}
    used.update(int(x['slot'],16) for x in e['bank_rules'])
    used.update(int(q[k],16) for q in e['source_proofs'] for k in ['zero_slot','nonzero_slot'] if k in q)
    assert e['source_fixups']==R.Parent.fixups(used) and len(e['source_fixups']['records'])==50
    alternative=R.Parent.fixups({0x101076f70})['records'][0]
    assert alternative['decoded_target']=='0x100709868' and alternative['diversity']=='0x4113' and alternative['key']=='IA'
    fresh=R.obligations();assert len(fresh)==len(e['source_proofs'])==a['source_queries_unsat']==12
    assert [q['label'] for q in fresh]==[q['label'] for q in e['source_proofs']]
    for row in e['source_proofs']:
        q=z3.Solver();q.set(timeout=30000);q.from_string(row['query'])
        assert row['result']=='unsat' and row['premises_nonvacuous'] and q.check()==z3.unsat
    parent=json.loads(read(ROOT/'daemon_notification_registration_checks.json'))
    gates=[q for q in parent['source_proofs'] if q['label'].startswith('zero_only_status_gate_')];assert len(gates)==6
    for row in gates:
        q=z3.Solver();q.set(timeout=30000);q.from_string(row['query']);assert row['result']=='unsat' and q.check()==z3.unsat
    assert e['verified_counts']==a['verified_counts']==COUNTS and a['independent_totals']==INDEPENDENT
    assert [c['configuration'] for c in e['cases']]==list(R.configurations())
    assert len(e['cases'])==84 and len(a['independent_lifts'])==1224 and len(a['alternate_controls'])==84
    assert a['interfaces']==[A.interface(c) for c in e['cases']]
    assert Counter(r['kind'] for r in a['interfaces'])=={'retained_failure':48,'cleanup_control':36}
    assert sum(len(r['header_rewrites']) for r in a['interfaces'])==48
    totals=Counter();counts=Counter();cursor=0
    for ix,c in enumerate(e['cases']):
        cfg=c['configuration'];assert not c['native_target_executed'] and not c['uninterrupted_provider_join_established']
        rows=R.intervals(c)
        for row in rows:
            assert len(row['source_visits'])==len(row['source_frames']) and not row['native_target_executed']
            counts.update({'intervals':1,'source_visits':len(row['source_visits']),'read_events':len(row['source_reads']),
                           'write_events':len(row['source_writes']),'logical_edges':len(row['logical_edges'])})
        counts['registration_return_premises']+=len(c['registration_return_premises']);counts['free_return_premises']+=len(c['free_return_premises'])
        for key,sequence in [('registration_return_premises',c['registration_intervals']),('free_return_premises',c['cleanup_intervals'])]:
            assert len(sequence)==len(c[key])+1
            for event,before,after in zip(c[key],sequence,sequence[1:]):
                assert event['call_site']==before['boundary']['pc'] and event['continuation_PC']==after['entry_PC']
                assert event['return_registers31']==after['entry_registers31'] and event['return_NZCV']==after['entry_NZCV']
                assert event['return_registers31'][18:30]==before['boundary']['registers31'][18:30]
                assert not event['native_API_executed'] and event['ABI_return_and_output_premise']
                if key=='free_return_premises':
                    assert event['void_return_premise'] and 'return32'not in event
                    assert event['return_registers31'][0]==event['unspecified_X0_fixture']
        assert c['registration_intervals'][-1]['boundary']['registers31']==c['cleanup_intervals'][0]['entry_registers31']
        assert c['registration_intervals'][-1]['boundary_NZCV']==c['cleanup_intervals'][0]['entry_NZCV']
        assert len(c['cleanup_entry_premises'])==(2 if cfg['kind']=='cleanup_control' else 0)
        for j,premise in enumerate(c['cleanup_entry_premises']):
            raw=R.RECORDS[j] if cfg['record_states'][j] else 0
            assert premise['raw_record']==hex(raw) and premise['encoded64']==hex((raw+R.SENTINELS[j])&((1<<64)-1))
            assert premise['separate_entry_premise']
        assert a['alternate_controls'][ix]=={'configuration':cfg,'alternate_configuration':A.alternate(cfg),
                                           'same_source_control_stores_and_calls':True,'helper_and_caller_result_preserved':True}
        for variant in [cfg,A.alternate(cfg)]:
            for j,source in enumerate(rows):
                row=a['independent_lifts'][cursor];cursor+=1
                assert row['configuration']==variant and row['boundary']==source['boundary']['pc']
                assert row['interval_index']==j and row['role']==source['role'] and row['unknown_origins_retained']==0
                assert row['all_checks_pass'] and not row['native_target_executed'];totals.update(row['verified_counts'])
    assert cursor==1224 and {'cases':84,**counts}==COUNTS and dict(totals)==INDEPENDENT
    assert a['sentinel_slice_nonclobber']==A.nonclobber() and len(a['sentinel_slice_nonclobber'])==31
    assert a['SDK_checks']==A.sdk_checks() and a['all_checks_pass']
    for obj in [e,a]:assert not any(obj[k] for k in ['native_API_executed','native_daemon_kext_pairing_established','full_goal_complete'])
    report=read(BASE/'daemon_notification_failure_report.md')
    assert all(f'| NF{j} |' in report and f'| NF-A{j} |' in report for j in range(1,9))
    assert all(f'**QG{j}**' in report for j in range(1,8))
    return e,a

def main():
    e,a=receipts();raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST))
    before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==8682 and len(after)==8688 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
    assert {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256'] and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
    assert new['validation']['daemon_notification_failure_increment_checks']==COUNTS
    assert new['validation']['daemon_notification_failure_replay_checks']==INDEPENDENT
    assert new['validation']['daemon_notification_failure_static_scope']==e['scope']
    assert new['validation']['daemon_notification_failure_source_queries_unsat']==12
    assert new['validation']['daemon_notification_failure_SDK_compile_exit']==0
    assert new['validation']['reports']==old['validation']['reports']+1==495
    assert new['goal_status']=='active' and new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    fields=extent=0
    for obj in [e,a]:
        path_hygiene(json.dumps(H.paths_in_typed_payloads(obj)).encode());n,b=decoded_hex_hygiene(obj);fields+=n;extent+=b
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
    assert delta==OWNED,delta^OWNED
    print(json.dumps({'unchanged_manifest_entries':8673,'owned_physical_files':len(OWNED),'original_inputs_preserved':3,'reports':495,
                      'source_cases':84,'source_intervals':612,'independent_lifts':1224,'source_queries_unsat':12,
                      'parent_status_gate_queries_unsat':6,'original_fixup_records':50,'alternate_caller_slots_checked':1,
                      'source_instructions':848,'original_authenticated_edges_checked':1680,'register_values_checked':2981376,
                      'selector_inputs_checked':1024,'source_header_rewrites':48,'source_payload_free_requests':24,
                      'source_record_free_requests':48,'sentinel_nonclobber_instructions':31,'SDK_compile_exit':0,
                      'helper_return64':'0x0','caller_target':'0x1006cdaf8',
                      'decoded_hex_fields_path_checked':fields,'decoded_hex_bytes_path_checked':extent,
                      'native_API_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':main()
