#!/usr/bin/env python3
"""Verify daemon notification evidence, historical scope and exact owned delta.

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
import recover_daemon_notification_registration as R
import audit_daemon_notification_registration as A

ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='31b5ad723657efde68926203bf52096ac3990488'
BASELINE_SHA='fb8092808a0bc15a34ea2d0da734afca8afd848517462f1ab8b7071a268782d9'
CHECKS_SHA='529c75b8010fac82b87afcf276533fb5865f40d0bcac519c9d7afa20a483071d'
AUDIT_SHA='eb4cc790c9f4b20f167edd667c56ec3008ab69a946c2f810ec44251ee09ece36'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'interface_investigation_status.md','interface_abi_report.md','foundational_triage_report.md',
         'mach_ports_report.md','obfuscated_routines_report.md','corefp_client_paths_report.md',
         'daemon_environment_outputs_report.md','notify_ipc_report.md','adid_notification_report.md',
         'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'daemon_notification_registration_report.md','triage_evidence/recover_daemon_notification_registration.py',
       'triage_evidence/audit_daemon_notification_registration.py','triage_evidence/verify_daemon_notification_registration_publication.py',
       'triage_evidence/daemon_notification_registration_checks.json','triage_evidence/daemon_notification_registration_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/daemon_notification_registration_checks.json','triage_evidence/daemon_notification_registration_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'cases':80,'intervals':448,'source_visits':33648,'read_events':9224,'write_events':4016,'logical_edges':408,'API_return_premises':296}
INDEPENDENT={'register_values_checked':2182144,'NZCV_values_checked':68192,'source_visits':67296,
             'write_bytes_checked':60000,'read_bytes_checked':106368,'original_authenticated_edges_checked':816}
INTERFACES={'failure_before_ready':48,'registration_and_baseline_success':16,'already_ready':8,'exit_callback':8}

def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)

def reference_context(e):
    path=ROOT/'adid_notification_contracts.json'
    assert sha(path)=='277b300a5bab70b2832dcd746be9f7c3dd32e77824930e57dc5a184a3c2114bc'
    ref=json.loads(read(path))
    assert ref['provider_thin_sha256']=='ad149b360cbd98c1cb6d1ce820125e944bcaaf1758c2633d2588e159cfc15fcf'
    for image in ['client','provider']:
        rows=[r for r in ref['original_names'] if r['image']==image]
        assert [r['name'] for r in rows]==R.NAMES
        assert [r['bytes'] for r in rows]==[r['bytes_hex'] for r in e['notification_names']]
    q=ref['proofs'][0];assert q['path']=='adid_notification_name_class64.smt2' and q['result']=='unsat'
    assert sha(ROOT/q['path'])==q['sha256']=='ac6fd95e5427da43f55c4324cce75cd3b083fab603d6a73ec8a0cb73ffb30e9d'
    s=z3.Solver();s.set(timeout=30000);s.from_string(read(ROOT/q['path']));assert s.check()==z3.unsat
    current=Path('/System/Library/PrivateFrameworks/CoreADI.framework/adid')
    assert size(current)==9797952 and sha(current)=='9c872e64548288f7d1a9db5e2dbd97311e30b4df5745f52936ae277c80a4abe1'
    from adid_reader import SOURCE_SHA
    assert SOURCE_SHA=='58eeb13dade3e1867641345b38961344fe53e6319928a1503bdb3315681fe929' and sha(current)!=SOURCE_SHA
    parent=json.loads(read(ROOT/'daemon_environment_outputs_checks.json'))
    assert parent['source_sha256']==e['source_sha256']
    q=next(q for q in parent['source_proofs'] if q['label']=='complete_negative_argument_class_tests')
    s=z3.Solver();s.set(timeout=30000);s.from_string(q['query']);assert q['result']=='unsat' and s.check()==z3.unsat
    return {'exact_historical_name_matches':6,'historical_class_queries_unsat':1,
            'parent_class_query_rechecked':True,'current_provider_matches_historical_image':False}

def receipts():
    assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
    e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
    assert e['generator_sha256']==a['generator_sha256']==sha(R.__file__) and a['auditor_sha256']==sha(A.__file__)
    assert a['checks_sha256']==CHECKS_SHA and e['dependencies']==a['dependencies']=={n:sha(ROOT/n) for n in e['dependencies']}
    assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert e['source_regions']==R.source() and e['bank_rules']==R.banks()
    assert len(e['bank_rules'])==20 and sum(r['inputs_checked'] for r in e['bank_rules'])==5120
    assert all(len(set(r['XOR_outputs_256']))==1 for r in e['bank_rules'])
    assert len(e['source_pool'])==781
    for pc,row in e['source_pool'].items():
        i=next(A.Parent.DEC.disasm(IMAGE.read(int(pc,16),4),int(pc,16)))
        assert row=={'pc':pc,'bytes_hex':bytes(i.bytes).hex(),'mnemonic':i.mnemonic,'operands':i.op_str}
    used={int(x['address'],16) for c in e['cases'] for row in A.intervals(c) for x in row['source_reads']
          if x['size_bytes']==8 and int(x['address'],16) in FIXUPS}
    used.update(int(x['slot'],16) for x in e['bank_rules'])
    used.update(int(q[k],16) for q in e['source_proofs'] for k in ['zero_slot','nonzero_slot'] if k in q)
    assert e['source_fixups']==R.Parent.fixups(used) and len(e['source_fixups']['records'])==44
    for row in e['notification_names']:
        assert bytes.fromhex(row['bytes_hex'])==row['name'].encode()+b'\0'
        assert row['bytes_hex']==IMAGE.read(int(row['address'],16),len(row['name'])+1).hex()
    fresh=R.obligations(e['cases']);assert len(fresh)==len(e['source_proofs'])==a['source_queries_unsat']==9
    assert [q['label'] for q in fresh]==[q['label'] for q in e['source_proofs']]
    for row in e['source_proofs']:
        q=z3.Solver();q.set(timeout=30000);q.from_string(row['query'])
        assert row['result']=='unsat' and row['premises_nonvacuous'] and q.check()==z3.unsat
    assert e['verified_counts']==a['verified_counts']==COUNTS and a['independent_totals']==INDEPENDENT
    assert [c['configuration'] for c in e['cases']]==list(R.configurations())
    assert len(e['cases'])==80 and len(a['independent_lifts'])==896 and len(a['alternate_controls'])==80
    assert a['interfaces']==[A.interface(c) for c in e['cases']]
    assert dict(Counter(r['kind'] for r in a['interfaces']))==INTERFACES
    totals=Counter();counts=Counter();cursor=0
    for ix,c in enumerate(e['cases']):
        cfg=c['configuration'];assert not c['native_target_executed']
        rows=A.intervals(c)
        for row in rows:
            assert len(row['source_visits'])==len(row['source_frames']) and not row['native_target_executed']
            counts.update({'intervals':1,'source_visits':len(row['source_visits']),'read_events':len(row['source_reads']),
                           'write_events':len(row['source_writes']),'logical_edges':len(row['logical_edges'])})
        counts['API_return_premises']+=len(c['API_return_premises'])
        for event,before,after in zip(c['API_return_premises'],c['intervals'],c['intervals'][1:]):
            assert event['call_site']==before['boundary']['pc'] and event['continuation_PC']==after['entry_PC']
            assert event['return_registers31']==after['entry_registers31'] and event['return_NZCV']==after['entry_NZCV']
            assert event['return_registers31'][18:30]==before['boundary']['registers31'][18:30]
            assert not event['native_API_executed'] and event['ABI_return_and_output_premise']
        assert a['alternate_controls'][ix]=={'configuration':cfg,'alternate_configuration':A.alternate(cfg),
                                           'same_source_control_and_stores':True,'unread_baseline_and_atexit_results_do_not_change_control':True}
        for variant in [cfg,A.alternate(cfg)]:
            for j,source in enumerate(rows):
                row=a['independent_lifts'][cursor];cursor+=1
                assert row['configuration']==variant and row['boundary']==source['boundary']['pc']
                assert row['interval_index']==j and row['role']==source['role'] and row['unknown_origins_retained']==0
                assert row['all_checks_pass'] and not row['native_target_executed'];totals.update(row['verified_counts'])
    assert cursor==896 and {'cases':80,**counts}==COUNTS and dict(totals)==INDEPENDENT
    assert a['SDK_checks']==A.sdk_checks() and a['all_checks_pass']
    for obj in [e,a]:assert not any(obj[k] for k in ['native_API_executed','native_daemon_kext_pairing_established','full_goal_complete'])
    report=read(BASE/'daemon_notification_registration_report.md')
    assert all(f'| NR{j} |' in report and f'| NR-A{j} |' in report for j in range(1,9))
    assert all(f'**QG{j}**' in report for j in range(1,8))
    reference=reference_context(e)
    return e,a,reference

def main():
    e,a,reference=receipts();raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST))
    before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==8676 and len(after)==8682 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
    assert {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256'] and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
    assert new['validation']['daemon_notification_registration_increment_checks']==COUNTS
    assert new['validation']['daemon_notification_registration_replay_checks']==INDEPENDENT
    assert new['validation']['daemon_notification_registration_static_scope']==e['scope']
    assert new['validation']['daemon_notification_registration_source_queries_unsat']==9
    assert new['validation']['daemon_notification_registration_SDK_compile_exit']==0
    assert new['validation']['reports']==old['validation']['reports']+1==494
    assert new['goal_status']=='active' and new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    fields=extent=0
    for obj in [e,a]:
        path_hygiene(json.dumps(H.paths_in_typed_payloads(obj)).encode());n,b=decoded_hex_hygiene(obj);fields+=n;extent+=b
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
    assert delta==OWNED,delta^OWNED
    print(json.dumps({'unchanged_manifest_entries':8666,'owned_physical_files':len(OWNED),'original_inputs_preserved':3,'reports':494,
                      'source_cases':80,'source_intervals':448,'explicit_API_return_premises':296,'independent_lifts':896,
                      'source_queries_unsat':9,'original_fixup_records':44,'source_instructions':781,
                      'original_authenticated_edges_checked':816,'register_values_checked':2182144,
                      'bank_rules':20,'selector_inputs_checked':5120,'SDK_compile_exit':0,'interfaces':INTERFACES,
                      **reference,'decoded_hex_fields_path_checked':fields,'decoded_hex_bytes_path_checked':extent,
                      'native_API_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':main()
