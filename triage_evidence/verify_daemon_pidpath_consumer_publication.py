#!/usr/bin/env python3
"""Verify process-path source evidence and exact owned publication delta.

O(receipts+owned bytes+source+manifest+queries) time/space; 30 s/query.
No native API/IPC, allocation/free, hardware PAC or IDB mutation executes.
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
import recover_daemon_pidpath_consumer as R
import audit_daemon_pidpath_consumer as A

ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='97d7f4690f130256000bb8884007e3fa0da78013'
BASELINE_SHA='1cb55c8156bbb9540ca453fdcca9db6dd887b8cb7c6913e5622c6abc8fc7a9f7'
CHECKS_SHA='f9a105c38dec4eddc7e8dcca013946283e333b550d621e391e21a2199a044a2c'
AUDIT_SHA='0f8f49eeafd521ffec90ae7066f9eb17a9f56cb8ff2bbea4c79324df54556161'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'interface_investigation_status.md','interface_abi_report.md','foundational_triage_report.md',
         'mach_ports_report.md','obfuscated_routines_report.md','corefp_client_paths_report.md',
         'daemon_audit_scratch_report.md','daemon_notification_failure_report.md',
         'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'daemon_pidpath_consumer_report.md','triage_evidence/recover_daemon_pidpath_consumer.py',
       'triage_evidence/audit_daemon_pidpath_consumer.py','triage_evidence/verify_daemon_pidpath_consumer_publication.py',
       'triage_evidence/daemon_pidpath_consumer_checks.json','triage_evidence/daemon_pidpath_consumer_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/daemon_pidpath_consumer_checks.json','triage_evidence/daemon_pidpath_consumer_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'basis_cases':2,'PID_cases':16,'result_cases':16,'intervals':36,'source_visits':48809,'reads':4710,'writes':2464,'logical_edges':2152}
INDEPENDENT={'register_values_checked':4455072,'NZCV_values_checked':139221,'source_visits':139181,
             'read_bytes_checked':102168,'original_authenticated_edges_checked':6246,'write_bytes_checked':8024}

def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)

def receipts():
    assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
    e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
    assert e['generator_sha256']==a['generator_sha256']==sha(R.__file__) and a['auditor_sha256']==sha(A.__file__)
    assert a['checks_sha256']==CHECKS_SHA and e['dependencies']==a['dependencies']=={n:sha(ROOT/n) for n in R.DEPS}
    assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert e['source_regions']==R.source() and e['bank_rules']==R.banks() and len(e['bank_rules'])==2
    assert [r['target'] for r in e['bank_rules']]==['libSystem/_proc_pidpath',hex(R.COMPARE)]
    assert all(len(set(r['XOR_outputs_256']))==1 for r in e['bank_rules']) and sum(r['inputs_checked'] for r in e['bank_rules'])==512
    used={int(x['address'],16) for row in R.intervals(e) for x in row['source_reads'] if int(x['address'],16) in FIXUPS}
    used.update(int(r['slot'],16) for r in e['bank_rules'])
    assert e['source_fixups']==R.Env.fixups(used) and len(e['source_fixups']['records'])==17
    assert e['verified_counts']==a['verified_counts']==COUNTS and a['independent_totals']==INDEPENDENT
    assert len(e['basis_cases'])==2 and len(e['PID_cases'])==len(e['result_cases'])==16
    counts=Counter();totals=Counter()
    for row in R.intervals(e):
        assert not row['native_target_executed'] and len(row['source_frames'])==len(row['source_visits'])
        counts.update(source_visits=len(row['source_visits']),reads=len(row['source_reads']),writes=len(row['source_writes']),logical_edges=len(row['logical_edges']))
        for v in row['source_visits']:assert v['bytes_hex']==IMAGE.read(int(v['pc'],16),4).hex() and v['pc'] not in [hex(R.PATH),hex(R.Parent.BSM)]
    assert {'basis_cases':2,'PID_cases':16,'result_cases':16,'intervals':36,**counts}==COUNTS
    assert len(a['independent_lifts'])==40 and Counter(r['kind'] for r in a['independent_lifts'])=={'original':36,'alternate_PID_fill':4}
    for r in a['independent_lifts']:
        assert r['all_checks_pass'] and not r['native_target_executed'];totals.update(r['verified_counts'])
    assert dict(totals)==INDEPENDENT
    assert a['basis_interfaces']==[A.basis_interface(b) for b in e['basis_cases']]
    assert a['PID_interfaces']==[A.PID_interface(c,e['basis_cases'][c['basis_index']]) for c in e['PID_cases']]
    assert a['result_interfaces']==[A.result_interface(c,e['PID_cases'][c['PID_case_index']]) for c in e['result_cases']]
    assert Counter(r['cursor_restored'] for r in a['result_interfaces'])=={True:8,False:8}
    assert len(a['alternate_PID_controls'])==4 and all(r['identical_source_frames_effects_and_boundary'] for r in a['alternate_PID_controls'])
    parent=json.loads(read(ROOT/(R.Parent.P+'_checks.json')))
    for b in e['basis_cases']:
        original=next(c['trace'] for c in parent['cases'] if c['configuration']==b['configuration'])
        assert {k:v for k,v in b['prefix'].items() if k!='role'}=={k:v for k,v in original.items() if k!='role'}
        assert len(b['fill']['source_visits'])==22593 and len(b['fill']['source_writes'])==1026
    fresh=R.obligations();assert len(fresh)==len(e['source_proofs'])==a['source_queries_unsat']==12
    assert [r['label'] for r in fresh]==[r['label'] for r in e['source_proofs']]
    for q in e['source_proofs']:
        s=z3.Solver();s.set(timeout=30000);s.from_string(q['query']);assert q['result']=='unsat' and q['premises_nonvacuous'] and s.check()==z3.unsat
    assert a['SDK_checks']==A.sdk_checks() and a['all_checks_pass']
    for obj in [e,a]:assert not any(obj[k] for k in ['native_API_executed','native_daemon_kext_pairing_established','full_goal_complete'])
    report=read(BASE/'daemon_pidpath_consumer_report.md')
    assert all(f'| PC{j} |' in report for j in range(1,7)) and all(f'| PC-A{j} |' in report for j in range(1,9))
    assert all(f'**QG{j}**' in report for j in range(1,8))
    return e,a

def main():
    e,a=receipts();raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST))
    before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==8694 and len(after)==8700 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
    assert {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256'] and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
    assert new['validation']['daemon_pidpath_consumer_increment_checks']==COUNTS
    assert new['validation']['daemon_pidpath_consumer_replay_checks']==INDEPENDENT
    assert new['validation']['daemon_pidpath_consumer_static_scope']==e['scope']
    assert new['validation']['daemon_pidpath_consumer_source_queries_unsat']==12
    assert new['validation']['daemon_pidpath_consumer_SDK_compile_exit']==0
    assert new['validation']['reports']==old['validation']['reports']+1==497
    assert new['goal_status']=='active' and new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    fields=extent=0
    for obj in [e,a]:
        path_hygiene(json.dumps(H.paths_in_typed_payloads(obj)).encode());n,b=decoded_hex_hygiene(obj);fields+=n;extent+=b
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
    assert delta==OWNED,delta^OWNED
    print(json.dumps({'unchanged_manifest_entries':8685,'owned_physical_files':len(OWNED),'original_inputs_preserved':3,'reports':497,
                      'original_intervals':36,'independent_lifts':40,'source_queries_unsat':12,
                      'original_fixup_records':17,'selector_inputs_checked':512,'SDK_compile_exit':0,
                      'zero_bytes_per_basis':1024,'nonpositive_cursor_restorations':8,'positive_continuations':8,
                      'decoded_hex_fields_path_checked':fields,'decoded_hex_bytes_path_checked':extent,
                      'native_API_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':main()
