#!/usr/bin/env python3
"""Verify audit-scratch source receipts, boundaries and exact owned publication.

O(receipts+source+manifest+owned bytes+queries) time/space; 30 s/query.
No native API, IPC, allocation/free, hardware PAC or IDB mutation executes.
"""
import json,subprocess
from collections import Counter
from pathlib import Path
from hashlib import sha256
from compression import zstd
import z3
from daemon_receive_tools import SOURCE,IMAGE,TABLE,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene
from verify_daemon_iokit_result_publication import decoded_hex_hygiene
import verify_corefp_late_preparation_publication as H
import recover_daemon_audit_scratch as R
import audit_daemon_audit_scratch as A

ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='b905f9a1dcff0580434096de076a83b13bdfd050'
BASELINE_SHA='0567a810310615e58a4bdad20cc588085a655e101abf3b1b57f30800e35c619f'
CHECKS_SHA='4bd1cef91f6fa8ad80dd01563fb0bf75eeb2a8aaedeb6f1e9d5a54e4219f8489'
AUDIT_SHA='225e55b11760b26e472f53daa8e27d681b98b921c9765bd300e9f71c43033705'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'interface_investigation_status.md','interface_abi_report.md','foundational_triage_report.md',
         'mach_ports_report.md','obfuscated_routines_report.md','corefp_client_paths_report.md',
         'daemon_notification_failure_report.md','daemon_scratch_pointer_origin_report.md',
         'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'daemon_audit_scratch_report.md','triage_evidence/recover_daemon_audit_scratch.py',
       'triage_evidence/audit_daemon_audit_scratch.py','triage_evidence/verify_daemon_audit_scratch_publication.py',
       'triage_evidence/daemon_audit_scratch_checks.json','triage_evidence/daemon_audit_scratch_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/daemon_audit_scratch_checks.json','triage_evidence/daemon_audit_scratch_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'component_cases':72,'retained_cases':84,'source_visits':14632,'reads':3852,'writes':2636,'logical_edges':364}
INDEPENDENT={'register_values_checked':873856,'NZCV_values_checked':27308,'source_visits':27080,
             'read_bytes_checked':27552,'original_authenticated_edges_checked':516,'write_bytes_checked':14560}

def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)

def receipts():
    assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
    e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
    assert e['generator_sha256']==a['generator_sha256']==sha(R.__file__) and a['auditor_sha256']==sha(A.__file__)
    assert a['checks_sha256']==CHECKS_SHA and e['dependencies']==a['dependencies']=={n:sha(ROOT/n) for n in R.DEPS}
    assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert e['source_regions']==R.source() and e['bank_rules']==R.banks()
    assert len(e['bank_rules'])==2 and sum(r['inputs_checked'] for r in e['bank_rules'])==512
    assert all(len(set(r['XOR_outputs_256']))==1 for r in e['bank_rules'])
    used={int(x['address'],16) for c in e['cases']+e['retained_cases'] for x in c['trace']['source_reads'] if int(x['address'],16) in FIXUPS}
    used.update(TABLE+8*j for j in [0x2895,0x5e,0x6a1f,0x6a27,0xa424,0x7a10]);used.update(int(r['slot'],16) for r in e['bank_rules'])
    assert e['source_fixups']==R.Parent.Parent.fixups(used) and len(e['source_fixups']['records'])==8
    assert e['verified_counts']==a['verified_counts']==COUNTS and a['independent_totals']==INDEPENDENT
    assert [c['configuration'] for c in e['cases']]==list(R.configuration())
    counts=Counter();totals=Counter()
    for c in e['cases']+e['retained_cases']:
        row=c['trace'];assert not row['native_target_executed']
        assert len(row['source_frames'])==len(row['source_visits'])
        counts.update(source_visits=len(row['source_visits']),reads=len(row['source_reads']),writes=len(row['source_writes']),logical_edges=len(row['logical_edges']))
        for visit in row['source_visits']:
            assert visit['bytes_hex']==IMAGE.read(int(visit['pc'],16),4).hex() and visit['pc']!=hex(R.BSM)
    assert {'component_cases':72,'retained_cases':84,**counts}==COUNTS
    assert len(a['independent_lifts'])==228 and Counter(r['kind'] for r in a['independent_lifts'])=={'component':72,'retained':84,'alternate_component':72}
    for r in a['independent_lifts']:
        assert r['all_checks_pass'] and not r['native_target_executed'];totals.update(r['verified_counts'])
    assert dict(totals)==INDEPENDENT
    assert a['interfaces']==[A.interface(c) for c in e['cases']]
    assert Counter(r['kind'] for r in a['interfaces'])=={'null_restore':8,'pending_PID_extraction':64}
    assert a['retained_joins']==A.retained_join(e) and len(a['retained_joins'])==84
    assert all(c['unknown_cursor_bytes']==8 and c['trace']['boundary']['pc']=='0x1006e6148' for c in e['retained_cases'])
    assert len(a['alternate_controls'])==72 and all(r['same_source_control_addresses_and_calls'] and r['all_checks_pass'] for r in a['alternate_controls'])
    for c,r in zip(e['cases'],a['alternate_controls']):assert r['configuration']=={**c['configuration'],'pattern':c['configuration']['pattern']^255}
    assert [q['label'] for q in e['source_proofs']]==[q['label'] for q in R.obligations()]
    assert len(e['source_proofs'])==a['source_queries_unsat']==8
    fresh=A.copy_obligations(e);assert len(fresh)==len(a['copy_proofs'])==8
    assert [(r['source_alignment_mod8'],r['source_visits']) for r in fresh]==[(j,43 if j==0 else 86) for j in range(8)]
    for q in e['source_proofs']+a['copy_proofs']:
        s=z3.Solver();s.set(timeout=30000);s.from_string(q['query']);assert q['result']=='unsat' and s.check()==z3.unsat
    assert a['SDK_checks']==A.sdk_checks() and a['all_checks_pass']
    census=e['bounded_census'];assert census['text_bytes']==14849960 and census['aligned_words_checked']==3712490
    assert census['base_field31_words_decoded']==355213 and not census['unclassified_nearby_widths']
    assert sha256(IMAGE.read(int(census['text_start'],16),census['text_bytes'])).hexdigest()==census['text_sha256']=='94ac8c9aee57de5b820f453d310a9ffc512907a2868686849d3682d9b897597e'
    for off,n,writes in [('0x9b8',1648,365),('0x16d0',956,496)]:
        rows=[r for r in census['overlapping_literal_SP_accesses'] if r['field_offset']==off]
        assert len(rows)==n and sum(r['writes'] for r in rows)==writes
        for r in rows:assert r['bytes_hex']==IMAGE.read(int(r['pc'],16),4).hex()
    for obj in [e,a]:assert not any(obj[k] for k in ['native_API_executed','native_daemon_kext_pairing_established','full_goal_complete'])
    report=read(BASE/'daemon_audit_scratch_report.md')
    assert all(f'| AS{j} |' in report for j in range(1,7)) and all(f'| AS-A{j} |' in report for j in range(1,9))
    assert all(f'**QG{j}**' in report for j in range(1,8))
    return e,a

def main():
    e,a=receipts();raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST))
    before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==8688 and len(after)==8694 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
    assert {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256'] and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
    assert new['validation']['daemon_audit_scratch_increment_checks']==COUNTS
    assert new['validation']['daemon_audit_scratch_replay_checks']==INDEPENDENT
    assert new['validation']['daemon_audit_scratch_static_scope']==e['scope']
    assert new['validation']['daemon_audit_scratch_source_queries_unsat']==8
    assert new['validation']['daemon_audit_scratch_copy_queries_unsat']==8
    assert new['validation']['daemon_audit_scratch_SDK_compile_exit']==0
    assert new['validation']['reports']==old['validation']['reports']+1==496
    assert new['goal_status']=='active' and new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    fields=extent=0
    for obj in [e,a]:
        path_hygiene(json.dumps(H.paths_in_typed_payloads(obj)).encode());n,b=decoded_hex_hygiene(obj);fields+=n;extent+=b
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
    assert delta==OWNED,delta^OWNED
    print(json.dumps({'unchanged_manifest_entries':8679,'owned_physical_files':len(OWNED),'original_inputs_preserved':3,'reports':496,
                      'component_cases':72,'retained_cases':84,'independent_lifts':228,'source_queries_unsat':8,'copy_queries_unsat':8,
                      'original_fixup_records':8,'selector_inputs_checked':512,'SDK_compile_exit':0,
                      'decoded_hex_fields_path_checked':fields,'decoded_hex_bytes_path_checked':extent,
                      'native_API_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':main()
