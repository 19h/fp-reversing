#!/usr/bin/env python3
"""Verify environment-helper evidence and its exact owned publication delta.

O(receipts+owned bytes+manifest+source+queries) time/space excluding solver cost;
30 s/query. No native API/IPC, allocation/free, PAC or IDA mutation executes.
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
import recover_daemon_environment_outputs as R
import audit_daemon_environment_outputs as A

ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='4142d66bf16bcab41f3a026cf64185c21e73ca95'
BASELINE_SHA='d380ca060ddd5c0dedcdf84170fce52c2a90d206ad8ed27b6d5bb6caa21e1562'
CHECKS_SHA='36c80ced7ceff7163fbece778034f95054c54e3c711f2be20e4c12dcb0ce11c3'
AUDIT_SHA='d5c94edec96d8d0db23e160a87db88344d667274d17a9f44685e63b19ca14b0f'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'interface_investigation_status.md','interface_abi_report.md','foundational_triage_report.md',
         'mach_ports_report.md','obfuscated_routines_report.md','corefp_client_paths_report.md',
         'daemon_scratch_pointer_origin_report.md','notify_ipc_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'daemon_environment_outputs_report.md','triage_evidence/recover_daemon_environment_outputs.py',
       'triage_evidence/audit_daemon_environment_outputs.py','triage_evidence/verify_daemon_environment_outputs_publication.py',
       'triage_evidence/daemon_environment_outputs_checks.json','triage_evidence/daemon_environment_outputs_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/daemon_environment_outputs_checks.json','triage_evidence/daemon_environment_outputs_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'cases':72,'source_visits':22730,'read_events':5364,'write_events':3639,'logical_edges':417}
INDEPENDENT={'register_values_checked':1459328,'NZCV_values_checked':45604,'write_bytes_checked':54664,
             'source_visits':45460,'read_bytes_checked':61606,'original_authenticated_edges_checked':708,
             'unknown_copy_bytes_checked':768}
INTERFACES={'notify_check':32,'cache_hit_clock':16,'null_output_rejection':15,'allocation24':9}

def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)

def receipts():
    assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
    e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
    assert e['generator_sha256']==a['generator_sha256']==sha(R.__file__) and a['auditor_sha256']==sha(A.__file__)
    assert a['checks_sha256']==CHECKS_SHA and e['dependencies']==a['dependencies']=={n:sha(ROOT/n) for n in e['dependencies']}
    assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert e['source_regions']==R.source() and e['bank_rules']==R.banks()
    assert len(e['bank_rules'])==15 and sum(r['inputs_checked'] for r in e['bank_rules'])==3840
    assert all(len(set(r['XOR_outputs_256']))==1 for r in e['bank_rules'])
    assert len(e['source_pool'])==579
    for pc,row in e['source_pool'].items():
        i=next(A.DEC.disasm(IMAGE.read(int(pc,16),4),int(pc,16)))
        assert row=={'pc':pc,'bytes_hex':bytes(i.bytes).hex(),'mnemonic':i.mnemonic,'operands':i.op_str}
    used={int(x['address'],16) for c in e['cases'] for x in c['source_reads'] if x['size_bytes']==8 and int(x['address'],16) in FIXUPS}
    used.update(int(x['slot'],16) for x in e['bank_rules'])
    assert e['source_fixups']==R.fixups(used) and len(e['source_fixups']['records'])==38
    returned=R.fixups({0x101076e40,0x101076f70})['records']
    assert [r['decoded_target'] for r in returned]==['0x1006cdaf8','0x100709868']
    assert all(r['diversity']=='0x4113' and r['key']=='IA' and r['address_diversity']==0 for r in returned)
    fresh=R.obligations();assert len(fresh)==len(e['source_proofs'])==a['source_queries_unsat']==12
    assert [q['label'] for q in fresh]==[q['label'] for q in e['source_proofs']]
    for row in e['source_proofs']:
        q=z3.Solver();q.set(timeout=30000);q.from_string(row['query'])
        assert row['result']=='unsat' and row['premises_nonvacuous'] and q.check()==z3.unsat
    assert e['verified_counts']==a['verified_counts']==COUNTS and a['independent_totals']==INDEPENDENT
    assert [c['configuration'] for c in e['cases']]==list(R.configurations())
    assert len(e['cases'])==72 and len(a['independent_lifts'])==144 and len(a['paired_backing_controls'])==72
    assert a['interfaces']==[A.interface(c) for c in e['cases']]
    assert dict(Counter(r['kind'] for r in a['interfaces']))==INTERFACES
    totals=Counter();counts=Counter();copies=0
    for ix,c in enumerate(e['cases']):
        cfg=c['configuration'];counts.update(c['counts'])
        assert len(c['source_visits'])==len(c['source_frames'])==c['counts']['source_visits']
        assert not c['native_target_executed']
        if cfg['kind']=='caller':assert c['entry_registers31'][0]=='0x0'
        if c['unknown_copy_effects']:
            assert cfg['kind']=='caller' and cfg['cache_mode']=='miss' and cfg['flag8']&1==0
            assert len(c['unknown_copy_effects'])==3
            for row,(pc,(src,dst)) in zip(c['unknown_copy_effects'],R.COPIES.items()):
                f=int(c['caller_SP'],16)-0x4a0
                assert row=={'load_pc':hex(pc),'store_pc':hex(pc+4),'source':hex(f+src),'destination':hex(f+dst),
                             'size_bytes':8,'origin_offsets':list(range(src,src+8)),'known_mask_hex':'00'*8}
                w=next(w for w in c['source_writes'] if w['pc']==hex(pc+4))
                assert w['unknown_origins']==row['origin_offsets'] and w['known_mask_hex']=='00'*8
            copies+=3
        paired=a['paired_backing_controls'][ix]
        assert paired=={'configuration':cfg,'alternate_pattern':cfg['pattern']^255,
                        'same_source_control_and_boundary':True,'unknown_copies_remain_undefined':True}
        for alt,row in enumerate(a['independent_lifts'][2*ix:2*ix+2]):
            want={**cfg,'pattern':cfg['pattern']^(255 if alt else 0)}
            assert row['configuration']==want and row['boundary']==c['boundary']['pc']
            assert row['unknown_origins_retained']==(24 if c['unknown_copy_effects'] else 0)
            assert row['all_checks_pass'] and not row['native_target_executed'];totals.update(row['verified_counts'])
    assert copies==24 and {'cases':72,**counts}==COUNTS and dict(totals)==INDEPENDENT
    assert a['SDK_checks']==A.sdk_checks() and a['all_checks_pass']
    for obj in [e,a]:
        assert not any(obj[k] for k in ['native_API_executed','native_daemon_kext_pairing_established','full_goal_complete'])
    report=read(BASE/'daemon_environment_outputs_report.md')
    assert all(f'| EO{j} |' in report and f'| EO-A{j} |' in report for j in range(1,9))
    assert all(f'**QG{j}**' in report for j in range(1,8))
    return e,a

def main():
    e,a=receipts();raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST))
    before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==8670 and len(after)==8676 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
    assert {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256'] and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
    assert new['validation']['daemon_environment_outputs_increment_checks']==COUNTS
    assert new['validation']['daemon_environment_outputs_replay_checks']==INDEPENDENT
    assert new['validation']['daemon_environment_outputs_static_scope']==e['scope']
    assert new['validation']['daemon_environment_outputs_source_queries_unsat']==12
    assert new['validation']['daemon_environment_outputs_SDK_compile_exit']==0
    assert new['validation']['reports']==old['validation']['reports']+1==493
    assert new['goal_status']=='active' and new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    fields=extent=0
    for obj in [e,a]:
        path_hygiene(json.dumps(H.paths_in_typed_payloads(obj)).encode());n,b=decoded_hex_hygiene(obj);fields+=n;extent+=b
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
    assert delta==OWNED,delta^OWNED
    print(json.dumps({'unchanged_manifest_entries':8661,'owned_physical_files':len(OWNED),'original_inputs_preserved':3,'reports':493,
                      'source_component_cases':72,'independent_lifts':144,'source_queries_unsat':12,
                      'original_fixup_records':38,'separate_return_selector_slots':2,'source_instructions':579,
                      'original_authenticated_edges_checked':708,'register_values_checked':1459328,
                      'bank_rules':15,'bank_selector_bytes_checked':3840,'undefined_copy_bytes_checked':768,'SDK_compile_exit':0,
                      'frontiers':INTERFACES,'decoded_hex_fields_path_checked':fields,'decoded_hex_bytes_path_checked':extent,
                      'native_API_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':main()
