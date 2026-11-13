#!/usr/bin/env python3
"""Verify scratch-origin evidence, preservation and exact publication delta.

O(receipts+owned bytes+manifest+text words+queries) time and space,
30 s/query. No native API/IPC, IDA mutation or history rewrite executes.
"""
import json,subprocess
from collections import Counter
from pathlib import Path
from hashlib import sha256
from compression import zstd
import z3
from daemon_receive_tools import SOURCE,TABLE
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_lskd_vector_origin_publication import path_hygiene
from verify_daemon_iokit_result_publication import decoded_hex_hygiene
import verify_corefp_late_preparation_publication as H
import recover_daemon_scratch_pointer_origin as R
import audit_daemon_scratch_pointer_origin as A

ROOT=Path(__file__).resolve().parent;BASE=ROOT.parent
PREVIOUS='117dd9fb7c26fcae0c5f5b38fbafb9ec89d04e7f'
BASELINE_SHA='f0791adc5ead1e3228ca6023eb436bf308275aec22309cddb2a5001c10b85ba5'
CHECKS_SHA='0c0ce2d19a5fd4a1d0dafdb204fae869783719f8bdf2c2beb7a79cb7ea9efe00'
AUDIT_SHA='7be7c2f5a8a5f818b06a41a3c24b0702cb6cac3c9ab494c209d8faded51ce845'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'interface_investigation_status.md','interface_abi_report.md','foundational_triage_report.md',
         'mach_ports_report.md','obfuscated_routines_report.md','corefp_client_paths_report.md',
         'daemon_return_cache_codec_report.md','daemon_digest_output_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'daemon_scratch_pointer_origin_report.md','triage_evidence/recover_daemon_scratch_pointer_origin.py',
       'triage_evidence/audit_daemon_scratch_pointer_origin.py','triage_evidence/verify_daemon_scratch_pointer_origin_publication.py',
       'triage_evidence/daemon_scratch_pointer_origin_checks.json','triage_evidence/daemon_scratch_pointer_origin_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/daemon_scratch_pointer_origin_checks.json','triage_evidence/daemon_scratch_pointer_origin_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'cases':132,'source_visits':15144,'read_events':1800,'write_events':3144,'logical_edges':636}
INDEPENDENT={'A64_instructions_executed':29016,'register_values_checked':969216,'NZCV_values_checked':30288,
             'source_visits':30288,'read_bytes_checked':27744,'original_authenticated_edges_checked':1272,
             'write_bytes_checked':41064,'write_effects_checked':6288}

def git(*args):return subprocess.check_output(['git',*args],cwd=BASE)

def receipts():
    assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
    e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
    assert e['generator_sha256']==a['generator_sha256']==sha(R.__file__) and a['auditor_sha256']==sha(A.__file__)
    assert a['checks_sha256']==CHECKS_SHA and e['dependencies']==a['dependencies']=={n:sha(ROOT/n) for n in e['dependencies']}
    assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert e['source_regions']==R.source() and e['original_slots']==R.slots() and e['clock_helper']==R.clock_bank()
    assert e['retained_context']==R.retained_context() and e['bounded_census']==R.census()
    assert e['source_fixups']==R.verify_original_fixups({TABLE+8*j for j in R.INDICES})
    fresh=R.obligations();assert len(fresh)==len(e['source_proofs'])==a['source_queries_unsat']==9
    assert [q['label'] for q in fresh]==[q['label'] for q in e['source_proofs']]
    for row in e['source_proofs']:
        q=z3.Solver();q.set(timeout=30000);q.from_string(row['query'])
        assert row['result']=='unsat' and row['premises_nonvacuous'] and q.check()==z3.unsat
    assert e['verified_counts']==a['verified_counts']==COUNTS and a['independent_totals']==INDEPENDENT
    assert [c['configuration'] for c in e['cases']]==list(R.configurations())
    assert len(e['cases'])==132 and len(a['independent_replays'])==264
    totals=Counter();counts=Counter()
    for ix,c in enumerate(e['cases']):
        cfg=c['configuration'];s=int(cfg['SP'],16);u=int(cfg['cursor64'],16);status=int(cfg['status32'],16)
        assert int(cfg['phase32'],16)&R.PHASE_MASK==0x1366
        target=R.SPECIAL if status in [0x8b3dc650,0x8b3dc653] else R.RETURN
        assert c['boundary']['pc']==hex(target);counts.update(c['counts'])
        assert len(c['writes'])==(23 if target==R.SPECIAL else 24)
        pointer=next(w for w in c['writes'] if w['pc']=='0x10070e780')
        assert pointer['address']==hex(s+0x4a20) and int(pointer['value'],16)==(s+0xc0b0+u)&R.MASK
        for pattern,row in zip([0x35,0xca],a['independent_replays'][2*ix:2*ix+2]):
            assert row['configuration']==cfg and row['physical_backing_pattern']==pattern
            assert row['boundary']==c['boundary'] and row['pointer64']==pointer['value']
            assert row['final_cursor64']==hex((u+0x80)&R.MASK if target==R.SPECIAL else u)
            assert row['all_checks_pass'] and not row['native_target_executed'];totals.update(row['verified_counts'])
    assert {'cases':132,**dict(counts)}==COUNTS and dict(totals)==INDEPENDENT
    assert a['boundary_counts']=={'before_saved_continuation':216,'before_separate_helper':48}
    bank=e['clock_helper']['bank'];assert bank['XOR_outputs_256']==[0x14]*256 and bank['target']=='libSystem/_gettimeofday'
    assert len(a['helper_controls'])==16 and len(a['return_controls'])==6
    assert a['helper_controls']==A.helper_controls() and a['return_controls']==A.return_controls()
    assert sum(c['source_visits'] for c in a['helper_controls']+a['return_controls'])==544
    assert a['SDK_checks']==A.sdk_checks() and a['all_checks_pass']
    census=e['bounded_census'];assert census['aligned_words_checked']==3712490 and census['base_field31_words_decoded']==355213
    assert len(census['overlapping_literal_SP_accesses'])==4 and sum(h['writes'] for h in census['overlapping_literal_SP_accesses'])==1
    assert not census['unclassified_nearby_widths'] and not census['W32_unsigned_immediate_encoding_at_4a20_possible']
    assert len(e['retained_context']['prior_initializer_paths'])==12 and len(e['retained_context']['prior_caller_unknown_pointer_boundaries'])==8
    for obj in [e,a]:
        assert not any(obj[k] for k in ['retained_IOKit_caller_join_established','native_API_executed','native_daemon_kext_pairing_established','full_goal_complete'])
    report=read(BASE/'daemon_scratch_pointer_origin_report.md')
    assert all(f'| SP{j} |' in report for j in range(1,8)) and all(f'| SP-A{j} |' in report for j in range(1,8))
    assert all(f'**QG{j}**' in report for j in range(1,8))
    return e,a

def main():
    e,a=receipts();raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'))
    assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST))
    before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==8664 and len(after)==8670 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
    assert {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256'] and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
    assert new['validation']['daemon_scratch_pointer_origin_increment_checks']==COUNTS
    assert new['validation']['daemon_scratch_pointer_origin_replay_checks']==INDEPENDENT
    assert new['validation']['daemon_scratch_pointer_origin_static_scope']==e['scope']
    assert new['validation']['daemon_scratch_pointer_origin_clock_controls']==16
    assert new['validation']['daemon_scratch_pointer_origin_return_controls']==6
    assert new['validation']['daemon_scratch_pointer_origin_SDK_compile_exit']==0
    assert new['validation']['reports']==old['validation']['reports']+1==492
    assert new['goal_status']=='active' and new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    fields=extent=0
    for obj in [e,a]:
        path_hygiene(json.dumps(H.paths_in_typed_payloads(obj)).encode());n,b=decoded_hex_hygiene(obj);fields+=n;extent+=b
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
    assert delta==OWNED,delta^OWNED
    print(json.dumps({'unchanged_manifest_entries':8655,'owned_physical_files':len(OWNED),'original_inputs_preserved':3,'reports':492,
                      'source_component_cases':132,'independent_component_replays':264,'source_queries_unsat':9,
                      'clock_prefix_controls':16,'return_selector_controls':6,'A64_component_instructions_executed':29016,
                      'original_authenticated_edges_checked':1272,'register_values_checked':969216,
                      'local_control_instructions':544,'direct_pointer_writers':1,'direct_pointer_readers':3,
                      'bank_selector_bytes_checked':256,'SDK_compile_exit':0,
                      'decoded_hex_fields_path_checked':fields,'decoded_hex_bytes_path_checked':extent,
                      'retained_IOKit_caller_join_established':False,'native_API_executed':False,
                      'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':main()
