#!/usr/bin/env python3
"""Verify descriptor/metadata receipts, source contracts and exact publication.

O(receipts+visits+owned bytes+manifest+query DAG) time/storage;30 s/query.
No native target operation executes; SDK/library and caller epochs are premises.
"""
import json
from hashlib import sha256
from collections import Counter
from compression import zstd
import z3
from daemon_receive_tools import SOURCE,IMAGE,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_daemon_payload_mix_publication import ROOT,BASE,git,hygiene,path_hygiene
from verify_daemon_second_mix_publication import canonical_expression,check_query_comparison
import recover_daemon_state_file_metadata as R
import audit_daemon_state_file_metadata as A

PREVIOUS='850f95498fc3fb47018b4207e51040fd6c175c7b'
BASELINE_SHA='173be3ff729ad39f1840cc58ee2f74132111e46ebd34ac9121004d91690b9472'
CHECKS_SHA='5b3c1afdb63249ce5a6ea5ba39701b2a9010ba2e1ce259284fbfb1652d2e6c23';AUDIT_SHA='85528d5d16ef6269ec172e5481bcb9872c3a6145e9b41123c25f0256f7d1f51c'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'mach_ports_report.md','interface_abi_report.md','interface_investigation_status.md',
         'obfuscated_routines_report.md','foundational_triage_report.md','corefp_client_paths_report.md',
         'daemon_state_file_admission_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'daemon_state_file_metadata_report.md','triage_evidence/recover_daemon_state_file_metadata.py',
       'triage_evidence/audit_daemon_state_file_metadata.py','triage_evidence/verify_daemon_state_file_metadata_publication.py',
       'triage_evidence/daemon_state_file_metadata_checks.json','triage_evidence/daemon_state_file_metadata_audit.json',
       'triage_evidence/daemon_state_file_metadata_abi.c'}
ARCHIVES={MANIFEST,'triage_evidence/daemon_state_file_metadata_checks.json','triage_evidence/daemon_state_file_metadata_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'contexts': 256, 'open_cases': 1280, 'errno_accessor_cases': 256, 'errno_word_cases': 1024, 'fstat_cases': 768, 'size_cases': 1536, 'close_cases': 1536, 'intervals': 6400, 'source_visits': 680960, 'reads': 186368, 'writes': 32256, 'logical_edges': 30208, 'source_calls': 2560}
INDEPENDENT={'register_values_checked': 21995520, 'NZCV_values_checked': 687360, 'vector_register_values_checked': 21995520, 'source_visits': 680960, 'write_bytes_checked': 197632, 'read_bytes_checked': 1266688, 'original_authenticated_edges_checked': 19968}
MODEL={'opaque_output_span_bytes_checked': 124928, 'API_return_joins_checked': 3840, 'open_signed_return_partitions_checked': 1280, 'descriptor_argument_forwards_checked': 768, 'existing_borrowed_errno_pointer_returns_checked': 256, 'supplied_output_word_bytes_checked': 16384, 'output_word_state_joins_checked': 2560, 'raw_status_record_stores_checked': 7680, 'common_wrapper_allocation_requests_checked': 2560, 'errno_word_partitions_checked': 1024, 'fstat_return_partitions_checked': 768, 'stat_output_bytes_invalidated_checked': 110592, 'failure_close_descriptor_requests_checked': 512, 'size_word_to_allocation_requests_checked': 1536, 'supplied_size_bytes_checked': 12288, 'close_return_continuations_checked': 1536, 'foreign_owner_and_generated_stream_preservation_intervals_checked': 6400}

def receipts():
    assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
    e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
    assert e['generator_sha256']==a['generator_sha256']==sha(R.__file__) and a['auditor_sha256']==sha(A.__file__) and a['checks_sha256']==CHECKS_SHA
    assert e['dependencies']==a['dependencies']=={n:sha(ROOT/n) for n in R.DEPS} and a['auditor_dependencies']=={n:sha(ROOT/n) for n in A.AD}
    assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert e['verified_counts']==a['verified_counts']==COUNTS and a['independent_totals']==INDEPENDENT and a['model_checks']==MODEL and a['all_checks_pass']
    assert e['source_regions']==R.source() and e['SDK_checks']==R.sdk_checks() and e['SDK_checks']['source']==read(ROOT/'daemon_state_file_metadata_abi.c')
    assert 'ldr\tx0, [x0, #96]' in e['SDK_checks']['assembly'] and '_malloc' in e['SDK_checks']['assembly']
    parent=json.loads(read(ROOT/(R.Parent.P+'_checks.json')));h=Counter();counts=Counter();total=Counter();model=Counter();used=set();keys=set();n=0
    for pc in parent['contexts']:
        for op in pc['open_cases']:
            calls=[v for p in op['intervals_packed'] for v in R.unpack(p)['source_calls'] if v['target'] in {'0x10043d044','0x100d3e6d8','0x100d3d658'}]
            assert [(v['pc'],v['target'],v['modifier'],v['arguments8'][0]) for v in calls]==[
                ('0x100689800','0x10043d044','0xa499','0x6800070db8'),
                ('0x10043d324','0x100d3e6d8','0xc037','0x68000600b8'),
                ('0x100d3e940','0x100d3d658','0x7dde','0x68000600b8')]
            assert [calls[1]['arguments8'][1],calls[2]['arguments8'][1]]==['0x68000600a8','0x680005ffd0']
    assert len(e['contexts'])==len(a['contexts'])==256
    for c,ac in zip(e['contexts'],a['contexts']):
        key=tuple(c[k] for k in ['parent_context_index','parent_open_case_index','ABI_clobber_pattern']);assert key not in keys;keys.add(key)
        assert tuple(ac[k] for k in ['parent_context_index','parent_open_case_index','ABI_clobber_pattern'])==key and ac['all_checks_pass']
        ct=A.contract(c,parent['contexts'][key[0]]['open_cases'][key[1]]);assert ct==ac['contract'];model.update(ct['model_checks'])
        rows=list(R.context_intervals(c));assert len(rows)==len(ac['independent_lifts'])==25;local=Counter()
        for row,lift in zip(rows,ac['independent_lifts']):
            n+=1;h.update(hygiene(row));counts.update(R.rc(row));local.update(lift['verified_counts'])
            assert not row['native_target_executed'] and lift['all_checks_pass'] and not lift['native_target_executed']
            assert len(row['source_visits'])==len(row['source_frames'])==lift['verified_counts'].get('source_visits',0) and row['boundary']['pc']==lift['boundary']
            for visit,frame in zip(row['source_visits'],row['source_frames']):
                assert visit['bytes_hex']==IMAGE.read(int(visit['pc'],16),4).hex() and visit['pc']==frame['pc'] and len(frame['Q_registers32'])==32
            used.update(int(x['address'],16) for x in row['source_reads'] if int(x['address'],16) in FIXUPS)
        assert dict(local)==ac['independent_totals'];total.update(local)
    assert keys=={(j,k,p) for j in range(32) for k in range(4) for p in [0,1]} and n==6400
    assert dict(total)==INDEPENDENT and dict(model)==MODEL and dict(counts)=={k:COUNTS[k] for k in counts} and e['source_fixups']==R.Parent.Parent.fixups(used)
    check_query_comparison();fresh=A.obligations();assert len(fresh)==len(a['source_proofs'])==a['source_queries_unsat']==9
    for old,new in zip(a['source_proofs'],fresh):
        assert {k:v for k,v in old.items() if k!='query'}=={k:v for k,v in new.items() if k!='query'}
        oa,na=z3.parse_smt2_string(old['query']),z3.parse_smt2_string(new['query']);assert len(oa)==len(na)>0 and all(canonical_expression(x)==canonical_expression(y) for x,y in zip(oa,na))
        s=z3.Solver();s.set(timeout=30000);s.from_string(old['query']);assert s.check()==z3.unsat and old['premises_nonvacuous']
    for obj in [e,a]:
        h.update(hygiene(obj));assert all(not obj[k] for k in ['native_API_executed','native_daemon_kext_pairing_established','native_epoch_join_established','full_goal_complete'])
    report=read(BASE/'daemon_state_file_metadata_report.md');assert CHECKS_SHA in report and AUDIT_SHA in report
    assert all(f'| SM{j} |' in report for j in range(1,7)) and all(f'| SM-A{j}:' in report for j in range(1,9)) and all(f'**QG{j}**' in report for j in range(1,8))
    return e,a,h

def main():
    e,a,h=receipts();raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==8809 and len(after)==8816 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
    assert {p for p in before if before[p]!=after[p]}==CHANGED and new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256'] and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
    for suffix,value in [('increment_checks',COUNTS),('replay_checks',INDEPENDENT),('model_checks',MODEL),('static_scope',e['scope']),('source_queries_unsat',9)]:assert new['validation'][R.P+'_'+suffix]==value
    assert new['validation']['reports']==old['validation']['reports']+1==516 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        path_hygiene((BASE/p).read_bytes());path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,delta^OWNED
    print(json.dumps({'unchanged_manifest_entries':8801,'owned_physical_files':16,'original_inputs_preserved':3,'reports':516,'independent_lifts':6400,'source_visits':COUNTS['source_visits'],'source_queries_unsat':9,**h,'native_API_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':main()
