#!/usr/bin/env python3
"""Fresh conditional count-pointer lineage receipts and exact publication custody.
O(owned bytes+receipts+proof DAG) wrapper time/space plus documented
extraction/audit and solver costs. No native target or IDB operation.
"""
import json
import re
from hashlib import sha256
from compression import zstd
import z3
from daemon_receive_tools import ROOT, SOURCE
from verify_daemon_reader_record_payloads_publication import read, sha, size
from verify_daemon_payload_mix_publication import BASE, git, hygiene, path_hygiene
from verify_daemon_second_mix_publication import canonical_expression
import recover_daemon_count_pointer_lineage as R
import audit_daemon_count_pointer_lineage as A

PREVIOUS='b3f89f1877be7b97385a7162968a7d1e5defb848'
BASELINE_SHA='c7c606f3ee062ce7122691d0e46b0cef2cc8954309c5eaac20d434cffc605535'
CHECKS_SHA='dc0f782dbed641ce994be21437845794091bd2220ee2615a8cd793c1a681f1f7'
AUDIT_SHA='cd50e869fd7e5526dbe544fd31d9bc74fd1f3cf9ac83cd3359d1624496395d85'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'foundational_triage_report.md', 'daemon_payload_count_flow_report.md', 'interface_investigation_status.md', 'interface_abi_report.md', 'triage_evidence/validate_rpc502_sidecar_delivery.py', 'mach_ports_report.md', 'daemon_count_pointer_origin_report.md', 'obfuscated_routines_report.md'}
ADDED={'daemon_count_pointer_lineage_report.md','triage_evidence/recover_daemon_count_pointer_lineage.py',
       'triage_evidence/audit_daemon_count_pointer_lineage.py','triage_evidence/verify_daemon_count_pointer_lineage_publication.py',
       'triage_evidence/daemon_count_pointer_lineage_checks.json','triage_evidence/daemon_count_pointer_lineage_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/daemon_count_pointer_lineage_checks.json','triage_evidence/daemon_count_pointer_lineage_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'upstream_family_cases': 16, 'conditional_pointer_lineages': 2, 'lineage_stages': 298, 'cell_boundary_links': 296, 'examined_recorded_visits': 2519528, 'examined_write_events': 70268, 'inherited_entry_root_bytes_per_lineage': 116, 'source_chunks': 18, 'source_visits': 34, 'new_target_intervals': 0, 'new_root_bytes': 0, 'new_API_return_premises': 0}
TOTALS={'direct_store_pattern_candidates_checked': 3, 'upstream_base_publications_checked': 16, 'upstream_fixture_bytes_checked': 128, 'disjoint_premise_spans_checked': 78, 'lineage_stages_checked': 298, 'recorded_visits_examined': 2519528, 'recorded_write_events_examined': 70268, 'boundary_cell_bytes_checked': 2368, 'API_boundary_links_checked': 18, 'PC_boundary_links_checked': 296, 'derived_exports_checked': 18, 'consumer_pointer_reads_checked': 2, 'inherited_root_bytes_checked': 232, 'source_visits': 34, 'GP_SP_values': 1664, 'NZCV_frames': 52, 'reads': 18, 'writes': 16, 'chunks': 18, 'new_source_queries_unsat': 2}


def receipts():
    assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
    evidence=json.loads(read(ROOT/(R.P+'_checks.json')));audit=json.loads(read(ROOT/(R.P+'_audit.json')))
    assert evidence==R.build();fresh=A.audit()
    old,new=audit.pop('source_proofs'),fresh.pop('source_proofs')
    assert audit==fresh and evidence['verified_counts']==COUNTS and audit['independent_totals']==TOTALS
    assert evidence['source_sha256']==audit['source_sha256']==sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert len(old)==len(new)==2
    for a,b in zip(old,new):
        x,y=dict(a),dict(b);p,q=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'))
        assert x==y and x['premises_nonvacuous'] and x['result']=='unsat'
        assert len(p)==len(q)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(p,q))
        s=z3.Solver();s.set(timeout=30000);s.add(*p);assert s.check()==z3.unsat
    audit['source_proofs']=old
    report=read(BASE/'daemon_count_pointer_lineage_report.md')
    assert all('| PL'+str(j)+' |' in report for j in range(1,6))
    assert all('| PL-A'+str(j)+':' in report for j in range(1,6))
    assert all('**QG'+str(j)+'**' in report for j in range(1,8)) and CHECKS_SHA in report and AUDIT_SHA in report
    for word in ['0x1005d0f78','0x10083e780','116 B','149','296','34 selected']:
        assert word in report
    for p in CHANGED:
        if p.endswith('.md'):assert 'daemon_count_pointer_lineage_report.md' in read(BASE/p)
    for receipt in [evidence,audit]:
        hygiene(receipt);assert receipt['conditional_count_pointer_byte_lineage_established'] is True
        for key in ['full_constructor_to_consumer_epoch_join_established','native_constructor_epoch_join_established','native_API_executed','native_daemon_kext_pairing_established','full_goal_complete']:assert receipt[key] is False
    print(json.dumps({'fresh_extraction_audit_match':True,'source_queries_reconstructed_and_resolved':2}),flush=True)
    return evidence,audit


def publication(evidence,audit):
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST))
    before,after=({r['path']:r for r in m['files']} for m in [old,new])
    assert len(before)==9126 and len(after)==9132
    assert not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
    assert {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:
        p=r['path'];assert sha(BASE/p)==r['sha256'] and size(BASE/p)==r['size_bytes']
        if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==r['sha256']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
    for key,value in [('increment_checks',COUNTS),('static_scope',evidence['scope']),('independent_checks',TOTALS),
                      ('new_source_queries_unsat',2),('conditional_count_pointer_byte_lineage_established',True)]:
        assert new['validation'][R.P+'_'+key]==value
    assert new['validation']['reports']==old['validation']['reports']+1==567
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
    assert new['goal_status']=='active'
    for p in ARCHIVES:assert not (BASE/p).exists()
    for p in OWNED:
        path_hygiene((BASE/p).read_bytes());decoded=read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode()
        path_hygiene(decoded)
        assert not re.search(rb'/(?:Users/(?!Shared(?:/|\b))|home/|tmp/|private/|Library[/]Developer/|opt[/]homebrew/)',decoded)
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
    assert delta==OWNED,delta^OWNED
    print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':567,
                      'original_inputs_preserved':3,**COUNTS,**TOTALS,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)


if __name__=='__main__':publication(*receipts())
