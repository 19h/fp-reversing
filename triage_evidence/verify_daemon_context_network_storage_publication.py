#!/usr/bin/env python3
"""Fresh context network-storage receipts and exact publication custody.
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
import recover_daemon_context_network_storage as R
import audit_daemon_context_network_storage as A

PREVIOUS='f68ae19e36f342c118e344e5924b9342b31687ee'
BASELINE_SHA='a804cbc39e6e0d917295469b4bc15fc21a354b5db8ad3b06ebb840c36a17ac5b'
CHECKS_SHA='3e28325a3ea3c23e8074002d933686c6f9f29998b9a744363aa28067bc136e06'
AUDIT_SHA='30cb2ad9fb16deb06e70e52fd101f6fcc08aa7a589e496a2e50f0b873a9f6ede'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'daemon_count_pointer_origin_report.md', 'triage_evidence/validate_rpc502_sidecar_delivery.py', 'interface_abi_report.md', 'daemon_count_pointer_lineage_report.md', 'foundational_triage_report.md', 'obfuscated_routines_report.md', 'daemon_context_state_publish_report.md', 'mach_ports_report.md', 'interface_investigation_status.md'}
ADDED={'daemon_context_network_storage_report.md','triage_evidence/recover_daemon_context_network_storage.py',
       'triage_evidence/audit_daemon_context_network_storage.py','triage_evidence/verify_daemon_context_network_storage_publication.py',
       'triage_evidence/daemon_context_network_storage_checks.json','triage_evidence/daemon_context_network_storage_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/daemon_context_network_storage_checks.json','triage_evidence/daemon_context_network_storage_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'constructor_zeroed_data_bytes': 20, 'network_success_controls': 4, 'nonzero_network_controls': 2, 'publication_intervals': 20, 'network_byte_transfers': 24, 'unchanged_tail_bytes_per_success_control': 14, 'saved_base_family_cases': 16, 'saved_base_lineage_stages': 320, 'saved_base_boundary_links': 304, 'saved_base_recorded_visits_examined': 196000, 'saved_base_write_events_examined': 9600, 'later_snapshot_layout_correspondences': 76, 'source_chunks': 61, 'source_visits': 110, 'new_target_intervals': 0, 'new_root_bytes': 0, 'new_API_return_premises': 0}
TOTALS={'constructor_zeroed_bytes_checked': 20, 'ordered_tail_fixture_queries': 280, 'tail_queries_with_conflicting_earlier_overlay': 280, 'network_byte_transfers_checked': 24, 'network_success_controls_checked': 4, 'nonzero_network_controls_checked': 2, 'raw_success_tail_bytes_checked': 56, 'disjoint_API_spans_checked': 304, 'saved_base_input_stores_checked': 16, 'saved_base_lineage_stages_checked': 320, 'recorded_visits_examined': 196000, 'recorded_write_events_examined': 9600, 'saved_base_boundary_bytes_checked': 2432, 'API_boundary_links_checked': 288, 'PC_boundary_links_checked': 304, 'saved_base_alias_stores_checked': 16, 'later_snapshot_layout_correspondences_checked': 76, 'source_visits': 110, 'GP_SP_values': 5472, 'NZCV_frames': 171, 'reads': 48, 'writes': 63, 'chunks': 61, 'new_source_queries_unsat': 3}


def receipts():
    assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
    evidence=json.loads(read(ROOT/(R.P+'_checks.json')));audit=json.loads(read(ROOT/(R.P+'_audit.json')))
    assert evidence==R.build();fresh=A.audit()
    old,new=audit.pop('source_proofs'),fresh.pop('source_proofs')
    assert audit==fresh and evidence['verified_counts']==COUNTS and audit['independent_totals']==TOTALS
    assert evidence['source_sha256']==audit['source_sha256']==sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert len(old)==len(new)==3
    for a,b in zip(old,new):
        x,y=dict(a),dict(b);p,q=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'))
        assert x==y and x['premises_nonvacuous'] and x['result']=='unsat'
        assert len(p)==len(q)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(p,q))
        s=z3.Solver();s.set(timeout=30000);s.add(*p);assert s.check()==z3.unsat
    audit['source_proofs']=old
    report=read(BASE/'daemon_context_network_storage_report.md')
    assert all('| NS'+str(j)+' |' in report for j in range(1,7))
    assert all('| NS-A'+str(j)+':' in report for j in range(1,6))
    assert all('**QG'+str(j)+'**' in report for j in range(1,8)) and CHECKS_SHA in report and AUDIT_SHA in report
    for word in ['0x1004cf268','0x10032197c','20 B','14 B','110 selected']:
        assert word in report
    for p in CHANGED:
        if p.endswith('.md'):assert 'daemon_context_network_storage_report.md' in read(BASE/p)
    for receipt in [evidence,audit]:
        hygiene(receipt);assert receipt['raw_success_network_storage_contract_established'] is True and receipt['conditional_saved_base_alias_established'] is True
        for key in ['full_saved_base_to_count_producer_epoch_join_established','native_constructor_epoch_join_established','native_API_executed','native_daemon_kext_pairing_established','full_goal_complete']:assert receipt[key] is False
    print(json.dumps({'fresh_extraction_audit_match':True,'source_queries_reconstructed_and_resolved':3}),flush=True)
    return evidence,audit


def publication(evidence,audit):
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST))
    before,after=({r['path']:r for r in m['files']} for m in [old,new])
    assert len(before)==9132 and len(after)==9138
    assert not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
    assert {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:
        p=r['path'];assert sha(BASE/p)==r['sha256'] and size(BASE/p)==r['size_bytes']
        if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==r['sha256']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
    for key,value in [('increment_checks',COUNTS),('static_scope',evidence['scope']),('independent_checks',TOTALS),
                      ('new_source_queries_unsat',3),('raw_success_network_storage_contract_established',True),('conditional_saved_base_alias_established',True)]:
        assert new['validation'][R.P+'_'+key]==value
    assert new['validation']['reports']==old['validation']['reports']+1==568
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
    print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':568,
                      'original_inputs_preserved':3,**COUNTS,**TOTALS,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)


if __name__=='__main__':publication(*receipts())
