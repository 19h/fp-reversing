#!/usr/bin/env python3
"""Fresh saved-base state-file lineage receipts and exact publication custody.
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
import recover_daemon_saved_base_statefile_lineage as R
import audit_daemon_saved_base_statefile_lineage as A

PREVIOUS='9b926afca51ca461a356d56c7c0b7b2871396350'
BASELINE_SHA='59609c3dfd55f42595b8a99d1e665bfa77918bb4ba29b5f19f76530801296278'
CHECKS_SHA='3e11e65054d84710e24465f20e9004075c0e924f53a7d9458a8cd293087f2347'
AUDIT_SHA='b6d4842ecf171d6892730d174c23dd2617a45b71eac053847a5146e5a5d8313b'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'foundational_triage_report.md', 'interface_investigation_status.md', 'daemon_context_network_storage_report.md', 'daemon_state_container_construction_report.md', 'mach_ports_report.md', 'obfuscated_routines_report.md', 'daemon_count_pointer_origin_report.md', 'daemon_count_pointer_lineage_report.md', 'triage_evidence/validate_rpc502_sidecar_delivery.py', 'interface_abi_report.md', 'daemon_state_file_input_report.md'}
ADDED={'daemon_saved_base_statefile_lineage_report.md','triage_evidence/recover_daemon_saved_base_statefile_lineage.py',
       'triage_evidence/audit_daemon_saved_base_statefile_lineage.py','triage_evidence/verify_daemon_saved_base_statefile_lineage_publication.py',
       'triage_evidence/daemon_saved_base_statefile_lineage_checks.json','triage_evidence/daemon_saved_base_statefile_lineage_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/daemon_saved_base_statefile_lineage_checks.json','triage_evidence/daemon_saved_base_statefile_lineage_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'constructor_contexts': 76, 'pathname_family_sources': 1, 'SIDB_word_parent_selections': 4, 'unique_stages': 481, 'chain_stages': 2304, 'chain_boundary_links': 2228, 'unique_API_transition_stages': 333, 'unique_scalar_output_stages': 147, 'unique_recorded_visits_examined': 74288, 'unique_recorded_write_events_examined': 4834, 'source_chunks': 153, 'source_visits': 230, 'new_target_intervals': 0, 'new_root_bytes': 0, 'new_API_return_premises': 0}
TOTALS={'API_chain_links_checked': 1696, 'chain_boundary_links_checked': 2228, 'chain_boundary_bytes_checked': 17824, 'scalar_output_chain_links_checked': 532, 'chain_stages_checked': 2304, 'disjoint_premise_spans_checked': 731, 'earlier_alias_source_joins_checked': 1, 'unique_stages_checked': 481, 'unique_recorded_visits_examined': 74288, 'unique_recorded_write_events_examined': 4834, 'unique_API_transition_stages_checked': 333, 'unique_scalar_output_stages_checked': 147, 'zero_visit_stages_checked': 12, 'unique_incoming_fixture_bytes_checked': 3840, 'constructor_base_reads_checked': 76, 'count_pointer_publications_checked': 76, 'X21_frames_checked': 6308, 'X21_definition_call_exclusions_checked': 6156, 'prior_constructor_source_joins_checked': 76, 'source_visits': 230, 'GP_SP_values': 12256, 'NZCV_frames': 383, 'reads': 77, 'writes': 77, 'chunks': 153, 'new_source_queries_unsat': 2}


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
    report=read(BASE/'daemon_saved_base_statefile_lineage_report.md')
    assert all('| SB'+str(j)+' |' in report for j in range(1,7))
    assert all('| SB-A'+str(j)+':' in report for j in range(1,6))
    assert all('**QG'+str(j)+'**' in report for j in range(1,8)) and CHECKS_SHA in report and AUDIT_SHA in report
    for word in ['0x1004cf268','0x1008337c4','2,228','230 selected']:
        assert word in report
    for p in CHANGED:
        if p.endswith('.md'):assert 'daemon_saved_base_statefile_lineage_report.md' in read(BASE/p)
    for receipt in [evidence,audit]:
        hygiene(receipt);assert receipt['conditional_saved_base_to_count_producer_lineage_established'] is True
        for key in ['whole_machine_context_lifetime_established','native_constructor_epoch_join_established','native_API_executed','native_daemon_kext_pairing_established','full_goal_complete']:assert receipt[key] is False
    print(json.dumps({'fresh_extraction_audit_match':True,'source_queries_reconstructed_and_resolved':2}),flush=True)
    return evidence,audit


def publication(evidence,audit):
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST))
    before,after=({r['path']:r for r in m['files']} for m in [old,new])
    assert len(before)==9138 and len(after)==9144
    assert not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
    assert {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:
        p=r['path'];assert sha(BASE/p)==r['sha256'] and size(BASE/p)==r['size_bytes']
        if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==r['sha256']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
    for key,value in [('increment_checks',COUNTS),('static_scope',evidence['scope']),('independent_checks',TOTALS),
                      ('new_source_queries_unsat',2),('conditional_saved_base_to_count_producer_lineage_established',True)]:
        assert new['validation'][R.P+'_'+key]==value
    assert new['validation']['reports']==old['validation']['reports']+1==569
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
    print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':569,
                      'original_inputs_preserved':3,**COUNTS,**TOTALS,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)


if __name__=='__main__':publication(*receipts())
