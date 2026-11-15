#!/usr/bin/env python3
"""Fresh count/data-flow receipts and exact publication custody.
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
import recover_daemon_payload_count_flow as R
import audit_daemon_payload_count_flow as A

PREVIOUS='ff4b5127171c7dd384f7363a4c84fc3d00fc5fd3'
BASELINE_SHA='63b5e94394bca78c5557dbb256b9dd57901ec81015f2f16cbf5cdd33c725c4c2'
CHECKS_SHA='ae049dbc07c56b85bd8e5929b91cfc90078b54c739208d9a9a3396bdc0fb3a3b'
AUDIT_SHA='8ce40257cf18caf157ce8803cbbd9085c150889079eed458e2fdf9ac22d5820b'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'daemon_context_state_publish_report.md',
 'daemon_digest_record_structure_report.md',
 'daemon_payload_scalar_mixers_report.md',
 'foundational_triage_report.md',
 'interface_abi_report.md',
 'interface_investigation_status.md',
 'mach_ports_report.md',
 'obfuscated_routines_report.md',
 'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'daemon_payload_count_flow_report.md','triage_evidence/recover_daemon_payload_count_flow.py',
       'triage_evidence/audit_daemon_payload_count_flow.py','triage_evidence/verify_daemon_payload_count_flow_publication.py',
       'triage_evidence/daemon_payload_count_flow_checks.json','triage_evidence/daemon_payload_count_flow_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/daemon_payload_count_flow_checks.json','triage_evidence/daemon_payload_count_flow_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'retained_contexts': 2,
 'count_data_field_pairs': 2,
 'saved_cell_boundary_links': 8,
 'word_gates': 4,
 'tail_iterations': 4,
 'source_chunks': 36,
 'source_visits': 666,
 'new_target_intervals': 0,
 'new_root_bytes': 0,
 'new_API_return_premises': 0}
TOTALS={'source_visits': 666,
 'writeback_instructions_checked': 10,
 'GP_SP_values': 22464,
 'NZCV_frames': 702,
 'reads': 110,
 'writes': 58,
 'chunks': 36,
 'selected_read_last_writer_bytes_checked': 364,
 'selected_read_incoming_or_image_bytes_separate': 332,
 'preserved_register_frame_checks': 606,
 'saved_boundary_bytes_checked': 64,
 'logical_edges': 18,
 'word_gates_checked': 4,
 'tail_iterations_checked': 4,
 'count_data_pairs_checked': 2,
 'new_source_queries_unsat': 16}


def receipts():
    assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
    evidence=json.loads(read(ROOT/(R.P+'_checks.json')));audit=json.loads(read(ROOT/(R.P+'_audit.json')))
    assert evidence==R.build();fresh=A.audit()
    old,new=audit.pop('source_proofs'),fresh.pop('source_proofs')
    assert audit==fresh and evidence['verified_counts']==COUNTS and audit['independent_totals']==TOTALS
    assert evidence['source_sha256']==audit['source_sha256']==sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert len(old)==len(new)==16
    for a,b in zip(old,new):
        x,y=dict(a),dict(b);p,q=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'))
        assert x==y and x['premises_nonvacuous'] and x['result']=='unsat'
        assert len(p)==len(q)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(p,q))
        s=z3.Solver();s.set(timeout=30000);s.add(*p);assert s.check()==z3.unsat
    audit['source_proofs']=old
    report=read(BASE/'daemon_payload_count_flow_report.md')
    assert all('| CF'+str(j)+' |' in report and '| CF-A'+str(j)+':' in report for j in range(1,7))
    assert all('**QG'+str(j)+'**' in report for j in range(1,8)) and CHECKS_SHA in report and AUDIT_SHA in report
    for word in ['0x4a2cb691c686c716','0x6659','0x66ad','0x10083e784','N>=4']:
        assert word in report
    for p in CHANGED:
        if p.endswith('.md'):assert 'daemon_payload_count_flow_report.md' in read(BASE/p)
    for receipt in [evidence,audit]:
        hygiene(receipt);assert receipt['retained_count_data_flow_established'] is True
        for key in ['native_constructor_epoch_join_established','native_API_executed','native_daemon_kext_pairing_established','full_goal_complete']:assert receipt[key] is False
    print(json.dumps({'fresh_extraction_audit_match':True,'source_queries_reconstructed_and_resolved':16}),flush=True)
    return evidence,audit


def publication(evidence,audit):
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST))
    before,after=({r['path']:r for r in m['files']} for m in [old,new])
    assert len(before)==9114 and len(after)==9120
    assert not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
    assert {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:
        p=r['path'];assert sha(BASE/p)==r['sha256'] and size(BASE/p)==r['size_bytes']
        if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==r['sha256']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
    for key,value in [('increment_checks',COUNTS),('static_scope',evidence['scope']),('independent_checks',TOTALS),
                      ('new_source_queries_unsat',16),('retained_count_data_flow_established',True)]:
        assert new['validation'][R.P+'_'+key]==value
    assert new['validation']['reports']==old['validation']['reports']+1==565
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
    print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':565,
                      'original_inputs_preserved':3,**COUNTS,**TOTALS,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)


if __name__=='__main__':publication(*receipts())
