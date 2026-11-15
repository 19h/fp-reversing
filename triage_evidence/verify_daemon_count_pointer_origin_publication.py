#!/usr/bin/env python3
"""Fresh count-pointer origin receipts and exact publication custody.
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
import recover_daemon_count_pointer_origin as R
import audit_daemon_count_pointer_origin as A

PREVIOUS='07ebdcc537bfce71c335e2295a944aff78bacba8'
BASELINE_SHA='775becf4bd39dd2768516cb9055ae93f020606492dafb2f333454fd222f5121d'
CHECKS_SHA='e5b618f3d9d245d5d0a3919fae60d4be635905e32b34686b82dcec5d1be9dcb6'
AUDIT_SHA='b82f4d46a1ab485a7aa2359680e4b2e008f51a0137972f56ad97f52335be112c'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'obfuscated_routines_report.md', 'mach_ports_report.md', 'daemon_payload_count_flow_report.md', 'interface_abi_report.md', 'interface_investigation_status.md', 'foundational_triage_report.md', 'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'daemon_count_pointer_origin_report.md','triage_evidence/recover_daemon_count_pointer_origin.py',
       'triage_evidence/audit_daemon_count_pointer_origin.py','triage_evidence/verify_daemon_count_pointer_origin_publication.py',
       'triage_evidence/daemon_count_pointer_origin_checks.json','triage_evidence/daemon_count_pointer_origin_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/daemon_count_pointer_origin_checks.json','triage_evidence/daemon_count_pointer_origin_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'retained_constructor_contexts': 76, 'free_return_paths': 912, 'pointer_stores': 912, 'X21_preserved_frame_checks': 75696, 'snapshot_copies': 76, 'snapshot_bytes': 1824, 'saved_pointer_boundary_links': 76, 'consumer_layout_correspondences': 2, 'representative_contexts': 4, 'source_chunks': 108, 'source_visits': 208, 'new_target_intervals': 0, 'new_root_bytes': 0, 'new_API_return_premises': 0}
TOTALS={'pointer_paths_checked': 912, 'pointer_store_bytes_checked': 7296, 'X21_preserved_frames_checked': 75696, 'X21_nondefinition_visits_checked': 73872, 'byte_transfer_instruction_checks': 3648, 'snapshot_copies_checked': 76, 'snapshot_bytes_checked': 1824, 'saved_pointer_boundary_bytes_checked': 608, 'source_visits': 208, 'GP_SP_values': 10112, 'NZCV_frames': 316, 'reads': 104, 'writes': 100, 'chunks': 108, 'byte_writeback_instructions': 192, 'new_source_queries_unsat': 11}


def receipts():
    assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
    evidence=json.loads(read(ROOT/(R.P+'_checks.json')));audit=json.loads(read(ROOT/(R.P+'_audit.json')))
    assert evidence==R.build();fresh=A.audit()
    old,new=audit.pop('source_proofs'),fresh.pop('source_proofs')
    assert audit==fresh and evidence['verified_counts']==COUNTS and audit['independent_totals']==TOTALS
    assert evidence['source_sha256']==audit['source_sha256']==sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert len(old)==len(new)==11
    for a,b in zip(old,new):
        x,y=dict(a),dict(b);p,q=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'))
        assert x==y and x['premises_nonvacuous'] and x['result']=='unsat'
        assert len(p)==len(q)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(p,q))
        s=z3.Solver();s.set(timeout=30000);s.add(*p);assert s.check()==z3.unsat
    audit['source_proofs']=old
    report=read(BASE/'daemon_count_pointer_origin_report.md')
    assert all('| CP'+str(j)+' |' in report for j in range(1,7))
    assert all('| CP-A'+str(j)+':' in report for j in range(1,6))
    assert all('**QG'+str(j)+'**' in report for j in range(1,8)) and CHECKS_SHA in report and AUDIT_SHA in report
    for word in ['0x100710630','0x1008337c4','0x100595f5c','0x100595f84','14 B','912']:
        assert word in report
    for p in CHANGED:
        if p.endswith('.md'):assert 'daemon_count_pointer_origin_report.md' in read(BASE/p)
    for receipt in [evidence,audit]:
        hygiene(receipt);assert receipt['retained_pointer_initialization_established'] is True
        for key in ['full_constructor_to_consumer_epoch_join_established','native_constructor_epoch_join_established','native_API_executed','native_daemon_kext_pairing_established','full_goal_complete']:assert receipt[key] is False
    print(json.dumps({'fresh_extraction_audit_match':True,'source_queries_reconstructed_and_resolved':11}),flush=True)
    return evidence,audit


def publication(evidence,audit):
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST))
    before,after=({r['path']:r for r in m['files']} for m in [old,new])
    assert len(before)==9120 and len(after)==9126
    assert not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
    assert {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:
        p=r['path'];assert sha(BASE/p)==r['sha256'] and size(BASE/p)==r['size_bytes']
        if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==r['sha256']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
    for key,value in [('increment_checks',COUNTS),('static_scope',evidence['scope']),('independent_checks',TOTALS),
                      ('new_source_queries_unsat',11),('retained_pointer_initialization_established',True)]:
        assert new['validation'][R.P+'_'+key]==value
    assert new['validation']['reports']==old['validation']['reports']+1==566
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
    print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':566,
                      'original_inputs_preserved':3,**COUNTS,**TOTALS,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)


if __name__=='__main__':publication(*receipts())
