#!/usr/bin/env python3
"""Fresh retained-structure audit and exact publication custody.
Wrapper O(owned bytes+receipts+proof DAG) time/space, plus documented
extraction/audit and solver costs. No native target or IDB operation.
"""
import json
from hashlib import sha256
from compression import zstd
import z3
from daemon_receive_tools import ROOT, SOURCE
from verify_daemon_reader_record_payloads_publication import read, sha, size
from verify_daemon_payload_mix_publication import BASE, git, hygiene, path_hygiene
from verify_daemon_second_mix_publication import canonical_expression
import recover_daemon_digest_record_structure as R
import audit_daemon_digest_record_structure as A

PREVIOUS='691d3ca7183cd0c0a6c189567bbbbe0ebd0c2871'
BASELINE_SHA='c50b8b3df452cd606a3c0813a6f334cb692367b3f39ddbeda4fb6cba58a9f4c0'
CHECKS_SHA='8b4b05e9d76bdbb22ae73de9c2b37b66888f98f92268483547c53169de2acb9e'
AUDIT_SHA='862051c07acb2f45558aff786793b531b028a04b63883933500769e32565692b'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'interface_investigation_status.md','foundational_triage_report.md','interface_abi_report.md',
         'obfuscated_routines_report.md','mach_ports_report.md','daemon_record_digest_report.md',
         'daemon_digest_body_origins_report.md','daemon_record_spans_report.md','daemon_packed_words_report.md',
         'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'daemon_digest_record_structure_report.md','triage_evidence/recover_daemon_digest_record_structure.py',
       'triage_evidence/audit_daemon_digest_record_structure.py','triage_evidence/verify_daemon_digest_record_structure_publication.py',
       'triage_evidence/daemon_digest_record_structure_checks.json','triage_evidence/daemon_digest_record_structure_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/daemon_digest_record_structure_checks.json','triage_evidence/daemon_digest_record_structure_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'retained_contexts':2,'word_fields':16,'packed_fields':8,'array_fields':4,'opaque_fields':4,
        'tempered_words':8,'retained_byte_consumers':24,'count_loop_iterations':26,'post_read_overwrites':316,
        'changed_post_read_bytes':316,'lineage_queries':1052,'source_chunks':390,'source_visits':6322,
        'new_target_intervals':0,'new_root_bytes':0,'new_API_return_premises':0}
TOTALS={'selected_read_last_writer_bytes_checked':288,'selected_read_incoming_or_image_bytes_separate':1648,
        'all_lineage_queries_checked':1052,'source_visits':6322,'GP_SP_values':214784,'NZCV_frames':6712,
        'reads':434,'writes':396,'chunks':390,'incoming_read_later_overwrites_checked':316,
        'changed_post_read_bytes_checked':316,'logical_edges':50,'scalar_count_last_writer_bytes_checked':64,
        'scalar_count_incoming_or_image_bytes_separate':0,'count_iterations_checked':26,'packed_fields_checked':8,
        'array_last_writer_bytes_checked':0,'array_incoming_or_image_bytes_separate':16,'array_fields_checked':4,
        'opaque_producer_paths_checked':4,'W9_preserved_frame_checks':3736,'byte_consumers_joined':24,
        'tempered_words_checked':8,'nested_layouts_checked':2,'new_source_queries_unsat':2,
        'prior_source_queries_freshly_rechecked':50,'prior_ring_normalizations_freshly_rechecked':1}


def receipts():
    assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
    evidence=json.loads(read(ROOT/(R.P+'_checks.json')));audit=json.loads(read(ROOT/(R.P+'_audit.json')))
    assert evidence==R.build();fresh=A.audit()
    proof_groups=[]
    for key,n in [('source_proofs',2),('rechecked_prior_source_proofs',50)]:
        a,b=audit.pop(key),fresh.pop(key);assert len(a)==len(b)==n;proof_groups.append((key,a,b))
    assert audit==fresh and evidence['verified_counts']==COUNTS and audit['independent_totals']==TOTALS
    assert evidence['source_sha256']==audit['source_sha256']==sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    for key,old_proofs,new_proofs in proof_groups:
        for old,new in zip(old_proofs,new_proofs):
            x,y=dict(old),dict(new);p,q=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'))
            assert x==y and x['premises_nonvacuous'] and x['result']=='unsat'
            assert len(p)==len(q)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(p,q))
            s=z3.Solver();s.set(timeout=30000);s.add(*p);assert s.check()==z3.unsat
        audit[key]=old_proofs
    report=read(BASE/'daemon_digest_record_structure_report.md')
    assert all('| DS'+str(j)+' |' in report and '| DS-A'+str(j)+':' in report for j in range(1,7))
    assert all('**QG'+str(j)+'**' in report for j in range(1,8)) and CHECKS_SHA in report and AUDIT_SHA in report
    for case in evidence['cases']:
        for field in case['fields']:
            assert field['values']['normalized4_hex'] in report
            if field['kind'] in ['packed','opaque_a','opaque_b']:assert field['values']['source_A32'] in report
        for word in case['tempered_words']:
            assert word['raw_W19'].replace('0x','').lstrip('0') in report and word['tempered_W9'] in report
    for receipt in [evidence,audit]:
        hygiene(receipt);assert receipt['retained_nested_span_layout_established'] is True
        for key in ['native_schema_established','native_API_executed','native_daemon_kext_pairing_established','full_goal_complete']:assert receipt[key] is False
    old_report=read(BASE/'daemon_digest_body_origins_report.md')
    assert 'incoming-fixture queries were excluded' in old_report and 'No selected query in this corpus has a later' not in old_report
    for p in CHANGED:
        if p.endswith('.md'):assert 'daemon_digest_record_structure_report.md' in read(BASE/p)
    return evidence,audit


def publication(evidence,audit):
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST))
    before,after=({r['path']:r for r in m['files']} for m in [old,new])
    assert len(before)==9102 and len(after)==9108
    assert not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
    assert {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:
        p=r['path'];assert sha(BASE/p)==r['sha256'] and size(BASE/p)==r['size_bytes']
        if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==r['sha256']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
    for key,value in [('increment_checks',evidence['verified_counts']),('static_scope',evidence['scope']),
                      ('independent_checks',audit['independent_totals']),('new_source_queries_unsat',2),
                      ('prior_source_queries_rechecked',50),('retained_layout',evidence['cases'][0]['layout']),
                      ('retained_nested_span_layout_established',True)]:
        assert new['validation'][R.P+'_'+key]==value
    assert new['validation']['reports']==old['validation']['reports']+1==563
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
    assert new['goal_status']=='active'
    for p in ARCHIVES:assert not (BASE/p).exists()
    for p in OWNED:
        path_hygiene((BASE/p).read_bytes());path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
    assert delta==OWNED,delta^OWNED
    print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':563,
                      'original_inputs_preserved':3,**COUNTS,**TOTALS,
                      'retained_nested_span_layout_established':True,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)


if __name__=='__main__':publication(*receipts())
