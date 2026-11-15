#!/usr/bin/env python3
"""Fresh byte-lineage audit and exact publication custody.
O(owned bytes+parent receipts+audit/proof DAG) wrapper time/space, plus the
documented extraction/audit and solver costs. No native target or IDB action.
"""
import json
from hashlib import sha256
from compression import zstd
import z3
from daemon_receive_tools import ROOT, SOURCE
from verify_daemon_reader_record_payloads_publication import read, sha, size
from verify_daemon_payload_mix_publication import BASE, git, hygiene, path_hygiene
from verify_daemon_second_mix_publication import canonical_expression
import recover_daemon_digest_body_origins as R
import audit_daemon_digest_body_origins as A

PREVIOUS='2653a031e41dcaf10ab3c3e37b8a8c887602a96c'
BASELINE_SHA='16b94750d7602a1557a2c73b5d0a9423fc1748b49d121500366a39427020d0e1'
CHECKS_SHA='625ffd36a7cca083c4e20b295639adbdd190d858e2b83a7c4ff81f30e66f1758'
AUDIT_SHA='dc216f1beb7244d7269b4d2bf682ef5d80dc1d2a4e844ecd20ab14fc735fa239'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'interface_investigation_status.md','foundational_triage_report.md','interface_abi_report.md',
         'obfuscated_routines_report.md','mach_ports_report.md','daemon_record_digest_report.md',
         'daemon_postseed_output_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'daemon_digest_body_origins_report.md','triage_evidence/recover_daemon_digest_body_origins.py',
       'triage_evidence/audit_daemon_digest_body_origins.py','triage_evidence/verify_daemon_digest_body_origins_publication.py',
       'triage_evidence/daemon_digest_body_origins_checks.json','triage_evidence/daemon_digest_body_origins_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/daemon_digest_body_origins_checks.json','triage_evidence/daemon_digest_body_origins_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'retained_contexts':2,'body_bytes_per_context':48,'producer_byte_links':96,'copy_byte_links':316,
        'incoming_boundary_links':640,'word_groups':16,'source_chunks':360,'source_visits':3744,
        'new_target_intervals':0,'new_root_bytes':0}
TOTALS={'fixed_word_codec_rows_checked':16,'incoming_boundary_links_checked':640,
        'selected_read_last_writer_bytes_checked':384,'selected_read_incoming_or_image_bytes_separate':2212,
        'copy_byte_links_checked':316,'source_visits':3744,'GP_SP_values':131328,'NZCV_frames':4104,
        'reads':856,'writes':412,'chunks':360,'producer_byte_links_checked':96,'word_image_bank_bytes_checked':192,
        'word_groups_checked':16,'complete_byte_codec_cases_checked':24,'pair_image_bank_bytes_checked':24,
        'two_byte_groups_checked':4,'source_queries_unsat':8}
CONTROLS={'earlier_different_byte_queries':10,'end_of_interval_writer_changes':0,'wrong_mask_phase_changed_bytes':48}


def receipts():
    assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
    evidence=json.loads(read(ROOT/(R.P+'_checks.json')));audit=json.loads(read(ROOT/(R.P+'_audit.json')))
    assert evidence==R.build();fresh=A.audit()
    old_proofs,new_proofs=audit.pop('source_proofs'),fresh.pop('source_proofs')
    assert audit==fresh and evidence['verified_counts']==COUNTS and audit['independent_totals']==TOTALS
    assert audit['epoch_and_phase_controls']==CONTROLS
    assert evidence['source_sha256']==audit['source_sha256']==sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert len(old_proofs)==len(new_proofs)==8 and len({p['label'] for p in old_proofs})==8
    for old,new in zip(old_proofs,new_proofs):
        x,y=dict(old),dict(new);p,q=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'))
        assert x==y and x['premises_nonvacuous'] and x['result']=='unsat'
        assert len(p)==len(q)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(p,q))
        s=z3.SolverFor('QF_BV');s.set(timeout=30000);s.add(*p);assert s.check()==z3.unsat
    audit['source_proofs']=old_proofs
    report=read(BASE/'daemon_digest_body_origins_report.md')
    assert all('| DB'+str(j)+' |' in report and '| DB-A'+str(j)+':' in report for j in range(1,7))
    assert all('**QG'+str(j)+'**' in report for j in range(1,8)) and CHECKS_SHA in report and AUDIT_SHA in report
    for case in evidence['cases']:
        for word in case['word_groups']:
            assert all(word[k] in report for k in ['source_W11','decoded4_hex'])
            assert all(str(j) in report for j in word['writer_visits'])
        for pair in case['two_byte_groups']:
            assert pair['source_W8_after_arithmetic'] in report and pair['decoded2_hex'] in report
    for receipt in [evidence,audit]:
        hygiene(receipt);assert receipt['retained_body_writer_lineage_established'] is True
        for key in ['application_field_names_established','native_API_executed','native_daemon_kext_pairing_established','full_goal_complete']:assert receipt[key] is False
    for p in CHANGED:
        if p.endswith('.md'):assert 'daemon_digest_body_origins_report.md' in read(BASE/p)
    return evidence,audit


def publication(evidence,audit):
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST))
    before,after=({r['path']:r for r in m['files']} for m in [old,new])
    assert len(before)==9096 and len(after)==9102
    assert not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
    assert {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:
        p=r['path'];assert sha(BASE/p)==r['sha256'] and size(BASE/p)==r['size_bytes']
        if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==r['sha256']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
    for key,value in [('increment_checks',evidence['verified_counts']),('static_scope',evidence['scope']),
                      ('independent_checks',audit['independent_totals']),('source_queries_unsat',8),
                      ('epoch_and_phase_controls',audit['epoch_and_phase_controls']),('retained_body_writer_lineage_established',True)]:
        assert new['validation'][R.P+'_'+key]==value
    assert new['validation']['reports']==old['validation']['reports']+1==562
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
    assert new['goal_status']=='active'
    for p in ARCHIVES:assert not (BASE/p).exists()
    for p in OWNED:
        path_hygiene((BASE/p).read_bytes());path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
    assert delta==OWNED,delta^OWNED
    print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':562,
                      'original_inputs_preserved':3,**COUNTS,**TOTALS,**CONTROLS,
                      'retained_body_writer_lineage_established':True,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)


if __name__=='__main__':publication(*receipts())
