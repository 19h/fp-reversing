#!/usr/bin/env python3
"""Fresh scalar-mixer receipts and exact publication custody.
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
import recover_daemon_payload_scalar_mixers as R
import audit_daemon_payload_scalar_mixers as A

PREVIOUS='a26a3437b023ad3305723134312617a9eead88a3'
BASELINE_SHA='06941c01c77fa8ebcafeb50ff31299f0443ea8976a751840d06be2577329abfa'
CHECKS_SHA='8abdca9c7bcd681797345d9cd20123a6c429761feacf9e212c12c519310e74d1'
AUDIT_SHA='e8691cddd430c2eeba98e6d70bdafbbb0c226cfb4823f82e3f279b540530a870'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'interface_investigation_status.md','foundational_triage_report.md','interface_abi_report.md',
         'obfuscated_routines_report.md','mach_ports_report.md','daemon_digest_record_structure_report.md',
         'daemon_record_digest_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'daemon_payload_scalar_mixers_report.md','triage_evidence/recover_daemon_payload_scalar_mixers.py',
       'triage_evidence/audit_daemon_payload_scalar_mixers.py','triage_evidence/verify_daemon_payload_scalar_mixers_publication.py',
       'triage_evidence/daemon_payload_scalar_mixers_checks.json','triage_evidence/daemon_payload_scalar_mixers_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/daemon_payload_scalar_mixers_checks.json','triage_evidence/daemon_payload_scalar_mixers_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'retained_contexts':2,'BE32_input_fields':4,'source_mixer_variants':2,'scratch_write_events':12,
        'scratch_byte_encoders':8,'scratch_prefix_copies':4,'scratch_tempered_words':2,'source_chunks':18,
        'source_visits':1462,'W9_preserved_frame_checks':1384,'new_target_intervals':0,'new_root_bytes':0,'new_API_return_premises':0}
TOTALS={'source_visits':1462,'logical_edges':8,'GP_SP_values':47360,'NZCV_frames':1480,'reads':192,'writes':28,
        'chunks':18,'selected_read_last_writer_bytes_checked':184,'selected_read_incoming_or_image_bytes_separate':668,
        'input_last_writer_bytes_checked':8,'input_incoming_or_image_bytes_separate':8,'BE32_fields_checked':4,
        'word_emission_bytes_checked':16,'scratch_write_events_checked':12,'scratch_prefix_copies_checked':4,
        'copy_last_writer_bytes_checked':0,'copy_incoming_or_image_bytes_separate':4,'scratch_byte_encoders_checked':8,
        'W9_preserved_frame_checks':1384,'scratch_tempered_words_checked':2,'new_source_queries_unsat':12}


def receipts():
    assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
    evidence=json.loads(read(ROOT/(R.P+'_checks.json')));audit=json.loads(read(ROOT/(R.P+'_audit.json')))
    assert evidence==R.build();fresh=A.audit()
    old,new=audit.pop('source_proofs'),fresh.pop('source_proofs')
    assert audit==fresh and evidence['verified_counts']==COUNTS and audit['independent_totals']==TOTALS
    assert evidence['source_sha256']==audit['source_sha256']==sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert len(old)==len(new)==12
    for a,b in zip(old,new):
        x,y=dict(a),dict(b);p,q=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'))
        assert x==y and x['premises_nonvacuous'] and x['result']=='unsat'
        assert len(p)==len(q)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(p,q))
        s=z3.Solver();s.set(timeout=30000);s.add(*p);assert s.check()==z3.unsat
    audit['source_proofs']=old
    report=read(BASE/'daemon_payload_scalar_mixers_report.md')
    assert all('| PS'+str(j)+' |' in report and '| PS-A'+str(j)+':' in report for j in range(1,7))
    assert all('**QG'+str(j)+'**' in report for j in range(1,8)) and CHECKS_SHA in report and AUDIT_SHA in report
    for word in ['00833631','69114534','000063fd','0x6703cce9','0x6703af14','0xa46fd0ff','20a363fd']:
        assert word in report
    for p in CHANGED:
        if p.endswith('.md'):assert 'daemon_payload_scalar_mixers_report.md' in read(BASE/p)
    for receipt in [evidence,audit]:
        hygiene(receipt);assert receipt['retained_payload_scalar_contract_established'] is True
        for key in ['native_schema_established','native_API_executed','native_daemon_kext_pairing_established','full_goal_complete']:assert receipt[key] is False
    print(json.dumps({'fresh_extraction_audit_match':True,'source_queries_reconstructed_and_resolved':12}),flush=True)
    return evidence,audit


def publication(evidence,audit):
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST))
    before,after=({r['path']:r for r in m['files']} for m in [old,new])
    assert len(before)==9108 and len(after)==9114
    assert not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
    assert {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:
        p=r['path'];assert sha(BASE/p)==r['sha256'] and size(BASE/p)==r['size_bytes']
        if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==r['sha256']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
    for key,value in [('increment_checks',COUNTS),('static_scope',evidence['scope']),('independent_checks',TOTALS),
                      ('new_source_queries_unsat',12),('retained_payload_scalar_contract_established',True)]:
        assert new['validation'][R.P+'_'+key]==value
    assert new['validation']['reports']==old['validation']['reports']+1==564
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
    print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':564,
                      'original_inputs_preserved':3,**COUNTS,**TOTALS,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)


if __name__=='__main__':publication(*receipts())
