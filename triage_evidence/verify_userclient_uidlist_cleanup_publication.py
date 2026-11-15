#!/usr/bin/env python3
"""Fresh original-source receipts and exact publication custody.
O(owned bytes+receipts+proof DAG) wrapper time/space plus documented
extraction/audit and solver costs. No native target or IDB operation.
"""
import json
import re
from hashlib import sha256
from compression import zstd
import z3
from kext_port_tools import ROOT, SOURCE
from verify_daemon_reader_record_payloads_publication import read, sha, size
from verify_daemon_payload_mix_publication import BASE, git, hygiene, path_hygiene
from verify_daemon_second_mix_publication import canonical_expression
import recover_userclient_uidlist_cleanup as R
import audit_userclient_uidlist_cleanup as A

PREVIOUS='0a0d1f9e77d66918c7695c5e4b7cb3442f0cb88d'
BASELINE_SHA='16e84f13a05fa783f99f00cd43f38fc4d9ce1288bfd41064e08d9a4c81a689c8'
CHECKS_SHA='d43b29782714595f1d80e59a2169b2c87ec9ffe55366aaa93ee5f6af597407bd'
AUDIT_SHA='801e96725f8b9bf58dd6c50c705c6978242c84abc372792e2654b34223025c01'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'foundational_triage_report.md','interface_investigation_status.md','mach_ports_report.md',
         'obfuscated_routines_report.md','interface_abi_report.md','userclient_context_lifecycle_report.md',
         'context_descriptor_task_flow_report.md','iokit_connection_lifecycle_report.md',
         'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'userclient_uidlist_cleanup_report.md','triage_evidence/recover_userclient_uidlist_cleanup.py',
       'triage_evidence/audit_userclient_uidlist_cleanup.py','triage_evidence/verify_userclient_uidlist_cleanup_publication.py',
       'triage_evidence/userclient_uidlist_cleanup_checks.json','triage_evidence/userclient_uidlist_cleanup_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/userclient_uidlist_cleanup_checks.json','triage_evidence/userclient_uidlist_cleanup_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'source_spans':5,'source_instructions':79,'terminal_transfers':3,'literal_bank_arrays':4,
        'bank_input_cases':512,'pool_pointers':4,'branch_pointers':4,'new_typed_descriptors':1,'node_bytes':16,'context_bytes':24}
TOTALS={'new_source_queries_unsat':5,'prior_source_queries_unsat':5,'abstract_controls_sat':2,
        'altered_evidence_rejections':4,'bank_input_cases_checked':512,'selected_source_instructions':79,
        'selected_source_reads':19,'selected_source_writes':2}

def receipts():
    assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
    evidence=json.loads(read(ROOT/(R.P+'_checks.json')));audit=json.loads(read(ROOT/(R.P+'_audit.json')))
    assert evidence==R.build();fresh=A.audit()
    old,new=audit.pop('source_proofs'),fresh.pop('source_proofs')
    assert audit==fresh and evidence['verified_counts']==COUNTS and audit['independent_totals']==TOTALS
    assert evidence['source_sha256']==audit['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
    assert len(old)==len(new)==5
    for a,b in zip(old,new):
        x,y=dict(a),dict(b);p,q=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'))
        assert x==y and x['premises_nonvacuous'] and x['result']=='unsat'
        assert len(p)==len(q)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(p,q))
        s=z3.Solver();s.set(timeout=30000);s.add(*p);assert s.check()==z3.unsat
    audit['source_proofs']=old
    report=read(BASE/'userclient_uidlist_cleanup_report.md')
    assert all('| UL'+str(j)+' |' in report for j in range(1,7))
    assert all('| UL-A'+str(j)+':' in report for j in range(1,7))
    assert all('**QG'+str(j)+'**' in report for j in range(1,8)) and CHECKS_SHA in report and AUDIT_SHA in report
    for word in ['0x31ae0066','site.UIDList','0xfffffe000a626a3c','79 instructions','(16*n + 24) B']:
        assert word in report
    # Check every displayed branch/call-table mapping against original evidence.
    for p in evidence['branch_pointers']:
        assert p['slot'] in report and p['target'] in report and hex(p['index']) in report
    for r in evidence['bank_rules']:assert r['slot'] in report and r['target'] in report
    for p in CHANGED:
        if p.endswith('.md'):assert 'userclient_uidlist_cleanup_report.md' in read(BASE/p)
    for receipt in [evidence,audit]:
        hygiene(receipt);assert receipt['conditional_UIDList_fast_cleanup_established'] is True
        for key in R.FALSE:assert receipt[key] is False
    print(json.dumps({'fresh_extraction_audit_match':True,'source_queries_reconstructed_and_resolved':5,
                      'predecessor_queries_resolved':5,'native_target_executed':False}),flush=True)
    return evidence,audit

def publication(evidence,audit):
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST))
    before,after=({r['path']:r for r in m['files']} for m in [old,new])
    assert len(before)==9144 and len(after)==9150
    assert not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
    assert {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:
        p=r['path'];assert sha(BASE/p)==r['sha256'] and size(BASE/p)==r['size_bytes']
        if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==r['sha256']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
    for key,value in [('increment_checks',COUNTS),('static_scope',evidence['scope']),('independent_checks',TOTALS),
                      ('new_source_queries_unsat',5),('prior_source_queries_rechecked',5),
                      ('conditional_UIDList_fast_cleanup_established',True)]:
        assert new['validation'][R.P+'_'+key]==value
    assert new['validation']['reports']==old['validation']['reports']+1==570
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
    print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':570,
                      'original_inputs_preserved':3,**COUNTS,**TOTALS,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':publication(*receipts())
