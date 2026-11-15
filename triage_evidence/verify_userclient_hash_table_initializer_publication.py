#!/usr/bin/env python3
"""Fresh shared-table initializer receipts and exact publication custody.
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
import recover_userclient_hash_table_initializer as R
import audit_userclient_hash_table_initializer as A

PREVIOUS='b3c4a42916c067904d04eef4aa6cac7e00d2fce7'
BASELINE_SHA='35c17f8caf8b3d6af75e8b179237a5cb60d2b12d23c508534c32f9438295f8c6'
CHECKS_SHA='8daa704b136cfeb42d21efad5360e4eb7d15fceb2c4a44f4490c9706017c37f7'
AUDIT_SHA='74cda9ca05f63296fa580560ee0ca6ae1f836e9934dbca2a694258124a3fdb57'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'foundational_triage_report.md','interface_investigation_status.md','mach_ports_report.md',
         'obfuscated_routines_report.md','interface_abi_report.md','userclient_context_lifecycle_report.md',
         'context_descriptor_task_flow_report.md','iokit_connection_lifecycle_report.md',
         'triage_evidence/validate_rpc502_sidecar_delivery.py','userclient_hash_table_bootstrap_report.md'}
ADDED={'userclient_hash_table_initializer_report.md','triage_evidence/recover_userclient_hash_table_initializer.py',
       'triage_evidence/audit_userclient_hash_table_initializer.py','triage_evidence/verify_userclient_hash_table_initializer_publication.py',
       'triage_evidence/userclient_hash_table_initializer_checks.json','triage_evidence/userclient_hash_table_initializer_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/userclient_hash_table_initializer_checks.json','triage_evidence/userclient_hash_table_initializer_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'functions': 3, 'captured_instructions': 407, 'source_spans': 23, 'selected_instructions': 386, 'terminal_transfers': 13, 'literal_bank_arrays': 8, 'bank_rules': 7, 'bank_input_cases': 1792, 'pool_pointers': 8, 'branch_pointers': 7, 'header_bytes': 16, 'entry_stride_bytes': 24, 'entry_count': 128, 'requested_array_bytes': 3072}
TOTALS={'new_source_queries_unsat': 21, 'prior_source_queries_unsat': 3, 'bank_input_cases_checked': 1792, 'source_instruction_instances': 1594, 'distinct_source_instructions': 386, 'array_source_instruction_instances': 3456, 'array_entries_checked': 128, 'array_written_bytes_checked': 2560, 'array_padding_bytes_preserved': 512, 'altered_evidence_rejections': 4}


def receipts():
    assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
    evidence=json.loads(read(ROOT/(R.P+'_checks.json')));audit=json.loads(read(ROOT/(R.P+'_audit.json')))
    assert evidence==R.build();fresh=A.audit()
    old,new=audit.pop('source_proofs'),fresh.pop('source_proofs')
    assert audit==fresh and evidence['verified_counts']==COUNTS and audit['independent_totals']==TOTALS
    assert evidence['source_sha256']==audit['source_sha256']==sha(SOURCE)=='2ec5e76ffc0a1873d284cbc50846b63f3576df2e5af98738df81faae33954a2c'
    assert len(old)==len(new)==21
    for a,b in zip(old,new):
        x,y=dict(a),dict(b);p,q=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'))
        assert x==y and x['premises_nonvacuous'] and x['result']=='unsat'
        assert len(p)==len(q)>0 and all(canonical_expression(i)==canonical_expression(j) for i,j in zip(p,q))
        s=z3.Solver();s.set(timeout=30000);s.add(*p);assert s.check()==z3.unsat
    audit['source_proofs']=old
    report=read(BASE/'userclient_hash_table_initializer_report.md')
    assert all('| HI'+str(j)+' |' in report for j in range(1,9))
    assert all('| HI-A'+str(j)+':' in report for j in range(1,9))
    assert all('**QG'+str(j)+'**' in report for j in range(1,8)) and CHECKS_SHA in report and AUDIT_SHA in report
    for word in ['0xfffffe000ccc3720','site.FPHashTableEntry','3072 B','386','0x7cb49d7a']:
        assert word in report
    # Check every displayed branch/call-table mapping against original evidence.
    for p in evidence['branch_pointers']:
        assert p['slot'] in report and p['target'] in report and hex(p['index']) in report
    for r in evidence['bank_rules'][4:]:assert r['slot'] in report and r['target'] in report
    for p in CHANGED:
        if p.endswith('.md'):assert 'userclient_hash_table_initializer_report.md' in read(BASE/p)
    for receipt in [evidence,audit]:
        hygiene(receipt);assert receipt['conditional_hash_table_initializer_contract_established'] is True
        for key in R.FALSE:assert receipt[key] is False
    print(json.dumps({'fresh_extraction_audit_match':True,'source_queries_reconstructed_and_resolved':21,
                      'predecessor_queries_resolved':3,'native_target_executed':False}),flush=True)
    return evidence,audit

def publication(evidence,audit):
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST))
    before,after=({r['path']:r for r in m['files']} for m in [old,new])
    assert len(before)==9156 and len(after)==9162
    assert not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
    assert {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:
        p=r['path'];assert sha(BASE/p)==r['sha256'] and size(BASE/p)==r['size_bytes']
        if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==r['sha256']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
    for key,value in [('increment_checks',COUNTS),('static_scope',evidence['scope']),('independent_checks',TOTALS),
                      ('new_source_queries_unsat',21),('prior_source_queries_rechecked',3),
                      ('conditional_hash_table_initializer_contract_established',True)]:
        assert new['validation'][R.P+'_'+key]==value
    assert new['validation']['reports']==old['validation']['reports']+1==572
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
    print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':572,
                      'original_inputs_preserved':3,**COUNTS,**TOTALS,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':publication(*receipts())
