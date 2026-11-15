#!/usr/bin/env python3
"""Verify complete extension receipts, fresh local contracts and publication.
Full numeric replay/admissions are bound by their current-source receipt;
publication does not repeat that corpus. Source words, representative
semantics and SMT contracts are reconstructed afresh.
O(receipt bytes + representative events + owned bytes + proof DAG) time/space,
excluding solver search. No target operation or history rewrite executes.
"""
import json
from collections import Counter
from hashlib import sha256
from compression import zstd
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_daemon_payload_mix_publication import BASE,git,path_hygiene,hygiene
from verify_daemon_second_mix_publication import canonical_expression
from verify_daemon_constructor_buffer_publication import packed_hygiene
import recover_daemon_record_extension as R
import replay_daemon_record_extension as A

PREVIOUS='fc6581f280a08c1b114944d2aeb252362456c077'
BASELINE_SHA='15c2b66b7decee688171e8c2b78afa29f43f7341b0a5db11a264c7147527eeba'
CHECKS_SHA='9e89cde6b9d04019761c1f7370584e72ad85afc0aa0fd657f4cb4aa9ff0571d7'
REPLAY_SHA='7ffde847a48145ad9821ab9d228a345dbd7722ab6d00179836624c202b81993d'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'interface_investigation_status.md','foundational_triage_report.md','interface_abi_report.md',
    'obfuscated_routines_report.md','mach_ports_report.md','corefp_client_paths_report.md',
    'daemon_descriptor_growth_report.md','daemon_child_loop_report.md','daemon_feedback_callers_report.md',
    'daemon_state_container_construction_report.md','daemon_descriptor_polynomial_report.md',
    'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'daemon_record_extension_report.md','triage_evidence/recover_daemon_record_extension.py',
    'triage_evidence/replay_daemon_record_extension.py','triage_evidence/verify_daemon_record_extension_publication.py',
    'triage_evidence/daemon_record_extension_checks.json','triage_evidence/daemon_record_extension_replay.json'}
ARCHIVES={MANIFEST,'triage_evidence/daemon_record_extension_checks.json','triage_evidence/daemon_record_extension_replay.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}


def receipts():
    assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_replay.json'))==REPLAY_SHA
    e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_replay.json')))
    assert e['generator_sha256']==a['generator_sha256']==sha(R.__file__)
    assert e['dependencies']=={p:sha(ROOT/p) for p in R.DEPS}
    assert a['replayer_sha256']==sha(A.__file__) and a['replayer_dependencies']=={p:sha(ROOT/p) for p in A.DEPS}
    assert a['checks_sha256']==CHECKS_SHA
    assert a['ADC_integer_controls']==A.adc_controls()==60
    assert a['CCMN_integer_controls']==A.ccmn_controls()==960
    assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    for p,d in R.PINS.items():assert sha(ROOT/p)==d
    incoming=R.parents();counts=Counter();numeric=Counter();seen=set();pcs={};used=set();publication_cases=0
    views={(c['parent_index'],c['ABI_clobber_pattern'],c['normal_branch']):c for c in e['coverage']}
    assert len(e['coverage'])==len(views)==1216
    assert set(views)=={(j,p,n) for j in range(304) for p in [0,1] for n in [False,True]}
    for ci,(c,ac) in enumerate(zip(e['classes'],a['classes'])):
        assert ac['class_index']==ci and ac['all_checks_pass'] and len(c['intervals'])==len(ac['intervals'])
        current=incoming[c['representative_parent_index']]['state'];rows=[];entries=[];terminals=[]
        for item,lift in zip(c['intervals'],ac['intervals']):
            entry,ev=R.returned(current,item['API_return_premise']);assert ev==item['API_return_premise']
            row=R.unpack(item['interval_packed']);A.Replay.GS.joined(entry,row)
            for v in row['source_visits']:
                pc=int(v['pc'],16)
                if pc not in pcs:pcs[pc]=IMAGE.read(pc,4).hex()
                assert v['bytes_hex']==pcs[pc]
            used.update(int(r['address'],16) for r in row['source_reads'] if int(r['address'],16) in FIXUPS)
            projection=R.B.registers([row]);assert projection==item['register_projection']
            assert lift['full_replay']['verified_counts']['source_visits']==len(row['source_visits'])
            counts.update(R.B.rc(row));numeric.update(lift['full_replay']['verified_counts'])
            terminal=R.B.export(entry,row,projection)
            rows.append(row);entries.append(entry);terminals.append(terminal);current=terminal
        assert A.semantics(c,rows,entries,terminals)==ac['semantics']
        publication_cases+=len(ac['semantics']['parent_publications'])
        for member in c['members']:
            key=member['parent_index'],member['ABI_clobber_pattern'],c['normal_branch']
            assert key not in seen and views[key]['class_index']==ci;seen.add(key)
        del rows,entries,terminals
    assert seen==set(views) and len(a['classes'])==len(e['classes'])
    assert e['source_words']==[{'start':hex(pc),'bytes_hex':pcs[pc]} for pc in sorted(pcs)]
    assert e['source_fixups']==R.B.APIParent.API.Parent.fixups(used)
    expected={'incoming_parents':304,'branch_classes':len(e['classes']),'terminal_exports':1216,
        'ABI_patterns':2,'first_malloc_outcomes':2,'new_payload_bytes_supplied':0,
        'new_root_bytes_supplied':0,'new_node_bytes_supplied':0,**counts}
    assert e['verified_counts']==a['verified_counts']==expected
    assert dict(numeric)==a['independent_totals'] and a['admissions']['branch_admissions']==1216
    assert a['admissions']['terminal_exports']==1216 and a['all_checks_pass']
    before=a['source_proofs'];after=A.obligations();assert len(before)==len(after)==5
    for x,y in zip(before,after):
        x,y=dict(x),dict(y);old,new=z3.parse_smt2_string(x.pop('query')),z3.parse_smt2_string(y.pop('query'))
        assert x==y and x['premises_nonvacuous'] and x['result']=='unsat'
        assert len(old)==len(new)>0 and all(canonical_expression(p)==canonical_expression(q) for p,q in zip(old,new))
        s=z3.Solver();s.set(timeout=30000);s.add(*old);assert s.check()==z3.unsat
    for x in [e,a]:
        assert not x['native_API_executed'] and not x['native_daemon_kext_pairing_established']
        assert not x['initializer_to_current_caller_join_established'] and not x['full_goal_complete']
    packed_hygiene(e);hygiene(a)
    report=read(BASE/'daemon_record_extension_report.md')
    assert all('| RE'+str(j)+' |' in report for j in range(1,7))
    assert all('| RE-A'+str(j)+':' in report for j in range(1,7))
    assert all('**QG'+str(j)+'**' in report for j in range(1,8))
    assert all(s in report for s in ['0x100901498','J+0x68','0x4aba552460e435c6','SP+0x390','97','125','145','185','224'])
    for p in CHANGED:
        if p.endswith(('_report.md','_status.md')):assert 'daemon_record_extension_report.md' in read(BASE/p)
    return e,a


def publication(e,a):
    raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST))
    before,after=({r['path']:r for r in m['files']} for m in [old,new])
    assert len(before)==9031 and len(after)==9037
    assert not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
    assert {p for p in before if before[p]!=after[p]}==CHANGED
    assert new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:
        p=r['path'];assert sha(BASE/p)==r['sha256'] and size(BASE/p)==r['size_bytes']
        if git('ls-files','--',p).decode().strip():assert sha256(git('show',PREVIOUS+':'+p)).hexdigest()==r['sha256']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
    for key,value in [('increment_checks',e['verified_counts']),('static_scope',e['scope']),
        ('replay_checks',a['independent_totals']),('admissions',a['admissions']),('source_queries_unsat',5)]:
        assert new['validation'][R.P+'_'+key]==value
    assert new['validation']['reports']==old['validation']['reports']+1==552
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
    assert new['goal_status']=='active'
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        if p=='triage_evidence/daemon_record_extension_checks.json.zst':
            # receipts() checked every typed payload; bind the identical bytes.
            assert sha(BASE/p[:-4])==CHECKS_SHA
        else:
            path_hygiene((BASE/p).read_bytes())
            path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
    assert delta==OWNED,delta^OWNED
    print(json.dumps({'owned_physical_files':len(OWNED),'logical_manifest_files':len(after),'reports':552,
        'original_inputs_preserved':3,**e['verified_counts'],'source_queries_unsat':5,
        'full_numeric_replay_repeated_in_publication':False,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)


if __name__=='__main__':publication(*receipts())
