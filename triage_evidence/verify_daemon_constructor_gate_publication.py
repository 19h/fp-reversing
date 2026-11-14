#!/usr/bin/env python3
"""Verify conditional constructor contracts and exact publication preservation.
Pinned full independent replay; fresh root provenance, admissions, effects,
pointer origins, source equations, census and decoded path hygiene.
O(receipts+visits+parents*demands+text words+owned bytes+query DAG) time/storage;
30 s/query. No native target operation, IDB mutation or history rewrite.
"""
import json
from collections import Counter
from hashlib import sha256
from compression import zstd
import z3
from daemon_receive_tools import SOURCE,IMAGE,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_daemon_payload_mix_publication import ROOT,BASE,git,hygiene,path_hygiene
from verify_daemon_second_mix_publication import canonical_expression,check_query_comparison
import recover_daemon_constructor_gate as R
import replay_daemon_constructor_gate as Replay
import audit_daemon_constructor_gate as A

PREVIOUS='32bc98dc2ac25cb8a8cbcfbd8b438c43080fe9ff'
BASELINE_SHA='4326b23e0b3ec83ce202053808d87de75a0f94eebde6cff620ac370201d70fb1'
CHECKS_SHA='9c4ad519628142f228742dd3a011a6b10f94aa106783bd6ba30caffad70af6ff';REPLAY_SHA='fc62eda40f7eeb4750c193183740342c223f684247ade9713b7fcd5decb047dc';AUDIT_SHA='d95e9e56e1fef1cd3f2fcf610670abcaa98e03159995d478d166e572d97d5b34'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'mach_ports_report.md','interface_abi_report.md','interface_investigation_status.md',
         'obfuscated_routines_report.md','foundational_triage_report.md','corefp_client_paths_report.md',
         'daemon_table_consumer_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'daemon_constructor_gate_report.md','triage_evidence/recover_daemon_constructor_gate.py',
       'triage_evidence/replay_daemon_constructor_gate.py','triage_evidence/audit_daemon_constructor_gate.py',
       'triage_evidence/verify_daemon_constructor_gate_publication.py',
       'triage_evidence/daemon_constructor_gate_checks.json','triage_evidence/daemon_constructor_gate_replay.json',
       'triage_evidence/daemon_constructor_gate_audit.json'}
ARCHIVES={MANIFEST,*{'triage_evidence/daemon_constructor_gate_'+k+'.json' for k in ['checks','replay','audit']}}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'incoming_parents':76,'representative_classes':4,'intervals':4,'new_root_premise_bytes_per_parent':88,
        'source_visits':386004,'reads':67152,'writes':12328,'logical_edges':18384,'source_calls':48}

def receipts():
    for kind,want in [('checks',CHECKS_SHA),('replay',REPLAY_SHA),('audit',AUDIT_SHA)]:assert sha(ROOT/(R.P+'_'+kind+'.json'))==want
    e=json.loads(read(ROOT/(R.P+'_checks.json')));replay=json.loads(read(ROOT/(R.P+'_replay.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
    assert e['generator_sha256']==replay['generator_sha256']==a['generator_sha256']==sha(R.__file__)
    assert a['auditor_sha256']==sha(A.__file__) and a['replayer_sha256']==replay['replayer_sha256']==sha(Replay.__file__)
    assert a['checks_sha256']==replay['checks_sha256']==CHECKS_SHA and a['replay_sha256']==REPLAY_SHA
    assert e['dependencies']==a['dependencies']==replay['dependencies']=={n:sha(ROOT/n) for n in R.DEPS}
    assert a['auditor_dependencies']=={n:sha(ROOT/n) for n in A.AD} and replay['replayer_dependencies']=={n:sha(ROOT/n) for n in Replay.DEPS}
    assert e['verified_counts']==replay['verified_counts']==a['verified_counts']==COUNTS
    assert e['source_sha256']==replay['source_sha256']==a['source_sha256']==sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert e['root_provenance']==R.roots() and e['root_provenance']['supplied_bytes']==88
    p=json.loads(read(ROOT/(R.Parent.P+'_checks.json')));parents={x['parent_index']:R.unpack(x['derived_terminal_state_packed']) for x in p['coverage']}
    assert A.coverage(e,parents)==a['coverage'] and a['coverage']['all_checks_pass']
    assert A.contracts(e,parents)==a['model'] and a['model']['all_checks_pass'] and A.foundation(e)==a['foundation']
    inherited=Replay.inherited_continuation();assert inherited==replay['inherited_saved_continuation'] and inherited['all_checks_pass']
    assert len(e['classes'])==len(replay['cases'])==4 and [len(c['member_parent_indices']) for c in e['classes']]==[34,4,34,4]
    counts=Counter();total=Counter();h=Counter();rows=[];used=set()
    for c,rc in zip(e['classes'],replay['cases']):
        row=R.unpack(c['interval_packed']);pr=R.registers([row]);assert pr==c['register_projection'] and len(pr['required'])==6 and pr['vector_accesses']==0
        assert rc['all_checks_pass'] and rc['lift']['all_checks_pass']
        assert set(rc['semantic_register_dependencies']['required'])<=set(pr['required']) and rc['semantic_register_dependencies']['written']==pr['written']
        before,fx=R.premised(parents[c['representative_parent_index']],e['root_provenance']);assert fx==c['entry_premises'];Replay.GS.joined(before,row)
        origin,ct=Replay.pointer_origins(row,(0x101048b28,0x1008c7994),inherited)
        for k,v in ct.items():assert rc['lift']['verified_counts'][k]==v
        assert len(origin)==rc['lift']['verified_counts']['original_authenticated_edges_checked']
        h.update(hygiene(row));counts.update(R.rc(row));total.update(rc['lift']['verified_counts']);rows.append(row)
        assert row['boundary']['pc']==rc['lift']['boundary'] and not row['native_target_executed'] and not rc['lift']['native_target_executed']
        assert len(row['source_visits'])==len(row['source_frames'])==rc['lift']['verified_counts']['source_visits']
        assert rc['lift']['verified_counts']['register_values_checked']==rc['lift']['verified_counts']['vector_register_values_checked']==(len(row['source_visits'])+1)*32
        for v,f in zip(row['source_visits'],row['source_frames']):assert v['pc']==f['pc'] and v['bytes_hex']==IMAGE.read(int(v['pc'],16),4).hex() and len(f['Q_registers32'])==32
        used.update(int(x['address'],16) for x in row['source_reads'] if int(x['address'],16) in FIXUPS)
    assert dict(counts)=={k:COUNTS[k] for k in counts} and dict(total)==a['independent_totals']==replay['independent_totals']
    assert total['register_values_checked']==total['vector_register_values_checked']==12352256 and total['NZCV_values_checked']==386008
    assert total['original_authenticated_edges_checked']==18336 and total['CAS_value_transitions_checked']==4 and total['cross_interval_target_origins_checked']==4
    assert e['source_regions']==R.source(rows) and e['source_fixups']==R.Parent.Parent.Parent.Parent.API.Parent.fixups(used)
    for x in e['coverage']:h.update(hygiene(R.unpack(x['derived_terminal_state_packed'])))
    check_query_comparison();fresh=A.obligations();assert len(fresh)==len(a['source_proofs'])==a['source_queries_unsat']==8
    for old,new in zip(a['source_proofs'],fresh):
        assert {k:v for k,v in old.items() if k!='query'}=={k:v for k,v in new.items() if k!='query'}
        x,y=z3.parse_smt2_string(old['query']),z3.parse_smt2_string(new['query']);assert len(x)==len(y)>0 and all(canonical_expression(p)==canonical_expression(q) for p,q in zip(x,y))
        s=z3.Solver();s.set(timeout=30000);s.from_string(old['query']);assert s.check()==z3.unsat and old['premises_nonvacuous']
    for obj in [e,a,replay]:h.update(hygiene(obj));assert not obj['native_API_executed'] and not obj['full_goal_complete']
    assert a['all_checks_pass'] and replay['all_checks_pass'] and not e['continuous_initializer_join_established'] and not e['native_daemon_kext_pairing_established']
    report=read(BASE/'daemon_constructor_gate_report.md');assert all(x in report for x in [CHECKS_SHA,REPLAY_SHA,AUDIT_SHA])
    assert all(f'| CG{j} |' in report for j in range(1,7)) and all(f'| CG-A{j}:' in report for j in range(1,9)) and all(f'**QG{j}**' in report for j in range(1,8))
    return e,a,replay,h

def main():
    e,a,replay,h=receipts();raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==8871 and len(after)==8879 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
    assert {p for p in before if before[p]!=after[p]}==CHANGED and new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256'] and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
    for suffix,value in [('increment_checks',COUNTS),('replay_checks',a['independent_totals']),('model_checks',a['model']['verified_counts']),
                         ('coverage_checks',a['coverage']['verified_counts']),('static_scope',e['scope']),('source_queries_unsat',8),('root_provenance',e['root_provenance'])]:
        assert new['validation'][R.P+'_'+suffix]==value
    assert new['validation']['reports']==old['validation']['reports']+1==525 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:path_hygiene((BASE/p).read_bytes());path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,delta^OWNED
    print(json.dumps({'unchanged_manifest_entries':8863,'owned_physical_files':17,'original_inputs_preserved':3,'reports':525,
                      'independent_lifts':4,'source_visits':386004,'admitted_parent_states':76,'source_queries_unsat':8,**h,
                      'new_root_premise_bytes_per_parent':88,'continuous_initializer_join_established':False,
                      'native_API_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':main()
