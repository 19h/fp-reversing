#!/usr/bin/env python3
"""Verify pathname-family receipts, source equations and exact publication delta.

O(receipts+visits+owned bytes+manifest+query DAG) time/storage;30 s/query.
No native target operation executes. API effects and caller epochs are premises.
"""
import json
from hashlib import sha256
from collections import Counter
from compression import zstd
import z3
from daemon_receive_tools import SOURCE,IMAGE,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_daemon_payload_mix_publication import ROOT,BASE,git,hygiene,path_hygiene
from verify_daemon_second_mix_publication import canonical_expression,check_query_comparison
import recover_daemon_state_path_family as R
import audit_daemon_state_path_family as A

PREVIOUS='56611202c571f0d5efbb4af5675e51f43d0b933d'
BASELINE_SHA='49190673ebe1abb4a63d3d896beb41441178cb48a4ab16af4857718e3b407594'
CHECKS_SHA='b264e1892232c182f44e15fe3ff00f5a64804ed2d53dd17bae29d26fe94ddc82'
AUDIT_SHA='cdbb348eeee38b883aba51fcbac4285d70a2dfb36cf771a21a806f21bde40f32'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'mach_ports_report.md','interface_abi_report.md','interface_investigation_status.md',
         'obfuscated_routines_report.md','foundational_triage_report.md','corefp_client_paths_report.md',
         'daemon_state_path_objects_report.md','daemon_rwlock_lifecycle_report.md',
         'triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'daemon_state_path_family_report.md','triage_evidence/recover_daemon_state_path_family.py',
       'triage_evidence/audit_daemon_state_path_family.py','triage_evidence/verify_daemon_state_path_family_publication.py',
       'triage_evidence/daemon_state_path_family_checks.json','triage_evidence/daemon_state_path_family_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/daemon_state_path_family_checks.json','triage_evidence/daemon_state_path_family_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'cases': 16, 'gate_controls': 20, 'intervals': 484, 'source_visits': 282104, 'reads': 39942, 'writes': 14374, 'logical_edges': 11260, 'source_calls': 364}
INDEPENDENT={'register_values_checked': 9042816, 'NZCV_values_checked': 282588, 'vector_register_values_checked': 9042816, 'source_visits': 282104, 'read_bytes_checked': 207996, 'original_authenticated_edges_checked': 10970, 'write_bytes_checked': 70542}
MODEL={'API_return_joins_checked': 448, 'initially_undefined_allocated_bytes_checked': 39584, 'opaque_lock_bytes_checked': 28800, 'ordinary_state_joins_checked': 16, 'initially_undefined_borrowed_bytes_checked': 64, 'object_publications_checked': 144, 'constructor_status_words_checked': 144, 'object_defined_bytes_checked': 9200, 'object_undefined_gap_bytes_checked': 1584, 'directory_byte_defuses_checked': 2880, 'basename_source_bytes_checked': 1856, 'path_payload_bytes_checked': 5024, 'preinit_lock_header_bytes_checked': 1152, 'caller_nonnull_field_checks': 144, 'consumer_record_object_defuses_checked': 16, 'errno_source_zero_bytes_checked': 64, 'lstat_requests_checked': 16, 'generated_stream_bytes_preserved_checked': 512, 'complete_family_object_masks_checked': 160, 'single_field_zero_state_joins_checked': 20, 'zero_control_bytes_checked': 160, 'required_field_controls_reach_destroy_checked': 18, 'optional_field_controls_reach_errno_checked': 2}

def receipts():
    assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
    e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
    assert e['generator_sha256']==a['generator_sha256']==sha(R.__file__) and a['auditor_sha256']==sha(A.__file__) and a['checks_sha256']==CHECKS_SHA
    assert e['dependencies']==a['dependencies']=={n:sha(ROOT/n) for n in R.DEPS} and a['auditor_dependencies']=={n:sha(ROOT/n) for n in A.AD}
    assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert e['verified_counts']==a['verified_counts']==COUNTS and a['independent_totals']==INDEPENDENT and a['model_checks']==MODEL and a['all_checks_pass']
    assert e['source_regions']==R.source() and len(e['cases'])==len(a['cases'])==16 and len(e['gate_controls'])==len(a['gate_controls'])==20
    parent=json.loads(read(ROOT/(R.Parent.P+'_checks.json')));h=Counter();counts=Counter();totals=Counter();model=Counter();used=set();keys=set();control_keys=set()
    def interval(row,lift):
        h.update(hygiene(row));assert not row['native_target_executed'] and lift['all_checks_pass'] and not lift['native_target_executed']
        assert not any(A.overlap(x,R.J+0x34,32) for x in row['source_reads']+row['source_writes'])
        cs=R.rc(row);ts=lift['verified_counts']
        assert len(row['source_visits'])==len(row['source_frames'])==ts['source_visits'] and row['boundary']['pc']==lift['boundary']
        for visit,frame in zip(row['source_visits'],row['source_frames']):
            assert visit['bytes_hex']==IMAGE.read(int(visit['pc'],16),4).hex() and visit['pc']==frame['pc'] and len(frame['Q_registers32'])==32
        used.update(int(x['address'],16) for x in row['source_reads'] if int(x['address'],16) in FIXUPS)
        counts.update(cs);totals.update(ts);return cs,ts
    for c,ac in zip(e['cases'],a['cases']):
        key=(c['parent_case_index'],c['ABI_clobber_pattern']);assert key not in keys;keys.add(key)
        assert tuple(ac[k] for k in ['parent_case_index','ABI_clobber_pattern'])==key and ac['all_checks_pass']
        assert c['all_new_initializer_statuses32_zero'] and parent['cases'][key[0]]['scenario']=='init_0'
        rebuilt=json.loads(json.dumps(A.contract(c,parent['cases'][key[0]])));assert rebuilt==ac['contract'];model.update(rebuilt['model_checks'])
        rows=[R.unpack(p) for p in c['intervals_packed']];assert len(rows)==len(ac['independent_lifts'])==len(c['API_return_premises'])==29
        cs=Counter();ts=Counter()
        for row,lift in zip(rows,ac['independent_lifts']):
            cc,tt=interval(row,lift);cs.update(cc);ts.update(tt)
        assert dict(cs)==c['counts'] and dict(ts)==ac['independent_totals']
    assert keys=={(j,p) for j in R.PARENTS for p in [0,1]}
    for c,ac in zip(e['gate_controls'],a['gate_controls']):
        key=(c['family_case_index'],c['zero_context_offset']);assert key not in control_keys;control_keys.add(key)
        assert tuple(ac[k] for k in ['family_case_index','zero_context_offset'])==key and ac['all_checks_pass']
        rebuilt=json.loads(json.dumps(A.control_contract(c,e['cases'][key[0]])));assert rebuilt==ac['contract'];model.update(rebuilt['model_checks'])
        cc,_=interval(R.unpack(c['interval_packed']),ac['independent_lift']);assert cc==c['counts']
    assert control_keys=={(ci,hex(off)) for ci in [0,1] for _,off,*_ in R.FAMILY}
    assert dict(totals)==INDEPENDENT and dict(model)==MODEL and dict(counts)=={k:COUNTS[k] for k in counts} and e['source_fixups']==R.fixups(used)
    check_query_comparison();fresh=A.obligations(e);assert len(fresh)==len(a['source_proofs'])==a['source_queries_unsat']==23
    for old,new in zip(a['source_proofs'],fresh):
        assert {k:v for k,v in old.items() if k!='query'}=={k:v for k,v in new.items() if k!='query'}
        oa,na=z3.parse_smt2_string(old['query']),z3.parse_smt2_string(new['query']);assert len(oa)==len(na)>0
        assert all(canonical_expression(x)==canonical_expression(y) for x,y in zip(oa,na))
        solver=z3.Solver();solver.set(timeout=30000);solver.from_string(old['query']);assert solver.check()==z3.unsat and old['premises_nonvacuous']
    for obj in [e,a]:
        h.update(hygiene(obj));assert all(not obj[k] for k in ['native_API_executed','native_daemon_kext_pairing_established','native_epoch_join_established','full_goal_complete'])
    report=read(BASE/'daemon_state_path_family_report.md');assert CHECKS_SHA in report and AUDIT_SHA in report
    assert all(f'| PF{j} |' in report for j in range(1,7)) and all(f'| PF-A{j}:' in report for j in range(1,9)) and all(f'**QG{j}**' in report for j in range(1,8))
    return e,a,h

def main():
    e,a,h=receipts();raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==8796 and len(after)==8802 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
    assert {p for p in before if before[p]!=after[p]}==CHANGED and new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256'] and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
    for suffix,value in [('increment_checks',COUNTS),('replay_checks',INDEPENDENT),('model_checks',MODEL),('static_scope',e['scope']),('source_queries_unsat',23)]:
        assert new['validation']['daemon_state_path_family_'+suffix]==value
    assert new['validation']['reports']==old['validation']['reports']+1==514 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        path_hygiene((BASE/p).read_bytes());path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
    assert delta==OWNED,delta^OWNED
    print(json.dumps({'unchanged_manifest_entries':8787,'owned_physical_files':16,'original_inputs_preserved':3,'reports':514,
                     'independent_lifts':484,'source_visits':282104,'source_queries_unsat':23,**h,
                     'native_API_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':main()
