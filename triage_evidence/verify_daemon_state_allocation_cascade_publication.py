#!/usr/bin/env python3
"""Verify all76 allocator cascades, emitter contracts and publication.

O(receipts+visits+owner joins+owned bytes+manifest+query DAG) time/storage;
30 s/query. No native target operation, IDB mutation or history rewrite.
"""
import json,struct,bisect
from collections import Counter
from hashlib import sha256
from compression import zstd
import z3
from daemon_receive_tools import SOURCE,IMAGE,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_daemon_payload_mix_publication import ROOT,BASE,git,hygiene,path_hygiene
from verify_daemon_second_mix_publication import canonical_expression,check_query_comparison
import recover_daemon_state_allocation_cascade as R
import audit_daemon_state_allocation_cascade as A

PREVIOUS='57ca5ea05e71c122e5aae61c2854c12aa07659c7'
BASELINE_SHA='b657ae7f6099ece6697051025997280d8a5037ce99aa1046fe6fdbd6ececb1f5'
CHECKS_SHA='661c3f804d79bbbf49c44f4c464a1c773f43cbbc3fb796212d40a4deea46f809';AUDIT_SHA='81d62f637d5d932dce165be5686198ae50afcf727fd8aba6d4b90794f1f99641'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'mach_ports_report.md','interface_abi_report.md','interface_investigation_status.md',
         'obfuscated_routines_report.md','foundational_triage_report.md','corefp_client_paths_report.md',
         'daemon_state_container_construction_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'daemon_state_allocation_cascade_report.md','triage_evidence/recover_daemon_state_allocation_cascade.py',
       'triage_evidence/audit_daemon_state_allocation_cascade.py','triage_evidence/verify_daemon_state_allocation_cascade_publication.py',
       'triage_evidence/daemon_state_allocation_cascade_checks.json','triage_evidence/daemon_state_allocation_cascade_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/daemon_state_allocation_cascade_checks.json','triage_evidence/daemon_state_allocation_cascade_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'incoming_constructor_states':76,'continued_parents':76,'allocation21_cases':152,
        'allocation48_cases':152,'free21_returns':76,'emitter_entries':76,'intervals':456,
        'source_visits':98952,'reads':14212,'writes':8512,'logical_edges':2280,'source_calls':228}

def function_metadata():
    from resolve_kernel_collection_interfaces import commands
    data=SOURCE.read_bytes();assert sha256(data).hexdigest()=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    cmds=list(commands(data,0));o=next(o for o,c,n in cmds if c==0x26);off,n=struct.unpack_from('<II',data,o+8);raw=data[off:off+n]
    assert (off,n,sha256(raw).hexdigest())==(17603576,1864,'ce02892286eaa20b5ad18e05d3a348a5c4b20ab49c668be14fd9e2eb119ccd54')
    starts=[];address=0x100000000;j=0;terminated=False
    while j<len(raw):
        delta=shift=0
        while True:
            assert j<len(raw);b=raw[j];j+=1;delta|=(b&127)<<shift;shift+=7;assert shift<=70
            if not b&128:break
        if not delta:terminated=True;break
        address+=delta;starts.append(address)
    assert terminated and len(starts)==1005 and all(a<b for a,b in zip(starts,starts[1:]))
    sites=[R.MALLOC21,R.MALLOC48,R.FREE21,R.UNKNOWN,0x10093ca80,R.ADAPTER,R.EMITTER,R.COMPARE,R.TWIST,0x100934a4c,0x1008a1060,0x10068ae84]
    brackets=[]
    for pc in sites:
        k=bisect.bisect_right(starts,pc)-1;assert 0<=k<len(starts)-1
        brackets.append({'site':hex(pc),'preceding_advertised_start':hex(starts[k]),'next_advertised_start':hex(starts[k+1]),'is_advertised_start':pc==starts[k]})
    o=next(o for o,c,n in cmds if c==2);sy,ns,st,sz=struct.unpack_from('<IIII',data,o+8);names=[]
    for j in range(ns):
        ix,ty,se,de,va=struct.unpack_from('<IBBHQ',data,sy+16*j)
        if ix and va in sites:
            assert ix<sz;end=data.index(0,st+ix,st+sz);names.append({'address':hex(va),'name':data[st+ix:end].decode()})
    assert not names
    return {'advertised_starts_checked':1005,'table_file_offset':off,'table_bytes':n,'table_sha256':sha256(raw).hexdigest(),
            'site_brackets':brackets,'exact_site_symbols':names,'scope':'Advertised brackets only; complete chunks and original semantic names remain unknown.'}

def receipts():
    assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
    e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
    assert e['generator_sha256']==a['generator_sha256']==sha(R.__file__) and a['auditor_sha256']==sha(A.__file__) and a['checks_sha256']==CHECKS_SHA
    assert e['dependencies']==a['dependencies']=={n:sha(ROOT/n) for n in R.DEPS} and a['auditor_dependencies']=={n:sha(ROOT/n) for n in A.AD}
    assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert e['verified_counts']==a['verified_counts']==COUNTS and e['source_regions']==R.source() and e['SDK_checks']==R.Parent.sdk_checks()
    parent=json.loads(read(ROOT/(R.Parent.P+'_checks.json')));counts=Counter();total=Counter();model=Counter();used=set();h=Counter();number=0;keys=set()
    assert len(e['contexts'])==len(a['contexts'])==len(parent['contexts'])==76
    for c,ac in zip(e['contexts'],a['contexts']):
        ci=c['parent_context_index'];assert ci not in keys;keys.add(ci);p=parent['contexts'][ci]
        ct=A.contract(c,p);assert ct==ac['contract'];model.update(ct['model_checks'])
        rows=list(R.context_intervals(c));assert len(rows)==len(ac['independent_lifts'])==6 and ac['all_checks_pass']
        for row,lift in zip(rows,ac['independent_lifts']):
            number+=1;h.update(hygiene(row));counts.update(R.rc(row));total.update(lift['verified_counts'])
            assert not row['native_target_executed'] and not lift['native_target_executed'] and lift['all_checks_pass']
            assert len(row['source_visits'])==len(row['source_frames'])==lift['verified_counts'].get('source_visits',0) and row['boundary']['pc']==lift['boundary']
            for v,f in zip(row['source_visits'],row['source_frames']):
                assert v['pc']==f['pc'] and v['bytes_hex']==IMAGE.read(int(v['pc'],16),4).hex() and len(f['Q_registers32'])==32
            used.update(int(x['address'],16) for x in row['source_reads'] if int(x['address'],16) in FIXUPS)
    assert keys==set(range(76)) and number==456 and dict(counts)=={k:COUNTS[k] for k in counts}
    assert dict(total)==a['independent_totals'] and dict(model)==a['model_checks'] and e['source_fixups']==R.API.Parent.fixups(used)
    assert total['register_values_checked']==total['vector_register_values_checked']==(98952+456)*32
    assert total['parent_saved_continuation_origins_checked']==152
    check_query_comparison();fresh=A.obligations();assert len(fresh)==len(a['source_proofs'])==a['source_queries_unsat']==11
    for old,new in zip(a['source_proofs'],fresh):
        assert {k:v for k,v in old.items() if k!='query'}=={k:v for k,v in new.items() if k!='query'}
        x,y=z3.parse_smt2_string(old['query']),z3.parse_smt2_string(new['query']);assert len(x)==len(y)>0 and all(canonical_expression(p)==canonical_expression(q) for p,q in zip(x,y))
        s=z3.Solver();s.set(timeout=30000);s.from_string(old['query']);assert s.check()==z3.unsat and old['premises_nonvacuous']
    for obj in [e,a]:
        h.update(hygiene(obj));assert all(not obj[k] for k in ['native_API_executed','native_daemon_kext_pairing_established','native_epoch_join_established','full_goal_complete'])
    assert a['all_checks_pass'];h.update(hygiene(function_metadata()))
    report=read(BASE/'daemon_state_allocation_cascade_report.md');assert CHECKS_SHA in report and AUDIT_SHA in report
    assert all(f'| AC{j} |' in report for j in range(1,7)) and all(f'| AC-A{j}:' in report for j in range(1,9)) and all(f'**QG{j}**' in report for j in range(1,8))
    return e,a,h

def main():
    e,a,h=receipts();raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==8843 and len(after)==8849 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
    assert {p for p in before if before[p]!=after[p]}==CHANGED and new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256'] and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
    for suffix,value in [('increment_checks',COUNTS),('replay_checks',a['independent_totals']),('model_checks',a['model_checks']),('static_scope',e['scope']),('source_queries_unsat',11),('function_metadata',function_metadata())]:assert new['validation'][R.P+'_'+suffix]==value
    assert new['validation']['reports']==old['validation']['reports']+1==521 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:path_hygiene((BASE/p).read_bytes());path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,delta^OWNED
    print(json.dumps({'unchanged_manifest_entries':8835,'owned_physical_files':15,'original_inputs_preserved':3,'reports':521,
                      'independent_lifts':456,'source_visits':98952,'source_queries_unsat':11,**h,
                      'native_API_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':main()
