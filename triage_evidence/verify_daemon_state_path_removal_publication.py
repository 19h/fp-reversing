#!/usr/bin/env python3
"""Verify finite SIDB removal/SIDN handoff evidence and exact publication.

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
import recover_daemon_state_path_removal as R
import audit_daemon_state_path_removal as A

PREVIOUS='d18fc0e3b4cae500ca6d0f5f3eae4419cb1f93cd'
BASELINE_SHA='f1d2c465276d9a774b3c9cf18fc687356dca770878c32d072d8e77bf91f74bfd'
CHECKS_SHA='0e62dbdb1446e6751b3912b53e136bc467e249b8dacd2615960d9ab80ec83fb1';AUDIT_SHA='195067aac1f44f3eb7e7d02cc3e9bf79fd22f144ed85812a30ee7e4b9d8712b3'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'mach_ports_report.md','interface_abi_report.md','interface_investigation_status.md',
         'obfuscated_routines_report.md','foundational_triage_report.md','corefp_client_paths_report.md',
         'daemon_state_word_routing_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'daemon_state_path_removal_report.md','triage_evidence/recover_daemon_state_path_removal.py',
       'triage_evidence/audit_daemon_state_path_removal.py','triage_evidence/verify_daemon_state_path_removal_publication.py',
       'triage_evidence/daemon_state_path_removal_checks.json','triage_evidence/daemon_state_path_removal_audit.json',
       'triage_evidence/daemon_state_path_removal_abi.c'}
ARCHIVES={MANIFEST,'triage_evidence/daemon_state_path_removal_checks.json','triage_evidence/daemon_state_path_removal_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'incoming_lstat_parents':1543,'continued_parents':4,'stat_cases':16,'mode_cases':24,'errno_accessor_cases':12,
        'errno_word_cases':48,'unlink_cases':16,'synchronization_sequences':8,'SIDN_queries':76,'intervals':224,
        'source_visits':51832,'reads':11956,'writes':3780,'logical_edges':780,'source_calls':240}

def function_metadata():
    from resolve_kernel_collection_interfaces import commands
    data=SOURCE.read_bytes();assert sha256(data).hexdigest()=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    cmds=list(commands(data,0));o=next(o for o,c,n in cmds if c==0x26);off,n=struct.unpack_from('<II',data,o+8);raw=data[off:off+n]
    assert (off,n,sha256(raw).hexdigest())==(17603576,1864,'ce02892286eaa20b5ad18e05d3a348a5c4b20ab49c668be14fd9e2eb119ccd54')
    starts=[];a=0x100000000;j=0;terminated=False
    while j<len(raw):
        delta=shift=0
        while True:
            assert j<len(raw);b=raw[j];j+=1;delta|=(b&127)<<shift;shift+=7;assert shift<=70
            if not b&128:break
        if not delta:terminated=True;break
        a+=delta;starts.append(a)
    assert terminated and len(starts)==1005 and all(a<b for a,b in zip(starts,starts[1:]))
    sites=[R.LSTAT,R.MODE,R.ERRNO,R.UNLINK,0x100628a28,0x1004af644,0x10041ac4c,0x100863f38,0x100863fa4,0x10043e280,0x1004423f8]
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
    assert e['verified_counts']==a['verified_counts']==COUNTS and e['source_regions']==R.source() and e['SDK_checks']==R.sdk_checks()
    parent=json.loads(read(ROOT/(R.Parent.P+'_checks.json')));counts=Counter();total=Counter();model=Counter();used=set();h=Counter();number=0
    assert len(e['contexts'])==len(a['contexts'])==4 and [c['parent_case_index'] for c in e['contexts']]==R.PARENTS
    assert {(c['raw_parent_word32'],c['prior_ABI_clobber_pattern']) for c in e['contexts']}=={(hex(w),p) for w in [0,R.Parent.HIGH] for p in [0,1]}
    for c,ac in zip(e['contexts'],a['contexts']):
        ct=A.contract(c,parent['cases'][c['parent_case_index']]);assert ct==ac['contract'];model.update(ct['model_checks'])
        rows=list(R.context_intervals(c));assert len(rows)==len(ac['independent_lifts'])==56 and ac['all_checks_pass']
        for row,lift in zip(rows,ac['independent_lifts']):
            number+=1;h.update(hygiene(row));counts.update(R.rc(row));total.update(lift['verified_counts'])
            assert not row['native_target_executed'] and not lift['native_target_executed'] and lift['all_checks_pass']
            assert len(row['source_visits'])==len(row['source_frames'])==lift['verified_counts'].get('source_visits',0) and row['boundary']['pc']==lift['boundary']
            for v,f in zip(row['source_visits'],row['source_frames']):
                assert v['pc']==f['pc'] and v['bytes_hex']==IMAGE.read(int(v['pc'],16),4).hex() and len(f['Q_registers32'])==32
            used.update(int(x['address'],16) for x in row['source_reads'] if int(x['address'],16) in FIXUPS)
    assert number==224 and dict(counts)=={k:COUNTS[k] for k in counts}
    assert dict(total)==a['independent_totals'] and dict(model)==a['model_checks'] and e['source_fixups']==R.API.Parent.fixups(used)
    assert total['source_visits']==51832 and total['register_values_checked']==total['vector_register_values_checked']==(51832+224)*32
    check_query_comparison();fresh=A.obligations();assert len(fresh)==len(a['source_proofs'])==a['source_queries_unsat']==10
    for old,new in zip(a['source_proofs'],fresh):
        assert {k:v for k,v in old.items() if k!='query'}=={k:v for k,v in new.items() if k!='query'}
        x,y=z3.parse_smt2_string(old['query']),z3.parse_smt2_string(new['query']);assert len(x)==len(y)>0 and all(canonical_expression(p)==canonical_expression(q) for p,q in zip(x,y))
        s=z3.Solver();s.set(timeout=30000);s.from_string(old['query']);assert s.check()==z3.unsat and old['premises_nonvacuous']
    for obj in [e,a]:
        h.update(hygiene(obj));assert all(not obj[k] for k in ['native_API_executed','native_daemon_kext_pairing_established','native_epoch_join_established','full_goal_complete'])
    assert a['all_checks_pass'];h.update(hygiene(function_metadata()))
    report=read(BASE/'daemon_state_path_removal_report.md');assert CHECKS_SHA in report and AUDIT_SHA in report
    assert all(f'| PR{j} |' in report for j in range(1,7)) and all(f'| PR-A{j}:' in report for j in range(1,8)) and all(f'**QG{j}**' in report for j in range(1,8))
    return e,a,h

def main():
    e,a,h=receipts();raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==8829 and len(after)==8836 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
    assert {p for p in before if before[p]!=after[p]}==CHANGED and new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256'] and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
    for suffix,value in [('increment_checks',COUNTS),('replay_checks',a['independent_totals']),('model_checks',a['model_checks']),('static_scope',e['scope']),('source_queries_unsat',10),('function_metadata',function_metadata())]:assert new['validation'][R.P+'_'+suffix]==value
    assert new['validation']['reports']==old['validation']['reports']+1==519 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:path_hygiene((BASE/p).read_bytes());path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines())
    # Ignored new C/receipt paths become visible through the explicit staged set.
    assert delta==OWNED,delta^OWNED
    print(json.dumps({'unchanged_manifest_entries':8821,'owned_physical_files':16,'original_inputs_preserved':3,'reports':519,
                      'independent_lifts':224,'source_visits':51832,'source_queries_unsat':10,**h,
                      'native_API_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':main()
