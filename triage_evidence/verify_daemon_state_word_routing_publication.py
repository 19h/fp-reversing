#!/usr/bin/env python3
"""Verify SIDB word/range receipts, source equations and exact publication.

O(receipts+visits+owner joins+owned bytes+manifest+query DAG) time/storage;
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
import recover_daemon_state_word_routing as R
import audit_daemon_state_word_routing as A

PREVIOUS='0f33a3958a34b384d54cca09fb1f3d605e8d509d'
BASELINE_SHA='86e4fd5c5f53da04f3dc172c5edfaddb943d8fff00befebf034abab471402c39'
CHECKS_SHA='8b8018a75831eeb9c205087dabc5be372a7d30b6a756c6fb344529108ad55565';AUDIT_SHA='9fa9599b2f510aab80d74a73dd55ab409af362790e51606a025a4d1456838e96'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'mach_ports_report.md','interface_abi_report.md','interface_investigation_status.md',
         'obfuscated_routines_report.md','foundational_triage_report.md','corefp_client_paths_report.md',
         'daemon_state_file_input_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'daemon_state_word_routing_report.md','triage_evidence/recover_daemon_state_word_routing.py',
       'triage_evidence/audit_daemon_state_word_routing.py','triage_evidence/verify_daemon_state_word_routing_publication.py',
       'triage_evidence/daemon_state_word_routing_checks.json','triage_evidence/daemon_state_word_routing_audit.json'}
ARCHIVES={MANIFEST,'triage_evidence/daemon_state_word_routing_checks.json','triage_evidence/daemon_state_word_routing_audit.json'}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'parent_contexts': 256, 'incoming_first_byte_cuts': 768, 'synthetic_prefix_cases': 2316, 'inside_interval_cases': 773, 'borrowed_errno_continuations': 1543, 'intervals': 3859, 'source_visits': 1374568, 'reads': 256989, 'writes': 74070, 'logical_edges': 20844, 'source_calls': 5402}
INDEPENDENT={'inherited_X9_fixup_origins_checked': 2316, 'register_values_checked': 44109664, 'NZCV_values_checked': 1378427, 'vector_register_values_checked': 44109664, 'read_bytes_checked': 1339004, 'source_visits': 1374568, 'write_bytes_checked': 549332, 'original_authenticated_edges_checked': 20071, 'private_dispatch_values_matched_to_original_fixups': 1543}
MODEL={'parent_to_entry_X9_origins_checked': 2316, 'supplied_output_word_bytes_checked': 9264, 'output_word_state_joins_checked': 2316, 'synthetic_prefix_source_reads_checked': 9264, 'raw_word_private_stores_checked': 4632, 'lower_gate_source_partitions_checked': 2316, 'existing_borrowed_errno_pointer_returns_checked': 1543, 'API_return_joins_checked': 1543, 'errno_clear_and_pending_lstat_requests_checked': 1543, 'owner_and_generated_stream_preservation_intervals_checked': 3859, 'unsupplied_payload_bytes_preserved_checked': 15791028, 'upper_gate_source_partitions_checked': 1546, 'inside_pending_64_byte_allocations_checked': 773}

def function_metadata():
    import struct,bisect
    from resolve_kernel_collection_interfaces import commands
    data=SOURCE.read_bytes();assert sha256(data).hexdigest()=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    cmds=list(commands(data,0));text=next(o for o,c,n in cmds if c==0x19 and data[o+8:o+24].rstrip(b'\0')==b'__TEXT')
    base=struct.unpack_from('<Q',data,text+24)[0];assert base==0x100000000
    table=next(o for o,c,n in cmds if c==0x26);off,size=struct.unpack_from('<II',data,table+8);raw=data[off:off+size]
    assert (off,size,sha256(raw).hexdigest())==(17603576,1864,'ce02892286eaa20b5ad18e05d3a348a5c4b20ab49c668be14fd9e2eb119ccd54')
    starts=[];cursor=0;address=base;terminated=False
    while cursor<len(raw):
        delta=shift=0
        while True:
            assert cursor<len(raw);b=raw[cursor];cursor+=1;delta|=(b&127)<<shift;shift+=7;assert shift<=70
            if not b&128:break
        if not delta:terminated=True;break
        address+=delta;starts.append(address)
    assert terminated and len(starts)==1005 and all(a<b for a,b in zip(starts,starts[1:]))
    expected=[(0x10041a980,0x10041a980,0x10041ac7c),(0x1004946d8,0x1004946d8,0x100494948),
              (0x100493f38,0x100493f38,0x1004946d8),(0x100436378,0x100436378,0x100436388),
              (0x1005b94fc,0x100559b7c,0x10061748c),(0x1005fa9e0,0x100559b7c,0x10061748c),
              (0x10054e94c,0x10054127c,0x10055975c),(0x10058bf4c,0x100559b7c,0x10061748c),
              (0x1004cd11c,0x1004bd65c,0x1004d4268),(0x1004cd194,0x1004bd65c,0x1004d4268)]
    brackets=[]
    for pc,lo,hi in expected:
        j=bisect.bisect_right(starts,pc)-1;assert j>=0 and (starts[j],starts[j+1])==(lo,hi)
        brackets.append({'site':hex(pc),'preceding_advertised_start':hex(lo),'next_advertised_start':hex(hi),'is_advertised_start':pc==lo})
    so=next(o for o,c,n in cmds if c==2);sy,ns,st,sz=struct.unpack_from('<IIII',data,so+8);sites={a for a,_,_ in expected};names=[]
    for j in range(ns):
        ix,ty,se,de,va=struct.unpack_from('<IBBHQ',data,sy+j*16)
        if ix and va in sites:
            assert ix<sz;end=data.index(0,st+ix,st+sz);names.append({'address':hex(va),'name':data[st+ix:end].decode()})
    assert not names
    return {'LC_FUNCTION_STARTS_file_offset':off,'LC_FUNCTION_STARTS_bytes':size,'LC_FUNCTION_STARTS_sha256':sha256(raw).hexdigest(),
            'advertised_starts_checked':len(starts),'site_brackets':brackets,'exact_site_symbols':names,
            'scope':'Advertised starts and exact-site symbols; complete chunk ownership and recovered semantic names remain unknown.'}

def receipts():
    assert sha(ROOT/(R.P+'_checks.json'))==CHECKS_SHA and sha(ROOT/(R.P+'_audit.json'))==AUDIT_SHA
    e=json.loads(read(ROOT/(R.P+'_checks.json')));a=json.loads(read(ROOT/(R.P+'_audit.json')))
    assert e['generator_sha256']==a['generator_sha256']==sha(R.__file__) and a['auditor_sha256']==sha(A.__file__) and a['checks_sha256']==CHECKS_SHA
    assert e['dependencies']==a['dependencies']=={n:sha(ROOT/n) for n in R.DEPS} and a['auditor_dependencies']=={n:sha(ROOT/n) for n in A.AD}
    assert e['source_sha256']==a['source_sha256']==sha(SOURCE)=='4ffe3ea1dbd27c5026b448ffe06e8489b02cd9064500bcc67792d4ac36ffb63e'
    assert e['verified_counts']==a['verified_counts']==COUNTS and a['independent_totals']==INDEPENDENT and a['model_checks']==MODEL and a['all_checks_pass']
    assert e['source_regions']==R.source() and e['dispatch_metadata']==R.dispatch_metadata()
    parent=json.loads(read(ROOT/(R.Parent.P+'_checks.json')));keys=set();counts=Counter();total=Counter();model=Counter();used=set();h=Counter();number=0
    assert len(e['cases'])==len(a['cases'])==2316
    for c,ac in zip(e['cases'],a['cases']):
        ci,ti=c['parent_context_index'],c['parent_timestamp_case_index'];word=int(c['raw_big_endian_word32'],16)
        key=(ci,ti,word);assert key not in keys;keys.add(key)
        ct=A.contract(c,parent['contexts'][ci]);assert ct==ac['contract'];model.update(ct['model_checks'])
        rows=list(R.case_intervals(c));assert len(rows)==len(ac['independent_lifts']) and ac['all_checks_pass']
        for row,lift in zip(rows,ac['independent_lifts']):
            number+=1;h.update(hygiene(row));counts.update(R.rc(row));total.update(lift['verified_counts'])
            assert not row['native_target_executed'] and lift['all_checks_pass'] and not lift['native_target_executed']
            assert len(row['source_visits'])==len(row['source_frames'])==lift['verified_counts']['source_visits'] and row['boundary']['pc']==lift['boundary']
            for v,f in zip(row['source_visits'],row['source_frames']):
                assert v['pc']==f['pc'] and v['bytes_hex']==IMAGE.read(int(v['pc'],16),4).hex() and len(f['Q_registers32'])==32
            used.update(int(x['address'],16) for x in row['source_reads'] if int(x['address'],16) in FIXUPS)
    expected={(ci,ti,word) for ci in range(256) for ti in range(3) for word in R.BASE_WORDS}|{(0,0,w) for w in R.EXTRA_WORDS}
    assert keys==expected and number==3859 and dict(counts)=={k:COUNTS[k] for k in counts}
    assert dict(total)==INDEPENDENT and dict(model)==MODEL and e['source_fixups']==R.Parent.Parent.Parent.Parent.fixups(used)
    check_query_comparison();fresh=A.obligations();assert len(fresh)==len(a['source_proofs'])==a['source_queries_unsat']==12
    for old,new in zip(a['source_proofs'],fresh):
        assert {k:v for k,v in old.items() if k!='query'}=={k:v for k,v in new.items() if k!='query'}
        x,y=z3.parse_smt2_string(old['query']),z3.parse_smt2_string(new['query']);assert len(x)==len(y)>0 and all(canonical_expression(p)==canonical_expression(q) for p,q in zip(x,y))
        s=z3.Solver();s.set(timeout=30000);s.from_string(old['query']);assert s.check()==z3.unsat and old['premises_nonvacuous']
    for obj in [e,a]:
        h.update(hygiene(obj));assert all(not obj[k] for k in ['native_API_executed','native_daemon_kext_pairing_established','native_epoch_join_established','full_goal_complete'])
    report=read(BASE/'daemon_state_word_routing_report.md');assert CHECKS_SHA in report and AUDIT_SHA in report
    assert all(f'| WR{j} |' in report for j in range(1,6)) and all(f'| WR-A{j}:' in report for j in range(1,8)) and all(f'**QG{j}**' in report for j in range(1,8))
    h.update(hygiene(function_metadata()));return e,a,h

def main():
    e,a,h=receipts();raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==8823 and len(after)==8829 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
    assert {p for p in before if before[p]!=after[p]}==CHANGED and new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256'] and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
    for suffix,value in [('increment_checks',COUNTS),('replay_checks',INDEPENDENT),('model_checks',MODEL),('static_scope',e['scope']),('source_queries_unsat',12),('dispatch_metadata',e['dispatch_metadata'])]:assert new['validation'][R.P+'_'+suffix]==value
    assert new['validation'][R.P+'_function_metadata']==function_metadata()
    assert new['validation']['reports']==old['validation']['reports']+1==518 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:path_hygiene((BASE/p).read_bytes());path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,delta^OWNED
    print(json.dumps({'unchanged_manifest_entries':8815,'owned_physical_files':15,'original_inputs_preserved':3,'reports':518,'independent_lifts':3859,'source_visits':COUNTS['source_visits'],'source_queries_unsat':12,**h,'native_API_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':main()
