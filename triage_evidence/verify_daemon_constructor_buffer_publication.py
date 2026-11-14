#!/usr/bin/env python3
"""Verify pinned full replay and fresh conditional buffer/publication contracts.
O(receipts+visits+admissions*demands+joins*M*log(M)+owned bytes+query DAG)
time; O(receipts+largest interval+parent maps) storage; 30 s/query. No native
target operation, IDB mutation or Git history rewrite executes.
"""
import json
import base64,zlib
from collections import Counter
from hashlib import sha256
from compression import zstd
import z3
from daemon_receive_tools import SOURCE,IMAGE,FIXUPS,CS
from verify_daemon_reader_record_payloads_publication import read,sha,size
from verify_daemon_payload_mix_publication import ROOT,BASE,git,hygiene,path_hygiene
from verify_daemon_second_mix_publication import canonical_expression,check_query_comparison
import recover_daemon_constructor_buffer as R
import replay_daemon_constructor_buffer as Replay
import audit_daemon_constructor_buffer as A
PREVIOUS='3daa86524f1c3c0d6f43fccaacef51b259f69757'
BASELINE_SHA='5fb633dc54fb8d71a6ec3bbca1f9ccb6a50d04703669e3332ea85f20d4b11255'
CHECKS_SHA='fe29b3d2d39daecdd79d1d00057229f0f583b8b0ead9c4eb9bd4fd5aa7cafa07';REPLAY_SHA='61f012a43cbae9cf2ff8a5207603a30b9bbf82c7b2d92811e0c1a2ff7505c107';AUDIT_SHA='47108bdf5bedbb6a9aec1397ae777d6317a689cdea625638da5fb94a3c86e252'
MANIFEST='triage_evidence/interface_manifest.json'
CHANGED={'mach_ports_report.md','interface_abi_report.md','interface_investigation_status.md',
         'obfuscated_routines_report.md','foundational_triage_report.md','corefp_client_paths_report.md',
         'daemon_constructor_gate_report.md','triage_evidence/validate_rpc502_sidecar_delivery.py'}
ADDED={'daemon_constructor_buffer_report.md',*{'triage_evidence/'+s+'_daemon_constructor_buffer.py' for s in ['recover','replay','audit']},
       'triage_evidence/verify_daemon_constructor_buffer_publication.py',
       *{'triage_evidence/daemon_constructor_buffer_'+s+'.json' for s in ['checks','replay','audit']}}
ARCHIVES={MANIFEST,*{'triage_evidence/daemon_constructor_buffer_'+s+'.json' for s in ['checks','replay','audit']}}
OWNED=((CHANGED|ADDED)-ARCHIVES)|{p+'.zst' for p in ARCHIVES}
COUNTS={'incoming_parents':76,'representative_classes':4,'prefixes':4,'branch_classes':16,'terminal_exports':304,
        'new_root_premise_bytes_per_parent':8,'intervals':44,'source_visits':1410944,'reads':254300,
        'writes':73860,'logical_edges':62628,'source_calls':364}

def packed_hygiene(obj):
    """Check typed payload bytes, rather than pathname-like Base64 accidents.
    Only the exact three-key pack schema is treated as encoded content. Every
    such value is validated, decompressed, hash/size checked and path checked;
    every other JSON key/value retains the ordinary path checks.
    """
    counts=Counter()
    def walk(x):
        if isinstance(x,list):return [walk(v) for v in x]
        if not isinstance(x,dict):return x
        if 'payload_zlib_base64' in x:
            assert set(x)=={'decoded_sha256','decoded_size_bytes','payload_zlib_base64'}
            raw=zlib.decompress(base64.b64decode(x['payload_zlib_base64'],validate=True))
            assert sha256(raw).hexdigest()==x['decoded_sha256'] and len(raw)==x['decoded_size_bytes']
            path_hygiene(raw);counts.update(hygiene(json.loads(raw)));counts['typed_packed_payloads_path_checked']+=1
            return {**x,'payload_zlib_base64':'verified decoded payload '+x['decoded_sha256']}
        return {k:walk(v) for k,v in x.items()}
    clean=walk(obj);counts.update(hygiene(clean));return counts

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
    p=json.loads(read(ROOT/(R.Parent.P+'_checks.json')));parents={x['parent_index']:R.unpack(x['derived_terminal_state_packed']) for x in p['coverage']}
    assert A.coverage(e,parents)==a['coverage'] and A.contracts(e,parents)==a['model'] and A.foundation()==a['foundation']
    assert a['coverage']['all_checks_pass'] and a['model']['all_checks_pass']
    inherited=Replay.Prior.inherited_continuation();assert inherited==replay['inherited_saved_continuation'] and inherited['all_checks_pass']
    assert len(e['prefixes'])==len(replay['prefixes'])==4 and [len(c['member_parent_indices']) for c in e['prefixes']]==[34,4,34,4]
    counts=Counter();total=Counter();h=Counter();pcs=set();used=set();prefix_tags={}
    def row_check(row,entry,projection,receipt,tags):
        Replay.GS.joined(entry,row);assert R.registers([row])==projection and projection['vector_accesses']==0
        journal,tags,ct=Replay.origins(row,tags);assert ct==receipt['pointer_counts']
        lift=receipt['lift'];assert receipt['all_checks_pass'] and lift['all_checks_pass'] and not lift['native_target_executed'] and not row['native_target_executed']
        assert set(receipt['semantic_register_dependencies']['required'])<=set(projection['required']) and receipt['semantic_register_dependencies']['written']==projection['written']
        lc=lift['verified_counts'];n=len(row['source_visits']);assert n==len(row['source_frames'])==lc['source_visits']
        assert lc['register_values_checked']==lc['vector_register_values_checked']==(n+1)*32 and lc['NZCV_values_checked']==n+1
        assert len(journal)==lc['original_authenticated_edges_checked'] and lift['boundary']==row['boundary']['pc']
        for v,f in zip(row['source_visits'],row['source_frames']):
            pc=int(v['pc'],16);pcs.add(pc);assert v['pc']==f['pc'] and v['bytes_hex']==IMAGE.read(pc,4).hex() and len(f['Q_registers32'])==32
        used.update(int(x['address'],16) for x in row['source_reads'] if int(x['address'],16) in FIXUPS)
        if row['boundary']['kind']=='before_unmodeled_import_call':
            b=row['boundary'];i=Replay.Prior.instruction(int(b['pc'],16));assert i.mnemonic=='blraa'
            target_name=R.Parent.Parent.Parent.normalized(i.reg_name(i.operands[0].reg));modifier_name=R.Parent.Parent.Parent.normalized(i.reg_name(i.operands[1].reg))
            slot,target=tags[0][target_name];values=R.machine(row);word=int.from_bytes(IMAGE.read(slot,8),'little')
            assert FIXUPS[slot]['target']==b['detail']['symbol'] and target==int(values[target_name],16)==int(b['detail']['target'],16)
            assert int(values[modifier_name],16)==int(b['detail']['modifier'],16)==(word>>32)&65535 and ((word>>48)&7)==0
        counts.update(R.rc(row));total.update(lc);h.update(hygiene(row));return tags
    for ci,(c,rc) in enumerate(zip(e['prefixes'],replay['prefixes'])):
        row=R.unpack(c['interval_packed']);before,fx=R.premised(parents[c['representative_parent_index']]);assert fx==c['entry_premise']
        old_ci=next(x['class_index'] for x in p['coverage'] if x['parent_index']==c['representative_parent_index'])
        tags,origin=Replay.parent_origins(p,old_ci,inherited);assert origin==rc['parent_pointer_origin']
        prefix_tags[ci]=row_check(row,before,c['register_projection'],rc,tags)
    assert len(e['branches'])==len(replay['branches'])==16
    for c,rc in zip(e['branches'],replay['branches']):
        assert rc['all_checks_pass'] and len(c['intervals'])==len(rc['intervals'])
        before=R.unpack(next(x for x in e['prefix_coverage'] if x['parent_index']==c['representative_parent_index'])['derived_terminal_state_packed']);tags=prefix_tags[c['prefix_class_index']]
        for x,rr in zip(c['intervals'],rc['intervals']):
            ev=x['API_return_premise'];entry=A.abi(before,ev,c['ABI_clobber_pattern']);row=R.unpack(x['interval_packed'])
            tags=row_check(row,entry,x['register_projection'],rr,Replay.abi_origins(tags,ev));before=R.export(entry,row,x['register_projection'])
    assert dict(counts)=={k:COUNTS[k] for k in counts} and dict(total)==a['independent_totals']==replay['independent_totals']
    assert total['register_values_checked']==total['vector_register_values_checked']==45151616 and total['NZCV_values_checked']==1410988
    assert total['original_authenticated_edges_checked']==62264 and total['CAS_value_transitions_checked']==8
    expected_source=[];ordered=sorted(pcs);j=0
    while j<len(ordered):
        k=j+1
        while k<len(ordered) and ordered[k]==ordered[k-1]+4:k+=1
        start,end=ordered[j],ordered[k-1]+4;raw=IMAGE.read(start,end-start)
        expected_source.append({'start':hex(start),'end':hex(end),'bytes_hex':raw.hex(),'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(raw,start)]});j=k
    assert e['source_regions']==expected_source and e['source_fixups']==R.APIParent.API.Parent.fixups(used)
    for x in [*e['prefix_coverage'],*e['coverage']]:h.update(hygiene(R.unpack(x['derived_terminal_state_packed'])))
    check_query_comparison();fresh=A.obligations();assert len(fresh)==len(a['source_proofs'])==a['source_queries_unsat']==6
    for old,new in zip(a['source_proofs'],fresh):
        assert {k:v for k,v in old.items() if k!='query'}=={k:v for k,v in new.items() if k!='query'}
        x,y=z3.parse_smt2_string(old['query']),z3.parse_smt2_string(new['query']);assert len(x)==len(y)>0 and all(canonical_expression(p)==canonical_expression(q) for p,q in zip(x,y))
        s=z3.Solver();s.set(timeout=30000);s.from_string(old['query']);assert s.check()==z3.unsat and old['premises_nonvacuous']
    for obj in [e,a,replay]:h.update(packed_hygiene(obj));assert not obj['native_API_executed'] and not obj['full_goal_complete']
    assert a['all_checks_pass'] and replay['all_checks_pass'] and not e['continuous_initializer_join_established'] and not e['native_daemon_kext_pairing_established']
    report=read(BASE/'daemon_constructor_buffer_report.md');assert all(x in report for x in [CHECKS_SHA,REPLAY_SHA,AUDIT_SHA])
    assert all(f'| CB{j} |' in report for j in range(1,7)) and all(f'| CB-A{j}:' in report for j in range(1,7)) and all(f'**QG{j}**' in report for j in range(1,8))
    return e,a,replay,h

def main():
    e,a,replay,h=receipts();raw=zstd.decompress(git('show',PREVIOUS+':'+MANIFEST+'.zst'));assert sha256(raw).hexdigest()==BASELINE_SHA
    old,new=json.loads(raw),json.loads(read(BASE/MANIFEST));before={r['path']:r for r in old['files']};after={r['path']:r for r in new['files']}
    assert len(before)==8879 and len(after)==8887 and not before.keys()-after.keys() and after.keys()-before.keys()==ADDED
    assert {p for p in before if before[p]!=after[p]}==CHANGED and new['inputs_preserved']==old['inputs_preserved'] and len(new['inputs_preserved'])==3
    for r in new['inputs_preserved']:assert sha(BASE/r['path'])==r['sha256'] and size(BASE/r['path'])==r['size_bytes']
    for p in CHANGED|ADDED:assert sha(BASE/p)==after[p]['sha256'] and size(BASE/p)==after[p]['size_bytes']
    for suffix,value in [('increment_checks',COUNTS),('replay_checks',a['independent_totals']),('model_checks',a['model']['verified_counts']),
                         ('coverage_checks',a['coverage']['verified_counts']),('static_scope',e['scope']),('source_queries_unsat',6),('root_provenance',a['foundation'])]:
        assert new['validation'][R.P+'_'+suffix]==value
    assert new['validation']['reports']==old['validation']['reports']+1==526 and new['goal_status']=='active'
    assert new['validation']['unavailable_external_primary_references']==old['validation']['unavailable_external_primary_references']
    for p in ARCHIVES:assert not(BASE/p).exists()
    for p in OWNED:
        if p=='triage_evidence/daemon_constructor_buffer_checks.json.zst':
            packed_hygiene(json.loads(read(BASE/p[:-4])))
        else:
            path_hygiene((BASE/p).read_bytes());path_hygiene(read(BASE/(p[:-4] if p.endswith('.zst') else p)).encode())
    path_hygiene(git('show','-s','--format=fuller','HEAD'))
    delta=set(git('diff','--name-only',PREVIOUS).decode().splitlines())|set(git('ls-files','--others','--exclude-standard').decode().splitlines());assert delta==OWNED,delta^OWNED
    print(json.dumps({'unchanged_manifest_entries':8871,'owned_physical_files':17,'original_inputs_preserved':3,'reports':526,
                      'independent_lifts':44,'source_visits':1410944,'parent_interval_admissions':836,'terminal_exports':304,'source_queries_unsat':6,**h,
                      'new_root_premise_bytes_per_parent':8,'continuous_initializer_join_established':False,
                      'native_API_executed':False,'analyst_paths_absent':True,'all_checks_pass':True}),flush=True)

if __name__=='__main__':main()
