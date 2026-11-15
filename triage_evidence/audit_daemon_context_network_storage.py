#!/usr/bin/env python3
"""Independent context data-region, ordered overlays and saved-base epochs.
O(parent bytes+effect bytes+32C+proof DAG) time and O(parent receipts+largest
interval+selected chunks+proof DAG) space; solver search 30 s/query.
No new target/API/IPC, hardware PAC or IDB action.
"""
import gc,json
from collections import Counter
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE
from verify_daemon_reader_record_payloads_publication import read,sha
from recover_daemon_state_container_construction import unpack
from recover_daemon_callback_revisit import unpack as raw_unpack
from audit_daemon_record_input_origin import replay
from audit_daemon_append_fields import Lift
from audit_daemon_alternative_fill import Source
import recover_daemon_context_network_storage as R


def incoming(row,address):
    """Latest fixture overlay wins; return earlier conflicting-byte evidence."""
    candidates=[]
    for kind in ['initial_private_fixtures','initial_image_fixtures']:
        for f in row[kind]:
            a=int(f['address'],16);raw=bytes.fromhex(f['bytes_hex'])
            if a<=address<a+len(raw):candidates.append(raw[address-a])
    assert candidates
    return candidates[-1],len(set(candidates))>1


def disjoint(payload,address,n):
    pending=[payload];spans=[]
    while pending:
        item=pending.pop()
        if isinstance(item,list):pending.extend(item)
        elif isinstance(item,dict):
            pending.extend(item.values())
            if 'address' in item and ('size_bytes' in item or 'bytes_hex' in item):
                a=int(item['address'],16);k=item['size_bytes'] if 'size_bytes' in item else len(bytes.fromhex(item['bytes_hex']))
                assert a+k<=address or address+n<=a
                spans.append((a,k))
    return sorted(spans)


def obligations():
    out=[]
    def prove(label,bad,premises=()):
        s=z3.Solver();s.set(timeout=30000);s.add(*premises);assert s.check()==z3.sat
        s.add(z3.simplify(bad));assert s.check()==z3.unsat,label
        out.append({'label':label,'premises_nonvacuous':True,'result':'unsat','query':s.to_smt2()})
    ctx,src,sp,i,k=z3.BitVecs('cns_context64 cns_source64 cns_SP64 cns_index64 cns_tail_index64',64)
    b=z3.BitVec('cns_byte8',8)
    v=Lift();v.seed('x8',ctx);v.run_block(0x10032197c,0x100321984)
    assert [w['size_bytes'] for w in v.stores]==[8,8,4]
    prove('original_twenty_byte_zero_initialization',z3.Or(*[z3.Or(w['address']!=ctx+off,w['value']!=0) for w,off in zip(v.stores,[32,40,48])]))
    v=Source({0x10059ccd4:(1,b)});v.seed('x20',src);v.seed('x27',ctx+32);v.seed('x4',i)
    v.run_block(0x10059ccd4,0x10059ccdc);w,=v.stores
    prove('original_six_byte_publication_excludes_fourteen_byte_tail',z3.Or(v.loads[0][1]!=src+i,
          w['address']!=ctx+32+i,w['value']!=b,w['address']==ctx+32+k),
          [z3.ULE(i,5),z3.UGE(k,6),z3.ULE(k,19)])
    v=Lift();v.seed('x22',ctx);v.seed('sp',sp);v.run_block(0x1004cf268,0x1004cf26c);w,=v.stores
    prove('original_saved_context_base_input_store',z3.Or(w['address']!=sp+0x9b8,w['value']!=ctx))
    return out


def audit():
    evidence=json.loads(read(ROOT/(R.P+'_checks.json')));totals=Counter()
    for p,h in R.PINS.items():assert sha(ROOT/p)==h
    raw=raw_unpack(json.loads(read(ROOT/'daemon_callback_revisit_profiles.json')))
    zero=evidence['constructor_zeroing'];assert len(zero['visits'])==2 and len(zero['writes'])==3
    for j,v in enumerate(zero['visits'],27129):
        s=raw['steps'][j];assert v['pc']==s['pc'] and v['bytes_hex']==s['bytes_hex']==IMAGE.read(int(v['pc'],16),4).hex()
        effects=[w for w in zero['writes'] if w['source_visit_index']==j]
        assert [(w['address'],w['size_bytes'],w['after_hex']) for w in effects]==[(e['address'],e['size_bytes'],e['value']['hex']) for e in s['events'] if e['kind']=='write']
    assert zero['frames'][0]['registers31'][8]==hex(R.J)
    totals['constructor_zeroed_bytes_checked']=sum(w['size_bytes'] for w in zero['writes'])
    parent=json.loads(read(ROOT/'daemon_context_state_publish_checks.json'))
    assert [c['case_index'] for c in evidence['network_publications']]==[1,2,4,5]
    for case in evidence['network_publications']:
        c=parent['cases'][case['case_index']];assert c['second_pointer_return64']=='0x6600004000'
        assert case['MAC6_premise_hex']==c['MAC6_premise_hex'] and len(case['intervals'])==len(c['intervals'])==5
        all_data_writes=[]
        for ii,(summary,row) in enumerate(zip(case['intervals'],c['intervals'])):
            assert summary['interval_index']==ii and (summary['entry_PC'],summary['end_PC'])==(row['entry_PC'],row['boundary']['pc'])
            for a in range(R.J+38,R.J+52):
                value,changed=incoming(row,a);assert value==0
                totals.update(ordered_tail_fixture_queries=1,tail_queries_with_conflicting_earlier_overlay=int(changed))
            assert not any(R.overlap(w,R.J+38,14) for w in row['source_writes'])
            assert not summary['tail_overlapping_writes'] and summary['incoming_tail_hex']=='00'*14
            transitions=c['transitions'][ii];disjoint([transitions['effects'],transitions['import_return']],R.J+38,14)
            ws=[w for w in row['source_writes'] if R.overlap(w,R.J+32,20)]
            assert ws==summary['data_overlapping_writes'];all_data_writes.extend(ws)
        assert len(all_data_writes)==len(case['byte_transfers'])==6
        for transfer,w in zip(case['byte_transfers'],all_data_writes):
            row=c['intervals'][transfer['interval_index']];r=transfer['read'];assert transfer['write']==w and r in row['source_reads']
            i=transfer['index'];assert 0<=i<6 and int(w['address'],16)==R.J+32+i
            assert int(r['address'],16)==0x1010c5768+i and r['bytes_hex']==w['after_hex']
            assert r['size_bytes']==w['size_bytes']==1 and r['source_visit_index']+1==w['source_visit_index']
            totals['network_byte_transfers_checked']+=1
        count=case['count_write'];assert any(count in row['source_writes'] for row in c['intervals'])
        assert (count['pc'],count['address'],count['after_hex'])==('0x10059797c',hex(R.J+28),'06000000')
        assert case['data6_hex']==(c['MAC6_premise_hex'] or '00'*6)
        assert case['final_data20_hex']==c['final_context_hex'][64:104]==case['data6_hex']+'00'*14
        totals.update(network_success_controls_checked=1,nonzero_network_controls_checked=int(c['MAC6_premise_hex'] is not None),raw_success_tail_bytes_checked=14)
    family=json.loads(read(ROOT/'daemon_state_path_family_checks.json'))
    assert len(evidence['saved_base_lineages'])==len(family['cases'])==16
    for ci,(lineage,c) in enumerate(zip(evidence['saved_base_lineages'],family['cases'])):
        assert lineage['family_case_index']==ci and lineage['parent_case_index']==c['parent_case_index'] and lineage['ABI_clobber_pattern']==c['ABI_clobber_pattern']
        assert [s['interval_index'] for s in lineage['stages']]==list(range(8,28));previous=None;pc=None
        for summary in lineage['stages']:
            ii=summary['interval_index'];packed=c['intervals_packed'][ii];row=unpack(packed);ev=c['API_return_premises'][ii]
            assert summary['interval_sha256']==packed['decoded_sha256']
            cut=179 if ii==27 else len(row['source_visits']);assert cut==summary['cut_visit_exclusive']==summary['source_visits_examined']
            actual=disjoint(ev,R.SAVED,8)
            assert actual==sorted((int(s['address'],16),s['size_bytes']) for s in summary['disjoint_API_spans'])
            assert summary['API_call_site']==(ev['call_site'] if ev else None)
            totals['disjoint_API_spans_checked']+=len(actual)
            writes=[w for w in row['source_writes'] if w['source_visit_index']<cut and R.overlap(w,R.SAVED,8)]
            assert writes==summary['overlapping_writes']
            if ii==8:
                w,=writes;assert w['pc']=='0x1004cf268' and w['after_hex']==R.JHEX
                f=row['source_frames'][w['source_visit_index']]
                assert int(f['SP'],16)+0x9b8==R.SAVED and int(f['registers31'][22],16)==R.J
                totals['saved_base_input_stores_checked']+=1
            else:
                assert not writes
                for k in range(8):assert incoming(row,R.SAVED+k)[0]==bytes.fromhex(previous)[k]
                assert summary['incoming_cell_hex']==previous;totals['saved_base_boundary_bytes_checked']+=8
            entry=row['entry_PC'];end=row['source_frames'][cut]['pc'] if cut<len(row['source_visits']) else row['boundary']['pc']
            assert (entry,end)==(summary['entry_PC'],summary['end_PC'])
            if pc is not None:
                assert int(entry,16)==int(pc,16)+(4 if ev else 0)
                if ev:assert ev['call_site']==pc;totals['API_boundary_links_checked']+=1
                totals['PC_boundary_links_checked']+=1
            if ii==27:
                r=summary['last_read'];w=summary['alias_store']
                assert r in row['source_reads'] and w in row['source_writes']
                assert r['pc']=='0x1005d0f74' and r['source_visit_index']==177 and r['address']==hex(R.SAVED)
                assert w['pc']=='0x1005d0f78' and w['source_visit_index']==178 and w['address']=='0x6800068038'
                assert r['bytes_hex']==w['after_hex']==R.JHEX
                totals['saved_base_alias_stores_checked']+=1
            assert summary['outgoing_cell_hex']==R.JHEX
            totals.update(saved_base_lineage_stages_checked=1,recorded_visits_examined=cut,
                          recorded_write_events_examined=sum(w['source_visit_index']<cut for w in row['source_writes']))
            previous=R.JHEX;pc=end;del row;gc.collect()
    snapshots=json.loads(read(ROOT/'daemon_count_pointer_origin_checks.json'))['cases']
    assert len(evidence['later_snapshot_layout_correspondences'])==len(snapshots)==76
    for row,c in zip(evidence['later_snapshot_layout_correspondences'],snapshots):
        assert row['constructor_context_index']==c['context_index'] and row['snapshot24_hex']==c['snapshot']['bytes_hex']=='06000000'+'00'*20
        assert row['data20_hex']=='00'*20 and row['tail14_hex']=='00'*14
        totals['later_snapshot_layout_correspondences_checked']+=1
    for chunk in evidence['chunks']:totals.update(replay(chunk))
    proofs=obligations();totals['new_source_queries_unsat']=len(proofs)
    return {'scope':__doc__,'auditor_sha256':sha(__file__),'checks_sha256':sha(ROOT/(R.P+'_checks.json')),
            'source_sha256':sha(SOURCE),'parent_pins':R.PINS,
            'dependencies':{p:sha(ROOT/p) for p in ['audit_daemon_record_input_origin.py','audit_daemon_append_fields.py','audit_daemon_alternative_fill.py']},
            'source_proofs':proofs,'independent_totals':dict(totals),'raw_success_network_storage_contract_established':True,
            'conditional_saved_base_alias_established':True,'native_constructor_epoch_join_established':False,
            'full_saved_base_to_count_producer_epoch_join_established':False,'native_API_executed':False,
            'native_daemon_kext_pairing_established':False,'full_goal_complete':False,'all_checks_pass':True}

if __name__=='__main__':
    x=audit();(ROOT/(R.P+'_audit.json')).write_text(json.dumps(x,indent=2)+'\n');print(json.dumps(x['independent_totals']),flush=True)
