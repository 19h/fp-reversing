#!/usr/bin/env python3
"""Original context data-region zeroing, six-byte publication and saved-base alias.
O(parent bytes+selected visits+effect bytes) time; O(parent receipts+largest
interval+selected chunks) space. No new target/API/root byte or IDB action.
"""
import gc,json
from daemon_receive_tools import ROOT,SOURCE,IMAGE
from verify_daemon_reader_record_payloads_publication import read,sha
from recover_daemon_callback_revisit import unpack as raw_unpack
from recover_daemon_state_container_construction import unpack
from recover_daemon_record_input_origin import piece
from recover_daemon_count_pointer_lineage import memory_spans
from replay_daemon_context_transfer import evaluate

P='daemon_context_network_storage'
J=0x6500115b20
SAVED=0x6800060ab8
JHEX=J.to_bytes(8,'little').hex()
PINS={'daemon_callback_revisit_profiles.json': '93b06846a3fd1be8cf6b2a7af2e44b1851567f19652a7ba32cbb40de6ac58793', 'daemon_callback_revisit_snapshot.json': '1d2faacf9222f8ee22fbeff3fa13446c3890053a82ba778671547d74b8da70f2', 'daemon_callback_revisit_replays.json': 'af159751dbb8b2bd7dc41cdabe77612370b98b1bb5b2f0e6e59b5437b6d88356', 'daemon_context_state_publish_checks.json': 'a0c631dcec58e837f66de9a1222f9789d8058b98d89b79c685393a5fcbbfa74e', 'daemon_context_state_publish_audit.json': '157858700ca7dd19ca2651c78ffebce0a502953fbb5599059a8ffc7c47dcec53', 'daemon_state_path_family_checks.json': 'b264e1892232c182f44e15fe3ff00f5a64804ed2d53dd17bae29d26fe94ddc82', 'daemon_state_path_family_audit.json': 'cdbb348eeee38b883aba51fcbac4285d70a2dfb36cf771a21a806f21bde40f32', 'daemon_count_pointer_origin_checks.json': 'e5b618f3d9d245d5d0a3919fae60d4be635905e32b34686b82dcec5d1be9dcb6', 'daemon_count_pointer_lineage_checks.json': 'dc0f782dbed641ce994be21437845794091bd2220ee2615a8cd793c1a681f1f7'}

DEPS=['daemon_receive_tools.py','recover_daemon_callback_revisit.py','recover_daemon_state_container_construction.py',
      'recover_daemon_record_input_origin.py','recover_daemon_count_pointer_lineage.py','replay_daemon_context_transfer.py']

def overlap(e,a,n):
    b=int(e['address'],16);return b<a+n and a<b+e['size_bytes']

def fixture_bytes(row,a,n):
    """Ordered overlays match the pinned parent restore/audit semantics."""
    values={}
    for kind in ['initial_private_fixtures','initial_image_fixtures']:
        for f in row[kind]:
            b=int(f['address'],16);raw=bytes.fromhex(f['bytes_hex'])
            for address in range(max(a,b),min(a+n,b+len(raw))):values[address]=raw[address-b]
    assert len(values)==n
    return bytes(values[a+k] for k in range(n)).hex()

def zero_chunk():
    p=json.loads(read(ROOT/'daemon_callback_revisit_profiles.json'));trace=raw_unpack(p)
    snapshot=json.loads(read(ROOT/'daemon_callback_revisit_snapshot.json'))
    backing={int(k):v for k,v in snapshot['inherited_unknown_backing'].items()}
    regs=trace['initial_registers'].copy();flags=int(trace['initial_NZCV'],16)
    frames=[];visits=[];reads=[];writes=[]
    for j,s in enumerate(trace['steps'][:27132]):
        if 27129<=j<=27131:
            frames.append({'pc':s['pc'],'registers31':[hex(int.from_bytes(evaluate(regs['x'+str(k)],backing),'little')) for k in range(31)],
                           'SP':hex(int.from_bytes(evaluate(regs['sp'],backing),'little')),'NZCV':hex(flags)})
        if 27129<=j<27131:
            assert s['bytes_hex']==IMAGE.read(int(s['pc'],16),4).hex()
            visits.append({'pc':s['pc'],'source_visit_index':j,'bytes_hex':s['bytes_hex'],'image':'daemon'})
            for e in s['events']:
                row={'pc':s['pc'],'source_visit_index':j,'address':e['address'],'size_bytes':e['size_bytes'],
                     'after_hex' if e['kind']=='write' else 'bytes_hex':e['value']['hex']}
                (writes if e['kind']=='write' else reads).append(row)
        regs.update(s['registers_after'])
        if 'NZCV_after' in s:flags=int(s['NZCV_after'],16) if isinstance(s['NZCV_after'],str) else s['NZCV_after']
    assert [v['pc'] for v in visits]==['0x10032197c','0x100321980']
    assert frames[0]['registers31'][8]==hex(J)
    assert [(w['address'],w['size_bytes'],w['after_hex']) for w in writes]==[(hex(J+32),8,'00'*8),(hex(J+40),8,'00'*8),(hex(J+48),4,'00'*4)]
    return {'kind':'constructor_zero20','start_visit':27129,'end_visit_exclusive':27131,
            'visits':visits,'frames':frames,'reads':reads,'writes':writes,'edges':[]}

def publications():
    p=json.loads(read(ROOT/'daemon_context_state_publish_checks.json'));out=[];chunks=[]
    for ci in [1,2,4,5]:
        c=p['cases'][ci];assert c['second_pointer_return64']=='0x6600004000'
        expected=c['MAC6_premise_hex'] or '00'*6;rows=[];copies=[];counts=[]
        for ii,row in enumerate(c['intervals']):
            tail=fixture_bytes(row,J+38,14);assert tail=='00'*14
            tail_writes=[w for w in row['source_writes'] if overlap(w,J+38,14)];assert not tail_writes
            writes=[w for w in row['source_writes'] if overlap(w,J+32,20)]
            for w in writes:
                assert w['pc']=='0x10059ccd8' and w['size_bytes']==1
                rr,=[r for r in row['source_reads'] if r['source_visit_index']==w['source_visit_index']-1]
                assert rr['pc']=='0x10059ccd4' and rr['bytes_hex']==w['after_hex']
                k=int(w['address'],16)-(J+32);assert 0<=k<6 and int(rr['address'],16)==0x1010c5768+k
                copies.append({'interval_index':ii,'index':k,'read':rr,'write':w})
                chunks.append(piece(row,rr['source_visit_index'],w['source_visit_index']+1,'network_byte_publication'))
            for w in row['source_writes']:
                if w['pc']=='0x10059797c':
                    assert (w['address'],w['size_bytes'],w['after_hex'])==(hex(J+28),4,'06000000')
                    j=w['source_visit_index'];chunks.append(piece(row,j-2,j+1,'network_count_publication'));counts.append(w)
            rows.append({'interval_index':ii,'entry_PC':row['entry_PC'],'end_PC':row['boundary']['pc'],
                         'incoming_tail_hex':tail,'tail_overlapping_writes':tail_writes,'data_overlapping_writes':writes})
        assert len(copies)==6 and [x['index'] for x in copies]==list(range(5,-1,-1)) and len(counts)==1
        assert c['final_context_hex'][64:104]==expected+'00'*14
        assert ''.join(x['write']['after_hex'] for x in reversed(copies))==expected
        out.append({'case_index':ci,'ABI_clobber_pattern':c['ABI_clobber_pattern'],
                    'MAC6_premise_hex':c['MAC6_premise_hex'],'data6_hex':expected,'final_data20_hex':c['final_context_hex'][64:104],
                    'intervals':rows,'byte_transfers':copies,'count_write':counts[0]})
    return out,chunks

def base_aliases():
    p=json.loads(read(ROOT/'daemon_state_path_family_checks.json'));out=[];chunks=[]
    assert len(p['cases'])==16
    for ci,c in enumerate(p['cases']):
        stages=[];prior=None;pc=None
        for ii in range(8,28):
            packed=c['intervals_packed'][ii];row=unpack(packed);ev=c['API_return_premises'][ii]
            cut=179 if ii==27 else len(row['source_visits'])
            writes=[w for w in row['source_writes'] if w['source_visit_index']<cut and overlap(w,SAVED,8)]
            if ii==8:
                w,=writes;assert w['pc']=='0x1004cf268' and w['after_hex']==JHEX
                j=w['source_visit_index'];assert row['source_frames'][j]['registers31'][22]==hex(J)
                assert row['source_frames'][j]['SP']=='0x6800060100'
                chunks.append(piece(row,j,j+1,'saved_context_base_input_store'))
                assert all(x['source_visit_index']==j for x in writes)
            else:assert not writes and fixture_bytes(row,SAVED,8)==prior==JHEX
            effects=memory_spans(ev);assert not any(overlap(x,SAVED,8) for x in effects)
            entry=row['entry_PC'];end=row['source_frames'][cut]['pc'] if cut<len(row['source_visits']) else row['boundary']['pc']
            if pc is not None:
                assert entry==hex(int(pc,16)+(4 if ev else 0))
                if ev:assert ev['call_site']==pc
            record={'interval_index':ii,'interval_sha256':packed['decoded_sha256'],'entry_PC':entry,'end_PC':end,
                    'cut_visit_exclusive':cut,'incoming_cell_hex':fixture_bytes(row,SAVED,8),
                    'outgoing_cell_hex':JHEX,'overlapping_writes':writes,'API_call_site':ev['call_site'] if ev else None,
                    'disjoint_API_spans':effects,'source_visits_examined':cut,
                    'write_events_examined':sum(w['source_visit_index']<cut for w in row['source_writes'])}
            if ii==27:
                r,=[r for r in row['source_reads'] if r['pc']=='0x1005d0f74'];w,=[w for w in row['source_writes'] if w['pc']=='0x1005d0f78']
                assert (r['source_visit_index'],w['source_visit_index'])==(177,178)
                assert r['address']==hex(SAVED) and r['bytes_hex']==w['after_hex']==JHEX and w['address']=='0x6800068038'
                record['last_read']=r;record['alias_store']=w
                chunks.append(piece(row,177,179,'saved_context_base_alias_store'))
            stages.append(record);prior=JHEX;pc=end
            del row;gc.collect()
        out.append({'family_case_index':ci,'parent_case_index':c['parent_case_index'],'ABI_clobber_pattern':c['ABI_clobber_pattern'],'stages':stages})
    return out,chunks

def build():
    for p,h in PINS.items():assert sha(ROOT/p)==h
    zero=zero_chunk();pub,pc=publications();bases,bc=base_aliases();chunks=[zero]+pc+bc
    later=json.loads(read(ROOT/'daemon_count_pointer_origin_checks.json'));snapshots=[]
    for c in later['cases']:
        snapshot=c['snapshot'];assert snapshot['bytes_hex']=='06000000'+'00'*20
        snapshots.append({'constructor_context_index':c['context_index'],'source_start':hex(J+28),
                          'destination_start':'0x6600040018','snapshot24_hex':snapshot['bytes_hex'],
                          'data20_hex':snapshot['bytes_hex'][8:],'tail14_hex':snapshot['bytes_hex'][20:]})
    counts={'constructor_zeroed_data_bytes':20,'network_success_controls':4,'nonzero_network_controls':2,
            'publication_intervals':sum(len(c['intervals']) for c in pub),'network_byte_transfers':24,
            'unchanged_tail_bytes_per_success_control':14,'saved_base_family_cases':16,
            'saved_base_lineage_stages':sum(len(c['stages']) for c in bases),'saved_base_boundary_links':16*19,
            'saved_base_recorded_visits_examined':sum(s['source_visits_examined'] for c in bases for s in c['stages']),
            'saved_base_write_events_examined':sum(s['write_events_examined'] for c in bases for s in c['stages']),
            'later_snapshot_layout_correspondences':len(snapshots),'source_chunks':len(chunks),
            'source_visits':sum(len(p['visits']) for p in chunks),'new_target_intervals':0,'new_root_bytes':0,'new_API_return_premises':0}
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),
            'parent_pins':PINS,'dependencies':{p:sha(ROOT/p) for p in DEPS},'constructor_zeroing':zero,
            'network_publications':pub,'saved_base_lineages':bases,'later_snapshot_layout_correspondences':snapshots,
            'chunks':chunks,'verified_counts':counts,'raw_success_network_storage_contract_established':True,
            'conditional_saved_base_alias_established':True,'native_constructor_epoch_join_established':False,
            'full_saved_base_to_count_producer_epoch_join_established':False,'native_API_executed':False,
            'native_daemon_kext_pairing_established':False,'full_goal_complete':False}

if __name__=='__main__':
    x=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(x,indent=2)+'\n');print(json.dumps(x['verified_counts']),flush=True)
