#!/usr/bin/env python3
"""Saved count-pointer initialization and 24 B container snapshot.
O(P+V+E+32C) time, O(parent receipts+largest interval+selected chunks)
space; P parent bytes, V examined visits, E memory-event bytes, C selected
frames. Reuses retained epochs; no new target/API/IPC or IDB operation.
"""
import json
from daemon_receive_tools import ROOT, SOURCE
from verify_daemon_reader_record_payloads_publication import read, sha
from recover_daemon_state_container_construction import unpack
from recover_daemon_record_input_origin import piece
from recover_daemon_payload_count_flow import cell_value

P='daemon_count_pointer_origin'
J=0x6500115b20
S=0x6600040000
SP=0x6800060100
CELL=SP+0x71c0
PINS={'daemon_state_container_construction_checks.json':'1d19f7bc139ef5a334eb536ffc6f47a6f176553211402458b2a82fb649260ade',
      'daemon_state_container_construction_audit.json':'1db414094dfe83752510cf330f25090c8f2b1fc63a75d1911c1a9481e47c4ea6',
      'daemon_payload_count_flow_checks.json':'ae049dbc07c56b85bd8e5929b91cfc90078b54c739208d9a9a3396bdc0fb3a3b'}
DEPS=['daemon_receive_tools.py','recover_daemon_state_container_construction.py',
      'recover_daemon_record_input_origin.py','recover_daemon_payload_count_flow.py']
REPRESENTATIVES=[0,19,38,57]


def overlap(e,a,n):
    b=int(e['address'],16)
    return b<a+n and a<b+e['size_bytes']


def build():
    for p,h in PINS.items():assert sha(ROOT/p)==h
    parent=json.loads(read(ROOT/'daemon_state_container_construction_checks.json'))
    cases=[];representatives=[]
    assert len(parent['contexts'])==76
    for ci,c in enumerate(parent['contexts']):
        paths=[];selected=[]
        assert len(c['buffer_frees'])==12
        for fi,item in enumerate(c['buffer_frees']):
            row=unpack(item['interval_packed'])
            r,=[r for r in row['source_reads'] if r['pc']=='0x1008337c4']
            w,=[w for w in row['source_writes'] if overlap(w,CELL,8)]
            assert (r['source_visit_index'],r['address'],r['bytes_hex'])==(29,hex(SP+0x7f38),J.to_bytes(8,'little').hex())
            assert (w['source_visit_index'],w['pc'],w['address'],w['after_hex'])==(112,'0x100710630',hex(CELL),(J+28).to_bytes(8,'little').hex())
            assert all(f['registers31'][21]==hex(J) for f in row['source_frames'][30:113])
            assert row['source_frames'][111]['SP']==hex(SP)
            assert row['source_frames'][113]['registers31'][9]==hex(J+28)
            assert cell_value(row,CELL)==w['after_hex']
            paths.append({'free_index':fi,'origin_kind':item['origin_kind'],'origin_index':item['origin_index'],
                          'interval_sha256':item['interval_packed']['decoded_sha256'],
                          'saved_context_pointer_read':r,'count_pointer_write':w,'X21_preserved_frames':83})
            if ci in REPRESENTATIVES and fi==0:
                selected=[piece(row,29,30,'saved_context_pointer_load'),piece(row,111,113,'count_pointer_initialization')]
        item=c['allocation_cases'][1];assert item['pointer_return64']==hex(S)
        row=unpack(item['interval_packed'])
        load,=[r for r in row['source_reads'] if r['pc']=='0x100595f5c']
        assert (load['address'],load['bytes_hex'])==(hex(CELL),paths[0]['count_pointer_write']['after_hex'])
        assert cell_value(row,CELL,load['source_visit_index'])==load['bytes_hex']
        assert not any(overlap(w,CELL,8) for w in row['source_writes'])
        call,=[x for x in row['source_calls'] if x['pc']=='0x100595f84']
        assert (call['target'],call['modifier'],call['arguments8'][:3])==('0x10046f89c','0x34a1',[hex(J+28),hex(S+24),'0x18'])
        reads=[r for r in row['source_reads'] if 0x10046f89c<=int(r['pc'],16)<0x10046fa90]
        writes=[w for w in row['source_writes'] if 0x10046f89c<=int(w['pc'],16)<0x10046fa90]
        assert len(reads)==len(writes)==24
        for k,(r,w) in enumerate(zip(reads,writes)):
            assert r['size_bytes']==w['size_bytes']==1
            assert (r['address'],w['address'],r['bytes_hex'])==(hex(J+28+k),hex(S+24+k),w['after_hex'])
            assert w['source_visit_index']==r['source_visit_index']+1
        snapshot=''.join(r['bytes_hex'] for r in reads)
        assert snapshot=='06000000'+'00'*20
        cases.append({'context_index':ci,'parent_context_index':c['parent_context_index'],
                      'ABI_clobber_pattern':c['ABI_clobber_pattern'],'pointer_paths':paths,
                      'snapshot':{'interval_sha256':item['interval_packed']['decoded_sha256'],
                                  'saved_pointer_reload':load,'call':call,'reads':reads,'writes':writes,'bytes_hex':snapshot,
                                  'incoming_saved_pointer_matches_first_free_output':True,
                                  'overlapping_pointer_writes':0}})
        if selected:
            selected.append(piece(row,load['source_visit_index'],load['source_visit_index']+1,'snapshot_source_pointer_reload'))
            selected.extend(piece(row,r['source_visit_index'],r['source_visit_index']+2,'snapshot_byte_transfer') for r in reads)
            representatives.append({'context_index':ci,'chunks':selected})
    consumer=json.loads(read(ROOT/'daemon_payload_count_flow_checks.json'))
    consumers=[]
    for c in consumer['cases']:
        r,=[r for chunk in c['intervals'][0]['chunks'] for r in chunk['reads'] if r['pc']=='0x10083e780']
        assert (r['address'],r['bytes_hex'])==(hex(CELL),(J+28).to_bytes(8,'little').hex())
        consumers.append({'class_index':c['class_index'],'read':r})
    counts={'retained_constructor_contexts':76,'free_return_paths':912,'pointer_stores':912,
            'X21_preserved_frame_checks':912*83,'snapshot_copies':76,'snapshot_bytes':76*24,
            'saved_pointer_boundary_links':76,'consumer_layout_correspondences':2,
            'representative_contexts':4,'source_chunks':sum(len(c['chunks']) for c in representatives),
            'source_visits':sum(len(p['visits']) for c in representatives for p in c['chunks']),
            'new_target_intervals':0,'new_root_bytes':0,'new_API_return_premises':0}
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),
            'parent_pins':PINS,'dependencies':{p:sha(ROOT/p) for p in DEPS},'cases':cases,
            'representatives':representatives,'later_consumer_layout_correspondences':consumers,
            'verified_counts':counts,'retained_pointer_initialization_established':True,
            'full_constructor_to_consumer_epoch_join_established':False,'native_constructor_epoch_join_established':False,
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'full_goal_complete':False}


if __name__=='__main__':
    x=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(x,indent=2)+'\n')
    print(json.dumps(x['verified_counts']),flush=True)
