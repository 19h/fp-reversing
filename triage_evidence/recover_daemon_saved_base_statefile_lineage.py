#!/usr/bin/env python3
"""Saved context-base lineage across retained SIDB/SIDN filesystem controls.
O(parent bytes+unique recorded visits+effect bytes+chain links) time;
O(parent receipts+largest interval+compact stages/chains) space.
No new target interval, API return, root bytes, IPC or IDB action.
"""
import gc,json
from collections import Counter
from daemon_receive_tools import ROOT,SOURCE
from verify_daemon_reader_record_payloads_publication import read,sha
from recover_daemon_state_container_construction import unpack
from recover_daemon_record_input_origin import piece
from recover_daemon_count_pointer_lineage import parent,at,memory_spans
from recover_daemon_context_network_storage import fixture_bytes,overlap

P='daemon_saved_base_statefile_lineage'
J=0x6500115b20;CELL=0x6800068038;VALUE=J.to_bytes(8,'little').hex()
NAMES=['state_path_family','state_file_admission','state_file_metadata','state_file_input',
       'state_word_routing','state_path_removal','state_container_construction',
       'context_network_storage','count_pointer_origin','count_pointer_lineage']
PINS={'daemon_state_path_family_checks.json': 'b264e1892232c182f44e15fe3ff00f5a64804ed2d53dd17bae29d26fe94ddc82', 'daemon_state_path_family_audit.json': 'cdbb348eeee38b883aba51fcbac4285d70a2dfb36cf771a21a806f21bde40f32', 'daemon_state_file_admission_checks.json': '093f49d0085d6c94cbaf1a27b68a3a7e2d0caee8354eb0e5162dff7c048a9008', 'daemon_state_file_admission_audit.json': '3a216888a8eb8d2767efee8f24b12dbadffcc8a5c9636c71cba37f4f4ef49cce', 'daemon_state_file_metadata_checks.json': '5b3c1afdb63249ce5a6ea5ba39701b2a9010ba2e1ce259284fbfb1652d2e6c23', 'daemon_state_file_metadata_audit.json': '85528d5d16ef6269ec172e5481bcb9872c3a6145e9b41123c25f0256f7d1f51c', 'daemon_state_file_input_checks.json': 'cdd60c06abc58fbb4b891ef851c6fa563ccff2fe671057d135a3633af379bd2b', 'daemon_state_file_input_audit.json': '03f9d598480d49ba7f28e9d31379c1892aae2ac366175811139ba42d5ee042bf', 'daemon_state_word_routing_checks.json': '8b8018a75831eeb9c205087dabc5be372a7d30b6a756c6fb344529108ad55565', 'daemon_state_word_routing_audit.json': '9fa9599b2f510aab80d74a73dd55ab409af362790e51606a025a4d1456838e96', 'daemon_state_path_removal_checks.json': '0e62dbdb1446e6751b3912b53e136bc467e249b8dacd2615960d9ab80ec83fb1', 'daemon_state_path_removal_audit.json': '195067aac1f44f3eb7e7d02cc3e9bf79fd22f144ed85812a30ee7e4b9d8712b3', 'daemon_state_container_construction_checks.json': '1d19f7bc139ef5a334eb536ffc6f47a6f176553211402458b2a82fb649260ade', 'daemon_state_container_construction_audit.json': '1db414094dfe83752510cf330f25090c8f2b1fc63a75d1911c1a9481e47c4ea6', 'daemon_context_network_storage_checks.json': '3e28325a3ea3c23e8074002d933686c6f9f29998b9a744363aa28067bc136e06', 'daemon_context_network_storage_audit.json': '30cb2ad9fb16deb06e70e52fd101f6fcc08aa7a589e496a2e50f0b873a9f6ede', 'daemon_count_pointer_origin_checks.json': 'e5b618f3d9d245d5d0a3919fae60d4be635905e32b34686b82dcec5d1be9dcb6', 'daemon_count_pointer_origin_audit.json': 'b82f4d46a1ab485a7aa2359680e4b2e008f51a0137972f56ad97f52335be112c', 'daemon_count_pointer_lineage_checks.json': 'dc0f782dbed641ce994be21437845794091bd2220ee2615a8cd793c1a681f1f7', 'daemon_count_pointer_lineage_audit.json': 'cd50e869fd7e5526dbe544fd31d9bc74fd1f3cf9ac83cd3359d1624496395d85'}
DEPS=['daemon_receive_tools.py','recover_daemon_state_container_construction.py',
      'recover_daemon_record_input_origin.py','recover_daemon_count_pointer_lineage.py',
      'recover_daemon_context_network_storage.py']


def ancestry(pi):
    c=parent('state_container_construction')['contexts'][pi]
    ri=c['parent_context_index'];qi=c['parent_SIDN_query_index'];r=parent('state_path_removal')['contexts'][ri]
    wi=r['parent_case_index'];w=parent('state_word_routing')['cases'][wi]
    ii=w['parent_context_index'];ti=w['parent_timestamp_case_index'];i=parent('state_file_input')['contexts'][ii]
    mi=i['parent_context_index'];m=parent('state_file_metadata')['contexts'][mi]
    ai=m['parent_context_index'];oi=m['parent_open_case_index'];a=parent('state_file_admission')['contexts'][ai]
    return {'constructor_parent':pi,'removal_context':ri,'SIDN_query':qi,'word_case':wi,'input_context':ii,
            'timestamp_case':ti,'metadata_context':mi,'admission_context':ai,'open_case':oi,
            'family_case':a['parent_case_index']}


def selectors(m):
    """Chronological source intervals; scalar and API transitions stay distinct."""
    out=[]
    def add(name,path):out.append((name,path))
    fi=m['family_case'];ai=m['admission_context'];oi=m['open_case'];mi=m['metadata_context'];ii=m['input_context']
    for j in [27,28]:add('state_path_family',['cases',fi,'intervals_packed',j])
    for key,j in [('stat_cases',0),('mode_cases',1)]:add('state_file_admission',['contexts',ai,key,j])
    op=parent('state_file_admission')['contexts'][ai]['open_cases'][oi];assert not op['invoke_callback']
    for j in range(len(op['intervals_packed'])):add('state_file_admission',['contexts',ai,'open_cases',oi,'intervals_packed',j])
    for key,j in [('open_cases',3),('fstat_cases',0),('size_cases',2)]:add('state_file_metadata',['contexts',mi,key,j])
    for key,j in [('nonnull_allocations',2),('read_cases',4),('success_lock_cases',0),('success_lock_cases',1)]:
        add('state_file_input',['contexts',ii,key,j])
    tp=['contexts',ii,'timestamp_cases',m['timestamp_case']]
    for key in ['seconds','nanoseconds']:add('state_file_input',tp+[key])
    for j in range(3):add('state_file_input',tp+['completion',j])
    for key in ['prefix','errno_accessor']:add('state_word_routing',['cases',m['word_case'],key])
    ri=m['removal_context'];qi=m['SIDN_query'];r=parent('state_path_removal')['contexts'][ri];q=r['SIDN_queries'][qi]
    rp=['contexts',ri];kind=q['origin_kind'];j=q['origin_index']
    if kind=='errno':
        ei,wi=divmod(j,4);add('state_path_removal',rp+['stat_cases',r['error_accessors'][ei]['stat_case_index']])
        add('state_path_removal',rp+['error_accessors',ei]);add('state_path_removal',rp+['error_accessors',ei,'word_cases',wi])
    else:
        add('state_path_removal',rp+['stat_cases',0]);add('state_path_removal',rp+['mode_cases',j if kind=='mode' else 1])
        if kind in ['unlink','sync']:add('state_path_removal',rp+['unlink_cases',j if kind=='unlink' else 0])
        if kind=='sync':
            for k in range(4):add('state_path_removal',rp+['synchronization_cases',j,'returns',k])
    add('state_path_removal',rp+['SIDN_queries',qi])
    cp=['contexts',m['constructor_parent']]
    for key,j in [('stat_cases',0),('mode_cases',0),('buffer_frees',0)]:add('state_container_construction',cp+[key,j])
    return out


def materialize(name,path):
    obj=at(parent(name),path)
    if path[-2]=='intervals_packed':
        ev=at(parent(name),path[:-2]+['API_return_premises',path[-1]])
        packed=obj;output=None
    else:packed=obj['interval_packed'];ev=obj.get('API_return_premise');output=obj.get('output_premise')
    return unpack(packed),packed,ev,output


def stage(name,path):
    row,packed,ev,output=materialize(name,path);first=name=='state_path_family' and path[-1]==27
    last=name=='state_container_construction' and path[-2]=='buffer_frees'
    lo=177 if first else 0;hi=113 if last else len(row['source_visits'])
    if first:ev=None;output=None
    writes=[w for w in row['source_writes'] if lo<=w['source_visit_index']<hi and overlap(w,CELL,8)]
    if first:
        w,=writes;assert (w['pc'],w['source_visit_index'],w['after_hex'])==('0x1005d0f78',178,VALUE)
    else:assert not writes and fixture_bytes(row,CELL,8)==VALUE
    spans=memory_spans([ev,output]);assert not any(overlap(s,CELL,8) for s in spans)
    chunks=[]
    if first:chunks.append(piece(row,177,179,'context_base_alias_publication'))
    if last:
        r,=[r for r in row['source_reads'] if r['pc']=='0x1008337c4'];assert (r['source_visit_index'],r['address'],r['bytes_hex'])==(29,hex(CELL),VALUE)
        w,=[w for w in row['source_writes'] if w['pc']=='0x100710630'];assert w['source_visit_index']==112 and w['after_hex']==(J+28).to_bytes(8,'little').hex()
        chunks.extend([piece(row,29,30,'saved_context_base_reload'),piece(row,111,113,'count_pointer_publication')])
    result={'parent_name':name,'selector':path,'interval_sha256':packed['decoded_sha256'],
            'start_visit':lo,'cut_visit_exclusive':hi,'entry_PC':row['source_frames'][lo]['pc'] if lo else row['entry_PC'],
            'end_PC':row['source_frames'][hi]['pc'] if hi<len(row['source_visits']) else row['boundary']['pc'],
            'API_return_premise':ev,'output_premise':output,'disjoint_premise_spans':spans,
            'incoming_cell_hex':None if first else fixture_bytes(row,CELL,8),'outgoing_cell_hex':VALUE,'overlapping_writes':writes,
            'recorded_visits_examined':hi-lo,'recorded_write_events_examined':sum(lo<=w['source_visit_index']<hi for w in row['source_writes'])}
    if last:result.update(base_reload=r,count_pointer_store=w)
    del row;gc.collect();return result,chunks


def build():
    for p,h in PINS.items():assert sha(ROOT/p)==h
    stages=[];cache={};chains=[];chunks=[];totals=Counter()
    for pi in range(76):
        m=ancestry(pi);ids=[];previous=None
        for name,path in selectors(m):
            key=json.dumps([name,path])
            if key not in cache:
                rec,parts=stage(name,path);cache[key]=len(stages);stages.append(rec);chunks.extend(parts)
            si=cache[key];s=stages[si]
            if previous is not None:
                assert int(s['entry_PC'],16)==int(previous['end_PC'],16)+(4 if s['API_return_premise'] else 0)
                assert previous['outgoing_cell_hex']==s['incoming_cell_hex']==VALUE
                if s['API_return_premise']:assert s['API_return_premise']['call_site']==previous['end_PC']
                totals['chain_boundary_links']+=1
            ids.append(si);previous=s
        chains.append({'ancestry':m,'stage_indices':ids})
    counts={'constructor_contexts':76,'pathname_family_sources':len({c['ancestry']['family_case'] for c in chains}),
            'SIDB_word_parent_selections':len({c['ancestry']['word_case'] for c in chains}),
            'unique_stages':len(stages),'chain_stages':sum(len(c['stage_indices']) for c in chains),
            'chain_boundary_links':totals['chain_boundary_links'],
            'unique_API_transition_stages':sum(bool(s['API_return_premise']) for s in stages),
            'unique_scalar_output_stages':sum(bool(s['output_premise']) for s in stages),
            'unique_recorded_visits_examined':sum(s['recorded_visits_examined'] for s in stages),
            'unique_recorded_write_events_examined':sum(s['recorded_write_events_examined'] for s in stages),
            'source_chunks':len(chunks),'source_visits':sum(len(c['visits']) for c in chunks),
            'new_target_intervals':0,'new_root_bytes':0,'new_API_return_premises':0}
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'parent_pins':PINS,
            'dependencies':{p:sha(ROOT/p) for p in DEPS},'stages':stages,'chains':chains,'chunks':chunks,'verified_counts':counts,
            'conditional_saved_base_to_count_producer_lineage_established':True,
            'whole_machine_context_lifetime_established':False,'native_constructor_epoch_join_established':False,
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'full_goal_complete':False}


if __name__=='__main__':
    x=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(x,indent=2)+'\n');print(json.dumps(x['verified_counts']),flush=True)
