#!/usr/bin/env python3
"""Conditional saved-pointer lineage and earlier context-base publication.
O(image bytes+parent bytes+recorded visits+effect bytes+selected frames) time;
O(parent receipts+largest interval+compact lineage) space. No new target,
API, root byte, Mach operation or IDB action.
"""
import gc
import json
import struct
from functools import lru_cache
from daemon_receive_tools import ROOT,SOURCE,IMAGE
from verify_daemon_reader_record_payloads_publication import read,sha
from recover_daemon_state_container_construction import unpack
from recover_daemon_record_input_origin import piece

P="daemon_count_pointer_lineage"
J=0x6500115b20
CELL=0x68000672c0
EXPECTED=(J+28).to_bytes(8,"little").hex()
PINS={'daemon_state_path_family_checks.json': 'b264e1892232c182f44e15fe3ff00f5a64804ed2d53dd17bae29d26fe94ddc82', 'daemon_state_path_family_audit.json': 'cdbb348eeee38b883aba51fcbac4285d70a2dfb36cf771a21a806f21bde40f32', 'daemon_state_container_construction_checks.json': '1d19f7bc139ef5a334eb536ffc6f47a6f176553211402458b2a82fb649260ade', 'daemon_state_container_construction_audit.json': '1db414094dfe83752510cf330f25090c8f2b1fc63a75d1911c1a9481e47c4ea6', 'daemon_state_allocation_cascade_checks.json': '661c3f804d79bbbf49c44f4c464a1c773f43cbbc3fb796212d40a4deea46f809', 'daemon_state_allocation_cascade_audit.json': '81d62f637d5d932dce165be5686198ae50afcf727fd8aba6d4b90794f1f99641', 'daemon_state_emitter_completion_checks.json': '7339ebf095b22c8c390b536023d1639fbd2d36295124208a1784f1737f0bd2f1', 'daemon_state_emitter_completion_audit.json': 'f94527805283b8d0c99a5fd964e914e043ba57869bd551c4864c02ceb03931ba', 'daemon_state_table_mixing_checks.json': '48880e37460e2a7bf8862ebb59b739357791656bcb426a4b2ecc4643a94edbe7', 'daemon_state_table_mixing_audit.json': '15c8b51ba1a781a2ee03efa37e24e14737faed37851c614a037a30aebf0dac91', 'daemon_state_table_mixing_replay.json': 'db6afc8b68eeead78fcc0f7399ad0d8382b4bf4b964c74d52d686eea278ec0f8', 'daemon_table_consumer_checks.json': '5137ecaa23c9984c362309dced8482323b1aca63357dcac61d3de3090a695f14', 'daemon_table_consumer_audit.json': '05e23d2ba79cb44cde6226bc8dcf93fc280110810a3fdae1bed49edab9f05f8a', 'daemon_table_consumer_replay.json': '6318ee73698283ebfc4cf0534516402c471f75ae07b339feecfacdc4b433dd4c', 'daemon_constructor_gate_checks.json': '9c4ad519628142f228742dd3a011a6b10f94aa106783bd6ba30caffad70af6ff', 'daemon_constructor_gate_audit.json': 'd95e9e56e1fef1cd3f2fcf610670abcaa98e03159995d478d166e572d97d5b34', 'daemon_constructor_gate_replay.json': 'fc62eda40f7eeb4750c193183740342c223f684247ade9713b7fcd5decb047dc', 'daemon_constructor_buffer_checks.json': 'fe29b3d2d39daecdd79d1d00057229f0f583b8b0ead9c4eb9bd4fd5aa7cafa07', 'daemon_constructor_buffer_audit.json': '47108bdf5bedbb6a9aec1397ae777d6317a689cdea625638da5fb94a3c86e252', 'daemon_constructor_buffer_replay.json': '61f012a43cbae9cf2ff8a5207603a30b9bbf82c7b2d92811e0c1a2ff7505c107', 'daemon_descriptor_walk_checks.json': 'f11399df1f9b98d5b06ee61996c335d749a33b14ad764fe442cc47a03c419a50', 'daemon_descriptor_walk_replay.json': 'd09df40f234c9391aaaade51e397f69dbcc536063f4738fdaade624822ade023', 'daemon_descriptor_polynomial_checks.json': 'a43e977f7a9b786f44427b67e8152ba8e64ad940014c6cf821a800b9479b60c6', 'daemon_descriptor_polynomial_replay.json': '7acd16ed49134447d3588f8c2d4a00b0adfb0cd734217f8b939af82d03fd954c', 'daemon_descriptor_growth_checks.json': 'b2606c71e79e0ed6707d5102e00a96dc8f0f492e2b73b6087ca2cd47d4030ef2', 'daemon_descriptor_growth_replay.json': 'bee4ab3224710559fefdd8bca070110e48c03ab52d01c92b617988b9b3d5bd67', 'daemon_record_extension_checks.json': '9e89cde6b9d04019761c1f7370584e72ad85afc0aa0fd657f4cb4aa9ff0571d7', 'daemon_record_extension_replay.json': '7ffde847a48145ad9821ab9d228a345dbd7722ab6d00179836624c202b81993d', 'daemon_count_pointer_origin_checks.json': 'e5b618f3d9d245d5d0a3919fae60d4be635905e32b34686b82dcec5d1be9dcb6', 'daemon_count_pointer_origin_audit.json': 'b82f4d46a1ab485a7aa2359680e4b2e008f51a0137972f56ad97f52335be112c', 'daemon_payload_count_flow_checks.json': 'ae049dbc07c56b85bd8e5929b91cfc90078b54c739208d9a9a3396bdc0fb3a3b', 'daemon_payload_count_flow_audit.json': '8ce40257cf18caf157ce8803cbbd9085c150889079eed458e2fdf9ac22d5820b'}

DEPS=['daemon_receive_tools.py','recover_daemon_state_container_construction.py','recover_daemon_record_input_origin.py']

@lru_cache(None)
def parent(name):return json.loads(read(ROOT/('daemon_'+name+'_checks.json')))

def at(obj,path):
    for key in path:obj=obj[key]
    return obj

def span(x,a,n):
    b=int(x['address'],16);size=x.get('size_bytes',len(x.get('bytes_hex',''))//2)
    return b<a+n and a<b+size

def fixture_bytes(row,a,n):
    values={}
    for kind in ['initial_private_fixtures','initial_image_fixtures']:
        for f in row[kind]:
            b=int(f['address'],16);raw=bytes.fromhex(f['bytes_hex'])
            for address in range(max(a,b),min(a+n,b+len(raw))):
                byte=raw[address-b]
                if address in values:assert values[address]==byte
                values[address]=byte
    return None if len(values)!=n else bytes(values[a+k] for k in range(n)).hex()

def memory_spans(x):
    out=[]
    if isinstance(x,dict):
        if 'address' in x and ('size_bytes' in x or 'bytes_hex' in x):
            out.append({'address':x['address'],'size_bytes':x.get('size_bytes',len(x.get('bytes_hex',''))//2)})
        for v in x.values():out.extend(memory_spans(v))
    elif isinstance(x,list):
        for v in x:out.extend(memory_spans(v))
    return out

def mapping(ec):
    e=parent('record_extension')['classes'][ec];ri=e['representative_parent_index']
    gs=[(j,x) for j,x in enumerate(parent('descriptor_growth')['coverage']) if x['pointer_return64']=='0x6600080000']
    gi,g=gs[ri];co=g['cohort_index']
    def coverage(name,key,value):return next(x for x in parent(name)['coverage'] if x[key]==value)
    pol=coverage('descriptor_polynomial','cohort_index',co);walk=coverage('descriptor_walk','cohort_index',co)
    pi=walk['parent_index'];bi=walk['parent_branch_index'];b=parent('constructor_buffer')['branches'][bi]
    return {'record_class':ec,'record_parent':ri,'growth_coverage':gi,'growth_class':g['class_index'],'cohort':co,
            'polynomial_class':pol['class_index'],'walk_class':walk['class_index'],'constructor_parent':pi,
            'buffer_branch':bi,'buffer_prefix':b['prefix_class_index'],
            'gate_class':coverage('constructor_gate','parent_index',pi)['class_index'],
            'consumer_class':coverage('table_consumer','parent_index',pi)['class_index'],
            'mix_handoff_class':coverage('state_table_mixing','parent_index',pi)['handoff_class_index'],
            'emitter_class':coverage('state_emitter_completion','parent_index',pi)['class_index']}

def selections(m):
    pi=m['constructor_parent']
    def item(name,path,roots=None,cut=None):
        obj=at(parent(name),path)
        return {'parent_name':name,'selector':path,'kind':'interval','API_return_premise':obj.get('API_return_premise'),
                'entry_roots':roots or [],'cut_visit_exclusive':cut}
    def export(name,key,value,extra=None):
        ci=next(j for j,c in enumerate(parent(name)['coverage']) if c[key]==value and (extra is None or extra(c)))
        return {'parent_name':name,'selector':['coverage',ci],'kind':'export','API_return_premise':None,'entry_roots':[],'cut_visit_exclusive':None}
    yield item('state_container_construction',['contexts',pi,'buffer_frees',0])
    yield item('state_container_construction',['contexts',pi,'allocation_cases',1])
    for key in ['allocation21_cases','allocation48_cases']:
        yield item('state_allocation_cascade',['contexts',pi,key,1])
    yield item('state_allocation_cascade',['contexts',pi,'refill_comparison'])
    ci=m['emitter_class']
    for ii in range(len(parent('state_emitter_completion')['classes'][ci]['intervals'])):
        yield item('state_emitter_completion',['classes',ci,'intervals',ii])
    yield export('state_emitter_completion','parent_index',pi)
    for ii in range(len(parent('state_table_mixing')['shared_intervals'])):
        yield item('state_table_mixing',['shared_intervals',ii])
    yield item('state_table_mixing',['handoff_classes',m['mix_handoff_class']])
    yield export('state_table_mixing','parent_index',pi)
    ci=m['consumer_class']
    for ii in range(len(parent('table_consumer')['classes'][ci]['intervals'])):
        yield item('table_consumer',['classes',ci,'intervals',ii])
    yield export('table_consumer','parent_index',pi)
    ci=m['gate_class'];c=parent('constructor_gate')['classes'][ci]
    yield item('constructor_gate',['classes',ci],c['entry_premises'])
    yield export('constructor_gate','parent_index',pi)
    ci=m['buffer_prefix'];c=parent('constructor_buffer')['prefixes'][ci]
    yield item('constructor_buffer',['prefixes',ci],[c['entry_premise']])
    pc=next(j for j,x in enumerate(parent('constructor_buffer')['prefix_coverage']) if x['parent_index']==pi)
    yield {'parent_name':'constructor_buffer','selector':['prefix_coverage',pc],'kind':'export','API_return_premise':None,'entry_roots':[],'cut_visit_exclusive':None}
    ci=m['buffer_branch']
    for ii in range(len(parent('constructor_buffer')['branches'][ci]['intervals'])):
        yield item('constructor_buffer',['branches',ci,'intervals',ii])
    yield export('constructor_buffer','parent_index',pi,lambda x:x['branch_index']==ci)
    ci=m['walk_class'];c=parent('descriptor_walk')['classes'][ci]
    yield item('descriptor_walk',['classes',ci],[c['root_premise']])
    yield export('descriptor_walk','cohort_index',m['cohort'])
    ci=m['polynomial_class'];c=parent('descriptor_polynomial')['classes'][ci]
    yield item('descriptor_polynomial',['classes',ci],c['node_premises'])
    yield export('descriptor_polynomial','cohort_index',m['cohort'])
    ci=m['growth_class']
    for ii in range(len(parent('descriptor_growth')['classes'][ci]['intervals'])):
        yield item('descriptor_growth',['classes',ci,'intervals',ii])
    yield {'parent_name':'descriptor_growth','selector':['coverage',m['growth_coverage']],'kind':'export','API_return_premise':None,'entry_roots':[],'cut_visit_exclusive':None}
    for ii in [0,1]:yield item('record_extension',['classes',m['record_class'],'intervals',ii],cut=86099 if ii==1 else None)

def build():
    for p,h in PINS.items():assert sha(ROOT/p)==h
    pattern=0xf9000000+((0x7f38//8)<<10)+(31<<5)
    candidates=[]
    for va,offset,n in IMAGE.segments:
        for k in range(0,n-3,4):
            word=struct.unpack_from('<I',IMAGE.data,offset+k)[0]
            if word&0xffffffe0==pattern:
                candidates.append({'PC':hex(va+k),'word_hex':IMAGE.data[offset+k:offset+k+4].hex()})
    assert [x['PC'] for x in candidates]==['0x1005d0f78','0x10077fe50','0x10080c458']
    upstream=[];chunks=[]
    for ci,c in enumerate(parent('state_path_family')['cases']):
        packed=c['intervals_packed'][27];row=unpack(packed)
        r,=[r for r in row['source_reads'] if r['pc']=='0x1005d0f74']
        w,=[w for w in row['source_writes'] if span(w,0x6800068038,8)]
        assert (r['source_visit_index'],r['address'],r['bytes_hex'])==(177,'0x6800060ab8',J.to_bytes(8,'little').hex())
        assert (w['source_visit_index'],w['pc'],w['address'],w['after_hex'])==(178,'0x1005d0f78','0x6800068038',r['bytes_hex'])
        upstream.append({'family_case_index':ci,'parent_case_index':c['parent_case_index'],'ABI_clobber_pattern':c['ABI_clobber_pattern'],
                         'interval_sha256':packed['decoded_sha256'],'read':r,'write':w})
        chunks.append(piece(row,177,179,'saved_context_base_publication'))
    chains=[]
    for ec in [2,3]:
        m=mapping(ec);stages=[];prior=None;prior_pc=None
        for ordinal,s in enumerate(selections(m)):
            obj=at(parent(s['parent_name']),s['selector']);packed=obj['interval_packed' if s['kind']=='interval' else 'derived_terminal_state_packed']
            row=unpack(packed);n=len(row['source_visits']);cut=s['cut_visit_exclusive'] if s['cut_visit_exclusive'] is not None else n
            incoming=fixture_bytes(row,CELL,8);writes=[w for w in row['source_writes'] if w['source_visit_index']<cut and span(w,CELL,8)]
            if ordinal==0:
                assert len(writes)==1 and writes[0]['pc']=='0x100710630' and writes[0]['after_hex']==EXPECTED
                outgoing=EXPECTED
            else:
                assert incoming==prior==EXPECTED and not writes
                outgoing=incoming
            effects=memory_spans(s['API_return_premise'])+memory_spans(s['entry_roots'])
            assert not any(span(x,CELL,8) for x in effects)
            entry=row['entry_PC'] if s['kind']=='interval' else row['boundary']['pc']
            end=row['source_frames'][cut]['pc'] if cut<n else row['boundary']['pc']
            if prior_pc is not None:
                assert entry==hex(int(prior_pc,16)+(4 if s['API_return_premise'] else 0)),(s,entry,prior_pc)
            record={**s,'interval_sha256':packed['decoded_sha256'],'entry_PC':entry,'end_PC':end,
                    'incoming_cell_hex':incoming,'outgoing_cell_hex':outgoing,'overlapping_writes':writes,
                    'examined_source_visits':cut,'examined_write_events':sum(w['source_visit_index']<cut for w in row['source_writes']),
                    'disjoint_premise_spans':effects}
            if s['parent_name']=='record_extension' and s['selector'][-1]==1:
                rr,=[r for r in row['source_reads'] if r['pc']=='0x10083e780'];assert rr['source_visit_index']==86098 and rr['bytes_hex']==EXPECTED and int(rr['address'],16)==CELL
                record['consumer_read']=rr;chunks.append(piece(row,86098,86099,'later_count_pointer_read'))
            stages.append(record);prior=outgoing;prior_pc=end
            del row;gc.collect()
        chains.append({'mapping':m,'stages':stages})
        print(json.dumps({'record_class':ec,'constructor_parent':m['constructor_parent'],'stages':len(stages),'root_bytes':sum(len(f['bytes_hex'])//2 for s in stages for f in s['entry_roots'])}),flush=True)
    counts={'upstream_family_cases':len(upstream),'conditional_pointer_lineages':2,
            'lineage_stages':sum(len(c['stages']) for c in chains),
            'cell_boundary_links':sum(len(c['stages'])-1 for c in chains),
            'examined_recorded_visits':sum(s['examined_source_visits'] for c in chains for s in c['stages']),
            'examined_write_events':sum(s['examined_write_events'] for c in chains for s in c['stages']),
            'inherited_entry_root_bytes_per_lineage':116,'source_chunks':len(chunks),
            'source_visits':sum(len(p['visits']) for p in chunks),'new_target_intervals':0,'new_root_bytes':0,'new_API_return_premises':0}
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'parent_pins':PINS,
            'dependencies':{p:sha(ROOT/p) for p in DEPS},'upstream_base_publications':upstream,
            'direct_SP_7f38_store_pattern_candidates':candidates,'direct_store_scan_mask32':0xffffffe0,
            'direct_store_scan_pattern32':pattern,'direct_store_scan_scope':'all aligned words of file-backed segments; candidates may include data; indirect aliases excluded',
            'conditional_lineages':chains,'chunks':chunks,'verified_counts':counts,
            'conditional_count_pointer_byte_lineage_established':True,'full_constructor_to_consumer_epoch_join_established':False,
            'native_constructor_epoch_join_established':False,'native_API_executed':False,
            'native_daemon_kext_pairing_established':False,'full_goal_complete':False}

if __name__=='__main__':
    x=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(x,indent=2)+'\n');print(json.dumps(x['verified_counts']),flush=True)
