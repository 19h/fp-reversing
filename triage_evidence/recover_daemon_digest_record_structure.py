#!/usr/bin/env python3
"""Digest-body source inputs, nested span layout and post-read overwrites.
Conservative O(P+(Q+C)*E+(E+Q)*log(E+Q)+32V) time; P parent bytes,
Q queries, C chunks, E events/fixture bytes, V selected visits. Space is
O(parent receipts+largest interval+selected frames). No new target execution,
root input, API-return premise, native operation or IDB mutation.
"""
import gc
import json
from bisect import bisect_left
from collections import defaultdict
from daemon_receive_tools import ROOT, SOURCE
from verify_daemon_reader_record_payloads_publication import read, sha
from recover_daemon_record_extension import unpack
from recover_daemon_record_input_origin import piece, byte_origins
from recover_daemon_packed_words import PHASE

P='daemon_digest_record_structure'
PINS={'daemon_record_extension_checks.json':'9e89cde6b9d04019761c1f7370584e72ad85afc0aa0fd657f4cb4aa9ff0571d7',
      'daemon_record_extension_replay.json':'7ffde847a48145ad9821ab9d228a345dbd7722ab6d00179836624c202b81993d',
      'daemon_digest_body_origins_checks.json':'625ffd36a7cca083c4e20b295639adbdd190d858e2b83a7c4ff81f30e66f1758',
      'daemon_digest_body_origins_audit.json':'dc216f1beb7244d7269b4d2bf682ef5d80dc1d2a4e844ecd20ab14fc735fa239',
      'daemon_packed_words_checks.json':'e8d3a4ffe60b0a28944a5d4a47227f6d313c609e00ab8dcc304c38fc00734554',
      'daemon_packed_words_audit.json':'fc68105796266bb76dbf92fa3c8efc35fed3d970b4bd6aa11ed08aedd4bd2aaa',
      'daemon_append_fields_audit.json':'a79919e954824d1e1716e3298b455d6f8f03966cfc5ef6242c80d97dad903049'}
DEPS=['daemon_receive_tools.py','recover_daemon_record_extension.py','recover_daemon_record_input_origin.py',
      'recover_daemon_packed_words.py','recover_daemon_record_banks.py']
STARTS={'0x100c29254':'packed','0x1009dabb0':'array','0x100a630cc':'opaque_a','0x100a86930':'opaque_b'}


def model_temper(x):
    x^=x>>11;x^=(x<<7)&0x9d2c5680;x^=(x<<15)&0xefc60000
    return (x^(x>>18))&0xffffffff


def build():
    for p,d in PINS.items():assert sha(ROOT/p)==d
    old=json.loads(read(ROOT/'daemon_record_extension_checks.json'))
    body=json.loads(read(ROOT/'daemon_digest_body_origins_checks.json'))
    cases=[]
    for bc in body['cases']:
        ci=bc['class_index'];intervals=[];fields=[];tempered=[];future=[]
        for ii in range(9,0,-1):
            item=old['classes'][ci]['intervals'][ii];row=unpack(item['interval_packed'])
            chunks=set();readmap=defaultdict(list)
            for r in row['source_reads']:readmap[r['source_visit_index']].append(r)
            for wg in [w for w in bc['word_groups'] if w['interval_index']==ii]:
                cut=wg['start_visit'];lo=next(j for j in range(cut-1,-1,-1) if row['source_visits'][j]['pc'] in STARTS)
                kind=STARTS[row['source_visits'][lo]['pc']];start=lo
                hi=wg['writer_visits'][-1]+1
                entry=row['source_frames'][lo];values={'source_A32':entry['registers31'][8],
                    'normalized4_hex':wg['decoded4_hex'],'writer_W11':wg['source_W11']}
                selected=[]
                if kind=='packed':
                    rr=[r for r in row['source_reads'] if lo<=r['source_visit_index']<lo+364]
                    nr,=[r for r in rr if r['pc']=='0x100c29260'];kr,=[r for r in rr if r['pc']=='0x100c2943c']
                    n=int.from_bytes(bytes.fromhex(nr['bytes_hex']),'little');d=int.from_bytes(bytes.fromhex(kr['bytes_hex']),'little')^0x8b3dc651
                    auxiliary=int(entry['registers31'][8],16)^0x6703cce9
                    packed=((((auxiliary<<(n&31))&0x07ffffff)|((n<<27)&0xffffffff))+d)&0xffffffff
                    assert packed.to_bytes(4,'big').hex()==wg['decoded4_hex'] and n==max(1,d.bit_length()) and 1<=n<=27
                    origins=byte_origins(row,[nr,kr]);writers={o['writer']['source_visit_index']:o['writer'] for x in origins for o in x['origins']}
                    assert len(writers)==2 and all(len(x['origins'])==4 for x in origins)
                    raw_writer,=[w for w in writers.values() if w['pc']=='0x100a30dfc']
                    count_writer,=[w for w in writers.values() if w['pc']=='0x100add45c']
                    a,b=raw_writer['source_visit_index'],count_writer['source_visit_index']
                    assert row['source_visits'][a-3]['pc']=='0x100a30df0'
                    chunks.update([(a-3,a-2,'count_initialization'),(a,a+1,'raw_scalar_store'),(b,b+1,'count_store')])
                    steps=[]
                    for j in range(a,b):
                        if row['source_visits'][j]['pc']!='0x100cc81e0':continue
                        regs=[int(x,16) for x in row['source_frames'][j]['registers31']]
                        assert all(regs[k]==v for k,v in PHASE.items())
                        steps.append({'source_visit':j,'current_scalar32':regs[11]^0x8b3dc651,'counter32':regs[10]})
                        chunks.add((j,j+20,'count_loop_with_branch'))
                    assert len(steps)==n and [s['current_scalar32'] for s in steps]==[d>>j for j in range(n)]
                    values.update(count32=n,decoded_scalar32=d,auxiliary32=hex(auxiliary),packed32=hex(packed),
                                  retained_auxiliary_bits=27-n,retained_auxiliary_value=hex(auxiliary&((1<<(27-n))-1)),
                                  count_steps=steps,scalar_and_count_reads=[kr,nr],scalar_and_count_origins=origins)
                    selected=[nr,kr]
                elif kind=='array':
                    start=lo-17;assert row['source_visits'][start]['pc']=='0x1009dab6c'
                    pointer,=readmap[start];element,=readmap[start+1]
                    base=int.from_bytes(bytes.fromhex(pointer['bytes_hex']),'little');index=int(row['source_frames'][start+1]['registers31'][11],16)
                    raw=int.from_bytes(bytes.fromhex(element['bytes_hex']),'little')
                    assert int(element['address'],16)==base+4*index and ((raw+0xb69f7313)&0xffffffff).to_bytes(4,'big').hex()==wg['decoded4_hex']
                    values.update(array_pointer_read=pointer,array_element_read=element,index32=index,array_base=hex(base),
                                  raw_element32=hex(raw),element_origins=byte_origins(row,[element]))
                    selected=[element]
                else:
                    values['application_semantics']='unknown'
                chunks.add((start,hi,kind+'_producer_to_word_stores'))
                fields.append({'kind':kind,'interval_index':ii,'owner_offset_bytes':wg['owner_offset_bytes'],
                               'start_visit':start,'end_visit_exclusive':hi,'values':values})
            for word in sorted({b['source_W9'] for b in bc['byte_fields'] if b['interval_index']==ii}):
                fields_b=[b for b in bc['byte_fields'] if b['interval_index']==ii and b['source_W9']==word]
                cut=min(b['start_visit'] for b in fields_b)
                lo=next(j for j in range(cut-1,-1,-1) if row['source_visits'][j]['pc']=='0x100a7ccc0')
                raw=int(row['source_frames'][lo]['registers31'][19],16)&0xffffffff
                assert model_temper(raw)==int(word,16)
                assert int(row['source_frames'][lo]['registers31'][10],16)&31==6
                chunks.add((lo,lo+12,'word_tempering'))
                # Original instructions through each selected consumer establish W9 preservation.
                for b in fields_b:
                    assert all((int(f['registers31'][9],16)&0xffffffff)==int(word,16)
                               for f in row['source_frames'][lo+12:b['start_visit']+1])
                tempered.append({'interval_index':ii,'start_visit':lo,'raw_W19':hex(raw),'tempered_W9':word,
                                 'consumer_start_visits':[b['start_visit'] for b in fields_b],
                                 'destinations':[b['destination'] for b in fields_b]})
            histories=defaultdict(list)
            for w in row['source_writes']:
                for k,b in enumerate(bytes.fromhex(w['after_hex'])):histories[int(w['address'],16)+k].append((w['source_visit_index'],w,k,b))
            query_count=0
            for chain in bc['chains']:
                for s in chain['steps']:
                    if s['interval_index']!=ii:continue
                    query_count+=1;cut=s['before_visit_exclusive']
                    if cut is None:continue
                    h=histories[int(s['address'],16)];n=bisect_left(h,cut,key=lambda x:x[0])
                    if n==len(h):continue
                    j,w,k,b=h[n]
                    future.append({'interval_index':ii,'body_byte':chain['body_byte'],'query_kind':s['kind'],
                                   'address':s['address'],'reader_cut':cut,'consumed_byte':chain['stored_byte'],
                                   'first_later_writer':w,'writer_byte':k,'later_byte':b,'value_changed':b!=chain['stored_byte']})
                    chunks.add((j,j+1,'post_read_overwrite'))
            pieces=[piece(row,a,b,k) for a,b,k in sorted(chunks)]
            rr={json.dumps(r,sort_keys=True):r for p in pieces for r in p['reads']}
            intervals.append({'interval_index':ii,'parent_interval_sha256':item['interval_packed']['decoded_sha256'],
                              'chunks':pieces,'lineage_queries':query_count,
                              'selected_read_origins':byte_origins(row,sorted(rr.values(),key=lambda r:(r['source_visit_index'],r['address'])))})
            print(json.dumps({'class':ci,'interval':ii,'fields':len(fields),'future_writes':len(future),'chunks':len(pieces)}),flush=True)
            del row,readmap,histories;gc.collect()
        fields.sort(key=lambda x:x['owner_offset_bytes'])
        assert [(f['owner_offset_bytes'],f['values']['decoded_scalar32']) for f in fields if f['kind']=='packed']==[(77,48),(85,1),(97,28),(105,1)]
        assert len(fields)==8 and len(tempered)==4
        cases.append({'class_index':ci,'fields':fields,'tempered_words':tempered,'post_read_overwrites':future,'intervals':intervals,
                      'layout':{'parent_start':77,'parent_span':48,'prefix_bytes':20,'child_start':97,'child_span':28,
                                'payload_start':117,'payload_size_bytes':8,'end_exclusive':125}})
    counts={'retained_contexts':2,'word_fields':16,'packed_fields':8,'array_fields':4,'opaque_fields':4,
            'tempered_words':8,'retained_byte_consumers':24,
            'count_loop_iterations':sum(len(f['values']['count_steps']) for c in cases for f in c['fields'] if f['kind']=='packed'),
            'post_read_overwrites':sum(len(c['post_read_overwrites']) for c in cases),
            'changed_post_read_bytes':sum(w['value_changed'] for c in cases for w in c['post_read_overwrites']),
            'lineage_queries':sum(i['lineage_queries'] for c in cases for i in c['intervals']),
            'source_chunks':sum(len(i['chunks']) for c in cases for i in c['intervals']),
            'source_visits':sum(len(p['visits']) for c in cases for i in c['intervals'] for p in i['chunks']),
            'new_target_intervals':0,'new_root_bytes':0,'new_API_return_premises':0}
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'parent_pins':PINS,
            'dependencies':{p:sha(ROOT/p) for p in DEPS},'cases':cases,'verified_counts':counts,
            'retained_nested_span_layout_established':True,'native_schema_established':False,
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'full_goal_complete':False}


if __name__=='__main__':
    x=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(x,indent=2)+'\n')
    print(json.dumps(x['verified_counts']),flush=True)
