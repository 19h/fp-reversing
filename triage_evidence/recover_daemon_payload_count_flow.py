#!/usr/bin/env python3
"""Context count/data pointer, saved count epochs and word/tail copy gates.
O(P+C*E+Q*log(E+Q)+32V) time; O(parent receipts+largest interval+
selected frames) space; P parent bytes, C chunks, E event/fixture bytes,
Q read-byte queries, V selected visits. No new target/API/IPC/IDB action.
"""
import gc
import json
from daemon_receive_tools import ROOT, SOURCE
from verify_daemon_reader_record_payloads_publication import read, sha
from recover_daemon_record_extension import unpack
from recover_daemon_record_input_origin import piece, byte_origins
from recover_daemon_digest_body_origins import incoming, invalidated

P='daemon_payload_count_flow'
PINS={'daemon_record_extension_checks.json':'9e89cde6b9d04019761c1f7370584e72ad85afc0aa0fd657f4cb4aa9ff0571d7',
      'daemon_record_extension_replay.json':'7ffde847a48145ad9821ab9d228a345dbd7722ab6d00179836624c202b81993d',
      'daemon_payload_scalar_mixers_checks.json':'8abdca9c7bcd681797345d9cd20123a6c429761feacf9e212c12c519310e74d1',
      'daemon_payload_scalar_mixers_audit.json':'e8691cddd430c2eeba98e6d70bdafbbb0c226cfb4823f82e3f279b540530a870',
      'daemon_context_state_publish_checks.json':'a0c631dcec58e837f66de9a1222f9789d8058b98d89b79c685393a5fcbbfa74e',
      'daemon_context_state_publish_audit.json':'157858700ca7dd19ca2651c78ffebce0a502953fbb5599059a8ffc7c47dcec53'}
DEPS=['daemon_receive_tools.py','recover_daemon_record_extension.py','recover_daemon_record_input_origin.py',
      'recover_daemon_digest_body_origins.py']
C=0x6500115b20
BIAS=0x4a2cb691c686c716
CELLS={'count':(0x680005fc08,(BIAS+6).to_bytes(8,'little').hex()),
       'data':(0x680005fd20,(C+32).to_bytes(8,'little').hex())}
RANGES={1:[(86094,86149,'count_pointer_and_encoded_state'),(87581,87611,'saved_count_unsigned_extension'),
           (87694,87695,'count_bias'),(87829,87830,'count_spill'),(88127,88130,'data_pointer_publication')],
        2:[],
        3:[(85736,85738,'count_copy_to_loop_slot'),(85931,85936,'word_cursor_initialization'),
           (85936,85966,'initial_word_gate'),(86003,86040,'first_word_reader'),
           (86247,86289,'word_advance_and_gate'),(86306,86308,'scratch_pointer_publication'),
           (86343,86344,'save_outer_cursor'),(86488,86492,'save_inner_registers'),
           (100204,100210,'restore_inner_registers'),(100218,100219,'restore_outer_cursor'),
           (100220,100251,'tail_entry_gate'),(100251,100287,'two_byte_copy_loop'),
           (100287,100333,'scratch_reader_setup')]}


def cell_value(row,address,cut=None):
    values=[]
    for k in range(8):
        a=address+k;ws=[w for w in row['source_writes'] if int(w['address'],16)<=a<int(w['address'],16)+w['size_bytes']
                        and (cut is None or w['source_visit_index']<cut)]
        if ws:
            w=ws[-1];values.append(bytes.fromhex(w['after_hex'])[a-int(w['address'],16)])
        else:values.append(incoming(row,a)[0]['byte'])
    return bytes(values).hex()


def build():
    for p,h in PINS.items():assert sha(ROOT/p)==h
    parent=json.loads(read(ROOT/'daemon_record_extension_checks.json'));cases=[]
    for ci in [2,3]:
        intervals=[];count=None;previous=None;field=None;loops=None
        for ii in [1,2,3]:
            item=parent['classes'][ci]['intervals'][ii];row=unpack(item['interval_packed'])
            chunks=[piece(row,a,b,k) for a,b,k in RANGES[ii]]
            unique={json.dumps(r,sort_keys=True):r for p in chunks for r in p['reads']}
            epochs={}
            for name,(address,expected) in CELLS.items():
                if ii==1:
                    assert cell_value(row,address)==expected
                    epochs[name]={'address':hex(address),'end_bytes_hex':expected}
                else:
                    initial=bytes(incoming(row,address+k)[0]['byte'] for k in range(8)).hex()
                    assert initial==expected==previous[name]['end_bytes_hex']
                    cut=None if ii==2 else (85736 if name=='count' else 100249)
                    assert cell_value(row,address,cut)==expected
                    for k in range(8):assert not invalidated(item['API_return_premise'],address+k)
                    overlapping=[w for w in row['source_writes'] if int(w['address'],16)<address+8 and address<int(w['address'],16)+w['size_bytes']
                                 and (cut is None or w['source_visit_index']<cut)]
                    assert not overlapping
                    epochs[name]={'address':hex(address),'incoming_bytes_hex':initial,'end_bytes_hex':cell_value(row,address),
                                  'reader_cut':cut,'overlapping_writes_before_cut':overlapping,'not_invalidated_by_API_premise':True}
            if ii==1:
                rr,=[r for r in row['source_reads'] if r['source_visit_index']==86099]
                n=int.from_bytes(bytes.fromhex(rr['bytes_hex']),'little');assert rr['address']==hex(C+28) and n==6
                field={'count_read':rr,'count_input32':n,'context_address':hex(C),
                       'advanced_pointer':row['source_frames'][86100]['registers31'][12],
                       'prepared_q32':row['source_frames'][86143]['registers31'][16],
                       'extension_q64':row['source_frames'][87602]['registers31'][13],
                       'extension_phase_W8':row['source_frames'][87591]['registers31'][8],
                       'extended_count_X10':row['source_frames'][87611]['registers31'][10],
                       'biased_count_X1':row['source_frames'][87695]['registers31'][1]}
                assert field['advanced_pointer']==hex(C+32) and int(field['biased_count_X1'],16)==BIAS+n
                assert int(field['prepared_q32'],16)==int(field['extension_q64'],16)&0xffffffff
                assert field['extension_phase_W8']=='0x250'
            if ii==3:
                loops={'word_gates':[],'tail_iterations':[],'tail_entry':{'start_visit':100220,'logical_start_index':4,'logical_count':6}}
                for j in [85942,86265]:
                    regs=[int(x,16) for x in row['source_frames'][j]['registers31']]
                    logical=(regs[22]-0x4a384b6e)&0xffffffff
                    assert logical in [0,4] and regs[23]==BIAS+6
                    loops['word_gates'].append({'start_visit':j,'logical_index':logical,'encoded_cursor32':hex(regs[22]),'encoded_count64':hex(regs[23])})
                for j in [100251,100269]:
                    regs=[int(x,16) for x in row['source_frames'][j]['registers31']]
                    r,=[r for r in row['source_reads'] if r['source_visit_index']==j+4]
                    w,=[w for w in row['source_writes'] if w['source_visit_index']==j+6]
                    logical=(regs[9]-0x4a384b6e)&0xffffffff
                    assert int(r['address'],16)==C+32+logical and logical in [4,5]
                    edge,=[e for e in row['logical_edges'] if e['source_visit_index']==j+17]
                    loops['tail_iterations'].append({'start_visit':j,'logical_index':logical,'read':r,'write':w,'edge':edge})
                assert [x['logical_index'] for x in loops['word_gates']]==[0,4]
                assert [x['logical_index'] for x in loops['tail_iterations']]==[4,5]
            intervals.append({'interval_index':ii,'parent_interval_sha256':item['interval_packed']['decoded_sha256'],
                              'API_return_premise':item['API_return_premise'],'saved_cell_epochs':epochs,'chunks':chunks,
                              'selected_read_origins':byte_origins(row,sorted(unique.values(),key=lambda r:(r['source_visit_index'],r['address'])))})
            previous=epochs
            print(json.dumps({'class':ci,'interval':ii,'chunks':len(chunks),'visits':sum(len(p['visits']) for p in chunks)}),flush=True)
            del row;gc.collect()
        cases.append({'class_index':ci,'context_fields':field,'loop_inputs':loops,'intervals':intervals})
    counts={'retained_contexts':2,'count_data_field_pairs':2,'saved_cell_boundary_links':8,'word_gates':4,
            'tail_iterations':4,'source_chunks':sum(len(i['chunks']) for c in cases for i in c['intervals']),
            'source_visits':sum(len(p['visits']) for c in cases for i in c['intervals'] for p in i['chunks']),
            'new_target_intervals':0,'new_root_bytes':0,'new_API_return_premises':0}
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'parent_pins':PINS,
            'dependencies':{p:sha(ROOT/p) for p in DEPS},'cases':cases,'verified_counts':counts,
            'retained_count_data_flow_established':True,'native_constructor_epoch_join_established':False,
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'full_goal_complete':False}


if __name__=='__main__':
    x=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(x,indent=2)+'\n');print(json.dumps(x['verified_counts']),flush=True)
