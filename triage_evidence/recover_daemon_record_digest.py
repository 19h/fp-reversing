#!/usr/bin/env python3
"""Retained record-input SHA-1 message, two compression blocks and source epochs.
O(parent bytes + visits + effects + selected frames) time/space. No new target
interval, root byte, native API/IPC, hardware PAC or IDB operation.
"""
import gc
import json
from collections import Counter
from daemon_receive_tools import ROOT, SOURCE, IMAGE
from verify_daemon_reader_record_payloads_publication import read, sha
from recover_daemon_record_extension import unpack
from recover_daemon_record_input_origin import piece, inside, byte_origins
from daemon_sha1_core_model import IV, STATE_XOR, reference

P = 'daemon_record_digest'
PINS = {'daemon_record_spans_checks.json': 'c86a7ff3de166cae5034ee4543dc13cd27f6fc13076221ecb94788491f1ffb99',
        'daemon_record_spans_audit.json': '2e5259ad78e740d82a91d1310d8a3c4991d0f843427bf2ac93e09144b77c1a89',
        'daemon_record_extension_checks.json': '9e89cde6b9d04019761c1f7370584e72ad85afc0aa0fd657f4cb4aa9ff0571d7',
        'daemon_record_extension_replay.json': '7ffde847a48145ad9821ab9d228a345dbd7722ab6d00179836624c202b81993d',
        'daemon_state_splice_checks.json': '850a325d4f00433f9dc33bafb04344c95e2887b09e048f9c90aaa1adf900b066',
        'daemon_state_splice_audit.json': '96bcc09acbe63d071a6363a9cf6e666b6826710febeba1ac68dde8cb4d736161'}
DEPS = ['daemon_receive_tools.py', 'recover_daemon_record_extension.py',
        'recover_daemon_record_input_origin.py', 'daemon_sha1_core_model.py']
ROUND_STARTS = [0x100a0c1ac, 0x100aa8330, 0x100bd9094, 0x100a1a054]
COPY_STARTS = {0x100b55b04: 0x100b55aec, 0x100a7bba4: 0x100a7bb48, 0x100b6dbe4: 0x100b6dbd0}
INPUT_PCS = {0x100aac294, 0x100aac2a8, 0x100aac2b8, 0x100aac2d0}


def extract(row, ci, interval_digest, downstream):
    visits = row['source_visits']; frame = int(downstream['frame_F'], 16); context = frame+0x3cc
    starts = [j for j,v in enumerate(visits) if v['pc'] == '0x100a42c34']
    assert len(starts) == 2
    chunks = []; blocks = []; initial = IV[:]
    for bi, lo in enumerate(starts):
        hi = next(j+1 for j in range(lo, len(visits)) if visits[j]['pc'] == '0x100a14f28')
        chunk = piece(row, lo, hi, 'complete_record_digest_compression')
        chunks.append(chunk)
        rr = [r for r in chunk['reads'] if int(r['pc'],16) in INPUT_PCS]
        assert len(rr) == 64 and [int(r['address'],16) for r in rr] == list(range(context,context+64))
        encoded = bytes.fromhex(''.join(r['bytes_hex'] for r in rr)); block = bytes(x^0x98 for x in encoded)
        model = reference(block, initial)
        # The initial schedule store is recovered from the actual decoder loop.
        first_store_pcs = Counter(w['pc'] for w in chunk['writes'] if w['source_visit_index'] < next(j for j in range(lo, hi) if visits[j]['pc']=='0x100a8b6b4'))
        first_store_pc, = [pc for pc,n in first_store_pcs.items() if n==16]
        assert first_store_pc=='0x100aac488'
        schedule = [w for w in chunk['writes'] if w['pc'] in [first_store_pc,'0x100a8b73c']]
        assert len(schedule) == 80 and [int(w['address'],16) for w in schedule] == list(range(int(schedule[0]['address'],16),int(schedule[0]['address'],16)+320,4))
        assert [int.from_bytes(bytes.fromhex(w['after_hex']),'little')^0x8b3dc651 for w in schedule] == model['schedule80']
        rounds = []; maps = []
        for phase, pc in enumerate(ROUND_STARTS):
            js = [j for j in range(lo,hi) if visits[j]['pc']==hex(pc)]
            assert len(js)==20
            options = [set(range(31)) for _ in range(5)]
            for k,j in enumerate(js):
                f = row['source_frames'][j]; expected = model['working_states81'][20*phase+k]
                for word in range(5):
                    options[word] &= {reg for reg,x in enumerate(f['registers31']) if (int(x,16)&0xffffffff)^STATE_XOR == expected[word]}
                rounds.append({'round':20*phase+k,'source_visit_index':j,'pc':hex(pc),
                               'registers31':f['registers31'],'SP':f['SP']})
            assert all(len(s)==1 for s in options), options
            maps.append([next(iter(s)) for s in options])
        state_writes = [w for w in chunk['writes'] if inside(w, context+0x48,20)]
        assert len(state_writes)==5
        state = {int(w['address'],16):int.from_bytes(bytes.fromhex(w['after_hex']),'little') for w in state_writes}
        final = [state[context+0x48+4*j]^STATE_XOR for j in range(5)]
        assert final==model['final_state5']
        final_working_frame=row['source_frames'][next(j for j in range(lo,hi) if visits[j]['pc']=='0x100abc2f8')]
        blocks.append({'block_index':bi,'start_visit':lo,'end_visit_exclusive':hi,
                       'encoded_input64_hex':encoded.hex(),'decoded_input64_hex':block.hex(),
                       'initial_state5':initial,'final_state5':final,'input_reads':rr,
                       'final_working_registers31':final_working_frame['registers31'],
                       'final_working_source_visit':final_working_frame['source_visit_index'] if 'source_visit_index' in final_working_frame else next(j for j in range(lo,hi) if visits[j]['pc']=='0x100abc2f8'),
                       'schedule_writes':schedule,'initial_schedule_store_pc':first_store_pc,
                       'round_entries':rounds,'round_register_maps':maps,'state_writes':state_writes})
        initial = final
    message = bytes.fromhex(blocks[0]['decoded_input64_hex'])+bytes.fromhex(blocks[1]['decoded_input64_hex'])[:3]
    assert len(message)==67 and b''.join(bytes.fromhex(b['decoded_input64_hex']) for b in blocks)==message+b'\x80'+bytes(52)+(536).to_bytes(8,'big')
    assert b''.join(w.to_bytes(4,'big') for w in initial).hex()==downstream['decoded20_hex']
    lo = next(j for j,v in enumerate(visits) if v['pc']=='0x100490494')
    hi = next(j+1 for j in range(lo,len(visits)) if visits[j]['pc']=='0x10031cf6c')
    init = piece(row,lo,hi,'record_digest_state_initialization'); chunks.append(init)
    input_origins = byte_origins(row,[r for b in blocks for r in b['input_reads']])
    assert all(len(x['origins'])==1 for x in input_origins)
    writers = {o['writer']['source_visit_index']:o['writer'] for x in input_origins for o in x['origins']}
    message_writes = sorted([w for w in writers.values() if int(w['pc'],16) in COPY_STARTS],key=lambda w:w['source_visit_index'])
    assert len(message_writes)==67
    for w in message_writes:
        end=w['source_visit_index']+1; a=COPY_STARTS[int(w['pc'],16)]
        candidates=[j for j in range(end-1,max(-1,end-80),-1) if visits[j]['pc']==hex(a)]
        assert candidates,(w,visits[end-25:end])
        start=candidates[0]
        chunks.append(piece(row,start,end,'record_digest_message_byte'))
    # Every padding byte is an actual preceding source write, with its own epoch.
    padding_writes = sorted([w for w in writers.values() if w not in message_writes],key=lambda w:w['source_visit_index'])
    assert len(padding_writes)==61
    for w in padding_writes:
        end=w['source_visit_index']+1
        chunks.append(piece(row,end-1,end,'record_digest_padding_byte_store'))
    # Preserve actual source input reads feeding the selected copy/codec slices.
    segment_reads=[r for c in chunks if c['kind']=='record_digest_message_byte' for r in c['reads']]
    copy_origins = byte_origins(row, segment_reads)
    body_chunks=[p for p in chunks if p['kind']=='record_digest_message_byte' and p['writes'][0]['pc']=='0x100a7bba4']
    assert len(body_chunks)==48
    body_reads=[p['reads'][0] for p in body_chunks]
    first=int(body_reads[0]['address'],16)
    assert [int(r['address'],16) for r in body_reads]==list(range(first,first+48))
    owner,=[o for o in row['foreign_owners'] if int(o['address'],16)<=first and first+48<=int(o['address'],16)+o['size_bytes']]
    assert first-int(owner['address'],16)==77
    raw=bytes.fromhex(''.join(r['bytes_hex'] for r in body_reads))
    incoming={}
    for field in ['initial_private_fixtures','initial_image_fixtures']:
        for fixture in row[field]:
            a=int(fixture['address'],16)
            for k,b in enumerate(bytes.fromhex(fixture['bytes_hex'])):
                if first<=a+k<first+48:incoming[a+k]={'byte':b,'provenance':fixture['provenance'],'fixture_kind':field}
    assert bytes(incoming[first+k]['byte'] for k in range(48))==raw
    nibble=[(int(p['frames'][0]['registers31'][12],16)+int(p['frames'][0]['registers31'][6],16))&15 for p in body_chunks]
    assert nibble==[(77+j)&15 for j in range(48)]
    bias,={int(p['frames'][0]['registers31'][0],16)&255 for p in body_chunks}
    rr=body_chunks[0]['reads']; bases=[int(rr[k]['address'],16)-nibble[0] for k in [1,2,3]]
    banks=[IMAGE.read(a,16) for a in bases]
    masks=bytes((banks[0][n]^banks[1][n]^banks[2][n]^(n|(n<<5))^bias^0x98)&255 for n in range(16))
    assert masks.hex()=='d98c9317498b221182b3198570dd904f'
    assert bytes(b^masks[(77+j)&15] for j,b in enumerate(raw))==message[11:59]
    body_codec={'input_owner':owner,'input_offset_bytes':77,'input_size_bytes':48,'input48_hex':raw.hex(),
                'decoded48_hex':message[11:59].hex(),'mask16_hex':masks.hex(),'source_bias8':hex(bias),
                'nibble_indices':nibble,'fixed_bank_slices':[{'start':hex(a),'bytes16_hex':b.hex()} for a,b in zip(bases,banks)],
                'inherited_input_bytes':[incoming[first+k] for k in range(48)]}
    return {'class_index':ci,'parent_interval_sha256':interval_digest,'frame_F':hex(frame),'context_C':hex(context),
            'body_codec':body_codec,'message67_hex':message.hex(),'segments':[{'offset':a,'size_bytes':b-a,'decoded_hex':message[a:b].hex()} for a,b in [(0,11),(11,59),(59,67)]],
            'digest20_hex':downstream['decoded20_hex'],'record_input20_hex':downstream['record_input20_hex'],
            'blocks':blocks,'initialization_state_writes':[w for w in init['writes'] if inside(w,context+0x48,20)],
            'input_byte_origins':input_origins,
            'core_read_origins':byte_origins(row,[r for c in chunks if c['kind']=='complete_record_digest_compression' for r in c['reads']]),'message_writes':message_writes,'padding_writes':padding_writes,
            'copy_read_origins':copy_origins,'source_chunks':chunks}


def build():
    for p,d in PINS.items(): assert sha(ROOT/p)==d
    old=json.loads(read(ROOT/'daemon_record_extension_checks.json'))
    downstream=json.loads(read(ROOT/'daemon_state_splice_checks.json'))
    cases=[]
    for ci, target in zip([2,3],downstream['cases']):
        packed=old['classes'][ci]['intervals'][-1]['interval_packed']; row=unpack(packed)
        cases.append(extract(row,ci,packed['decoded_sha256'],target))
        print(json.dumps({'class':ci,'blocks':2,'message_bytes':67,'source_visits':sum(len(c['visits']) for c in cases[-1]['source_chunks'])}),flush=True)
        del row;gc.collect()
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),
            'parent_pins':PINS,'dependencies':{p:sha(ROOT/p) for p in DEPS},'cases':cases,
            'verified_counts':{'retained_contexts':2,'complete_compression_blocks':4,'message_bytes_per_context':67,
                'source_chunks':sum(len(c['source_chunks']) for c in cases),
                'source_visits':sum(len(p['visits']) for c in cases for p in c['source_chunks']),
                'source_round_entries':320,'source_schedule_words':320,'input_byte_epoch_links':256,
                'message_byte_stores':134,'padding_byte_stores':122,'new_target_intervals':0,'new_root_bytes':0},
            'retained_digest_message_identity_established':True,'universal_new_compression_equivalence_established':False,
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'full_goal_complete':False}


if __name__=='__main__':
    result=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result['verified_counts']),flush=True)
