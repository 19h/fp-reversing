#!/usr/bin/env python3
"""Retained digest body: byte epochs across owner growth and actual producers.
Conservative O(P+(Q+C)*E+(E+Q)*log(E+Q)+32V) time, where P is parent
bytes, Q byte queries, C selected chunks, E events/fixture bytes and V selected
visits; O(largest interval+receipts+32V) space. No new target
execution, root input, native API/IPC, hardware PAC or IDB operation.
"""
import gc
import json
from bisect import bisect_left
from collections import Counter, defaultdict
from daemon_receive_tools import ROOT, SOURCE, IMAGE
from verify_daemon_reader_record_payloads_publication import read, sha
from recover_daemon_record_extension import unpack
from recover_daemon_record_input_origin import piece, byte_origins

P = 'daemon_digest_body_origins'
PINS = {'daemon_record_extension_checks.json': '9e89cde6b9d04019761c1f7370584e72ad85afc0aa0fd657f4cb4aa9ff0571d7',
        'daemon_record_extension_replay.json': '7ffde847a48145ad9821ab9d228a345dbd7722ab6d00179836624c202b81993d',
        'daemon_record_digest_checks.json': '34ac5df9c9e8652805299b78578beec6487bdf4b6cf734a8cbc4a9a3b06239f4',
        'daemon_record_digest_audit.json': 'a431060e47f25bd562afe90e795d4c8d762ad767787eec3dc3bf99a1eb060244'}
DEPS = ['daemon_receive_tools.py', 'recover_daemon_record_extension.py',
        'recover_daemon_record_input_origin.py', 'recover_daemon_record_banks.py']
COPY_READ, COPY_WRITE = '0x100b5c9b4', '0x100b5c9b8'
WORD_PCS = ['0x100c70e28', '0x100c70e80', '0x100c70ed0', '0x100c70f18']
BYTE_PC = '0x100a0ca74'
PAIR_PCS = ['0x100b755ac', '0x100b755f8']
MASK = bytes.fromhex('d98c9317498b221182b3198570dd904f')
BANK_STARTS = [0x100e36310, 0x100f2f6b3, 0x100ed2441, 0x100f21190, 0x100fa38b4, 0x100ffc9e1]


def incoming(row, address):
    found = []
    for kind in ['initial_private_fixtures', 'initial_image_fixtures']:
        for f in row[kind]:
            a = int(f['address'], 16); b = bytes.fromhex(f['bytes_hex'])
            if a <= address < a+len(b):
                found.append({'fixture_kind': kind, 'fixture_address': f['address'],
                              'fixture_byte': address-a, 'byte': b[address-a], 'provenance': f['provenance']})
    assert found and len({f['byte'] for f in found}) == 1
    return found


def invalidated(premise, address):
    spans = list(premise['invalidated_spans'])
    if 'allocated_owner_premise' in premise: spans.append(premise['allocated_owner_premise'])
    return any(int(s['address'],16) <= address < int(s['address'],16)+s['size_bytes'] for s in spans)


def byte_encoding(chunk):
    f=chunk['frames'][0];regs=[int(x,16) for x in f['registers31']]
    w,shift,phase=regs[9]&0xffffffff,regs[8]&31,regs[10]&0xffffffff
    write,=chunk['writes'];a=int(write['address'],16)
    def value(pc):
        r,=[r for r in chunk['reads'] if r['pc']==hex(pc)]
        return int.from_bytes(bytes.fromhex(r['bytes_hex']),'little')
    cache=value(0x100a0c9d8);mask=value(0x100a0c9f8)^0xa7a730ec
    text=value(0x100a0ca14)^0x12af5504870a589f
    r=(cache+(a&0xffffffff))&0xffffffff
    prekey=(((phase+0xe3064333)&0xffffffff)&0x1cf9b3ff)^0x0ba37f51
    addresses=[text+(((r+k)&0xffffffff)&mask) for k in [prekey,0x0ba3ccca]]
    bs=[IMAGE.read(p,1)[0] for p in addresses]
    for pc,p,b in zip([0x100a0ca30,0x100a0ca54],addresses,bs):
        rr,=[rr for rr in chunk['reads'] if rr['pc']==hex(pc)]
        assert rr['address']==hex(p) and rr['bytes_hex']==bytes([b]).hex()
    perturb=(((phase-0xba15)&0xffffffff)|0x2480)^6
    stored=((w>>shift)^(31*(a&0xffffffff))^bs[0]^bs[1]^perturb)&255
    assert bytes([stored]).hex()==write['after_hex'] and phase==0xbc66 and perturb&255==0xd7
    return {'source_W9':hex(w),'shift_bits':shift,'phase_W10':hex(phase),'destination':hex(a),
            'cached_word32':hex(cache),'r32':hex(r),'mask64':hex(mask),'text_base':hex(text),
            'text_addresses':[hex(p) for p in addresses],'text_bytes_hex':bytes(bs).hex(),
            'stored_byte_hex':write['after_hex']}


def build():
    for p, digest in PINS.items(): assert sha(ROOT/p) == digest
    parent = json.loads(read(ROOT/'daemon_record_extension_checks.json'))
    digest = json.loads(read(ROOT/'daemon_record_digest_checks.json'))
    banks = [IMAGE.read(a,16) for a in BANK_STARTS]; mask_rows = []
    for n in range(16):
        left = banks[0][n]^banks[1][n]^banks[2][n]^(n|(n<<5))
        right = banks[3][n]^banks[4][n]^banks[5][n]^(31*n)
        row = [(left^0x12^MASK[n])&255]+[(right^c^MASK[n])&255 for c in [0x7e,0x74,0xff]]
        assert bytes(row).hex() == 'e4b5bf34'
        mask_rows.append({'nibble':n,'decoded_word_XOR_bytes':row})
    cases = []
    for dc in digest['cases']:
        ci = dc['class_index']; raw = bytes.fromhex(dc['body_codec']['input48_hex'])
        selected = [c['reads'][0] for c in dc['source_chunks']
                    if c['kind'] == 'record_digest_message_byte' and c['writes'][0]['pc'] == '0x100a7bba4']
        assert len(selected) == 48 and bytes.fromhex(''.join(r['bytes_hex'] for r in selected)) == raw
        chains = [{'body_byte': k, 'consumer_read': r, 'stored_byte': raw[k], 'steps': []} for k,r in enumerate(selected)]
        demands = [{'body_byte': k, 'address': int(r['address'],16), 'cut': r['source_visit_index']} for k,r in enumerate(selected)]
        intervals = []; leaves = []; chunks = []; words = []; byte_fields=[]; pairs=[]
        for ii in range(9, -1, -1):
            if not demands: break
            interval = parent['classes'][ci]['intervals'][ii]; packed = interval['interval_packed']; row = unpack(packed)
            history = defaultdict(list)
            for w in row['source_writes']:
                for k,b in enumerate(bytes.fromhex(w['after_hex'])):
                    history[int(w['address'],16)+k].append((w['source_visit_index'],w,k,b))
            readmap = defaultdict(list)
            for r in row['source_reads']: readmap[r['source_visit_index']].append(r)
            wanted_chunks = set(); carry = []
            for d in demands:
                k = d['body_byte']; address = d['address']; cut = d['cut']; expected = raw[k]
                while True:
                    h = history[address]; n = len(h) if cut is None else bisect_left(h,cut,key=lambda t:t[0])
                    step = {'interval_index': ii, 'address': hex(address), 'before_visit_exclusive': cut}
                    if not n:
                        fixtures = incoming(row,address); assert fixtures[0]['byte'] == expected
                        assert not invalidated(interval['API_return_premise'],address)
                        step.update(kind='incoming', fixtures=fixtures, not_invalidated_by_API_premise=True)
                        chains[k]['steps'].append(step); carry.append({'body_byte':k,'address':address,'cut':None}); break
                    j,w,wb,b = h[n-1]; assert b == expected
                    step.update(writer=w, writer_byte=wb)
                    if w['pc'] == COPY_WRITE:
                        r, = readmap[j-1]
                        assert r['pc'] == COPY_READ and r['size_bytes'] == w['size_bytes'] == 1 and r['bytes_hex'] == w['after_hex']
                        assert row['source_visits'][j-2]['pc'] == '0x100b5c9b0'
                        step.update(kind='copy', source_read=r); wanted_chunks.add((j-2,j+1,'growth_copy_step'))
                        chains[k]['steps'].append(step); address = int(r['address'],16); cut = r['source_visit_index']; continue
                    assert w['pc'] in WORD_PCS+[BYTE_PC]+PAIR_PCS
                    step['kind'] = 'producer'; chains[k]['steps'].append(step)
                    leaf = {'body_byte':k,'interval_index':ii,'writer':w,'writer_byte':wb}
                    leaves.append(leaf)
                    if w['pc'] in WORD_PCS:
                        lo = next(t for t in range(j,max(-1,j-100),-1) if row['source_visits'][t]['pc'] == '0x100c70dd8')
                        hi = next(t+1 for t in range(j,j+100) if row['source_visits'][t]['pc'] == WORD_PCS[-1])
                        wanted_chunks.add((lo,hi,'four_byte_word_writer'))
                    elif w['pc'] == BYTE_PC:
                        lo=j-(0x100a0ca74-0x100a0c99c)//4
                        assert row['source_visits'][lo]['pc']=='0x100a0c99c'
                        wanted_chunks.add((lo,j+1,'table_encoded_byte_writer'))
                    else:
                        lo = next(t for t in range(j,max(-1,j-70),-1) if row['source_visits'][t]['pc']=='0x100b75548')
                        hi = next(t+1 for t in range(j,j+70) if row['source_visits'][t]['pc']==PAIR_PCS[-1])
                        wanted_chunks.add((lo,hi,'two_byte_writer'))
                    break
            interval_chunks = [piece(row,a,b,kind) for a,b,kind in sorted(wanted_chunks)]
            for c in interval_chunks:
                c['interval_index'] = ii
                if c['kind']=='table_encoded_byte_writer':
                    byte_fields.append({'interval_index':ii,'start_visit':c['start_visit'],**byte_encoding(c)})
                if c['kind']=='two_byte_writer':
                    ws=[w for w in c['writes'] if w['pc'] in PAIR_PCS];assert len(ws)==2
                    j=next(j for j,v in enumerate(c['visits']) if v['pc']=='0x100b755a0')
                    v=int(c['frames'][j]['registers31'][8],16)&0xffffffff
                    owner=int(c['frames'][0]['registers31'][22],16);off=int(ws[0]['address'],16)-owner
                    assert int(ws[1]['address'],16)==owner+off+1
                    raw2=bytes.fromhex(''.join(w['after_hex'] for w in ws))
                    out=bytes(b^MASK[(off+k)&15] for k,b in enumerate(raw2))
                    assert out==((v^0x534c)&0xffff).to_bytes(2,'big')
                    pairs.append({'interval_index':ii,'start_visit':c['start_visit'],'owner':hex(owner),
                                  'owner_offset_bytes':off,'source_W8_after_arithmetic':hex(v),
                                  'stored2_hex':raw2.hex(),'decoded2_hex':out.hex(),
                                  'writer_visits':[w['source_visit_index'] for w in ws]})
                if c['kind'] != 'four_byte_word_writer': continue
                ws = [w for w in c['writes'] if w['pc'] in WORD_PCS]; assert len(ws)==4
                address = int(ws[0]['address'],16)
                assert [int(w['address'],16) for w in ws] == list(range(address,address+4))
                owner = int(c['frames'][0]['registers31'][9],16); offset = address-owner
                source32 = int(c['frames'][0]['registers31'][11],16)&0xffffffff
                stored = bytes.fromhex(''.join(w['after_hex'] for w in ws))
                decoded = bytes(b^MASK[(offset+t)&15] for t,b in enumerate(stored))
                assert int.from_bytes(decoded,'big') == source32^0xe4b5bf34
                words.append({'interval_index':ii,'start_visit':c['start_visit'],'owner':hex(owner),
                              'owner_offset_bytes':offset,'source_W11':hex(source32),'stored4_hex':stored.hex(),
                              'decoded4_hex':decoded.hex(),'writer_visits':[w['source_visit_index'] for w in ws]})
            unique_reads = {json.dumps(r,sort_keys=True):r for c in interval_chunks for r in c['reads']}
            origins = byte_origins(row, sorted(unique_reads.values(), key=lambda r:(r['source_visit_index'],r['address'])))
            intervals.append({'interval_index':ii,'parent_interval_sha256':packed['decoded_sha256'],
                              'API_return_premise':interval['API_return_premise'], 'selected_read_origins':origins,
                              'chunks':interval_chunks})
            chunks.extend(interval_chunks); demands=carry
            print(json.dumps({'class':ci,'interval':ii,'unresolved_bytes':len(demands),'producer_bytes':len(leaves)}),flush=True)
            del row, history, readmap; gc.collect()
        assert not demands and len(leaves)==48
        leaves.sort(key=lambda x:x['body_byte']); words.sort(key=lambda x:x['owner_offset_bytes'])
        assert len(words)==8 and [w['owner_offset_bytes'] for w in words]==[77,81,85,97,101,105,117,121]
        cases.append({'class_index':ci,'body48_stored_hex':raw.hex(),'body48_decoded_hex':dc['body_codec']['decoded48_hex'],
                      'consumer_owner':dc['body_codec']['input_owner'],'chains':chains,'producer_bytes':leaves,
                      'word_groups':words,'byte_fields':byte_fields,'two_byte_groups':pairs,'intervals':intervals,
                      'producer_byte_census':dict(Counter(x['writer']['pc'] for x in leaves))})
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'parent_pins':PINS,
            'dependencies':{p:sha(ROOT/p) for p in DEPS},'cases':cases,
            'fixed_banks':[{'address':hex(a),'bytes16_hex':b.hex()} for a,b in zip(BANK_STARTS,banks)],
            'word_mask_rows':mask_rows,
            'verified_counts':{'retained_contexts':len(cases),'body_bytes_per_context':48,
                'producer_byte_links':sum(len(c['producer_bytes']) for c in cases),
                'copy_byte_links':sum(s['kind']=='copy' for c in cases for b in c['chains'] for s in b['steps']),
                'incoming_boundary_links':sum(s['kind']=='incoming' for c in cases for b in c['chains'] for s in b['steps']),
                'word_groups':sum(len(c['word_groups']) for c in cases),
                'source_chunks':sum(len(i['chunks']) for c in cases for i in c['intervals']),
                'source_visits':sum(len(p['visits']) for c in cases for i in c['intervals'] for p in i['chunks']),
                'new_target_intervals':0,'new_root_bytes':0},
            'retained_body_writer_lineage_established':True,'application_field_names_established':False,
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'full_goal_complete':False}


if __name__=='__main__':
    result=build(); (ROOT/(P+'_checks.json')).write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result['verified_counts']),flush=True)
