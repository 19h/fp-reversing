#!/usr/bin/env python3
"""Two source word mixers, BE32 inputs and scratch overwrite epochs.
O(P+C*E+Q*log(E+Q)+32V) time; O(parent receipts+largest interval+
selected frames) space, P parent bytes, C chunks, E events/fixture bytes,
Q selected read-byte queries and V selected visits.
No new target execution, API premise, root byte, native IPC or IDB action.
"""
import gc
import json
from collections import defaultdict
from daemon_receive_tools import ROOT, SOURCE
from verify_daemon_reader_record_payloads_publication import read, sha
from recover_daemon_record_extension import unpack
from recover_daemon_record_input_origin import piece, byte_origins
from recover_daemon_digest_body_origins import byte_encoding, incoming
from recover_daemon_record_banks import instruction

P='daemon_payload_scalar_mixers'
PINS={'daemon_record_extension_checks.json':'9e89cde6b9d04019761c1f7370584e72ad85afc0aa0fd657f4cb4aa9ff0571d7',
      'daemon_record_extension_replay.json':'7ffde847a48145ad9821ab9d228a345dbd7722ab6d00179836624c202b81993d',
      'daemon_digest_record_structure_checks.json':'8b4b05e9d76bdbb22ae73de9c2b37b66888f98f92268483547c53169de2acb9e',
      'daemon_digest_record_structure_audit.json':'862051c07acb2f45558aff786793b531b028a04b63883933500769e32565692b',
      'daemon_digest_body_origins_audit.json':'dc216f1beb7244d7269b4d2bf682ef5d80dc1d2a4e844ecd20ab14fc735fa239'}
DEPS=['daemon_receive_tools.py','recover_daemon_record_extension.py','recover_daemon_record_input_origin.py',
      'recover_daemon_digest_body_origins.py','recover_daemon_record_banks.py']
MASK=(1<<32)-1
SPANS=[(0x100a630cc,0x100a6311c,0x100a63130,0x100a63288,0x8ab88387,0xb894cb59,0xe8),
       (0x100a86930,0x100a86980,0x100a86994,0x100a86b00,0xbc5121c0,0x86fc2d20,0xe4)]
PHASE={'w12':0x9e3c2396,'w13':0x475f,'w14':0xec3e0ab8,'w15':0x29a8f200,'w16':0x94d479dc,'w0':0xfe53bc48}


def build():
    for p,h in PINS.items():assert sha(ROOT/p)==h
    parent=json.loads(read(ROOT/'daemon_record_extension_checks.json'))
    prior=json.loads(read(ROOT/'daemon_digest_record_structure_checks.json'));cases=[]
    for case in prior['cases']:
        ci=case['class_index'];item=parent['classes'][ci]['intervals'][3];row=unpack(item['interval_packed'])
        fs=[f for f in case['fields'] if f['kind'] in ['opaque_a','opaque_b']]
        ranges=set();fields=[]
        for index,f in enumerate(fs):
            end=f['start_visit'];start=end-37
            assert row['source_visits'][start]['pc']=='0x100a8d894'
            reads=[r for r in row['source_reads'] if start<=r['source_visit_index']<end and r['size_bytes']==1]
            assert len(reads)==4
            raw=bytes.fromhex(''.join(r['bytes_hex'] for r in reads));d=int.from_bytes(raw,'big')
            a=int(row['source_frames'][end]['registers31'][8],16)&MASK
            value=(d*0x01ef2eff+0x00833631)&MASK
            assert a==d^0x6703cce9 and value.to_bytes(4,'big').hex()==f['values']['normalized4_hex']
            regs=row['source_frames'][start]['registers31'];phase={n:int(regs[int(n[1:])],16)&MASK for n in PHASE}
            assert phase==PHASE
            base=int(regs[21],16);offset=(int(regs[8],16)+0xfe53bc45)&MASK
            assert [int(r['address'],16) for r in reads]==[base+((offset+k)&MASK) for k in range(4)]
            ranges.add((start,f['end_visit_exclusive'],'reader_mixer_to_word_emissions'))
            fields.append({'owner_offset_bytes':f['owner_offset_bytes'],'reader_start_visit':start,
                           'mixer_start_visit':end,'emission_end_visit_exclusive':f['end_visit_exclusive'],
                           'mixer_start_pc':hex(SPANS[index][0]),'source_base':hex(base),'source_offset32':offset,
                           'source_reads':reads,'source_origins':byte_origins(row,reads),'raw_BE32_hex':raw.hex(),
                           'decoded_input32':d,'entry_A32':hex(a),'normalized_word_hex':value.to_bytes(4,'big').hex(),
                           'writer_W11':f['values']['writer_W11'],'reader_phase':phase})
        scratch=fields[1];low=int(scratch['source_reads'][0]['address'],16);cut=scratch['reader_start_visit']
        writes=[w for w in row['source_writes'] if low<=int(w['address'],16)<low+4 and w['source_visit_index']<cut]
        assert len(writes)==6 and [w['pc'] for w in writes]==['0x100a0ca74']*4+['0x100a396ac']*2
        encoders=[];copy_reads=[]
        for w in writes:
            j=w['source_visit_index']
            if w['pc']=='0x100a0ca74':
                lo=j-54;chunk=piece(row,lo,j+1,'scratch_byte_encoder')
                encoders.append({'start_visit':lo,**byte_encoding(chunk)})
                ranges.add((lo,j+1,'scratch_byte_encoder'))
            else:
                lo=j-6;assert row['source_visits'][lo]['pc']=='0x100a39694'
                ranges.add((lo,j+1,'scratch_prefix_copy'))
                rr,=[r for r in row['source_reads'] if r['source_visit_index']==j-2]
                copy_reads.append(rr)
        first=min(x['start_visit'] for x in encoders)
        temper=next(j for j in range(first-1,-1,-1) if row['source_visits'][j]['pc']=='0x100a7ccc0')
        ranges.add((temper,temper+12,'scratch_word_tempering'))
        raw_W19=int(row['source_frames'][temper]['registers31'][19],16)&MASK
        w9=int(row['source_frames'][temper+12]['registers31'][9],16)&MASK
        preservation=[]
        for e in encoders:
            cut=e['start_visit'];assert int(e['source_W9'],16)==w9
            assert all((int(f['registers31'][9],16)&MASK)==w9 for f in row['source_frames'][temper+12:cut+1])
            for visit in row['source_visits'][temper+12:cut]:
                ins=instruction(int(visit['pc'],16));assert not any(ins.reg_name(r) in ['w9','x9'] for r in ins.regs_access()[1])
            preservation.append({'consumer_start_visit':cut,'frame_checks':cut-(temper+12)+1})
        chunks=[piece(row,a,b,k) for a,b,k in sorted(ranges)]
        unique={json.dumps(r,sort_keys=True):r for c in chunks for r in c['reads']}
        fields[0]['incoming_source_fixtures']=[incoming(row,int(r['address'],16)) for r in fields[0]['source_reads']]
        owner,=[o for o in row['foreign_owners'] if int(o['address'],16)==0x6500115b20]
        cases.append({'class_index':ci,'interval_index':3,'parent_interval_sha256':item['interval_packed']['decoded_sha256'],
                      'fields':fields,'scratch_writes':writes,'scratch_encoders':encoders,'scratch_copy_reads':copy_reads,
                      'scratch_copy_origins':byte_origins(row,copy_reads),'context_owner':owner,
                      'scratch_tempering':{'start_visit':temper,'input_W19':hex(raw_W19),'output_W9':hex(w9),
                                            'phase_W10':row['source_frames'][temper]['registers31'][10],
                                            'preservation':preservation},
                      'chunks':chunks,'selected_read_origins':byte_origins(row,sorted(unique.values(),key=lambda r:(r['source_visit_index'],r['address'])))})
        print(json.dumps({'class':ci,'chunks':len(chunks),'visits':sum(len(c['visits']) for c in chunks)}),flush=True)
        del row;gc.collect()
    counts={'retained_contexts':len(cases),'BE32_input_fields':4,'source_mixer_variants':2,'scratch_write_events':12,
            'scratch_byte_encoders':8,'scratch_prefix_copies':4,'scratch_tempered_words':2,
            'source_chunks':sum(len(c['chunks']) for c in cases),'source_visits':sum(len(p['visits']) for c in cases for p in c['chunks']),
            'W9_preserved_frame_checks':sum(p['frame_checks'] for c in cases for p in c['scratch_tempering']['preservation']),
            'new_target_intervals':0,'new_root_bytes':0,'new_API_return_premises':0}
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'parent_pins':PINS,
            'dependencies':{p:sha(ROOT/p) for p in DEPS},'cases':cases,'verified_counts':counts,
            'retained_payload_scalar_contract_established':True,'native_schema_established':False,
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'full_goal_complete':False}


if __name__=='__main__':
    x=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(x,indent=2)+'\n')
    print(json.dumps(x['verified_counts']),flush=True)
