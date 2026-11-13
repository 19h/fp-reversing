#!/usr/bin/env python3
"""Conditional constructor-payload inverse, field reset and representation cycle.

The original constructor's exact 2184 source-defined bytes are an explicit
separate producer-state premise at the parent's undefined read. No native
epoch join follows. Four retained parent cases cover both stream states and
NULL/nonnull auxiliary pointers. No further bytes or API returns are added.
O(parent+producer bytes+visits+effects) time/storage; no native API/IPC,
allocation/free, hardware PAC or IDB mutation executes.
"""
import json,zlib,base64
from functools import lru_cache
from collections import Counter
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha
from recover_daemon_callback_revisit import unpack as old_unpack,snapshot_read
from recover_daemon_environment_outputs import fixups
import recover_daemon_auxiliary_state as Parent

P='daemon_payload_reactivation';D=0x6500115274;N=2184;J=Parent.J
ENTRY=Parent.STOP;BYTE=0x100866124;RAW=0x10086623c;REQUEST=0x100867254
HEADER=0x1004dec3c;RESEAL=0x1004a0b28;REFERENCE=0x1004a0c60;NEXT=0x10018ed34
SELECTED=[0,2,12,14];SEED=0x4546796b
pack=Parent.pack;unpack=Parent.unpack;rc=Parent.rc
DEPS=['daemon_receive_tools.py','daemon_receive_fixups.txt',
      'recover_daemon_auxiliary_state.py','audit_daemon_auxiliary_state.py',
      'daemon_auxiliary_state_checks.json','daemon_auxiliary_state_audit.json',
      'recover_daemon_generated_stream.py','recover_daemon_second_mix.py',
      'recover_daemon_context_unseal.py','recover_daemon_callback_revisit.py',
      'daemon_callback_revisit_contracts.json','daemon_callback_revisit_profiles.json',
      'daemon_callback_revisit_snapshot.json','daemon_callback_revisit_replays.json',
      'daemon_context_lock_snapshot.json','daemon_context_seal_contracts.json',
      'validate_daemon_callback_payload.py','audit_daemon_context_unseal.py',
      'audit_daemon_readiness_arena.py','replay_daemon_callback_revisit.py']

@lru_cache(None)
def producer():
    contracts=json.loads(read(ROOT/'daemon_callback_revisit_contracts.json'));payload=contracts['context_payload']
    assert (payload['address'],payload['extent_bytes'],payload['seed32'])==(hex(D),N,hex(SEED))
    profile=json.loads(read(ROOT/'daemon_callback_revisit_profiles.json'));trace=old_unpack(profile)
    assert __import__('hashlib').sha256(zlib.decompress(base64.b64decode(profile['payload_zlib_base64']))).hexdigest()==profile['payload_sha256']
    start=next(j for j,s in enumerate(trace['steps']) if s['pc']=='0x100462818')
    end=next(j for j,s in enumerate(trace['steps']) if s['pc']=='0x100462974')
    pointer=[];slots=[];later=[]
    for j,s in enumerate(trace['steps']):
        for e in s['events']:
            if e['kind']!='write':continue
            a=int(e['address'],16);n=e['size_bytes'];event={'pc':s['pc'],'source_visit_index':j,**e}
            if a<J+0x108 and J+0x100<a+n:pointer.append(event)
            if j<start and s['pc'] in ['0x100293ee4','0x100293ee8','0x100293eec'] and D<=a<D+N:slots.append(event)
            if j>=end and a<D+N and D<a+n:later.append(event)
    assert len(pointer)==9 and pointer[-1]['pc']=='0x1002fb264' and pointer[-1]['value']['hex']=='2e4c2bee000003c5'
    assert len(slots)==120 and not later
    snap=json.loads(read(ROOT/'daemon_context_lock_snapshot.json'));mask=zlib.decompress(base64.b64decode(snap['heap_owner']['known_mask_zlib_base64']));H=int(snap['arena_owner'],16)
    assert len(mask[D-H:D-H+N])==N and all(mask[D-H:D-H+N])
    assert snapshot_read(snap,D,N).hex()==payload['after_hex'] and snapshot_read(snap,J+0x100,8).hex()==pointer[-1]['value']['hex']
    seal=json.loads(read(ROOT/'daemon_context_seal_contracts.json'))['cases']
    assert len(seal)==13 and all(bytes.fromhex(c['before_hex'])[0x100:0x108].hex()==pointer[-1]['value']['hex'] for c in seal)
    return {'payload':payload,'pointer_field_writers':pointer,'slot_initializer_writes':slots,
            'constructor_codec_start_visit':start,'constructor_codec_end_visit':end,
            'constructor_source_visits':len(trace['steps']),'later_payload_overlapping_writes':0,
            'snapshot_defined_payload_bytes':N,'raw_context_profiles_preserving_pointer':13,
            'native_epoch_join_established':False}

def case(parent_index,parent):
    before=unpack(parent['intervals_packed'][-1]);v=Parent.Parent.restore(before)
    assert before['boundary']['pc']==hex(ENTRY)
    effect={'address':hex(D),'bytes_hex':producer()['payload']['after_hex'],'provenance':'separate_original_constructor_encoded_payload2184'}
    v.foreign_fixture(D,bytes.fromhex(effect['bytes_hex']),effect['provenance']);Parent.Parent.compact(v)
    rows=[];counts=Counter()
    for a,b,label in [(ENTRY,BYTE,'inverse_word_permutation'),(BYTE,RAW,'inverse_byte_transform'),
                      (RAW,REQUEST,'raw_reference_and_next_output_request'),
                      (REQUEST,HEADER,'four_byte_generation_and_scalar_pack'),
                      (HEADER,RESEAL,'header_slot_reset_and_reseal_setup'),
                      (RESEAL,REFERENCE,'byte_transform_and_descending_shuffle'),
                      (REFERENCE,NEXT,'encoded_reference_and_typed_allocation')]:
        v.cut_stops=set() if b==NEXT else {b};row=v.interval(a,label);assert row['boundary']['pc']==hex(b)
        rows.append({'label':label,'packed':pack(row)});counts.update(rc(row));Parent.Parent.compact(v)
    assert row['boundary']['kind']=='before_unmodeled_import_call' and row['boundary']['detail']['symbol']=='libSystem/_malloc' and row['boundary']['registers31'][0]=='0x4a'
    return {'parent_case_index':parent_index,'stream_parent_index':parent['parent_case_index'],
            'ABI_clobber_pattern':parent['ABI_clobber_pattern'],'auxiliary_pointer64':parent['pointer_return64'],
            'producer_state_effect':effect,'intervals':rows,'counts':dict(counts),'final_boundary':row['boundary'],'final_NZCV':row['boundary_NZCV']}

def intervals(e):
    for c in e['cases']:
        for p in c['intervals']:yield unpack(p['packed'])

def source():
    spans=[('constructor_slot_initialization',0x100293ed8,0x100293ef8),
           ('constructor_pointer_publication',0x1002fb248,0x1002fb280),
           ('inverse_word_loop',ENTRY,BYTE),('inverse_byte_body',BYTE,RAW),
           ('raw_pointer_publication',RAW,0x100866254),('four_byte_request',0x100867168,REQUEST+4),
           ('generated_scalar_pack',0x1005b94f8,0x1005b9550),('packed_scalar_save',0x1005b95b8,0x1005b95c0),
           ('header_word',HEADER,0x1004decbc),('slot_reset',0x100570e20,0x100570e4c),
           ('reseal_vector',RESEAL,0x1004a0ba8),('reseal_tail_and_words',0x1004a0ba8,REFERENCE),
           ('encoded_pointer_publication',REFERENCE,0x1004a0d04),('pending_typed_allocation',NEXT-16,NEXT+4)]
    return [{'name':name,'start':hex(a),'end':hex(b),'bytes_hex':IMAGE.read(a,b-a).hex(),
             'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(IMAGE.read(a,b-a),a)]} for name,a,b in spans]

def build():
    parent=json.loads(read(ROOT/(Parent.P+'_checks.json')));cases=[];counts=Counter();used=set()
    for j in SELECTED:
        c=case(j,parent['cases'][j]);cases.append(c);print(json.dumps({'parent_case':j,'counts':c['counts']}),flush=True)
    for row in intervals({'cases':cases}):
        counts.update(rc(row));used.update(int(x['address'],16) for x in row['source_reads'] if int(x['address'],16) in FIXUPS)
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n) for n in DEPS},
            'producer_evidence':producer(),'source_regions':source(),'source_fixups':fixups(used),'cases':cases,
            'verified_counts':{'cases':len(cases),'intervals':sum(len(c['intervals']) for c in cases),**counts},
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'native_epoch_join_established':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
