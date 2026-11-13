#!/usr/bin/env python3
"""Post-seed payload retirement, full twist and first private output byte.

Frozen caller/controller/API premises remain inherited. One additional8 B
neighbor-header field comes from the same constructor snapshot, with source
knownness and later-write preservation checked. Strict missing-field controls
remain separate. No native epoch, API/IPC/PAC or ownership is established.
O(parent bytes+source visits+byte effects+packed receipts) time/storage.
"""
import json,zlib,base64
from collections import Counter
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS,POOL,qword
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_daemon_network_record import state_bytes
import recover_daemon_second_mix as Parent
import recover_daemon_arena_split as Arena

P='daemon_postseed_output';ENTRY=Parent.NEXT;POINTER=0x100c21ab8;EXTENT=0x100abb0c0
RETIRE=0x100cb2ef0;NEIGHBOR=0x100a77ef8;RELEASE=0x100bde5d8
TWIST1=0x100a5e910;TWIST2=0x100a8d294;TWIST_LAST=0x100a2f5e4
RESET=0x100b2296c;SELECT=0x100a3c074;COUNTER=0x100b7c410
BYTE=0x100a0c988;NEXT=0x100bf6d40;G=Parent.G;PAYLOAD=Arena.PAYLOAD
DEPS=['daemon_receive_tools.py','daemon_receive_fixups.txt','recover_daemon_second_mix.py',
      'audit_daemon_second_mix.py','daemon_second_mix_checks.json','daemon_second_mix_audit.json',
      'recover_daemon_arena_split.py','daemon_context_lock_snapshot.json','daemon_context_lock_success.json',
      'recover_daemon_context_unseal.py','recover_daemon_return_bank_origins.py',
      'audit_daemon_readiness_arena.py','audit_daemon_clock_record.py','audit_daemon_context_state_publish.py']

def neighbor():
    s=json.loads(read(ROOT/'daemon_context_lock_snapshot.json'));a=Arena.MARKER+8
    mask=zlib.decompress(base64.b64decode(s['heap_owner']['known_mask_zlib_base64']));offset=a-Arena.H
    assert mask[offset:offset+8]==bytes([1])*8;raw=Arena.snapshot_read(s,a,8)
    t=json.loads(zlib.decompress(base64.b64decode(json.loads(read(ROOT/'daemon_context_lock_success.json'))['case']['payload_zlib_base64'])))
    count=0
    for step in t['steps']:
        assert step['bytes_hex']==IMAGE.read(int(step['pc'],16),4).hex();count+=1
        for e in step['events']:
            if e['kind']=='write':assert not(int(e['address'],16)<a+8 and a<int(e['address'],16)+e['size_bytes'])
    assert int.from_bytes(raw,'little')==Arena.M-2220
    return {'address':hex(a),'bytes_hex':raw.hex(),'source_known_mask_hex':'01'*8,
            'provenance':'separate_source_defined_constructor_snapshot_neighbor_header','later_constructor_visits_without_overlap':count}

def restore(row):return Parent.restore(row,Parent.Parent.RunBase)

def case(index,parent):
    old=Parent.Parent.unpack(parent['exit_intervals_packed'][-1]);v=restore(old);before=state_bytes(old)
    rows=[];counts=Counter();used=set();field=neighbor();sp=int(old['boundary']['SP'],16)
    def keep(r,label):
        rows.append({'label':label,'packed':Parent.Parent.pack(r)})
        counts.update(source_visits=len(r['source_visits']),reads=len(r['source_reads']),writes=len(r['source_writes']),logical_edges=len(r['logical_edges']),source_calls=len(r['source_calls']))
        used.update(int(x['address'],16) for x in r['source_reads'] if int(x['address'],16) in FIXUPS)
    specs=[(ENTRY,POINTER,'readiness_runtime_flag_route'),(POINTER,EXTENT,'saved_payload_nonnull'),
           (EXTENT,RETIRE,'encoded_extent_sign'),(RETIRE,None,'strict_retirement_prefix')]
    for pc,target,label in specs:
        v.cut_stops={target} if target else {RELEASE};r=v.interval(pc,label);keep(r,label);Parent.Parent.compact_fixtures(v)
        assert r['boundary']['pc']==hex(target if target else NEIGHBOR)
    assert r['boundary']['kind']=='before_undefined_foreign_owner_read' and r['boundary']['detail']=={'address':field['address'],'size_bytes':8}
    control=restore(r);control.cut_stops=set();missing=control.interval(NEIGHBOR,'strict_missing_neighbor_control')
    assert not missing['source_visits'] and missing['boundary']['pc']==hex(NEIGHBOR)
    a=int(field['address'],16);v.foreign_fixture(a,bytes.fromhex(field['bytes_hex']),field['provenance'])
    for pc,target,label in [(NEIGHBOR,RELEASE,'snapshot_neighbor_retirement_tail'),(RELEASE,TWIST1,'gate_release_and_twist_entry'),
                            (TWIST1,TWIST2,'first_twist_phase227'),(TWIST2,TWIST_LAST,'second_twist_phase396'),
                            (TWIST_LAST,RESET,'last_twist_word_and_index_partition'),(RESET,SELECT,'reset_extraction_index'),
                            (SELECT,COUNTER,'state_word_selection_and_counter_comparison'),(COUNTER,BYTE,'counter_publication_and_tempering'),
                            (BYTE,NEXT,'first_encoded_byte_and_control')]:
        v.cut_stops={target};r=v.interval(pc,label);assert r['boundary']['pc']==hex(target);keep(r,label);Parent.Parent.compact_fixtures(v)
    final=state_bytes(r);output=int.from_bytes(bytes(before[sp+0xa0+j] for j in range(8)),'little')
    return {'parent_case_index':index,'intervals':rows,'missing_neighbor_control_packed':Parent.Parent.pack(missing),
            'snapshot_neighbor_effect':{k:field[k] for k in ['address','bytes_hex','provenance']},
            'entry_state2496_hex':bytes(before[G+j] for j in range(2496)).hex(),'final_state2496_hex':bytes(final[G+j] for j in range(2496)).hex(),
            'entry_payload64_hex':bytes(before[PAYLOAD+j] for j in range(64)).hex(),'final_payload64_hex':bytes(final[PAYLOAD+j] for j in range(64)).hex(),
            'output_pointer':hex(output),'output_first_address':hex(output+31),'output_first_byte_hex':bytes([final[output+31]]).hex(),
            'final_boundary':r['boundary'],'final_NZCV':r['boundary_NZCV'],'counts':dict(counts),'used_fixups':[hex(x) for x in sorted(used)]}

def source():
    spans=[('readiness_route',ENTRY,0x100a388d4),('pointer',POINTER,0x100c21af0),('extent',EXTENT,0x100abb120),
           ('payload_overwrite',0x1009f296c,0x1009f29ac),('accounting',0x100c19b30,0x100c19ba4),
           ('pending_neighbor',0x100a77edc,0x100a77f38),('marker_commit',0x100c0ceac,0x100c0ced0),
           ('second_overwrite',0x100b7c0b8,0x100b7c104),('gate_release',RELEASE,0x100bde624),
           ('twist_entry',0x100a6cd1c,0x100a6cd3c),('twist1',TWIST1,0x100a5e960),
           ('twist2_setup',TWIST2,0x100a8d2c8),('twist2',0x100b31278,0x100b312c8),
           ('twist_last',TWIST_LAST,0x100a2f65c),('reset',RESET,0x100b22988),
           ('selection',SELECT,0x100a3c154),('counter',COUNTER,0x100b7c480),
           ('temper',0x100a7ccac,0x100a7cd1c),('byte_consumer',BYTE,0x100a0caa4)]
    return [{'name':n,'start':hex(a),'end':hex(b),'bytes_hex':IMAGE.read(a,b-a).hex(),
             'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(IMAGE.read(a,b-a),a)]} for n,a,b in spans]

def intervals(e):
    for c in e['cases']:
        for r in c['intervals']:yield Parent.Parent.unpack(r['packed'])
        yield Parent.Parent.unpack(c['missing_neighbor_control_packed'])

def route_decoder():
    left,right=0x100e99700,0x100f4e190;l,r=IMAGE.read(left,256),IMAGE.read(right,256)
    outputs=[j^r[l[j]^0x56] for j in range(256)];assert set(outputs)=={0x14}
    slot=POOL+8*(0x565+0x14);pointer=qword(slot)-0x07829387;assert pointer==0x1010b6cb8
    return {'left':hex(left),'right':hex(right),'left256_hex':l.hex(),'right256_hex':r.hex(),
            'XOR_outputs_256':outputs,'index':hex(0x579),'slot':hex(slot),'original_slot_hex':IMAGE.read(slot,8).hex(),
            'decoded_slot_scalar':hex(qword(slot)),'subtractive_bias':hex(0x07829387),'runtime_flag_pointer':hex(pointer)}

def build():
    p=json.loads(read(ROOT/(Parent.P+'_checks.json')));cases=[case(j,c) for j,c in enumerate(p['cases'])];counts=Counter()
    for c in cases:counts.update(c['counts'])
    used={int(x,16) for c in cases for x in c['used_fixups']}
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n) for n in DEPS},
            'snapshot_neighbor':neighbor(),'route_decoder':route_decoder(),'source_regions':source(),'source_fixups':Parent.Parent.Parent.Parent.Parent.Parent.Parent.Parent.Parent.Parent.Env.fixups(used),
            'cases':cases,'verified_counts':{'cases':len(cases),'intervals':sum(len(c['intervals'])+1 for c in cases),**counts},
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'native_epoch_join_established':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
