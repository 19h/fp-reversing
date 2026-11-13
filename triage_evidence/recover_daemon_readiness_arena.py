#!/usr/bin/env python3
"""Source gate/readiness admission and arena-descriptor demand interfaces.

Parent entry states, 24 initial-image metadata bytes, current gate/flag/link
words and one producer-derived arena-header word remain separate premises.
O(parent receipts+cases*(visits+effects)) time/space. No native API/IPC,
allocation/free, hardware PAC or IDB mutation executes.
"""
import json,struct,zlib,base64
from collections import Counter
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha
from daemon_context_transfer_symbolic import loaded_bytes
from recover_daemon_callback_revisit import snapshot_read
import recover_daemon_context_state_publish as Parent

P='daemon_readiness_arena';CAS=0x100a6e5b8;RETRY=0x100a6e57c;ACQUIRED=0x100b73f98
FLAG_READ=0x100b74044;DESC_READ=0x100ba7724;NODE_READ=0x100ae2cbc
GATE=0x1010b5de0;FLAG=0x1010c5798;D=0x1010b5ef0;CELL=D+72;SENTINEL=D+48
H=0x6500100000;N=90000;M=0x5e878c613b8123ea
METADATA=[(0x1010b9008,8),(0x1010c4f48,8),(0x1010c67dc,4),(0x1010c8258,4)]
DEPS=['daemon_receive_tools.py','daemon_receive_fixups.txt','recover_daemon_context_state_publish.py',
      'daemon_context_state_publish_checks.json','daemon_context_state_publish_audit.json',
      'recover_daemon_context_lock_use.py','recover_daemon_context_unseal.py',
      'daemon_arena_storage_profiles.json','daemon_arena_storage_checks.json','daemon_arena_storage_contracts.json',
      'daemon_context_lock_snapshot.json','daemon_context_lock_success.json']

def entry_state(row):
    return {**row,'boundary':{'registers31':row['entry_registers31'],'Q_registers32':row['entry_Q_registers32'],'SP':row['caller_SP']},
            'boundary_NZCV':row['entry_NZCV'],'source_writes':[]}

def prefix(index,parent):
    row=parent['intervals'][-1];v=Parent.Parent.restore(entry_state(row));effects=[]
    for a,n in METADATA:
        f={'address':hex(a),'bytes_hex':loaded_bytes(a,n).hex(),'provenance':'separate_initial_image_metadata_premise_not_native_epoch'}
        v.image_fixture(a,bytes.fromhex(f['bytes_hex']),f['provenance']);effects.append(f)
    v.cut_stops={CAS};r=v.interval(int(row['entry_PC'],16),'parent_entry_to_pending_atomic_gate')
    assert r['boundary']['pc']==hex(CAS)
    return {'parent_main_case_index':index,'effects':effects,'intervals':[r]}

def gate_case(index,parent,word):
    before=parent['intervals'][-1];v=Parent.Parent.restore(before)
    f={'address':hex(GATE),'bytes_hex':struct.pack('<I',word).hex(),'provenance':'separate_current_gate_word'}
    v.image_fixture(GATE,bytes.fromhex(f['bytes_hex']),f['provenance']);v.cut_stops={RETRY,ACQUIRED}
    r=v.interval(CAS,'original_compare_exchange_and_admission')
    assert r['boundary']['pc']==hex(ACQUIRED if word==0x5d96 else RETRY)
    return {'parent_prefix_index':index,'gate_word32':hex(word),'effect':f,'intervals':[r]}

def acquired(index,parent):
    before=parent['intervals'][-1];v=Parent.Parent.restore(before);v.cut_stops={FLAG_READ}
    r=v.interval(ACQUIRED,'original_acquired_gate_to_readiness_demand');assert r['boundary']['pc']==hex(FLAG_READ)
    return {'parent_gate_case_index':index,'intervals':[r]}

def flag_case(index,parent,flag):
    before=parent['intervals'][-1];v=Parent.Parent.restore(before)
    f={'address':hex(FLAG),'bytes_hex':bytes([flag]).hex(),'provenance':'separate_current_readiness_byte'}
    v.image_fixture(FLAG,bytes([flag]),f['provenance']);v.cut_stops={DESC_READ}
    r=v.interval(FLAG_READ,'original_readiness_partition')
    assert r['boundary']['pc']==hex(DESC_READ if flag==1 else Parent.ARC)
    return {'parent_acquired_index':index,'flag8':flag,'effect':f,'intervals':[r]}

def descriptor_case(index,parent,word):
    before=parent['intervals'][-1];v=Parent.Parent.restore(before)
    f={'address':hex(CELL),'bytes_hex':struct.pack('<Q',word).hex(),'provenance':'separate_current_descriptor_link'}
    v.image_fixture(CELL,bytes.fromhex(f['bytes_hex']),f['provenance']);v.cut_stops={NODE_READ}
    r=v.interval(DESC_READ,'original_descriptor_link_comparison')
    assert r['boundary']['pc']==hex(0x100a7b8d8 if word==SENTINEL else NODE_READ)
    if word==SENTINEL:assert r['boundary']['detail']['symbol']=='libSystem/_malloc' and r['boundary']['registers31'][0]=='0x1388'
    return {'parent_flag_case_index':index,'descriptor_word64':hex(word),'effect':f,'intervals':[r]}

def snapshot_evidence():
    s=json.loads(read(ROOT/'daemon_context_lock_snapshot.json'))
    assert s['heap_owner']['address']==hex(H) and s['heap_owner']['size_bytes']==N and s['snapshot_before_creator_call']
    mask=zlib.decompress(base64.b64decode(s['heap_owner']['known_mask_zlib_base64']))
    fields=[]
    for a,n in [(GATE,4),(FLAG,1),(CELL,8),(H,8),(H+8,8),(H+86620,16),(H+N-24,16)]:
        raw=snapshot_read(s,a,n)
        if H<=a<H+N:assert mask[a-H:a-H+n]==bytes([1])*n
        fields.append({'address':hex(a),'size_bytes':n,'bytes_hex':raw.hex()})
    assert [int.from_bytes(bytes.fromhex(f['bytes_hex']),'little') for f in fields[:5]]==[0x5d96,1,H,M,M+86620]
    trace=json.loads(zlib.decompress(base64.b64decode(json.loads(read(ROOT/'daemon_context_lock_success.json'))['case']['payload_zlib_base64'])))
    checked=0
    for step in trace['steps']:
        assert IMAGE.read(int(step['pc'],16),4).hex()==step['bytes_hex']
        for ev in step['events']:
            if ev['kind']=='write':
                a=int(ev['address'],16);n=ev['size_bytes']
                assert all(not(a<int(f['address'],16)+f['size_bytes'] and int(f['address'],16)<a+n) for f in fields)
                checked+=1
    return {'fields':fields,'later_constructor_write_events_checked':checked,'later_constructor_source_visits_checked':len(trace['steps']),
            'overlapping_writes':0,'epoch_join_established':False,'native_observation':False}

def header_case(index,parent,epoch):
    before=parent['intervals'][-1];assert parent['descriptor_word64']==hex(H)
    v=Parent.Parent.restore(before);Parent.owner(v,H,N)
    delta=N-24 if epoch=='fresh_startup' else 86620
    f={'address':hex(H+8),'bytes_hex':struct.pack('<Q',M+delta).hex(),
       'provenance':'separate_'+epoch+'_header_word'}
    v.foreign_fixture(H+8,bytes.fromhex(f['bytes_hex']),f['provenance']);v.cut_stops=set()
    r=v.interval(NODE_READ,'original_arena_header_consumer_to_undefined_field')
    assert r['boundary']['pc']=='0x100b6a918' and r['boundary']['kind']=='before_undefined_foreign_owner_read'
    assert r['boundary']['detail']=={'address':hex(H+delta),'size_bytes':8}
    return {'parent_descriptor_case_index':index,'header_epoch':epoch,'decoded_marker_offset_bytes':delta,'outer_owner_premise':{'address':hex(H),'size_bytes':N,'nested_existing_views':True},
            'effect':f,'intervals':[r]}

def producer():
    p=json.loads(read(ROOT/'daemon_arena_storage_profiles.json'));c=p['cases'][1]
    assert c['heap_snapshot']['address']==hex(H) and c['heap_snapshot']['size_bytes']==N
    ws=[w for w in c['source_writes'] if w['pc'] in ['0x10032a56c','0x10032a5d0','0x10046c750']]
    assert [(w['address'],w['size_bytes'],w['after_hex']) for w in ws]==[
        (hex(CELL),8,struct.pack('<Q',H).hex()),(hex(H+8),8,struct.pack('<Q',M+N-24).hex()),(hex(FLAG),1,'01')]
    return {'profile_index':1,'owner':{'address':hex(H),'size_bytes':N},'source_writes':ws,
            'source_visit_indices':[w['source_visit_index'] for w in ws],'epoch_join_established':False}

def intervals(e):return [r for k in ['prefixes','gate_cases','acquired_cases','flag_cases','descriptor_cases','header_cases'] for c in e[k] for r in c['intervals']]

def source():
    specs=[('gate_pointer_and_CAS',0x100a6e57c,0x100a6e5d8),('readiness_setup',ACQUIRED,0x100b7410c),
           ('warm_dispatch',0x100ba6f80,0x100ba6f9c),('descriptor_reader',0x100ba7700,0x100ba774c),
           ('cold_saved_pointer_and_gate_release',0x100a8c054,0x100a8c080),
           ('node_header_reader',0x100ae2cac,0x100ae2d04),('expansion_allocation',0x100a7b890,0x100a7b8dc),
           ('next_unknown_arena_read',0x100b6a8e0,0x100b6a930),
           ('startup_descriptor_link',0x10032a560,0x10032a570),('startup_header',0x10032a5cc,0x10032a5d4),
           ('startup_readiness',0x10046c73c,0x10046c754)]
    return [{'name':n,'start':hex(a),'end':hex(b),'bytes_hex':IMAGE.read(a,b-a).hex(),
             'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(IMAGE.read(a,b-a),a)]} for n,a,b in specs]

def build():
    p=json.loads(read(ROOT/(Parent.P+'_checks.json')))
    prefixes=[prefix(j,c) for j,c in enumerate(p['cases']) if int(c['second_pointer_return64'],16)]
    gates=[gate_case(j,c,w) for j,c in enumerate(prefixes) for w in [0,0x5d96,0xa94ef,0xffffffff]]
    admitted=[acquired(j,c) for j,c in enumerate(gates) if c['gate_word32']=='0x5d96']
    flags=[flag_case(j,c,b) for j,c in enumerate(admitted) for b in [0,1,2,255]]
    descriptors=[descriptor_case(j,c,w) for j,c in enumerate(flags) if c['flag8']==1 for w in [0,SENTINEL,H]]
    headers=[header_case(j,c,epoch) for j,c in enumerate(descriptors) if c['descriptor_word64']==hex(H) for epoch in ['fresh_startup','constructor_snapshot']]
    e={'prefixes':prefixes,'gate_cases':gates,'acquired_cases':admitted,'flag_cases':flags,'descriptor_cases':descriptors,'header_cases':headers};counts=Counter()
    for r in intervals(e):counts.update(source_visits=len(r['source_visits']),reads=len(r['source_reads']),writes=len(r['source_writes']),logical_edges=len(r['logical_edges']),source_calls=len(r['source_calls']))
    used={int(x['address'],16) for r in intervals(e) for x in r['source_reads'] if int(x['address'],16) in FIXUPS}
    e.update(scope=__doc__,generator_sha256=sha(__file__),source_sha256=sha(SOURCE),dependencies={n:sha(ROOT/n) for n in DEPS},
        source_regions=source(),source_fixups=Parent.Parent.Parent.Parent.Parent.Parent.Env.fixups(used),producer_evidence=producer(),snapshot_evidence=snapshot_evidence(),
        verified_counts={**{k:len(v) for k,v in e.items()},'intervals':len(intervals(e)),**counts},
        native_API_executed=False,native_daemon_kext_pairing_established=False,native_epoch_join_established=False,full_goal_complete=False)
    return e

if __name__=='__main__':
    e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
