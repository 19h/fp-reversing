#!/usr/bin/env python3
"""Conditional SIDB first-word stores, range dispatch and pathname re-query.

All768 inherited first-byte cuts receive three explicitly synthetic four-byte
controls: zero, lower interval endpoint and first word above the interval.
One representative cut adds twelve boundary/high-bit controls. Outside the
interval, one opposite-pattern borrowed errno-pointer return continues to
lstat; its output and the in-interval64B allocator remain unexecuted.
No recovered file content, native API/IPC/filesystem/allocation/free/PAC or
IDB mutation. O(parent bytes+visits+effects) time and retained storage.
"""
import json
from collections import Counter
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS,TABLE
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_daemon_state_file_input as Parent

P='daemon_state_word_routing';A=Parent.A;N=Parent.N;E=Parent.E;B=Parent.B;J=Parent.J
BYTE=Parent.BYTE;LOW=0x60003;HIGH=0x7000c
GATE1=0x1005fa9e0;GATE2=0x10054e94c;ERROR=0x1004cd11c;LSTAT=0x1004cd194;MALLOC=0x10058bf4c
BASE_WORDS=[0,LOW,HIGH]
EXTRA_WORDS=[1,LOW-1,LOW+1,0x68000,0x70000,HIGH-2,HIGH-1,HIGH+1,0x7fffffff,0x80000000,0xffffffff,0x6703cce9]
pack=Parent.pack;unpack=Parent.unpack;rc=Parent.rc;restore=Parent.restore
DEPS=['daemon_receive_tools.py','daemon_receive_fixups.txt','probe_daemon_descriptor_producers.py',
      'recover_daemon_state_file_input.py','daemon_state_file_input_checks.json',
      'recover_daemon_state_file_admission.py','recover_daemon_context_lock_use.py',
      'recover_daemon_state_path_objects.py']

def case(ci,ti,parent,before,word):
    pattern=1-parent['ABI_clobber_pattern']
    supplied=Parent.Parent.supplied(before,A,word.to_bytes(4,'big'),'synthetic_file_prefix4')
    row=unpack(supplied['interval_packed']);inside=LOW<=word<HIGH
    assert row['boundary']['pc']==hex(MALLOC if inside else ERROR)
    accessor=None
    if not inside:
        accessor=Parent.Parent.returned(row,pattern,pointer=True)
        after=unpack(accessor['interval_packed'])
        assert after['boundary']['pc']==hex(LSTAT) and after['boundary']['registers31'][:2]==[hex(B+32),'0x680005ff38']
    return {'parent_context_index':ci,'parent_timestamp_case_index':ti,'raw_big_endian_word32':hex(word),
            'inside_source_interval':inside,'ABI_clobber_pattern':pattern,'prefix':supplied,'errno_accessor':accessor}

def case_intervals(c):
    yield unpack(c['prefix']['interval_packed'])
    if c['errno_accessor']:yield unpack(c['errno_accessor']['interval_packed'])

def intervals(e):
    for c in e['cases']:yield from case_intervals(c)

def source():
    specs=[('prefix_and_first_private_store',BYTE,0x1005b95e8),('second_private_store',0x10059ab00,0x10059ab50),
           ('lower_range_gate',GATE1,0x1005faa90),('upper_range_gate',GATE2,0x10054e9fc),
           ('other_route_continuation',0x1006655b0,0x1006655c0),
           ('inside_record_leaf',0x100436378,0x100436388),('inside_pending_allocator',0x10058bf44,MALLOC+4),
           ('errno_clear_and_path',ERROR,0x1004cd12c),('pending_path_lstat',0x1004cd188,LSTAT+4)]
    return [{'name':n,'start':hex(a),'end':hex(b),'bytes_hex':IMAGE.read(a,b-a).hex(),
             'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(IMAGE.read(a,b-a),a)]} for n,a,b in specs]

def dispatch_metadata():
    slots=[0x10103f8c0,0x101040f50]+[TABLE+8*i for i in [0x3c5d,0x450b,0x9039,0x9045]]
    return [{'slot':hex(a),'original_word_hex':IMAGE.read(a,8).hex(),'logical_fixup':FIXUPS[a]} for a in slots]

def build():
    parent=json.loads(read(ROOT/(Parent.P+'_checks.json')));cases=[];counts=Counter();used=set();number=0
    for ci,c in enumerate(parent['contexts']):
        for ti,t in enumerate(c['timestamp_cases']):
            before=unpack(t['completion'][-1]['interval_packed'])
            words=BASE_WORDS+(EXTRA_WORDS if (ci,ti)==(0,0) else [])
            for word in words:cases.append(case(ci,ti,c,before,word))
        if ci%16==0:print(json.dumps({'context':ci,'cases':len(cases)}),flush=True)
    for row in intervals({'cases':cases}):
        number+=1;counts.update(rc(row));used.update(int(x['address'],16) for x in row['source_reads'] if int(x['address'],16) in FIXUPS)
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),
            'dependencies':{n:sha(ROOT/n) for n in DEPS},'cases':cases,'source_regions':source(),'dispatch_metadata':dispatch_metadata(),
            'source_fixups':Parent.Parent.Parent.Parent.fixups(used),
            'verified_counts':{'parent_contexts':256,'incoming_first_byte_cuts':768,'synthetic_prefix_cases':len(cases),
                               'inside_interval_cases':sum(c['inside_source_interval'] for c in cases),
                               'borrowed_errno_continuations':sum(c['errno_accessor'] is not None for c in cases),'intervals':number,**counts},
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'native_epoch_join_established':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
