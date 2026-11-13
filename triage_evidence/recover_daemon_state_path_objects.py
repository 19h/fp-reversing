#!/usr/bin/env python3
"""Conditional SIDB path-object constructor, local lock and cleanup contracts.

Four frozen parents cross two ordinary ABI clobber patterns and six separate
allocation/initializer outcomes. New nonnull owners have no initial byte
definitions. All200 lock bytes become opaque after pthread_rwlock_init;
free returns retire only the explicit74-byte owner. No native API/IPC,
allocation/free, hardware PAC or IDB mutation executes. O(parent bytes+
cases*(visits+effects)) time/storage. Native epochs/ownership remain unknown.
"""
import json
from collections import Counter
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha
from recover_daemon_context_lock_use import imported_return
from recover_daemon_context_state_publish import owner
from recover_daemon_environment_outputs import fixups
import recover_daemon_payload_reactivation as Parent

P='daemon_state_path_objects';ENTRY=0x10018ed38;RETURN=0x1004cef34
MALLOC=Parent.NEXT;LOCK_MALLOC=0x10019385c;INIT=0x100130fcc;FREE=0x100085acc
B=0x6600006000;L=0x6600007000;N=74;LN=200;J=Parent.J;R=0x6800070db8
SCENARIOS=['object_NULL','lock_NULL','init_0','init_12','init_16','init_22']
pack=Parent.pack;unpack=Parent.unpack;rc=Parent.rc;compact=Parent.Parent.Parent.compact
DEPS=['daemon_receive_tools.py','daemon_receive_fixups.txt','recover_daemon_payload_reactivation.py',
      'audit_daemon_payload_reactivation.py','daemon_payload_reactivation_checks.json','daemon_payload_reactivation_audit.json',
      'recover_daemon_context_lock_use.py','recover_daemon_context_state_publish.py','recover_daemon_second_mix.py',
      'recover_daemon_context_unseal.py','recover_daemon_environment_outputs.py','audit_daemon_readiness_arena.py',
      'audit_daemon_network_record.py','daemon_rwlock_lifecycle_symbolic.py']

def restore(row):
    v=Parent.Parent.Parent.restore(row)
    # A carried, initially undefined owner may have no fixture on its page.
    # Map its backing without adding source definitions or another owner.
    for a,n in v.foreign_owners:
        for page in range(a&~4095,((a+n-1)&~4095)+4096,4096):
            if page not in v.pages:v.u.mem_map(page,4096);v.pages.add(page)
    return v

def forget(v,a,n):
    v.foreign_defined.difference_update(range(a,a+n))
    rebuilt=[]
    for f in v.image_fixtures:
        lo=int(f['address'],16);raw=bytes.fromhex(f['bytes_hex']);hi=lo+len(raw)
        for start,end in [(lo,min(hi,a)),(max(lo,a+n),hi)]:
            if start<end:rebuilt.append({**f,'address':hex(start),'bytes_hex':raw[start-lo:end-lo].hex()})
    v.image_fixtures=rebuilt

def event(v,before,pattern,kind,value=0):
    e=imported_return(v,before,value if kind=='init' else 0,pattern)
    if kind in ['object','lock']:
        n=N if kind=='object' else LN
        v.set(0,value);e['return_registers31'][0]=hex(value)
        e.pop('return32');e.pop('int_return_upper32_unspecified_fixture');e['pointer_return64']=hex(value)
        e['allocated_owner_premise']={'address':hex(value),'size_bytes':n,'initial_bytes_defined':False} if value else None
        if value:
            assert all(not(a<value+n and value<a+size) for a,size in v.foreign_owners);owner(v,value,n)
    elif kind=='init':
        assert before['boundary']['pc']==hex(INIT);forget(v,L,LN)
        e['opaque_owner_premise']={'address':hex(L),'size_bytes':LN,'initial_bytes_defined':False}
    else:
        assert kind=='free' and before['boundary']['pc']==hex(FREE) and before['boundary']['registers31'][0]==hex(B)
        v.foreign_owners.remove((B,N));forget(v,B,N);e['retired_owner_premise']={'address':hex(B),'size_bytes':N}
        v.set(0,0xa5b6c7d8e9f01234^pattern);e['return_registers31'][0]=hex(v.reg(0))
        e.pop('return32');e.pop('int_return_upper32_unspecified_fixture');e['void_return_premise']=True
    return e

def case(index,parent,pattern,scenario):
    before=unpack(parent['intervals'][-1]['packed']);assert before['boundary']['pc']==hex(MALLOC)
    v=restore(before);rows=[];events=[];counts=Counter()
    def run(start,kind,value=0):
        nonlocal before
        e=event(v,before,pattern,kind,value) if kind else None;compact(v);v.cut_stops={RETURN} if kind else set()
        row=v.interval(start,kind+'_return' if kind else 'caller_next_path_record');rows.append(pack(row));events.append(e);counts.update(rc(row));before=row;return row
    first=run(ENTRY,'object',0 if scenario=='object_NULL' else B)
    if scenario!='object_NULL':
        assert first['boundary']['pc']==hex(LOCK_MALLOC)
        row=run(LOCK_MALLOC+4,'lock',0 if scenario=='lock_NULL' else L)
        if scenario!='lock_NULL':
            assert row['boundary']['pc']==hex(INIT);row=run(INIT+4,'init',int(scenario.split('_')[1]))
        if row['boundary']['pc']==hex(FREE):row=run(FREE+4,'free')
        assert row['boundary']['pc']==hex(RETURN)
    else:assert first['boundary']['pc']==hex(RETURN)
    result=before;run(RETURN,None)
    assert before['boundary']['pc']==hex(MALLOC) and before['boundary']['detail']['symbol']=='libSystem/_malloc'
    assert before['boundary']['registers31'][:3]==['0x4a',hex(J+0x120),'0x14']
    return {'parent_case_index':index,'ABI_clobber_pattern':pattern,'scenario':scenario,
            'intervals_packed':rows,'API_return_premises':events,'counts':dict(counts),
            'constructor_return':result['boundary'],'constructor_return_NZCV':result['boundary_NZCV'],
            'final_boundary':before['boundary'],'final_NZCV':before['boundary_NZCV']}

def intervals(e):
    for c in e['cases']:
        for p in c['intervals_packed']:yield unpack(p)

def source():
    spans=[('object_allocation_return',ENTRY,0x10018ed64),('lock_request_record',0x10006eb78,0x10006ec84),
           ('creator_record_decode',0x10043a364,0x10043a420),('lock_allocator',LOCK_MALLOC-8,LOCK_MALLOC+44),
           ('lock_header',0x100130f60,0x100130f80),('lock_initializer',0x100130fc4,INIT+8),
           ('object_header_and_directory',0x1000fc56c,0x1000fc5e0),('directory_byte',0x1000879c4,0x1000879ec),
           ('path_separator',0x1000fe474,0x1000fe4e4),('basename_quad',0x1000915ec,0x100091678),
           ('path_terminator_and_publish',0x10003a3d8,0x10003a3f8),('failure_free',FREE-8,FREE+16),
           ('constructor_status_and_return',0x1000354d4,0x100035510),('next_caller_record',RETURN,0x1004cf03c)]
    return [{'name':name,'start':hex(a),'end':hex(b),'bytes_hex':IMAGE.read(a,b-a).hex(),
             'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(IMAGE.read(a,b-a),a)]} for name,a,b in spans]

def build():
    p=json.loads(read(ROOT/(Parent.P+'_checks.json')));cases=[];counts=Counter();used=set()
    for j,parent in enumerate(p['cases']):
        for pattern in [0,1]:
            for scenario in SCENARIOS:
                c=case(j,parent,pattern,scenario);cases.append(c);print(json.dumps({'parent':j,'pattern':pattern,'scenario':scenario,'counts':c['counts']}),flush=True)
    for row in intervals({'cases':cases}):counts.update(rc(row));used.update(int(x['address'],16) for x in row['source_reads'] if int(x['address'],16) in FIXUPS)
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n) for n in DEPS},
            'source_regions':source(),'source_fixups':fixups(used),'cases':cases,'verified_counts':{'cases':len(cases),'intervals':sum(len(c['intervals_packed']) for c in cases),**counts},
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'native_epoch_join_established':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
