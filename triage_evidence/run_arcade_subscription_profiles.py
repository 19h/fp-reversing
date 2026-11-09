#!/usr/bin/env python3
"""Fresh original initializer followed by isolated private MIG61471 cases.

No disk checkpoint is consumed. One original-code initialization supplies an
in-memory snapshot cloned for each case. API models/PAC bypass remain explicit;
XPC send stops before a real reply or any host operation. O(N*B+sum(I)) work,
O(B+largest trace) live memory apart from retained result JSON.
"""
import hashlib
import json
from pathlib import Path
import pickle
import struct
from probe_arcade_subscription import SubscriptionProbe,ROOT,IMAGE,SOURCE,OBJECTS,OOL,ar


def code_evidence(p):
    for a in p.visited:assert bytes(p.u.mem_read(a,4))==IMAGE.read(a,4),hex(a)
    pages=sorted({a&~4095 for a in p.visited});h=hashlib.sha256()
    for a in pages:h.update(struct.pack('<Q',a));h.update(IMAGE.read(a,4096))
    return {'visited_instruction_addresses':[hex(a) for a in sorted(p.visited)],
        'original_instruction_bytes_verified':len(p.visited),'visited_original_code_pages':[hex(a) for a in pages],
        'visited_original_code_pages_sha256':h.hexdigest()}


def main():
    p=SubscriptionProbe('fresh_initialization',explore_original_code=True)
    result=p.run_initialization_prefix(budget=10000000)
    assert result['full_initialization_complete'],result
    init={'scope':__doc__,'source_sha256':hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        'probe_generator_sha256':hashlib.sha256((ROOT/'probe_arcade_subscription.py').read_bytes()).hexdigest(),
        'runner_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'result':result,'calls':p.calls,'image_writes':p.writes,'pac_bypasses':p.pac,
        'private_allocations':[{'address':hex(h['address']),'extent_bytes':h['extent'],
            'known_bytes':sum(h['known']),'freed':h['freed']} for h in p.allocations],
        'opaque_rwlocks':{hex(a):v for a,v in p.rwlocks.items()},'initialization_status_word':hex(int.from_bytes(p.u.mem_read(0x1010b6360,4),'little')),
        'native_target_executed':False,'target_host_operations_executed':False,**code_evidence(p)}
    (ROOT/'arcade_subscription_initialization_profile.json').write_text(json.dumps(init,indent=2)+'\n')
    print(json.dumps({'stage':'fresh_init','steps':p.steps,'stop':p.stop_reason,'allocations':len(p.allocations)}),flush=True)
    snapshot=pickle.dumps({k:v for k,v in p.__dict__.items() if k not in ('u','decoded')})
    memory=[(a,z,pr,bytes(p.u.mem_read(a,z-a+1))) for a,z,pr in p.u.mem_regions()]
    context=p.u.context_save();cases=[('default',{}),('service_mismatch',{'service_name':0x7107}),
        ('path_empty',{'path_length':0}),('path_one',{'path_length':1}),('path15',{'path_length':15}),
        ('path16',{'path_length':16}),('path1023',{'path_length':1023}),('path1024',{'path_length':1024}),
        ('count0',{'count':0}),('count1',{'count':1}),('count57',{'count':57}),('countmax',{'count':0xffffffff}),
        ('opaque0',{'opaque':0}),('opaquemax',{'opaque':0xffffffffffffffff}),
        ('malloc_first_null',{'malloc_fail_at':0}),('malloc_second_null',{'malloc_fail_at':1})]
    rows=[]
    for label,kw in cases:
        q=SubscriptionProbe(label,explore_original_code=True,xpc_mode='opaque',**kw)
        private_payload=q.payload
        for a,z,pr in list(q.u.mem_regions()):q.u.mem_unmap(a,z-a+1)
        for a,z,pr,raw in memory:q.u.mem_map(a,z-a+1,pr);q.u.mem_write(a,raw)
        q.__dict__.update(pickle.loads(snapshot));q.decoded={};q.u.context_restore(context)
        q.label=label;q.payload=private_payload;q.u.mem_write(OOL,private_payload)
        q.service_name=kw.get('service_name',0x5107);q.count=kw.get('count',4096);q.opaque=kw.get('opaque',0x1122334455667788)
        q.malloc_fail_at=kw.get('malloc_fail_at');q.application_malloc_calls=0;q.argument_record_address=None
        q.xpc_mode='opaque';q.xpc_objects={};q.xpc_next=OBJECTS+0x4000;q.initializing=False
        q.records=[];q.calls=[];q.steps=0;q.visited=set();q.writes=[];q.pac=[]
        q.initialization_prefix={'profile':'arcade_subscription_initialization_profile.json','full_initialization_complete':True,
            'profile_sha256':hashlib.sha256((ROOT/'arcade_subscription_initialization_profile.json').read_bytes()).hexdigest()}
        for n in range(29):q.setreg(n,0)
        r=q.run_subscription(budget=5000000);rows.append(r)
        print(json.dumps({'label':label,'steps':r['steps'],'stop':r['stop_reason'],'last':r['records'][-1]}),flush=True)
    (ROOT/'arcade_subscription_profiles.json').write_text(json.dumps({'scope':__doc__,'fresh_initialization':True,'profiles':rows},indent=2)+'\n')


if __name__=='__main__':main()
