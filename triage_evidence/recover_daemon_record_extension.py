#!/usr/bin/env python3
"""Conditional post-77B record construction and parent-publication frontier.
Inherited growth-success exports cross two declared ABI clobber patterns.
The first 97B request receives NULL or a fresh owner; the normal branch then
uses fresh returns only until a non-allocation boundary or parent write.
All fresh bytes start undefined. No native API, IPC or IDB action executes.
O(parent bytes + representative visits + members*demands) time;
O(receipts + member maps + largest interval) space.
"""
import json
import sys
from collections import defaultdict,Counter
from copy import deepcopy
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha
from audit_daemon_network_record import state_bytes
from audit_daemon_state_table_mixing import admission
from audit_daemon_state_emitter_completion import requirements
import recover_daemon_descriptor_growth as Parent

P='daemon_record_extension'
B=Parent.B
pack,unpack=B.pack,B.unpack
FIRST_SIZE=97
FRESH_BASE=0x6600090000
MAX_EVENTS=40
MAX_FRESH_EXTENT=0x10000
PINS={'daemon_descriptor_growth_checks.json':'b2606c71e79e0ed6707d5102e00a96dc8f0f492e2b73b6087ca2cd47d4030ef2',
      'daemon_descriptor_growth_replay.json':'bee4ab3224710559fefdd8bca070110e48c03ab52d01c92b617988b9b3d5bd67'}
DEPS=['daemon_receive_tools.py','daemon_receive_fixups.txt','recover_daemon_descriptor_growth.py',
      'recover_daemon_constructor_buffer.py','audit_daemon_network_record.py',
      'audit_daemon_state_table_mixing.py','audit_daemon_state_emitter_completion.py']


def parents():
    old=json.loads(read(ROOT/'daemon_descriptor_growth_checks.json'))
    result=[]
    for old_index,c in enumerate(old['coverage']):
        if c['pointer_return64']!=hex(Parent.H):continue
        state=unpack(c['derived_terminal_state_packed'])
        assert state['boundary']['pc']=='0x100d640ac' and state['boundary']['registers31'][0]==hex(FIRST_SIZE)
        result.append({'growth_coverage_index':old_index,'growth_class_index':c['class_index'],
            'cohort_index':c['cohort_index'],'prior_ABI_pattern':c['ABI_clobber_pattern'],'state':state})
    assert len(result)==304
    return result


def event(before,pattern,pointer=None):
    b=before['boundary'];v=B.restore(before);invalid=[(B.APIParent.E,4)]
    assert b['kind']=='before_unmodeled_import_call'
    retired=None;allocated=None
    if pointer is None:
        assert b['detail']['symbol']=='libSystem/_free'
        a=int(b['registers31'][0],16)
        matches=[(p,n) for p,n in v.foreign_owners if p==a];assert len(matches)==1
        retired=matches[0];invalid.append(retired)
    else:
        assert b['detail']['symbol']=='libSystem/_malloc'
        n=int(b['registers31'][0],16);assert 0<n<MAX_FRESH_EXTENT
        if pointer:
            assert pointer>=FRESH_BASE and (pointer-FRESH_BASE)%MAX_FRESH_EXTENT==0
            assert all(not(a<pointer+n and pointer<a+k) for a,k in v.foreign_owners)
            memory=state_bytes(before)
            assert all(pointer+j not in memory for j in range(n))
    ev=B.API.event(v,before,pattern,invalid=invalid)
    ev.pop('return32');ev.pop('int_return_upper32_unspecified_fixture');ev['ABI_clobber_pattern']=pattern
    if pointer is None:
        v.set(0,0xa5b6c7d8e9f01234^pattern);v.foreign_owners.remove(retired)
        ev.update(void_return_premise=True,retired_owner_premise={'address':hex(retired[0]),'size_bytes':retired[1]},
            effect_kind='declared_free_return')
    else:
        v.set(0,pointer)
        if pointer:
            B.APIParent.owner(v,pointer,n)
            allocated={'address':hex(pointer),'size_bytes':n,'initial_bytes_defined':False}
        ev.update(pointer_return64=hex(pointer),allocated_owner_premise=allocated,
            requested_extent_bytes=n,effect_kind='declared_malloc_return')
    ev['return_registers31']=[hex(v.reg(j)) for j in range(31)]
    return v,ev


def returned(parent,template,pattern=None):
    ev=deepcopy(template);pattern=ev['ABI_clobber_pattern'] if pattern is None else pattern
    assert pattern in [0,1];ev['ABI_clobber_pattern']=pattern
    assert parent['boundary']['pc']==ev['call_site'] and parent['boundary']['detail']['symbol']==ev['symbol']
    if ev['symbol']=='libSystem/_malloc':
        assert parent['boundary']['registers31'][0]==hex(ev['requested_extent_bytes'])
    else:
        assert parent['boundary']['registers31'][0]==ev['retired_owner_premise']['address']
    for j in range(18,30):ev['return_registers31'][j]=parent['boundary']['registers31'][j]
    for j in range(32):
        bits=((j+1)*0x123456789abcdef0123456789abcdef+pattern*0xfedcba9876543210fedcba9876543210)&((1<<128)-1)
        if 8<=j<16:bits=(bits&~((1<<64)-1))|(int(parent['boundary']['Q_registers32'][j],16)&((1<<64)-1))
        ev['return_Q_registers32'][j]=hex(bits)
    ev['return_NZCV']='0x50000000' if pattern else '0xa0000000'
    if ev.get('void_return_premise'):ev['return_registers31'][0]=hex(0xa5b6c7d8e9f01234^pattern)
    if ev.get('allocated_owner_premise'):
        o=ev['allocated_owner_premise'];a,n=int(o['address'],16),o['size_bytes']
        assert parent['boundary']['registers31'][0]==hex(n)
        assert all(not(int(q['address'],16)<a+n and a<int(q['address'],16)+q['size_bytes']) for q in parent['foreign_owners'])
        memory=state_bytes(parent)
        assert all(a+j not in memory for j in range(n))
    return B.fixture_state(parent,ev),ev


def path(before,pattern,normal):
    current=before;items=[];data=[];allocation_index=0
    for step in range(MAX_EVENTS):
        boundary=current['boundary'];symbol=boundary['detail']['symbol']
        if symbol=='libSystem/_malloc':
            pointer=FRESH_BASE+allocation_index*MAX_FRESH_EXTENT if normal else 0
            assert normal or allocation_index==0
            allocation_index+=1
        else:
            assert symbol=='libSystem/_free';pointer=None
        v,ev=event(current,pattern,pointer)
        B.API.compact(v);v.cut_stops=set()
        row=B.interval(v,int(boundary['pc'],16)+4,ev['effect_kind'])
        entry,own=returned(current,ev);assert own==ev
        projection=B.registers([row]);need,effects,_=requirements(entry,[row])
        items.append({'API_return_premise':ev,'interval_packed':pack(row),'register_projection':projection})
        data.append((entry,row,need,projection))
        current=B.export(entry,row,projection)
        jw=[w for w in row['source_writes'] if int(w['address'],16)<B.J+552 and B.J<int(w['address'],16)+w['size_bytes']]
        print(json.dumps({'event':step,'normal_branch':normal,'visits':len(row['source_visits']),
            'continued':symbol,'requested_extent_bytes':ev.get('requested_extent_bytes'),
            'next_PC':row['boundary']['pc'],'next_kind':row['boundary']['kind'],
            'next_symbol':row['boundary'].get('detail',{}).get('symbol'),
            'next_X0':row['boundary']['registers31'][0],'J_store_events':jw,
            'stop_detail':row['boundary'].get('detail') if jw else None}),flush=True)
        next_boundary=current['boundary']
        if jw or next_boundary['kind']!='before_unmodeled_import_call':break
        next_symbol=next_boundary['detail']['symbol']
        if next_symbol not in ['libSystem/_malloc','libSystem/_free']:break
        if not normal and next_symbol=='libSystem/_malloc':break
        if next_symbol=='libSystem/_malloc' and not 0<int(next_boundary['registers31'][0],16)<MAX_FRESH_EXTENT:break
    else:raise AssertionError('analysis event observation limit reached')
    return items,data,current


def build():
    for p,d in PINS.items():assert sha(ROOT/p)==d
    incoming=parents();groups=defaultdict(list)
    for j,p in enumerate(incoming):
        s=p['state'];key=json.dumps({'configuration':s['configuration'],'owners':s['foreign_owners']},sort_keys=True)
        groups[key].extend((j,pattern) for pattern in [0,1])
    classes=[];coverage=[];counts=Counter();used=set();pcs=set()
    for normal in [False,True]:
        for members in groups.values():
            pending=members.copy()
            while pending:
                representative,pattern=pending[0]
                items,data,current=path(incoming[representative]['state'],pattern,normal)
                accepted=[];rejected=[];ci=len(classes)
                for j,member_pattern in pending:
                    current=incoming[j]['state']
                    try:
                        for item,(rep_entry,row,need,projection) in zip(items,data):
                            entry,ev=returned(current,item['API_return_premise'],member_pattern)
                            admission(entry,rep_entry,need,projection);current=B.export(entry,row,projection)
                    except AssertionError:
                        assert (j,member_pattern)!=(representative,pattern)
                        rejected.append((j,member_pattern));continue
                    coverage.append({'parent_index':j,'class_index':ci,'ABI_clobber_pattern':member_pattern,
                        'normal_branch':normal,'derived_terminal_state_packed':pack(current)})
                    accepted.append({'parent_index':j,'ABI_clobber_pattern':member_pattern})
                classes.append({'representative_parent_index':representative,'members':accepted,
                    'representative_ABI_pattern':pattern,'normal_branch':normal,'intervals':items})
                for entry,row,need,projection in data:
                    counts.update(B.rc(row))
                    used.update(int(r['address'],16) for r in row['source_reads'] if int(r['address'],16) in FIXUPS)
                    pcs.update(int(v['pc'],16) for v in row['source_visits'])
                print(json.dumps({'class':ci,'members':len(accepted),'intervals':len(items),
                    'normal_branch':normal,'terminal':data[-1][1]['boundary']['pc']}),flush=True)
                pending=rejected
    assert len(coverage)==1216
    assert {(c['parent_index'],c['ABI_clobber_pattern'],c['normal_branch']) for c in coverage}=={
        (j,p,n) for j in range(304) for p in [0,1] for n in [False,True]}
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),
        'dependencies':{p:sha(ROOT/p) for p in DEPS},'parent_pins':PINS,'classes':classes,'coverage':coverage,
        'source_words':[{'start':hex(pc),'bytes_hex':IMAGE.read(pc,4).hex()} for pc in sorted(pcs)],
        'source_fixups':B.APIParent.API.Parent.fixups(used),
        'verified_counts':{'incoming_parents':304,'branch_classes':len(classes),'terminal_exports':1216,
            'ABI_patterns':2,'first_malloc_outcomes':2,'new_payload_bytes_supplied':0,
            'new_root_bytes_supplied':0,'new_node_bytes_supplied':0,**counts},
        'normal_policy':'Fresh return at each admitted malloc; no later NULL outcome claimed.',
        'observation_event_limit':MAX_EVENTS,'fresh_extent_limit_bytes':MAX_FRESH_EXTENT,
        'native_API_executed':False,'native_daemon_kext_pairing_established':False,
        'initializer_to_current_caller_join_established':False,'full_goal_complete':False}


if __name__=='__main__':
    if '--probe' in sys.argv:
        path(parents()[0]['state'],0,True)
    else:
        e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n')
        print(json.dumps(e['verified_counts']),flush=True)
