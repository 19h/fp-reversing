#!/usr/bin/env python3
"""Conditional ten-path family, caller gate and first SIDB lstat request.

Eight successful SIDB parents cross two new ABI clobber patterns. Nine
additional constructors use separate nonnull allocation/init-zero premises.
Twenty single-field-zero controls cross ten fields and both patterns in the
first parent only; they are not allocation-failure observations. A borrowed
four-byte errno cell has no initial definition. No native API/IPC, filesystem,
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
import recover_daemon_state_path_objects as Parent

P='daemon_state_path_family';J=Parent.J
GATE=0x1004cf894;ERRNO=0x10063c2f8;LSTAT=0x10063c368;DESTROY=0x10031ca0c
E=0x6600020000
PARENTS=[2,8,14,20,26,32,38,44]
# Ordinal, context offset, source filename, caller call site, payload bytes.
FAMILY=[(1,0x118,0x10102fa20,0x1004cef30,12,'SC Info.sidb'),
        (2,0x120,0x1010130e0,0x1004cf038,12,'SC Info.sidn'),
        (3,0x110,0x10100a2f0,0x1004cf148,12,'SC Info.sidd'),
        (4,0x108,0x100fc22f0,0x1004cf260,12,'SC Info.sidv'),
        (5,0x128,0x100fec610,0x1004cf36c,12,'SC Info.sidr'),
        (6,0x130,0x100f70f65,0x1004cf474,12,'SC Info.sidl'),
        (7,0x138,0x101029830,0x1004cf578,20,'SC Info.rbSyncResp'),
        (8,0x140,0x100eef330,0x1004cf684,12,'SC Info.sidt'),
        (9,0x148,0x101004660,0x1004cf778,12,'SC Info.sids'),
        (10,0x150,0x100fea4f0,0x1004cf888,12,'SC Info.sido')]
GATES=[(0x118,0x1004cf894,0x1004cf8b0,'w9'),
       (0x110,0x1005a8ad8,0x1005a8af4,'w10'),
       (0x108,0x10059fe2c,0x10059fe48,'w9'),
       (0x120,0x1005d3370,0x1005d3394,'w10'),
       (0x128,0x1007f5294,0x1007f52b4,'w10'),
       (0x130,0x1007fc548,0x1007fc56c,'w10'),
       (0x140,0x1005eb634,0x1005eb660,'w9'),
       (0x148,0x1005c57b4,0x1005c57d4,'w10'),
       (0x150,0x10060f1c0,0x10060f1dc,'w9')]
pack=Parent.pack;unpack=Parent.unpack;rc=Parent.rc;compact=Parent.compact
restore=Parent.restore;forget=Parent.forget
DEPS=['daemon_receive_tools.py','daemon_receive_fixups.txt','recover_daemon_state_path_objects.py',
      'audit_daemon_state_path_objects.py','daemon_state_path_objects_checks.json','daemon_state_path_objects_audit.json',
      'recover_daemon_context_lock_use.py','recover_daemon_context_state_publish.py',
      'recover_daemon_environment_outputs.py','audit_daemon_readiness_arena.py','audit_daemon_network_record.py',
      'recover_daemon_return_bank_origins.py','lskd_values_symbolic.py','daemon_rwlock_lifecycle_symbolic.py',
      'daemon_rwlock_lifecycle_contracts.json']

def address(ordinal):return Parent.B+(ordinal-1)*0x2000

def path_payload(source,n):
    e=IMAGE.read(source,n)
    return b''.join(bytes([e[j+2]^0x52,e[j]^0x3e,e[j+3]^0x99,e[j+1]^0x22]) for j in range(0,n,4))

def pointer_event(v,before,pattern,a,n,borrowed=False):
    e=imported_return(v,before,0,pattern);v.set(0,a);e['return_registers31'][0]=hex(a)
    e.pop('return32');e.pop('int_return_upper32_unspecified_fixture');e['pointer_return64']=hex(a)
    assert all(not(lo<a+n and a<lo+size) for lo,size in v.foreign_owners)
    owner(v,a,n)
    e['borrowed_owner_premise' if borrowed else 'allocated_owner_premise']={'address':hex(a),'size_bytes':n,'initial_bytes_defined':False}
    return e

def case(index,parent,pattern):
    before=unpack(parent['intervals_packed'][-1]);v=restore(before);rows=[];events=[];counts=Counter()
    def run(event,stop=None):
        nonlocal before
        start=int(before['boundary']['pc'],16)+(4 if event else 0)
        compact(v);v.cut_stops={stop} if stop else set()
        row=v.interval(start,'source_family_API_return' if event else 'source_family_caller_gate')
        rows.append(pack(row));events.append(event);counts.update(rc(row));before=row;return row
    for ordinal,offset,source,call,n,name in FAMILY[1:]:
        a=address(ordinal);lock=a+0x1000;size=62+n
        assert before['boundary']['pc']==hex(Parent.MALLOC)
        assert before['boundary']['registers31'][:3]==[hex(size),hex(J+offset),'0x14'] and before['boundary']['registers31'][23]==hex(source)
        run(pointer_event(v,before,pattern,a,size));assert before['boundary']['pc']==hex(Parent.LOCK_MALLOC)
        run(pointer_event(v,before,pattern,lock,200));assert before['boundary']['pc']==hex(Parent.INIT)
        assert before['boundary']['registers31'][:2]==[hex(lock),'0x0']
        e=imported_return(v,before,0,pattern);forget(v,lock,200)
        e['opaque_owner_premise']={'address':hex(lock),'size_bytes':200,'initial_bytes_defined':False}
        run(e,GATE if ordinal==10 else None)
    assert before['boundary']['pc']==hex(GATE);run(None)
    assert before['boundary']['pc']==hex(ERRNO)
    run(pointer_event(v,before,pattern,E,4,True))
    assert before['boundary']['pc']==hex(LSTAT)
    return {'parent_case_index':index,'ABI_clobber_pattern':pattern,'intervals_packed':rows,
            'API_return_premises':events,'counts':dict(counts),'all_new_initializer_statuses32_zero':True,
            'final_boundary':before['boundary'],'final_NZCV':before['boundary_NZCV']}

def control(case_index,c,offset):
    before=unpack(c['intervals_packed'][26]);assert before['boundary']['pc']==hex(GATE)
    v=restore(before);forget(v,J+offset,8)
    v.foreign_fixture(J+offset,bytes(8),'explicit_single_field_zero_control_not_native_failure')
    compact(v);v.cut_stops=set();row=v.interval(GATE,'source_single_field_zero_control')
    assert row['boundary']['pc']==hex(ERRNO if offset==0x138 else DESTROY)
    return {'family_case_index':case_index,'zero_context_offset':hex(offset),
            'premise':{'address':hex(J+offset),'size_bytes':8,'bytes_hex':'00'*8,
                       'native_allocation_failure_observed':False},
            'interval_packed':pack(row),'counts':rc(row)}

def intervals(e):
    for c in e['cases']:
        for p in c['intervals_packed']:yield unpack(p)
    for c in e['gate_controls']:yield unpack(c['interval_packed'])

def source():
    spans=[('family_caller',0x1004cf034,0x1004cf8bc),
           ('filesystem_record',0x10042f3a0,0x10042f3cc),
           ('filesystem_adapter_call',0x10042f4a8,0x10042f4c0),
           ('filesystem_inner_call',0x10061922c,0x10061924c),
           ('errno_and_lstat',0x10063c2e0,0x10063c384)]
    spans += [('gate_'+hex(off),a,b+4) for off,a,b,_ in GATES[1:]]
    code=[{'name':name,'start':hex(a),'end':hex(b),'bytes_hex':IMAGE.read(a,b-a).hex(),
           'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(IMAGE.read(a,b-a),a)]} for name,a,b in spans]
    return {'code':code,'filename_constants':[{'ordinal':o,'context_offset':hex(off),'source':hex(a),
           'constructor_call':hex(call),'encoded_bytes_hex':IMAGE.read(a,n).hex(),
           'decoded_payload_hex':path_payload(a,n).hex(),'payload_size_bytes':n,'basename_ascii':name}
           for o,off,a,call,n,name in FAMILY]}

def build():
    p=json.loads(read(ROOT/(Parent.P+'_checks.json')));cases=[];controls=[];counts=Counter();used=set()
    assert [i for i,c in enumerate(p['cases']) if c['scenario']=='init_0']==PARENTS
    for index in PARENTS:
        for pattern in [0,1]:
            c=case(index,p['cases'][index],pattern);cases.append(c)
            print(json.dumps({'parent':index,'pattern':pattern,'counts':c['counts']}),flush=True)
    for ci in [0,1]:
        for _,offset,*_ in FAMILY:controls.append(control(ci,cases[ci],offset))
    e={'cases':cases,'gate_controls':controls}
    for row in intervals(e):
        counts.update(rc(row));used.update(int(x['address'],16) for x in row['source_reads'] if int(x['address'],16) in FIXUPS)
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),
            'dependencies':{n:sha(ROOT/n) for n in DEPS},'source_regions':source(),'source_fixups':fixups(used),**e,
            'verified_counts':{'cases':len(cases),'gate_controls':len(controls),'intervals':sum(len(c['intervals_packed']) for c in cases)+len(controls),**counts},
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'native_epoch_join_established':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
