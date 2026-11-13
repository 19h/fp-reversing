#!/usr/bin/env python3
"""SIDB allocation, read-result, metadata publication and first content demand.

All256 frozen metadata contexts retain six NULL size controls and three
bounded nonnull controls. Each uses the opposite new ABI clobber pattern;
both patterns occur across the matrix without doubling inherited states.
Descriptor7/4096B continues through seven full64 read-return controls,
NULL/unequal cleanup and three independently supplied timestamp pairs.
Nonempty fresh owners have no defined bytes; no file content is supplied.
No native target API/filesystem/IPC/allocation/free/PAC or IDB mutation.
O(parent bytes+visits+effects+SDK source) time and retained storage.
"""
import json,subprocess
from pathlib import Path
from collections import Counter
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha
from recover_daemon_context_lock_use import imported_return
from recover_daemon_context_state_publish import owner
import recover_daemon_state_file_metadata as Parent

P='daemon_state_file_input';A=0x6600030000;N=4096;E=Parent.E;B=Parent.B;J=Parent.J
ALLOC=Parent.MALLOC;READ=0x100d69fc0;FREE=0x100cf92e8;CLOSE=Parent.CLOSE
ONCE=0x10043e508;WRLOCK=0x100361df4;MTIME=0x100be5f18;NSEC=MTIME+8
ONCE2=0x100442650;UNLOCK=0x100208efc;BYTE=0x1005b94fc
SEC_ADDRESS=Parent.STAT+48;NSEC_ADDRESS=Parent.STAT+56
READ_RETURNS=[0xffffffffffffffff,0,1,4095,4096,4097,0x100000000]
TIMES=[(0,0),(1,999999999),(0xffffffffffffffff,0x8000000000000000)]
pack=Parent.pack;unpack=Parent.unpack;rc=Parent.rc;restore=Parent.restore
DEPS=['daemon_receive_tools.py','daemon_receive_fixups.txt','probe_daemon_descriptor_producers.py',
      'recover_daemon_state_file_metadata.py','daemon_state_file_metadata_checks.json',
      'recover_daemon_state_file_admission.py','recover_daemon_context_lock_use.py',
      'recover_daemon_context_state_publish.py','daemon_state_file_input_abi.c']

def event(v,before,pattern,kind,value=0,size=0):
    e=imported_return(v,before,value if kind in ['close','sync'] else 0,pattern)
    invalid=[(E,4)] if kind in ['allocation','read','free','close'] else []
    if kind in ['allocation','read','free']:
        e.pop('return32');e.pop('int_return_upper32_unspecified_fixture')
        if kind=='allocation':
            v.set(0,value);e['pointer_return64']=hex(value)
            e['allocated_owner_premise']={'address':hex(value),'size_bytes':size,'initial_bytes_defined':False} if value else None
            if value:
                assert all(not(a<value+size and value<a+n) for a,n in v.foreign_owners)
                owner(v,value,size)
        elif kind=='read':
            assert before['boundary']['registers31'][:3]==['0x7',hex(A),hex(N)]
            v.set(0,value);e['ssize_return64_bits']=hex(value);invalid.append((A,N))
            e['count_exceeds_request_synthetic_control']=0<=value<0x8000000000000000 and value>N
        else:
            assert before['boundary']['pc']==hex(FREE) and before['boundary']['registers31'][0]==hex(A)
            assert (A,N) in v.foreign_owners;v.foreign_owners.remove((A,N));invalid.append((A,N))
            e['retired_owner_premise']={'address':hex(A),'size_bytes':N};e['void_return_premise']=True
            v.set(0,0xa5b6c7d8e9f01234^pattern)
        e['return_registers31'][0]=hex(v.reg(0))
    elif kind=='sync':
        pc=int(before['boundary']['pc'],16)
        invalid=[(Parent.Parent.ONCE_CELL,16)] if pc in [ONCE,ONCE2] else [(Parent.Parent.L,200)]
        e['once_completion_without_additional_callback_effects_premise']=pc in [ONCE,ONCE2]
    else:assert kind=='close'
    e['effect_kind']=kind;e['invalidated_spans']=[{'address':hex(a),'size_bytes':n} for a,n in invalid]
    for a,n in invalid:Parent.Parent.forget(v,a,n)
    return e

def returned(before,pattern,kind,value=0,size=0):
    v=restore(before);e=event(v,before,pattern,kind,value,size);row=Parent.Parent.interval(v,before,e)
    return {'API_return_premise':e,'interval_packed':pack(row)}

def context(index,parent):
    pattern=1-parent['ABI_clobber_pattern'];nulls=[];nonnull=[]
    for j,q in enumerate(parent['size_cases']):
        before=unpack(q['interval_packed']);size=int(q['size64'],16)
        c=returned(before,pattern,'allocation',0,size);c['parent_size_case_index']=j;nulls.append(c)
        if j in [0,1,2]:
            c=returned(before,pattern,'allocation',A,size);c['parent_size_case_index']=j;nonnull.append(c)
    read_parent=unpack(nonnull[2]['interval_packed']);assert read_parent['boundary']['pc']==hex(READ)
    reads=[]
    for bits in READ_RETURNS:
        c=returned(read_parent,pattern,'read',bits);c['return64_bits']=hex(bits);reads.append(c)
    null_parent=unpack(nulls[2]['interval_packed']);assert null_parent['boundary']['pc']==hex(CLOSE)
    null_close=[]
    for status in [0,0xffffffff]:
        c=returned(null_parent,pattern,'close',status);c['return32']=status;null_close.append(c)
    mismatch=unpack(reads[0]['interval_packed']);assert mismatch['boundary']['pc']==hex(FREE)
    freed=returned(mismatch,pattern,'free');free_parent=unpack(freed['interval_packed']);assert free_parent['boundary']['pc']==hex(CLOSE)
    failure_close=[]
    for status in [0,0xffffffff]:
        c=returned(free_parent,pattern,'close',status);c['return32']=status;failure_close.append(c)
    before=unpack(reads[4]['interval_packed']);assert before['boundary']['pc']==hex(ONCE)
    status=35 if pattern else 0;sync=[]
    for pc in [ONCE,WRLOCK]:
        assert before['boundary']['pc']==hex(pc)
        c=returned(before,pattern,'sync',status);sync.append(c);before=unpack(c['interval_packed'])
    assert before['boundary']['pc']==hex(MTIME)
    times=[]
    for seconds,nanoseconds in TIMES:
        sec=Parent.supplied(before,SEC_ADDRESS,seconds.to_bytes(8,'little'),'mtime_seconds64')
        second=unpack(sec['interval_packed']);assert second['boundary']['pc']==hex(NSEC)
        nsec=Parent.supplied(second,NSEC_ADDRESS,nanoseconds.to_bytes(8,'little'),'mtime_nanoseconds64')
        current=unpack(nsec['interval_packed']);rows=[]
        for pc,kind,value in [(ONCE2,'sync',status),(UNLOCK,'sync',status),(CLOSE,'close',0)]:
            assert current['boundary']['pc']==hex(pc)
            c=returned(current,pattern,kind,value);rows.append(c);current=unpack(c['interval_packed'])
        assert current['boundary']['pc']==hex(BYTE) and current['boundary']['detail']=={'address':hex(A),'size_bytes':1}
        times.append({'seconds64_bits':hex(seconds),'nanoseconds64_bits':hex(nanoseconds),'seconds':sec,'nanoseconds':nsec,'completion':rows})
    return {'parent_context_index':index,'ABI_clobber_pattern':pattern,'synchronization_return32':status,
            'NULL_allocations':nulls,'nonnull_allocations':nonnull,'read_cases':reads,'NULL_close_cases':null_close,
            'mismatch_free':freed,'mismatch_close_cases':failure_close,'success_lock_cases':sync,'timestamp_cases':times}

def context_intervals(c):
    for item in c['NULL_allocations']+c['nonnull_allocations']+c['read_cases']+c['NULL_close_cases']+[c['mismatch_free']]+c['mismatch_close_cases']+c['success_lock_cases']:yield unpack(item['interval_packed'])
    for t in c['timestamp_cases']:
        for item in [t['seconds'],t['nanoseconds']]+t['completion']:yield unpack(item['interval_packed'])

def intervals(e):
    for c in e['contexts']:yield from context_intervals(c)

def source():
    specs=[('allocation_result',ALLOC+4,0x100ce1d80),('read_arguments',0x100d69f9c,READ+4),
           ('read_result',READ+4,0x100d69fec),('unequal_free',0x100cf92c8,FREE+4),
           ('exact_read_pointer',0x100be5e00,0x100be5e4c),('timestamp_publication',MTIME,0x100be5f2c),
           ('first_file_byte',BYTE,BYTE+32)]
    return [{'name':n,'start':hex(a),'end':hex(b),'bytes_hex':IMAGE.read(a,b-a).hex(),
             'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(IMAGE.read(a,b-a),a)]} for n,a,b in specs]

def sdk_checks():
    sdk=Path(subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip());source=(ROOT/'daemon_state_file_input_abi.c').read_text()
    cmd=['xcrun','clang','-target','arm64e-apple-macos13.0','-isysroot',str(sdk),'-std=c11','-S','-O1','-x','c','-','-o','-']
    p=subprocess.run(cmd,input=source,text=True,capture_output=True,timeout=30);assert p.returncode==0 and not p.stderr,p.stderr
    portable=cmd.copy();portable[portable.index('-isysroot')+1]='<SDK>'
    headers=['usr/include/sys/stat.h','usr/include/sys/types.h','usr/include/unistd.h','usr/include/stdlib.h']
    return {'command':portable,'source':source,'assembly':p.stdout,'exit_code':0,'headers':[{'SDK_relative_header':h,'sha256':sha(sdk/h)} for h in headers],
            'scope':'Current compile-only arm64e ABI; historical native equivalence unknown.','native_API_executed':False}

def build():
    parent=json.loads(read(ROOT/(Parent.P+'_checks.json')));contexts=[];counts=Counter();used=set();number=0
    for j,p in enumerate(parent['contexts']):
        c=context(j,p);contexts.append(c)
        if j%8==0:print(json.dumps({'parent':j,'contexts':len(contexts)}),flush=True)
    for row in intervals({'contexts':contexts}):
        number+=1;counts.update(rc(row));used.update(int(x['address'],16) for x in row['source_reads'] if int(x['address'],16) in FIXUPS)
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n) for n in DEPS},
            'contexts':contexts,'source_regions':source(),'source_fixups':Parent.Parent.Parent.fixups(used),'SDK_checks':sdk_checks(),
            'verified_counts':{'contexts':len(contexts),'NULL_allocations':1536,'nonnull_allocations':768,'read_cases':1792,
                               'NULL_close_cases':512,'mismatch_free_cases':256,'mismatch_close_cases':512,'success_lock_cases':512,'timestamp_cases':768,'intervals':number,**counts},
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'native_epoch_join_established':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
