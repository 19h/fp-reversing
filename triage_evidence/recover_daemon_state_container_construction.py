#!/usr/bin/env python3
"""All76 pending SIDN query parents: cleanup and conditional64B construction.

Four lstat controls, two representative modes, three borrowed errno accessors
with two scalar controls each, four unlink controls and two synchronization
sequences retain twelve terminal paths per parent. Every path continues a
declared buffer-free return. The link route additionally crosses NULL/fresh64B
allocator returns in every parent. Other terminal allocations remain pending.
ABI returns, opaque spans, allocator owners and scalar controls are premises.
No native API/IPC/filesystem/allocation/free/PAC or IDB mutation executes.
O(parent bytes+retained visits+effects+SDK source) time and retained storage.
"""
import json,subprocess
from pathlib import Path
from collections import Counter
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha
from recover_daemon_context_state_publish import owner
import recover_daemon_state_path_removal as Parent

P='daemon_state_container_construction';API=Parent.API
B=Parent.D;L=B+0x1000;A=Parent.A;N=Parent.N;E=Parent.E;J=Parent.J
S=0x6600040000;SIZE=64;BIAS=0x4aba552460e435c6
LSTAT=Parent.LSTAT;MODE=Parent.MODE;ERRNO=Parent.ERRNO;UNLINK=Parent.UNLINK
ONCE=Parent.ONCE;WRLOCK=Parent.WRLOCK;ONCE2=Parent.ONCE2;UNLOCK=Parent.UNLOCK
FREE=0x10074aa20;MALLOC=0x100710758;NEXT_ERROR=0x10063c2f8;NEXT_MALLOC=0x1009342fc
STATUSES=Parent.STATUSES;MODES=[0xa000,0x81a4];ERRNOS=[2,13]
pack=Parent.pack;unpack=Parent.unpack;rc=Parent.rc;restore=Parent.Parent.restore
DEPS=['daemon_receive_tools.py','daemon_receive_fixups.txt','probe_daemon_descriptor_producers.py',
      'recover_daemon_state_path_removal.py','daemon_state_path_removal_checks.json',
      'recover_daemon_state_file_admission.py','recover_daemon_context_lock_use.py',
      'recover_daemon_context_state_publish.py','recover_daemon_state_path_family.py',
      'daemon_state_container_construction_abi.c']

def retire(before,pattern):
    assert before['boundary']['pc']==hex(FREE) and before['boundary']['registers31'][0]==hex(A)
    v=restore(before);ev=API.event(v,before,pattern,invalid=[(A,N),(E,4)])
    ev.pop('return32');ev.pop('int_return_upper32_unspecified_fixture');ev['void_return_premise']=True
    v.set(0,0xa5b6c7d8e9f01234^pattern);ev['return_registers31'][0]=hex(v.reg(0))
    assert (A,N) in v.foreign_owners;v.foreign_owners.remove((A,N))
    ev['retired_owner_premise']={'address':hex(A),'size_bytes':N};ev['effect_kind']='buffer_free'
    row=API.interval(v,before,ev);assert row['boundary']['pc']==hex(MALLOC) and row['boundary']['registers31'][0]=='0x40'
    return {'API_return_premise':ev,'interval_packed':pack(row)}

def allocate(before,pattern,pointer):
    assert before['boundary']['pc']==hex(MALLOC) and before['boundary']['registers31'][0]=='0x40'
    v=restore(before);ev=API.event(v,before,pattern,invalid=[(E,4)])
    ev.pop('return32');ev.pop('int_return_upper32_unspecified_fixture');v.set(0,pointer);ev['return_registers31'][0]=hex(pointer)
    ev['pointer_return64']=hex(pointer);ev['effect_kind']='container_allocation'
    ev['allocated_owner_premise']={'address':hex(pointer),'size_bytes':SIZE,'initial_bytes_defined':False} if pointer else None
    if pointer:
        assert all(not(a<pointer+SIZE and pointer<a+n) for a,n in v.foreign_owners);owner(v,pointer,SIZE)
    row=API.interval(v,before,ev);assert row['boundary']['pc']==hex(NEXT_MALLOC if pointer else NEXT_ERROR)
    return {'pointer_return64':hex(pointer),'API_return_premise':ev,'interval_packed':pack(row)}

def context(ci,qi,parent,item):
    start=unpack(item['interval_packed']);pattern=1-parent['ABI_clobber_pattern'];stat=int(start['boundary']['registers31'][1],16)
    assert start['boundary']['pc']==hex(LSTAT) and start['boundary']['registers31'][:2]==[hex(B+32),'0x680005ff18']
    stats=[];terminals=[]
    for status in STATUSES:
        c=API.returned(start,pattern,status,[(stat,144),(E,4)]);c['return32']=status;stats.append(c)
    modes=[]
    for j,mode in enumerate(MODES):
        c=API.supplied(unpack(stats[0]['interval_packed']),stat+4,mode.to_bytes(2,'little'),'mode16');c['mode16']=mode;modes.append(c)
        if mode&0xf000==0xa000:terminals.append(('mode',j,unpack(c['interval_packed'])))
    errors=[]
    for si in range(1,len(stats)):
        c=API.returned(unpack(stats[si]['interval_packed']),pattern,pointer=True);c['stat_case_index']=si;er=unpack(c['interval_packed']);words=[]
        for wi,error in enumerate(ERRNOS):
            w=API.supplied(er,E,error.to_bytes(4,'little'),'errno32');w['errno32']=error;words.append(w)
            terminals.append(('errno',len(errors)*len(ERRNOS)+wi,unpack(w['interval_packed'])))
        c['word_cases']=words;errors.append(c)
    unlinks=[]
    for ui,status in enumerate(STATUSES):
        c=API.returned(unpack(modes[1]['interval_packed']),pattern,status,[(E,4)]);c['return32']=status;unlinks.append(c)
        if status:terminals.append(('unlink',ui,unpack(c['interval_packed'])))
    sync=[]
    for si,status in enumerate([0,35]):
        before=unpack(unlinks[0]['interval_packed']);items=[]
        for j,pc in enumerate([ONCE,WRLOCK,ONCE2,UNLOCK]):
            assert before['boundary']['pc']==hex(pc)
            invalid=[(API.ONCE_CELL,16)] if j%2==0 else [(L,200)]
            c=API.returned(before,pattern,status,invalid);c['API_return_premise'].update(effect_kind='sync',once_completion_without_additional_callback_effects_premise=j%2==0)
            items.append(c);before=unpack(c['interval_packed'])
        sync.append({'synchronization_return32':status,'returns':items});terminals.append(('sync',si,before))
    frees=[]
    for kind,j,before in terminals:
        c=retire(before,pattern);c.update(origin_kind=kind,origin_index=j);frees.append(c)
    allocations=[allocate(unpack(frees[0]['interval_packed']),pattern,pointer) for pointer in [0,S]]
    return {'parent_context_index':ci,'parent_SIDN_query_index':qi,'parent_origin_kind':item['origin_kind'],
            'parent_origin_index':item['origin_index'],'ABI_clobber_pattern':pattern,'stat_cases':stats,'mode_cases':modes,
            'error_accessors':errors,'unlink_cases':unlinks,'synchronization_cases':sync,'buffer_frees':frees,'allocation_cases':allocations}

def items(c):
    yield from c['stat_cases'];yield from c['mode_cases']
    for a in c['error_accessors']:
        yield a;yield from a['word_cases']
    yield from c['unlink_cases']
    for s in c['synchronization_cases']:yield from s['returns']
    yield from c['buffer_frees'];yield from c['allocation_cases']

def context_intervals(c):
    for item in items(c):yield unpack(item['interval_packed'])

def intervals(e):
    for c in e['contexts']:yield from context_intervals(c)

def source():
    specs=[('SIDN_caller_return',0x100863fa8,0x100863fb8),('buffer_free_request',0x10074aa04,FREE+4),
           ('post_free_status',0x100689dfc,0x100689e10),('allocator_return',MALLOC+4,0x1007107a4),
           ('initializer',0x100413164,0x100413254),('post_initializer',0x1006c23a4,0x1006c23cc),
           ('nonnull_fields_and_copy',0x100595edc,0x100596018),('retained_copy_helper',0x10046f89c,0x10046fa90),
           ('null_publication',0x100901494,0x10090149c),('null_metadata_call',0x1006965a4,0x1006965b8),
           ('next_allocator',0x1009342e0,NEXT_MALLOC+4)]
    return [{'name':n,'start':hex(a),'end':hex(b),'bytes_hex':IMAGE.read(a,b-a).hex(),
             'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(IMAGE.read(a,b-a),a)]} for n,a,b in specs]

def sdk_checks():
    sdk=Path(subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip());source=(ROOT/'daemon_state_container_construction_abi.c').read_text()
    cmd=['xcrun','clang','-target','arm64e-apple-macos13.0','-isysroot',str(sdk),'-std=c11','-S','-O1','-x','c','-','-o','-']
    p=subprocess.run(cmd,input=source,text=True,capture_output=True,timeout=30);assert p.returncode==0 and not p.stderr,p.stderr
    portable=cmd.copy();portable[portable.index('-isysroot')+1]='<SDK>'
    headers=['usr/include/stdlib.h','usr/include/sys/stat.h','usr/include/sys/errno.h','usr/include/pthread/pthread.h']
    return {'command':portable,'source':source,'assembly':p.stdout,'exit_code':0,'headers':[{'SDK_relative_header':h,'sha256':sha(sdk/h)} for h in headers],
            'scope':'Current compile-only arm64e ABI; historical native runtime equivalence unknown.','native_API_executed':False}

def build():
    p=json.loads(read(ROOT/(Parent.P+'_checks.json')));contexts=[];counts=Counter();used=set();number=0
    for ci,parent in enumerate(p['contexts']):
        for qi,item in enumerate(parent['SIDN_queries']):
            c=context(ci,qi,parent,item);contexts.append(c)
            for row in context_intervals(c):
                number+=1;counts.update(rc(row));used.update(int(x['address'],16) for x in row['source_reads'] if int(x['address'],16) in FIXUPS)
            if qi%6==0:print(json.dumps({'context':ci,'query':qi,'intervals':number,**counts}),flush=True)
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n) for n in DEPS},
            'contexts':contexts,'source_regions':source(),'source_fixups':API.Parent.fixups(used),'SDK_checks':sdk_checks(),
            'verified_counts':{'incoming_SIDN_queries':76,'continued_parents':76,'stat_cases':304,'mode_cases':152,
                               'errno_accessor_cases':228,'errno_word_cases':456,'unlink_cases':304,'synchronization_sequences':152,
                               'buffer_free_returns':912,'allocation_cases':152,'intervals':number,**counts},
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'native_epoch_join_established':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
