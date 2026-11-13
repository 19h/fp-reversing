#!/usr/bin/env python3
"""Conditional SIDB metadata admission, synchronization and open interface.

Sixteen frozen parents cross two new ABI patterns. Three lstat returns,
six mode controls and two opaque errno accessors with four value controls
per accessor retain distinct definedness cuts. Regular-mode continuations
cross optional original once callback invocation and status0/35 perturbations.
SDK extents, callback stack gap and imported effects are explicit premises.
No native target API/IPC, filesystem operation, allocation/free, hardware PAC
or IDB mutation executes. O(parent bytes+visits+effects+SDK source) time/storage.
"""
import json,subprocess
from pathlib import Path
from collections import Counter
from unicorn import arm64_const as ar
import probe_daemon_descriptor_producers as Base
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha
from recover_daemon_context_lock_use import imported_return
import recover_daemon_state_path_family as Parent

P='daemon_state_file_admission';LSTAT=Parent.LSTAT;MODE=0x10061734c
ERRNO=0x1006222d0;ERR_READ=ERRNO+4;ONCE=0x10041a59c;RDLOCK=0x10008a9f4
ONCE2=0x1004292c8;UNLOCK=0x100082454;OPEN_ERRNO=0x100d8fefc;OPEN=0x100d8ff74
MALLOC=0x100710758;CALLBACK=0x10040ebd4;TOKEN=0x680000e000;ONCE_CELL=0x1010b8cd0
B=Parent.Parent.B;L=Parent.Parent.L;E=Parent.E;J=Parent.J
STAT=0x680005fed8;SN=144
MODES=[0,0x81a4,0x41ed,0xa000,0xa1ff,0xffff];ERRNOS=[0,2,13,0xffffffff]
pack=Parent.pack;unpack=Parent.unpack;rc=Parent.rc;restore=Parent.restore;compact=Parent.compact
DEPS=['daemon_receive_tools.py','daemon_receive_fixups.txt','probe_daemon_descriptor_producers.py',
      'recover_daemon_state_path_family.py','audit_daemon_state_path_family.py',
      'daemon_state_path_family_checks.json','daemon_state_path_family_audit.json',
      'recover_daemon_context_lock_use.py','recover_daemon_environment_outputs.py',
      'recover_daemon_network_gate.py','audit_daemon_readiness_arena.py','audit_daemon_network_record.py',
      'recover_daemon_return_bank_origins.py','lskd_values_symbolic.py','daemon_state_file_admission_abi.c']

def forget(v,a,n):
    Parent.forget(v,a,n)
    if Base.P<=a<a+n<=Base.P+Base.SIZE:v.known[a-Base.P:a-Base.P+n]=bytes(n)
    rebuilt=[]
    for f in v.initial:
        lo=int(f['address'],16);raw=bytes.fromhex(f['bytes_hex']);hi=lo+len(raw)
        for start,end in [(lo,min(hi,a)),(max(lo,a+n),hi)]:
            if start<end:rebuilt.append({**f,'address':hex(start),'bytes_hex':raw[start-lo:end-lo].hex()})
    v.initial=rebuilt

def event(v,before,pattern,status=0,invalid=(),pointer=False):
    e=imported_return(v,before,status,pattern)
    if pointer:
        v.set(0,E);e['return_registers31'][0]=hex(E);e.pop('return32');e.pop('int_return_upper32_unspecified_fixture')
        e['pointer_return64']=hex(E);e['existing_borrowed_owner_premise']={'address':hex(E),'size_bytes':4}
    e['invalidated_spans']=[{'address':hex(a),'size_bytes':n} for a,n in invalid]
    for a,n in invalid:forget(v,a,n)
    return e

def interval(v,before,ev=None,role='original_source_continuation'):
    compact(v);v.cut_stops=set();return v.interval(int(before['boundary']['pc'],16)+(4 if ev else 0),role)

def returned(before,pattern,status=0,invalid=(),pointer=False):
    v=restore(before);e=event(v,before,pattern,status,invalid,pointer);row=interval(v,before,e)
    return {'API_return_premise':e,'interval_packed':pack(row)}

def supplied(before,address,raw,kind):
    v=restore(before)
    if Base.P<=address<address+len(raw)<=Base.P+Base.SIZE:v.fixture(address,raw)
    else:v.foreign_fixture(address,raw,'explicit_'+kind+'_output_word_not_native_observation')
    row=interval(v,before,role='original_source_after_'+kind+'_word')
    return {'output_premise':{'address':hex(address),'bytes_hex':raw.hex(),'size_bytes':len(raw),'kind':kind},'interval_packed':pack(row)}

def open_case(mode_case,pattern,invoke,status):
    before=unpack(mode_case['interval_packed']);assert before['boundary']['pc']==hex(ONCE)
    v=restore(before);cb=None;premise=None;rows=[];events=[]
    if invoke:
        sp=int(before['boundary']['SP'],16);v.u.reg_write(ar.UC_ARM64_REG_SP,sp-256);v.set(30,TOKEN);v.cut_stops={TOKEN}
        cb=v.interval(CALLBACK,'separate_original_once_callback_invocation')
        assert cb['boundary']['pc']==hex(TOKEN) and cb['boundary']['SP']==hex(sp-256)
        v.u.reg_write(ar.UC_ARM64_REG_SP,sp)
        premise={'callback':hex(CALLBACK),'SP_gap_bytes':256,'return_token':hex(TOKEN),'native_pthread_stack_layout_claimed':False}
    for pc,symbol,invalid,pointer in [
        (ONCE,'libSystem/_pthread_once',[(ONCE_CELL,16)],False),
        (RDLOCK,'libSystem/_pthread_rwlock_rdlock',[(L,200)],False),
        (ONCE2,'libSystem/_pthread_once',[(ONCE_CELL,16)],False),
        (UNLOCK,'libSystem/_pthread_rwlock_unlock',[(L,200)],False),
        (OPEN_ERRNO,'libSystem/___error',[],True)]:
        assert before['boundary']['pc']==hex(pc) and before['boundary']['detail']['symbol']==symbol
        ev=event(v,before,pattern,status,invalid,pointer);row=interval(v,before,ev)
        rows.append(pack(row));events.append(ev);before=row
    assert before['boundary']['pc']==hex(OPEN) and before['boundary']['registers31'][:2]==[hex(B+32),'0x110']
    return {'invoke_callback':invoke,'synchronization_return32':status,'callback_invocation_premise':premise,
            'callback_interval_packed':pack(cb) if cb else None,'API_return_premises':events,'intervals_packed':rows}

def context(index,parent,pattern):
    before=unpack(parent['intervals_packed'][-1]);assert before['boundary']['pc']==hex(LSTAT)
    stats=[]
    for status in [0,0xffffffff,1]:
        c=returned(before,pattern,status,[(STAT,SN),(E,4)]);c['return32']=status;stats.append(c)
    mode_parent=unpack(stats[0]['interval_packed']);assert mode_parent['boundary']['pc']==hex(MODE)
    modes=[]
    for mode in MODES:
        c=supplied(mode_parent,STAT+4,mode.to_bytes(2,'little'),'mode16');c['mode16']=mode;modes.append(c)
    errors=[]
    for si in [1,2]:
        q=unpack(stats[si]['interval_packed']);assert q['boundary']['pc']==hex(ERRNO)
        c=returned(q,pattern,pointer=True);c['stat_case_index']=si;er=unpack(c['interval_packed']);assert er['boundary']['pc']==hex(ERR_READ)
        words=[]
        for error in ERRNOS:
            w=supplied(er,E,error.to_bytes(4,'little'),'errno32');w['errno32']=error;words.append(w)
        c['word_cases']=words;errors.append(c)
    opens=[open_case(modes[1],pattern,invoke,status) for invoke in [False,True] for status in [0,35]]
    return {'parent_case_index':index,'ABI_clobber_pattern':pattern,'stat_cases':stats,'mode_cases':modes,'error_accessors':errors,'open_cases':opens}

def context_intervals(c):
    for row in c['stat_cases']+c['mode_cases']:yield unpack(row['interval_packed'])
    for a in c['error_accessors']:
        yield unpack(a['interval_packed'])
        for w in a['word_cases']:yield unpack(w['interval_packed'])
    for op in c['open_cases']:
        if op['callback_interval_packed']:yield unpack(op['callback_interval_packed'])
        for p in op['intervals_packed']:yield unpack(p)

def intervals(e):
    for c in e['contexts']:yield from context_intervals(c)

def source():
    specs=[('lstat_result',LSTAT+4,0x10063c390),('mode_gate',0x100617314,0x100617384),
           ('errno_gate',0x100622244,0x100622310),('caller_status',0x10042f4bc,0x10042f4ec),
           ('mode_lock_record',0x1004cffc0,0x1004d00a8),('read_lock_return',0x10008a9f8,0x10008aa14),
           ('preopen_field',0x1005141e0,0x100514224),('open_request',OPEN_ERRNO,OPEN+4),
           ('wrapper_allocation',0x100710740,0x100710794),('once_callback',CALLBACK,0x10040ee54)]
    return [{'name':name,'start':hex(a),'end':hex(b),'bytes_hex':IMAGE.read(a,b-a).hex(),
             'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(IMAGE.read(a,b-a),a)]} for name,a,b in specs]

def sdk_checks():
    sdk=Path(subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip())
    source=(ROOT/'daemon_state_file_admission_abi.c').read_text()
    cmd=['xcrun','clang','-target','arm64e-apple-macos13.0','-isysroot',str(sdk),'-std=c11','-S','-O1','-x','c','-','-o','-']
    p=subprocess.run(cmd,input=source,text=True,capture_output=True,timeout=30);assert p.returncode==0 and not p.stderr
    portable=cmd.copy();portable[portable.index('-isysroot')+1]='<SDK>'
    headers=['usr/include/sys/stat.h','usr/include/sys/fcntl.h','usr/include/sys/errno.h','usr/include/pthread/pthread.h']
    return {'command':portable,'source':source,'assembly':p.stdout,'exit_code':0,
            'headers':[{'SDK_relative_header':h,'sha256':sha(sdk/h)} for h in headers],
            'scope':'Current compile-only arm64e ABI; target runtime/library equivalence remains unknown.','native_API_executed':False}

def build():
    p=json.loads(read(ROOT/(Parent.P+'_checks.json')));contexts=[];counts=Counter();used=set()
    for j,parent in enumerate(p['cases']):
        for pattern in [0,1]:
            c=context(j,parent,pattern);contexts.append(c);cc=Counter()
            for row in context_intervals(c):cc.update(rc(row))
            print(json.dumps({'parent':j,'pattern':pattern,**cc}),flush=True)
    e={'contexts':contexts};number=0
    for row in intervals(e):
        number+=1;counts.update(rc(row));used.update(int(x['address'],16) for x in row['source_reads'] if int(x['address'],16) in FIXUPS)
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n) for n in DEPS},
            **e,'source_regions':source(),'source_fixups':Parent.fixups(used),'SDK_checks':sdk_checks(),
            'verified_counts':{'contexts':len(contexts),'stat_cases':96,'mode_cases':192,'errno_accessor_cases':64,'errno_word_cases':256,'open_cases':128,'callback_cases':64,'intervals':number,**counts},
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'native_epoch_join_established':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
