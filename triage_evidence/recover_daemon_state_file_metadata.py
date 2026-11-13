#!/usr/bin/env python3
"""Conditional SIDB descriptor, fstat size and failure-cleanup interfaces.

All128 frozen open parents cross two new ABI patterns. Five open controls;
the -1 branch crosses four errno controls, and descriptor7 crosses three
fstat returns, six size words and three close returns per nonzero fstat.
Outputs are invalidated before any scalar is supplied. No native target API,
filesystem, IPC, allocation/free, hardware PAC or IDB mutation executes.
O(parent bytes+source visits+effects+SDK source) time and retained storage.
"""
import json,subprocess
from pathlib import Path
from collections import Counter
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_daemon_state_file_admission as Parent

P='daemon_state_file_metadata';OPEN=Parent.OPEN;E=Parent.E;B=Parent.B;J=Parent.J
FSTAT=0x100c22ca8;ERROR=0x100d9e364;ERROR_READ=ERROR+4
STAT=0x680005feb8;SN=144;SIZE=STAT+96;SIZE_READ=0x100ce1d20
CLOSE=0x100ac8b2c;MALLOC=0x100ce1d3c;WRAPPER=Parent.MALLOC
RETURNS=[0xffffffff,0x80000000,0,7,0x7fffffff]
SIZES=[0,1,4096,0x100000000,0x8000000000000000,0xffffffffffffffff]
STATUSES=[0,0xffffffff,1];ERRNOS=[0,2,13,0xffffffff]
pack=Parent.pack;unpack=Parent.unpack;rc=Parent.rc;restore=Parent.restore
returned=Parent.returned;supplied=Parent.supplied
DEPS=['daemon_receive_tools.py','daemon_receive_fixups.txt','probe_daemon_descriptor_producers.py',
      'recover_daemon_state_file_admission.py','daemon_state_file_admission_checks.json',
      'recover_daemon_state_path_family.py','recover_daemon_context_lock_use.py',
      'daemon_state_file_metadata_abi.c']

def context(ci,oi,before,pattern):
    assert before['boundary']['pc']==hex(OPEN)
    opens=[]
    for status in RETURNS:
        q=returned(before,pattern,status,[(E,4)]);q['return32']=status;opens.append(q)
    negative=unpack(opens[0]['interval_packed']);assert negative['boundary']['pc']==hex(ERROR)
    error=returned(negative,pattern,pointer=True);unknown=unpack(error['interval_packed'])
    assert unknown['boundary']['pc']==hex(ERROR_READ)
    error['word_cases']=[]
    for errno in ERRNOS:
        q=supplied(unknown,E,errno.to_bytes(4,'little'),'open_errno32');q['errno32']=errno
        error['word_cases'].append(q)
    positive=unpack(opens[3]['interval_packed']);assert positive['boundary']['pc']==hex(FSTAT)
    stats=[]
    for status in STATUSES:
        q=returned(positive,pattern,status,[(STAT,SN),(E,4)]);q['return32']=status;stats.append(q)
    size_parent=unpack(stats[0]['interval_packed']);assert size_parent['boundary']['pc']==hex(SIZE_READ)
    sizes=[]
    for size in SIZES:
        q=supplied(size_parent,SIZE,size.to_bytes(8,'little'),'stat_size64');q['size64']=hex(size);sizes.append(q)
    closes=[]
    for i in [1,2]:
        close_parent=unpack(stats[i]['interval_packed']);assert close_parent['boundary']['pc']==hex(CLOSE)
        words=[]
        for status in STATUSES:
            q=returned(close_parent,pattern,status,[(E,4)]);q['return32']=status;words.append(q)
        closes.append({'fstat_case_index':i,'return_cases':words})
    return {'parent_context_index':ci,'parent_open_case_index':oi,'ABI_clobber_pattern':pattern,
            'open_cases':opens,'error_accessor':error,'fstat_cases':stats,'size_cases':sizes,'close_cases':closes}

def context_intervals(c):
    for q in c['open_cases']:yield unpack(q['interval_packed'])
    yield unpack(c['error_accessor']['interval_packed'])
    for q in c['error_accessor']['word_cases']+c['fstat_cases']+c['size_cases']:yield unpack(q['interval_packed'])
    for q in c['close_cases']:
        for w in q['return_cases']:yield unpack(w['interval_packed'])

def intervals(e):
    for c in e['contexts']:yield from context_intervals(c)

def source():
    specs=[('open_result',OPEN+4,0x100d8ffac),('fstat_arguments',0x100c22c9c,FSTAT+4),
           ('fstat_result',FSTAT+4,0x100c22cd0),('size_to_allocation',SIZE_READ,MALLOC+4),
           ('open_errno_mapping',ERROR_READ,0x100d9e390),('close_request_and_return',0x100ac8b24,0x100ac8b40),
           ('adapter_status_store',0x100ccedd4,0x100ccedd8),('caller_status_store',0x10043d338,0x10043d340),
           ('outer_status_store',0x100712c88,0x100712ca0)]
    return [{'name':n,'start':hex(a),'end':hex(b),'bytes_hex':IMAGE.read(a,b-a).hex(),
             'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(IMAGE.read(a,b-a),a)]} for n,a,b in specs]

def sdk_checks():
    sdk=Path(subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip())
    source=(ROOT/'daemon_state_file_metadata_abi.c').read_text()
    cmd=['xcrun','clang','-target','arm64e-apple-macos13.0','-isysroot',str(sdk),'-std=c11','-S','-O1','-x','c','-','-o','-']
    p=subprocess.run(cmd,input=source,text=True,capture_output=True,timeout=30);assert p.returncode==0 and not p.stderr,p.stderr
    portable=cmd.copy();portable[portable.index('-isysroot')+1]='<SDK>'
    headers=['usr/include/sys/stat.h','usr/include/sys/types.h','usr/include/unistd.h','usr/include/stdlib.h']
    return {'command':portable,'source':source,'assembly':p.stdout,'exit_code':0,
            'headers':[{'SDK_relative_header':h,'sha256':sha(sdk/h)} for h in headers],
            'scope':'Current compile-only arm64e ABI; historical native equivalence unknown.','native_API_executed':False}

def build():
    parent=json.loads(read(ROOT/(Parent.P+'_checks.json')));contexts=[];counts=Counter();used=set();number=0
    for ci,c in enumerate(parent['contexts']):
        for oi,op in enumerate(c['open_cases']):
            before=unpack(op['intervals_packed'][-1])
            for pattern in [0,1]:
                row=context(ci,oi,before,pattern);contexts.append(row)
        print(json.dumps({'parent_context':ci,'contexts':len(contexts)}),flush=True)
    for row in intervals({'contexts':contexts}):
        number+=1;counts.update(rc(row));used.update(int(x['address'],16) for x in row['source_reads'] if int(x['address'],16) in FIXUPS)
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),
            'dependencies':{n:sha(ROOT/n) for n in DEPS},'contexts':contexts,'source_regions':source(),
            'source_fixups':Parent.Parent.fixups(used),'SDK_checks':sdk_checks(),
            'verified_counts':{'contexts':256,'open_cases':1280,'errno_accessor_cases':256,'errno_word_cases':1024,
                               'fstat_cases':768,'size_cases':1536,'close_cases':1536,'intervals':number,**counts},
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'native_epoch_join_established':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
