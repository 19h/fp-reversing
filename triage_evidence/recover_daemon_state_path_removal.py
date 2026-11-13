#!/usr/bin/env python3
"""Conditional SIDB pathname removal, object reset and SIDN query handoff.

Four retained parents cross two prior word routes and two prior ABI patterns.
Each receives the opposite new ABI pattern, four lstat controls, six mode
controls, three errno accessors with four words each, four unlink controls,
two synchronization-status sequences and nineteen SIDN errno-pointer returns.
All controls are premises, not recovered file content or native observations.
No native API/IPC/filesystem/allocation/free/PAC or IDB mutation executes.
O(parent bytes+retained visits+effects) time and retained storage.
"""
import json,subprocess
from pathlib import Path
from collections import Counter
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_daemon_state_word_routing as Parent
import recover_daemon_state_file_admission as API

P='daemon_state_path_removal';B=Parent.B;D=0x6600008000;E=Parent.E;A=Parent.A;N=Parent.N;J=Parent.J
L=B+0x1000;STAT=0x680005ff38;SN=144;MODE=0x1003795d4;ERRNO=0x1005797c4;UNLINK=0x100628150
LSTAT=Parent.LSTAT;ERROR=Parent.ERROR;ONCE=0x10043e508;WRLOCK=0x100361df4;ONCE2=0x100442650;UNLOCK=0x100208efc
STATUSES=[0,0xffffffff,1,0x80000000];MODES=API.MODES;ERRNOS=API.ERRNOS;PARENTS=[0,2,21,23]
pack=Parent.pack;unpack=Parent.unpack;rc=Parent.rc
DEPS=['daemon_receive_tools.py','daemon_receive_fixups.txt','probe_daemon_descriptor_producers.py',
      'recover_daemon_state_word_routing.py','daemon_state_word_routing_checks.json',
      'recover_daemon_state_file_admission.py','recover_daemon_state_file_input.py',
      'recover_daemon_context_lock_use.py','recover_daemon_state_path_family.py','daemon_state_path_removal_abi.c']

def context(index,parent):
    before=unpack(parent['errno_accessor']['interval_packed']);pattern=1-parent['ABI_clobber_pattern']
    assert before['boundary']['pc']==hex(LSTAT)
    stats=[]
    for status in STATUSES:
        c=API.returned(before,pattern,status,[(STAT,SN),(E,4)]);c['return32']=status;stats.append(c)
    modes=[];terminals=[]
    for j,mode in enumerate(MODES):
        c=API.supplied(unpack(stats[0]['interval_packed']),STAT+4,mode.to_bytes(2,'little'),'mode16');c['mode16']=mode;modes.append(c)
        if mode&0xf000==0xa000:terminals.append(('mode',j,unpack(c['interval_packed'])))
    errors=[]
    for si in range(1,len(stats)):
        c=API.returned(unpack(stats[si]['interval_packed']),pattern,pointer=True);c['stat_case_index']=si;er=unpack(c['interval_packed']);words=[]
        for wi,error in enumerate(ERRNOS):
            w=API.supplied(er,E,error.to_bytes(4,'little'),'errno32');w['errno32']=error;words.append(w)
            terminals.append(('errno',len(errors)*len(ERRNOS)+wi,unpack(w['interval_packed'])))
        c['word_cases']=words;errors.append(c)
    unlinks=[];before=unpack(modes[1]['interval_packed'])
    for ui,status in enumerate(STATUSES):
        c=API.returned(before,pattern,status,[(E,4)]);c['return32']=status;unlinks.append(c)
        if status:terminals.append(('unlink',ui,unpack(c['interval_packed'])))
    sync=[]
    for si,status in enumerate([0,35]):
        before=unpack(unlinks[0]['interval_packed']);items=[]
        for pc in [ONCE,WRLOCK,ONCE2,UNLOCK]:
            assert before['boundary']['pc']==hex(pc)
            c=Parent.Parent.returned(before,pattern,'sync',status);items.append(c);before=unpack(c['interval_packed'])
        sync.append({'synchronization_return32':status,'returns':items});terminals.append(('sync',si,before))
    queries=[]
    for kind,j,before in terminals:
        assert before['boundary']['pc']==hex(ERROR)
        c=API.returned(before,pattern,pointer=True);c.update(origin_kind=kind,origin_index=j)
        after=unpack(c['interval_packed']);assert after['boundary']['pc']==hex(LSTAT)
        assert after['boundary']['registers31'][:2]==[hex(D+32),'0x680005ff18'];queries.append(c)
    return {'parent_case_index':index,'prior_ABI_clobber_pattern':parent['ABI_clobber_pattern'],
            'raw_parent_word32':parent['raw_big_endian_word32'],'ABI_clobber_pattern':pattern,
            'stat_cases':stats,'mode_cases':modes,'error_accessors':errors,'unlink_cases':unlinks,
            'synchronization_cases':sync,'SIDN_queries':queries}

def items(c):
    yield from c['stat_cases'];yield from c['mode_cases']
    for a in c['error_accessors']:
        yield a;yield from a['word_cases']
    yield from c['unlink_cases']
    for s in c['synchronization_cases']:yield from s['returns']
    yield from c['SIDN_queries']

def context_intervals(c):
    for item in items(c):yield unpack(item['interval_packed'])

def intervals(e):
    for c in e['contexts']:yield from context_intervals(c)

def source():
    specs=[('lstat_result',LSTAT+4,0x1004cd1c0),('mode_gate',0x1003795c8,0x100379614),
           ('errno_result',ERRNO,0x1005797fc),('unlink_request',0x100628138,0x100628154),
           ('unlink_result',UNLINK+4,0x100628190),('reset_and_lock_records',0x1006289c8,0x100628ae8),
           ('adapter_status',0x1004af644,0x1004af64c),('caller_status',0x10041ac38,0x10041ac58),
           ('SIDN_record',0x100863f34,0x100863fa8),('next_errno_and_path',ERROR,0x1004cd12c),
           ('pending_query',0x1004cd188,LSTAT+4)]
    return [{'name':n,'start':hex(a),'end':hex(b),'bytes_hex':IMAGE.read(a,b-a).hex(),
             'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(IMAGE.read(a,b-a),a)]} for n,a,b in specs]

def sdk_checks():
    sdk=Path(subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip())
    source=(ROOT/'daemon_state_path_removal_abi.c').read_text()
    cmd=['xcrun','clang','-target','arm64e-apple-macos13.0','-isysroot',str(sdk),'-std=c11','-S','-O1','-x','c','-','-o','-']
    p=subprocess.run(cmd,input=source,text=True,capture_output=True,timeout=30);assert p.returncode==0 and not p.stderr,p.stderr
    portable=cmd.copy();portable[portable.index('-isysroot')+1]='<SDK>'
    headers=['usr/include/sys/stat.h','usr/include/sys/errno.h','usr/include/unistd.h','usr/include/pthread/pthread.h']
    return {'command':portable,'source':source,'assembly':p.stdout,'headers':[{'SDK_relative_header':h,'sha256':sha(sdk/h)} for h in headers],
            'exit_code':0,'scope':'Current compile-only arm64e ABI; historical target runtime equivalence unknown.','native_API_executed':False}

def build():
    p=json.loads(read(ROOT/(Parent.P+'_checks.json')));contexts=[];counts=Counter();used=set();number=0
    for index in PARENTS:
        c=context(index,p['cases'][index]);contexts.append(c)
        for row in context_intervals(c):
            number+=1;counts.update(rc(row));used.update(int(x['address'],16) for x in row['source_reads'] if int(x['address'],16) in FIXUPS)
        print(json.dumps({'parent_case_index':index,'intervals':number,**counts}),flush=True)
    return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),
            'dependencies':{n:sha(ROOT/n) for n in DEPS},'contexts':contexts,'source_regions':source(),'SDK_checks':sdk_checks(),
            'source_fixups':API.Parent.fixups(used),
            'coverage':'Four of1543 pending lstat parents. No trace equivalence or full-parent continuation claim.',
            'verified_counts':{'incoming_lstat_parents':1543,'continued_parents':4,'stat_cases':16,'mode_cases':24,
                               'errno_accessor_cases':12,'errno_word_cases':48,'unlink_cases':16,
                               'synchronization_sequences':8,'SIDN_queries':76,'intervals':number,**counts},
            'native_API_executed':False,'native_daemon_kext_pairing_established':False,'native_epoch_join_established':False,'full_goal_complete':False}

if __name__=='__main__':
    e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
