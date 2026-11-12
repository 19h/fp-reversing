#!/usr/bin/env python3
"""Independent cold-prefix RAM reconstruction, sparse replay and lock/reset oracle.

Does not import the new producer. Original bytes, full CPU, every data/API/PAC
and point effect are checked; live-IDB snapshots are byte corroboration only.
O(C*(B+F+V+J+R)) time/space; 12000-visit and separate SMT/compiler bounds.
No native target/API/IPC, IDB mutation or compiler output artifact.
"""
import json,copy,subprocess
from pathlib import Path
from hashlib import sha256
from collections import Counter
import z3
import unicorn as U
from unicorn import arm64_const as A
from audit_fpsd1201_predicates import Replay as Frozen,frame,restore,unpack,CS
from corefp_fixups_reader import Pointers,ROOT,THIN_SHA
from probe_corefp_exports import BASE,BIND
from verify_daemon_reader_record_payloads_publication import read
SHA=lambda b:sha256(b).hexdigest();M64=(1<<64)-1
STACK=0x62000000;SP=STACK+0x18000;REC=0x63000100;OUT=0x63000300;HEAP=0x64000000;DONE=0x65000000
PRIMARY=0x1d44448;SECONDARY=0x1d37838;LOCKS=[0x1d444a8,0x1d47fb8]


def declared_inputs():
    p=REC&0xffffffff;k=(((((p|0x20d7d4ce)-p+(p&0xdf282b31))&0xffffffff)^0xab997307)*0x0bcb7857)&0xffffffff
    b=bytearray(b'\xa5'*32);b[8:16]=OUT.to_bytes(8,'little');b[16:24]=(OUT+4).to_bytes(8,'little');b[24]=(k+9)&255;b[28:32]=((k+0xba27)&0xffffffff).to_bytes(4,'little')
    return [(REC,bytes(b)),(OUT,b'\xa5'*8),(BASE+PRIMARY,(0x5017).to_bytes(4,'little')),(BASE+SECONDARY,(0x5034).to_bytes(4,'little')),
      (BASE+SECONDARY+0x158,bytes.fromhex('4433221188776655ccbbaa990a000000')),(BIND+86*16,(0x1b57).to_bytes(4,'little'))]


def initial_page(s,a):
    raw=None
    for seg in s.meta['segments']:
        if BASE+seg['address']<=a<a+4096<=BASE+seg['address']+((seg['vm_size']+4095)&~4095):
            raw=bytearray(4096);off=a-BASE-seg['address'];n=max(0,min(4096,seg['file_size']-off));raw[:n]=s.data[seg['file_offset']+off:seg['file_offset']+off+n];break
    if raw is None:
        if STACK<=a<a+4096<=STACK+0x20000:raw=bytearray(b'\xa5'*4096)
        else:assert a in [REC&~4095,HEAP,BIND,BIND+4096];raw=bytearray(4096)
    for addr,row in s.decoded.items():
        addr+=BASE
        if a<=addr<addr+8<=a+4096:
            v=BIND+row['import']['ordinal']*16+row['pointer_addend']if row['bind']else BASE+int(row['target'],16);raw[addr-a:addr-a+8]=v.to_bytes(8,'little')
    for addr,b in declared_inputs():
        if a<=addr<addr+len(b)<=a+4096:raw[addr-a:addr-a+len(b)]=b
    return bytes(raw)


def ret(f,value,clobber,lr=None):
    f=copy.deepcopy(f)
    if lr is not None:f['X31'][30]=hex(lr)
    if clobber:
        for j in range(1,18):f['X31'][j]=hex(j*0x13579bdf2468ace&M64)
        f['NZCV']='0xa0000000'
    f['X31'][0]=hex(value);f['PC']=f['X31'][30];return f


class Replay(Frozen):
    def __init__(self,p,spans,s):
        super().__init__(p,spans);self.s=s;self.mi=self.pi=self.allocs=0;self.once=[];self.records=[];self.once_done=set()
        for page in [DONE,BIND]:
            if not any(lo<=page<=hi for lo,hi,_ in self.u.mem_regions()):self.u.mem_map(page,4096)
        self.imports={BIND+r['ordinal']*16:r['name']for r in s.imports}
    def snapshot(self,label):
        return {'label':label,'CPU':frame(self.u),'locks_u64':[hex(int.from_bytes(self.ram(BASE+a,8),'little'))for a in LOCKS],
          'primary_u32':int.from_bytes(self.ram(BASE+PRIMARY,4),'little'),'secondary_u32':int.from_bytes(self.ram(BASE+SECONDARY,4),'little'),
          'metadata20_hex':self.ram(BASE+SECONDARY+0x158,20).hex(),'reset_word_u32':int.from_bytes(self.ram(BASE+SECONDARY+0x38,4),'little')}
    def point(self,row):assert row==self.p['points'][self.pi];self.pi+=1
    def event(self):
        e=self.p['models'][self.mi];self.mi+=1;assert e['before']==frame(self.u);return e
    def effects(self,e,writes):
        want=[]
        for a,b in writes:want.append({'address':hex(a),'before_hex':self.ram(a,len(b)).hex(),'after_hex':b.hex()});self.u.mem_write(a,b)
        assert e['memory']==want
    def code(self,u,pc,n,d):
        self.flush();cfg=self.p['configuration']
        if pc==DONE+0x100:
            control,lr,callback=self.once.pop();assert control not in self.once_done;self.once_done.add(control);e=self.event()
            assert e['kind']=='declared_once_return'and e['control']==hex(control)and e['callback']==hex(callback);self.effects(e,[])
            self.point(self.snapshot('once_callback_return_'+hex(callback-BASE)));f=ret(e['before'],0,cfg.get('clobber_callers',False),lr);assert e['after']==f;restore(u,f);return
        if pc in self.imports:
            name=self.imports[pc];args=[u.reg_read(getattr(A,'UC_ARM64_REG_X'+str(j)))for j in range(8)];call=hex(u.reg_read(A.UC_ARM64_REG_LR)-4-BASE)
            if name=='_bootstrap_look_up'or name=='_pthread_rwlock_wrlock'and not cfg.get('continue_to_bootstrap'):
                assert self.p['frontier']=={'reason':'before_'+name,'CPU':frame(u),'args_x0_x7':[hex(v)for v in args],'callsite':call};self.done=True;u.emu_stop();return
            e=self.event();assert e['name']==name and e['callsite']==call and e['args_x0_x7']==[hex(v)for v in args];writes=[]
            if name=='_pthread_once':
                assert e['kind']=='declared_once_enter'and args[0]not in self.once_done
                assert (args[0],args[1])in [(BASE+0x1d34f90,BASE+0x4a21e0),(BASE+0x1d37f50,BASE+0x59e868)]
                self.once.append((args[0],u.reg_read(A.UC_ARM64_REG_LR),args[1]));f=copy.deepcopy(e['before']);f['X31'][30]=hex(DONE+0x100);f['PC']=hex(args[1]);self.effects(e,[]);assert e['after']==f;restore(u,f);return
            assert e['kind']=='declared_API'
            if name=='_malloc':
                assert args[0]==200 and self.allocs<2;j=self.allocs;self.allocs+=1;value=HEAP+j*0x100 if cfg['allocation_success'][j]else 0
                if value:writes=[(value,b'\xa5'*200)]
            elif name=='_pthread_rwlock_init':
                j=(args[0]-HEAP)//0x100;assert j in [0,1]and args[:2]==[HEAP+j*0x100,0]and cfg['allocation_success'][j];value=cfg['lock_init_status_u32'][j]
            elif name=='_pthread_rwlock_wrlock':assert args[0]==(HEAP if cfg['allocation_success'][0]and cfg['lock_init_status_u32'][0]==0 else BASE+0x1d27bf0);value=0
            elif name=='___chkstk_darwin':
                assert u.reg_read(A.UC_ARM64_REG_X9)<0x17000;f=copy.deepcopy(e['before']);f['PC']=f['X31'][30];self.effects(e,[]);assert e['after']==f;restore(u,f);return
            else:raise AssertionError(name)
            self.effects(e,writes);assert e['return_u64']==hex(value);f=ret(e['before'],value,cfg.get('clobber_callers',False));assert e['after']==f;restore(u,f);return
        at=pc-BASE;raw=self.ram(pc,4);i=next(CS.disasm(raw,at));assert self.p['visits'][self.v]=={'pc':hex(at),'bytes_hex':raw.hex(),'instruction':i.mnemonic+' '+i.op_str};self.v+=1
        if at==0x59e33c:
            r=u.reg_read(A.UC_ARM64_REG_X0);self.records.append(r);self.point({'label':'constructor_entry','CPU':frame(u),'record16_hex':self.ram(r,16).hex()})
        if at in [0x4a2438,0x4a2504]:
            r=self.records[-1];self.point({'label':'constructor_return','CPU':frame(u),'record':hex(r),'record16_hex':self.ram(r,16).hex()})
        if i.mnemonic in ['braa','blraa']:
            e=self.p['PAC_models'][self.pac];self.pac+=1;rn,mn=i.op_str.split(', ');target=u.reg_read(getattr(A,'UC_ARM64_REG_'+rn.upper()));modifier=u.reg_read(getattr(A,'UC_ARM64_REG_'+mn.upper()))
            load=next(j for j in range(self.r-1,-1,-1)if self.p['reads'][j]['size_B']==8 and int.from_bytes(bytes.fromhex(self.p['reads'][j]['bytes_hex']),'little')==target)
            slot=int(self.p['reads'][load]['address'],16)-BASE;row=self.s.decoded[slot]
            assert e=={'visit':self.v-1,'pc':hex(at),'target':hex(target),'modifier':hex(modifier),'load_index':load,'pointer_row':row,'CPU':frame(u)}
            assert row['authenticated']and row['key']=='IA'and modifier==(BASE+slot if row['address_diversity']else int(row['diversity'],16))
            want=BIND+row['import']['ordinal']*16+row['pointer_addend']if row['bind']else BASE+int(row['target'],16);assert want==target and self.ram(BASE+slot,8)==target.to_bytes(8,'little')
            if i.mnemonic=='blraa':u.reg_write(A.UC_ARM64_REG_LR,pc+4)
            u.reg_write(A.UC_ARM64_REG_PC,target)
        elif i.mnemonic.startswith(('pac','aut')):u.reg_write(A.UC_ARM64_REG_PC,pc+4)
        elif i.mnemonic=='retab':u.reg_write(A.UC_ARM64_REG_PC,u.reg_read(A.UC_ARM64_REG_LR))
    def run(self):
        self.u.emu_start(BASE+0x1cdb24,0,count=12001);self.flush();assert self.done and not self.once
        assert [self.v,self.r,self.w,self.pac,self.mi,self.pi]==[len(self.p[k])for k in ['visits','reads','writes','PAC_models','models','points']]
        for row in self.p['final_RAM']:assert self.ram(int(row['address'],16),4096)==unpack(row['payload'])
        assert self.snapshot('frontier')==self.p['final_state']and self.allocs==self.p['allocations_attempted']==2
        return {'visits_checked':self.v,'reads_checked':self.r,'writes_checked':self.w,'PAC_models_checked':self.pac,'models_checked':self.mi,'points_checked':self.pi,'final_RAM_B_checked':4096*len(self.p['final_RAM'])}


def oracle(p,replay):
    c=p['configuration'];locks=[];statuses=[];calls=['declared_once_enter']
    for j in range(2):
        allocated=c['allocation_success'][j];status=c['lock_init_status_u32'][j];calls+=['_malloc']
        if allocated:
            calls+=['_pthread_rwlock_init'];assert replay.ram(HEAP+j*256,200)==b'\0'*8+b'\xa5'*192
        locks.append(hex(HEAP+j*256)if allocated and status==0 else '0x0')
        statuses.append(0x45e2a20f if not allocated or status==12 else 0xba1df9db if status==0 else 0x45e2a208 if status==16 else 0x45e2a209)
    calls+=['declared_once_return','declared_once_enter','declared_once_return']
    if c.get('continue_to_bootstrap'):calls+=['_pthread_rwlock_wrlock']
    actual=[e['name']if e['kind']=='declared_API'else e['kind']for e in p['models']];assert actual==calls
    for snap in [p['final_state']]+[v for v in p['points']if v['label'].startswith('once_callback_return')]:
        assert snap['locks_u64']==locks and snap['primary_u32']==snap['secondary_u32']==0 and snap['metadata20_hex']=='00'*20 and snap['reset_word_u32']==0x59fece35
    entries=[v for v in p['points']if v['label']=='constructor_entry'];returns=[v for v in p['points']if v['label']=='constructor_return'];assert len(entries)==len(returns)==2
    records=[]
    for j,(before,after)in enumerate(zip(entries,returns)):
        r=int(before['CPU']['X31'][0],16)
        assert not any(int(v['address'],16)<r+12 and r+8<int(v['address'],16)+v['size_B']for v in p['reads'])
        b=bytes.fromhex(before['record16_hex']);out=bytes.fromhex(after['record16_hex']);low=r&0xffffffff
        key=((((low|0x3747a74c)+0xc8b858b3-(low|0xc8b858b3))&0xffffffff)^0x035a67fd)*0xdb676c6f&0xffffffff
        assert int.from_bytes(b[:8],'little')==BASE+LOCKS[j]and (int.from_bytes(b[12:],'little')+key)&0xffffffff==0xc1a5
        assert out==b[:8]+statuses[j].to_bytes(4,'little')+b[12:]
        records.append({'record':hex(r),'output_slot':hex(BASE+LOCKS[j]),'decoded_control_u32':'0xc1a5','raw_status_u32':hex(statuses[j])})
    frontier=p['frontier'];args=list(map(lambda v:int(v,16),frontier['args_x0_x7']))
    if c.get('continue_to_bootstrap'):
        assert frontier['reason']=='before__bootstrap_look_up'and frontier['callsite']=='0x1ce1bc'and args[0]==0x1b57 and args[2]==BASE+PRIMARY
        assert replay.ram(args[1],len(b'com.apple.fpsd\0'))==b'com.apple.fpsd\0'
    else:assert frontier['reason']=='before__pthread_rwlock_wrlock'and frontier['callsite']=='0x20f6cc'and args[0]==(int(locks[0],16)or BASE+0x1d27bf0)
    return {'label':c['label'],'locks_u64':locks,'constructor_records':records,'call_sequence':calls,'frontier':frontier['reason']}


def source_checks(s):
    exact={0x59e564:('mov','w0, #0xc8'),0x59e5d0:('strh','wzr, [x0]'),0x59e5d4:('strh','wzr, [x0, #2]'),
      0x59e5d8:('strh','wzr, [x0, #4]'),0x59e5dc:('strh','wzr, [x0, #6]'),0x59e634:('mov','x1, #0'),
      0x59e640:('cmp','w0, #0x10'),0x59e650:('cmp','w0, #0xc'),0x59e658:('cbnz','w0, #0x59e698'),
      0x59e668:('str','x20, [x9]'),0x59e5a8:('str','w8, [x19, #8]'),0x57aa3c:('str','wzr, [x25]'),
      0x57aa40:('str','wzr, [x24]'),0x57aa44:('stp','xzr, xzr, [x24, #0x158]'),0x57aa48:('str','wzr, [x24, #0x168]'),
      0x57aa4c:('mov','w8, #0xce35'),0x57aa50:('movk','w8, #0x59fe, lsl #16'),0x57aa54:('str','w8, [x24, #0x38]'),
      0x438d40:('ret','')}
    for a,want in exact.items():i=next(CS.disasm(s.read(a,4),a));assert (i.mnemonic,i.op_str)==want
    status=z3.BitVec('pthread_init_status32',32)
    # Original comparisons admit publication only on the zero arm; 12 and 16
    # bypass it, and the remaining nonzero arm has its own encoded result.
    published=z3.And(status!=16,status!=12,status==0)
    x=z3.BitVec('record_low32',32);a=z3.BitVecVal(0x3747a74c,32);b=z3.BitVecVal(0xc8b858b3,32)
    claims=[('publication_zero_only',published,status==0),
      ('constructor_address_key',(((x|a)+b-(x|b))^0x035a67fd)*0xdb676c6f,((a+(x&~a)-(x&~b))^0x035a67fd)*0xdb676c6f)]
    proof=[]
    for label,left,right in claims:
        sol=z3.Solver();sol.set(timeout=30000);sol.add(left!=right);assert sol.check()==z3.unsat;proof.append({'label':label,'query':sol.to_smt2(),'result':'unsat'})
    code='#include <pthread.h>\n#include <stdalign.h>\n_Static_assert(sizeof(pthread_rwlock_t)==200,"rwlock200");\n_Static_assert(alignof(pthread_rwlock_t)==8,"rwlock_align8");\n_Static_assert(_PTHREAD_RWLOCK_SIG_init==0x2da8b3b4,"static_lock_signature");\n_Static_assert(__builtin_types_compatible_p(__typeof__(&pthread_rwlock_init),int(*)(pthread_rwlock_t*,const pthread_rwlockattr_t*)),"rwlock_init_proto");\n'
    cmd=['xcrun','clang','-target','arm64e-apple-macos14','-fsyntax-only','-x','c','-'];r=subprocess.run(cmd,input=code,text=True,capture_output=True,timeout=30);assert r.returncode==0,r.stderr
    sdk=Path(subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip());headers=[]
    for name in ['usr/include/pthread.h','usr/include/sys/_pthread/_pthread_types.h']:
        raw=(sdk/name).read_bytes()
        if name=='usr/include/pthread.h':assert b'#define PTHREAD_RWLOCK_INITIALIZER {_PTHREAD_RWLOCK_SIG_init, {0}}'in raw
        headers.append({'SDK_relative_header':name,'size_B':len(raw),'sha256':SHA(raw)})
    fallback=s.read(0x1d27bf0,200)
    return {'fallback_lock':{'address':'0x1d27bf0','size_B':200,'bytes_hex':fallback.hex(),'sha256':SHA(fallback)},'exact_instructions_checked':len(exact),'proofs':proof,'ABI_compile':{'command':cmd,'source':code,'source_sha256':SHA(code.encode()),'exit_code':r.returncode,'stderr':r.stderr,'emitted_artifact':False,'headers':headers}}


def live_checks(e,s):
    d=json.loads(read(ROOT/'corefp_lookup_initialization_ida.json'));assert d['target']=='c3d025e56a86'and not d['IDB_mutated']and not d['native_target_executed']
    assert d['requests']['network_recall']['query']=='IOMACAddress'and d['requests']['initialization_recall']['query']=='initialization'
    assert d['requests']['xrefs']['max_results']==1000 and d['requests']['xrefs']['direction']=='to'
    checked=[]
    for group in ['network_bytes','initializer_bytes']:
        for row in d[group]['results']:
            raw=bytes.fromhex(row['bytes']);at=int(row['address'],16);assert raw==s.read(at,len(raw))and len(raw)==row['size_read']==row['size_requested']
            checked.append({'address':row['address'],'size_B':len(raw),'sha256':SHA(raw)})
    assert len(checked)==6 and sum(r['size_B']for r in checked)==4976
    xrefs={r['address']:r for r in d['xrefs']['results']};assert not xrefs['0x86c0']['xrefs_to']and not xrefs['0x1d0fe78']['xrefs_to']
    assert [(r['from'],r['type'])for r in xrefs['0x1d44409']['xrefs_to']]==[('0x1d0fe78','data')]
    assert all(len(r['xrefs_to'])<1000 for r in xrefs.values())
    assert [r['from']for r in xrefs['0x1d443c0']['xrefs_to']]==['0x86e8','0x86f0','0x8818','0x8820','0x8848']
    assert len(xrefs['0x1d443c8']['xrefs_to'])==3 and len(xrefs['0x8708']['xrefs_to'])==1
    assert not any(v.get('address')==0x86c0 for v in s.exports.values())
    assert not any(not v['bind']and int(v['target'],16)==0x86c0 for v in s.decoded.values())
    assert all(d[k]['count']==0 and not d[k]['truncated']for k in ['network_recall','initialization_recall'])
    return {'live_byte_ranges':checked,'live_B_checked':4976,'getter_xrefs_to':0,'getter_exported':False,'getter_exact_chained_pointer_targets':0,'selector_pointer_cell':'0x1d0fe78','knowledge_queries_with_zero_results':2,'semantic_annotations_used_as_proof':False}


def main():
    e=json.loads(read(ROOT/'corefp_lookup_initialization_checks.json'));assert e['generator_sha256']==SHA((ROOT/'recover_corefp_lookup_initialization.py').read_bytes())and e['thin_sha256']==THIN_SHA
    for n,h in e['dependencies'].items():assert SHA(read(ROOT/n).encode())==h
    s=Pointers();assert e['declared_inputs']==[{'address':hex(a),'bytes_hex':b.hex()}for a,b in declared_inputs()]
    for span in e['source_spans']:assert span==s.function(int(span['start'],16))
    totals=Counter();oracles=[];stores=set()
    for p in e['profiles']:
        cpu={'X31':[hex(((j+1)*0x123456789abcdef)&M64)for j in range(31)],'Q32':[hex(int.from_bytes(bytes([j])*16,'little'))for j in range(32)],
          'SP':hex(SP),'PC':hex(BASE+0x1cdb24),'NZCV':'0x60000000','FPCR':'0x0','FPSR':'0x0','CPACR_EL1':'0x300000'}
        cpu['X31'][0]=hex(REC);cpu['X31'][30]=hex(DONE);assert p['initial_CPU']==cpu;totals['initial_CPU_frames_checked']+=1
        for row in p['initial_RAM']:assert unpack(row['payload'])==initial_page(s,int(row['address'],16));totals['initial_RAM_B_checked']+=4096
        replay=Replay(p,e['source_spans'],s);totals.update(replay.run());oracles.append(oracle(p,replay))
        for w in p['writes']:
            a=int(w['address'],16)-BASE
            if 0x1c80000<=a<0x1d4c000:stores.add((p['visits'][w['visit']]['pc'],hex(a),w['size_B']))
    assert all(not(a<=0x1d44409<a+n or a<=0x1d32e18<a+n)for _,addr,n in stores for a in [int(addr,16)])
    counts={'profiles':len(e['profiles']),**{k:sum(len(p[k])for p in e['profiles'])for k in ['visits','reads','writes','PAC_models','models','points']}};assert counts==e['verified_counts']
    outer=lambda p:[v['pc']for v in p['visits']if 0x4a21e0<=int(v['pc'],16)<0x4a25d8]
    assert all(outer(p)==outer(e['profiles'][0])for p in e['profiles'])
    assert s.read(0x1d27bf0,200)==(0x2da8b3b4).to_bytes(8,'little')+b'\0'*192
    source=source_checks(s);live=live_checks(e,s);result={'verified_counts':counts,'independent_replay':dict(totals),'compact_oracle_profiles':len(oracles),'queries_unsat':len(source['proofs']),
      'exact_instructions_checked':source['exact_instructions_checked'],'source_B_checked':sum(len(bytes.fromhex(v['bytes']))for v in e['source_spans']),'live_B_checked':live['live_B_checked'],
      'ABI_compile_exit':0,'constructor_status_reads_checked':0,'outer_initializer_paths_identical':True,'native_target_executed':False,'all_checks_pass':True}
    out={'result':result,'checks_sha256':SHA(read(ROOT/'corefp_lookup_initialization_checks.json').encode()),'auditor_sha256':SHA(Path(__file__).read_bytes()),
      'IDA_readback_sha256':SHA(read(ROOT/'corefp_lookup_initialization_ida.json').encode()),'dependencies':e['dependencies'],'oracles':oracles,
      'source_checks':source,'live_checks':live,'original_global_store_sites':[{'pc':pc,'address':a,'size_B':n}for pc,a,n in sorted(stores)],'fresh_replay_completed':True,'process_exit_code':0}
    (ROOT/'corefp_lookup_initialization_audit.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(result),flush=True)


if __name__=='__main__':main()
