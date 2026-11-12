#!/usr/bin/env python3
"""Independent sparse original-byte replay and registry/cache semantic oracle.

Does not import the new producer. Checks original-backed initial pages, every
CPU/data/API effect, same-instance returns and complete cache/status results.
Conservative time/space O(C*(B+F+V+J+R)); SMT/network/compiler separately bounded.
No native target/API/IPC, database mutation or emitted compiler artifact.
"""
import json,copy,struct,subprocess
from pathlib import Path
from hashlib import sha256
from collections import Counter
from urllib.request import urlopen
import z3
import unicorn as U
from unicorn import arm64_const as A
from audit_fpsd1201_predicates import Replay as Frozen,frame,restore,unpack,CS
from corefp_fixups_reader import Pointers,ROOT,THIN_SHA
from probe_corefp_exports import BASE,BIND
from verify_daemon_reader_record_payloads_publication import read
SHA=lambda b:sha256(b).hexdigest();STACK=0x62000000;SP=STACK+0x4000;OUT=0x63000100;DONE=0x65000000
CACHE=0x1d443c0;ONCE=0x1d443c8;STATUS=0x1d25200;M64=(1<<64)-1
MATCH=0x66000100;FILTER=0x66000200;TRUE=0x66000300;ITER=0x5101


def return_frame(f,v,clobber,lr=None):
    out=copy.deepcopy(f)
    if lr is not None:out['X31'][30]=hex(lr)
    if clobber:
        for j in range(1,18):out['X31'][j]=hex((j*0x13579bdf2468ace)&M64)
        out['NZCV']='0xa0000000'
    out['X31'][0]=hex(v);out['PC']=out['X31'][30];return out


def initial_page(s,p,a):
    b=None
    for seg in s.meta['segments']:
        if BASE+seg['address']<=a<a+4096<=BASE+seg['address']+((seg['vm_size']+4095)&~4095):
            b=bytearray(4096);off=a-BASE-seg['address'];n=max(0,min(4096,seg['file_size']-off))
            b[:n]=s.data[seg['file_offset']+off:seg['file_offset']+off+n];break
    if b is None:
        if STACK<=a<a+4096<=STACK+0x5000:b=bytearray(b'\xa5'*4096)
        else:assert a in [OUT&~4095,BIND];b=bytearray(4096)
    for addr,row in s.decoded.items():
        addr+=BASE
        if a<=addr<addr+8<=a+4096:
            v=BIND+row['import']['ordinal']*16+row['pointer_addend']if row['bind']else BASE+int(row['target'],16)
            b[addr-a:addr-a+8]=v.to_bytes(8,'little')
    for addr,raw in [(OUT,b'\xa5'*8),(BIND+177*16,TRUE.to_bytes(8,'little'))]+[(int(r['address'],16),bytes.fromhex(r['after_hex']))for r in p['controls']]:
        if a<=addr<addr+len(raw)<=a+4096:b[addr-a:addr-a+len(raw)]=raw
    return bytes(b)


class Replay(Frozen):
    def __init__(self,p,src,s):
        super().__init__(p,src['spans']);self.src=src;self.s=s;self.mi=self.ri=self.next_node=0;self.current=None;self.once_lr=None;self.data={}
        for page in [DONE,BIND]:
            if not any(lo<=page<=hi for lo,hi,_ in self.u.mem_regions()):self.u.mem_map(page,4096)
        self.imports={BIND+r['pointer']['import']['ordinal']*16:r['pointer']['import']['name']for r in src['stubs']}
    def effect(self,e,writes):
        want=[]
        for addr,b in writes:
            want.append({'address':hex(addr),'before_hex':self.ram(addr,len(b)).hex(),'after_hex':b.hex()});self.u.mem_write(addr,b)
        assert e['memory']==want
    def event(self):
        e=self.p['models'][self.mi];self.mi+=1;assert e['before']==frame(self.u);return e
    def code(self,u,pc,n,d):
        self.flush()
        if pc==DONE:
            assert self.p['getter_returns'][self.ri]=={'CPU':frame(u),'output8_hex':self.ram(OUT,8).hex()};self.ri+=1
            if self.ri==1 and 'repeat_capacity_u64'in self.p['configuration']:
                e=self.event();assert e['kind']=='declared_second_getter_call';self.effect(e,[]);f=copy.deepcopy(frame(u))
                f['X31'][0]=hex(OUT);f['X31'][1]=hex(self.p['configuration']['repeat_capacity_u64']);f['PC']=hex(BASE+0x86c0);assert e['after']==f;restore(u,f);return
            assert self.p['frontier']=={'reason':'complete_getter_return','CPU':frame(u)};self.done=True;u.emu_stop();return
        if pc==DONE+0x100:
            e=self.event();assert e['kind']=='declared_once_return';self.effect(e,[(BASE+ONCE,b'\xff'*8)])
            f=return_frame(e['before'],0,self.p['configuration'].get('clobber_callers',False),self.once_lr);assert e['after']==f;restore(u,f);return
        if pc in self.imports:
            name=self.imports[pc];e=self.event();cfg=self.p['configuration'];args=[u.reg_read(getattr(A,'UC_ARM64_REG_X'+str(j)))for j in range(8)]
            assert e['name']==name and e['args_x0_x7']==[hex(v)for v in args]and e['callsite']==hex(u.reg_read(A.UC_ARM64_REG_LR)-4-BASE)
            writes=[]
            if name=='_dispatch_once':
                assert cfg['cold']and self.once_lr is None and args[:2]==[BASE+ONCE,BASE+0x1c80028]and e['kind']=='declared_once_enter'
                self.once_lr=u.reg_read(A.UC_ARM64_REG_LR);assert e['callback_row']==self.s.decoded[0x1c80038]
                f=copy.deepcopy(frame(u));f['X31'][0]=hex(BASE+0x1c80028);f['X31'][30]=hex(DONE+0x100);f['PC']=hex(BASE+0x8754)
                self.effect(e,[]);assert e['after']==f;restore(u,f);return
            assert e['kind']=='declared_API'
            if name=='_IOServiceMatching':assert args[0]==BASE+0x1c79dc6;value=0 if cfg.get('matching_nil')else MATCH
            elif name=='_CFDictionaryCreateMutable':assert args[:4]==[0,0,BIND+180*16,BIND+181*16];value=0 if cfg.get('filter_nil')else FILTER
            elif name=='_CFDictionarySetValue':assert args[:3]in [[FILTER,BASE+0x1d1c1e8,TRUE],[MATCH,BASE+0x1d1c208,FILTER]];value=0
            elif name=='_CFRelease':assert args[0]in [FILTER]+list(self.data);value=0
            elif name=='_IOServiceGetMatchingServices':
                assert args[:2]==[0,MATCH];value=cfg.get('matching_status_u32',0)
                if value==0:writes=[(args[2],ITER.to_bytes(4,'little'))]
            elif name=='_IOIteratorNext':
                assert args[0]==ITER
                if self.next_node<len(cfg['nodes']):self.current=self.next_node;self.next_node+=1;value=0x5200+self.current
                else:value=0
            elif name=='_IORegistryEntryGetParentEntry':
                assert args[:2]==[0x5200+self.current,BASE+0x1c79dfd];value=cfg['nodes'][self.current]['parent_status_u32']
                if value==0:writes=[(args[2],(0x5300+self.current).to_bytes(4,'little'))]
            elif name=='_IORegistryEntryCreateCFProperty':
                assert args[:4]==[0x5300+self.current,BASE+0x1d1c228,0,0];raw=cfg['nodes'][self.current]['property_hex'];value=0 if raw is None else 0x66001000+self.current*16
                if value:self.data[value]=bytes.fromhex(raw)
            elif name=='_CFDataGetBytes':assert args[0]in self.data and args[1:4]==[0,6,BASE+CACHE];writes=[(args[3],self.data[args[0]][:6])];value=0
            elif name=='_IOObjectRelease':assert args[0]==0 or args[0]==ITER or 0x5200<=args[0]<0x5200+len(cfg['nodes'])or 0x5300<=args[0]<0x5300+len(cfg['nodes']);value=cfg.get('release_status_u32',0)
            else:raise AssertionError(name)
            self.effect(e,writes);assert e['return_u64']==hex(value);f=return_frame(e['before'],value,cfg.get('clobber_callers',False));assert e['after']==f;restore(u,f);return
        at=pc-BASE;raw=self.ram(pc,4);i=next(CS.disasm(raw,at));assert self.p['visits'][self.v]=={'pc':hex(at),'bytes_hex':raw.hex(),'instruction':i.mnemonic+' '+i.op_str};self.v+=1
        if i.mnemonic=='braa':
            e=self.p['PAC_models'][self.pac];self.pac+=1;assert i.op_str=='x16, x17';target=u.reg_read(A.UC_ARM64_REG_X16);mod=u.reg_read(A.UC_ARM64_REG_X17);slot=mod-BASE;row=self.s.decoded[slot]
            assert e=={'visit':self.v-1,'pc':hex(at),'target':hex(target),'slot':hex(slot),'modifier':hex(mod),'original_pointer_row':row,'CPU':frame(u)}
            assert row['bind']and row['key']=='IA'and row['address_diversity']==1 and row['diversity']=='0x0'and target==BIND+row['import']['ordinal']*16;u.reg_write(A.UC_ARM64_REG_PC,target)
        elif i.mnemonic.startswith(('pac','aut')):u.reg_write(A.UC_ARM64_REG_PC,pc+4)
        elif i.mnemonic=='retab':u.reg_write(A.UC_ARM64_REG_PC,u.reg_read(A.UC_ARM64_REG_LR))
    def run(self):
        self.u.emu_start(BASE+0x86c0,0,count=5001);self.flush();assert self.done
        assert [self.v,self.r,self.w,self.pac,self.mi,self.ri]==[len(self.p[k])for k in ['visits','reads','writes','PAC_models','models','getter_returns']]
        for row in self.p['final_RAM']:assert self.ram(int(row['address'],16),4096)==unpack(row['payload'])
        assert self.ram(OUT,8).hex()==self.p['output8_hex']and self.ram(BASE+CACHE,8).hex()==self.p['cache8_hex']
        assert int.from_bytes(self.ram(BASE+STATUS,4),'little')==self.p['status_u32']and hex(int.from_bytes(self.ram(BASE+ONCE,8),'little'))==self.p['once_u64']
        return {'visits_checked':self.v,'reads_checked':self.r,'writes_checked':self.w,'PAC_models_checked':self.pac,'models_checked':self.mi,
          'getter_returns_checked':self.ri,'final_RAM_B_checked':4096*len(self.p['final_RAM'])}


def oracle(c):
    cache=bytes.fromhex('a0a1a2a3a4a5');status=c.get('status_u32',0x13572468);calls=[]
    if c['cold']:
        calls=['declared_once_enter','_IOServiceMatching']
        if c.get('matching_nil'):status=5
        else:
            calls+=['_CFDictionaryCreateMutable']
            if not c.get('filter_nil'):calls+=['_CFDictionarySetValue','_CFDictionarySetValue','_CFRelease']
            calls+=['_IOServiceGetMatchingServices'];status=c.get('matching_status_u32',0)
            if status==0:
                cache=b'\0'*6;status=5;calls+=['_IOIteratorNext']
                for node in c['nodes']:
                    calls+=['_IORegistryEntryGetParentEntry'];status=node['parent_status_u32']
                    if status==0:
                        calls+=['_IORegistryEntryCreateCFProperty'];status=5
                        if node['property_hex']is not None:cache=bytes.fromhex(node['property_hex'])[:6];status=0;calls+=['_CFDataGetBytes','_CFRelease']
                        calls+=['_IOObjectRelease']
                    calls+=['_IOObjectRelease','_IOIteratorNext']
        calls+=['_IOObjectRelease','declared_once_return']
    capacities=[c['capacity_u64']]
    if 'repeat_capacity_u64'in c:capacities.append(c['repeat_capacity_u64']);calls+=['declared_second_getter_call']
    out=b'\xa5'*8;returns=[]
    for cap in capacities:
        ok=(cap&0xffffffff)>5 and status==0
        if ok:out=cache+out[6:]
        returns.append({'result_u64':int(ok),'output8_hex':out.hex()})
    return {'status_u32':status,'cache8_hex':(cache+bytes.fromhex('d6d7')).hex(),'once_u64':hex(M64),'output8_hex':out.hex(),'getter_returns':returns,'call_sequence':calls}


def proofs(s):
    exact={0x86c8:('cmn','x8, #1'),0x86d0:('cmp','w1, #5'),0x86dc:('ccmp','w8, #0, #0, hi'),0x86e0:('cset','w8, eq'),
      0x8738:('cmp','w1, #5'),0x8744:('ccmp','w8, #0, #0, hi'),0x8748:('cset','w8, eq'),0x86f0:('ldr','w10, [x9]'),
      0x86f4:('ldrh','w9, [x9, #4]'),0x86f8:('strh','w9, [x0, #4]'),0x86fc:('str','w10, [x0]'),
      0x8820:('str','wzr, [x8]'),0x8824:('strh','wzr, [x8, #4]'),0x88b0:('mov','w2, #6')}
    for addr,want in exact.items():
        i=next(CS.disasm(s.read(addr,4),addr));assert (i.mnemonic,i.op_str)==want
    cap,token=z3.BitVecs('network_capacity64 network_once64',64);status=z3.BitVec('network_status32',32);lo=z3.Extract(31,0,cap)
    zflag=z3.If(z3.UGT(lo,5),status==0,z3.BoolVal(False));x=z3.BitVec('network_cache_low32',32);y=z3.BitVec('network_cache_high16',16)
    claims=[('once_completion_word',token+1==0,token==M64),('capacity_status_CCMP',zflag,z3.And(z3.UGE(lo,6),status==0)),
      ('split_copy_bytes',z3.Concat(y,x),z3.Concat(z3.Extract(15,8,y),z3.Extract(7,0,y),z3.Extract(31,24,x),z3.Extract(23,16,x),z3.Extract(15,8,x),z3.Extract(7,0,x)))]
    out=[]
    for label,a,b in claims:
        solver=z3.Solver();solver.set(timeout=30000);solver.add(a!=b);assert solver.check()==z3.unsat
        out.append({'label':label,'query':solver.to_smt2(),'result':'unsat'})
    return {'exact_instructions_checked':len(exact),'proofs':out}


def external_checks():
    code='#include <stddef.h>\n#include <IOKit/IOKitLib.h>\n#include <CoreFoundation/CFData.h>\n_Static_assert(sizeof(void*)==8,"pointer64");\n_Static_assert(sizeof(CFIndex)==8 && ((CFIndex)-1)<0,"CFIndex64");\n_Static_assert(sizeof(CFRange)==16 && offsetof(CFRange,location)==0 && offsetof(CFRange,length)==8,"CFRange");\n_Static_assert(sizeof(mach_port_t)==4 && sizeof(io_object_t)==4 && sizeof(io_iterator_t)==4,"IOKit handles");\n_Static_assert(__builtin_types_compatible_p(__typeof__(&CFDataGetBytes),void(*)(CFDataRef,CFRange,UInt8*)),"CFDataGetBytes prototype");\n'
    cmd=['xcrun','clang','-target','arm64e-apple-macos14','-fsyntax-only','-x','c','-'];r=subprocess.run(cmd,input=code,text=True,capture_output=True,timeout=30);assert r.returncode==0,r.stderr
    sdk=Path(subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip());headers=[]
    for name in ['IOKit.framework/Headers/IOKitLib.h','CoreFoundation.framework/Headers/CFData.h','CoreFoundation.framework/Headers/CFBase.h']:
        p=sdk/'System/Library/Frameworks'/name;b=p.read_bytes();headers.append({'SDK_relative_header':name,'size_B':len(b),'sha256':SHA(b)})
    refs=[]
    for url in ['https://raw.githubusercontent.com/apple-oss-distributions/IOKitUser/main/IOKitLib.h','https://raw.githubusercontent.com/apple-oss-distributions/libdispatch/main/src/once.c','https://clang.llvm.org/docs/Block-ABI-Apple.html']:
        b=urlopen(url,timeout=20).read();refs.append({'url':url,'size_B':len(b),'sha256':SHA(b),'body_retained':False})
    return {'ABI_compile':{'command':cmd,'source':code,'source_sha256':SHA(code.encode()),'exit_code':r.returncode,'stderr':r.stderr,'emitted_artifact':False,'headers':headers},'primary_references':refs}


def main():
    e=json.loads(read(ROOT/'corefp_network_identity_checks.json'));assert e['generator_sha256']==SHA((ROOT/'recover_corefp_network_identity.py').read_bytes())
    for name,h in e['dependencies'].items():assert SHA(read(ROOT/name).encode())==h
    s=Pointers();src=e['source'];assert src['thin_sha256']==THIN_SHA
    for span in src['spans']:
        a,z=int(span['start'],16),int(span['end'],16);b=s.read(a,z-a);assert b.hex()==span['bytes']and SHA(b)==span['sha256']
    assert src['spans'][0]==s.function(0x86c0)and src['spans'][1]==s.function(0x8754)
    for stub in src['stubs']:assert stub['pointer']==s.decoded[int(stub['pointer']['address'],16)]
    assert src['block']['invoke']==s.decoded[0x1c80038]and src['block']['invoke']['target']=='0x8754'
    assert src['block']['original32_hex']==s.read(0x1c80028,32).hex()and s.read(0x1c80030,8)==bytes.fromhex('0000005000000000')
    assert src['block']['descriptor24_hex']==s.read(0x1c80008,24).hex()and int.from_bytes(s.read(0x1c80010,8),'little')==32 and s.read(0x1c79dc0,6)==b'v8@?0\0'
    for row in src['strings']:
        a=int(row['CFString'],16);assert row['data_pointer_row']==s.decoded[a+16]and row['descriptor32_hex']==s.read(a,32).hex()
        text=row['value'].encode();assert s.read(int(row['data_pointer_row']['target'],16),len(text)+1)==text+b'\0'and int.from_bytes(s.read(a+24,8),'little')==len(text)
    totals=Counter();oracles=[]
    for p in e['profiles']:
        c=p['configuration'];controls=[(CACHE,bytes.fromhex('a0a1a2a3a4a5d6d7')),(ONCE,(0 if c['cold']else M64).to_bytes(8,'little')),(STATUS,c.get('status_u32',0x13572468).to_bytes(4,'little'))]
        cpu={'X31':[hex(((j+1)*0x123456789abcdef)&M64)for j in range(31)],
          'Q32':[hex(int.from_bytes(bytes([j])*16,'little'))for j in range(32)],
          'SP':hex(SP),'PC':hex(BASE+0x86c0),'NZCV':'0x60000000','FPCR':'0x0','FPSR':'0x0','CPACR_EL1':'0x300000'}
        cpu['X31'][0]=hex(OUT);cpu['X31'][1]=hex(c['capacity_u64']);cpu['X31'][30]=hex(DONE)
        assert p['initial_CPU']==cpu;totals['initial_CPU_frames_checked']+=1
        assert p['controls']==[{'address':hex(BASE+a),'before_hex':s.read(a,len(b)).hex(),'after_hex':b.hex(),'reason':'declared private cache/once/status input'}for a,b in controls]
        for row in p['initial_RAM']:
            assert unpack(row['payload'])==initial_page(s,p,int(row['address'],16));totals['initial_RAM_B_checked']+=4096
        totals.update(Replay(p,src,s).run());want=oracle(c)
        for key in ['output8_hex','cache8_hex','status_u32','once_u64']:assert p[key]==want[key]
        assert len(p['getter_returns'])==len(want['getter_returns'])
        for actual,w in zip(p['getter_returns'],want['getter_returns']):assert int(actual['CPU']['X31'][0],16)==w['result_u64']and actual['output8_hex']==w['output8_hex']
        calls=[v['name']if v['kind']=='declared_API'else v['kind']for v in p['models']];assert calls==want['call_sequence'];oracles.append({'label':c['label'],**want})
    sourceproof=proofs(s);external=external_checks();counts={'profiles':len(e['profiles']),'cold':sum(p['configuration']['cold']for p in e['profiles']),'warm':sum(not p['configuration']['cold']for p in e['profiles']),
      **{k:sum(len(p[k])for p in e['profiles'])for k in ['visits','reads','writes','PAC_models','models']}}
    assert counts==e['verified_counts'];result={'verified_counts':counts,'independent_replay':dict(totals),'compact_oracle_profiles':len(oracles),'queries_unsat':3,
      'exact_instructions_checked':14,'source_B_checked':sum(len(bytes.fromhex(v['bytes']))for v in src['spans']),'ABI_compile_exit':0,
      'native_target_executed':False,'all_checks_pass':True}
    out={'result':result,'checks_sha256':SHA(read(ROOT/'corefp_network_identity_checks.json').encode()),'auditor_sha256':SHA(Path(__file__).read_bytes()),
      'dependencies':e['dependencies'],'oracles':oracles,'source_proofs':sourceproof,'external_checks':external,'fresh_replay_completed':True,'process_exit_code':0}
    (ROOT/'corefp_network_identity_audit.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(result),flush=True)


if __name__=='__main__':main()
