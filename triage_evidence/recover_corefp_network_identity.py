#!/usr/bin/env python3
"""Original network-registry block and six-byte lazy-cache getter.

Private original-byte emulation; CF/IOKit returns and sequential dispatch_once
are explicit fixtures, not native objects, calls, concurrency or IPC. Time
O(C*(B+F+V+J+R)); conservative space O(C*(B+F+V+J+R)). Each case <=5000 visits.
"""
import json,struct,copy,bisect
from pathlib import Path
from hashlib import sha256
import unicorn as U
from unicorn import arm64_const as A
from recover_fpsd1201_predicates import frame,pack
from corefp_fixups_reader import Pointers,ROOT,THIN_SHA
from probe_corefp_exports import BASE,BIND
from daemon_receive_tools import CS
from verify_daemon_reader_record_payloads_publication import read

SHA=lambda b:sha256(b).hexdigest();STACK=0x62000000;SP=STACK+0x4000;OUT=0x63000100;DONE=0x65000000
CACHE=0x1d443c0;ONCE=0x1d443c8;STATUS=0x1d25200;M64=(1<<64)-1
MATCH=0x66000100;FILTER=0x66000200;TRUE=0x66000300;ITER=0x5101
DEPS=['corefp_library_reader.py','corefp_fixups_reader.py','corefp_fixups_inventory.json','corefp_import_calls.json']


def configs():
    valid=lambda b:{'parent_status_u32':0,'property_hex':b}
    bad={'parent_status_u32':0xe00002c7,'property_hex':None};missing={'parent_status_u32':0,'property_hex':None}
    A0=valid('020000000001');B0=valid('020000000002')
    rows=[]
    for label,nodes,extra in [('one_valid',[A0],{}),('two_valid',[A0,B0],{}),('empty',[],{}),('parent_error',[bad],{}),
      ('property_missing',[missing],{}),('valid_then_missing',[A0,missing],{}),('missing_then_valid',[missing,B0],{}),
      ('valid_then_parent_error',[A0,bad],{}),('parent_error_then_valid',[bad,B0],{}),('matching_nil',[],{'matching_nil':True}),
      ('filter_nil',[A0],{'filter_nil':True}),('matching_error',[],{'matching_status_u32':0xe00002c0}),
      ('one_valid_clobber',[A0],{'clobber_callers':True}),('one_valid_short',[A0],{'capacity_u64':5}),
      ('one_valid_release_error',[A0],{'release_status_u32':0xe00002bc}),
      ('one_valid_repeat',[A0],{'repeat_capacity_u64':6}),('matching_error_repeat',[],{'matching_status_u32':0xe00002c0,'repeat_capacity_u64':6}),
      ('short_then_long',[A0],{'capacity_u64':5,'repeat_capacity_u64':6})]:
        rows.append({'label':label,'cold':True,'capacity_u64':6,'nodes':copy.deepcopy(nodes),**extra})
    for cap,status in [(0,0),(5,0),(6,0),(7,0),(0xffffffff,0),(0x100000006,0),(0x100000005,0),(6,5),(0xffffffff,0xffffffff)]:
        rows.append({'label':'warm_'+hex(cap)+'_'+hex(status),'cold':False,'capacity_u64':cap,'status_u32':status,'nodes':[]})
    return rows


def source(s):
    inv=json.loads(read(ROOT/'corefp_import_calls.json'));stubs=[v for v in inv['stubs']if v['address']in
      ['0x15d15f4','0x15d1614','0x15d1634','0x15d1694','0x15d16d4','0x15d16e4','0x15d16f4','0x15d1704','0x15d1714','0x15d1724','0x15d18c4']]
    assert len(stubs)==11
    spans=[s.function(a)for a in [0x86c0,0x8754]]
    for lo,n in [(0x15d1580,20)]+[(int(v['address'],16),16)for v in stubs]:
        b=s.read(lo,n);spans.append({'start':hex(lo),'end':hex(lo+n),'bytes':b.hex(),'sha256':SHA(b)})
    strings=[]
    for a in [0x1d1c1e8,0x1d1c208,0x1d1c228]:
        row=s.decoded[a+16];at=int(row['target'],16);b=s.read(at,100);z=b.index(0);length=int.from_bytes(s.read(a+24,8),'little');assert length==z
        strings.append({'CFString':hex(a),'descriptor32_hex':s.read(a,32).hex(),'data_pointer_row':row,'value':b[:z].decode()})
    block={'address':'0x1c80028','original32_hex':s.read(0x1c80028,32).hex(),'invoke':s.decoded[0x1c80038],
      'isa':s.decoded[0x1c80028],'descriptor':s.decoded[0x1c80040],'descriptor24_hex':s.read(0x1c80008,24).hex(),
      'signature_pointer':s.decoded[0x1c80018],'signature':'v8@?0'}
    return {'spans':spans,'stubs':stubs,'strings':strings,'block':block,'initial_globals':{hex(a):s.read(a,n).hex()for a,n in [(CACHE,8),(ONCE,8),(STATUS,4)]},
      'thin_sha256':THIN_SHA,'compiler_getter_bounds':['0x86c0','0x8754'],'compiler_block_bounds':['0x8754','0x890c']}


class Run:
    def __init__(self,s,src,c):
        self.s=s;self.src=src;self.c=c;self.u=U.Uc(U.UC_ARCH_ARM64,U.UC_MODE_ARM);u=self.u
        for seg in s.meta['segments']:
            n=(seg['vm_size']+4095)&~4095
            if not n:continue
            u.mem_map(BASE+seg['address'],n)
            if seg['file_size']:u.mem_write(BASE+seg['address'],s.data[seg['file_offset']:seg['file_offset']+seg['file_size']])
        for a,n in [(STACK,0x5000),(OUT&~4095,4096),(BIND,0x2000),(DONE,4096)]:u.mem_map(a,n)
        self.binds={}
        for a,r in s.decoded.items():
            if r['bind']:v=BIND+r['import']['ordinal']*16+r['pointer_addend'];self.binds[BIND+r['import']['ordinal']*16]=r['import']
            else:v=BASE+int(r['target'],16)
            u.mem_write(BASE+a,v.to_bytes(8,'little'))
        u.mem_write(STACK,b'\xa5'*0x5000);u.mem_write(OUT,b'\xa5'*8);u.mem_write(BIND+177*16,TRUE.to_bytes(8,'little'))
        self.controls=[]
        for a,b in [(BASE+CACHE,bytes.fromhex('a0a1a2a3a4a5d6d7')),(BASE+ONCE,(0 if c['cold']else M64).to_bytes(8,'little')),
          (BASE+STATUS,c.get('status_u32',0x13572468).to_bytes(4,'little'))]:
            self.controls.append({'address':hex(a),'before_hex':bytes(u.mem_read(a,len(b))).hex(),'after_hex':b.hex(),'reason':'declared private cache/once/status input'});u.mem_write(a,b)
        for j in range(31):u.reg_write(getattr(A,'UC_ARM64_REG_X'+str(j)),((j+1)*0x123456789abcdef)&M64)
        for j in range(32):u.reg_write(A.UC_ARM64_REG_Q0+j,int.from_bytes(bytes([j])*16,'little'))
        for n,v in [('SP',SP),('PC',BASE+0x86c0),('X0',OUT),('X1',c['capacity_u64']),('LR',DONE),('NZCV',0x60000000),('CPACR_EL1',3<<20)]:u.reg_write(getattr(A,'UC_ARM64_REG_'+n),v)
        self.initial=frame(u);self.pages={};self.trace=[];self.reads=[];self.writes=[];self.pending=[];self.models=[];self.pacs=[];self.node_index=0;self.current=None;self.data={};self.once_return=None;self.returns=[]
        for a,n in [(OUT,8),(BASE+CACHE,16),(BASE+STATUS,4)]:self.touch(a,n)
        u.hook_add(U.UC_HOOK_CODE,self.code);u.hook_add(U.UC_HOOK_MEM_READ,self.memory);u.hook_add(U.UC_HOOK_MEM_WRITE,self.memory)
    def reg(self,n):return self.u.reg_read(getattr(A,'UC_ARM64_REG_'+n.upper()))
    def touch(self,a,n):
        for p in range(a&~4095,((a+n-1)&~4095)+1,4096):
            if p not in self.pages:self.pages[p]=bytes(self.u.mem_read(p,4096))
    def memory(self,u,access,a,n,v,d):
        self.touch(a,n)
        if access==U.UC_MEM_READ:self.reads.append({'visit':len(self.trace)-1,'address':hex(a),'size_B':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()})
        else:
            e={'visit':len(self.trace)-1,'address':hex(a),'size_B':n,'before_hex':bytes(u.mem_read(a,n)).hex()};self.writes.append(e);self.pending.append(e)
    def flush(self):
        for e in self.pending:e['after_hex']=bytes(self.u.mem_read(int(e['address'],16),e['size_B'])).hex()
        self.pending=[]
    def write_model(self,e,a,b):
        self.touch(a,len(b));old=bytes(self.u.mem_read(a,len(b)));self.u.mem_write(a,b)
        e.setdefault('memory',[]).append({'address':hex(a),'before_hex':old.hex(),'after_hex':b.hex()})
    def returned(self,v):
        if self.c.get('clobber_callers'):
            for j in range(1,18):self.u.reg_write(getattr(A,'UC_ARM64_REG_X'+str(j)),(j*0x13579bdf2468ace)&M64)
            self.u.reg_write(A.UC_ARM64_REG_NZCV,0xa0000000)
        self.u.reg_write(A.UC_ARM64_REG_X0,v);self.u.reg_write(A.UC_ARM64_REG_PC,self.reg('lr'))
    def code(self,u,pc,n,d):
        self.flush()
        if pc==DONE:
            self.returns.append({'CPU':frame(u),'output8_hex':bytes(u.mem_read(OUT,8)).hex()})
            if len(self.returns)==1 and 'repeat_capacity_u64'in self.c:
                e={'kind':'declared_second_getter_call','before':frame(u),'memory':[]}
                u.reg_write(A.UC_ARM64_REG_X0,OUT);u.reg_write(A.UC_ARM64_REG_X1,self.c['repeat_capacity_u64']);u.reg_write(A.UC_ARM64_REG_PC,BASE+0x86c0)
                e['after']=frame(u);self.models.append(e);return
            self.frontier={'reason':'complete_getter_return','CPU':frame(u)};u.emu_stop();return
        if pc==DONE+0x100:
            e={'kind':'declared_once_return','before':frame(u),'memory':[]};self.write_model(e,BASE+ONCE,b'\xff'*8)
            u.reg_write(A.UC_ARM64_REG_LR,self.once_return);self.returned(0);e['after']=frame(u);self.models.append(e);return
        if pc in self.binds:
            name=self.binds[pc]['name'];args=[self.reg('x'+str(j))for j in range(8)];e={'kind':'declared_API','name':name,'callsite':hex(self.reg('lr')-4-BASE),'args_x0_x7':[hex(v)for v in args],'before':frame(u),'memory':[]};self.models.append(e)
            if name=='_dispatch_once':
                assert args[:2]==[BASE+ONCE,BASE+0x1c80028]and self.c['cold']and self.once_return is None
                self.once_return=self.reg('lr');u.reg_write(A.UC_ARM64_REG_LR,DONE+0x100);u.reg_write(A.UC_ARM64_REG_X0,args[1]);u.reg_write(A.UC_ARM64_REG_PC,BASE+0x8754)
                e['kind']='declared_once_enter';e['callback_row']=self.src['block']['invoke'];e['after']=frame(u);return
            if name=='_IOServiceMatching':assert args[0]==BASE+0x1c79dc6;value=0 if self.c.get('matching_nil')else MATCH
            elif name=='_CFDictionaryCreateMutable':assert args[:4]==[0,0,BIND+180*16,BIND+181*16];value=0 if self.c.get('filter_nil')else FILTER
            elif name=='_CFDictionarySetValue':
                assert args[:3]in [[FILTER,BASE+0x1d1c1e8,TRUE],[MATCH,BASE+0x1d1c208,FILTER]];value=0
            elif name=='_CFRelease':assert args[0]in [FILTER]+list(self.data);value=0
            elif name=='_IOServiceGetMatchingServices':
                assert args[:2]==[0,MATCH];value=self.c.get('matching_status_u32',0)
                if value==0:self.write_model(e,args[2],ITER.to_bytes(4,'little'))
            elif name=='_IOIteratorNext':
                assert args[0]==ITER
                if self.node_index<len(self.c['nodes']):self.current=self.node_index;self.node_index+=1;value=0x5200+self.current
                else:value=0
            elif name=='_IORegistryEntryGetParentEntry':
                assert self.current is not None and args[:2]==[0x5200+self.current,BASE+0x1c79dfd]
                value=self.c['nodes'][self.current]['parent_status_u32']
                if value==0:self.write_model(e,args[2],(0x5300+self.current).to_bytes(4,'little'))
            elif name=='_IORegistryEntryCreateCFProperty':
                assert args[:4]==[0x5300+self.current,BASE+0x1d1c228,0,0];raw=self.c['nodes'][self.current]['property_hex'];value=0 if raw is None else 0x66001000+self.current*16
                if value:self.data[value]=bytes.fromhex(raw)
            elif name=='_CFDataGetBytes':
                assert args[0]in self.data and args[1:4]==[0,6,BASE+CACHE];self.write_model(e,args[3],self.data[args[0]][:6]);value=0
            elif name=='_IOObjectRelease':assert args[0]==0 or args[0]==ITER or 0x5200<=args[0]<0x5200+len(self.c['nodes'])or 0x5300<=args[0]<0x5300+len(self.c['nodes']);value=self.c.get('release_status_u32',0)
            else:raise AssertionError('unmodeled import '+name)
            e['return_u64']=hex(value);self.returned(value);e['after']=frame(u);return
        at=pc-BASE;assert any(int(s['start'],16)<=at<int(s['end'],16)for s in self.src['spans']),'unretained instruction'
        raw=bytes(u.mem_read(pc,4));i=next(CS.disasm(raw,at));self.trace.append({'pc':hex(at),'bytes_hex':raw.hex(),'instruction':i.mnemonic+' '+i.op_str})
        if i.mnemonic=='braa':
            assert i.op_str=='x16, x17';target=self.reg('x16');mod=self.reg('x17');slot=mod-BASE;row=self.s.decoded[slot]
            assert row['bind']and row['key']=='IA'and row['address_diversity']==1 and row['diversity']=='0x0'and target==BIND+row['import']['ordinal']*16
            self.pacs.append({'visit':len(self.trace)-1,'pc':hex(at),'target':hex(target),'slot':hex(slot),'modifier':hex(mod),'original_pointer_row':row,'CPU':frame(u)});u.reg_write(A.UC_ARM64_REG_PC,target)
        elif i.mnemonic.startswith(('pac','aut')):u.reg_write(A.UC_ARM64_REG_PC,pc+4)
        elif i.mnemonic=='retab':u.reg_write(A.UC_ARM64_REG_PC,self.reg('lr'))
    def run(self):
        self.u.emu_start(BASE+0x86c0,0,count=5001);self.flush();assert hasattr(self,'frontier')
        return {'configuration':self.c,'controls':self.controls,'getter_returns':self.returns,'initial_CPU':self.initial,'initial_RAM':[{'address':hex(a),'payload':pack(b)}for a,b in sorted(self.pages.items())],
          'visits':self.trace,'reads':self.reads,'writes':self.writes,'PAC_models':self.pacs,'models':self.models,'frontier':self.frontier,
          'final_RAM':[{'address':hex(a),'payload':pack(bytes(self.u.mem_read(a,4096)))}for a in sorted(self.pages)],
          'output8_hex':bytes(self.u.mem_read(OUT,8)).hex(),'cache8_hex':bytes(self.u.mem_read(BASE+CACHE,8)).hex(),
          'status_u32':int.from_bytes(self.u.mem_read(BASE+STATUS,4),'little'),'once_u64':hex(int.from_bytes(self.u.mem_read(BASE+ONCE,8),'little'))}


def main():
    s=Pointers();src=source(s);rows=[Run(s,src,c).run()for c in configs()]
    counts={'profiles':len(rows),'cold':sum(p['configuration']['cold']for p in rows),'warm':sum(not p['configuration']['cold']for p in rows),
      **{k:sum(len(p[k])for p in rows)for k in ['visits','reads','writes','PAC_models','models']}}
    e={'scope':__doc__,'generator_sha256':SHA(Path(__file__).read_bytes()),'dependencies':{n:SHA(read(ROOT/n).encode())for n in DEPS},'source':src,'profiles':rows,'verified_counts':counts,
      'native_target_executed':False,'native_API_executed':False,'IDB_mutated':False,'full_goal_complete':False}
    (ROOT/'corefp_network_identity_checks.json').write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(counts),flush=True)


if __name__=='__main__':main()
