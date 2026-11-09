#!/usr/bin/env python3
"""Finite private AMSKeybag import caller ABI probes.

Only original block 0x19c648880 executes. Framework, context, protected import,
record disposal and account-pair notification are explicit models. Cache faults
map original read-only cache pages, never guessed zero pages. No host target API
or IPC runs. O(C*K + P) time, O(P) mapped bytes with bounded private records.
"""
import hashlib
import json
from pathlib import Path
import struct
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_UNMAPPED,UC_HOOK_MEM_WRITE
from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_SP,UC_ARM64_REG_LR,UC_ARM64_REG_PC
from bootpolicy_cache_reader import Cache
from appstore_agent_reader import ROOT,sha

STACK=0x73000000;HEAP=0x74000000;DONE=0x75000000


class Probe:
    def __init__(self,f):
        self.fixture=f;self.cache=Cache();self.u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);self.records=[];self.visited=[];self.pages={};self.steps=0;self.reason=None
        self.objects={};self.next=HEAP+0x3000;self.freed=False;self.pairs=[];self.posts=[]
        self.contract=json.loads((ROOT/'appstore_events_contracts.json').read_text())
        row=next(x for x in self.contract['reference_ams_ranges'] if x['start']=='0x19c648880')
        self.nodes={int(x['ea'],16):x for x in row['instructions']};self.stubs={int(x['address'],16):x for x in self.contract['reference_ams_stubs']}
        self.u.mem_map(STACK,0x10000);self.u.mem_map(HEAP,0x10000);self.u.mem_map(DONE,4096)
        self.map_original(0x19c648880)
        self.u.reg_write(UC_ARM64_REG_SP,STACK+0xf000);self.u.reg_write(UC_ARM64_REG_LR,DONE)
        self.block=HEAP+0x100;self.error=HEAP+0x400;self.flag=HEAP+0x500;self.buffer=HEAP+0x1000
        self.writeq(self.block+32,0 if f.get('data_null') else HEAP+0x200)
        self.writeq(self.block+40,HEAP+0x300);self.writeq(self.block+48,self.flag);self.writeq(self.block+56,self.error)
        self.writeq(self.error+8,self.error);self.writeq(self.flag+8,self.flag)
        for j,fields in enumerate(f.get('output_records',[])):self.u.mem_write(self.buffer+32*j,struct.pack('<4Q',*fields))
        self.u.hook_add(UC_HOOK_CODE,self.code);self.u.hook_add(UC_HOOK_MEM_UNMAPPED,self.unmapped);self.u.hook_add(UC_HOOK_MEM_WRITE,self.write_guard)

    def map_original(self,a):
        page=a&~4095
        if page in self.pages:return
        raw=self.cache.read(page,4096);self.u.mem_map(page,4096);self.u.mem_write(page,raw);self.pages[page]=sha(raw)
    def unmapped(self,u,access,address,size,value,data):
        try:
            for a in range(address&~4095,(address+size+4095)&~4095,4096):self.map_original(a)
            return True
        except Exception as e:self.reason='unmapped_original_cache_guard:'+str(e);return False
    def write_guard(self,u,access,address,size,value,data):
        if not (STACK<=address and address+size<=STACK+0x10000 or HEAP<=address and address+size<=HEAP+0x10000):self.stop('nonprivate_write_guard')
    def writeq(self,a,v):self.u.mem_write(a,struct.pack('<Q',v))
    def reg(self,n):return self.u.reg_read(UC_ARM64_REG_X0+n)
    def ret(self,v):self.u.reg_write(UC_ARM64_REG_X0,v&((1<<64)-1));self.u.reg_write(UC_ARM64_REG_PC,self.u.reg_read(UC_ARM64_REG_LR))
    def stop(self,why):self.reason=why;self.u.emu_stop()
    def obj(self,kind,**fields):
        a=self.next;self.next+=0x100;assert self.next<HEAP+0x9000
        self.objects[a]={'kind':kind,**fields};return a

    def code(self,u,pc,size,data):
        self.steps+=1
        if self.steps>2000:return self.stop('instruction_budget_guard')
        if pc==DONE:return self.stop('returned_to_private_fixture')
        x=[self.reg(j) for j in range(5)]
        if pc==0x19c9ec168:
            assert x[:3]==[self.fixture.get('context_u32',7),HEAP+0x2000,64]
            self.writeq(x[3],0 if self.fixture.get('output_pointer_null') else self.buffer)
            self.u.mem_write(x[4],struct.pack('<I',len(self.fixture.get('output_records',[]))))
            self.records.append({'kind':'modeled_obfuscated_import','pc':hex(pc),'args':[hex(v) for v in x],
                'output_records':self.fixture.get('output_records',[]),'status_u32':self.fixture.get('import_status_u32',0)})
            return self.ret(self.fixture.get('import_status_u32',0))
        if pc==0x19ca1dd68:
            assert x[0]==self.buffer and not self.freed;self.freed=True
            self.records.append({'kind':'modeled_record_disposal','pointer':hex(x[0])});return self.ret(0)
        if pc==0x19c1de808:
            self.records.append({'kind':'modeled_AMS_error_creation','code_u32':x[0]&0xffffffff});return self.ret(self.obj('error'))
        if pc in self.stubs:
            st=self.stubs[pc];sel=st.get('selector');exports=st.get('exact_exports',[]);result=None
            self.records.append({'kind':'modeled_API','pc':hex(pc),'selector':sel,'exact_exports':exports,'args':[hex(v) for v in x]})
            if any(v in exports for v in ('_objc_retain','_objc_claimAutoreleasedReturnValue','_objc_retainAutorelease')):result=x[0]
            elif any(v in exports for v in ('_objc_release','_objc_storeStrong')):
                if '_objc_storeStrong' in exports:self.writeq(x[0],x[1])
                result=0
            elif any(v in exports for v in ('_objc_alloc','_objc_alloc_init')):result=self.obj('allocated')
            elif sel=='fairplayContextWithError:':
                self.writeq(x[2],self.obj('error') if self.fixture.get('context_error') else 0);result=self.fixture.get('context_u32',7)
            elif sel=='bytes':result=HEAP+0x2000
            elif sel=='length':result=64
            elif sel=='stringWithFormat:':result=self.obj('error_description')
            elif sel=='initWithDownloaderAccountID:purchaserAccountID:familyID:':
                pair={'downloader_u64':x[2],'purchaser_u64':x[3],'family_u64':x[4]};self.pairs.append(pair);result=self.obj('account_pair',**pair)
            elif sel=='addObject:':result=0
            elif sel=='count':result=len(self.pairs)
            elif sel=='postDistributedNotificationWithAccountPairs:':self.posts.append(list(self.pairs));result=0
            if result is None:return self.stop('unmodeled_API_guard:'+str((hex(pc),sel,exports)))
            return self.ret(result)
        if pc not in self.nodes:return self.stop('unapproved_original_function_guard:'+hex(pc))
        self.visited.append(pc);i=self.nodes[pc];m=i['mnemonic']
        if m.startswith(('pac','aut')):self.u.reg_write(UC_ARM64_REG_PC,pc+4)
        elif m in ('retab','retaa'):self.u.reg_write(UC_ARM64_REG_PC,self.u.reg_read(UC_ARM64_REG_LR))

    def run(self):
        self.u.reg_write(UC_ARM64_REG_X0,self.block)
        try:self.u.emu_start(0x19c648880,DONE+4,count=2001)
        except Exception as e:
            if self.reason is None:self.reason='private_emulator_exception:'+str(e)
        h=hashlib.sha256()
        for pc in self.visited:h.update(struct.pack('<Q',pc));h.update(self.cache.read(pc,4))
        flag=bytes(self.u.mem_read(self.flag+24,1))[0];err=struct.unpack('<Q',bytes(self.u.mem_read(self.error+40,8)))[0]
        return {'fixture':self.fixture,'stop_reason':self.reason,'steps':self.steps,'success_byte':flag,'error_present':bool(err),
            'records_disposed':self.freed,'account_pairs':self.pairs,'notification_arguments':self.posts,'records':self.records,
            'visited_original_instructions':[hex(x) for x in self.visited],'original_instruction_bytes_sha256':h.hexdigest(),
            'mapped_original_pages':[{'address':hex(a),'sha256':h} for a,h in sorted(self.pages.items())]}


def main():
    fixtures=[{'label':'nil_data','data_null':True}, {'label':'zero_context','context_u32':0},
        {'label':'context_error','context_error':True}, {'label':'protected_import_error','import_status_u32':0xffff5a90},
        {'label':'null_output_pointer','output_pointer_null':True}, {'label':'zero_record_count','output_records':[]},
        {'label':'one_account_pair','output_records':[[11,22,33,0xaaaaaaaaaaaaaaaa]]},
        {'label':'two_distinct_account_pairs','output_records':[[11,22,33,0xaaaaaaaaaaaaaaaa],[44,55,66,0xbbbbbbbbbbbbbbbb]]}]
    rows=[Probe(f).run() for f in fixtures]
    out={'scope':__doc__,'reference_cache_uuid':Cache().uuid,'reference_ams_uuid':'1b464993-f0e2-3804-b412-a6cc8091798c',
        'generator_sha256':sha(Path(__file__).read_bytes()),'source_contracts_sha256':sha((ROOT/'appstore_events_contracts.json').read_bytes()),
        'profiles':rows,'native_target_executed':False,'protected_algorithm_executed':False,'hardware_PAC_checked':False,'full_goal_complete':False}
    (ROOT/'ams_keybag_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
    assert all(x['stop_reason']=='returned_to_private_fixture' for x in rows),[(x['fixture']['label'],x['stop_reason']) for x in rows]
    print(json.dumps({'cases':len(rows),'all_returned':True,'native_target_executed':False}))


if __name__=='__main__':main()
