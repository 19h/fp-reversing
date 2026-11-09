#!/usr/bin/env python3
"""Original protected AMS private execution with v5 pointer materialization.

No native target/API executes. PAC is bypassed, decoded pointers materialized
in private pages, and unknown external calls/syscalls stop. Disposal models
only exact free of an owned private object. Creation-wrapper cases explicitly
model the backend status; deep cases stop before any external API executes.
Time O(K+P), K<=50000 steps, memory O(P) private original pages plus fixtures.
"""
import bisect
import hashlib
import json
from pathlib import Path
import struct
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_UNMAPPED,UC_HOOK_MEM_WRITE
from unicorn import arm64_const as A
from ams_core_reader import Core,ROOT,CS,sha
from bootpolicy_cache_reader import Dylib

STACK=0x76000000;HEAP=0x77000000;DONE=0x78000000


class Probe:
    def __init__(self,f):
        self.core=Core();self.cache=self.core.cache;self.lib=self.core.ams;self.fixture=f;self.records=[];self.visited=[];self.functions={};self.pages={};self.steps=0;self.reason=None;self.freed=False
        self.u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);self.u.mem_map(STACK,0x20000);self.u.mem_map(HEAP,0x10000);self.u.mem_map(DONE,4096)
        self.sp=STACK+0x18000+f.get('stack_delta',0);self.u.reg_write(A.UC_ARM64_REG_SP,self.sp);self.u.reg_write(A.UC_ARM64_REG_LR,DONE)
        inv=json.loads((ROOT/'ams_core_pointer_inventory.json').read_text());self.external={int(x['address'],16):x for x in inv['external_executable_targets']}
        self.images=sorted((x['address'],x['path']) for x in self.cache.images);self.image_starts=[a for a,p in self.images];self.libs={self.lib.path:self.lib}
        self.starts=self.lib.functions;self.texts=[x for x in self.lib.sections if x['name']=='__text'];self.mutables=[x for x in self.lib.sections if x['segment'] in ('__DATA','__DATA_DIRTY')]
        self.stub_sections=[x for x in self.lib.sections if x['name'] in ('__stubs','__auth_stubs','__objc_stubs')];self.stub_instructions={}
        self.ins_cache={};self.block=HEAP+0x1000;self.owned=HEAP+0x2000
        self.once_state={};self.once_stack=[]
        self.allocations={};self.next_alloc=HEAP+0x3000;self.locks={}
        self.shared_stubs={}
        self.library_inventory=json.loads((ROOT/'corefp_library_inventory.json').read_text())
        self.library_entrypoints={DONE+0x200+j*16:n[1:] for j,n in enumerate(self.library_inventory['exports'])}
        self.initial_export_returns=0
        self.u.mem_write(HEAP+0x200,b'/Users/Shared/SC Info\0')
        for a,v in zip([0x1ebbfdbf0,0x1ebbfdf10],f.get('dispose_state',[0x123456789abcdef0,0x9988776655443322])):
            self.map_original(a);self.u.mem_write(a,struct.pack('<Q',v))
        self.state_before=[bytes(self.u.mem_read(a,8)).hex() for a in [0x1ebbfdbf0,0x1ebbfdf10]]
        self.u.hook_add(UC_HOOK_MEM_UNMAPPED,self.unmapped);self.u.hook_add(UC_HOOK_MEM_WRITE,self.write_hook);self.u.hook_add(UC_HOOK_CODE,self.code)

    def map_original(self,a):
        page=a&~4095
        if page in self.pages:return
        raw=self.cache.read(page,4096);self.u.mem_map(page,4096);self.u.mem_write(page,raw);chains=[]
        for at,row in self.core.page_chains(page).items():
            if page<=at<page+4096:
                self.u.mem_write(at,struct.pack('<Q',int(row['target'],16)));chains.append(row)
        self.pages[page]={'address':hex(page),'original_sha256':sha(raw),'materialized_sha256':sha(bytes(self.u.mem_read(page,4096))),'relocations':chains}
    def unmapped(self,u,access,address,size,value,data):
        try:
            for p in range(address&~4095,(address+size+4095)&~4095,4096):self.map_original(p)
            return True
        except Exception as e:self.reason='unmapped_original_cache_guard:'+str(e);return False
    def stop(self,why):self.reason=why;self.u.emu_stop()
    def write_hook(self,u,access,address,size,value,data):
        if STACK<=address and address+size<=STACK+0x20000 or HEAP<=address and address+size<=HEAP+0x10000:return
        if any(x['address']<=address and address+size<=x['address']+x['size'] for x in self.mutables):
            self.records.append({'kind':'private_original_global_write','pc':hex(self.u.reg_read(A.UC_ARM64_REG_PC)),
                'address':hex(address),'size_bytes':size,'value':hex(value&((1<<(size*8))-1))});return
        self.stop('unapproved_global_write_guard:'+hex(address))
    def reg(self,name):
        if name=='sp':return self.u.reg_read(A.UC_ARM64_REG_SP)
        if name in ('xzr','wzr'):return 0
        return self.u.reg_read(getattr(A,'UC_ARM64_REG_'+name.upper()))
    def ret(self,value=0):
        self.u.reg_write(A.UC_ARM64_REG_X0,value);self.u.reg_write(A.UC_ARM64_REG_PC,self.u.reg_read(A.UC_ARM64_REG_LR))
    def cstring(self,at,limit=1024):
        buf=bytearray()
        for j in range(limit):
            p=at+j
            if not (STACK<=p<STACK+0x20000 or HEAP<=p<HEAP+0x10000 or DONE<=p<DONE+4096):self.map_original(p)
            byte=bytes(self.u.mem_read(p,1))
            if byte==b'\0':return buf.decode()
            buf+=byte
        raise ValueError('private string bound')

    def code(self,u,pc,size,data):
        self.steps+=1
        if self.steps>50000:return self.stop('instruction_budget_guard')
        if pc==DONE:return self.stop('returned_to_private_fixture')
        if pc in self.library_entrypoints:
            live=[self.reg('x'+str(j)) for j in range(9)];snapshots=[]
            for j,at in enumerate(live):
                if STACK<=at<STACK+0x1ffc0 or HEAP<=at<HEAP+0xffc0:snapshots.append({'register':'x'+str(j),'pointer':hex(at),'first64_bytes':bytes(self.u.mem_read(at,64)).hex()})
            self.records.append({'kind':'CoreFP_export_call_boundary','export':self.library_entrypoints[pc],
                'live_registers_x0_x8':[hex(x) for x in live],'pointer_snapshots':snapshots,'callsite':hex(self.u.reg_read(A.UC_ARM64_REG_LR)-4)})
            if self.library_entrypoints[pc]=='lxpgvVMLd0S7uRl' and 'initial_export_status_u32' in self.fixture:
                if self.initial_export_returns:return self.stop('repeated_initial_export_guard')
                self.initial_export_returns+=1;value=self.fixture['initial_export_status_u32']
                self.records[-1].update({'kind':'modeled_initial_CoreFP_export','modeled_return_u32':value,'output_effects':'none; private original global state preserved'})
                return self.ret(value)
            return self.stop('CoreFP_export_call_boundary')
        if pc==DONE+0x100:
            control,lr=self.once_stack.pop();self.once_state[control]='done';self.u.reg_write(A.UC_ARM64_REG_LR,lr)
            self.records.append({'kind':'modeled_once_initializer_return','control':hex(control)});return self.ret(0)
        if pc==0x19c237c80:
            self.records.append({'kind':'original_decoded_create_operation','pc':hex(pc),'operation_u32':self.reg('w20'),'record_pointer':hex(self.reg('x19'))})
        if pc==0x19c9e1468:
            at=self.reg('sp')+8;raw=bytes(self.u.mem_read(at,48));encoded=struct.unpack_from('<I',raw,32)[0]
            self.records.append({'kind':'original_create_record_return','record_pointer':hex(at),'record_bytes':raw.hex(),'encoded_status_u32':encoded,'decoded_status_u32':encoded^0x0ef7dc36})
        if pc==0x181e7a6f0 and self.fixture['mode']=='dispose':
            ptr=self.reg('x0');assert ptr==self.owned and not self.freed
            self.freed=True;self.records.append({'kind':'modeled_exact_free','pointer':hex(ptr),'pc':hex(pc)});return self.ret(0)
        if pc==0x19c237b30 and self.fixture['mode']=='create_wrapper':
            ptr=self.reg('x0');raw=bytes(self.u.mem_read(ptr,48));v=struct.unpack('<QIIQQIIQ',raw)
            operation=(v[1]-(((ptr&0xffffffff)^0x0df1d93a)*0x7f12daa3))&0xffffffff
            self.records.append({'kind':'modeled_create_backend','pc':hex(pc),'record_pointer':hex(ptr),'record_bytes':raw.hex(),
                'operation_u32':operation,'original_X1':hex(v[0]),'context_output_pointer':hex(v[3]),'original_X0':hex(v[4]),'path_pointer':hex(v[7])})
            assert operation==0xc4b
            self.u.mem_write(ptr+32,struct.pack('<I',(self.fixture['backend_status_u32']^0x0ef7dc36)&0xffffffff));return self.ret(0)
        in_stub=any(x['address']<=pc<x['address']+x['size'] for x in self.stub_sections)
        if not in_stub and not any(x['address']<=pc<x['address']+x['size'] for x in self.texts):
            raw=self.cache.read(pc,16);decoded=list(CS.disasm(raw,pc))
            if len(decoded)==4 and [i.mnemonic for i in decoded]==['adrp','add','ldr','braa'] and decoded[0].op_str.startswith('x17,') and decoded[3].op_str=='x16, x17':
                slot=int(decoded[0].op_str.split('#')[1],0)+int(decoded[1].op_str.split('#')[1],0);ptr=self.core.pointer(slot);target=int(ptr['target'],16)
                self.shared_stubs[pc]={'address':hex(pc),'bytes':raw.hex(),'pointer':ptr}
                self.records.append({'kind':'original_shared_stub_resolution','pc':hex(pc),'slot':hex(slot),'target':hex(target),'PAC_bypassed':True})
                self.u.reg_write(A.UC_ARM64_REG_X17,slot);self.u.reg_write(A.UC_ARM64_REG_X16,target);self.u.reg_write(A.UC_ARM64_REG_PC,target);return
            target=self.external.get(pc)
            if target is None:
                path=self.images[bisect.bisect_right(self.image_starts,pc)-1][1]
                if path not in self.libs:self.libs[path]=Dylib(self.cache,path)
                lib=self.libs[path];target={'address':hex(pc),'library':path,'library_uuid':lib.uuid,
                    'exact_exports':[n for n,r in lib.exports.items() if r['address']==pc],
                    'compiler_function_start':pc in lib.functions,'original_names':lib.symbols_at(pc)}
                self.external[pc]=target
            if '____chkstk_darwin' in target['exact_exports']:
                need=self.reg('x9');self.records.append({'kind':'modeled_private_stack_check','pc':hex(pc),'binding':target,'requested_size_x9':hex(need)})
                if need>0x10000:return self.stop('private_stack_check_size_guard')
                self.u.reg_write(A.UC_ARM64_REG_PC,self.u.reg_read(A.UC_ARM64_REG_LR));return
            if '_pthread_once' in target['exact_exports'] and self.fixture.get('continue_once'):
                control=self.reg('x0');callback=self.reg('x1');state=self.once_state.get(control,'unstarted')
                self.records.append({'kind':'modeled_once','control':hex(control),'callback':hex(callback),'state':state,'binding':target})
                if state=='done':return self.ret(0)
                if state=='running':return self.stop('private_once_reentry_guard')
                self.once_state[control]='running';self.once_stack.append((control,self.u.reg_read(A.UC_ARM64_REG_LR)))
                self.u.reg_write(A.UC_ARM64_REG_LR,DONE+0x100);self.u.reg_write(A.UC_ARM64_REG_PC,callback);return
            exports=target['exact_exports']
            if '_dlopen' in exports and self.fixture.get('dlopen'):
                path=self.cstring(self.reg('x0'));assert path=='/System/Library/PrivateFrameworks/CoreFP.framework/CoreFP' and self.reg('x1')==5
                handle=HEAP+0xe000 if self.fixture['dlopen']=='success' else 0
                self.records.append({'kind':'modeled_dlopen','binding':target,'path':path,'flags_u32':5,'handle':hex(handle),'callsite':hex(self.u.reg_read(A.UC_ARM64_REG_LR)-4)})
                return self.ret(handle)
            if '_dlsym' in exports and self.fixture.get('dlsym'):
                name=self.cstring(self.reg('x1'),128);assert self.reg('x0')==HEAP+0xe000
                matches=[p for p,n in self.library_entrypoints.items() if n==name]
                if len(matches)!=1:return self.stop('unexpected_CoreFP_export_lookup:'+name)
                value=matches[0] if self.fixture['dlsym']=='success' else 0
                self.records.append({'kind':'modeled_dlsym','binding':target,'name':name,'pointer':hex(value),'callsite':hex(self.u.reg_read(A.UC_ARM64_REG_LR)-4)});return self.ret(value)
            if '_malloc' in exports and self.fixture.get('allocator'):
                n=self.reg('x0');self.records.append({'kind':'modeled_private_malloc','size_bytes':n,'null':self.fixture['allocator']=='null','callsite':hex(self.u.reg_read(A.UC_ARM64_REG_LR)-4)})
                if self.fixture['allocator']=='null':return self.ret(0)
                if n>0x4000 or self.next_alloc+max(n,1)>=HEAP+0xf000:return self.stop('private_allocator_size_guard')
                ptr=self.next_alloc;self.next_alloc=(ptr+max(n,1)+15)&~15;self.allocations[ptr]={'size':n,'alive':True}
                self.u.mem_write(ptr,bytes([0xa5])*n);self.records[-1]['pointer']=hex(ptr);return self.ret(ptr)
            if self.fixture.get('model_locks') and any(n in exports for n in ['_pthread_rwlock_init','_pthread_rwlock_wrlock','_pthread_rwlock_unlock']):
                ptr=self.reg('x0')
                if '_pthread_rwlock_init' in exports:
                    if ptr not in self.allocations or self.allocations[ptr]['size']<200:return self.stop('private_rwlock_storage_guard')
                    self.locks[ptr]=0
                elif '_pthread_rwlock_wrlock' in exports:
                    if ptr not in self.locks or self.locks[ptr]!=0:return self.stop('private_rwlock_reentry_guard')
                    self.locks[ptr]=1
                else:
                    if self.locks.get(ptr)!=1:return self.stop('private_rwlock_unlock_guard')
                    self.locks[ptr]=0
                self.records.append({'kind':'modeled_private_rwlock','exports':exports,'pointer':hex(ptr),'callsite':hex(self.u.reg_read(A.UC_ARM64_REG_LR)-4),'modeled_status_u32':0});return self.ret(0)
            self.records.append({'kind':'external_boundary','pc':hex(pc),'binding':target,
                'args':[hex(self.reg('x'+str(j))) for j in range(8)],'callsite':hex(self.u.reg_read(A.UC_ARM64_REG_LR)-4)})
            return self.stop('external_API_boundary' if target else 'unresolved_external_code_boundary')
        if in_stub and pc not in self.ins_cache:
            d=next(CS.disasm(self.cache.read(pc,4),pc));i={'ea':hex(pc),'mnemonic':d.mnemonic,'operands':d.op_str}
            self.ins_cache[pc]=i;self.stub_instructions[pc]=i
        elif pc not in self.ins_cache:
            ix=bisect.bisect_right(self.starts,pc)-1;entry=self.starts[ix];r=self.lib.function(entry);self.functions[entry]=r
            self.ins_cache.update({int(i['ea'],16):i for i in r['instructions']})
        i=self.ins_cache[pc];self.visited.append(pc);m=i['mnemonic'];op=i['operands']
        if m in ('svc','hvc','smc','brk'):return self.stop('native_instruction_guard:'+m)
        if m in ('braa','brab','blraa','blrab','braaz','brabz','blraaz','blrabz'):
            regs=op.split(', ');target=self.reg(regs[0]);self.records.append({'kind':'PAC_bypassed_indirect_edge','pc':hex(pc),'target':hex(target),
                'modifier':None if len(regs)==1 else hex(self.reg(regs[1])),'link':m.startswith('bl')})
            if m.startswith('bl'):self.u.reg_write(A.UC_ARM64_REG_LR,pc+4)
            self.u.reg_write(A.UC_ARM64_REG_PC,target)
        elif m.startswith(('pac','aut')):self.u.reg_write(A.UC_ARM64_REG_PC,pc+4)
        elif m in ('retab','retaa'):self.u.reg_write(A.UC_ARM64_REG_PC,self.u.reg_read(A.UC_ARM64_REG_LR))

    def run(self):
        mode=self.fixture['mode']
        if mode=='dispose':entry=0x19ca1dd68;args=[0 if self.fixture.get('null') else self.owned]
        elif mode.startswith('create'):entry=0x19c9e12a0;args=[0,HEAP+0x300,HEAP+0x200,HEAP+0x400]
        elif mode=='validate':entry=0x19ca0d0e4;args=[self.fixture.get('context_u32',0)]
        else:entry=0x19c9ec168;args=[self.fixture.get('context_u32',0),HEAP+0x500,64,HEAP+0x600,HEAP+0x608]
        self.map_original(entry)
        for j,x in enumerate(args):self.u.reg_write(A.UC_ARM64_REG_X0+j,x)
        try:self.u.emu_start(entry,DONE+4,count=50001)
        except Exception as e:
            if self.reason is None:self.reason='private_emulator_exception:'+str(e)
        h=hashlib.sha256()
        for pc in self.visited:h.update(struct.pack('<Q',pc));h.update(self.cache.read(pc,4))
        return {'fixture':self.fixture,'stop_reason':self.reason,'steps':self.steps,'result_u32':self.reg('w0'),
            'private_object_freed':self.freed,'state_before':self.state_before,
            'state_after':[bytes(self.u.mem_read(a,8)).hex() for a in [0x1ebbfdbf0,0x1ebbfdf10]],
            'visited_original_instructions':[hex(x) for x in self.visited],'original_instruction_bytes_sha256':h.hexdigest(),
            'original_functions':list(self.functions.values()),'original_shared_stubs':list(self.shared_stubs.values()),
            'original_stub_instructions':list(self.stub_instructions.values()),'mapped_original_pages':list(self.pages.values()),'records':self.records}


def main():
    fixtures=[]
    for null in (True,False):
        for j,state in enumerate([[0,0],[(1<<64)-1,1],[0x123456789abcdef0,0x9988776655443322]]):
            fixtures.append({'label':f'dispose_{"null" if null else "owned"}_{j}','mode':'dispose','null':null,'dispose_state':state,'stack_delta':j*16})
    for j,status in enumerate([0,1,0xffffffff,0xffff5a90]):fixtures.append({'label':f'create_wrapper_status_{status:08x}','mode':'create_wrapper','backend_status_u32':status,'stack_delta':j*16})
    fixtures.extend([{'label':'create_deep_first_boundary','mode':'create_deep'},
        {'label':'validate_zero_context','mode':'validate','context_u32':0},
        {'label':'import_zero_context_first_boundary','mode':'import','context_u32':0},
        {'label':'create_once_initializer_boundary','mode':'create_deep','continue_once':True},
        {'label':'validate_once_initializer_boundary','mode':'validate','context_u32':0,'continue_once':True},
        {'label':'import_once_initializer_boundary','mode':'import','context_u32':0,'continue_once':True}])
    fixtures.extend([{'label':'create_private_malloc_boundary','mode':'create_deep','continue_once':True,'allocator':'success'},
        {'label':'create_private_malloc_null','mode':'create_deep','continue_once':True,'allocator':'null'},
        {'label':'create_private_lock_initialized','mode':'create_deep','continue_once':True,'allocator':'success','model_locks':True},
        {'label':'import_private_lock_initialized','mode':'import','continue_once':True,'allocator':'success','model_locks':True}])
    fixtures.extend([{'label':'create_CoreFP_load_failure','mode':'create_deep','continue_once':True,'allocator':'success','model_locks':True,'dlopen':'null'},
        {'label':'create_CoreFP_load_success_boundary','mode':'create_deep','continue_once':True,'allocator':'success','model_locks':True,'dlopen':'success'},
        {'label':'import_CoreFP_load_success_boundary','mode':'import','continue_once':True,'allocator':'success','model_locks':True,'dlopen':'success'}])
    fixtures.extend([{'label':'create_CoreFP_symbol_absent','mode':'create_deep','continue_once':True,'allocator':'success','model_locks':True,'dlopen':'success','dlsym':'null'},
        {'label':'create_CoreFP_export_call','mode':'create_deep','continue_once':True,'allocator':'success','model_locks':True,'dlopen':'success','dlsym':'success'},
        {'label':'import_CoreFP_export_call','mode':'import','continue_once':True,'allocator':'success','model_locks':True,'dlopen':'success','dlsym':'success'}])
    fixtures.extend([{'label':'create_initial_CoreFP_return_zero','mode':'create_deep','continue_once':True,'allocator':'success','model_locks':True,'dlopen':'success','dlsym':'success','initial_export_status_u32':0},
        {'label':'create_initial_CoreFP_return_error','mode':'create_deep','continue_once':True,'allocator':'success','model_locks':True,'dlopen':'success','dlsym':'success','initial_export_status_u32':1},
        {'label':'import_initial_CoreFP_return_zero','mode':'import','continue_once':True,'allocator':'success','model_locks':True,'dlopen':'success','dlsym':'success','initial_export_status_u32':0}])
    rows=[Probe(f).run() for f in fixtures]
    functions={};pages={}
    for row in rows:
        ff=row.pop('original_functions');pp=row.pop('mapped_original_pages')
        row['original_function_starts']=[x['start'] for x in ff];row['mapped_original_page_addresses']=[x['address'] for x in pp]
        for x in ff:
            at=x['start'];assert at not in functions or functions[at]==x;functions[at]=x
        for x in pp:
            at=x['address'];assert at not in pages or pages[at]==x;pages[at]=x
    out={'scope':__doc__,'cache_uuid':Core().cache.uuid,'generator_sha256':sha(Path(__file__).read_bytes()),
        'reader_sha256':sha((ROOT/'ams_core_reader.py').read_bytes()),'source_contracts_sha256':sha((ROOT/'ams_core_contracts.json').read_bytes()),
        'CoreFP_library_inventory_sha256':sha((ROOT/'corefp_library_inventory.json').read_bytes()),
        'original_functions':list(functions.values()),'mapped_original_pages':list(pages.values()),
        'profiles':rows,'native_target_executed':False,'hardware_PAC_checked':False,'full_goal_complete':False}
    (ROOT/'ams_core_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
    for row in rows:print(json.dumps({'label':row['fixture']['label'],'reason':row['stop_reason'],'steps':row['steps'],'result_u32':hex(row['result_u32']),
        'last_boundary':next((e for e in reversed(row['records']) if e['kind']=='external_boundary'),None)}))


if __name__=='__main__':main()
