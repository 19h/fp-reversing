#!/usr/bin/env python3
"""Original libnotify exports/builders in private cache pages and API models.

Cold allocation executes the original context constructor. Unknown interfaces
and native instructions stop. No target/loader/Mach/notify/file operation.
O(P+K) private time/space,finite instruction and owned-allocation caps.
"""
import base64
import bisect
import copy
import hashlib
import json
from pathlib import Path
import struct
import zlib
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_UNMAPPED,UC_HOOK_MEM_WRITE,UC_HOOK_MEM_READ
from unicorn import arm64_const as A
from notify_ipc_reader import Notify,ROOT,CS,sha
from bootpolicy_cache_reader import Dylib

STACK=0x76000000
HEAP=0x77000000
DONE=0x78000000
CTX=HEAP+0x10000
SHMEM=HEAP+0x20000
MASK=(1<<64)-1


class IPC:
    def __init__(self,s,f):
        self.s=s;self.fixture=f;self.u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);self.pages={};self.visited=[];self.instructions={};self.functions={};self.records=[];self.steps=0;self.reason=None;self.pending=[];self.collections={};self.allocations={};self.next_alloc=HEAP+0x30000;self.context_ready=False
        for a,n in [(STACK,0x40000),(HEAP,0x80000),(DONE,4096)]:self.u.mem_map(a,n)
        self.sp=STACK+0x38000;self.u.reg_write(A.UC_ARM64_REG_SP,self.sp);self.u.reg_write(A.UC_ARM64_REG_LR,DONE);self.u.mem_write(HEAP,b'\xa5'*0x80000);self.u.mem_write(HEAP+0x1000,f.get('notification_name','com.apple.adid.midchangedV1').encode()+b'\0');self.u.mem_write(SHMEM,bytes(16384));self.u.mem_write(SHMEM,struct.pack('<I',f.get('server_pid',311)))
        self.u.mem_write(SHMEM+4,struct.pack('<I',f.get('initial_shared_counter',1)))
        self.external={int(r['address'],16):r for r in json.loads((ROOT/'notify_ipc_inventory.json').read_text())['external_bound_targets']};self.export_entries={r['address']:n for n,r in s.lib.exports.items()}
        self.allowed_libraries=[s.lib]
        if f.get('execute_original_collections'):
            path='/usr/lib/system/libsystem_collections.dylib';library=Dylib(s.cache,path);s.libs[path]=library;self.allowed_libraries.append(library)
        if f.get('execute_original_mig_string',True):
            path='/usr/lib/system/libsystem_kernel.dylib';library=Dylib(s.cache,path);s.libs[path]=library;self.allowed_libraries.append(library)
        self.u.hook_add(UC_HOOK_MEM_UNMAPPED,self.unmapped);self.u.hook_add(UC_HOOK_MEM_WRITE,self.write);self.u.hook_add(UC_HOOK_CODE,self.code);self.u.hook_add(UC_HOOK_MEM_READ,self.read_hook)
    def reg(self,n):return 0 if n in ['xzr','wzr'] else self.u.reg_read(getattr(A,'UC_ARM64_REG_'+n.upper()))
    def stop(self,why):self.reason=why;self.u.emu_stop()
    def finish(self,value=0):self.u.reg_write(A.UC_ARM64_REG_X0,value&MASK);self.u.reg_write(A.UC_ARM64_REG_PC,self.reg('lr'))
    def map(self,a):
        page=a&~4095
        if page in self.pages:return
        raw=self.s.read(page,4096);self.u.mem_map(page,4096);self.u.mem_write(page,raw);chains=[]
        for at,p in self.s.page_chains(page).items():
            if page<=at<page+4096:self.u.mem_write(at,struct.pack('<Q',int(p['target'],16)));chains.append(p)
        self.pages[page]={'address':hex(page),'original_sha256':sha(raw),'materialized_sha256':sha(bytes(self.u.mem_read(page,4096))),'original_chain_members':chains}
    def unmapped(self,u,access,a,n,value,data):
        try:
            for page in range(a&~4095,(a+n+4095)&~4095,4096):self.map(page)
            return True
        except Exception as e:self.records.append({'kind':'unresolved_private_cache_boundary','pc':hex(self.reg('pc')),'address':hex(a),'size_bytes':n,'detail':str(e),'native_fault_inferred':False});self.reason='unresolved_private_cache_boundary';return False
    def string(self,a,limit=1024):
        result=bytearray()
        for j in range(limit):
            if not HEAP<=a+j<HEAP+0x80000 and not STACK<=a+j<STACK+0x40000:self.map(a+j)
            b=bytes(self.u.mem_read(a+j,1))
            if b==b'\0':return result.decode()
            result+=b
        raise ValueError('IPC private string bound')
    def read_hook(self,u,access,a,n,value,data):
        if SHMEM<=a and a+n<=SHMEM+16384:self.records.append({'kind':'original_shared_memory_read','pc':hex(self.reg('pc')),'address':hex(a),'offset_bytes':a-SHMEM,'size_bytes':n,'bytes':bytes(self.u.mem_read(a,n)).hex()})
    def write(self,u,access,a,n,value,data):
        if STACK<=a and a+n<=STACK+0x40000 or HEAP<=a and a+n<=HEAP+0x80000:return
        if any(sec['segment'] in ['__DATA','__DATA_DIRTY'] and sec['address']<=a and a+n<=sec['address']+sec['size'] for lib in self.allowed_libraries for sec in lib.sections):self.records.append({'kind':'original_private_global_write','pc':hex(self.reg('pc')),'address':hex(a),'size_bytes':n,'value':hex(value&((1<<(8*n))-1))});return
        self.stop('unowned_original_write_guard:'+hex(a))
    def api(self,meta):
        names=meta['exact_exports'];name=names[0] if names else '';x=[self.reg('x'+str(j)) for j in range(8)];site=getattr(self,'last_client_branch',self.reg('lr')-4)
        e={'kind':'opaque_original_API_boundary','name':name,'exact_exports':names,'callsite':hex(site),'args_x0_x7':[hex(v) for v in x],'native_API_executed':False};self.records.append(e);f=self.fixture
        if name=='__os_alloc_once':
            if x[1:3]!=[600,0x1805984f4] or self.context_ready:return self.stop('unreviewed_notify_once_shape')
            self.u.mem_write(CTX,bytes(600));marker=DONE+0x100+16*len(self.pending);self.pending.append({'kind':'context','marker':marker,'source_return':self.reg('lr'),'entry':x[0]});e.update(kind='modeled_original_constructor_callback',constructor=hex(x[2]),context=hex(CTX));self.u.reg_write(A.UC_ARM64_REG_X0,CTX);self.u.reg_write(A.UC_ARM64_REG_LR,marker);self.u.reg_write(A.UC_ARM64_REG_PC,x[2]);return
        if name=='_dispatch_once':
            old=int.from_bytes(self.u.mem_read(x[0],8),'little');e.update(kind='modeled_once_API',token=hex(x[0]),old_u64=hex(old),native_concurrency_validated=False)
            if old==MASK:return self.finish(0)
            if old!=0:return self.stop('notify_once_in_progress_boundary')
            if not STACK<=x[1]<STACK+0x40000 and not HEAP<=x[1]<HEAP+0x80000:
                for page in range(x[1]&~4095,(x[1]+32+4095)&~4095,4096):self.map(page)
            callback=int.from_bytes(self.u.mem_read(x[1]+16,8),'little');marker=DONE+0x100+16*len(self.pending);self.pending.append({'kind':'block','marker':marker,'source_return':self.reg('lr'),'entry':x[0]});e['original_block_callback']=hex(callback);self.u.reg_write(A.UC_ARM64_REG_X0,x[1]);self.u.reg_write(A.UC_ARM64_REG_LR,marker);self.u.reg_write(A.UC_ARM64_REG_PC,callback);return
        if name.startswith('_os_set_') and name.endswith('_init') or name=='_os_map_64_init':
            self.collections[x[0]]={'kind':name,'items':{}};e.update(kind='modeled_collection_API',container=hex(x[0]));return self.finish(0)
        if name.startswith('_os_set_') and any(name.endswith('_'+suffix) for suffix in ['find','insert','delete']):
            container=self.collections.get(x[0])
            if container is None:return self.stop('unowned_collection_container')
            suffix=name.rsplit('_',1)[1];typ='str' if '_str_' in name else '32' if '_32_' in name else '64'
            if suffix in ['find','delete']:
                key=self.string(x[1]) if typ=='str' else x[1]&((1<<int(typ))-1);result=container['items'].get(str(key),0)
                if suffix=='delete':container['items'].pop(str(key),None)
            else:
                ptr=x[1];key=self.string(int.from_bytes(self.u.mem_read(ptr,8),'little')) if typ=='str' else int.from_bytes(self.u.mem_read(ptr,int(typ)//8),'little')
                if suffix=='insert':container['items'][str(key)]=ptr;result=0
                else:result=container['items'].pop(str(key),0)
            e.update(kind='modeled_collection_API',key=key,result=hex(result));return self.finish(result)
        if name in ['_os_unfair_lock_lock_with_options','_os_unfair_lock_unlock','_os_unfair_lock_assert_owner']:
            e.update(kind='modeled_sequential_lock_API',native_concurrency_validated=False);return self.finish(0)
        if name in ['__platform_strncmp','_strncmp']:
            a=self.string(x[0]);b=self.string(x[1]);left=a.encode()[:x[2]];right=b.encode()[:x[2]];value=(left>right)-(left<right);e.update(kind='modeled_bounded_string_API',left=a,right=b,count_bytes=x[2]);return self.finish(value)
        if name in ['__platform_strlen','_strlen']:value=self.string(x[0]);e.update(kind='modeled_bounded_string_API',string=value,length_bytes=len(value.encode()));return self.finish(len(value.encode()))
        if name in ['__platform_strcmp','_strcmp']:
            left=self.string(x[0]);right=self.string(x[1]);e.update(kind='modeled_bounded_string_API',left=left,right=right);return self.finish((left>right)-(left<right))
        if name=='__dyld_is_memory_immutable':
            if not (HEAP<=x[0] and x[0]+x[1]<=HEAP+0x80000):return self.stop('notify_immutable_query_extent')
            e.update(kind='modeled_owned_memory_query',result_bool=False,scope='owned mutable guest heap');return self.finish(0)
        if name in ['__platform_memmove','__platform_memcpy','_memmove','_memcpy']:
            if x[2]>8192 or not (HEAP<=x[0] and x[0]+x[2]<=HEAP+0x80000 or STACK<=x[0] and x[0]+x[2]<=STACK+0x40000):return self.stop('notify_copy_extent_guard')
            if not HEAP<=x[1]<HEAP+0x80000 and not STACK<=x[1]<STACK+0x40000:
                for page in range(x[1]&~4095,(x[1]+x[2]+4095)&~4095,4096):self.map(page)
            raw=bytes(self.u.mem_read(x[1],x[2]));self.u.mem_write(x[0],raw);e.update(kind='modeled_bounded_copy_API',size_bytes=x[2],source_bytes=raw.hex());return self.finish(x[0])
        if name in ['_mig_strncpy','_mig_strncpy_zerofill']:
            raw=self.string(x[1]).encode()+b'\0';bound=x[2]
            if not 0<bound<=8192:return self.stop('unreviewed_mig_string_extent')
            raw=raw[:bound];raw=raw[:-1]+b'\0' if raw[-1]!=0 else raw;self.u.mem_write(x[0],raw);e.update(kind='modeled_mig_name_copy',bytes=raw.hex(),bound_bytes=bound);return self.finish(len(raw))
        if name in ['_mig_get_special_reply_port','_mig_get_reply_port']:e.update(kind='modeled_reply_port_API',result_name_u32=0x5901);return self.finish(0x5901)
        if name=='_voucher_mach_msg_set':e.update(kind='modeled_voucher_API',message_pointer=hex(x[0]),output_effects='none');return self.finish(0)
        if name=='_mach_msg':
            if not 24<=x[2]<=8192:return self.stop('unreviewed_mach_send_extent')
            raw=bytes(self.u.mem_read(x[0],x[2]));mid=int.from_bytes(raw[20:24],'little');e.update(kind='original_notify_mach_message_boundary',send_bytes=raw.hex(),send_size_bytes=x[2],receive_size_bytes=x[3],receive_name_u32=x[4]&0xffffffff,options_u32=x[1]&0xffffffff,message_id_u32=mid)
            if str(mid) in f.get('oneway_result_by_id',{}):
                if x[3]!=0 or x[4]!=0:return self.stop('notify_oneway_shape_guard')
                result=f['oneway_result_by_id'][str(mid)]&0xffffffff;e.update(kind='explicit_notify_oneway_transport_model',kernel_result_u32=result);return self.finish(result)
            replies=f.get('reply_by_id',{})
            if str(mid) not in replies:return self.stop('opaque_mach_msg_boundary')
            reply=bytes.fromhex(replies[str(mid)])
            if len(reply)>x[3]:return self.stop('notify_reply_capacity_guard')
            self.u.mem_write(x[0],reply);e.update(kind='explicit_notify_mach_reply_model',reply_bytes=reply.hex(),kernel_result_u32=0);return self.finish(0)
        if name in ['_malloc_type_calloc','_malloc_type_malloc']:
            n=x[0]*x[1] if name.endswith('calloc') else x[0]
            if not 0<n<=65536 or self.next_alloc+n>HEAP+0x70000 or len(self.allocations)>=64:return self.stop('notify_allocator_extent_guard')
            ptr=self.next_alloc;self.next_alloc=(ptr+n+15)&~15;self.u.mem_write(ptr,bytes(n) if name.endswith('calloc') else b'\xa5'*n);self.allocations[ptr]={'size_bytes':n,'freed':False};e.update(kind='modeled_owned_allocator',result=hex(ptr),size_bytes=n);return self.finish(ptr)
        if name=='_free':
            if x[0] and x[0] not in self.allocations:return self.stop('unowned_notify_free_boundary')
            if x[0]:self.allocations[x[0]]['freed']=True
            e.update(kind='modeled_owned_free');return self.finish(0)
        if '_getpid' in names:e.update(kind='modeled_process_id_API',result=2117);return self.finish(2117)
        if name=='_bootstrap_look_up2':
            e.update(kind='modeled_bootstrap_lookup_API',service=self.string(x[1]),output_name_u32=0x5902);self.u.mem_write(x[2],struct.pack('<I',0x5902));return self.finish(0)
        if name=='_xpc_copy_entitlement_for_token':e.update(kind='modeled_entitlement_query_API',key=self.string(x[0]),token_pointer=hex(x[1]),result='NULL fixture;effective entitlement unknown');return self.finish(0)
        if name=='__Block_object_dispose':
            if x[1]!=8 or not STACK<=x[0]<STACK+0x3ffd0:return self.stop('unreviewed_Block_dispose_shape')
            e.update(kind='modeled_stack_byref_dispose',before48=bytes(self.u.mem_read(x[0],48)).hex(),output_effects='none;original stack byref remains readable');return self.finish(0)
        if name=='_os_variant_has_internal_diagnostics':e.update(kind='modeled_environment_API',subsystem=self.string(x[0]),result_bool=f.get('internal_diagnostics',False));return self.finish(int(f.get('internal_diagnostics',False)))
        if name=='__dispatch_is_multithreaded':e.update(kind='modeled_environment_API',result_bool=f.get('multithreaded',False));return self.finish(int(f.get('multithreaded',False)))
        if name=='_shm_open':
            key=self.string(x[0]);e.update(kind='modeled_notification_shm_open',object_name=key,flags_u32=x[1]&0xffffffff,first_variadic_stack_u64=hex(int.from_bytes(self.u.mem_read(self.reg('sp'),8),'little')),result_fd_signed32=72)
            if key!='apple.shm.notification_center' or x[1]!=0:return self.stop('unreviewed_notify_shm_open_shape')
            return self.finish(72)
        if name=='_mmap':
            if x[:4]!=[0,16384,1,1] or x[4]!=72 or x[5]!=0:return self.stop('unreviewed_notify_shm_mapping_shape')
            e.update(kind='modeled_notification_shared_mapping',result=hex(SHMEM),length_bytes=16384,PROT_READ=True,MAP_SHARED=True);return self.finish(SHMEM)
        if name in ['_close','___close_nocancel','_close$NOCANCEL']:
            if x[0]!=72:return self.stop('unowned_notify_file_close')
            e.update(kind='modeled_notification_shm_close',fd_signed32=72);return self.finish(0)
        return self.stop('opaque_original_API_boundary:'+name)
    def code(self,u,pc,n,data):
        self.steps+=1
        if self.steps>self.fixture.get('instruction_budget',200000):return self.stop('notify_instruction_budget_guard')
        if pc==DONE:return self.stop('returned_to_private_fixture')
        if self.pending and pc==self.pending[-1]['marker']:
            pending=self.pending.pop();self.u.reg_write(A.UC_ARM64_REG_LR,pending['source_return'])
            if pending['kind']=='context':self.u.mem_write(pending['entry'],struct.pack('<QQ',MASK,CTX));self.context_ready=True;self.records.append({'kind':'modeled_original_constructor_return','constructor_completed':True,'context':hex(CTX),'once_entry':hex(pending['entry']),'native_once_semantics_validated':False});return self.finish(CTX)
            self.u.mem_write(pending['entry'],struct.pack('<Q',MASK));self.records.append({'kind':'modeled_original_once_block_return','once_entry':hex(pending['entry']),'native_once_semantics_validated':False});return self.finish(0)
        if pc in self.s.external:self.external[pc]=self.s.external[pc]
        owner=next((lib for lib in self.allowed_libraries if any(sec['name']=='__text' and sec['address']<=pc<sec['address']+sec['size'] for sec in lib.sections)),None)
        if pc in self.external:
            meta=self.external[pc];original_collection=self.fixture.get('execute_original_collections') and meta['library']=='/usr/lib/system/libsystem_collections.dylib';original_string=self.fixture.get('execute_original_mig_string',True) and '_mig_strncpy_zerofill' in meta['exact_exports']
            if not (original_collection or original_string):return self.api(meta)
        if owner is None:
            if not any(int(v['address'],16)<=pc<int(v['address'],16)+16 for v in self.s.veneers.values()):
                try:self.s.veneer(pc)
                except Exception:return self.stop('unknown_notify_code_guard:'+hex(pc))
        raw=self.s.read(pc,4);ins=next(CS.disasm(raw,pc));self.instructions[pc]={'ea':hex(pc),'bytes':raw.hex(),'mnemonic':ins.mnemonic,'operands':ins.op_str};self.visited.append(pc)
        if owner is not None:
            ix=bisect.bisect_right(owner.functions,pc)-1;a=owner.functions[ix];z=owner.functions[ix+1] if ix+1<len(owner.functions) else next(sec['address']+sec['size'] for sec in owner.sections if sec['name']=='__text')
            if a not in self.functions:self.functions[a]={'start':hex(a),'end':hex(z),'sha256':sha(self.s.read(a,z-a)),'library':owner.path,'uuid':owner.uuid}
        m=ins.mnemonic;op=ins.op_str
        if m in ['b','bl'] and op.startswith('#'):
            target=int(op[1:],16)
            if owner is not None and not any(sec['name']=='__text' and sec['address']<=target<sec['address']+sec['size'] for sec in owner.sections):self.last_client_branch=pc
        if m in ['svc','hvc','smc','brk']:return self.stop('unexecuted_native_instruction:'+m)
        if m in ['braa','brab','blraa','blrab','braaz','brabz','blraaz','blrabz']:
            regs=op.split(', ');target=self.reg(regs[0]);self.last_branch=pc;self.records.append({'kind':'PAC_bypassed_edge','pc':hex(pc),'target':hex(target),'link':m.startswith('bl'),'hardware_PAC_validated':False})
            if m.startswith('bl'):self.u.reg_write(A.UC_ARM64_REG_LR,pc+4)
            self.u.reg_write(A.UC_ARM64_REG_PC,target);return
        if m.startswith(('pac','aut')):self.u.reg_write(A.UC_ARM64_REG_PC,pc+4);return
        if m in ['retab','retaa']:self.u.reg_write(A.UC_ARM64_REG_PC,self.reg('lr'));return
        if m.startswith('ldadd'):
            src,dst,mem=op.split(', ');p=self.reg(mem.strip('[]'));n=4 if src.startswith('w') else 8;old=int.from_bytes(self.u.mem_read(p,n),'little');new=(old+self.reg(src))&((1<<(8*n))-1);self.u.mem_write(p,new.to_bytes(n,'little'));self.u.reg_write(getattr(A,'UC_ARM64_REG_'+dst.upper()),old);self.records.append({'kind':'modeled_sequential_original_atomic_add','pc':hex(pc),'address':hex(p),'size_bytes':n,'before':old,'after':new,'native_concurrency_validated':False});self.u.reg_write(A.UC_ARM64_REG_PC,pc+4)
        if m=='ldapr':
            dst,mem=op.split(', ');p=self.reg(mem.strip('[]'));n=4 if dst.startswith('w') else 8;value=int.from_bytes(self.u.mem_read(p,n),'little');self.u.reg_write(getattr(A,'UC_ARM64_REG_'+dst.upper()),value);self.records.append({'kind':'modeled_sequential_original_acquire_load','pc':hex(pc),'address':hex(p),'size_bytes':n,'value':value,'native_concurrency_validated':False});self.u.reg_write(A.UC_ARM64_REG_PC,pc+4)
    def invoke(self,label,entry,args,shared_counter=None):
        if self.pending:raise ValueError('unfinished original callback')
        if shared_counter is not None:self.u.mem_write(SHMEM+4,struct.pack('<I',shared_counter))
        self.fixture={**self.fixture,'label':label,'entry':entry,'args':args,'declared_external_shared_counter_update':shared_counter}
        self.records=[];self.visited=[];self.instructions={};self.functions={};self.reason=None;self.steps=0
        self.u.reg_write(A.UC_ARM64_REG_SP,self.sp);self.u.reg_write(A.UC_ARM64_REG_LR,DONE)
        return copy.deepcopy(self.run())
    def run(self):
        for j,value in enumerate(self.fixture['args']):self.u.reg_write(A.UC_ARM64_REG_X0+j,value)
        try:self.u.emu_start(self.fixture['entry'],DONE+4,count=self.fixture.get('instruction_budget',200000)+1)
        except Exception as e:
            if self.reason is None:self.reason='private_notify_guest_exception:'+str(e)
        h=hashlib.sha256()
        for pc in self.visited:h.update(struct.pack('<Q',pc));h.update(self.s.read(pc,4))
        return {'fixture':self.fixture,'stop_reason':self.reason,'steps':self.steps,'result_u32':self.reg('w0'),'records':self.records,'visited_original_instructions_zlib_base64':base64.b64encode(zlib.compress(b''.join(struct.pack('<Q',pc) for pc in self.visited))).decode(),'visited_original_instruction_count':len(self.visited),'ordered_original_instruction_sha256':h.hexdigest(),'original_functions':list(self.functions.values()),'original_instruction_records':list(self.instructions.values()),'original_materialized_pages':list(self.pages.values()),'context600_bytes':bytes(self.u.mem_read(CTX,600)).hex(),'owned_allocator_final':self.allocations,'owned_allocator_bytes_after':{hex(a):bytes(self.u.mem_read(a,v['size_bytes'])).hex() for a,v in self.allocations.items()},'collections_final':self.collections,'token_output_u32':int.from_bytes(self.u.mem_read(HEAP+0x2000,4),'little'),'check_output_u32':int.from_bytes(self.u.mem_read(HEAP+0x2010,4),'little'),'shared_slot1_u32':int.from_bytes(self.u.mem_read(SHMEM+4,4),'little'),'stack_balanced':self.reg('sp')==self.sp,'native_target_executed':False,'native_transaction_executed':False,'full_goal_complete':False}


def base_fixture(s,**kw):
    ndr=bytes.fromhex('0000000001000000');reply=struct.pack('<6I',0,48,0,0x5901,0,1123)+ndr+struct.pack('<4I',0,3,311,0);registration=struct.pack('<6I',0,56,0,0x5901,0,1112)+ndr+struct.pack('<IIIQI',0,16384,1,0x1122334455667788,0);check=struct.pack('<6I',0,44,0,0x5901,0,1102)+ndr+struct.pack('<3I',0,1,0)
    f={'label':'cold_register_check','entry':s.lib.exports['_notify_register_check']['address'],'args':[HEAP+0x1000,HEAP+0x2000],'instruction_budget':200000,'execute_original_collections':True,'initial_shared_counter':1,'reply_by_id':{'1023':reply.hex(),'1012':registration.hex(),'1002':check.hex()},'oneway_result_by_id':{'1009':0,'1016':0}};f.update(kw);return f


def run_sequence(s,case):
    f=base_fixture(s,**case.get('fixture',{}));q=IPC(s,f);rows=[]
    for step in case['calls']:
        args=step['args'];r=q.invoke(step['label'],s.lib.exports[step['export']]['address'],args,step.get('shared_counter'))
        rows.append(r)
        if r['stop_reason']!='returned_to_private_fixture':break
    return {'case':case,'calls':rows}


def main():
    s=Notify();reg={'label':'register','export':'_notify_register_check','args':[HEAP+0x1000,HEAP+0x2000]};check=lambda label,**kw:{'label':label,'export':'_notify_check','args':[2,HEAP+0x2010],**kw};post={'label':'post','export':'_notify_post','args':[HEAP+0x1000]};cancel={'label':'cancel','export':'_notify_cancel','args':[2]}
    cases=[]
    lifecycle=[reg,check('initial'),check('unchanged'),check('external_update',shared_counter=2),check('unchanged_after_update'),post,check('post_without_server_update'),cancel,check('cancelled'),cancel]
    for name in ['com.apple.adid.midchangedV1','com.apple.adid.midchangedV1.5','com.apple.adid.midchangedV3']:
        cases.append({'label':'lifecycle_'+name,'fixture':{'notification_name':name},'calls':lifecycle})
    for value in [0,1,0xffffffff]:cases.append({'label':'initial_counter_'+str(value),'fixture':{'initial_shared_counter':value},'calls':[reg,check('initial'),check('same'),check('wrap_or_update',shared_counter=(value+1)&0xffffffff)]})
    cases.append({'label':'counter_full_wrap_alias','calls':[reg,check('initial'),check('same_after_2pow32_posts',shared_counter=1)]})
    cases.append({'label':'post_transport_failure','fixture':{'oneway_result_by_id':{'1009':0x10000003,'1016':0}},'calls':[reg,post]})
    cases.append({'label':'cancel_transport_failure','fixture':{'oneway_result_by_id':{'1009':0,'1016':0x10000003}},'calls':[reg,cancel,check('after_cancel')]})
    cases.append({'label':'opaque_initial_transport','fixture':{'reply_by_id':{}},'calls':[reg]})
    for label,args in [('null_name',[0,HEAP+0x2000]),('null_token_output',[HEAP+0x1000,0])]:cases.append({'label':label,'calls':[{**reg,'args':args}]})
    for token in [0,1,3,0xffffffff]:cases.append({'label':'invalid_token_'+str(token),'calls':[reg,{'label':'invalid_check','export':'_notify_check','args':[token,HEAP+0x2010]}]})
    cases.append({'label':'null_check_output','calls':[reg,{'label':'null_out','export':'_notify_check','args':[2,0]}]})
    cases.append({'label':'post_uncached_name','calls':[post]})
    for count in [1,511,512,513]:cases.append({'label':'name_length_'+str(count),'fixture':{'notification_name':'a'*count},'calls':[reg]})
    for version in [0,2,3,4,0xffffffff]:
        f=base_fixture(s);raw=bytearray.fromhex(f['reply_by_id']['1023']);struct.pack_into('<I',raw,36,version);f['reply_by_id']['1023']=raw.hex();cases.append({'label':'checkin_version_'+str(version),'fixture':{'reply_by_id':f['reply_by_id']},'calls':[reg]})
    for label,off,value in [('bad_reply_id',20,1122),('complex_reply',0,0x80000000),('short_reply_size',4,47),('checkin_kernel_status',32,5),('checkin_app_status',44,5)]:
        f=base_fixture(s);raw=bytearray.fromhex(f['reply_by_id']['1023']);struct.pack_into('<I',raw,off,value);f['reply_by_id']['1023']=raw.hex();cases.append({'label':label,'fixture':{'reply_by_id':f['reply_by_id']},'calls':[reg]})
    f=base_fixture(s);raw=bytearray.fromhex(f['reply_by_id']['1012']);struct.pack_into('<II',raw,36,0xffffffff,0xffffffff);f['reply_by_id']['1012']=raw.hex();cases.append({'label':'server_no_shared_memory','fixture':{'reply_by_id':f['reply_by_id']},'calls':[reg,check('rpc_check'),cancel]})
    cases.append({'label':'duplicate_registration','calls':[reg,{**reg,'label':'second_register'},check('token2_check'),{'label':'token3_check','export':'_notify_check','args':[3,HEAP+0x2010]},cancel,{'label':'cancel3','export':'_notify_cancel','args':[3]}]})
    rows=[run_sequence(s,case) for case in cases];functions={};instructions={};pages={}
    for case in rows:
        for r in case['calls']:
            for v in r.pop('original_functions'):functions[v['start']]=v
            for v in r.pop('original_instruction_records'):instructions[v['ea']]=v
            for v in r.pop('original_materialized_pages'):pages[v['address']]=v
    out={'scope':__doc__,'cache_uuid':s.cache.uuid,'library_uuid':s.lib.uuid,'generator_sha256':sha(Path(__file__).read_bytes()),'dependencies':{n:sha((ROOT/n).read_bytes()) for n in ['notify_ipc_reader.py','notify_ipc_inventory.json','bootpolicy_cache_reader.py']},'cases':rows,'original_functions':list(functions.values()),'original_instruction_records':list(instructions.values()),'original_materialized_pages':list(pages.values()),'native_target_executed':False,'native_transaction_executed':False,'full_goal_complete':False};(ROOT/'notify_ipc_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
    for case in rows:
        print(json.dumps({'label':case['case']['label'],'calls':[{'label':r['fixture']['label'],'stop':r['stop_reason'],'return':r['result_u32'],'changed':r['check_output_u32'],'steps':r['steps'],'messages':[e['message_id_u32'] for e in r['records'] if 'message_id_u32' in e],'last':r['records'][-1].get('name') if r['records'] else None} for r in case['calls']]}),flush=True)

if __name__=='__main__':main()
