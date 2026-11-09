#!/usr/bin/env python3
"""Stateful original notifyd startup/registration/post/cancel interfaces.

Original universal functions and original cache collection functions execute in
one private bounded guest. External environment/kernel/dispatch APIs are explicit
fixtures; unknown interfaces/native instructions stop. No native target/service/
IPC/file/sandbox/entitlement operation. O(B+P+V+W) time/space per finite sequence.
"""
import base64
import bisect
import copy
import hashlib
import json
from pathlib import Path
import struct
import zlib
from unicorn import arm64_const as A
from unicorn import UC_HOOK_MEM_UNMAPPED
from probe_notifyd_ipc import Server,REQUEST,REPLY,request
from probe_adid_receiver import HEAP,STACK,BIND,DONE
from notifyd_ipc_reader import Notifyd,ROOT,sha,THIN_SHA,CS
from notify_ipc_reader import Notify
from bootpolicy_cache_reader import Dylib

SHARED=0x7e000000
MASK=(1<<64)-1

class Hybrid:
    def __init__(self,provider,cache):self.provider=provider;self.cache=cache
    def __getattr__(self,k):return getattr(self.provider,k)
    def read(self,a,n):
        if self.provider.base<=a<self.provider.base+0x20000:return self.provider.read(a,n)
        return self.cache.read(a,n)

class Session(Server):
    def __init__(self,d,f):
        super().__init__(d,{'effective_request_and_trailer_hex':request().hex(),'model_APIs':[],'instruction_budget':300000,**f})
        self.provider=d;self.cache=Notify();self.s=Hybrid(d,self.cache);self.pages={};self.next_alloc=HEAP+0x20000;self.allocations={};self.objects={};self.next_object=HEAP+0x70000;self.cache_functions={};self.context_epochs=[];self.pending_writes=[]
        path='/usr/lib/system/libsystem_collections.dylib';self.collection_lib=Dylib(self.cache.cache,path);self.cache.libs[path]=self.collection_lib;self.cache_exports={n:r['address'] for n,r in self.collection_lib.exports.items()}
        self.u.mem_map(HEAP+0x20000,0x60000);self.u.mem_write(HEAP+0x20000,b'\xa5'*0x60000);self.u.mem_map(SHARED,65536);self.u.mem_write(SHARED,bytes(65536));self.u.mem_write(HEAP+0x1000,b'/usr/sbin/notifyd\0');self.u.mem_write(HEAP+0x1800,struct.pack('<QQ',HEAP+0x1000,0))
        argv=['/usr/sbin/notifyd']+f.get('argv',[]);self.argc=len(argv);pointers=[]
        for j,value in enumerate(argv):
            raw=value.encode()+b'\0';assert len(raw)<=128 and j<16;at=HEAP+0x1000+j*128;self.u.mem_write(at,raw);pointers.append(at)
        self.u.mem_write(HEAP+0x1800,struct.pack('<'+'Q'*(len(pointers)+1),*pointers,0))
        for name,value in [('_mach_task_self_',0x5801),('_bootstrap_port',0x5802)]:self.u.mem_write(self.symbols[name],struct.pack('<I',value))
    def map_cache(self,a):
        page=a&~4095
        if page in self.pages:return
        raw=self.cache.read(page,4096);self.u.mem_map(page,4096);self.u.mem_write(page,raw);members=[]
        for at,p in self.cache.page_chains(page).items():
            if page<=at<page+4096:self.u.mem_write(at,struct.pack('<Q',int(p['target'],16)));members.append(p)
        self.pages[page]={'address':hex(page),'original_sha256':sha(raw),'materialized_sha256':sha(bytes(self.u.mem_read(page,4096))),'original_chain_members':members}
    def invalid(self,u,access,a,n,value,data):
        try:
            for page in range(a&~4095,(a+n+4095)&~4095,4096):self.map_cache(page)
            return True
        except Exception:return super().invalid(u,access,a,n,value,data)
    def string(self,p,limit=1024):
        raw=bytearray()
        for i in range(limit):
            try:b=bytes(self.u.mem_read(p+i,1))
            except Exception:self.map_cache(p+i);b=bytes(self.u.mem_read(p+i,1))
            if b==b'\0':return raw.decode(errors='replace')
            raw+=b
        raise ValueError('private bounded string exceeded')
    def write(self,u,access,a,n,value,data):
        if STACK<=a and a+n<=STACK+0x40000:return
        if HEAP<=a and a+n<=HEAP+0x80000 or SHARED<=a and a+n<=SHARED+65536:
            if hasattr(self,'allocations'):
                e={'kind':'original_owned_data_write','pc':hex(self.reg('pc')),'address':hex(a),'size_bytes':n,'value_hex':(value&((1<<(8*n))-1)).to_bytes(n,'little').hex()};self.records.append(e);self.pending_writes.append(e)
            return
        if hasattr(self,'collection_lib') and any(sec['segment'] in ['__DATA','__DATA_DIRTY'] and sec['address']<=a and a+n<=sec['address']+sec['size'] for sec in self.collection_lib.sections):return
        prior=len(self.records);result=super().write(u,access,a,n,value,data)
        if len(self.records)>prior and self.records[-1]['kind']=='original_private_global_write':self.pending_writes.append(self.records[-1])
        return result
    def read_hook(self,u,access,a,n,value,data):
        if SHARED<=a and a+n<=SHARED+65536:self.records.append({'kind':'original_shared_counter_read','pc':hex(self.reg('pc')),'offset_bytes':a-SHARED,'size_bytes':n,'bytes':bytes(self.u.mem_read(a,n)).hex()})
        return super().read_hook(u,access,a,n,value,data)
    def allocate(self,n,zero):
        if not 0<n<=65536 or self.next_alloc+n>HEAP+0x70000 or len(self.allocations)>=512:raise ValueError('bounded owned allocator extent')
        ptr=self.next_alloc;self.next_alloc=(ptr+n+15)&~15;raw=bytes(n) if zero else b'\xa5'*n;self.u.mem_write(ptr,raw);self.allocations[ptr]={'size_bytes':n,'freed':False};return ptr
    def api_write(self,a,raw,e):
        assert STACK<=a and a+len(raw)<=STACK+0x40000 or HEAP<=a and a+len(raw)<=HEAP+0x80000 or SHARED<=a and a+len(raw)<=SHARED+65536 or self.provider.base<=a<self.provider.base+0x20000
        self.u.mem_write(a,raw);e.setdefault('explicit_output_effects',[]).append({'address':hex(a),'bytes':raw.hex()})
    def api(self,im):
        name=im['name'];x=[self.reg('x'+str(j)) for j in range(8)];site=getattr(self,'last_source_branch',self.reg('lr')-4);e={'kind':'explicit_notifyd_API_model','name':name,'callsite':hex(site),'args_x0_x7':[hex(v) for v in x],'native_API_executed':False};self.records.append(e);f=self.fixture
        if name in self.cache_exports and name.startswith(('_os_set_','_os_map_')):
            target=self.cache_exports[name];e.update(kind='original_collection_function_transfer',original_cache_target=hex(target),cache_library_uuid=self.collection_lib.uuid);self.u.reg_write(A.UC_ARM64_REG_PC,target);return
        if name in ['_malloc_type_calloc','_malloc_type_malloc','_malloc_type_realloc']:
            n=x[0]*x[1] if name.endswith('calloc') else x[1] if name.endswith('realloc') else x[0];ptr=self.allocate(n,name.endswith('calloc'));e.update(result=hex(ptr),requested_size_bytes=n)
            if name.endswith('realloc') and x[0]:
                old=self.allocations.get(x[0]);assert old and not old['freed'];raw=bytes(self.u.mem_read(x[0],min(old['size_bytes'],n)));self.api_write(ptr,raw,e);old['freed']=True
            return self.finish_api(ptr)
        if name=='_free':
            if x[0]:assert x[0] in self.allocations and not self.allocations[x[0]]['freed'];self.allocations[x[0]]['freed']=True
            return self.finish_api(0)
        if name in ['_strdup']:
            value=self.string(x[0]);raw=value.encode()+b'\0';ptr=self.allocate(len(raw),False);self.api_write(ptr,raw,e);e.update(string=value,result=hex(ptr));return self.finish_api(ptr)
        if name in ['_bzero','__platform_bzero','_memset','__platform_memset']:
            n=x[1] if 'bzero' in name else x[2];assert n<=65536;self.api_write(x[0],bytes([0 if 'bzero' in name else x[1]&255])*n,e);return self.finish_api(x[0] if 'memset' in name else 0)
        if name in ['_memcpy','_memmove','__platform_memmove','__platform_memcpy','___memcpy_chk']:
            n=x[2];assert n<=65536
            if name=='___memcpy_chk':assert n<=x[3]
            try:raw=bytes(self.u.mem_read(x[1],n))
            except Exception:
                for page in range(x[1]&~4095,(x[1]+n+4095)&~4095,4096):self.map_cache(page)
                raw=bytes(self.u.mem_read(x[1],n))
            self.api_write(x[0],raw,e);return self.finish_api(x[0])
        if name in ['_strlen','__platform_strlen']:value=self.string(x[0]);e['string']=value;return self.finish_api(len(value.encode()))
        if name in ['_strcmp','__platform_strcmp','_strncmp','__platform_strncmp']:
            a=self.string(x[0]).encode();b=self.string(x[1]).encode();a=a[:x[2]] if 'ncmp' in name else a;b=b[:x[2]] if 'ncmp' in name else b;e.update(left=a.hex(),right=b.hex(),count_bytes=x[2] if 'ncmp' in name else None);return self.finish_api((a>b)-(a<b))
        if name=='_atoi':
            value=self.string(x[0]);assert value in ['0','1','2'];e['input']=value;return self.finish_api(int(value))
        if name=='___strlcat_chk':
            left=self.string(x[0]);right=self.string(x[1]);assert 0<x[2]<=x[3]<=1024;full=left.encode()+right.encode();raw=full[:x[2]-1]+b'\0';self.api_write(x[0],raw,e);e.update(left=left,right=right,result_length_bytes=len(full));return self.finish_api(len(full))
        if name=='_xpc_copy_entitlement_for_token':
            key=self.string(x[0]);choice=f.get('entitlements',{}).get(key);e.update(key=key,audit_token32_hex=bytes(self.u.mem_read(x[1],32)).hex(),fixture_value=choice)
            if choice is None:return self.finish_api(0)
            ptr=self.next_object;self.next_object+=64;self.objects[ptr]={'type':'bool','value':bool(choice),'key':key};e['result']=hex(ptr);return self.finish_api(ptr)
        if name=='_xpc_bool_get_value':
            obj=self.objects[x[0]];assert obj['type']=='bool';e['bool_value']=obj['value'];return self.finish_api(int(obj['value']))
        if name=='_xpc_release':e['modeled_effect']='external release request only';return self.finish_api(0)
        if name=='_snprintf':
            fmt=self.string(x[2]);assert fmt=='%s%d';a,b=struct.unpack('<QQ',self.u.mem_read(self.reg('sp'),16));num=b&0xffffffff;num=num-(1<<32) if num&(1<<31) else num;value=self.string(a)+str(num);raw=value.encode();assert 0<x[1]<=1024;self.api_write(x[0],raw[:x[1]-1]+b'\0',e);e.update(format=fmt,variadic_prefix=self.string(a),variadic_signed32=num,full_length_bytes=len(raw));return self.finish_api(len(raw))
        if name in ['_dispatch_assert_queue$V2','_dispatch_source_cancel','_dispatch_release']:
            e['modeled_effect']='external scheduling/lifetime request retained;not executed';return self.finish_api(0)
        if name=='_memchr':
            assert x[2]<=8192;raw=bytes(self.u.mem_read(x[0],x[2]));ix=raw.find(bytes([x[1]&255]));result=0 if ix<0 else x[0]+ix;e.update(source_bytes=raw.hex(),result=hex(result));return self.finish_api(result)
        if name in ['_notify_set_options','_os_trace_set_mode','_signal','_auditon','_setrlimit']:
            if name in ['_auditon','_setrlimit']:e['input16_hex']=bytes(self.u.mem_read(x[1],16)).hex()
            e['modeled_effect']='external process/library state not applied';return self.finish_api(0)
        if name=='_sandbox_init':e.update(profile=self.string(x[0]),result_u32=f.get('sandbox_init_result',0));return self.finish_api(f.get('sandbox_init_result',0))
        if name=='_mach_absolute_time':e['opaque_tick_value']=0x123456789;return self.finish_api(0x123456789)
        if name=='_getpagesize':return self.finish_api(f.get('page_size_bytes',16384))
        if name=='_getpid':return self.finish_api(f.get('server_pid',311))
        if name=='_bootstrap_check_in':e.update(service=self.string(x[1]),output_name_u32=0x5902);self.api_write(x[2],struct.pack('<I',0x5902),e);return self.finish_api(0)
        if name=='_mach_port_set_attributes':e.update(attributes_bytes=bytes(self.u.mem_read(x[3],x[4])).hex());return self.finish_api(0)
        if name=='_shm_open':
            e.update(object_name=self.string(x[0]),flags_u32=x[1],variadic_mode_u64=hex(int.from_bytes(self.u.mem_read(self.reg('sp'),8),'little')));result=-1 if x[1]==2 and f.get('shared_object_new',True) else 72;return self.finish_api(result)
        if name=='_ftruncate':e.update(length_bytes=x[1]);return self.finish_api(f.get('ftruncate_result',0))
        if name=='_mmap':
            assert x[:4]==[0,f.get('page_size_bytes',16384),3,1] and x[4:6]==[72,0];e.update(result=hex(SHARED));return self.finish_api(SHARED)
        if name in ['_close','_close$NOCANCEL','___close_nocancel']:assert x[0]==72;return self.finish_api(0)
        if name.startswith('_audit_token_to_'):
            token=struct.unpack('<8I',bytes(self.u.mem_read(x[0],32)));e['audit_words']=token
            if name=='_audit_token_to_au32':
                assert all(x[j]==0 for j in [1,2,3,4,5,7]) and int.from_bytes(self.u.mem_read(self.reg('sp'),8),'little')==0;self.api_write(x[6],struct.pack('<I',token[5]),e);return self.finish_api(0)
            field={'_audit_token_to_euid':1,'_audit_token_to_egid':2,'_audit_token_to_pid':5}[name];return self.finish_api(token[field])
        if name in ['_dispatch_workloop_create_inactive','_dispatch_source_create','_dispatch_mach_create_f','_xpc_event_publisher_create']:
            ptr=self.next_object;self.next_object+=64;assert self.next_object<=HEAP+0x80000;self.objects[ptr]={'API':name,'args':x};e['result']=hex(ptr)
            if name!='_dispatch_source_create':e['label']=self.string(x[0])
            return self.finish_api(ptr)
        if name in ['_dispatch_set_qos_class_fallback','_dispatch_activate','_dispatch_resume','_dispatch_set_context','_dispatch_source_set_event_handler_f','_dispatch_source_set_cancel_handler_f','_dispatch_source_set_timer','_dispatch_mach_connect','_xpc_event_publisher_activate','_xpc_event_publisher_set_throttling']:
            e['modeled_effect']='declaration retained;no scheduling or callback execution';return self.finish_api(0)
        if name in ['_dispatch_source_set_event_handler','_dispatch_source_set_cancel_handler','_dispatch_async','_xpc_event_publisher_set_handler','_xpc_event_publisher_set_error_handler']:
            e['block48_hex']=bytes(self.u.mem_read(x[1],48)).hex();e['modeled_effect']='callback retained;not invoked';return self.finish_api(0)
        if name=='_dispatch_time':return self.finish_api(0x123400)
        if name=='_dispatch_walltime':return self.finish_api(0x234500)
        if name=='_dispatch_main':return self.stop('original_startup_dispatch_main_boundary')
        if name=='_fopen':e.update(path=self.string(x[0]),mode=self.string(x[1]),result='NULL diagnostic-file fixture');return self.finish_api(0)
        if name=='_sandbox_check_by_audit_token':
            e.update(audit_token32_hex=bytes(self.u.mem_read(x[0],32)).hex(),operation=self.string(x[1]),filter_u32=x[2]);arg=int.from_bytes(self.u.mem_read(self.reg('sp'),8),'little');e['variadic_name']=self.string(arg);result=f.get('sandbox_post_result',0);e['result_signed32']=result;return self.finish_api(result)
        if name=='_stat':e.update(path=self.string(x[0]),result_signed32=-1);return self.finish_api(-1)
        if name=='_os_variant_has_internal_diagnostics':return self.finish_api(0)
        # Defer source-reviewed provider Mach/memchr/getpid models to frozen base.
        if name in ['_mach_port_construct','_mach_port_insert_right','_mach_port_request_notification','_mach_msg_destroy']:return super().api(im)
        return self.stop('opaque_notifyd_admission_API:'+name)
    def flush_writes(self):
        for e in self.pending_writes:
            raw=bytes(self.u.mem_read(int(e['address'],16),e['size_bytes']));e['actual_after_hex']=raw.hex()
            if e['kind']=='original_owned_data_write':e['value_hex']=raw.hex()
        self.pending_writes=[]
    def code(self,u,pc,n,data):
        self.flush_writes()
        if pc in self.binds:return super().code(u,pc,n,data)
        if self.provider.base<=pc<self.provider.base+0x20000:
            try:
                ins=next(CS.disasm(self.provider.read(pc,4),pc))
                if ins.mnemonic in ['b','bl'] and ins.op_str.startswith('#'):self.last_source_branch=pc
            except Exception:pass
            return super().code(u,pc,n,data)
        if pc==DONE:return self.stop('returned_to_private_fixture')
        meta=self.cache.external.get(pc)
        if meta and meta['library']!=self.collection_lib.path:
            return self.api({'name':meta['exact_exports'][0] if meta['exact_exports'] else '', 'original_cache_target':meta})
        self.steps+=1
        if self.steps>self.fixture.get('instruction_budget',300000):return self.stop('notifyd_admission_instruction_budget')
        owner=self.collection_lib if any(sec['name']=='__text' and sec['address']<=pc<sec['address']+sec['size'] for sec in self.collection_lib.sections) else None
        if owner is None:
            if not any(int(v['address'],16)<=pc<int(v['address'],16)+16 for v in self.cache.veneers.values()):
                try:self.cache.veneer(pc)
                except Exception:return self.stop('unknown_notifyd_cache_code:'+hex(pc))
        raw=self.cache.read(pc,4);ins=next(CS.disasm(raw,pc));self.instructions[pc]={'ea':hex(pc),'bytes':raw.hex(),'mnemonic':ins.mnemonic,'operands':ins.op_str};self.visited.append(pc)
        if owner:
            ix=bisect.bisect_right(owner.functions,pc)-1;a=owner.functions[ix];z=owner.functions[ix+1] if ix+1<len(owner.functions) else next(s['address']+s['size'] for s in owner.sections if s['name']=='__text');self.cache_functions[a]={'start':hex(a),'end':hex(z),'sha256':sha(self.cache.read(a,z-a)),'library':owner.path,'uuid':owner.uuid}
        m=ins.mnemonic;op=ins.op_str
        if m in ['b','bl'] and op.startswith('#'):self.last_source_branch=pc
        if m in ['braa','brab','blraa','blrab','braaz','brabz','blraaz','blrabz']:
            target=self.reg(op.split(', ')[0]);self.records.append({'kind':'PAC_bypassed_edge','pc':hex(pc),'target':hex(target),'hardware_PAC_validated':False})
            if m.startswith('bl'):self.u.reg_write(A.UC_ARM64_REG_LR,pc+4)
            self.u.reg_write(A.UC_ARM64_REG_PC,target);return
        if m.startswith(('pac','aut')):self.u.reg_write(A.UC_ARM64_REG_PC,pc+4);return
        if m in ['retab','retaa']:self.u.reg_write(A.UC_ARM64_REG_PC,self.reg('lr'));return
        if m in ['svc','hvc','smc','brk']:return self.stop('unexecuted_native_instruction:'+m)
    def invoke(self,label,entry,args):
        self.cache_functions={};r=super().invoke(label,entry,args)
        if 'records_zlib_base64' in r:r['records']=json.loads(zlib.decompress(base64.b64decode(r.pop('records_zlib_base64'))));r.pop('records_encoding',None)
        r.update(original_cache_functions=list(self.cache_functions.values()),original_materialized_cache_pages=list(self.pages.values()),owned_allocations=copy.deepcopy(self.allocations),owned_allocation_bytes_after={hex(a):bytes(self.u.mem_read(a,v['size_bytes'])).hex() for a,v in self.allocations.items()},shared_memory16384_after=bytes(self.u.mem_read(SHARED,16384)).hex(),external_objects_after=copy.deepcopy(self.objects),provider_DATA_after=[{'address':hex(seg['address']),'bytes':bytes(self.u.mem_read(seg['address'],seg['vm_size'])).hex()} for seg in self.provider.meta['segments'] if seg['name']=='__DATA']);return r


def main():
    d=Notifyd();f={'model_port_constructor':True,'model_port_request_notification':True};q=Session(d,f);r=q.invoke('startup',d.entry,[1,HEAP+0x1800]);Path('/tmp/notifyd_admission_exploration.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'stop':r['stop_reason'],'steps':r['steps'],'last':r['records'][-1] if r['records'] else None}),flush=True)

if __name__=='__main__':main()
