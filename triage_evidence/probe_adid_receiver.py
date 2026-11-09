#!/usr/bin/env python3
"""Original adid functions in a bounded private Unicorn guest.

File bytes and independently decoded format1 chains supply code/data. Explicit
fixtures model selected APIs; others stop. PAC is bypassed, never authenticated.
No native target/loader/IPC/API executes. O(C*(B+F+K)) time, O(B+F+K) space.
"""
import hashlib
import base64
import json
import re
from pathlib import Path
import struct
import zlib
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_WRITE,UC_HOOK_MEM_READ,UC_HOOK_MEM_INVALID
from unicorn import arm64_const as A
from adid_reader import Adid,ROOT,CS,sha,THIN_SHA

STACK=0x7a000000;HEAP=0x7b000000;BIND=0x7c000000;DONE=0x7d000000;MAPPING=0x7e000000
MASK=(1<<64)-1


class Probe:
    def __init__(self,s,f,seed=None):
        self.s=s;self.fixture=f;self.u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);self.records=[];self.visited=[];self.instructions={};self.functions={};self.reason=None;self.steps=0;self.last_edge=None;self.mappings=[]
        for seg in s.meta['segments']:
            if seg['name']=='__PAGEZERO' or not seg['vm_size']:continue
            self.u.mem_map(seg['address'],(seg['vm_size']+4095)&~4095)
            if seg['file_size']:self.u.mem_write(seg['address'],s.data[seg['file_offset']:seg['file_offset']+seg['file_size']])
        for at,n in [(STACK,0x40000),(HEAP,0x20000),(BIND,0x10000),(DONE,4096)]:self.u.mem_map(at,n)
        self.binds={};self.symbols={im['name']:BIND+im['ordinal']*0x100 for im in s.imports}
        for at,p in s.decoded.items():
            if p['bind']:
                im=p['import'];target=self.symbols[im['name']]+p['total_addend'];self.binds[self.symbols[im['name']]]=im
                if im['name']=='___stack_chk_guard':self.u.mem_write(self.symbols[im['name']],struct.pack('<Q',0x9012345678abcdef))
                if im['name'].startswith('_k'):
                    self.u.mem_write(self.symbols[im['name']],struct.pack('<Q',HEAP+0x10000+im['ordinal']*16))
            else:target=int(p['target'],16)
            self.u.mem_write(at,struct.pack('<Q',target&MASK))
        self.sp=STACK+0x38000+f.get('stack_delta',0);self.u.reg_write(A.UC_ARM64_REG_SP,self.sp);self.u.reg_write(A.UC_ARM64_REG_LR,DONE)
        self.u.mem_write(HEAP,b'\xa5'*0x20000)
        self.block=HEAP+0x100;self.event=HEAP+0x400;self.connection=HEAP+0x800;self.queue=HEAP+0xc00
        self.u.mem_write(self.block+32,struct.pack('<Q',self.connection))
        if seed:
            for start,raw,is_mapping in seed:
                if is_mapping:self.u.mem_map(start,len(raw));self.mappings.append((start,len(raw)))
                self.u.mem_write(start,raw)
        for reg,v in f.get('registers',{}).items():self.u.reg_write(getattr(A,'UC_ARM64_REG_'+reg.upper()),v)
        self.text=next(x for x in s.meta['sections'] if x['section']=='__text')
        self.u.hook_add(UC_HOOK_CODE,self.code);self.u.hook_add(UC_HOOK_MEM_WRITE,self.write);self.u.hook_add(UC_HOOK_MEM_READ,self.read_hook);self.u.hook_add(UC_HOOK_MEM_INVALID,self.invalid)
    def reg(self,n):return 0 if n in ('xzr','wzr') else self.u.reg_read(getattr(A,'UC_ARM64_REG_'+n.upper()))
    def stop(self,why):self.reason=why;self.u.emu_stop()
    def string(self,p,limit=512):
        raw=bytearray()
        for i in range(limit):
            b=bytes(self.u.mem_read(p+i,1))
            if b==b'\0':return raw.decode(errors='replace')
            raw+=b
        raise ValueError('private string budget')
    def write(self,u,access,a,n,value,data):
        if STACK<=a and a+n<=STACK+0x40000 or HEAP<=a and a+n<=HEAP+0x20000:return
        if any(start<=a and a+n<=start+size for start,size in self.mappings):return
        if any(seg['name']=='__DATA' and seg['address']<=a and a+n<=seg['address']+seg['vm_size'] for seg in self.s.meta['segments']):
            self.records.append({'kind':'original_private_global_write','pc':hex(self.reg('pc')),'address':hex(a),'size_bytes':n,'value':hex(value&((1<<(8*n))-1))});return
        self.stop('unowned_write_guard:'+hex(a))
    def read_hook(self,u,access,a,n,value,data):
        if a<HEAP+0x2040 and HEAP+0x2000<a+n:
            self.records.append({'kind':'original_payload_read','pc':hex(self.reg('pc')),'address':hex(a),'size_bytes':n,'bytes':bytes(self.u.mem_read(a,n)).hex()})
    def invalid(self,u,access,a,n,value,data):
        self.records.append({'kind':'unresolved_private_memory_boundary','pc':hex(self.reg('pc')),'access':access,'address':hex(a),'size_bytes':n,
            'x13':hex(self.reg('x13')),'x21':hex(self.reg('x21')),'native_fault_inferred':False});self.stop('unresolved_private_memory_boundary');return False
    def finish_api(self,result=0):self.u.reg_write(A.UC_ARM64_REG_X0,result&MASK);self.u.reg_write(A.UC_ARM64_REG_PC,self.reg('lr'))
    def api(self,im):
        name=im['name'];args=[self.reg('x'+str(j)) for j in range(8)];lr=self.reg('lr');site=lr-4
        if not self.s.base<=site<self.s.base+len(self.s.data):site=int(self.last_edge['pc'],16)
        event={'kind':'opaque_API_boundary','name':name,'import':im,'callsite':hex(site),'args_x0_x7':[hex(v) for v in args],'native_API_executed':False}
        if name in ('_sysctlbyname','_xpc_connection_create_mach_service','_os_transaction_create','_lstat','_statfs','_open','_getenv'):event['name_string']=self.string(args[0])
        if name=='_sysctlbyname':event['old_size_u64']=struct.unpack('<Q',self.u.mem_read(args[2],8))[0]
        if name=='_xpc_dictionary_set_data':
            event['key']=self.string(args[1]);event['size_bytes']=args[3]
            if args[3]>4096:return self.stop('private_response_extent_guard')
            event['payload_bytes']=bytes(self.u.mem_read(args[2],args[3])).hex()
        self.records.append(event)
        if name not in self.fixture.get('model_APIs',[]):return self.stop('opaque_API_boundary:'+name)
        event['kind']='modeled_API';result=0
        if name=='___chkstk_darwin':
            need=self.reg('x9');event['requested_bytes_x9']=need
            if need>self.reg('sp')-STACK-4096:return self.stop('private_stack_extent_guard')
            self.u.reg_write(A.UC_ARM64_REG_PC,self.reg('lr'));return
        if name=='_xpc_get_type':result=self.fixture.get('event_type_pointer',self.symbols['__xpc_type_'+self.fixture.get('event_type','dictionary')])
        elif name=='_xpc_connection_set_event_handler':
            event['block48_bytes']=bytes(self.u.mem_read(args[1],48)).hex()
        elif name=='_xpc_connection_set_target_queue':pass
        elif name in ('_xpc_connection_resume','_xpc_connection_activate','_xpc_connection_cancel','_xpc_release','_CFRelease','_xpc_transaction_begin','_xpc_transaction_end'):pass
        elif name=='_xpc_dictionary_get_data':
            event['key']=self.string(args[1]);payload=bytes.fromhex(self.fixture.get('payload_hex',''));result=HEAP+0x2000 if self.fixture.get('data_pointer','owned')=='owned' else 0
            self.u.mem_write(HEAP+0x2000,payload);self.u.mem_write(args[2],struct.pack('<Q',self.fixture.get('data_size',len(payload))));event.update({'result':hex(result),'size_bytes':self.fixture.get('data_size',len(payload)),'payload_bytes':payload.hex()})
        elif name=='_xpc_dictionary_get_audit_token':
            token=self.fixture.get('audit_words',[0,0,0,0,0,0,0,0]);self.u.mem_write(args[1],struct.pack('<8I',*token));event['audit_words']=token
        elif name=='_SecTaskCreateWithAuditToken':
            event['audit_token32_bytes']=bytes(self.u.mem_read(args[1],32)).hex();result=0 if self.fixture.get('task_result')=='NULL' else HEAP+0xe000
        elif name=='_SecTaskCopyValueForEntitlement':
            # Inspect the original CFString's characters through decoded fields.
            choice=self.fixture.get('entitlement_result','NULL')
            result=0 if choice=='NULL' else struct.unpack('<Q',self.u.mem_read(self.symbols['_kCFBoolean'+choice],8))[0] if choice in ('True','False') else HEAP+0xe100
            if args[2]:self.u.mem_write(args[2],struct.pack('<Q',0))
            event['key_object']=hex(args[1]);event['result']=hex(result)
        elif name=='_CFStringCreateWithCStringNoCopy':event['string']=self.string(args[1]);event['encoding_u32']=args[2]&0xffffffff;result=0 if self.fixture.get('key_result')=='NULL' else HEAP+0xe400
        elif name=='_xpc_dictionary_create_reply':result=0 if self.fixture.get('reply_result')=='NULL' else HEAP+0xe200
        elif name=='_xpc_dictionary_set_data':
            event['key']=self.string(args[1]);event['size_bytes']=args[3]
            if args[3]>4096:return self.stop('private_response_extent_guard')
            event['payload_bytes']=bytes(self.u.mem_read(args[2],args[3])).hex()
        elif name=='_xpc_dictionary_send_reply':event['reply_object']=hex(args[0]);result=self.fixture.get('send_reply_result',0)
        elif name=='_free':event['pointer']=hex(args[0])
        elif name=='_os_transaction_create':event['description']=self.string(args[0]);result=HEAP+0xe300
        elif name=='_ptrace':event['request_u32']=args[0]&0xffffffff;result=self.fixture.get('ptrace_result',0)
        elif name=='_pthread_set_qos_class_self_np':event['class_u32']=args[0]&0xffffffff;event['relative_priority_signed32']=struct.unpack('<i',struct.pack('<I',args[1]&0xffffffff))[0];result=0
        elif name in ('_pthread_rwlock_wrlock','_pthread_rwlock_rdlock','_pthread_rwlock_unlock','_pthread_rwlock_init'):event['lock_pointer']=hex(args[0]);result=0
        elif name=='_sysconf':event['selector_u32']=args[0]&0xffffffff;result=self.fixture.get('page_size',16384)
        elif name=='_mmap':
            if args[:4]!=[0,65536,3,0x1002] or args[4]&0xffffffff!=0xffffffff or args[5]!=0:return self.stop('unreviewed_mapping_guard')
            result=MASK if self.fixture.get('mapping_result')=='failed' else MAPPING+len(self.mappings)*65536
            if result!=MASK:
                if len(self.mappings)>=16:return self.stop('mapping_count_guard')
                self.u.mem_map(result,65536);self.mappings.append((result,65536))
            event['result']=hex(result);event['zero_initialized']=result!=MASK
        elif name=='_arc4random':result=self.fixture.get('random_u32',0x11223344)&0xffffffff
        elif name=='_audit_token_to_au32':
            token=bytes(self.u.mem_read(args[0],32));event['audit_token32_bytes']=token.hex();event['optional_output_pointers']=[hex(v) for v in args[1:]]+[hex(struct.unpack('<Q',self.u.mem_read(self.reg('sp'),8))[0])]
            if any(args[j] for j in (1,2,3,4,5,7)) or struct.unpack('<Q',self.u.mem_read(self.reg('sp'),8))[0]:return self.stop('unreviewed_audit_outputs_guard')
            pid=self.fixture.get('audit_pid_result',0);self.u.mem_write(args[6],struct.pack('<i',pid));event['modeled_pid_signed32']=pid
        elif name=='_audit_token_to_euid':event['audit_token32_bytes']=bytes(self.u.mem_read(args[0],32)).hex();result=self.fixture.get('audit_euid_result',0)&0xffffffff
        elif name=='_CFNumberGetTypeID':result=0x41f0
        elif name=='_CFGetTypeID':result={'number':0x41f0,'string':0x41f2}.get(self.fixture.get('entitlement_type'),0x41f1)
        elif name=='_CFStringGetTypeID':result=0x41f2
        elif name=='_CFNumberGetValue':
            if args[1]!=3:return self.stop('unreviewed_number_type_guard')
            value=self.fixture.get('entitlement_number',0)&0xffffffff;success=self.fixture.get('number_conversion_success',True)
            if success:self.u.mem_write(args[2],struct.pack('<I',value))
            event['value_u32']=value;event['conversion_success']=success;result=int(success)
        elif name=='_CFStringGetCString':
            raw=self.fixture.get('entitlement_string','').encode()+b'\0'
            if len(raw)>args[2]:return self.stop('entitlement_string_extent_guard')
            self.u.mem_write(args[1],raw);event['string']=self.fixture.get('entitlement_string','');result=1
        elif name=='_os_log_type_enabled':result=0
        elif name=='_strtoul':
            if args[2]!=10:return self.stop('unreviewed_numeric_base_guard')
            text=self.string(args[0]);match=re.match(r'^[\t\n\v\f\r ]*([+-]?)([0-9]+)',text);count=match.end() if match else 0
            value=int(match[2]) if match else 0
            if value>MASK:return self.stop('unreviewed_numeric_overflow_guard')
            result=(-value if match and match[1]=='-' else value)&MASK
            if args[1]:self.u.mem_write(args[1],struct.pack('<Q',args[0]+count))
            event.update({'input':text,'base':10,'consumed_bytes':count})
        elif name=='_getenv':
            value=self.fixture.get('osinstall_value');result=0 if value is None else HEAP+0xf000
            if result:self.u.mem_write(result,value.encode()+b'\0')
            event['modeled_value']=value
        elif name=='_proc_pidpath':
            path=self.fixture.get('process_path','');raw=path.encode()+b'\0'
            if len(raw)>args[2]:return self.stop('process_path_extent_guard')
            if path:self.u.mem_write(args[1],raw)
            event['modeled_path']=path;result=len(raw)-1 if path else 0
        else:return self.stop('unreviewed_model_guard:'+name)
        event['result']=hex(result);self.finish_api(result)
    def code(self,u,pc,n,data):
        self.steps+=1
        if self.steps>self.fixture.get('instruction_budget',100000):return self.stop('instruction_budget_guard')
        if pc==DONE:return self.stop('returned_to_private_fixture')
        if pc in self.binds:return self.api(self.binds[pc])
        if not self.text['address']<=pc<self.text['address']+self.text['size']:
            # The single authenticated canary stub is retained in the inventory.
            stubs=next(x for x in self.s.meta['sections'] if x['section']=='__auth_stubs')
            if not stubs['address']<=pc<stubs['address']+stubs['size']:return self.stop('unknown_code_guard:'+hex(pc))
        if pc not in self.instructions:
            raw=self.s.read(pc,4);i=next(CS.disasm(raw,pc));self.instructions[pc]={'ea':hex(pc),'bytes':raw.hex(),'mnemonic':i.mnemonic,'operands':i.op_str}
            if self.text['address']<=pc<self.text['address']+self.text['size']:
                a,z=self.s.bounds(pc)
                if a not in self.functions:
                    rawfn=self.s.read(a,z-a);self.functions[a]={'start':hex(a),'end':hex(z),'sha256':sha(rawfn),'size_bytes':z-a}
        i=self.instructions[pc];m=i['mnemonic'];op=i['operands'];self.visited.append(pc)
        if m=='eor3':
            e={'kind':'vector_instruction_boundary','pc':hex(pc),'instruction':m,'operands':op};self.records.append(e)
            if not self.fixture.get('model_eor3'):return self.stop('vector_instruction_boundary')
            regs=[getattr(A,'UC_ARM64_REG_Q'+v.strip().split('.')[0][1:]) for v in op.split(',')]
            inputs=[self.u.reg_read(r) for r in regs[1:]];result=inputs[0]^inputs[1]^inputs[2];self.u.reg_write(regs[0],result)
            e.update({'kind':'modeled_vector_XOR3','input_u128':[hex(x) for x in inputs],'output_u128':hex(result),'native_instruction_executed':False});self.u.reg_write(A.UC_ARM64_REG_PC,pc+4);return
        if m in ('swp','swpa','swpl','swpal'):
            src,dst,mem=op.split(', ');ptr=self.reg(mem.strip('[]'));width=4 if src.startswith('w') else 8
            e={'kind':'atomic_exchange_boundary','pc':hex(pc),'pointer':hex(ptr),'size_bytes':width,'source':hex(self.reg(src))};self.records.append(e)
            if not self.fixture.get('model_atomic'):return self.stop('atomic_exchange_boundary')
            before=bytes(self.u.mem_read(ptr,width));value=self.reg(src)&((1<<(8*width))-1);self.write(u,0,ptr,width,value,None)
            if self.reason:return
            self.u.mem_write(ptr,value.to_bytes(width,'little'))
            if dst not in ('wzr','xzr'):self.u.reg_write(getattr(A,'UC_ARM64_REG_'+dst.upper()),int.from_bytes(before,'little'))
            e.update({'kind':'modeled_sequential_atomic_exchange','before_bytes':before.hex(),'after_bytes':value.to_bytes(width,'little').hex(),'concurrency_validated':False});self.u.reg_write(A.UC_ARM64_REG_PC,pc+4);return
        if pc in (0x10002a204,0x10002a2b8,0x10002a3c8):
            event={'kind':'original_event_predicate','pc':hex(pc),'instruction':op,'x0':hex(self.reg('x0')),'x8':hex(self.reg('x8')),'x28':hex(self.reg('x28'))}
            self.records.append(event)
        if pc==0x1001661f8:
            ptr=self.reg('x0');self.core_record=ptr
            self.records.append({'kind':'original_core_record_entry','pc':hex(pc),'pointer':hex(ptr),'record48_bytes':bytes(self.u.mem_read(ptr,48)).hex(),'stack_adjust_output':hex(self.reg('x1'))})
        if pc==0x1000aa910:
            ptr=self.core_record;raw=bytes(self.u.mem_read(ptr,48));outptr=struct.unpack_from('<Q',raw,16)[0];outlenptr=struct.unpack_from('<Q',raw,40)[0]
            self.records.append({'kind':'original_core_record_return','pc':hex(pc),'pointer':hex(ptr),'record48_bytes':raw.hex(),
                'status_u32':struct.unpack_from('<I',raw,4)[0],'output_pointer_value':hex(struct.unpack('<Q',self.u.mem_read(outptr,8))[0]),'output_length_u64':struct.unpack('<Q',self.u.mem_read(outlenptr,8))[0],
                'x21':hex(self.reg('x21')),'x20':hex(self.reg('x20'))})
        if pc==0x10006234c:
            ptr=self.reg('x17');self.records.append({'kind':'original_context_gate','pc':hex(pc),'cell':hex(ptr),'value':hex(struct.unpack('<Q',self.u.mem_read(ptr,8))[0])})
        if pc==0x100169a34:
            self.records.append({'kind':'original_entitlement_numeric_fold','pc':hex(pc),'old_w19':hex(self.reg('w19')),'w20':hex(self.reg('w20')),
                'input_u32':struct.unpack('<I',self.u.mem_read(self.reg('sp')+0x2338,4))[0],'shift_low5':(self.reg('w20')-0x9b3)&31})
        if pc==0x100169acc:
            self.records.append({'kind':'original_entitlement_classifier_input','pc':hex(pc),'encoded_key_u32':struct.unpack('<I',self.u.mem_read(self.reg('sp')+0x415c,4))[0]})
        if m in ('svc','hvc','smc','brk'):return self.stop('native_instruction_guard:'+m)
        if m in ('braa','brab','blraa','blrab','braaz','brabz','blraaz','blrabz'):
            regs=op.split(', ');target=self.reg(regs[0]);edge={'kind':'PAC_bypassed_edge','pc':hex(pc),'target':hex(target),'modifier':None if len(regs)==1 else hex(self.reg(regs[1])),'link':m.startswith('bl')}
            self.records.append(edge);self.last_edge=edge
            if m.startswith('bl'):self.u.reg_write(A.UC_ARM64_REG_LR,pc+4)
            self.u.reg_write(A.UC_ARM64_REG_PC,target)
        elif m.startswith(('pac','aut')):self.u.reg_write(A.UC_ARM64_REG_PC,pc+4)
        elif m in ('retab','retaa'):self.u.reg_write(A.UC_ARM64_REG_PC,self.reg('lr'))
    def run(self):
        entry=self.fixture['entry'];args=self.fixture.get('args',[self.block,self.event])
        for j,v in enumerate(args):self.u.reg_write(A.UC_ARM64_REG_X0+j,v)
        try:self.u.emu_start(entry,DONE+4,count=self.fixture.get('instruction_budget',100000)+1)
        except Exception as e:
            if self.reason is None:self.reason='private_guest_exception:'+str(e)
        h=hashlib.sha256()
        for pc in self.visited:h.update(struct.pack('<Q',pc));h.update(self.s.read(pc,4))
        row={'fixture':self.fixture,'entry_sp':hex(self.sp),'stop_reason':self.reason,'steps':self.steps,'result_u32':self.reg('w0'),
            'records':self.records,'visited_original_instructions':[hex(pc) for pc in self.visited],'ordered_original_instruction_sha256':h.hexdigest(),
            'original_functions':list(self.functions.values()),'instruction_records':list(self.instructions.values())}
        if len(self.visited)>5000:
            packed=b''.join(struct.pack('<Q',pc) for pc in self.visited);row['visited_original_instructions_zlib_base64']=base64.b64encode(zlib.compress(packed)).decode()
            row['visited_original_instruction_count']=len(self.visited);row['visited_encoding']='zlib compressed little-endian uint64 addresses, then base64';del row['visited_original_instructions']
        if len(row['records'])>256:
            raw=json.dumps(row.pop('records'),separators=(',',':')).encode();row['records_zlib_base64']=base64.b64encode(zlib.compress(raw)).decode();row['records_encoding']='zlib compressed UTF-8 JSON array, then base64'
        return row


def main():
    s=Adid();fixtures=[]
    for entry in [s.entry,0x1000009f8,0x100029fc8]:fixtures.append({'label':'entry_'+hex(entry),'entry':entry})
    for apis in [['_os_transaction_create'],['_os_transaction_create','_ptrace'],['_os_transaction_create','_ptrace','_pthread_set_qos_class_self_np']]:
        fixtures.append({'label':'startup_stage_'+str(len(apis)),'entry':s.entry,'model_APIs':apis})
    startup=['_os_transaction_create','_pthread_set_qos_class_self_np','_pthread_rwlock_wrlock','_pthread_rwlock_unlock','_pthread_rwlock_init']
    fixtures.append({'label':'startup_locks','entry':s.entry,'model_APIs':startup})
    fixtures.append({'label':'startup_page_size','entry':s.entry,'model_APIs':startup+['_sysconf']})
    fixtures.append({'label':'startup_atomic','entry':s.entry,'model_atomic':True,'model_APIs':startup+['_sysconf']})
    for result in ('owned','failed'):
        fixtures.append({'label':'startup_mapping_'+result,'entry':s.entry,'model_atomic':True,'mapping_result':result,'model_APIs':startup+['_sysconf','_mmap','_ptrace']})
    fixtures.append({'label':'startup_random','entry':s.entry,'instruction_budget':2000000,'model_atomic':True,'model_APIs':startup+['_sysconf','_mmap','_ptrace','_arc4random']})
    fixtures.append({'label':'startup_vector','entry':s.entry,'instruction_budget':2000000,'model_atomic':True,'model_eor3':True,'model_APIs':startup+['_sysconf','_mmap','_ptrace','_arc4random']})
    for apis in [['_xpc_connection_set_target_queue'],['_xpc_connection_set_target_queue','_xpc_connection_set_event_handler','_xpc_connection_resume']]:
        fixtures.append({'label':'peer_setup_'+str(len(apis)),'entry':0x1000009f8,'model_APIs':apis})
    for ty in ('error','dictionary'):
        fixtures.append({'label':'event_type_'+ty,'entry':0x100029fc8,'event_type':ty,'model_APIs':['_xpc_get_type']})
    common=['_xpc_get_type','_xpc_dictionary_create_reply']
    for ty in ('error','dictionary'):
        for reply in ('NULL','owned'):
            fixtures.append({'label':f'event_{ty}_reply_{reply}','entry':0x100029fc8,'event_type':ty,'reply_result':reply,'model_APIs':common})
    payload='00000001632b8d6e00000001fffffffffffffff8000000007b000100'
    for size,pointer in [(28,'owned'),(0,'owned'),(27,'owned'),(29,'owned'),(28,'NULL')]:
        fixtures.append({'label':f'data_size_{size}_{pointer}','entry':0x100029fc8,'payload_hex':payload,'data_size':size,'data_pointer':pointer,
            'model_APIs':common+['_xpc_dictionary_get_audit_token','_xpc_dictionary_get_data','___chkstk_darwin','_xpc_release','_xpc_transaction_begin','_xpc_transaction_end']})
    for stage in [['_xpc_get_type','_xpc_dictionary_create_reply','_xpc_dictionary_get_audit_token'],
                  ['_xpc_get_type','_xpc_dictionary_create_reply','_xpc_dictionary_get_audit_token','_SecTaskCreateWithAuditToken']]:
        fixtures.append({'label':'admission_stage_'+str(len(stage)),'entry':0x100029fc8,'payload_hex':payload,'model_APIs':stage})
    for task in ('NULL','owned'):
        fixtures.append({'label':'admission_task_'+task,'entry':0x100029fc8,'task_result':task,'payload_hex':payload,
            'model_APIs':common+['_xpc_dictionary_get_audit_token','_SecTaskCreateWithAuditToken','_SecTaskCopyValueForEntitlement']})
    warm_apis=common+['_xpc_dictionary_get_audit_token','_xpc_dictionary_get_data','___chkstk_darwin','_xpc_release','_xpc_transaction_begin','_xpc_transaction_end']
    fixtures.append({'label':'initialized_context_data28','entry':0x100029fc8,'payload_hex':payload,'seed_from':'startup_vector','model_APIs':warm_apis})
    fixtures.append({'label':'initialized_context_atomic_data28','entry':0x100029fc8,'payload_hex':payload,'seed_from':'startup_vector','model_atomic':True,'model_APIs':warm_apis})
    for pid in (0,1234):
        fixtures.append({'label':'initialized_context_pid_'+str(pid),'entry':0x100029fc8,'payload_hex':payload,'seed_from':'startup_vector','model_atomic':True,
            'audit_pid_result':pid,'audit_words':[0,0,0,0,0,pid,0,0],'model_APIs':warm_apis+['_audit_token_to_au32']})
    for task in ('NULL','owned'):
        fixtures.append({'label':'initialized_context_security_task_'+task,'entry':0x100029fc8,'payload_hex':payload,'seed_from':'startup_vector','model_atomic':True,
            'audit_pid_result':1234,'audit_words':[0,0,0,0,0,1234,0,0],'task_result':task,
            'model_APIs':warm_apis+['_audit_token_to_au32','_CFStringCreateWithCStringNoCopy','_SecTaskCreateWithAuditToken']})
    security_apis=warm_apis+['_audit_token_to_au32','_CFStringCreateWithCStringNoCopy','_SecTaskCreateWithAuditToken','_SecTaskCopyValueForEntitlement','_CFRelease']
    for entitlement in ('NULL','False','True','Other'):
        fixtures.append({'label':'initialized_context_entitlement_'+entitlement,'entry':0x100029fc8,'payload_hex':payload,'seed_from':'startup_vector','model_atomic':True,
            'audit_pid_result':1234,'audit_words':[0,0,0,0,0,1234,0,0],'entitlement_result':entitlement,'model_APIs':security_apis})
    for kind in ('other','number'):
        fixtures.append({'label':'initialized_context_entitlement_type_'+kind,'entry':0x100029fc8,'payload_hex':payload,'seed_from':'startup_vector','model_atomic':True,
            'audit_pid_result':1234,'audit_words':[0,0,0,0,0,1234,0,0],'entitlement_result':'Number','entitlement_type':kind,
            'model_APIs':security_apis+['_CFNumberGetTypeID','_CFGetTypeID','_proc_pidpath']})
    fixtures.append({'label':'initialized_context_entitlement_absent_no_path','entry':0x100029fc8,'payload_hex':payload,'seed_from':'startup_vector','model_atomic':True,
        'audit_pid_result':1234,'audit_words':[0,0,0,0,0,1234,0,0],'entitlement_result':'NULL','model_APIs':security_apis+['_proc_pidpath']})
    admitted_apis=security_apis+['_CFNumberGetTypeID','_CFGetTypeID','_CFStringGetTypeID','_CFNumberGetValue','_CFStringGetCString','_proc_pidpath','_os_log_type_enabled']
    for value in (0,1,2,3,-1,0x7fffffff,0x80000000):
        fixtures.append({'label':'initialized_context_number_'+str(value),'entry':0x100029fc8,'payload_hex':payload,'seed_from':'startup_vector','model_atomic':True,
            'audit_pid_result':1234,'audit_words':[0,0,0,0,0,1234,0,0],'entitlement_result':'Number','entitlement_type':'number','entitlement_number':value,'model_APIs':admitted_apis})
    fixtures.append({'label':'initialized_context_string_entitlement','entry':0x100029fc8,'payload_hex':payload,'seed_from':'startup_vector','model_atomic':True,
        'audit_pid_result':1234,'audit_words':[0,0,0,0,0,1234,0,0],'entitlement_result':'String','entitlement_type':'string','entitlement_string':'1','model_APIs':admitted_apis})
    response_apis=admitted_apis+['_strtoul','_xpc_dictionary_set_data','_xpc_dictionary_send_reply','_free']
    for value in (0,1,2,3,-1):
        fixtures.append({'label':'initialized_path_number_'+str(value),'entry':0x100029fc8,'payload_hex':payload,'seed_from':'startup_vector','model_atomic':True,
            'audit_pid_result':1234,'audit_words':[0,0,0,0,0,1234,0,0],'process_path':'/usr/bin/fixture-client',
            'entitlement_result':'Number','entitlement_type':'number','entitlement_number':value,'model_APIs':response_apis})
    for value in ('1','0','2','-1','1junk'):
        fixtures.append({'label':'initialized_path_string_'+value,'entry':0x100029fc8,'payload_hex':payload,'seed_from':'startup_vector','model_atomic':True,
            'audit_pid_result':1234,'audit_words':[0,0,0,0,0,1234,0,0],'process_path':'/usr/bin/fixture-client',
            'entitlement_result':'String','entitlement_type':'string','entitlement_string':value,'model_APIs':response_apis})
    classifier=json.loads((ROOT/'adid_receiver_contracts.json').read_text())['classifier']
    for value in classifier['listed_values_under_XOR_u32']:
        fixtures.append({'label':'initialized_path_listed_'+hex(value),'entry':0x100029fc8,'payload_hex':payload,'seed_from':'startup_vector','model_atomic':True,
            'audit_pid_result':1234,'audit_words':[0,0,0,0,0,1234,0,0],'process_path':'/usr/bin/fixture-client',
            'entitlement_result':'Number','entitlement_type':'number','entitlement_number':value,'model_APIs':response_apis})
    for euid in (0,501):
        fixtures.append({'label':'initialized_listed_euid_'+str(euid),'entry':0x100029fc8,'payload_hex':payload,'seed_from':'startup_vector','model_atomic':True,
            'audit_pid_result':1234,'audit_euid_result':euid,'audit_words':[0,euid,0,0,0,1234,0,0],'process_path':'/usr/bin/fixture-client',
            'entitlement_result':'Number','entitlement_type':'number','entitlement_number':classifier['listed_values_under_XOR_u32'][0],'model_APIs':response_apis+['_audit_token_to_euid']})
    fixtures.append({'label':'initialized_listed_root_locks','entry':0x100029fc8,'payload_hex':payload,'seed_from':'startup_vector','model_atomic':True,
        'audit_pid_result':1234,'audit_euid_result':0,'audit_words':[0,0,0,0,0,1234,0,0],'process_path':'/usr/bin/fixture-client',
        'entitlement_result':'Number','entitlement_type':'number','entitlement_number':classifier['listed_values_under_XOR_u32'][0],
        'model_APIs':response_apis+['_audit_token_to_euid','_pthread_rwlock_wrlock','_pthread_rwlock_unlock','_pthread_rwlock_rdlock','_pthread_rwlock_init']})
    for value in (None,'1'):
        fixtures.append({'label':'initialized_root_osinstall_'+str(value),'entry':0x100029fc8,'payload_hex':payload,'seed_from':'startup_vector','model_atomic':True,
            'audit_pid_result':1234,'audit_euid_result':0,'audit_words':[0,0,0,0,0,1234,0,0],'process_path':'/usr/bin/fixture-client',
            'entitlement_result':'Number','entitlement_type':'number','entitlement_number':classifier['listed_values_under_XOR_u32'][0],'osinstall_value':value,
            'model_APIs':response_apis+['_audit_token_to_euid','_pthread_rwlock_wrlock','_pthread_rwlock_unlock','_pthread_rwlock_rdlock','_pthread_rwlock_init','_getenv']})
    for selector in (-8,-6,-5,-4,-3,-2):
        wire=struct.pack('>IIIqQ',1,0x632b8d6e,1,selector,HEAP+0x100)
        fixtures.append({'label':'denied_selector_'+str(selector),'entry':0x100029fc8,'payload_hex':wire.hex(),'seed_from':'startup_vector','model_atomic':True,
            'audit_pid_result':1234,'audit_words':[0,0,0,0,0,1234,0,0],'process_path':'/usr/bin/fixture-client',
            'entitlement_result':'Number','entitlement_type':'number','entitlement_number':1,'model_APIs':response_apis})
    fixtures.append({'label':'listed_entitlement_path_lookup_failure','entry':0x100029fc8,'payload_hex':payload,'seed_from':'startup_vector','model_atomic':True,
        'audit_pid_result':1234,'audit_words':[0,0,0,0,0,1234,0,0],'entitlement_result':'Number','entitlement_type':'number',
        'entitlement_number':classifier['listed_values_under_XOR_u32'][0],'model_APIs':response_apis})
    fixtures.append({'label':'invalid_connection_event','entry':0x100029fc8,'args':[HEAP+0x100,BIND+118*0x100],'event_type':'error',
        'model_APIs':['_xpc_get_type','_xpc_connection_cancel']})
    fixtures.append({'label':'other_event_type','entry':0x100029fc8,'event_type_pointer':HEAP+0xe900,
        'model_APIs':['_xpc_get_type','_xpc_connection_cancel']})
    fixtures.append({'label':'listed_decimal_string_entitlement','entry':0x100029fc8,'payload_hex':payload,'seed_from':'startup_vector','model_atomic':True,
        'audit_pid_result':1234,'audit_words':[0,0,0,0,0,1234,0,0],'process_path':'/usr/bin/fixture-client',
        'entitlement_result':'String','entitlement_type':'string','entitlement_string':str(classifier['listed_values_under_XOR_u32'][0]),'model_APIs':response_apis})
    rows=[];seed=None
    for f in fixtures:
        probe=Probe(s,f,seed if f.get('seed_from') else None);row=probe.run();rows.append(row)
        if f['label']=='startup_vector':
            seed=[(seg['address'],bytes(probe.u.mem_read(seg['address'],seg['vm_size'])),False) for seg in s.meta['segments'] if seg['name']=='__DATA']
            seed.append((HEAP,bytes(probe.u.mem_read(HEAP,0x20000)),False))
            seed.extend((a,bytes(probe.u.mem_read(a,n)),True) for a,n in probe.mappings)
            snap={'source_profile':'startup_vector','source_stop_reason':row['stop_reason'],'source_thin_sha256':THIN_SHA,
                'source_ordered_instruction_sha256':row['ordered_original_instruction_sha256'],'generator_sha256':sha(Path(__file__).read_bytes()),
                'regions':[{'address':hex(a),'size_bytes':len(raw),'mapping':ism,'sha256':sha(raw),'bytes_zlib_base64':base64.b64encode(zlib.compress(raw)).decode()} for a,raw,ism in seed],
                'scope':'Private DATA/heap/mappings from original startup prefix;no native ready state or live service inferred.'}
            (ROOT/'adid_initialized_context_snapshot.json').write_text(json.dumps(snap,indent=2)+'\n')
    functions={};instructions={}
    for r in rows:
        for v in r.pop('original_functions'):functions[v['start']]=v
        for v in r.pop('instruction_records'):instructions[v['ea']]=v
    out={'scope':__doc__,'source_thin_sha256':THIN_SHA,'generator_sha256':sha(Path(__file__).read_bytes()),'reader_sha256':sha((ROOT/'adid_reader.py').read_bytes()),
        'static_contracts_sha256':sha((ROOT/'adid_receiver_contracts.json').read_bytes()),'seed_snapshot_sha256':sha((ROOT/'adid_initialized_context_snapshot.json').read_bytes()),
        'original_functions':list(functions.values()),'original_instruction_records':list(instructions.values()),'profiles':rows,
        'native_target_executed':False,'hardware_PAC_validated':False,'full_goal_complete':False}
    (ROOT/'adid_receiver_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
    for row in rows:
        rr=row.get('records') or json.loads(zlib.decompress(base64.b64decode(row['records_zlib_base64'])))
        print(json.dumps({'label':row['fixture']['label'],'stop':row['stop_reason'],'steps':row['steps'],'last':rr[-1] if rr else None}))


if __name__=='__main__':main()
