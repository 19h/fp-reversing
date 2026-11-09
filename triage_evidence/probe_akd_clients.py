#!/usr/bin/env python3
"""Original AKADIProxy/client entries in a bounded private guest.

Wider owned import region accommodates1575 original imports. Original code
runs; PAC is bypassed,not authenticated. No native target/API. Explicit API
models only; unknown boundaries stop. O(C*(B+F+K)) time/space,finite hooks.
"""
import json
from pathlib import Path
import struct
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_WRITE,UC_HOOK_MEM_READ,UC_HOOK_MEM_INVALID
from unicorn import arm64_const as A
from akd_client_reader import Akd,ROOT,THIN_SHA,sha,CS
from probe_adid_receiver import Probe,STACK,HEAP,BIND,DONE,MASK

TARGETS={0x1002f86d8,0x10030f600,0x100308278,0x1003026f8,0x1002d8790,0x1002e1b74,0x100302898,0x1002dd3a0,0x1002ed22c,0x1002fd5c8,0x1002d3d84,0x1002e7d04,0x1002f3944}
OUTPUTS=[(HEAP+0x1100,8),(HEAP+0x1200,4),(HEAP+0x1300,8),(HEAP+0x1400,4),(HEAP+0x1500,8)]


class Client(Probe):
    def __init__(self,s,f):
        self.s=s;self.fixture=f;self.u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);self.records=[];self.visited=[];self.instructions={};self.functions={};self.reason=None;self.steps=0;self.last_edge=None;self.mappings=[]
        for seg in s.meta['segments']:
            if seg['name']=='__PAGEZERO' or not seg['vm_size']:continue
            self.u.mem_map(seg['address'],(seg['vm_size']+4095)&~4095)
            if seg['file_size']:self.u.mem_write(seg['address'],s.data[seg['file_offset']:seg['file_offset']+seg['file_size']])
        for at,n in [(STACK,0x40000),(HEAP,0x20000),(BIND,0x100000),(DONE,4096)]:self.u.mem_map(at,n)
        self.binds={};self.symbols={im['name']:BIND+im['ordinal']*0x100 for im in s.imports}
        for at,p in s.decoded.items():
            if p['bind']:
                im=p['import'];target=self.symbols[im['name']]+p['total_addend'];self.binds[self.symbols[im['name']]]=im
                if im['name']=='___stack_chk_guard':self.u.mem_write(self.symbols[im['name']],struct.pack('<Q',0x9012345678abcdef))
                if im['name'].startswith('_k'):self.u.mem_write(self.symbols[im['name']],struct.pack('<Q',HEAP+0x10000+im['ordinal']*16))
            else:target=int(p['target'],16)
            self.u.mem_write(at,struct.pack('<Q',target&MASK))
        self.sp=STACK+0x38000;self.u.reg_write(A.UC_ARM64_REG_SP,self.sp);self.u.reg_write(A.UC_ARM64_REG_LR,DONE);self.u.mem_write(HEAP,b'\xa5'*0x20000);self.block=HEAP+0x100;self.event=HEAP+0x400;self.connection=HEAP+0x800;self.queue=HEAP+0xc00;self.text=next(x for x in s.meta['sections'] if x['section']=='__text')
        self.u.mem_write(self.sp,struct.pack('<Q',HEAP+0x1400));self.u.mem_write(HEAP+0x4000,bytes.fromhex(f.get('input_hex','01234567')));self.u.mem_write(HEAP+0x5000,bytes.fromhex(f.get('input2_hex','89abcdef')))
        self.u.hook_add(UC_HOOK_CODE,self.code);self.u.hook_add(UC_HOOK_MEM_WRITE,self.write);self.u.hook_add(UC_HOOK_MEM_READ,self.read_hook);self.u.hook_add(UC_HOOK_MEM_INVALID,self.invalid)
        self.allocations=[];self.alloc_cursor=HEAP+0x6000;self.queue=HEAP+0x1c000;self.connection=HEAP+0x1d000;self.reply=HEAP+0x1e000
    def code(self,u,pc,n,data):
        if pc in TARGETS:self.records.append({'kind':'original_client_C_entry','pc':hex(pc),'source_return':hex(self.reg('lr')),'args_x0_x7':[hex(self.reg('x'+str(i))) for i in range(8)],'stack_first16':bytes(u.mem_read(self.reg('sp'),16)).hex()})
        objc=next((s for s in self.s.sections if s['section']=='__objc_stubs'),None)
        if objc and objc['address']<=pc<objc['address']+objc['size']:
            self.steps+=1
            if self.steps>self.fixture.get('instruction_budget',400000):return self.stop('instruction_budget_guard')
            raw=self.s.read(pc,4);i=next(CS.disasm(raw,pc));self.instructions[pc]={'ea':hex(pc),'bytes':raw.hex(),'mnemonic':i.mnemonic,'operands':i.op_str};self.visited.append(pc)
            if i.mnemonic=='braa':
                target,modifier=i.op_str.split(', ');self.records.append({'kind':'PAC_bypassed_edge','pc':hex(pc),'target':hex(self.reg(target)),'modifier':hex(self.reg(modifier)),'link':False});self.u.reg_write(A.UC_ARM64_REG_PC,self.reg(target))
            elif i.mnemonic not in ('adrp','add','ldr'):return self.stop('client_unknown_ObjC_stub_instruction')
            return
        return super().code(u,pc,n,data)
    def api(self,im):
        name=im['name'];x=[self.reg('x'+str(i)) for i in range(8)];site=hex(self.reg('lr')-4)
        if name=='_objc_msgSend' and 'active_dsid' in self.fixture:
            selector=self.string(x[1])
            if selector!='activeAnisettDSIDFromLastKnownIDMSEnvironment' or x[0]!=0x10043c930:return self.stop('client_unknown_ObjC_message')
            value=self.fixture['active_dsid'];self.records.append({'kind':'explicit_client_active_DSID','name':name,'callsite':site,'selector':selector,'class_pointer':hex(x[0]),'result_u64':hex(value),'native_API_executed':False});return self.finish_api(value)
        if name=='_dispatch_queue_create' and self.fixture.get('model_queue'):
            self.records.append({'kind':'explicit_client_queue','name':name,'callsite':site,'label':self.string(x[0]),'attribute_pointer':hex(x[1]),'result':hex(self.queue),'native_API_executed':False});return self.finish_api(self.queue)
        if name=='_xpc_connection_create_mach_service' and self.fixture.get('model_queue'):
            if self.string(x[0])!='com.apple.adid' or x[1]!=self.queue or x[2]!=0:return self.stop('client_connection_shape_guard')
            result=0 if self.fixture.get('connection_NULL') else self.connection;self.records.append({'kind':'explicit_client_connection','name':name,'callsite':site,'service':self.string(x[0]),'args_x0_x7':[hex(v) for v in x],'result':hex(result),'native_API_executed':False});return self.finish_api(result)
        if name=='_xpc_connection_send_message_with_reply_sync':
            self.records.append({'kind':'completed_client_sync_send_fixture' if self.fixture.get('provider_reply_resume') else 'original_client_sync_send','name':name,'callsite':site,'args_x0_x7':[hex(v) for v in x],'native_API_executed':False})
            if 'reply_hex' not in self.fixture:return self.stop('original_client_sync_send')
            return self.finish_api(self.reply)
        if name=='_xpc_get_type' and 'reply_hex' in self.fixture:
            value=self.symbols['__xpc_type_error'] if self.fixture.get('reply_type')=='error' else HEAP+0x1f000;self.records.append({'kind':'explicit_client_reply_type','name':name,'callsite':site,'result':hex(value),'classification':'error' if self.fixture.get('reply_type')=='error' else 'nonerror_fixture','native_API_executed':False});return self.finish_api(value)
        if name=='_xpc_dictionary_get_data' and 'reply_hex' in self.fixture:
            raw=bytes.fromhex(self.fixture['reply_hex'])
            if len(raw)>8192 or x[0]!=self.reply:return self.stop('client_reply_shape_guard')
            ptr=HEAP+0x2000;self.u.mem_write(ptr,raw);self.u.mem_write(x[2],struct.pack('<Q',len(raw)));self.records.append({'kind':'explicit_client_reply_data','name':name,'callsite':site,'key':self.string(x[1]),'bytes':raw.hex(),'size_bytes':len(raw),'native_API_executed':False});return self.finish_api(ptr)
        if name=='_dispatch_release' and self.fixture.get('model_queue'):
            if x[0]!=self.queue:return self.stop('client_dispatch_release_shape_guard')
            self.records.append({'kind':'explicit_client_queue_release','name':name,'callsite':site,'pointer':hex(x[0]),'native_API_executed':False});return self.finish_api(0)
        if name=='_xpc_dictionary_create_empty' and self.fixture.get('model_dictionary'):
            pointer=0 if self.fixture.get('dictionary_NULL') else HEAP+0x1b000;self.records.append({'kind':'explicit_client_dictionary','name':name,'callsite':site,'result':hex(pointer),'native_API_executed':False});return self.finish_api(pointer)
        if name=='_xpc_dictionary_set_data':
            if x[3]>8192:return self.stop('client_data_extent_guard')
            self.records.append({'kind':'original_client_data_emission','name':name,'callsite':site,'args_x0_x7':[hex(v) for v in x],'key':self.string(x[1]),'size_bytes':x[3],'payload_hex':bytes(self.u.mem_read(x[2],x[3])).hex(),'native_API_executed':False})
            if x[0]==0:return self.stop('client_NULL_dictionary_set_data_boundary')
            if self.fixture.get('continue_after_set_data'):return self.finish_api(0)
            return self.stop('original_client_data_emission')
        if name=='_malloc' and self.fixture.get('model_allocator'):
            size=x[0]
            if size>8192 or len(self.allocations)>=20 or self.alloc_cursor+size>HEAP+0x1a000:return self.stop('client_allocation_extent_guard')
            ptr=0 if self.fixture.get('allocation_NULL') else self.alloc_cursor
            if ptr:self.alloc_cursor=(ptr+size+15)&~15;self.allocations.append({'pointer':ptr,'size_bytes':size,'freed':False});self.u.mem_write(ptr,bytes([0xa5])*size)
            self.records.append({'kind':'explicit_client_allocation','name':name,'callsite':site,'size_bytes':size,'result':hex(ptr),'native_API_executed':False});return self.finish_api(ptr)
        if name=='_free' and self.fixture.get('model_free'):
            allocation=next((r for r in self.allocations if r['pointer']==x[0]),None)
            if x[0] and allocation is None and not (self.fixture['label']=='dispose' and x[0]==HEAP+0x4000):return self.stop('client_unowned_free_guard')
            if allocation:allocation['freed']=True
            self.records.append({'kind':'explicit_client_free','name':name,'callsite':site,'pointer':hex(x[0]),'native_API_executed':False});return self.finish_api(0)
        return super().api(im)


def methods():
    return [('get',0x10010db10,[HEAP+0x1100,MASK-7]),('set',0x10010db48,[0x1122334455667788,MASK-7]),('otp',0x10010db80,[0x1122334455667788,HEAP+0x1100,HEAP+0x1200,HEAP+0x1300,HEAP+0x1400]),('dispose',0x10010dbd0,[HEAP+0x4000]),('is_provisioned',0x10010dc00,[0x1122334455667788]),('start',0x10010dc30,[0x1122334455667788,HEAP+0x4000,4,HEAP+0x1100,HEAP+0x1200,HEAP+0x1300]),('end',0x10010dc88,[0x12345678,HEAP+0x4000,4,HEAP+0x5000,4]),('destroy',0x10010dcd8,[0x12345678]),('sync',0x10010dd08,[0x1122334455667788,HEAP+0x4000,4,HEAP+0x1100,HEAP+0x1200,HEAP+0x1300]),('erase',0x10010dd6c,[0x1122334455667788])]


def fixtures():
    apis=['_xpc_connection_set_target_queue','_xpc_connection_set_event_handler','_xpc_connection_activate','_xpc_connection_resume','_xpc_connection_cancel','_xpc_release'];out=[];base={}
    def add(label,entry,args,operation,scope='original_ObjC_method',**extra):
        f={'label':label,'entry':entry,'args':args,'operation':operation,'entry_scope':scope,'model_allocator':True,'model_free':True,'model_dictionary':True,'continue_after_set_data':True,'model_queue':True,'model_APIs':apis,'model_eor3':True,'model_atomic':True,'instruction_budget':400000,'internal_instruction_or_frame_overrides':False,**extra};out.append(f);return f
    for name,entry,args in methods():base[name]=add(name,entry,[HEAP+0x100,0]+args,name)
    base['login_code']=add('login_code',0x1000519f0,[HEAP+0x100,0,HEAP+0x1100],'login_code',active_dsid=MASK-1)
    base['login_core']=add('login_core',0x1002d3d84,[MASK-1,HEAP+0x1100],'login_code','original_C_entry_with_named_caller')
    base['unnamed720']=add('unnamed720',0x1002e7d04,[HEAP+0x1100,HEAP+0x1200],'unnamed720','original_C_entry_without_proved_caller')
    base['vmtohost']=add('vmtohost',0x1002f3944,[],'vmtohost','original_C_entry_without_proved_caller')
    def clone(name,label,**extra):f=json.loads(json.dumps(base[name]));f.update(label=label,**extra);out.append(f);return f
    for name,index in [('get',3),('set',3)]:
        for key in [-9,-8,-7,-6,-5,-4,-3,-2,-1,0,1,0xfffffff8]:
            if key==-8:continue
            f=clone(name,name+'_dsid_'+str(key));f['args'][index]=key&MASK
    for key in [-17,-16,-1,0,1]:f=clone('login_core','login_dsid_'+str(key));f['args'][0]=key&MASK
    f=clone('login_core','login_null_output');f['args'][1]=0
    for name in ['start','sync']:
        for length in [0,1,27,64]:
            f=clone(name,name+'_input_'+str(length),input_hex=bytes((i*37+11)&255 for i in range(length)).hex());f['args'][4]=length
    for a,b in [(0,0),(1,1),(27,32)]:
        f=clone('end',f'end_inputs_{a}_{b}',input_hex=bytes((i*17+3)&255 for i in range(a)).hex(),input2_hex=bytes((i*19+7)&255 for i in range(b)).hex());f['args'][4]=a;f['args'][6]=b
    for name,index in [('get',2),('otp',3),('start',5),('sync',5)]:f=clone(name,name+'_null_output');f['args'][index]=0
    for name in ['get','set','otp','is_provisioned','start','end','destroy','sync','erase','login_core']:clone(name,name+'_allocator_NULL',allocation_NULL=True)
    for name in ['get','start']:clone(name,name+'_dictionary_NULL',dictionary_NULL=True)
    for name in ['get','set','otp','is_provisioned','start','end','destroy','sync','erase','login_core']:
        for response in ['ffff501f','00000000']:clone(name,name+'_reply_'+response,reply_hex=response)
    for raw in ['','00','000000']:clone('get','get_short_reply_'+str(len(raw)//2),reply_hex=raw)
    rich=[('get','route',struct.pack('>IQ',0,0x1122334455667788)),('login_core','code',struct.pack('>II',0,0x12345678)),('otp','two_spans',struct.pack('>II',0,3)+b'abc'+struct.pack('>I',4)+b'WXYZ'),('sync','two_spans',struct.pack('>II',0,3)+b'abc'+struct.pack('>I',4)+b'WXYZ'),('start','blob_session',struct.pack('>II',0,3)+b'abc'+struct.pack('>I',0x12345678)),('start','session_blob_rejected',struct.pack('>III',0,0x12345678,3)+b'abc')]
    for name,label,raw in rich:clone(name,name+'_rich_'+label,reply_hex=raw.hex())
    return out


def run_one(s,f):
    q=Client(s,json.loads(json.dumps(f)));before={hex(a):bytes(q.u.mem_read(a,n)).hex() for a,n in OUTPUTS};r=q.run();r.update({'output_observation_windows_before':before,'output_observation_windows_after':{hex(a):bytes(q.u.mem_read(a,n)).hex() for a,n in OUTPUTS},'allocation_model_final':q.allocations,'allocation_observation_bytes_after':{hex(a['pointer']):bytes(q.u.mem_read(a['pointer'],a['size_bytes'])).hex() for a in q.allocations}});return q,r


def main():
    s=Akd();rows=[];functions={};instructions={}
    from probe_adid_startup import unpack_records
    for f in fixtures():
        q,r=run_one(s,f)
        for v in r.pop('original_functions'):functions[v['start']]=v
        for v in r.pop('instruction_records'):instructions[v['ea']]=v
        rows.append(r);es=unpack_records(r);print(json.dumps({'label':f['label'],'stop':r['stop_reason'],'steps':r['steps'],'result_u32':hex(r['result_u32']),'requests':[e['payload_hex'] for e in es if e['kind']=='original_client_data_emission'],'last_API':next((e.get('name') for e in reversed(es) if e.get('name')),None)}),flush=True)
    names=['akd_client_reader.py','akd_client_inventory.json','akd_client_fixups.txt','probe_akd_clients.py','probe_adid_receiver.py','appstore_agent_reader.py','recover_appstore_agent.py'];out={'scope':__doc__,'thin_sha256':THIN_SHA,'profiles':rows,'original_functions':list(functions.values()),'original_instruction_records':list(instructions.values()),'generator_sha256':sha(Path(__file__).read_bytes()),'dependencies':{n:sha((ROOT/n).read_bytes()) for n in names},'native_target_executed':False,'hardware_PAC_validated':False,'full_goal_complete':False};(ROOT/'akd_client_profiles.json').write_text(json.dumps(out,indent=2)+'\n')


if __name__=='__main__':main()
