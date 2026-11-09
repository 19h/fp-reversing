#!/usr/bin/env python3
"""Original secondary CoreFP constructor and its56-byte request1200 path.

Private original-image pages and explicit bounded allocation/data/IPC fixtures
only. No native target/loader/API/port operation. Unknown imports/instructions,
unowned writes and malformed extents stop. O(C*(B+F+K)) time,O(B+F+C*K) space,
with inherited30k-hook bound. The constructor selector is a64-bit input.
"""
import json
from pathlib import Path
import struct
from unicorn import arm64_const as A
from corefp_fixups_reader import Pointers,ROOT,sha,THIN_SHA
from probe_corefp_exports import Probe,BASE,HEAP,BIND
from probe_corefp_mach_requests import Request

ENTRY=0x15cc6f4


class Secondary(Request):
    def __init__(self,s,f):
        Probe.__init__(self,s,{**f,'mode':'packet','entry':f.get('entry_override',ENTRY),'reply_name_u32':0x6173,'voucher_present':False})
        self.stub_ins={};self.stub_rows={};self.used_stubs={};self.allocations=[];self.alloc_cursor=HEAP+0x1000;self.allocation_requests=0
        self.objects={};self.dict_data=[];self.mach_index=0
        for row in json.loads((ROOT/'corefp_import_calls.json').read_text())['stubs']:
            for ins in row['instructions']:
                a=int(ins['ea'],16);self.stub_ins[a]=ins;self.stub_rows[a]=row
        self.argument1_value=HEAP+0x100+f.get('argument1_delta',0);self.u.mem_write(self.argument1_value,b'\xa5'*8)
        self.args=[f['selector_signed64']&((1<<64)-1),self.argument1_value];self.ndr_fixture='0001020304050607'
        if f.get('entry_override')==0x15a4c14:self.args=[BASE+0x1d16350,HEAP+0xe400]
        self.u.mem_write(BIND+86*16,struct.pack('<I',0x1b57));self.u.mem_write(BIND+82*16,struct.pack('<I',0x1717))
        self.u.mem_write(BIND+175*16,bytes(range(8)));self.u.mem_write(BASE+0x1d1c5e8,struct.pack('<Q',0))
        if 'legacy_cached_name_u32' in f:self.u.mem_write(BASE+0x1d49068,struct.pack('<I',f['legacy_cached_name_u32']))
        self.u.reg_write(A.UC_ARM64_REG_CPACR_EL1,3<<20);self.lookup_index=0
        self.state_cells=[0x1d441a8,0x1d44158]
        if 'secondary_state64' in f:
            for a,v in zip(self.state_cells,f['secondary_state64']):self.u.mem_write(BASE+a,struct.pack('<Q',v))
        self.selector_state_before=[int.from_bytes(self.u.mem_read(BASE+a,8),'little') for a in self.state_cells]
    def ret(self,v=0):self.u.reg_write(A.UC_ARM64_REG_X0,v&((1<<64)-1));self.u.reg_write(A.UC_ARM64_REG_PC,self.reg('lr'))
    def string(self,p):
        data=bytes(self.u.mem_read(p,256));assert b'\0' in data
        return data.split(b'\0',1)[0].decode('ascii')
    def code(self,u,pc,n,data):
        if pc==BASE+0x15cc814:
            self.records.append({'kind':'original_secondary_state_prelude','entry_sp':hex(self.sp),'before_u64':self.selector_state_before,
                'after_u64':[int.from_bytes(u.mem_read(BASE+a,8),'little') for a in self.state_cells]})
        im=self.binds.get(pc)
        if im:
            name=im['name'];call=hex(self.reg('lr')-4-BASE)
            tail_call=not 0<=self.reg('lr')-4-BASE<0x2000000
            if tail_call:
                edge=next((e for e in reversed(self.records) if e['kind']=='PAC_bypassed_edge' and e['target']==hex(pc)),None)
                if edge is None:return self.stop('secondary_tail_provenance_guard')
                call=edge['pc']
            if name=='_xpc_copy_description' and self.fixture.get('model_description'):
                self.steps+=1;ptr=HEAP+0xd000;raw=b'private fixture event\0';self.allocations.append((ptr,len(raw)));u.mem_write(ptr,raw)
                self.records.append({'kind':'modeled_secondary_event_description','callsite':call,'event_object':hex(self.reg('x0')),
                    'result':hex(ptr),'bytes':raw.hex(),'native_XPC_executed':False});return self.ret(ptr)
            if name=='_mach_msg' and self.mach_index<len(self.fixture.get('mach_results',[])):
                self.steps+=1;args=[self.reg('x'+str(j)) for j in range(7)];raw=bytes(u.mem_read(args[0],args[2]))
                result=self.fixture['mach_results'][self.mach_index];self.mach_index+=1
                assert args[2:4]==[56,64] and struct.unpack_from('<I',raw,20)[0]==1200 and result!=0
                ptr=struct.unpack_from('<Q',raw,28)[0];size=struct.unpack_from('<I',raw,40)[0];assert size<=4096
                self.records.append({'kind':'modeled_secondary_mach_failure','callsite':call,'args_x0_x6':[hex(v) for v in args],
                    'request_bytes':raw.hex(),'OOL_bytes':bytes(u.mem_read(ptr,size)).hex(),'result_u32':result,
                    'native_message_sent':False});return self.ret(result)
            if name in ('_mig_put_reply_port','_mig_dealloc_reply_port','_mach_msg_destroy') and 'mach_results' in self.fixture:
                self.steps+=1;self.records.append({'kind':'modeled_secondary_MIG_cleanup','callsite':call,'name':name,
                    'argument':hex(self.reg('x0')),'native_cleanup_executed':False});return self.ret()
            if name=='_malloc' and self.fixture.get('allocator'):
                self.steps+=1;size=self.reg('x0');ptr=0
                if size>8192 or len(self.allocations)>=16:return self.stop('secondary_allocator_extent_guard')
                if self.fixture['allocator']=='success' and self.fixture.get('allocation_fail_index')!=self.allocation_requests:
                    ptr=self.alloc_cursor;self.alloc_cursor=(ptr+size+15)&~15
                    if self.alloc_cursor>HEAP+0x10000:return self.stop('secondary_allocator_capacity_guard')
                    self.allocations.append((ptr,size));u.mem_write(ptr,b'\xa5'*size)
                self.allocation_requests+=1
                self.records.append({'kind':'modeled_secondary_allocation','callsite':call,'size_bytes':size,'result':hex(ptr),
                    'native_allocator_executed':False});return self.ret(ptr)
            if name=='_xpc_dictionary_create_empty' and 'dictionary_result' in self.fixture:
                self.steps+=1;ptr=HEAP+0xe000 if self.fixture['dictionary_result']=='success' else 0
                if ptr:self.objects[ptr]='private_dictionary'
                self.records.append({'kind':'modeled_secondary_dictionary','callsite':call,'result':hex(ptr),'native_XPC_executed':False})
                return self.ret(ptr)
            if name=='_xpc_dictionary_set_data' and self.fixture.get('dictionary_result')=='success':
                self.steps+=1;obj=self.reg('x0');key=self.string(self.reg('x1'));ptr=self.reg('x2');length=self.reg('x3')
                assert self.objects.get(obj)=='private_dictionary'
                if length>4096:return self.stop('secondary_XPC_data_extent_guard')
                event={'kind':'modeled_secondary_XPC_set_data','callsite':call,'dictionary':hex(obj),'key':key,
                    'source_pointer':hex(ptr),'size_bytes':length,'bytes':bytes(u.mem_read(ptr,length)).hex(),'native_XPC_executed':False}
                self.records.append(event);self.dict_data.append(event);return self.ret()
            if name=='_dispatch_queue_create' and self.fixture.get('model_queue'):
                self.steps+=1;ptr=HEAP+0xe100;self.objects[ptr]='private_queue'
                self.records.append({'kind':'modeled_secondary_queue','callsite':call,'label':self.string(self.reg('x0')),
                    'attributes':hex(self.reg('x1')),'result':hex(ptr),'native_queue_executed':False});return self.ret(ptr)
            if name=='_xpc_connection_create_mach_service':
                event={'kind':'original_secondary_XPC_service_boundary','callsite':call,'service':self.string(self.reg('x0')),
                    'queue':hex(self.reg('x1')),'flags':hex(self.reg('x2')),'native_connection_created':False};self.records.append(event)
                if 'connection_result' not in self.fixture:return self.stop('original_secondary_XPC_service_boundary')
                ptr=HEAP+0xe200 if self.fixture['connection_result']=='success' else 0
                if ptr:self.objects[ptr]='private_connection'
                event.update({'kind':'modeled_secondary_connection','result':hex(ptr)});self.steps+=1;return self.ret(ptr)
            if name in ('_xpc_connection_set_event_handler','_xpc_connection_activate') and self.fixture.get('connection_result')=='success':
                self.steps+=1;event={'kind':'modeled_secondary_connection_setup','callsite':call,'name':name,'connection':hex(self.reg('x0')),
                    'native_XPC_executed':False}
                if name.endswith('event_handler'):
                    block=self.reg('x1');event.update({'block':hex(block),'block32_bytes':bytes(u.mem_read(block,32)).hex()})
                self.records.append(event);return self.ret()
            if name=='_xpc_connection_send_message_with_reply_sync':
                event={'kind':'original_secondary_XPC_send_boundary','callsite':call,'connection':hex(self.reg('x0')),
                    'dictionary':hex(self.reg('x1')),'data_fields':self.dict_data,'native_message_sent':False};self.records.append(event)
                kind=self.fixture.get('reply_kind')
                if kind is None:return self.stop('original_secondary_XPC_send_boundary')
                ptr=0 if kind=='null' else BIND+107*16 if kind=='interrupted' else HEAP+0xe400
                if ptr:self.objects[ptr]='private_error' if kind in ('interrupted','error') else 'private_reply_dictionary'
                event.update({'kind':'modeled_secondary_XPC_reply','reply_kind':kind,'result':hex(ptr)});self.steps+=1;return self.ret(ptr)
            if name=='_xpc_get_type' and self.fixture.get('reply_kind'):
                self.steps+=1;ptr=self.reg('x0');kind=self.objects.get(ptr)
                result=BIND+106*16 if kind=='private_error' else HEAP+0xe700
                self.records.append({'kind':'modeled_secondary_XPC_type','callsite':call,'object':hex(ptr),
                    'result':hex(result),'native_XPC_executed':False});return self.ret(result)
            if name=='_xpc_dictionary_get_data' and self.fixture.get('reply_kind'):
                self.records.append({'kind':'original_secondary_XPC_get_data_boundary','callsite':call,'object':hex(self.reg('x0')),
                    'key':self.string(self.reg('x1')),'size_output_pointer':hex(self.reg('x2')),'native_XPC_executed':False})
                return self.stop('original_secondary_XPC_get_data_boundary')
            if name in ('_free','_xpc_release','_dispatch_release') and self.fixture.get('model_cleanup'):
                self.steps+=1;ptr=self.reg('x0')
                if name=='_free' and ptr and not any(a==ptr for a,n in self.allocations):return self.stop('secondary_unowned_free_guard')
                self.records.append({'kind':'modeled_secondary_cleanup','callsite':call,'name':name,'pointer':hex(ptr),
                    'tail_call':tail_call,'native_cleanup_executed':False});return self.ret()
            if name=='_bootstrap_look_up':
                event={'kind':'original_secondary_lookup_boundary','callsite':call,'bootstrap_name_u32':self.reg('w0'),
                    'service_name':self.string(self.reg('x1')),'output_pointer':hex(self.reg('x2')),'native_lookup_executed':False}
                self.records.append(event)
                if 'bootstrap_results' not in self.fixture:return self.stop('original_secondary_lookup_boundary')
                if self.lookup_index>=len(self.fixture['bootstrap_results']):return self.stop('secondary_lookup_results_guard')
                value=self.fixture['bootstrap_results'][self.lookup_index];self.lookup_index+=1;event.update({'kind':'modeled_secondary_lookup','result':value})
                if 'write_port_u32' in value:u.mem_write(self.reg('x2'),struct.pack('<I',value['write_port_u32']))
                return self.ret(value['status_u32'])
        return super().code(u,pc,n,data)
    def run_secondary(self):
        row=self.run_request();row['result_u32']=self.reg('w0');row['argument1_fixture8_bytes']=bytes(self.u.mem_read(self.argument1_value,8)).hex()
        row['private_allocations']=[{'address':hex(a),'size_bytes':n,'first32_bytes':bytes(self.u.mem_read(a,min(n,32))).hex()} for a,n in self.allocations]
        return row


def main():
    s=Pointers();rows=[];functions={};instructions={}
    fixtures=[{'label':'selector_'+str(v),'selector_signed64':v,'allocator':'success'} for v in (-9,-8,-7,-6,-5,-4,-3,-2,-1,0)]
    fixtures += [{'label':'first_allocator_boundary','selector_signed64':-8},
                 {'label':'first_allocator_null','selector_signed64':-8,'allocator':'null'},
                 {'label':'second_allocator_null','selector_signed64':-8,'allocator':'success','allocation_fail_index':1,'model_cleanup':True},
                 {'label':'dictionary_null','selector_signed64':-8,'allocator':'success','dictionary_result':'null','model_cleanup':True},
                 {'label':'dictionary_success','selector_signed64':-8,'allocator':'success','dictionary_result':'success'},
                 {'label':'modeled_queue','selector_signed64':-8,'allocator':'success','dictionary_result':'success','model_queue':True},
                 {'label':'connection_null','selector_signed64':-8,'allocator':'success','dictionary_result':'success','model_queue':True,'connection_result':'null','model_cleanup':True},
                 {'label':'connection_success','selector_signed64':-8,'allocator':'success','dictionary_result':'success','model_queue':True,'connection_result':'success'}]
    for kind in ('null','error','interrupted','dictionary'):
        fixtures.append({'label':'reply_'+kind,'selector_signed64':-8,'allocator':'success','dictionary_result':'success',
            'model_queue':True,'connection_result':'success','reply_kind':kind,'model_cleanup':True})
    legacy={'selector_signed64':-8,'allocator':'success','dictionary_result':'success','model_queue':True,
        'connection_result':'success','reply_kind':'error','model_cleanup':True}
    fixtures += [{**legacy,'label':'legacy_invalid_destination_lookup','mach_results':[0x10000003]},
        {**legacy,'label':'legacy_lookup_success_retry','mach_results':[0x10000003],
            'bootstrap_results':[{'status_u32':0,'write_port_u32':0x6ad1}]},
        {**legacy,'label':'legacy_lookup_error','mach_results':[0x10000003],'bootstrap_results':[{'status_u32':5}]},
        {**legacy,'label':'legacy_other_transport_error','mach_results':[0x10000004]}]
    for selector,delta in [(-2,0),(-6,0),(-8,32)]:
        fixtures.append({**legacy,'label':'XPC_selector_'+str(selector)+'_argument1_delta_'+str(delta),
            'selector_signed64':selector,'argument1_delta':delta,'reply_kind':None})
    fixtures += [{**legacy,'label':'legacy_cached_name_request','legacy_cached_name_u32':0x6a90},
        {**legacy,'label':'legacy_cached_name_retry','legacy_cached_name_u32':0x6a90,'mach_results':[0x10000003],
            'bootstrap_results':[{'status_u32':0,'write_port_u32':0x6ad1}]}]
    fixtures += [{'label':'zero_extended_minus8','selector_signed64':0xfffffff8},
        {'label':'reject_state_ones','selector_signed64':0,'secondary_state64':[(1<<64)-1,1],'stack_delta':16},
        {'label':'reject_state_mixed','selector_signed64':0,'secondary_state64':[0x1122334455667788,0x8877665544332211],'stack_delta':32}]
    fixtures += [{'label':'event_description_boundary','selector_signed64':0,'entry_override':0x15a4c14},
        {'label':'event_description_cleanup','selector_signed64':0,'entry_override':0x15a4c14,'model_description':True,'model_cleanup':True}]
    for fixture in fixtures:
        row=Secondary(s,fixture).run_secondary();ff=row.pop('original_functions');ii=row.pop('visited_instruction_records')
        row['original_function_starts']=[v['start'] for v in ff]
        for v in ff:functions[v['start']]=v
        for v in ii:instructions[v['ea']]=v
        rows.append(row)
    out={'scope':__doc__,'thin_sha256':THIN_SHA,'profiles':rows,'original_functions':list(functions.values()),
        'visited_instruction_records':list(instructions.values()),'generator_sha256':sha(Path(__file__).read_bytes()),
        'dependencies':{name:sha((ROOT/name).read_bytes()) for name in ['probe_corefp_exports.py','probe_corefp_mach_requests.py','corefp_fixups_inventory.json','corefp_import_calls.json']},
        'native_target_executed':False,'full_goal_complete':False}
    (ROOT/'corefp_secondary_client_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
    for row in rows:print(json.dumps({'label':row['fixture']['label'],'stop':row['stop_reason'],'steps':row['steps'],
        'result_u32':hex(row['result_u32']),'out':row['argument1_fixture8_bytes'],'last':row['records'][-1]}))


if __name__=='__main__':main()
