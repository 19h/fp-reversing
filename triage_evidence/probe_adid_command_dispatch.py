#!/usr/bin/env python3
"""Full original ADID callbacks for recovered commands and packet variants.

Only request/API/filesystem/credential fixtures vary. No instruction/frame/PC
intervention selects constructor,dispatch,cleanup or VM paths. Frozen private
API/PAC models; no native target/host operation. O(C*(B+F+K)) time/space with
finite per-case hooks and small owned request extents.
"""
import json
from pathlib import Path
import struct
from adid_reader import Adid,ROOT,sha,THIN_SHA,CS
from probe_adid_record_lifecycle import Lifecycle
from probe_adid_iokit_callers import Callers
from probe_adid_startup import unpack_records
from probe_adid_receiver import HEAP

MASK=(1<<64)-1


class Commands(Callers,Lifecycle):
    def __init__(self,s,f,checkpoint):
        # Bypass Callers' synthetic-record initializer; reuse only its frozen
        # API models/observers with records built by the original full request.
        Lifecycle.__init__(self,s,f,checkpoint);self.copy_writes=[];self.external_allocations=[];self.initial_filesystem=json.loads(json.dumps(self.fs));self.tree=json.loads((ROOT/'adid_command_dispatch_contracts.json').read_text())['command_tree'];self.leaves={int(r['parser_entry'],16) for r in self.tree['accepted']}
    def api(self,im):
        name=im['name'];f=self.fixture;site=self.reg('lr')-4
        if name=='_time' and 'model_time_seconds' in f:
            if self.reg('x0')!=0:return self.stop('command_time_pointer_guard')
            value=f['model_time_seconds'];self.records.append({'kind':'command_explicit_API_model','name':name,'callsite':hex(site),'null_output_pointer':True,'result_seconds':value,'native_API_executed':False});return self.finish_api(value)
        if name=='_arc4random_uniform' and 'model_uniform_result' in f:
            upper=self.reg('w0');value=f['model_uniform_result']
            if not 0<=value<upper:return self.stop('command_uniform_range_guard')
            self.records.append({'kind':'command_explicit_API_model','name':name,'callsite':hex(site),'upper_u32':upper,'result_u32':value,'native_API_executed':False});return self.finish_api(value)
        if name=='_malloc' and f.get('bounded_external_allocator'):
            size=self.reg('x0')
            if size>4096 or len(self.external_allocations)>=3:return self.stop('command_external_allocator_extent_guard')
            pointer=0 if f.get('external_allocation_NULL') else HEAP+0x1c000+4096*len(self.external_allocations)
            if pointer:
                self.u.mem_write(pointer,bytes([0xa5])*size);self.external_allocations.append((pointer,size));key='external_'+str(len(self.external_allocations));self.objects[key]=(pointer,size);self.object_initial[key]=bytes(self.u.mem_read(pointer,size)).hex()
            self.records.append({'kind':'command_explicit_API_model','name':name,'callsite':hex(site),'requested_bytes':size,'result':hex(pointer),'native_API_executed':False});return self.finish_api(pointer)
        return super().api(im)
    def code(self,u,pc,n,data):
        if pc==0x10016cd58:
            self.records.append({'kind':'original_command_word','pc':hex(pc),'encoded_u32':self.reg('w8'),'raw_request_word_u32':int.from_bytes(bytes.fromhex(self.fixture['payload_hex'])[4:8],'big'),'core_operation_u32':self.reg('w2')})
        if pc in self.leaves or pc==0x10016ec20:self.observe('original_command_parser_entry' if pc in self.leaves else 'original_command_rejection_entry',pc)
        if pc==0x100058654:
            e=self.observe('original_request_driven_IOKit_caller',pc);pointer=self.reg('x0');e.update({'record_address':hex(pointer),'record40_bytes':bytes(u.mem_read(pointer,40)).hex(),'source_return':hex(self.reg('lr'))})
        if pc in (0x10019c654,0x10019c7cc):self.observe('original_request_driven_allocation_request',pc)
        if pc in (0x10019c658,0x10019c7d0):
            e=self.observe('original_request_driven_allocation_return',pc);k='outer' if pc==0x10019c658 else 'nested';extent=96 if k=='outer' else 176;a=self.reg('x0');e.update({'object':k,'requested_bytes':extent,'result_address':hex(a)})
            if a:self.objects[k]=(a,extent);self.object_initial[k]=bytes(u.mem_read(a,extent)).hex()
        if pc in (0x10016ac30,0x10019c578,0x10019cb24,0x10019cb80,0x10019cbac,0x10019cc10,0x1001a1618,0x1001a23f0,0x1001a2ae8,0x1001ca538,0x100062468):
            e=self.observe('original_command_packet_boundary',pc);sp=self.reg('sp')
            if 0x100062468!=pc:e['frame_fields']={hex(off):bytes(u.mem_read(sp+off,width)).hex() for off,width in [(0x1740,8),(0x1d0c,4),(0x1a80,8),(0x2be0,8),(0x1560,8),(0x34dc,4)]}
            if pc==0x10016ac30:e['tail_producer']={'input_base':hex(self.reg('x11')),'offset_u64':hex(self.reg('x9')),'pointer_to_store':hex(self.reg('x12')),'encoded_length_to_store_u32':self.reg('w8')}
            if pc==0x10019cb24:e['constructed_objects']={k:bytes(u.mem_read(a,z)).hex() for k,(a,z) in self.objects.items()}
        if self.s.base<=pc<self.s.base+len(self.s.data):
            i=next(CS.disasm(self.s.read(pc,4),pc),None)
            if i and i.mnemonic in ('brk','svc','hvc','smc'):self.records.append({'kind':'unexecuted_original_instruction_boundary','pc':hex(pc),'bytes':self.s.read(pc,4).hex(),'mnemonic':i.mnemonic,'operands':i.op_str,'native_instruction_executed':False})
        return super().code(u,pc,n,data)


def bases():
    prior=json.loads((ROOT/'adid_context_profiles.json').read_text());labels={0:'context_error_producer',265:'nonroot_ready_record_265',501:'nonroot_ready_record_501'}
    return {uid:next(r['fixture'] for r in prior['profiles'] if r['fixture']['label']==label) for uid,label in labels.items()}


def fixtures():
    b=bases();tree=json.loads((ROOT/'adid_command_dispatch_contracts.json').read_text())['command_tree'];out=[]
    def add(label,payload,kind,uid=0,**extra):out.append({**b[uid],'label':label,'mode':'command','case_kind':kind,'payload_hex':payload.hex(),'instruction_budget':800000,'instruction_or_frame_overrides':False,**extra})
    commands=sorted(r['wire_command_u32'] for r in tree['accepted'])
    for command in commands:add('command_'+hex(command),struct.pack('>IIIQQ',1,command,1,MASK-7,0),'selected_command')
    for command in sorted({0,0xffffffff}|{(x+d)&0xffffffff for x in commands for d in [-1,1]}):add('unknown_command_'+hex(command),struct.pack('>IIIQQ',1,command,1,MASK-7,0),'unknown_command')
    for length in [0,1,26,27,28,64]:add('construct_zero_'+str(length),struct.pack('>IIIQI',1,0x716bd86c,1,MASK-7,length)+bytes(length),'constructor_blob',declared_blob_bytes=length,actual_blob_bytes=length)
    for tag in [1,0x5747032f]:add('construct_first_word_'+hex(tag),struct.pack('>IIIQI',1,0x716bd86c,1,MASK-7,32)+struct.pack('>I',tag)+bytes(28),'constructor_blob',declared_blob_bytes=32,actual_blob_bytes=32)
    for declared,actual in [(32,0),(27,26)]:add(f'construct_truncated_{declared}_{actual}',struct.pack('>IIIQI',1,0x716bd86c,1,MASK-7,declared)+bytes(actual),'constructor_truncation',declared_blob_bytes=declared,actual_blob_bytes=actual)
    add('construct_uid501',struct.pack('>IIIQI',1,0x716bd86c,1,MASK-7,27)+bytes(27),'constructor_blob',uid=501,declared_blob_bytes=27,actual_blob_bytes=27)
    for uid in [0,265,501]:
        for status in [0,-1]:add(f'header_only_unlink_uid{uid}_status{status}',struct.pack('>III',1,0x72096fe6,1),'unlink_command',uid=uid,unlink_result=status)
    for value in [0,1,16,255,65535,0xffffffff]:add('allocation_argument_'+str(value),struct.pack('>IIII',1,0x9679d4b5,1,value),'allocation_argument',request_scalar_u32=value)
    for first in [0,2,0xffffffff]:add('bad_word0_'+str(first),struct.pack('>IIIQQ',first,0x632b8d6e,1,MASK-7,0),'bad_word0')
    for label,extra in [('zero',{'VMM_value':0}),('one',{'VMM_value':1}),('two',{'VMM_value':2}),('failure',{'VMM_value':1,'VMM_status':5})]:add('environment_command_'+label,struct.pack('>III',1,0x76e89210,1),'environment_command',**extra)
    env={'VMM_value':1,'model_time_seconds':1700000000,'model_uniform_result':0x12345678,'bounded_external_allocator':True}
    add('environment_to_IOMainPort',struct.pack('>III',1,0x76e89210,1),'environment_continuation',**env)
    hardware=['_IOMainPort','_IOServiceMatching','_IOServiceGetMatchingServices','_IOIteratorNext','_IOServiceOpen','_IOObjectRelease']
    for label,extra in [('opaque',{}),('transport_error',{'method100_mode':'return_error'}),('identity',{'method100_mode':'identity_success'}),('open_failure',{'service_open_status':0xe00002c7})]:
        add('environment_iokit_'+label,struct.pack('>III',1,0x76e89210,1),'environment_iokit',**env,**extra,split_provider_names=True,execute_once_callback=True)
        out[-1]['model_APIs']=sorted(set(out[-1]['model_APIs']+hardware))
    return out


def run_one(s,f,checkpoint):
    q=Commands(s,json.loads(json.dumps(f)),checkpoint);r=q.result();r['filesystem_model_initial']=q.initial_filesystem;return q,r


def main():
    s=Adid();checkpoint=json.loads((ROOT/'adid_peer_checkpoint.json').read_text());rows=[];functions={};instructions={}
    for f in fixtures():
        q,r=run_one(s,f,checkpoint)
        for x in r.pop('original_functions'):functions[x['start']]=x
        for x in r.pop('instruction_records'):instructions[x['ea']]=x
        rows.append(r);es=unpack_records(r);print(json.dumps({'label':f['label'],'kind':f['case_kind'],'stop':r['stop_reason'],'steps':r['steps'],'reply':[(e['size_bytes'],e['payload_bytes']) for e in es if e.get('name')=='_xpc_dictionary_set_data'],'objects':r['object_addresses'],'unlink':[(e.get('callsite'),e.get('path'),e.get('result')) for e in es if e.get('name')=='_unlink']}),flush=True)
    out={'scope':__doc__,'thin_sha256':THIN_SHA,'profiles':rows,'original_functions':list(functions.values()),'original_instruction_records':list(instructions.values()),'generator_sha256':sha(Path(__file__).read_bytes()),
        'dependencies':{n:sha((ROOT/n).read_bytes()) for n in ['adid_reader.py','probe_adid_command_dispatch.py','probe_adid_record_lifecycle.py','probe_adid_context_gates.py','probe_adid_iokit_callers.py','probe_adid_iokit.py','probe_adid_requests.py','probe_adid_startup.py','probe_adid_receiver.py','adid_peer_checkpoint.json','adid_context_profiles.json','adid_command_dispatch_contracts.json']},'native_target_executed':False,'full_goal_complete':False}
    (ROOT/'adid_command_dispatch_profiles.json').write_text(json.dumps(out,indent=2)+'\n')


if __name__=='__main__':main()
