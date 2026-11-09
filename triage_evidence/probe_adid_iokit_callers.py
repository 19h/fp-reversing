#!/usr/bin/env python3
"""Original ADID caller-built helper records and Avp method100 boundaries.

Frozen source reader and prior private models; no native target or host API.
New method100 outcomes are explicit identity/error controls. O(C*(B+F+K))
time and O(B+F+C*K) evidence space, with finite hook caps per case.
"""
import json
import struct
from pathlib import Path
from unicorn import UC_HOOK_MEM_READ,arm64_const as A
from adid_reader import Adid,ROOT,sha,THIN_SHA
from probe_adid_iokit import Hardware
from probe_adid_receiver import HEAP,DONE
from probe_adid_startup import unpack_records

MASK32=(1<<32)-1
MASK64=(1<<64)-1
P=HEAP+0x1c000
OUT=HEAP+0x1c100
BUF=HEAP+0x1c400
DEST=HEAP+0x1c900


def caller_record(f):
    raw=bytearray(64)
    if f['caller']=='primary':
        key=(((P&MASK32)^0x834674ac)*0x0a42990d)&MASK32
        struct.pack_into('<Q',raw,0,(f.get('output_pointer',OUT)+0x7e1f59740c8f6451)&MASK64)
        struct.pack_into('<I',raw,8,key^f.get('caller_basis',0x237f))
    else:
        key=(((P&MASK32)^0x4e89bd66)*0x0b08355f)&MASK32
        struct.pack_into('<Q',raw,0,(f.get('output_pointer',OUT)+0x68a91db5735d89de)&MASK64)
        struct.pack_into('<I',raw,8,(f['input_size']+0x4349792f-key)&MASK32)
        struct.pack_into('<QQ',raw,16,f.get('destination',DEST),f.get('buffer',BUF))
        struct.pack_into('<I',raw,36,(f.get('caller_basis',0x5f8)-key)&MASK32)
    if f.get('literal_zero_pointer_field'):struct.pack_into('<Q',raw,0,0)
    return bytes(raw)


class Callers(Hardware):
    def __init__(self,s,f,checkpoint):
        super().__init__(s,f,checkpoint)
        self.u.mem_write(P,caller_record(f))
        self.u.mem_write(OUT,bytes.fromhex('a5a5a5a5'))
        self.u.mem_write(BUF-16,bytes((i*37+11)&255 for i in range(1056)))
        self.u.mem_write(DEST,bytes([0xa5])*1024)
        self.watch_slots={0x1002d8640,0x1002d8998,0x1002d8400}
        for slot in self.watch_slots:self.u.hook_add(UC_HOOK_MEM_READ,self.pointer_read,begin=slot,end=slot+7)
        self.copy_writes=[]
        self.initial_buffers=self.buffers()
    def buffers(self):
        return {'record64':bytes(self.u.mem_read(P,64)).hex(),'output4':bytes(self.u.mem_read(OUT,4)).hex(),
            'source_surrounding1056':bytes(self.u.mem_read(BUF-16,1056)).hex(),'destination1024':bytes(self.u.mem_read(DEST,1024)).hex()}
    def pointer_read(self,u,access,address,size,value,data):
        self.records.append({'kind':'original_selected_pointer_read','pc':hex(self.reg('pc')),'address':hex(address),'size_bytes':size,
            'decoded_private_value_u64':hex(struct.unpack('<Q',u.mem_read(address,8))[0]),'source_pointer':self.s.decoded[address]})
    def code(self,u,pc,n,data):
        if pc in (0x100059548,0x10005895c):
            address=self.reg('sp')+(0x20 if pc==0x100059548 else 0x28)
            self.records.append({'kind':'original_caller_helper_return_record','pc':hex(pc),'address':hex(address),'bytes16':bytes(u.mem_read(address,16)).hex()})
        if pc==0x1000595fc:
            address=self.reg('x8');before=bytes(u.mem_read(address,36))
            event={'kind':'original_caller_post_context','pc':hex(pc),'address':hex(address),'original_observed_bytes36':before.hex()}
            self.records.append(event)
            if 'post_context_flag' in self.fixture:
                u.mem_write(address,bytes([self.fixture['post_context_flag']]))
                if 'post_context_tag' in self.fixture:u.mem_write(address+32,struct.pack('<I',self.fixture['post_context_tag']))
                self.records.append({'kind':'analyst_private_post_context_patch','pc':hex(pc),'address':hex(address),'bytes36':bytes(u.mem_read(address,36)).hex(),
                    'native_state_or_writer_established':False})
        if pc==0x100059644:
            self.records.append({'kind':'original_caller_post_tag_comparison','pc':hex(pc),'loaded_u32':self.reg('x8')&MASK32,'expected_u32':self.reg('x9')&MASK32})
        if pc in (0x1000208fc,0x10002af70):
            p=self.reg('x0');raw=bytes(u.mem_read(p,24));self.records.append({'kind':'original_caller_built_helper_record','entry':hex(pc),
                'caller_return':hex(self.reg('lr')),'address':hex(p),'observed_bytes24':raw.hex(),'stack_pointer':hex(self.reg('sp')),
                'callee_not_replaced':True})
        if pc in (0x100058ba0,0x100058c88):
            address=self.reg('x17') if pc==0x100058ba0 else self.reg('x14')
            value=self.reg('x0')&255 if pc==0x100058ba0 else self.reg('x16')&255
            self.copy_writes.append({'pc':hex(pc),'address':hex(address),'value_u8':value})
        return super().code(u,pc,n,data)
    def api(self,im):
        if im['name']=='_IOServiceOpen' and self.fixture.get('split_provider_names'):
            original=self.fixture
            if self.reg('x3')==0x1002dcee4:self.fixture={**original,'connection_name_u32':original.get('avp_connection_name_u32',0x580a)}
            try:return super().api(im)
            finally:self.fixture=original
        if im['name']=='_IOConnectCallStructMethod' and self.reg('x1')==26 and self.reg('x3')==96 and self.fixture.get('direct26_mode'):
            args=[self.reg('x'+str(i)) for i in range(8)];old=struct.unpack('<Q',self.u.mem_read(args[5],8))[0]
            expected=self.fixture.get('avp_connection_name_u32',0x580a) if self.fixture.get('split_provider_names') else 0x5804
            if args[0]!=expected or args[2]!=args[4] or old!=96:return self.stop('caller_direct26_shape_guard')
            mode=self.fixture['direct26_mode']
            if mode not in ('identity_success','return_error'):return self.stop('caller_direct26_mode_guard')
            result=0 if mode=='identity_success' else 0xe00002c7
            self.records.append({'kind':'original_direct26_boundary_and_model','name':im['name'],'callsite':hex(self.reg('lr')-4),'args_x0_x7':[hex(v) for v in args],
                'input_bytes':bytes(self.u.mem_read(args[2],96)).hex(),'output_size_before_u64':old,'mode':mode,'result_u32':result,
                'buffer_unchanged':True,'native_API_executed':False,'kext_transform_executed':False})
            return self.finish_api(result)
        if im['name']=='_IOConnectCallStructMethod' and self.reg('x1')==100:
            args=[self.reg('x'+str(i)) for i in range(8)];n=args[3]
            if n>4096 or args[2]!=args[4]:return self.stop('caller_method100_shape_guard')
            old=struct.unpack('<Q',self.u.mem_read(args[5],8))[0]
            e={'kind':'original_method100_boundary','name':im['name'],'callsite':hex(self.reg('lr')-4),'args_x0_x7':[hex(v) for v in args],
                'input_bytes':bytes(self.u.mem_read(args[2],n)).hex(),'output_size_before_u64':old,'native_API_executed':False}
            self.records.append(e)
            mode=self.fixture.get('method100_mode')
            if mode is None:return self.stop('original_method100_opaque_boundary')
            if args[0]!=self.fixture.get('connection_name_u32',0x5804) or old!=n:return self.stop('caller_method100_owned_shape_guard')
            if mode not in ('identity_success','return_error'):return self.stop('caller_method100_mode_guard')
            result=self.fixture.get('method100_status_u32',0xe00002c7) if mode=='return_error' else 0
            new=self.fixture.get('method100_output_size',old)
            if new>n:return self.stop('caller_method100_output_capacity_guard')
            self.u.mem_write(args[5],struct.pack('<Q',new))
            self.records.append({'kind':'caller_method100_model','callsite':e['callsite'],'mode':mode,'result_u32':result,
                'output_size_after_u64':new,'buffer_unchanged':True,'native_API_executed':False,'kext_transform_executed':False})
            return self.finish_api(result)
        return super().api(im)


def main():
    s=Adid();ck=json.loads((ROOT/'adid_peer_checkpoint.json').read_text());old=json.loads((ROOT/'adid_iokit_profiles.json').read_text())
    seed=next(r['fixture'] for r in old['profiles'] if r['fixture']['label']=='first_method26_error')
    seed={k:v for k,v in seed.items() if k not in ('synthetic_record_basis','record_codec','record_field8')}
    fixtures=[]
    def add(label,caller='avp100',**updates):
        f={**seed,'label':label,'caller':caller,'new_entry':0x1000590ac if caller=='primary' else 0x100058654,
            'new_args':[P],'input_size':96,'instruction_budget':400000,**updates};fixtures.append(f);return f
    primary=add('primary_error','primary')
    add('primary_identity','primary',method26_mode='identity_success')
    for flag,tag in [(0x41,0),(0x40,0x527e14b6),(0x41,0x527e14b6)]:
        add('primary_post_'+hex(flag)+'_'+hex(tag),'primary',method26_mode='identity_success',post_context_flag=flag,post_context_tag=tag)
    add('primary_null_output','primary',output_pointer=0)
    add('primary_literal_zero_field','primary',literal_zero_pointer_field=True)
    add('primary_bad_basis','primary',caller_basis=0)
    add('primary_VMM_nonzero','primary',VMM_value=2,method26_mode=None)
    for direct in ('identity_success','return_error'):
        for primary_mode in ('identity_success','return_error'):
            add('two_stage_'+direct+'_'+primary_mode,'primary',VMM_value=2,method26_mode=primary_mode,direct26_mode=direct,split_provider_names=True)
    avp=add('avp100_boundary')
    add('avp100_error',method100_mode='return_error')
    add('avp100_identity',method100_mode='identity_success')
    for n in (1,16,256):add('avp100_size_'+str(n),input_size=n,method100_mode='identity_success')
    for n in (0,1,16,95):add('avp100_returned_size_'+str(n),method100_mode='identity_success',method100_output_size=n)
    for name,dest in [('equal',BUF),('above',BUF+1),('below',BUF-1)]:add('avp100_overlap_'+name,destination=dest,method100_mode='identity_success')
    for name,fields in [('null_count',{'output_pointer':0}),('null_destination',{'destination':0}),('null_buffer',{'buffer':0}),('zero_size',{'input_size':0})]:add('avp100_'+name,**fields)
    for name,fields in [('mainport',{'mainport_status':5}),('no_service',{'service_name_u32':0}),('open',{'service_open_status':0xe00002c7})]:add('avp100_failure_'+name,**fields)
    profiles=[];functions={};instructions={}
    def retain(q,r):
        r['private_buffers_before']=q.initial_buffers;r['private_buffers_after']=q.buffers();r['source_copy_writes']=q.copy_writes
        r['iokit_object_models_final']=json.loads(json.dumps(q.iokit_objects));r['lock_models_final']=json.loads(json.dumps(q.lock_models))
        for f in r.pop('original_functions'):functions[f['start']]=f
        for i in r.pop('instruction_records'):instructions[i['ea']]=i
        profiles.append(r);es=unpack_records(r);print(json.dumps({'label':r['fixture']['label'],'stop':r['stop_reason'],'steps':r['steps'],
            'helpers':len([e for e in es if e['kind']=='original_caller_built_helper_record']),'copy_bytes':len(q.copy_writes),'record_status':r['private_buffers_after']['record64'][64:72] if q.fixture['caller']=='avp100' else r['private_buffers_after']['record64'][24:32]}),flush=True)
    for f in fixtures:
        q=Callers(s,f,ck);retain(q,q.run_continuation())
    for source,group in [(primary,'primary_recovery'),(next(f for f in fixtures if f['label']=='avp100_identity'),'avp100_warm')]:
        q=Callers(s,{**source,'label':group+'_0','sequence_group':group,'sequence_index':0},ck)
        for j in range(3 if group=='primary_recovery' else 2):
            if j:
                q.fixture={**source,'label':group+'_'+str(j),'sequence_group':group,'sequence_index':j,'all_private_state_retained':True}
                if group=='primary_recovery':q.fixture.update(method26_mode='identity_success',connection_name_u32=0x5814)
                q.steps=0;q.reason=None;q.records=[];q.visited=[];q.last_edge=None;q.copy_writes=[];q.initial_buffers=q.buffers()
                q.u.reg_write(A.UC_ARM64_REG_SP,q.sp);q.u.reg_write(A.UC_ARM64_REG_LR,DONE);q.u.reg_write(A.UC_ARM64_REG_PC,q.fixture['new_entry']);q.u.reg_write(A.UC_ARM64_REG_X0,P)
            retain(q,q.run_continuation())
    out={'scope':__doc__,'thin_sha256':THIN_SHA,'profiles':profiles,'original_functions':list(functions.values()),'original_instruction_records':list(instructions.values()),
        'generator_sha256':sha(Path(__file__).read_bytes()),'dependencies':{n:sha((ROOT/n).read_bytes()) for n in ['adid_reader.py','probe_adid_receiver.py','probe_adid_startup.py','probe_adid_requests.py','probe_adid_iokit.py','adid_peer_checkpoint.json','adid_iokit_profiles.json']},
        'native_target_executed':False,'full_goal_complete':False}
    (ROOT/'adid_iokit_caller_profiles.json').write_text(json.dumps(out,indent=2)+'\n')


if __name__=='__main__':main()
