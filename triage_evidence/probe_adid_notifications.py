#!/usr/bin/env python3
"""Original akd OTP notification/cache/exit sequences in an owned guest.

Calls enter complete original methods/callbacks; memory persists across calls.
Explicit libnotify,atexit,time,XPC/allocation models;no native target/API.
O(C*(B+F+K)) time/space;finite original-hook caps and bounded owned extents.
"""
import base64
import hashlib
import json
from pathlib import Path
import struct
import zlib
from unicorn import arm64_const as A
from akd_client_reader import Akd,ROOT,THIN_SHA,sha
from probe_akd_clients import Client,OUTPUTS
from probe_adid_receiver import DONE,HEAP
from probe_adid_startup import unpack_records

NAMES=['com.apple.adid.midchangedV1','com.apple.adid.midchangedV1.5','com.apple.adid.midchangedV3']
TOKENS={name:7331+j for j,name in enumerate(NAMES)}
CACHE_START=0x100450500
CACHE_SIZE=0xc0
GATES={0x100308b34,0x100308b3c,0x100308b40,0x100308b44,0x100308b60,
 0x100308f64,0x100309070,0x100309124,0x100309fb4,0x10030bb28,
 0x100308fe0,0x100308fe8,0x10030a094,0x10030a09c}


class Notifications(Client):
    def __init__(self,s,f):
        self.registered_tokens={};self.token_checks={};self.next_token=7331;self.exit_callbacks=[];self.notification_effects=[];self.cache_reads=[];self.heap_writes=[];self.heap_reads=[]
        super().__init__(s,f)
    def write(self,u,access,a,n,value,data):
        if HEAP+0x6000<=a and a+n<=HEAP+0x1a000:
            owners=[r for r in self.allocations if not r['freed'] and r['pointer']<=a and a+n<=r['pointer']+r['size_bytes']]
            event={'pc':hex(self.reg('pc')),'address':hex(a),'size_bytes':n,'before':bytes(u.mem_read(a,n)).hex(),'value':hex(value&((1<<(8*n))-1)),'nominal_live_allocation_owners':[hex(r['pointer']) for r in owners]}
            if self.reg('pc') in [0x100309618,0x100309624,0x100309634,0x100309838]:
                dest=self.reg('x0');allocation=next((r for r in self.allocations if r['pointer']==dest and not r['freed']),None);event.update(copy_destination_base=hex(dest),copy_source_base=hex(self.reg('x21')))
                if allocation:event.update(copy_destination_requested_bytes=allocation['size_bytes'],write_within_destination_request=dest<=a and a+n<=dest+allocation['size_bytes'])
            event['source_visit_index']=len(self.visited)-1;self.heap_writes.append(event)
        return super().write(u,access,a,n,value,data)
    def read_hook(self,u,access,a,n,value,data):
        if a<CACHE_START+CACHE_SIZE and CACHE_START<a+n:self.cache_reads.append({'pc':hex(self.reg('pc')),'address':hex(a),'size_bytes':n,'bytes':bytes(u.mem_read(a,n)).hex()})
        if HEAP+0x6000<=a and a+n<=HEAP+0x1a000:self.heap_reads.append({'pc':hex(self.reg('pc')),'address':hex(a),'size_bytes':n,'bytes':bytes(u.mem_read(a,n)).hex(),'nominal_live_allocation_owners':[hex(r['pointer']) for r in self.allocations if not r['freed'] and r['pointer']<=a and a+n<=r['pointer']+r['size_bytes']],'source_visit_index':len(self.visited)-1})
        return super().read_hook(u,access,a,n,value,data)
    def effect(self,p,raw,kind):
        before=bytes(self.u.mem_read(p,len(raw)));self.u.mem_write(p,raw);self.notification_effects.append({'kind':kind,'callsite':hex(self.reg('lr')-4),'address':hex(p),'size_bytes':len(raw),'before':before.hex(),'after':raw.hex(),'native_API_executed':False})
    def code(self,u,pc,n,data):
        if pc in GATES:self.records.append({'kind':'original_notification_cache_gate','pc':hex(pc),'registers':{r:hex(self.reg(r)) for r in ['x8','x9','x10','x11','x19','x20','x21','x22','x25','x27']},'NZCV':hex(u.reg_read(A.UC_ARM64_REG_NZCV))})
        old=len(self.records);result=super().code(u,pc,n,data)
        if pc in self.binds:
            for e in self.records[old:]:e.setdefault('source_visit_index',len(self.visited)-1)
        return result
    def api(self,im):
        name=im['name'];x=[self.reg('x'+str(i)) for i in range(8)];site_value=self.reg('lr')-4
        if not self.s.base<=site_value<self.s.base+len(self.s.data):site_value=int(self.last_edge['pc'],16)
        site=hex(site_value);f=self.fixture
        if name=='_free':self.records.append({'kind':'notification_free_argument_observation','name':name,'callsite':site,'pointer':hex(x[0]),'allocation_known':any(r['pointer']==x[0] for r in self.allocations),'native_API_executed':False})
        if name=='_malloc':
            size=x[0]
            if size>8192 or len(self.allocations)>=64 or self.alloc_cursor+size>HEAP+0x1a000:return self.stop('notification_sequence_allocator_extent_guard')
            ptr=0 if f.get('allocation_NULL') else self.alloc_cursor
            if ptr:self.alloc_cursor=(ptr+size+15)&~15;self.allocations.append({'pointer':ptr,'size_bytes':size,'freed':False});self.u.mem_write(ptr,b'\xa5'*size)
            self.records.append({'kind':'explicit_client_allocation','name':name,'callsite':site,'size_bytes':size,'result':hex(ptr),'native_API_executed':False,'sequence_allocation_cap':64});return self.finish_api(ptr)
        if name not in ['_notify_register_check','_notify_check','_notify_cancel','_atexit','_gettimeofday']:return super().api(im)
        e={'kind':'explicit_notification_API','name':name,'callsite':site,'args_x0_x7':[hex(v) for v in x],'native_API_executed':False};self.records.append(e)
        if name=='_notify_register_check':
            key=self.string(x[0]);e['notification_name']=key
            if key not in TOKENS:return self.stop('unreviewed_notification_name')
            result=f.get('register_status',{}).get(key,0);token=self.next_token
            e.update(result_u32=result&0xffffffff,token_output_before=bytes(self.u.mem_read(x[1],4)).hex(),output_written=result==0)
            if result==0:self.effect(x[1],struct.pack('<i',token),'notification_register_token_output');self.registered_tokens[token]=key;self.token_checks[token]=0;self.next_token+=1
        elif name=='_notify_check':
            token=x[0]&0xffffffff;key=self.registered_tokens.get(token);result=f.get('check_status',{}).get(key,0 if key else 2);initial=self.token_checks.get(token,0)==0;changed=f.get('initial_check_value',1) if initial else f.get('changed',{}).get(key,0)
            e.update(token_u32=token,notification_name=key,result_u32=result&0xffffffff,changed_u32=changed&0xffffffff,initial_check=initial,output_before=bytes(self.u.mem_read(x[1],4)).hex(),output_written=result==0)
            if result==0:self.effect(x[1],struct.pack('<I',changed&0xffffffff),'notification_check_flag_output');self.token_checks[token]=self.token_checks.get(token,0)+1
        elif name=='_notify_cancel':
            token=x[0]&0xffffffff;key=self.registered_tokens.get(token);result=f.get('cancel_status',0);e.update(token_u32=token,notification_name=key,result_u32=result&0xffffffff)
            if result==0:self.registered_tokens.pop(token,None)
        elif name=='_atexit':
            result=f.get('atexit_status',0);e.update(callback=hex(x[0]),result_signed32=result)
            if x[0] not in self.s.starts:return self.stop('notification_exit_callback_not_compiler_entry')
            if result==0:self.exit_callbacks.append(x[0])
        else:
            if x[1]!=0:return self.stop('notification_time_timezone_guard')
            sec=f.get('clock_seconds',1700000000);usec=f.get('clock_microseconds',0);result=f.get('clock_status',0)
            if not -(1<<63)<=sec<(1<<63) or not 0<=usec<1000000:return self.stop('notification_time_value_guard')
            e.update(seconds=sec,microseconds=usec,result_signed32=result,output_before=bytes(self.u.mem_read(x[0],16)).hex(),output_written=result==0)
            if result==0:self.effect(x[0],struct.pack('<qi4x',sec,usec),'notification_timeval_output')
        return self.finish_api(result)


def invoke(q,f,entry=None):
    """Fresh call boundary;preserve all guest global/heap state without patches."""
    assert q.reg('sp')==q.sp
    q.fixture=json.loads(json.dumps(f));q.reason=None;q.steps=0;q.records=[];q.visited=[];q.instructions={};q.functions={};q.notification_effects=[];q.cache_reads=[];q.heap_writes=[];q.heap_reads=[]
    if entry is not None:q.fixture.update(entry=entry,args=[],entry_scope='original_atexit_callback_after_successful_registration')
    q.u.reg_write(A.UC_ARM64_REG_LR,DONE)
    before={hex(a):bytes(q.u.mem_read(a,n)).hex() for a,n in OUTPUTS};cache=bytes(q.u.mem_read(CACHE_START,CACHE_SIZE)).hex();tokens=dict(q.registered_tokens);callbacks=list(q.exit_callbacks)
    r=q.run();r.update({'output_observation_windows_before':before,'output_observation_windows_after':{hex(a):bytes(q.u.mem_read(a,n)).hex() for a,n in OUTPUTS},'cache_region_before':cache,'cache_region_after':bytes(q.u.mem_read(CACHE_START,CACHE_SIZE)).hex(),'allocation_model_final':q.allocations,'allocation_observation_bytes_after':{hex(a['pointer']):bytes(q.u.mem_read(a['pointer'],a['size_bytes'])).hex() for a in q.allocations},'registered_tokens_before':tokens,'registered_tokens_after':q.registered_tokens,'exit_callbacks_before':[hex(a) for a in callbacks],'exit_callbacks_after':[hex(a) for a in q.exit_callbacks],'explicit_API_write_effects':q.notification_effects,'original_cache_reads':q.cache_reads,'call_boundary_LR':hex(DONE),'call_boundary_internal_frame_or_instruction_overrides':False})
    r['original_heap_writes']=q.heap_writes
    r['original_heap_reads']=q.heap_reads
    return json.loads(json.dumps(r))


def cases():
    base=next(r['fixture'] for r in json.loads((ROOT/'akd_client_profiles.json').read_text())['profiles'] if r['fixture']['label']=='otp_rich_two_spans');out=[]
    def add(label,dsid=1,warm=None,first=None,cleanup=False,second_dsid=None):
        f=json.loads(json.dumps(base));f.update(label=label+'_cold',clock_seconds=1700000000);f['args'][2]=dsid&((1<<64)-1);f.update(first or {});g={**f,'label':label+'_warm',**(warm or {})}
        if second_dsid is not None:g['args']=list(g['args']);g['args'][2]=second_dsid&((1<<64)-1)
        out.append({'label':label,'calls':[f,g],'cleanup_after':cleanup})
    for dsid in [-17,-16,-9,-8,-7,-6,-5,-4,-3,-2,-1,0,1,0x1122334455667788,0x1000000000000001]:add('dsid_'+str(dsid),dsid)
    for delta in [-9020,-9019,-8991,-8990,-8989,-8961,-8960,-61,-31,-30,-29,-21,-20,-19,-1,1,5,9,10,29,30,31,59,60,61]:add('clock_delta_'+str(delta),warm={'clock_seconds':1700000000+delta})
    for dsid in [-8,-1,1]:
        for name in NAMES:add('changed_'+str(dsid)+'_'+name.rsplit('.',1)[-1],dsid,warm={'changed':{name:1}})
    for dsid in [-8,-1,1]:add('check_failure_'+str(dsid),dsid,warm={'check_status':{name:2 for name in NAMES}})
    for name in NAMES:add('register_failure_'+name.rsplit('.',1)[-1],first={'register_status':{name:1}})
    add('atexit_failure',first={'atexit_status':-1})
    add('initial_check_zero_control',first={'initial_check_value':0})
    add('clock_failure',warm={'clock_status':-1})
    add('microseconds_only',warm={'clock_microseconds':999999})
    for label,mid,otp in [('larger',b'ABCDEFG',b'QRSTUVXYZ'),('smaller',b'a',b'Z')]:add('refresh_'+label+'_spans',warm={'reply_hex':(struct.pack('>II',0,len(mid))+mid+struct.pack('>I',len(otp))+otp).hex(),'changed':{NAMES[0]:1}})
    case=out[-2];third={**case['calls'][1],'label':'refresh_larger_spans_followup','changed':{}};case['calls'].append(third)
    for n in [17,33]:add('refresh_capacity_'+str(n),warm={'reply_hex':(struct.pack('>II',0,n)+bytes((65+i%26) for i in range(n))+struct.pack('>I',n)+bytes((97+i%26) for i in range(n))).hex(),'changed':{NAMES[0]:1}})
    add('other_dsid',second_dsid=2)
    for name in NAMES:add('changed_nonboolean_'+name.rsplit('.',1)[-1],warm={'changed':{name:0xffffffff}})
    add('cleanup_success',cleanup=True)
    add('cleanup_cancel_failure',warm={'cancel_status':2},cleanup=True)
    for sec in [-31,-30,-1,0,1,29,30,31,0x7fffffff,0xffffffff,1<<40,(1<<63)-1]:add('absolute_clock_'+str(sec),first={'clock_seconds':sec})
    for label,keys,changes in [('two_cache_keys',[1,2,1],{}),('three_cache_keys',[1,2,3,1],{}),('two_classes',[1,-1,1],{}),('invalidation_two_keys',[1,2,1,2],{2:{NAMES[0]:1}})]:
        add(label);case=out[-1];template=case['calls'][0];case['calls']=[]
        for j,key in enumerate(keys):
            f=json.loads(json.dumps(template));f.update(label=label+'_call_'+str(j),changed=changes.get(j,{}));f['args'][2]=key&((1<<64)-1);case['calls'].append(f)
    return out


def run_case(s,case):
    q=Notifications(s,case['calls'][0]);calls=[]
    for f in case['calls']:
        row=invoke(q,f);calls.append(row)
        if row['stop_reason']!='returned_to_private_fixture':break
    if case['cleanup_after'] and all(r['stop_reason']=='returned_to_private_fixture' for r in calls) and q.exit_callbacks:
        callback=q.exit_callbacks[-1];row=invoke(q,{**case['calls'][-1],'label':case['label']+'_exit'},callback);calls.append(row)
    return q,{'case':case,'calls':calls,'native_target_executed':False,'state_preserved_between_calls':True,'native_notification_or_exit_executed':False}


def main():
    s=Akd();out=[];functions={};instructions={}
    for case in cases():
        q,row=run_case(s,case)
        for r in row['calls']:
            for v in r.pop('original_functions'):functions[v['start']]=v
            for v in r.pop('instruction_records'):instructions[v['ea']]=v
        out.append(row);warm=row['calls'][1] if len(row['calls'])>1 else row['calls'][0];ev=unpack_records(warm);print(json.dumps({'label':case['label'],'stops':[r['stop_reason'] for r in row['calls']],'warm_u32':hex(warm['result_u32']),'warm_checks':[(e['notification_name'],e['result_u32'],e['changed_u32']) for e in ev if e.get('name')=='_notify_check'],'warm_sends':sum(e.get('name')=='_xpc_connection_send_message_with_reply_sync' for e in ev)}),flush=True)
    deps=['akd_client_reader.py','akd_client_inventory.json','akd_client_profiles.json','probe_akd_clients.py','probe_adid_receiver.py'];result={'scope':__doc__,'thin_sha256':THIN_SHA,'cases':out,'original_functions':list(functions.values()),'original_instruction_records':list(instructions.values()),'generator_sha256':sha(Path(__file__).read_bytes()),'dependencies':{n:sha((ROOT/n).read_bytes()) for n in deps},'native_target_executed':False,'full_goal_complete':False};(ROOT/'adid_notification_profiles.json').write_text(json.dumps(result,indent=2)+'\n')


if __name__=='__main__':main()
