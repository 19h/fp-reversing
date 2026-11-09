#!/usr/bin/env python3
"""Original notifyd selector/checkin stub/worker in private format12 guest.

Framework reply header and kernel effective request/trailer are explicit input
fixtures. Audit/getpid are modeled APIs. No native loader/service/IPC. No full
startup or dispatch_mach_mig_demux execution is inferred. O(C*(B+F+K)) time,
O(B+F+K) space, bounded cases/instructions and owned buffers.
"""
import copy
import json
from pathlib import Path
import struct
from unicorn import arm64_const as A
from probe_adid_receiver import Probe,HEAP,DONE
from notifyd_ipc_reader import Notifyd,ROOT,sha,THIN_SHA

REQUEST=HEAP+0x3000
REPLY=HEAP+0x4000
NDR=bytes.fromhex('0000000001000000')

class Server(Probe):
    def __init__(self,s,f):
        super().__init__(s,f)
        self.u.mem_write(self.symbols['_NDR_record'],NDR)
        raw=bytes.fromhex(f['effective_request_and_trailer_hex']);assert len(raw)<=4096;self.u.mem_write(REQUEST,bytes(4096));self.u.mem_write(REQUEST,raw)
        # Explicit framework header fixture; original stub constructs body/size.
        mid=struct.unpack_from('<I',raw,20)[0];self.u.mem_write(REPLY,bytes(4096));self.u.mem_write(REPLY,struct.pack('<6I',0,36,0,0x5901,0,(mid+100)&0xffffffff))
    def code(self,u,pc,n,data):
        if pc==0x100001c7c and self.fixture.get('stop_at_registration_worker'):
            x=[self.reg('x'+str(j)) for j in range(7)];self.records.append({'kind':'original_registration_worker_boundary','pc':hex(pc),'args_x0_x6':[hex(v) for v in x],'name':self.string(x[0]),'client_token_u32':x[1]&0xffffffff,'audit_token32_hex':bytes(self.u.mem_read(x[6],32)).hex(),'whole_worker_or_native_registration_established':False});return self.stop('original_registration_worker_boundary')
        return super().code(u,pc,n,data)
    def api(self,im):
        if im['name'] in ['_mach_msg','_mach_port_construct','_mach_port_insert_right','_mach_port_request_notification','_mach_msg_destroy']:
            x=[self.reg('x'+str(j)) for j in range(8)];e={'kind':'original_notifyd_Mach_API_boundary','name':im['name'],'callsite':hex(self.reg('lr')-4),'args_x0_x7':[hex(v) for v in x],'native_API_executed':False};self.records.append(e)
            if im['name']=='_mach_msg':
                assert x[2]==24 and x[3:7]==[0,0,0,0];e.update(send_bytes=bytes(self.u.mem_read(x[0],24)).hex(),send_size_bytes=24,options_u32=x[1]);result=self.fixture.get('sender_transport_result')
                if result is None:return self.stop('opaque_notifyd_mach_msg_boundary')
                e.update(kind='explicit_notifyd_transport_result_model',kernel_result_u32=result);return self.finish_api(result)
            if im['name']=='_mach_port_construct':
                e['original_options24_hex']=bytes(self.u.mem_read(x[1],24)).hex()
                if not self.fixture.get('model_port_constructor'):return self.stop('opaque_notifyd_port_constructor')
                self.u.mem_write(x[3],struct.pack('<I',0x5904));e.update(kind='explicit_notifyd_port_constructor_model',output_name_u32=0x5904);return self.finish_api(0)
            if im['name']=='_mach_port_insert_right' and self.fixture.get('model_port_constructor'):e['kind']='explicit_notifyd_insert_right_result_model';return self.finish_api(0)
            if im['name']=='_mach_port_request_notification' and self.fixture.get('model_port_request_notification'):self.u.mem_write(x[6],struct.pack('<I',0));e['kind']='explicit_notifyd_notification_request_result_model';return self.finish_api(0)
            if im['name']=='_mach_msg_destroy' and self.fixture.get('model_message_destroy'):e['kind']='explicit_notifyd_message_destroy_model';return self.finish_api(0)
            return self.stop('opaque_notifyd_Mach_API_boundary')
        if im['name']=='_memchr':
            x=[self.reg('x'+str(j)) for j in range(3)];assert x[2]<=512;raw=bytes(self.u.mem_read(x[0],x[2]));ix=raw.find(bytes([x[1]&255]));result=x[0]+ix if ix>=0 else 0;self.records.append({'kind':'explicit_bounded_memchr_model','name':im['name'],'callsite':hex(self.reg('lr')-4),'source_bytes':raw.hex(),'bound_bytes':x[2],'result':hex(result),'native_API_executed':False});return self.finish_api(result)
        if im['name']=='_getpid':
            result=self.fixture.get('server_pid',311);self.records.append({'kind':'explicit_process_id_API_model','name':im['name'],'result_signed32':result,'callsite':hex(self.reg('lr')-4),'native_API_executed':False});return self.finish_api(result)
        return super().api(im)
    def read_hook(self,u,access,a,n,value,data):
        if REQUEST<=a and a+n<=REQUEST+4096:self.records.append({'kind':'original_request_read','pc':hex(self.reg('pc')),'address':hex(a),'offset':a-REQUEST,'size_bytes':n,'bytes':bytes(self.u.mem_read(a,n)).hex()})
    def invoke(self,label,entry,args):
        self.fixture={**self.fixture,'label':label,'entry':entry,'args':args};self.records=[];self.visited=[];self.instructions={};self.functions={};self.reason=None;self.steps=0;self.u.reg_write(A.UC_ARM64_REG_SP,self.sp);self.u.reg_write(A.UC_ARM64_REG_LR,DONE)
        r=copy.deepcopy(super().run());r.update(result_x0=hex(self.reg('x0')),reply64_hex=bytes(self.u.mem_read(REPLY,64)).hex(),stack_balanced=self.reg('sp')==self.sp,native_target_executed=False);return r


def request(mid=1023,size=24,bits=0,trailer_type=0,trailer_size=52,audit_pid=2117):
    raw=bytearray(24+52);struct.pack_into('<6I',raw,0,bits,size,0,0x5902,0,mid);struct.pack_into('<5I',raw,24,trailer_type,trailer_size,0,0,0);struct.pack_into('<8I',raw,44,0,501,20,501,20,audit_pid,7,3);return bytes(raw)


def main():
    s=Notifyd();rows=[]
    for mid in [0,999,*range(1000,1034),0xffffffff]:
        f={'effective_request_and_trailer_hex':request(mid=mid).hex(),'model_APIs':['_audit_token_to_au32'],'audit_pid_result':2117,'instruction_budget':10000};q=Server(s,f);r=q.invoke('selector_'+str(mid),0x100008dfc,[REQUEST]);rows.append(r)
        if mid==1023:rows.append(q.invoke('checkin_valid',int(r['result_x0'],16),[REQUEST,REPLY]))
    for label,kw in [('complex',{'bits':0x80000000}),('short_size',{'size':23}),('long_size',{'size':25}),('trailer_type',{'trailer_type':1}),('trailer31',{'trailer_size':31}),('trailer32_backed52',{'trailer_size':32}),('trailer51_backed52',{'trailer_size':51}),('trailer0',{'trailer_size':0}),('max_pid',{'audit_pid':0x7fffffff})]:
        f={'effective_request_and_trailer_hex':request(**kw).hex(),'model_APIs':['_audit_token_to_au32'],'audit_pid_result':kw.get('audit_pid',2117),'instruction_budget':10000};q=Server(s,f);rows.append(q.invoke('checkin_'+label,0x10000a8e4,[REQUEST,REPLY]))
    for mid in [0,63,*range(64,74),0xffffffff]:
        f={'effective_request_and_trailer_hex':request(mid=mid).hex(),'model_APIs':[],'instruction_budget':10000};q=Server(s,f);rows.append(q.invoke('mach_selector_'+str(mid),0x100008af0,[REQUEST]))
    client=json.loads((ROOT/'notify_ipc_profiles.json').read_text())
    registration=[]
    for case in client.get('cases',[]):
        if case['case']['label'].startswith(('lifecycle_','name_length_')):
            e=next((e for r in case['calls'] for e in r['records'] if e.get('message_id_u32')==1012),None)
            if e:registration.append((case['case']['label'],bytes.fromhex(e['send_bytes'])))
    for label,raw in registration:
        effective=bytearray(raw);struct.pack_into('<I',effective,4,len(effective));trailer=request()[24:];f={'effective_request_and_trailer_hex':(effective+trailer).hex(),'stop_at_registration_worker':True,'model_APIs':[],'source_client_case':label,'source_raw_send_hex':raw.hex(),'declared_transport_transform':'write effective msgh_size=send-size and append 52-byte kernel audit trailer; framework header is separate fixture','instruction_budget':10000};q=Server(s,f);rows.append(q.invoke('registration_'+label,0x100009c3c,[REQUEST,REPLY]))
    if registration:
        seed=bytearray(registration[0][1]);struct.pack_into('<I',seed,4,len(seed))
        for label,offset,value in [('complex',0,0x80000000),('size43',4,43),('count513',36,513),('count0',36,0),('count27',36,27)]:
            raw=bytearray(seed);struct.pack_into('<I',raw,offset,value);f={'effective_request_and_trailer_hex':(raw+request()[24:]).hex(),'stop_at_registration_worker':True,'model_APIs':[],'instruction_budget':10000};q=Server(s,f);rows.append(q.invoke('registration_reject_'+label,0x100009c3c,[REQUEST,REPLY]))
    if registration:
        for label,token in [('name_without_nul_token2',2),('name_without_nul_token_all_ff',0xffffffff),('name_without_nul_token0',0)]:
            raw=bytearray(registration[0][1]);struct.pack_into('<I',raw,4,len(raw));raw[40:68]=b'A'*28;struct.pack_into('<I',raw,68,token);f={'effective_request_and_trailer_hex':(raw+request()[24:]).hex(),'stop_at_registration_worker':True,'model_APIs':[],'instruction_budget':10000};q=Server(s,f);rows.append(q.invoke('registration_'+label,0x100009c3c,[REQUEST,REPLY]))
    for label,opts,suspended,result in [('success_opts0',0,0,0),('success_opts2',2,0,0),('suspended',2,1,0),('opaque',2,0,None),('timeout_opts0',0,0,0x10000004),('timeout_opts2',2,0,0x10000004),('other_error',2,0,0x10000003)]:
        f={'effective_request_and_trailer_hex':request().hex(),'model_APIs':[],'local_sender_record_fixture':True,'global_flags_u32':opts,'port_record_flags_u32':suspended,'sender_transport_result':result,'model_message_destroy':True,'instruction_budget':10000};q=Server(s,f);client_record=HEAP+0x6000;port_record=HEAP+0x6100;q.u.mem_write(client_record,bytes(128));q.u.mem_write(port_record,bytes(128));q.u.mem_write(client_record+0x40,struct.pack('<I',0x12345678));q.u.mem_write(client_record+0x4e,bytes([7,0xc5]));q.u.mem_write(port_record+12,struct.pack('<I',suspended));q.u.mem_write(0x100014220,struct.pack('<I',opts));r=q.invoke('direct_sender_'+label,0x1000012a4,[client_record,port_record,0x5903]);r.update(client_record128_after=bytes(q.u.mem_read(client_record,128)).hex(),port_record128_after=bytes(q.u.mem_read(port_record,128)).hex());rows.append(r)
    for label,entry,args in [('port_construct_opaque',0x100001534,[]),('port_construct_and_insert',0x100001534,[]),('port_request_notification',0x1000015e8,[0x5905])]:
        f={'effective_request_and_trailer_hex':request().hex(),'model_APIs':[],'model_port_constructor':label=='port_construct_and_insert','model_port_request_notification':True,'local_port_helper_fixture':True,'instruction_budget':10000};q=Server(s,f);q.u.mem_write(q.symbols['_mach_task_self_'],struct.pack('<I',0x5801));q.u.mem_write(0x100014250,struct.pack('<I',0x5906));rows.append(q.invoke(label,entry,args))
    out={'scope':__doc__,'source_thin_sha256':THIN_SHA,'generator_sha256':sha(Path(__file__).read_bytes()),'base_engine_sha256':sha((ROOT/'probe_adid_receiver.py').read_bytes()),'client_profiles_sha256':sha((ROOT/'notify_ipc_profiles.json').read_bytes()),'profiles':rows,'native_target_executed':False,'native_transaction_executed':False,'full_goal_complete':False};(ROOT/'notifyd_ipc_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
    for r in rows:print(json.dumps({'label':r['fixture']['label'],'stop':r['stop_reason'],'result':r['result_x0'],'steps':r['steps'],'reply':r['reply64_hex'],'last':r['records'][-1] if r['records'] else None}),flush=True)

if __name__=='__main__':main()
