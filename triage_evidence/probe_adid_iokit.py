#!/usr/bin/env python3
"""Recover original ADID IOKit call boundaries in private memory.

Frozen startup/request models; only explicit IOKit fixtures continue. No native
target, IOKit, Mach, file or synchronization operation executes. Unknown shapes
stop. O(C*(B+F+K)) time, O(B+F+C*K) evidence space; finite hook caps.
"""
import json
import struct
from pathlib import Path
from adid_reader import Adid,ROOT,sha,THIN_SHA
from probe_adid_requests import Request
from probe_adid_startup import unpack_records,HEAP
from probe_adid_receiver import DONE
from unicorn import arm64_const as A


class Hardware(Request):
    def __init__(self,s,f,checkpoint):
        super().__init__(s,f,checkpoint)
        self.iokit_objects={};self.iterator_visits=0;self.once_pending=[]
        self.u.mem_write(self.symbols['_mach_task_self_'],struct.pack('<I',f.get('task_name_u32',0x5810)))
        if 'synthetic_record_basis' in f:
            ptr=HEAP+0x1c000;raw=bytearray(128)
            if f.get('record_codec')=='first':key=(((ptr&0xffffffff)^0x08f753d6)*0x255e728d)&0xffffffff;word=key^f['synthetic_record_basis']
            else:key=(((ptr&0xffffffff)^0x834674ac)*0x0a42990d)&0xffffffff;word=(key+f['synthetic_record_basis'])&0xffffffff
            struct.pack_into('<I',raw,0,word);struct.pack_into('<Q',raw,8,f.get('record_field8',0));self.u.mem_write(ptr,bytes(raw))
    def api(self,im):
        if im['name']=='_IOConnectCallStructMethod':
            args=[self.reg('x'+str(i)) for i in range(8)];e={'kind':'original_IOConnect_structure_boundary','name':im['name'],'callsite':hex(self.reg('lr')-4),'args_x0_x7':[hex(v) for v in args],'native_API_executed':False};self.records.append(e)
            if args[3]>4096:return self.stop('hardware_struct_extent_guard')
            e['input_bytes']=bytes(self.u.mem_read(args[2],args[3])).hex();e['output_size_before_u64']=struct.unpack('<Q',self.u.mem_read(args[5],8))[0]
            if args[3]==16:
                ptr,n,opaque=struct.unpack('<QII',bytes.fromhex(e['input_bytes']));e.update({'pointed_address':hex(ptr),'pointed_size_u32':n,'trailing_u32':opaque})
                if n>65536:return self.stop('hardware_pointed_extent_guard')
                e['pointed_bytes']=bytes(self.u.mem_read(ptr,n)).hex()
            mode=self.fixture.get('method26_mode')
            if mode:
                if args[1]!=26 or args[3]!=16 or args[2]!=args[4] or e['output_size_before_u64']!=16:return self.stop('hardware_method26_model_shape_guard')
                result=self.fixture.get('method26_status_u32',0xe00002c7) if mode=='return_error' else 0
                if mode not in ('return_error','identity_success'):return self.stop('hardware_method26_model_guard')
                self.records.append({'kind':'hardware_modeled_API','name':im['name'],'callsite':hex(self.reg('lr')-4),'result':hex(result),'mode':mode,'pointed_bytes_unchanged':True,'native_API_executed':False,'kext_transform_executed':False})
                return self.finish_api(result)
        if im['name']=='_dispatch_once' and self.fixture.get('execute_once_callback'):
            token,block=self.reg('x0'),self.reg('x1');old=struct.unpack('<Q',self.u.mem_read(token,8))[0];e={'kind':'hardware_modeled_API','name':im['name'],'callsite':hex(self.reg('lr')-4),'token':hex(token),'block':hex(block),'old_token_u64':hex(old),'native_API_executed':False,'concurrency_validated':False};self.records.append(e)
            if old==(1<<64)-1:e['callback_skipped']=True;return self.finish_api(0)
            if old!=0 or len(self.once_pending)>=4:return self.stop('hardware_once_state_guard')
            invoke=struct.unpack('<Q',self.u.mem_read(block+16,8))[0];e['source_callback']=hex(invoke);marker=DONE+0x100+len(self.once_pending)*16
            self.once_pending.append({'return':self.reg('lr'),'token':token,'marker':marker});self.u.mem_write(token,struct.pack('<Q',1));self.u.reg_write(A.UC_ARM64_REG_LR,marker);self.u.reg_write(A.UC_ARM64_REG_PC,invoke);return
        if im['name'] in ('_IOServiceMatching','_IOServiceGetMatchingServices','_IOIteratorNext','_IOServiceOpen','_IOObjectRelease') and im['name'] in self.fixture.get('model_APIs',[]):
            args=[self.reg('x'+str(i)) for i in range(8)];e={'kind':'hardware_modeled_API','name':im['name'],'callsite':hex(self.reg('lr')-4),'args_x0_x7':[hex(v) for v in args],'native_API_executed':False};self.records.append(e)
            if im['name']=='_IOServiceMatching':
                e['name_string']=self.string(args[0]);result=0 if self.fixture.get('matching_result')=='NULL' else HEAP+0x1b000
                if result:self.iokit_objects[result]={'kind':'matching_dictionary','class_name':e['name_string']}
            elif im['name']=='_IOServiceGetMatchingServices':
                if args[1] not in self.iokit_objects:return self.stop('hardware_matching_dictionary_guard')
                result=self.fixture.get('matching_services_status',0)
                if result==0:
                    name=self.fixture.get('iterator_name_u32',0x5802);self.u.mem_write(args[2],struct.pack('<I',name));self.iokit_objects[name]={'kind':'iterator'}
            elif im['name']=='_IOIteratorNext':
                if args[0] not in self.iokit_objects:return self.stop('hardware_iterator_ownership_guard')
                iterator=self.iokit_objects[args[0]];visits=iterator.get('visits',0);result=self.fixture.get('service_name_u32',0x5803) if visits==0 else 0;iterator['visits']=visits+1
                if result:self.iokit_objects[result]={'kind':'service'}
            elif im['name']=='_IOServiceOpen':
                if self.iokit_objects.get(args[0],{}).get('kind')!='service' or args[1]!=self.fixture.get('task_name_u32',0x5810) or args[2]!=0:return self.stop('hardware_service_open_shape_guard')
                result=self.fixture.get('service_open_status',0)
                if result==0:
                    name=self.fixture.get('connection_name_u32',0x5804);self.u.mem_write(args[3],struct.pack('<I',name));self.iokit_objects[name]={'kind':'connection'}
                e['connection_output_cell']=hex(args[3])
            else:
                if args[0] not in self.iokit_objects:return self.stop('hardware_release_ownership_guard')
                self.iokit_objects[args[0]]['released']=True;result=self.fixture.get('object_release_status',0)
            e['result']=hex(result);return self.finish_api(result)
        if im['name']=='_IOMainPort' and im['name'] in self.fixture.get('model_APIs',[]):
            args=[self.reg('x'+str(i)) for i in range(8)];e={'kind':'hardware_modeled_API','name':im['name'],'callsite':hex(self.reg('lr')-4),'args_x0_x7':[hex(v) for v in args],'native_API_executed':False};self.records.append(e)
            if args[0]!=0:return self.stop('hardware_mainport_shape_guard')
            result=self.fixture.get('mainport_status',0)
            if result==0:self.u.mem_write(args[1],struct.pack('<I',self.fixture.get('mainport_name_u32',0x5801)))
            e['result']=hex(result);return self.finish_api(result)
        return super().api(im)
    def code(self,u,pc,n,data):
        if self.once_pending and pc==self.once_pending[-1]['marker']:
            call=self.once_pending.pop();self.u.mem_write(call['token'],struct.pack('<Q',(1<<64)-1));self.records.append({'kind':'private_once_callback_return','source_return':hex(call['return']),'token':hex(call['token']),'native_once_semantics_validated':False});self.u.reg_write(A.UC_ARM64_REG_LR,call['return']);self.finish_api(0);return
        if pc==0x10002b50c:
            p=self.reg('x9');self.records.append({'kind':'original_AVP_name_source','pc':hex(pc),'address':hex(p),'bytes18':self.s.read(p,18).hex()})
        return super().code(u,pc,n,data)


def main():
    s=Adid();ck=json.loads((ROOT/'adid_peer_checkpoint.json').read_text());p=json.loads((ROOT/'adid_request_profiles.json').read_text());source=next(r['fixture'] for r in p['profiles'] if r['fixture']['label']=='setup_selector_-8_status_0')
    fixtures=[]
    for entry in (0x1000208fc,0x10002af70):
        fixtures.append({**source,'label':'getter_'+hex(entry),'new_entry':entry,'new_args':[0,0,0,0,0,0,0,0],'instruction_budget':100000})
    for field in (0,0x4a98f233707acdc1):
        fixtures.append({**source,'label':'record_basis_10fd_field_'+hex(field),'new_entry':0x10002af70,'new_args':[HEAP+0x1c000],'synthetic_record_basis':0x10fd,'record_field8':field,'instruction_budget':100000,'record_scope':'Explicit private record; normal caller provenance not established.'})
    f=dict(fixtures[-2]);f['label']='mainport_success';f['model_APIs']=f['model_APIs']+['_IOMainPort'];fixtures.append(f)
    for stage,apis in [('matching',['_IOServiceMatching']),('services',['_IOServiceMatching','_IOServiceGetMatchingServices']),('iterator',['_IOServiceMatching','_IOServiceGetMatchingServices','_IOIteratorNext'])]:
        f=dict(fixtures[-1] if stage=='matching' else next(v for v in fixtures if v['label']=='mainport_success'));f['label']='continue_'+stage;f['model_APIs']=f['model_APIs']+apis;fixtures.append(f)
    f=dict(fixtures[-1]);f['label']='open_success';f['model_APIs']=f['model_APIs']+['_IOServiceOpen','_IOObjectRelease'];fixtures.append(f)
    f=dict(f);f['label']='owned_output_open_success';f['record_field8']=(HEAP+0x1c100+0x4a98f233707acdc1)&((1<<64)-1);fixtures.append(f)
    f=dict(f);f['label']='first_getter_basis_25';f['new_entry']=0x1000208fc;f['synthetic_record_basis']=0x25;f['record_codec']='first';fixtures.append(f)
    f=dict(f);f['label']='first_getter_once_callback';f['execute_once_callback']=True;fixtures.append(f)
    for label,updates in [('first_VMM_1',{'VMM_value':1}),('first_VMM_2',{'VMM_value':2}),('first_VMM_query_error',{'VMM_status':-1}),
        ('first_method26_error',{'method26_mode':'return_error'}),('first_method26_identity',{'method26_mode':'identity_success'}),('first_no_service',{'service_name_u32':0})]:
        case=dict(f);case['label']=label;case.update(updates);fixtures.append(case)
    avp=next(v for v in fixtures if v['label']=='owned_output_open_success')
    for label,updates in [('avp_mainport_failure',{'mainport_status':5}),('avp_matching_services_failure',{'matching_services_status':5}),('avp_no_service',{'service_name_u32':0}),('avp_open_failure',{'service_open_status':0xe00002c7})]:
        case=dict(avp);case['label']=label;case.update(updates);fixtures.append(case)
    rows=[];functions={};instructions={}
    def retain(probe,r):
        r['private_output_u32']=struct.unpack('<I',probe.u.mem_read(HEAP+0x1c100,4))[0];r['private_record16_bytes']=bytes(probe.u.mem_read(HEAP+0x1c000,16)).hex();r['iokit_object_models_final']=json.loads(json.dumps(probe.iokit_objects))
        r['observed_globals_final']={hex(a):bytes(probe.u.mem_read(a,n)).hex() for a,n in [(0x1002dcc80,1),(0x1002dcc84,4),(0x1002dcc98,1),(0x1002dcee4,4),(0x1002dd220,1),(0x1002dd290,4),(0x1002dd2b8,8),(0x1002dd2e0,1)]}
        for x in r.pop('original_functions'):functions[x['start']]=x
        for x in r.pop('instruction_records'):instructions[x['ea']]=x
        rows.append(r);es=unpack_records(r);print(json.dumps({'label':r['fixture']['label'],'stop':r['stop_reason'],'steps':r['steps'],'last':es[-1] if es else None}),flush=True)
    for f in fixtures:
        probe=Hardware(s,f,ck);r=probe.run_continuation();retain(probe,r)
    sequences=[(label,label,[{},{}]) for label in ('owned_output_open_success','first_method26_error','first_method26_identity')]
    sequences.append(('first_method26_error','method26_error_recovery',[{},{'method26_mode':'identity_success','connection_name_u32':0x5814},{'method26_mode':'identity_success','connection_name_u32':0x5814}]))
    for source_label,group,changes in sequences:
        seed=next(f for f in fixtures if f['label']==source_label);probe=Hardware(s,{**seed,**changes[0],'label':group+'_sequence_0','sequence_group':group,'sequence_index':0},ck)
        for index,updates in enumerate(changes):
            if index:
                probe.fixture={**seed,**updates,'label':group+'_sequence_'+str(index),'sequence_group':group,'sequence_index':index,'all_private_state_retained':True};probe.steps=0;probe.reason=None;probe.records=[];probe.visited=[];probe.last_edge=None
                probe.u.reg_write(A.UC_ARM64_REG_SP,probe.sp);probe.u.reg_write(A.UC_ARM64_REG_LR,DONE);probe.u.reg_write(A.UC_ARM64_REG_PC,seed['new_entry'])
                for j in range(8):probe.u.reg_write(getattr(A,'UC_ARM64_REG_X'+str(j)),seed['new_args'][j] if j<len(seed['new_args']) else 0)
            retain(probe,probe.run_continuation())
    out={'scope':__doc__,'thin_sha256':THIN_SHA,'profiles':rows,'original_functions':list(functions.values()),'original_instruction_records':list(instructions.values()),'generator_sha256':sha(Path(__file__).read_bytes()),
        'dependencies':{n:sha((ROOT/n).read_bytes()) for n in ['adid_reader.py','probe_adid_receiver.py','probe_adid_startup.py','probe_adid_requests.py','adid_peer_checkpoint.json','adid_request_profiles.json']},'native_target_executed':False,'full_goal_complete':False}
    (ROOT/'adid_iokit_profiles.json').write_text(json.dumps(out,indent=2)+'\n')


if __name__=='__main__':main()
