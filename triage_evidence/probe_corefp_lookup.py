#!/usr/bin/env python3
"""Original CoreFP lookup/metadata client in bounded private Unicorn pages.

Fresh source image per case. Warm-once,abstract locks,bootstrap results and
optional transport replies are explicit fixtures,not native initialization,
ports,rights or IPC. Original record tag is an input precondition. O(C*(B+F+K))
time,O(B+F+C*K) space;all hooks remain bounded by the inherited30k guard.
"""
import json
from pathlib import Path
import struct
from unicorn import arm64_const as A
from corefp_fixups_reader import Pointers,ROOT,sha,THIN_SHA
from probe_corefp_exports import Probe,BASE,HEAP,BIND
from probe_corefp_mach_requests import Request

ENTRY=0x1cdb24;CACHE=0x1d44448;GLOBAL=0x1d37838


class Lookup(Request):
    def __init__(self,s,f):
        # Reuse original-image/PAC/guard engine without request-specific setup.
        Probe.__init__(self,s,{**f,'mode':'packet'})
        self.stub_ins={};self.stub_rows={};self.used_stubs={}
        for row in json.loads((ROOT/'corefp_import_calls.json').read_text())['stubs']:
            for ins in row['instructions']:
                at=int(ins['ea'],16);self.stub_ins[at]=ins;self.stub_rows[at]=row
        self.fixture.update({'entry':ENTRY,'reply_name_u32':0x5173,'voucher_present':False})
        self.args=[HEAP+0x100];self.ndr_fixture='0001020304050607';self.lookup_index=0
        self.record=self.args[0];self.out1=HEAP+0x300;self.out2=HEAP+0x304
        self.u.mem_write(self.out1,b'\xa5'*8)
        record=bytearray(b'\xa5'*32);struct.pack_into('<QQ',record,8,self.out1,self.out2)
        p=self.record&0xffffffff
        key=((((p|0x20d7d4ce)-p+(p&0xdf282b31))&0xffffffff)^0xab997307)*0x0bcb7857&0xffffffff
        record[24]=(key+f.get('flag_u8',9))&255
        struct.pack_into('<I',record,28,(key+f.get('tag_u32',0xba27))&0xffffffff)
        self.u.mem_write(self.record,bytes(record));self.record_before=bytes(record).hex()
        self.u.mem_write(BASE+CACHE,struct.pack('<I',f.get('cached_port_u32',0)))
        self.u.mem_write(BASE+GLOBAL,struct.pack('<I',f.get('secondary_port_u32',0)))
        self.u.mem_write(BASE+GLOBAL+0x158,struct.pack('<4I',*f.get('metadata_initial_u32',[0,0,0,f.get('global_flags_u32',0)])))
        self.u.mem_write(BIND+86*16,struct.pack('<I',0x1b57))
        self.u.mem_write(BIND+82*16,struct.pack('<I',0x1717))
        self.u.mem_write(BIND+175*16,bytes(range(8)))
        self.u.mem_write(BASE+0x1d1c5d0,struct.pack('<Q',0))
        self.u.reg_write(A.UC_ARM64_REG_CPACR_EL1,3<<20)

    def ret(self,value=0):
        self.u.reg_write(A.UC_ARM64_REG_X0,value&((1<<64)-1));self.u.reg_write(A.UC_ARM64_REG_PC,self.reg('lr'))
    def string(self,at,cap=128):
        out=bytearray()
        for i in range(cap):
            b=bytes(self.u.mem_read(at+i,1))
            if b==b'\0':return out.decode('ascii')
            out+=b
        raise ValueError('private_cstring_extent_guard')
    def code(self,u,pc,n,data):
        if pc==BASE+0x1cdc80:self.records.append({'kind':'original_decoded_lookup_record','tag_u32':self.reg('w28'),'flag_u8':self.reg('w20')})
        if pc==BASE+0x1ce278:self.records.append({'kind':'original_metadata_client_result','result_u32':self.reg('w0')})
        im=self.binds.get(pc)
        if im:
            name=im['name'];call=hex(self.reg('lr')-4-BASE)
            if name=='_pthread_once' and self.fixture.get('warm_once'):
                self.steps+=1;self.records.append({'kind':'modeled_already_initialized_once','control':hex(self.reg('x0')-BASE),
                    'initializer':hex(self.reg('x1')-BASE),'callsite':call,'original_initializer_executed':False});return self.ret()
            if name.startswith('_pthread_rwlock_') and self.fixture.get('model_locks'):
                self.steps+=1;self.records.append({'kind':'modeled_abstract_rwlock','name':name,'pointer':hex(self.reg('x0')),
                    'callsite':call,'result_u32':0,'native_lock_executed':False});return self.ret()
            if name=='_bootstrap_look_up':
                event={'kind':'original_bootstrap_lookup_boundary','callsite':call,'bootstrap_name_u32':self.reg('w0'),
                    'service_name':self.string(self.reg('x1')),'output_pointer':hex(self.reg('x2')),'native_lookup_executed':False}
                self.records.append(event)
                values=self.fixture.get('bootstrap_results')
                if values is None:return self.stop('original_bootstrap_lookup_boundary')
                if self.lookup_index>=len(values):return self.stop('bootstrap_model_exhaustion_guard')
                value=values[self.lookup_index];self.lookup_index+=1;event.update({'kind':'modeled_bootstrap_result','result':value})
                if 'write_port_u32' in value:
                    ptr=self.reg('x2');before=bytes(u.mem_read(ptr,4));u.mem_write(ptr,struct.pack('<I',value['write_port_u32']))
                    event.update({'before4_bytes':before.hex(),'after4_bytes':bytes(u.mem_read(ptr,4)).hex()})
                return self.ret(value['status_u32'])
            if name=='_mach_port_deallocate' and 'deallocate_status_u32' in self.fixture:
                self.steps+=1;self.records.append({'kind':'modeled_name_deallocation','callsite':call,
                    'task_name_u32':self.reg('w0'),'port_name_u32':self.reg('w1'),
                    'status_u32':self.fixture['deallocate_status_u32'],'native_right_retired':False})
                return self.ret(self.fixture['deallocate_status_u32'])
            if name=='_mach_msg' and self.fixture.get('transport'):
                ptr=self.reg('x0');args=[self.reg('x'+str(j)) for j in range(7)];raw=bytes(u.mem_read(ptr,args[2]));spec=self.fixture['transport']
                event={'kind':'modeled_metadata_transport','callsite':call,'args_x0_x6':[hex(v) for v in args],
                    'request_bytes':raw.hex(),'transport_status_u32':spec.get('status_u32',0),'native_message_emitted':False}
                assert args[1:]==[3,24,60,0x5173,0,0] and struct.unpack_from('<I',raw,20)[0]==1203
                if not spec.get('status_u32',0):
                    reply=struct.pack('<6I',0,spec.get('size_u32',52),0,0,0,spec.get('reply_id_u32',1303))+bytes(range(8))
                    reply+=struct.pack('<5I',spec.get('return_code_u32',0),*spec.get('outputs_u32',[1,2,3,4]))
                    u.mem_write(ptr,reply);event['synthetic_reply_bytes']=reply.hex()
                self.steps+=1;self.records.append(event);return self.ret(spec.get('status_u32',0))
            if name in ('_mig_put_reply_port','_mig_dealloc_reply_port','_mach_msg_destroy') and self.fixture.get('transport'):
                self.steps+=1;self.records.append({'kind':'modeled_transport_cleanup','name':name,'argument_x0':hex(self.reg('x0')),
                    'callsite':call,'native_cleanup_executed':False});return self.ret()
        return super().code(u,pc,n,data)
    def run_lookup(self):
        row=self.run_request();row.pop('NDR8_fixture_bytes')
        row.update({'record_pointer':hex(self.record),'record_before32_bytes':self.record_before,
            'record_after32_bytes':bytes(self.u.mem_read(self.record,32)).hex(),
            'output8_bytes':bytes(self.u.mem_read(self.out1,8)).hex(),
            'cache_after_u32':int.from_bytes(self.u.mem_read(BASE+CACHE,4),'little'),
            'metadata_after_u32':list(struct.unpack('<4I',self.u.mem_read(BASE+GLOBAL+0x158,16)))})
        return row


class Caller(Lookup):
    """One source caller prefix,with explicit decoded operation0xc1f7."""
    def __init__(self,s):
        super().__init__(s,{'label':'protected_caller_to_lookup','warm_once':True,'model_locks':True,'model_stack_check':True})
        self.fixture['entry']=0x8e81c8;self.args=[HEAP+0x100,HEAP+0x2000]
        record=bytearray(b'\xa5'*48);p=self.args[0]
        c=0x08ae71402ff5057c;inverse=0xf7518ebfd00afa83
        mixed=(((p|c)-p+(p&inverse))&((1<<64)-1))^0x8c1900eef68afb44
        key=mixed*0xfcf33521&((1<<64)-1)
        struct.pack_into('<Q',record,8,HEAP+0x1000);struct.pack_into('<I',record,20,(key+0xc1f7)&0xffffffff)
        struct.pack_into('<Q',record,32,HEAP+0x1200)
        self.u.mem_write(p,bytes(record));self.u.mem_write(self.args[1],struct.pack('<Q',0))
        self.caller_record_before=bytes(record).hex()
    def code(self,u,pc,n,data):
        if pc==BASE+ENTRY:
            p=self.reg('x0');self.records.append({'kind':'original_lookup_record_from_caller','callsite':hex(self.reg('lr')-4-BASE),
                'pointer':hex(p),'record32_bytes':bytes(u.mem_read(p,32)).hex()})
        return super().code(u,pc,n,data)
    def run_caller(self):
        row=self.run_request();row.pop('NDR8_fixture_bytes')
        row.update({'caller_record_pointer':hex(self.args[0]),'caller_record_before48_bytes':self.caller_record_before,
            'caller_decoded_operation_precondition_u32':0xc1f7,'cursor_before_u64':0,
            'cursor_after_u64':int.from_bytes(self.u.mem_read(self.args[1],8),'little')})
        return row


def main():
    s=Pointers();rows=[];functions={};instructions={}
    def f(label,**kw):return {'label':label,'flag_u8':9,'tag_u32':0xba27,**kw}
    warm={'warm_once':True,'model_locks':True}
    fixtures=[f('first_once_boundary'),f('warm_once_lock_boundary',warm_once=True),f('warm_lookup_boundary',**warm),
        f('primary_success_request',**warm,bootstrap_results=[{'status_u32':0,'write_port_u32':0x5017}]),
        f('primary_other_error',**warm,bootstrap_results=[{'status_u32':5}]),
        f('fallback_success',**warm,bootstrap_results=[{'status_u32':1102},{'status_u32':0,'write_port_u32':0x5034}]),
        f('fallback_other_error',**warm,bootstrap_results=[{'status_u32':1102},{'status_u32':5}]),
        f('fallback_unknown_service',**warm,bootstrap_results=[{'status_u32':1102},{'status_u32':1102}]),
        f('cached_port',**warm,cached_port_u32=0x5055,global_flags_u32=0x400),
        f('primary_metadata_reply',**warm,bootstrap_results=[{'status_u32':0,'write_port_u32':0x5017}],transport={}),
        f('primary_transport_error',**warm,bootstrap_results=[{'status_u32':0,'write_port_u32':0x5017}],transport={'status_u32':0x10000003}),
        f('primary_reply_return_error',**warm,bootstrap_results=[{'status_u32':0,'write_port_u32':0x5017}],transport={'return_code_u32':0x42}),
        f('alternate_flag_lookup',**warm,flag_u8=10),
        f('alternate_flag_retirement_boundary',**warm,flag_u8=10,cached_port_u32=0x5055,secondary_port_u32=0x5066),
        f('alternate_flag_deallocate_zero',**warm,flag_u8=10,cached_port_u32=0x5055,secondary_port_u32=0x5066,deallocate_status_u32=0),
        f('alternate_flag_deallocate_error',**warm,flag_u8=10,cached_port_u32=0x5055,secondary_port_u32=0x5066,deallocate_status_u32=5)]
    # An empty transport dict still requests a successful synthetic reply.
    for fixture in fixtures:
        if 'transport' in fixture:fixture['transport']={'enabled':True,**fixture['transport']}
        row=Lookup(s,fixture).run_lookup();ff=row.pop('original_functions');ii=row.pop('visited_instruction_records')
        row['original_function_starts']=[x['start'] for x in ff]
        for v in ff:functions[v['start']]=v
        for v in ii:instructions[v['ea']]=v
        rows.append(row)
    out={'scope':__doc__,'thin_sha256':THIN_SHA,'uuid':s.meta['uuid'],'profiles':rows,
        'original_functions':list(functions.values()),'visited_instruction_records':list(instructions.values()),
        'generator_sha256':sha(Path(__file__).read_bytes()),
        'dependencies':{name:sha((ROOT/name).read_bytes()) for name in ['probe_corefp_exports.py','probe_corefp_mach_requests.py','corefp_import_calls.json','corefp_fixups_inventory.json']},
        'native_target_executed':False,'hardware_PAC_checked':False,'full_goal_complete':False}
    (ROOT/'corefp_lookup_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
    caller=Caller(s).run_caller()
    (ROOT/'corefp_lookup_caller_profile.json').write_text(json.dumps({'scope':Caller.__doc__,'profile':caller,
        'generator_sha256':sha(Path(__file__).read_bytes()),'thin_sha256':THIN_SHA,
        'native_target_executed':False,'full_goal_complete':False},indent=2)+'\n')
    for row in rows:print(json.dumps({'label':row['fixture']['label'],'stop':row['stop_reason'],'steps':row['steps'],
        'record_status':row['record_after32_bytes'][:8],'outputs':row['output8_bytes'],'cache':hex(row['cache_after_u32']),
        'metadata':row['metadata_after_u32'],'last':row['records'][-1]}))


if __name__=='__main__':main()
