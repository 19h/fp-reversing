#!/usr/bin/env python3
"""Original record constructor, allocation facade and local field codecs.

Constructor/codec entries are explicit private fragments with declared frame
inputs; publication is an explicit data fixture. Neither proves feasible
native predecessors. Original source runs between stated boundaries; no native
target/API. O(C*(B+F+K)) time/space, finite hook caps and owned extents.
"""
import json
from pathlib import Path
import struct
from unicorn import arm64_const as A
from adid_reader import Adid,ROOT,sha,THIN_SHA
from probe_adid_context_gates import Gates,BLOCK
from probe_adid_startup import unpack_records
from probe_adid_receiver import HEAP
from adid_state_codec import close64

MASK=(1<<64)-1
XOR64=0xda8ca8cae5dfbd2d
NEST_BIAS=0x6fac17cb61e34e69
TABLE=0x1002c40c0


class Lifecycle(Gates):
    def __init__(self,s,f,checkpoint):
        super().__init__(s,f,checkpoint);self.objects={};self.object_initial={};self.object_writes=[];self.boundaries=[];self.published=False
        mode=f['mode'];sp=self.reg('sp');overrides={}
        if mode=='constructor':
            overrides={'pc':0x10019c578,'w20':0xd5b,'x23':TABLE,'x27':TABLE,'x30':struct.unpack('<Q',self.u.mem_read(sp+0x1660,8))[0],'w6':0x801ffa49}
            for off,width,value in [(0x1abc,4,f.get('status_marker',0x59248f)),(0x2be0,8,(f['key_u64']&MASK)^XOR64),(0x34dc,4,(f['record_uid']+0x46d726)&0xffffffff),(0x2524,4,f.get('outer_flag',0))]:self.u.mem_write(sp+off,value.to_bytes(width,'little'))
            if f.get('cold_first'):self.u.mem_write(0x1002dd2e8,bytes(8))
        elif mode in ('encode','decode'):
            q=f.get('original_nested_address',HEAP+0x1d000);self.objects={'nested':(q,176)}
            if mode=='encode':
                if 'original_nested_address' not in f:self.u.mem_write(q,bytes(176));self.u.mem_write(q+0x98,struct.pack('<Q',f['value_u64']^XOR64))
                self.u.mem_write(sp+0xf48,struct.pack('<Q',(q+NEST_BIAS)&MASK));overrides={'pc':0x10012004c,'w26':0xcf8,'w11':f.get('field_present',1),'x30':TABLE}
            else:
                raw=bytes.fromhex(f['local_input8']);self.u.mem_write(sp+0x11c8,raw);self.u.mem_write(sp+0xf80,struct.pack('<Q',(q+NEST_BIAS)&MASK));self.u.mem_write(q,bytes(176));self.u.mem_write(q+0x98,bytes.fromhex('efcdab8967452301'));overrides={'pc':0x10013f86c,'w26':0xcf8,'w14':f.get('field_present',1),'x30':TABLE}
            self.object_initial={k:bytes(self.u.mem_read(a,n)).hex() for k,(a,n) in self.objects.items()}
        elif mode=='update':
            self.objects={k:(f['original_'+k+'_address'],n) for k,n in [('outer',96),('nested',176)]};self.object_initial={k:bytes(self.u.mem_read(a,n)).hex() for k,(a,n) in self.objects.items()}
        if overrides:
            for r,v in overrides.items():self.u.reg_write(getattr(A,'UC_ARM64_REG_'+r.upper()),v)
            self.records.append({'kind':'analyst_local_fragment_entry','register_overrides':{k:hex(v) for k,v in overrides.items()},'frame_inputs':{k:v for k,v in f.items() if k in ['key_u64','record_uid','outer_flag','status_marker','local_input8','value_u64','field_present']},'feasible_whole_request_or_native_predecessors_established':False})
    def observe(self,kind,pc):
        e={'kind':kind,'pc':hex(pc),'registers':{r:hex(self.reg(r)) for r in ['x'+str(i) for i in range(31)]+['sp']}};self.records.append(e);self.boundaries.append(e);return e
    def write(self,u,access,address,size,value,data):
        for k,(a,n) in self.objects.items():
            if a<=address and address+size<=a+n:self.object_writes.append({'pc':hex(self.reg('pc')),'object':k,'offset_bytes':address-a,'size_bytes':size,'before_bytes':bytes(u.mem_read(address,size)).hex(),'value':hex(value&((1<<(size*8))-1))})
        return super().write(u,access,address,size,value,data)
    def code(self,u,pc,n,data):
        mode=self.fixture['mode']
        if mode=='constructor':
            if pc in (0x10019c654,0x10019c7cc):self.observe('original_allocation_request',pc)
            if pc in (0x10019c658,0x10019c7d0):
                e=self.observe('original_allocation_return',pc);key='outer' if pc==0x10019c658 else 'nested';size=96 if key=='outer' else 176;a=self.reg('x0');e.update({'object':key,'requested_bytes':size,'result_address':hex(a)})
                if a:self.objects[key]=(a,size);self.object_initial[key]=bytes(u.mem_read(a,size)).hex()
            if pc==0x10019c7c4 and self.fixture.get('cold_second'):
                u.mem_write(0x1002dd2e8,bytes(8));self.records.append({'kind':'analyst_cold_allocation_context','pc':hex(pc),'cell':'0x1002dd2e8','native_failure_inferred':False})
            if pc in (0x10019c840,0x10019c8d0,0x10019ca90):self.observe('original_constructor_scalar_boundary',pc)
            if pc==0x10019cb24:self.observe('original_constructor_complete',pc);return self.stop('constructor_before_publication')
            if pc==0x1001f7d00:self.observe('original_constructor_failure_exit',pc);return self.stop('constructor_failure_exit')
        elif mode in ('encode','decode'):
            if mode=='encode' and pc==0x1001201b4:self.observe('original_field_encode_complete',pc);return self.stop('local_field_encode_complete')
            if mode=='decode' and pc==0x10013f99c:self.observe('original_field_decode_complete',pc);return self.stop('local_field_decode_complete')
            if mode=='encode' and pc==0x1001223f4:self.observe('original_field_absent',pc);return self.stop('local_field_absent_boundary')
            if mode=='decode' and pc not in range(0x10013f86c,0x10013f99d) and pc>=self.s.base:
                self.observe('original_field_absent',pc);return self.stop('local_field_absent_boundary')
        elif mode=='update' and pc==0x10019bdcc:
            f=self.fixture;view=bytearray.fromhex(f['baseline_view64']);struct.pack_into('<I',view,0,0x16e4e4d4);struct.pack_into('<Q',view,8,HEAP+0x1c000+0x58ce03d8d8c95487);u.mem_write(HEAP+0x1c000,struct.pack('<QQ',0,(f['original_outer_address']+0x2d1ade42073e28af)&MASK));u.mem_write(BLOCK,bytes(view));self.published=True
            self.records.append({'kind':'analyst_publication_of_source_constructed_record','pc':hex(pc),'phase':'decoded view before original count load','view64':view.hex(),'outer_address':hex(f['original_outer_address']),'nested_address':hex(f['original_nested_address']),'object_fields_patched':False,'native_publication_established':False})
        if pc in (0x1000621d4,0x1002698cc,0x100267044,0x10006234c,0x100267a84,0x100267c18,0x100267b1c,0x100267cb8):self.observe('original_allocation_layer_boundary',pc)
        return super().code(u,pc,n,data)
    def result(self):
        r=self.run_continuation();r.update({'return_x0_u64':hex(self.reg('x0')),'object_addresses':{k:hex(a) for k,(a,n) in self.objects.items()},'object_initial_bytes':self.object_initial,'object_final_bytes':{k:bytes(self.u.mem_read(a,n)).hex() for k,(a,n) in self.objects.items()},'original_object_writes':self.object_writes})
        if self.fixture['mode']=='encode':r['local_output8']=bytes(self.u.mem_read(self.reg('sp')+0x11e8,8)).hex()
        return r


def base_fixture():
    return next(r['fixture'] for r in json.loads((ROOT/'adid_context_profiles.json').read_text())['profiles'] if r['fixture']['label']=='context_error_producer')


def fixture_set():
    b={**base_fixture(),'restore_models':True,'instruction_budget':200000}
    for k in ('new_entry','new_args'):b.pop(k,None)
    out=[]
    for key in [-17,-16,-9,-8,-6,-5,-4,-3,-2,-1,0,1,0x7fffffffffffffff,0x8000000000000000]:out.append({**b,'label':'constructor_key_'+str(key),'mode':'constructor','key_u64':key&MASK,'record_uid':0})
    for label,extra in [('uid501',{'record_uid':501}),('vmm1',{'VMM_value':1}),('vmm2',{'VMM_value':2}),('vmm_error',{'VMM_value':1,'VMM_status':5}),('cold_first',{'cold_first':True}),('cold_second',{'cold_second':True})]:out.append({**b,'label':'constructor_'+label,'mode':'constructor','key_u64':(-8)&MASK,'record_uid':0,**extra})
    for size in [0,1,15,16,17,32,64,96,176,224,225,256,4096,65535,65536,0xffffffff,0x100000000,0xffffffffffffff7f,0xffffffffffffff80,MASK]:out.append({**b,'label':'allocator_'+hex(size),'mode':'allocator','new_entry':0x1000621d4,'new_args':[size],'requested_bytes':size})
    out.append({**b,'label':'allocator_cold','mode':'allocator','new_entry':0x1000621d4,'new_args':[96],'requested_bytes':96,'cold_first':True})
    values=[0,1,0xff,0x0123456789abcdef,0xfedcba9876543210,0x8000000000000000,MASK]
    for value in values:
        out.append({**b,'label':'encode_'+hex(value),'mode':'encode','value_u64':value})
        raw=bytes((x+0x19)&255 for x in value.to_bytes(8,'big'));out.append({**b,'label':'decode_'+hex(value),'mode':'decode','local_input8':raw.hex(),'value_u64':value})
    out.append({**b,'label':'encode_absent','mode':'encode','value_u64':0x0123456789abcdef,'field_present':0})
    out.append({**b,'label':'decode_absent','mode':'decode','value_u64':0,'local_input8':'0019ff73007f8018','field_present':0})
    out.append({**b,'label':'decode_arbitrary_bytes','mode':'decode','local_input8':'0019ff73007f8018'})
    return out


def run_one(s,f,checkpoint):
    q=Lifecycle(s,json.loads(json.dumps(f)),checkpoint)
    if f['mode']=='allocator' and f.get('cold_first'):q.u.mem_write(0x1002dd2e8,bytes(8))
    return q,q.result()


def run_pipeline(s,checkpoint):
    b=base_fixture();cf={**b,'label':'pipeline_constructor','mode':'constructor','key_u64':(-8)&MASK,'record_uid':0,'restore_models':True,'instruction_budget':200000}
    for k in ('new_entry','new_args'):cf.pop(k,None)
    q,r=run_one(s,cf,checkpoint);assert r['stop_reason']=='constructor_before_publication';ck=q.checkpoint(r);outer=int(r['object_addresses']['outer'],16);nested=int(r['object_addresses']['nested'],16)
    old=json.loads((ROOT/'adid_state_producer_profiles.json').read_text())['profiles'][0];view=next(e['output64'] for e in unpack_records(old) if e['kind']=='original_state_view_complete');value=0x0123456789abcdef
    f={**b,'label':'pipeline_original_callback_update','mode':'update','restore_models':True,'new_entry':0x100029fc8,'new_args':[HEAP+0x300,HEAP+0xd100],'payload_hex':struct.pack('>IIIQQ',1,0x632b8d6e,1,MASK-7,value).hex(),'original_outer_address':outer,'original_nested_address':nested,'baseline_view64':view,'instruction_budget':800000}
    u,ur=run_one(s,f,ck);uck=u.checkpoint(ur)
    ef={**cf,'label':'pipeline_field_encode','mode':'encode','value_u64':value,'original_nested_address':nested};e,er=run_one(s,ef,uck)
    return [(q,r),(u,ur),(e,er)]


def main():
    s=Adid();checkpoint=json.loads((ROOT/'adid_driver_dispatch_frame.json').read_text());rows=[];functions={};instructions={}
    def keep(q,r):
        for x in r.pop('original_functions'):functions[x['start']]=x
        for x in r.pop('instruction_records'):instructions[x['ea']]=x
        rows.append(r);print(json.dumps({'label':r['fixture']['label'],'stop':r['stop_reason'],'steps':r['steps'],'objects':r['object_addresses'],'output8':r.get('local_output8'),'return_x0':r['return_x0_u64']}),flush=True)
    for f in fixture_set():
        q,r=run_one(s,f,checkpoint);keep(q,r)
    for q,r in run_pipeline(s,checkpoint):keep(q,r)
    out={'scope':__doc__,'thin_sha256':THIN_SHA,'profiles':rows,'original_functions':list(functions.values()),'original_instruction_records':list(instructions.values()),'generator_sha256':sha(Path(__file__).read_bytes()),
        'dependencies':{n:sha((ROOT/n).read_bytes()) for n in ['adid_reader.py','adid_state_codec.py','probe_adid_context_gates.py','probe_adid_iokit.py','probe_adid_requests.py','probe_adid_startup.py','probe_adid_receiver.py','adid_driver_dispatch_frame.json','adid_context_profiles.json','adid_state_producer_profiles.json']},'native_target_executed':False,'full_goal_complete':False}
    (ROOT/'adid_record_lifecycle_profiles.json').write_text(json.dumps(out,indent=2)+'\n')


if __name__=='__main__':main()
