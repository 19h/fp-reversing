#!/usr/bin/env python3
"""Original request-frame provenance and controlled upstream IOKit continuations.

The frame runs from the original XPC callback. Fragment entry/state overrides
are explicit,not feasible whole-request/native reachability proofs. Frozen
API/PAC/vector models only; no native target/host operation. O(B+F+C*K)
time/space,with finite source-hook caps per case.
"""
import json
from pathlib import Path
import struct
from unicorn import UC_HOOK_MEM_READ,arm64_const as A
from adid_reader import Adid,ROOT,sha,THIN_SHA
from probe_adid_iokit import Hardware
from probe_adid_iokit_callers import Callers
from probe_adid_startup import unpack_records

SITES=[{'label':'query_A','prefix':0x1001f4c24,'prefix_end':0x1001f4c34,'entry':0x1001f4cc4,'compare':0x1001f4d94,'stop':0x1001f4d9c,'state_register':'w9','state_value':0x1106,'output_stack_offset':0x150},
       {'label':'query_B','prefix':0x1001f5478,'prefix_end':0x1001f5484,'entry':0x1001f550c,'compare':0x1001f55e8,'stop':0x1001f55f0,'state_register':'w8','state_value':0x161c,'output_stack_offset':0x158},
       {'label':'query_C','prefix':0x1001f583c,'prefix_end':0x1001f584c,'entry':0x1001f58c0,'compare':0x1001f599c,'stop':0x1001f59a4,'state_register':'w8','state_value':0x1713,'output_stack_offset':0x148}]


class Dispatch(Callers):
    def __init__(self,s,f,checkpoint):
        Hardware.__init__(self,s,f,checkpoint);self.copy_writes=[]
        if 'request_lock_models' in checkpoint:
            self.lock_models=json.loads(json.dumps(checkpoint['request_lock_models']));self.umask_value=checkpoint['request_umask_value'];self.lockf_calls=checkpoint['request_lockf_calls']
        self.watch_slots={0x1002d86c8,0x1002d84a8,0x1002d8640,0x1002d8998,0x1002d8400}
        for slot in self.watch_slots:self.u.hook_add(UC_HOOK_MEM_READ,self.pointer_read,begin=slot,end=slot+7)
        if 'fragment_entry' in f:
            sp=self.reg('sp');base=struct.unpack('<Q',self.u.mem_read(sp+0x1660,8))[0];table=struct.unpack('<Q',self.u.mem_read(sp+0x1658,8))[0]
            overrides={f['state_register']:f['state_value'],'x30':base,'w6':0x801ffa49,'x27':table}
            for reg,value in overrides.items():self.u.reg_write(getattr(A,'UC_ARM64_REG_'+reg.upper()),value)
            self.u.reg_write(A.UC_ARM64_REG_PC,f['prefix_entry'])
            self.records.append({'kind':'analyst_fragment_entry','entry':hex(f['prefix_entry']),'constructor_entry':hex(f['fragment_entry']),'register_overrides':{k:hex(v) for k,v in overrides.items()},
                'original_frame_stack_preserved':True,'whole_request_or_native_reachability_established':False})
    def write(self,u,access,address,size,value,data):
        super().write(u,access,address,size,value,data)
        if 0x1001661f8<=self.reg('pc')<0x100266b80 and any(address<slot+8 and slot<address+size for slot in self.fixture.get('watched_source_slots',[])):
            self.records.append({'kind':'original_frame_slot_store','pc':hex(self.reg('pc')),'address':hex(address),'size_bytes':size,'value':hex(value&((1<<(8*size))-1))})
    def code(self,u,pc,n,data):
        if pc==self.fixture.get('prefix_end'):
            self.records.append({'kind':'analyst_fragment_jump','unexecuted_from':hex(pc),'to':hex(self.fixture['fragment_entry']),'intervening_predecessors_validated':False})
            self.u.reg_write(A.UC_ARM64_REG_PC,self.fixture['fragment_entry']);return
        if pc==self.fixture.get('compare_pc'):
            sp=self.reg('sp');label=self.fixture['site_label'];address=self.reg('x22')+0x1bb if label=='query_A' else sp+0x16db if label=='query_B' else self.reg('x19')+0x7b6
            self.records.append({'kind':'original_output_byte_comparison','pc':hex(pc),'address':hex(address),'loaded_u32':self.reg('w8'),'expected_u8':self.reg('w9')&255})
        if pc==self.fixture.get('stop_before_pc'):
            sp=self.reg('sp');fp=self.reg('x29');event={'kind':'original_dispatch_boundary','pc':hex(pc),'registers':{k:hex(self.reg(k)) for k in ['x'+str(j) for j in range(31)]+['sp']},
                'stack_slots':{hex(off):hex(struct.unpack('<Q',u.mem_read(sp+off,8))[0]) for off in [0x148,0x150,0x158,0x1598,0x15a0,0x15a8,0x15b0,0x1620,0x1628,0x1658,0x1660,0x1668,0x1670,0x1678,0x1680,0x1688]}}
            if 'fragment_entry' in self.fixture:
                raw=bytes(u.mem_read(fp-0xa8,16));pointer=(struct.unpack_from('<Q',raw)[0]-0x7e1f59740c8f6451)&((1<<64)-1)
                event['returned_caller_record']={'address':hex(fp-0xa8),'bytes16':raw.hex(),'decoded_output_pointer':hex(pointer),'output_byte_u8':u.mem_read(pointer,1)[0]}
            self.records.append(event);return self.stop('original_dispatch_boundary')
        if pc==0x1000590ac:
            p=self.reg('x0');raw=bytes(u.mem_read(p,16));self.records.append({'kind':'original_upstream_caller_record','entry':hex(pc),'source_return':hex(self.reg('lr')),'address':hex(p),'bytes16':raw.hex()})
        return Callers.code(self,u,pc,n,data)


def main():
    s=Adid();peer=json.loads((ROOT/'adid_peer_checkpoint.json').read_text());prior=json.loads((ROOT/'adid_context_profiles.json').read_text())
    source=next(r['fixture'] for r in prior['profiles'] if r['fixture']['label']=='context_error_producer')
    initial={**source,'label':'original_request_frame','stop_before_pc':0x10019bb18,'instruction_budget':500000}
    q=Dispatch(s,initial,peer);frame_row=q.run_continuation();assert frame_row['stop_reason']=='original_dispatch_boundary'
    checkpoint=q.checkpoint(frame_row);checkpoint.update(request_lock_models=q.lock_models,request_umask_value=q.umask_value,request_lockf_calls=q.lockf_calls)
    (ROOT/'adid_driver_dispatch_frame.json').write_text(json.dumps(checkpoint,indent=2)+'\n')
    seed=next(r['fixture'] for r in json.loads((ROOT/'adid_iokit_caller_profiles.json').read_text())['profiles'] if r['fixture']['label']=='primary_error')
    profiles=[];functions={};instructions={}
    def retain(row):
        for f in row.pop('original_functions'):functions[f['start']]=f
        for i in row.pop('instruction_records'):instructions[i['ea']]=i
        profiles.append(row);es=unpack_records(row);last=es[-1];print(json.dumps({'label':row['fixture']['label'],'stop':row['stop_reason'],'steps':row['steps'],'caller_output':last.get('returned_caller_record')}),flush=True)
    retain(frame_row)
    slots=[int(checkpoint['registers']['SP'],16)+off for off in (0x148,0x150,0x158)]
    writer=Dispatch(s,{**initial,'label':'original_frame_slot_writers','watched_source_slots':slots},peer);retain(writer.run_continuation())
    for site in SITES:
        for mode,extras in [('primary_error',{}),('primary_identity',{'method26_mode':'identity_success'}),
            ('two_stage_identity',{'method26_mode':'identity_success','VMM_value':2,'direct26_mode':'identity_success','split_provider_names':True}),
            ('post_context_control',{'method26_mode':'identity_success','post_context_flag':0x41,'post_context_tag':0x527e14b6})]:
            f={**source,**seed,'label':site['label']+'_'+mode,'site_label':site['label'],'prefix_entry':site['prefix'],'prefix_end':site['prefix_end'],'fragment_entry':site['entry'],'compare_pc':site['compare'],'stop_before_pc':site['stop'],'state_register':site['state_register'],
                'state_value':site['state_value'],'original_output_stack_offset':site['output_stack_offset'],'instruction_budget':400000,'restore_models':True,**extras}
            for key in ('new_entry','new_args','caller','synthetic_record_basis','record_codec','record_field8'):f.pop(key,None)
            q=Dispatch(s,f,checkpoint);retain(q.run_continuation())
    out={'scope':__doc__,'thin_sha256':THIN_SHA,'profiles':profiles,'original_functions':list(functions.values()),'original_instruction_records':list(instructions.values()),
        'generator_sha256':sha(Path(__file__).read_bytes()),'dependencies':{n:sha((ROOT/n).read_bytes()) for n in ['adid_reader.py','probe_adid_receiver.py','probe_adid_startup.py','probe_adid_requests.py','probe_adid_iokit.py','probe_adid_iokit_callers.py','adid_peer_checkpoint.json','adid_context_profiles.json','adid_iokit_caller_profiles.json','adid_driver_dispatch_frame.json']},
        'native_target_executed':False,'full_goal_complete':False}
    (ROOT/'adid_driver_dispatch_profiles.json').write_text(json.dumps(out,indent=2)+'\n')


if __name__=='__main__':main()
