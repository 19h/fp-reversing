#!/usr/bin/env python3
"""Original ADID context-gate data provenance and explicit field perturbations.

Full original callback entries; no instruction-PC jumps. Early/late private
field mutations are explicit and do not establish valid/native context states.
Frozen API/PAC/vector models; no target/host operation. O(C*(B+F+K)) time,
O(B+F+C*K) evidence space with finite source-hook caps.
"""
import json
from pathlib import Path
import struct
from unicorn import arm64_const as A
from adid_reader import Adid,ROOT,sha,THIN_SHA
from probe_adid_iokit import Hardware
from probe_adid_startup import unpack_records

BLOCK=0x1002dcb68


class Gates(Hardware):
    def __init__(self,s,f,checkpoint):
        super().__init__(s,f,checkpoint);self.pending_context_write=None;self.pending_vector=None;self.pending_chunk=None;self.observed_api_calls=0;self.initial_block_bytes64=bytes(self.u.mem_read(BLOCK,64)).hex()
        if 'early_tag' in f:
            before=bytes(self.u.mem_read(BLOCK,64));self.u.mem_write(BLOCK,struct.pack('<I',f['early_tag']))
            self.records.append({'kind':'analyst_early_field_patch','address':hex(BLOCK),'before_bytes64':before.hex(),'after_bytes64':bytes(self.u.mem_read(BLOCK,64)).hex(),'native_state_inferred':False})
    def api(self,im):
        self.observed_api_calls+=1
        before=bytes(self.u.mem_read(BLOCK,64));args=[self.reg('x'+str(i)) for i in range(8)];site=self.reg('lr')-4
        result=super().api(im);after=bytes(self.u.mem_read(BLOCK,64))
        if before!=after:
            e={'kind':'modeled_API_context_memory_effect','name':im['name'],'callsite':hex(site),'args_x0_x7':[hex(v) for v in args],
                'before_bytes64':before.hex(),'after_bytes64':after.hex(),'native_API_executed':False}
            if im['name'] in ('_memcpy','_memmove','___memcpy_chk','___memmove_chk') and args[2]<=4096:
                e['source_bytes_after']=bytes(self.u.mem_read(args[1],args[2])).hex()
            self.records.append(e)
        return result
    def write(self,u,access,address,size,value,data):
        super().write(u,access,address,size,value,data)
        if address<BLOCK+64 and BLOCK<address+size:
            if self.pending_context_write is None:self.pending_context_write={'kind':'original_context_memory_write_effect','pc':hex(self.reg('pc')),'before_bytes64':bytes(u.mem_read(BLOCK,64)).hex(),'writes':[]}
            self.pending_context_write['writes'].append({'address':hex(address),'size_bytes':size,'hook_value_low_u64':hex(value&((1<<64)-1))})
    def code(self,u,pc,n,data):
        if self.pending_context_write is not None:
            event=self.pending_context_write;event['observed_before_pc']=hex(pc);event['after_bytes64']=bytes(u.mem_read(BLOCK,64)).hex();self.records.append(event);self.pending_context_write=None
        if pc==0x100199800:
            self.pending_chunk={'key_u32':self.u.reg_read(A.UC_ARM64_REG_Q4)&0xffffffff,'offset_bytes':self.reg('x12'),'base':hex(self.reg('x13')),'address':hex(self.reg('x14')),'input16':bytes(u.mem_read(self.reg('x14'),16)).hex(),
                'position_vectors_q0_q3':[self.u.reg_read(getattr(A,'UC_ARM64_REG_Q'+str(i))).to_bytes(16,'little').hex() for i in range(4)]}
        if pc==0x10019986c:
            self.pending_vector={'kind':'original_context_table_vector','pc':hex(pc),'indices16':self.u.reg_read(A.UC_ARM64_REG_Q5).to_bytes(16,'little').hex(),
                'table64':b''.join(self.u.reg_read(getattr(A,'UC_ARM64_REG_Q'+str(i))).to_bytes(16,'little') for i in range(21,25)).hex(),'store_address':hex(self.reg('x14'))}
        if pc==0x100199870 and self.pending_vector is not None:
            event=self.pending_vector;event.update(self.pending_chunk or {});self.pending_chunk=None;event['output16']=self.u.reg_read(A.UC_ARM64_REG_Q5).to_bytes(16,'little').hex();self.records.append(event);self.pending_vector=None
        if pc in (0x10019bdcc,0x10019e498):
            base=self.reg('x9') if pc==0x10019bdcc else self.reg('x8');before=bytes(u.mem_read(base,64));key='late_tag' if pc==0x10019bdcc else 'late_pointer24'
            if key in self.fixture:
                offset=0 if key=='late_tag' else 24;width=4 if key=='late_tag' else 8;u.mem_write(base+offset,int(self.fixture[key]).to_bytes(width,'little'))
                self.records.append({'kind':'analyst_late_field_patch','pc':hex(pc),'address':hex(base+offset),'size_bytes':width,'before_bytes64':before.hex(),'after_bytes64':bytes(u.mem_read(base,64)).hex(),'native_state_inferred':False})
            self.records.append({'kind':'original_context_gate_load','pc':hex(pc),'base':hex(base),'bytes64':bytes(u.mem_read(base,64)).hex(),'state_w20':self.reg('w20')})
        if pc in (0x10019bde0,0x10019e4ac,0x10019be9c):
            names=('w3','w9') if pc==0x10019bde0 else ('x8','x14') if pc==0x10019e4ac else ('x13','x17')
            self.records.append({'kind':'original_context_gate_comparison','pc':hex(pc),'operand_registers':list(names),'operands':[hex(self.reg(r)) for r in names],'state_w20':self.reg('w20')})
        if pc in (0x10019be14,0x10019e4f8,0x10019bed8):
            reg='x6' if pc==0x10019bed8 else 'x9';self.records.append({'kind':'original_context_gate_branch','pc':hex(pc),'target':hex(self.reg(reg)),'state_w20':self.reg('w20')})
        if pc in (0x10019c1c4,0x10019bf0c):
            reg='x5' if pc==0x10019c1c4 else 'x17';self.records.append({'kind':'original_context_pointer_read_boundary','pc':hex(pc),'address':hex(self.reg(reg)),'native_fault_inferred':False})
        return super().code(u,pc,n,data)


def main():
    s=Adid();checkpoint=json.loads((ROOT/'adid_peer_checkpoint.json').read_text());old=json.loads((ROOT/'adid_context_profiles.json').read_text());base=next(r['fixture'] for r in old['profiles'] if r['fixture']['label']=='context_error_producer')
    fixtures=[{**base,'label':'gate_baseline','instruction_budget':600000}]
    for phase in ('early_tag','late_tag'):
        for value in (0,0x16e4e4d2,0x16e4e4d3,0xffffffff):fixtures.append({**base,'label':phase+'_'+hex(value),phase:value,'instruction_budget':600000})
    for value in (0x6fac17cb61e34e69,0x6fac17cb61e34e68,0):fixtures.append({**base,'label':'pointer24_'+hex(value),'late_pointer24':value,'instruction_budget':600000})
    rows=[];functions={};instructions={}
    for f in fixtures:
        q=Gates(s,f,checkpoint);r=q.run_continuation();r['context_block_final_bytes64']=bytes(q.u.mem_read(BLOCK,64)).hex();r['context_memory_API_calls_checked']=q.observed_api_calls;r['context_block_initial_bytes64']=q.initial_block_bytes64
        for x in r.pop('original_functions'):functions[x['start']]=x
        for x in r.pop('instruction_records'):instructions[x['ea']]=x
        rows.append(r);es=unpack_records(r);print(json.dumps({'label':f['label'],'stop':r['stop_reason'],'steps':r['steps'],'modeled_memory_effects':len([e for e in es if e['kind']=='modeled_API_context_memory_effect']),
            'reply':[e['payload_bytes'] for e in es if e.get('name')=='_xpc_dictionary_set_data'],'last':es[-1]}),flush=True)
    out={'scope':__doc__,'thin_sha256':THIN_SHA,'profiles':rows,'original_functions':list(functions.values()),'original_instruction_records':list(instructions.values()),'generator_sha256':sha(Path(__file__).read_bytes()),
        'dependencies':{n:sha((ROOT/n).read_bytes()) for n in ['adid_reader.py','probe_adid_receiver.py','probe_adid_startup.py','probe_adid_requests.py','probe_adid_iokit.py','adid_peer_checkpoint.json','adid_context_profiles.json']},'native_target_executed':False,'full_goal_complete':False}
    (ROOT/'adid_context_gate_profiles.json').write_text(json.dumps(out,indent=2)+'\n')


if __name__=='__main__':main()
