#!/usr/bin/env python3
"""Continue original protected CoreFP caller after source lookup completion.

Private image only;metadata,bootstrap,locks and stack probes are explicit
fixtures. Larger Mach requests stop before transmission. No native target,
loader,IPC or API runs. O(C*(B+F+K)) time,O(B+F+C*K) space;inherited30k bound.
Unknown packet schema/other callee inputs remain explicit preconditions.
"""
import json
from pathlib import Path
import struct
from corefp_fixups_reader import Pointers,ROOT,sha,THIN_SHA
from probe_corefp_lookup import Caller
from probe_corefp_exports import BASE,HEAP


class Flow(Caller):
    def __init__(self,s,f):
        super().__init__(s);self.fixture.update(f);self.private_allocations=[];self.alloc_cursor=HEAP+0x4000;self.certificate_copy=None
        ptr=self.args[0];key=((ptr^0x84b771aed97ffe38)*0xfcf33521)&((1<<64)-1)
        self.u.mem_write(ptr+24,struct.pack('<I',(key^f.get('mode_u32',0))&0xffffffff))
        self.caller_record_before=bytes(self.u.mem_read(ptr,48)).hex()
        # The parent froze baseline zero-cache state;these are new explicit
        # warm-state experiments,not changes to the original-image globals.
        from probe_corefp_lookup import CACHE,GLOBAL
        from probe_corefp_exports import BASE
        self.u.mem_write(BASE+CACHE,struct.pack('<I',f.get('cached_port_u32',0)))
        self.u.mem_write(BASE+GLOBAL+0x164,struct.pack('<I',f.get('flags_u32',0)))
    def code(self,u,pc,n,data):
        if pc==BASE+0x249434:
            index=self.reg('x12')
            if self.certificate_copy is None:
                self.certificate_copy={'kind':'original_certificate_XOR_copy','site':'0x249434',
                    'source_pointer':hex(self.reg('x11')-BASE),'output_pointer':hex(self.reg('x0')),
                    'xor_byte':self.reg('w13')&255,'iterations':0,'min_index':index,'max_index':index}
                self.records.append(self.certificate_copy)
            e=self.certificate_copy;e['iterations']+=1;e['min_index']=min(e['min_index'],index);e['max_index']=max(e['max_index'],index)
        if pc==BASE+0x8e8520:
            e=next(e for e in reversed(self.records) if e['kind']=='original_lookup_record_from_caller')
            raw=bytes.fromhex(e['record32_bytes']);port,flags=struct.unpack_from('<QQ',raw,8)
            self.records.append({'kind':'original_lookup_outputs_in_parent','callsite':'0x8e851c',
                'port_name_u32':int.from_bytes(u.mem_read(port,4),'little'),'flags_u32':int.from_bytes(u.mem_read(flags,4),'little')})
        im=self.binds.get(pc)
        if im and im['name']=='_free' and self.fixture.get('model_free'):
            self.steps+=1;ptr=self.reg('x0')
            if ptr and not any(a==ptr for a,n in self.private_allocations):return self.stop('unowned_private_free_guard')
            self.records.append({'kind':'modeled_private_free','callsite':hex(self.reg('lr')-4-BASE),'pointer':hex(ptr),
                'before_bytes':None if not ptr else bytes(u.mem_read(ptr,next(n for a,n in self.private_allocations if a==ptr))).hex(),
                'native_free_executed':False});return self.ret()
        if im and im['name']=='_malloc' and self.fixture.get('allocator'):
            self.steps+=1;size=self.reg('x0');mode=self.fixture['allocator'];ptr=0
            if size>8192 or len(self.private_allocations)>=16:return self.stop('private_allocator_extent_guard')
            if mode=='success':
                ptr=self.alloc_cursor;self.alloc_cursor=(ptr+size+15)&~15
                if self.alloc_cursor>HEAP+0x10000:return self.stop('private_allocator_capacity_guard')
                self.private_allocations.append((ptr,size));u.mem_write(ptr,b'\xa5'*size)
            self.records.append({'kind':'modeled_private_allocation','callsite':hex(self.reg('lr')-4-BASE),
                'size_bytes':size,'result':hex(ptr),'poison_byte':165 if ptr else None,'native_allocator_executed':False})
            return self.ret(ptr)
        if im and im['name']=='_mach_msg' and self.reg('x2')!=24:
            self.steps+=1;args=[self.reg('x'+str(j)) for j in range(7)]
            if args[2]>4096:return self.stop('larger_request_extent_guard')
            self.records.append({'kind':'original_larger_request_boundary','callsite':hex(self.reg('lr')-4-BASE),
                'args_x0_x6':[hex(v) for v in args],'message_bytes':bytes(u.mem_read(args[0],args[2])).hex(),
                'native_message_emitted':False})
            raw=bytes.fromhex(self.records[-1]['message_bytes'])
            if len(raw)>=44 and int.from_bytes(raw[:4],'little')&0x80000000:
                ptr,size=struct.unpack_from('<Q',raw,28)[0],struct.unpack_from('<I',raw,40)[0]
                if size>4096:return self.stop('larger_OOL_payload_extent_guard')
                self.records[-1].update({'OOL_source_pointer':hex(ptr),'OOL_size_bytes':size,'OOL_bytes':bytes(u.mem_read(ptr,size)).hex()})
            return self.stop('original_larger_request_boundary')
        return super().code(u,pc,n,data)
    def run_caller(self):
        row=super().run_caller();row['caller_record_after48_bytes']=bytes(self.u.mem_read(self.args[0],48)).hex()
        return row


def main():
    s=Pointers();rows=[];functions={};instructions={}
    fixtures=[]
    for flags in (0,1,2,4,8,10,42):fixtures.append({'label':'cached_flags_'+str(flags),'cached_port_u32':0x5017,'flags_u32':flags,'mode_u32':0})
    for mode in (1,2,7):fixtures.append({'label':'cached_mode_'+str(mode),'cached_port_u32':0x5017,'flags_u32':10,'mode_u32':mode})
    fixtures.append({'label':'fresh_primary_metadata_transport_error','bootstrap_results':[{'status_u32':0,'write_port_u32':0x5017}],
        'transport':{'enabled':True,'status_u32':0x10000003},'mode_u32':0})
    for mode in ('null','success'):
        fixtures.append({'label':'cached_allocator_'+mode,'cached_port_u32':0x5017,'flags_u32':10,'mode_u32':0,'allocator':mode})
    fixtures.append({'label':'cached_owned_cleanup','cached_port_u32':0x5017,'flags_u32':10,'mode_u32':0,'allocator':'success','model_free':True})
    fixtures.append({'label':'fresh_lookup_to_request1200','bootstrap_results':[{'status_u32':0,'write_port_u32':0x5017}],
        'transport':{'enabled':True,'status_u32':0x10000003},'mode_u32':0,'allocator':'success','model_free':True})
    for f in fixtures:
        probe=Flow(s,f);row=probe.run_caller();ff=row.pop('original_functions');ii=row.pop('visited_instruction_records')
        row['original_function_starts']=[v['start'] for v in ff]
        for v in ff:functions[v['start']]=v
        for v in ii:instructions[v['ea']]=v
        rows.append(row)
    out={'scope':__doc__,'thin_sha256':THIN_SHA,'profiles':rows,'original_functions':list(functions.values()),
        'visited_instruction_records':list(instructions.values()),'generator_sha256':sha(Path(__file__).read_bytes()),
        'dependencies':{name:sha((ROOT/name).read_bytes()) for name in ['probe_corefp_lookup.py','probe_corefp_mach_requests.py','probe_corefp_exports.py','corefp_fixups_inventory.json']},
        'native_target_executed':False,'full_goal_complete':False}
    (ROOT/'corefp_client_flow_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
    for row in rows:print(json.dumps({'label':row['fixture']['label'],'stop':row['stop_reason'],'steps':row['steps'],'last':row['records'][-1]}))


if __name__=='__main__':main()
