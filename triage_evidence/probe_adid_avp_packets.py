#!/usr/bin/env python3
"""Source-built Avp packet, representation epochs and explicit response controls.

Full original callbacks; only declared API results vary. No internal PC/frame
or context overrides and no native target/API. Stop before a second method100
response. O(C*(B+F+K)) time/space, 800000 hooks per case, <=4096 API bytes.
"""
import json
from pathlib import Path
import struct
from adid_reader import Adid,ROOT,sha,THIN_SHA
from probe_adid_command_dispatch import Commands
from probe_adid_startup import unpack_records

WATCH=[('method_buffer',0x7e000530,144),('caller_destination',0x7e010420,144),
       ('outgoing_staging',0x7e0105c0,144),('incoming_staging',0x7e0005d0,144),
       ('parser_input_candidate',0x7e0104c0,144),('allocated_state12',0x7b01c000,12),('allocated_state1',0x7b01d000,1)]


class Packets(Commands):
    def __init__(self,s,f,checkpoint):
        self.packet_effects=[];self.packet_reads=[];self.pending_packet_writes=[];self.method_index=0;self.pending_codec=None;self.caller_records=[]
        super().__init__(s,f,checkpoint)
    def snapshots(self):
        out={}
        for name,a,n in WATCH:
            try:out[name]=bytes(self.u.mem_read(a,n)).hex()
            except Exception:out[name]=None
        return out
    def flush_packet_writes(self,pc):
        for e in self.pending_packet_writes:
            e['after_bytes']=bytes(self.u.mem_read(int(e['address'],16),e['size_bytes'])).hex();e['observed_before_pc']=hex(pc);self.packet_effects.append(e)
        self.pending_packet_writes=[]
    def write(self,u,access,a,n,value,data):
        for name,start,size in WATCH:
            if a<start+size and start<a+n:
                self.pending_packet_writes.append({'kind':'original_watched_write','step':self.steps,'pc':hex(self.reg('pc')),'watch':name,'address':hex(a),'offset_bytes':a-start,'size_bytes':n,'before_bytes':bytes(u.mem_read(a,n)).hex(),'method_calls_already_observed':self.method_index})
        return super().write(u,access,a,n,value,data)
    def read_hook(self,u,access,a,n,value,data):
        for name,start,size in WATCH:
            if a<start+size and start<a+n:self.packet_reads.append({'step':self.steps,'pc':hex(self.reg('pc')),'watch':name,'address':hex(a),'offset_bytes':a-start,'size_bytes':n,'bytes':bytes(u.mem_read(a,n)).hex(),'method_calls_already_observed':self.method_index})
        return super().read_hook(u,access,a,n,value,data)
    def code(self,u,pc,n,data):
        self.flush_packet_writes(pc)
        if pc==0x100058654:
            a=self.reg('x0');raw=bytes(u.mem_read(a,40));self.caller_records.append({'address':a,'destination':struct.unpack_from('<Q',raw,16)[0],'count_pointer':(struct.unpack_from('<Q',raw)[0]-0x68a91db5735d89de)&((1<<64)-1)})
        if pc==0x10025fc38 and self.reg('x0')==0x7e000530 and self.method_index==0:
            dest=self.reg('x16');offset=dest-self.reg('x0');source=self.reg('x9')+offset
            self.records.append({'kind':'original_outgoing_byte_codec','step':self.steps,'pc':hex(pc),'source_address':hex(source),'destination_address':hex(dest),'offset_bytes':offset,'input_u8':u.mem_read(source,1)[0],'key_u32':self.reg('w1'),'output_u8':self.reg('w17')&255})
        if pc==0x10024bb7c:
            a=self.reg('x16');self.pending_codec={'source_address':hex(a),'input_u8':u.mem_read(a,1)[0],'mask_u32':self.reg('w1'),'source_pc':hex(pc)}
        if pc==0x10024bb90 and self.pending_codec:
            self.records.append({'kind':'original_physical_byte_codec','step':self.steps,'pc':hex(pc),**self.pending_codec,'destination_address':hex(self.reg('x15')),'output_u8':self.reg('w16')&255,'method_calls_already_observed':self.method_index});self.pending_codec=None
        if pc==0x10025fd18 and self.method_index==1:
            a=self.reg('x13');self.records.append({'kind':'original_parser_copy_codec','step':self.steps,'pc':hex(pc),'source_address':hex(a),'destination_address':hex(self.reg('x0')+self.reg('x11')),'offset_bytes':self.reg('x11'),'input_u8':u.mem_read(a,1)[0],'key_u32':self.reg('w14')})
        if pc in (0x10002c134,0x10002c254,0x10002c368,0x10002c464) and self.caller_records:
            c=self.caller_records[-1];self.records.append({'kind':'original_packet_caller_return','pc':hex(pc),'record_address':hex(c['address']),'record40_bytes':bytes(u.mem_read(c['address'],40)).hex(),'count_pointer':hex(c['count_pointer']),'count_raw_u32':int.from_bytes(u.mem_read(c['count_pointer'],4),'little'),'snapshots':self.snapshots()})
        if pc in (0x100260cd0,0x100260d94,0x100260e18,0x100260f28,0x100262090):
            self.records.append({'kind':'original_typed_parser_scalar','pc':hex(pc),'method_calls_already_observed':self.method_index,'registers':{r:hex(self.reg(r)) for r in ['x8','x9','x10','x11','x12','x13','x14','x15','x16','x17','x20','x21','x22','x23','sp']}})
        return super().code(u,pc,n,data)
    def api(self,im):
        before=self.snapshots();result=self.packet_api(im);after=self.snapshots()
        if before!=after:self.packet_effects.append({'kind':'declared_API_watched_effect','name':im['name'],'method_calls_already_observed':self.method_index,'before':before,'after':after,'native_API_executed':False})
        return result
    def packet_api(self,im):
        if im['name']!='_IOConnectCallStructMethod' or self.reg('w1')!=100:return super().api(im)
        self.method_index+=1;x=[self.reg('x'+str(i)) for i in range(8)];n=x[3]
        e={'kind':'original_method100_boundary','step':self.steps,'name':im['name'],'callsite':hex(self.reg('lr')-4),'method_index':self.method_index,'args_x0_x7':[hex(v) for v in x],'native_API_executed':False,'input_size_u64':n,'snapshots':self.snapshots()};self.records.append(e)
        if n>4096:return self.stop('packet_method_extent_guard')
        e['input_bytes']=bytes(self.u.mem_read(x[2],n)).hex();e['output_size_before_u64']=int.from_bytes(self.u.mem_read(x[5],8),'little')
        if self.method_index>1:return self.stop('original_subsequent_method100_boundary')
        if n!=144 or x[2]!=x[4] or x[0]!=0x5804 or e['output_size_before_u64']!=n:return self.stop('packet_first_method_shape_guard')
        mode=self.fixture['packet_response']['kind'];spec=self.fixture['packet_response']
        if mode=='opaque':return self.stop('original_method100_opaque_boundary')
        raw=bytes.fromhex(e['input_bytes'])
        if mode=='bytes':raw=bytes.fromhex(spec['bytes'])
        elif mode=='prefix':raw=raw[:spec['size_bytes']]
        elif mode=='patch':
            raw=bytearray(raw)
            for off,data in spec['patches']:
                piece=bytes.fromhex(data)
                if not 0<=off<=off+len(piece)<=n:return self.stop('packet_patch_extent_guard')
                raw[off:off+len(piece)]=piece
            raw=bytes(raw)
        elif mode!='identity':return self.stop('packet_response_model_guard')
        if len(raw)>n:return self.stop('packet_response_capacity_guard')
        if raw:self.u.mem_write(x[4],raw)
        self.u.mem_write(x[5],struct.pack('<Q',len(raw)));self.records.append({'kind':'declared_packet_response_model','mode':mode,'response_bytes':raw.hex(),'returned_size_bytes':len(raw),'result_u32':0,'native_API_executed':False,'native_driver_response_validated':False});return self.finish_api(0)


def fixtures():
    prior=json.loads((ROOT/'adid_command_dispatch_profiles.json').read_text());base=next(r['fixture'] for r in prior['profiles'] if r['fixture']['label']=='environment_iokit_opaque');out=[]
    def add(label,response=None,**extra):out.append({**base,'label':label,'packet_response':response or {'kind':'opaque'},'instruction_budget':800000,**extra})
    add('packet_opaque');add('packet_identity',{'kind':'identity'})
    for t in (0,1,2,0xffffffff,0x100000000,(1<<64)-1):add('time_'+hex(t),model_time_seconds=t)
    for v in (0,1,0x7ffffffe):add('random_'+hex(v),model_uniform_result=v)
    for n in (0,1,9,10,18,32,122,143):add('response_prefix_'+str(n),{'kind':'prefix','size_bytes':n})
    for name,raw in [('zeros10',bytes(10)),('ramp0',bytes(range(144))),('ramp144',bytes(range(144,256))),('scalar0',struct.pack('>IHI',0x7976211a,0x9777,4)+bytes(4)),('scalar1',struct.pack('>IHI',0x7976211a,0x9777,4)+struct.pack('>I',1))]:add('response_'+name,{'kind':'bytes','bytes':raw.hex()})
    for n in (1,0x8b3dc651,0xffffffff):add('response_scalar_'+hex(n),{'kind':'patch','patches':[(28,struct.pack('>I',n).hex())]})
    for name,off,raw in [('key0',0,bytes(4)),('tag0',4,bytes(2)),('length_max',6,bytes.fromhex('ffffffff')),('nested_tag0',46,bytes(2)),('nested_scalar0',94,bytes(4))]:add('response_patch_'+name,{'kind':'patch','patches':[(off,raw.hex())]})
    return out


def run_one(s,f,checkpoint):
    q=Packets(s,json.loads(json.dumps(f)),checkpoint);r=q.result();q.flush_packet_writes(q.reg('pc'));r.update({'packet_write_effects':q.packet_effects,'packet_read_observations':q.packet_reads,'watched_final_snapshots':q.snapshots(),'observed_method100_calls':q.method_index});return q,r


def main():
    s=Adid();ck=json.loads((ROOT/'adid_peer_checkpoint.json').read_text());rows=[];functions={};instructions={}
    for f in fixtures():
        q,r=run_one(s,f,ck)
        for row in r.pop('original_functions'):functions[row['start']]=row
        for row in r.pop('instruction_records'):instructions[row['ea']]=row
        rows.append(r);events=unpack_records(r);print(json.dumps({'label':f['label'],'stop':r['stop_reason'],'steps':r['steps'],'methods':[(e['method_index'],e['input_size_u64']) for e in events if e['kind']=='original_method100_boundary'],'reply':[e['payload_bytes'] for e in events if e.get('name')=='_xpc_dictionary_set_data']}),flush=True)
    names=['adid_reader.py','probe_adid_avp_packets.py','probe_adid_command_dispatch.py','probe_adid_record_lifecycle.py','probe_adid_iokit_callers.py','probe_adid_context_gates.py','probe_adid_iokit.py','probe_adid_requests.py','probe_adid_startup.py','probe_adid_receiver.py','adid_peer_checkpoint.json','adid_command_dispatch_profiles.json']
    out={'scope':__doc__,'thin_sha256':THIN_SHA,'watch_extents':[{'name':k,'address':hex(a),'size_bytes':n,'scope':'Address observation window;may contain multiple allocation/representation epochs.'} for k,a,n in WATCH],'profiles':rows,'original_functions':list(functions.values()),'original_instruction_records':list(instructions.values()),'generator_sha256':sha(Path(__file__).read_bytes()),'dependencies':{n:sha((ROOT/n).read_bytes()) for n in names},'native_target_executed':False,'full_goal_complete':False};(ROOT/'adid_avp_packet_profiles.json').write_text(json.dumps(out,indent=2)+'\n')


if __name__=='__main__':main()
