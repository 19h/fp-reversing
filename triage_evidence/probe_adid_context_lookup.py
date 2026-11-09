#!/usr/bin/env python3
"""Coupled count/array/holder/nested-record fixtures in original ADID callback.

No PC jumps, native target/API or native object validity claims. The frozen
local codec prepares a decoded collection view; all API/PAC models are retained.
O(C*(B+F+K+N)) time, O(B+F+C*K+N) evidence space; N<=256, nodes<=16,
finite per-case source-hook caps. Reads/writes retain original source sites.
"""
import json
from pathlib import Path
import struct
from unicorn import UC_HOOK_MEM_READ
from adid_reader import Adid,ROOT,sha,THIN_SHA
from probe_adid_context_gates import Gates,BLOCK
from probe_adid_receiver import HEAP
from probe_adid_startup import unpack_records
from adid_state_codec import close64

MASK=(1<<64)-1
ARRAY=HEAP+0x1c000
HOLDERS=HEAP+0x1d000
NESTED=HEAP+0x1e000
COUNT_BIAS=0x16e4e4d3
ARRAY_BIAS=0x58ce03d8d8c95487
HOLDER_BIAS=0x2d1ade42073e28af
NESTED_BIAS=0x6fac17cb61e34e69
KEY_XOR=0xda8ca8cae5dfbd2d
UID_BIAS=0x46d726


class Lookup(Gates):
    def __init__(self,s,f,checkpoint):
        super().__init__(s,f,checkpoint);self.prepared=False;self.regions=[];self.lookup_reads=[];self.lookup_writes=[]
        self.u.hook_add(UC_HOOK_MEM_READ,self.lookup_read)
    def region(self,address,size):
        return next((r for r in self.regions if r['address']<=address and address+size<=r['address']+r['size_bytes']),None)
    def lookup_read(self,u,access,address,size,value,data):
        r=self.region(address,size)
        if r:self.lookup_reads.append({'pc':hex(self.reg('pc')),'region':r['kind'],'index':r.get('index'),'offset_bytes':address-r['address'],'size_bytes':size,'bytes':bytes(u.mem_read(address,size)).hex()})
        pc=self.reg('pc')
        if 0x10019bdcc<=pc<0x10019c328 and address in self.s.decoded:
            self.records.append({'kind':'original_lookup_pointer_cell','pc':hex(pc),'cell':hex(address),'bytes8':bytes(u.mem_read(address,8)).hex()})
    def write(self,u,access,address,size,value,data):
        r=self.region(address,size)
        if r:self.lookup_writes.append({'pc':hex(self.reg('pc')),'region':r['kind'],'index':r.get('index'),'offset_bytes':address-r['address'],'size_bytes':size,'before_bytes':bytes(u.mem_read(address,size)).hex(),'value':hex(value&((1<<(size*8))-1))})
        return super().write(u,access,address,size,value,data)
    def code(self,u,pc,n,data):
        if pc==0x100199778 and self.fixture.get('prepare_lookup'):
            assert not self.prepared
            f=self.fixture;count=f['lookup_count'];nodes=f['lookup_nodes'];assert 0<=count<=256 and len(nodes)<=16
            view=bytearray.fromhex(f['baseline_view64']);struct.pack_into('<I',view,0,(COUNT_BIAS+count)&0xffffffff);struct.pack_into('<Q',view,8,ARRAY_BIAS if f.get('null_array') else (ARRAY+ARRAY_BIAS)&MASK)
            raw_array=bytearray(max(16,16*count))
            for i in range(count):struct.pack_into('<QQ',raw_array,16*i,(0x8123456789abcdef+i*0x1020304050607)&MASK,HOLDER_BIAS)
            u.mem_write(ARRAY,bytes(raw_array));self.regions=[{'kind':'array','address':ARRAY,'size_bytes':len(raw_array)}]
            for i,node in enumerate(nodes):
                if node is None:continue
                assert i<count
                o=HOLDERS+256*i;q=NESTED+256*i;u.mem_write(o,bytes(256));u.mem_write(q,bytes(256))
                struct.pack_into('<Q',raw_array,16*i+8,(o+HOLDER_BIAS)&MASK)
                u.mem_write(o,struct.pack('<Q',NESTED_BIAS if node.get('null_nested') else (q+NESTED_BIAS)&MASK))
                key=node.get('key',f['first_request_u64'])&MASK;uid=node.get('uid',f.get('audit_euid_result',0))&0xffffffff
                u.mem_write(q+8,struct.pack('<Q',key^KEY_XOR));u.mem_write(q+0x98,struct.pack('<Q',node.get('initial_field98',0x0123456789abcdef)));u.mem_write(q+0xa0,struct.pack('<I',(uid+UID_BIAS)&0xffffffff))
                self.regions.extend([{'kind':'holder','address':o,'size_bytes':256,'index':i},{'kind':'nested','address':q,'size_bytes':256,'index':i}])
            u.mem_write(ARRAY,bytes(raw_array));prepared=close64(view,BLOCK);u.mem_write(BLOCK,prepared);self.prepared=True
            self.records.append({'kind':'analyst_coupled_collection_fixture','pc':hex(pc),'block_address':hex(BLOCK),'input64':prepared.hex(),'target_view64':view.hex(),'array_bytes':raw_array.hex(),'regions':self.regions,
                'expected_key_slot_u64':hex(struct.unpack('<Q',u.mem_read(self.reg('sp')+0x1c18,8))[0]),'expected_uid_slot_u32':hex(struct.unpack('<I',u.mem_read(self.reg('sp')+0x29f4,4))[0]),'value_slot24b8_u64':hex(struct.unpack('<Q',u.mem_read(self.reg('sp')+0x24b8,8))[0]),'native_valid_object_inferred':False})
        if pc==0x100199894 and self.prepared:self.records.append({'kind':'original_lookup_view_complete','pc':hex(pc),'output64':bytes(u.mem_read(BLOCK,64)).hex()})
        if pc in (0x10019be18,0x10019c048,0x10019c0d0,0x10019c150,0x10019c310,0x10021ac34,0x10021ac38):
            e={'kind':'original_lookup_boundary','pc':hex(pc),'registers':{r:hex(self.reg(r)) for r in ['x0','x1','x2','x3','x4','x5','x6','x7','x8','x9','x12','x13','x14','x15','x16','x17','x20','x23']}}
            if pc==0x10021ac34:e['load_address']=hex(self.reg('x8'));e['load_bytes8']=bytes(u.mem_read(self.reg('x8'),8)).hex()
            self.records.append(e)
        return super().code(u,pc,n,data)


def fixtures():
    prior=json.loads((ROOT/'adid_context_profiles.json').read_text());base=next(r['fixture'] for r in prior['profiles'] if r['fixture']['label']=='context_error_producer')
    producer=json.loads((ROOT/'adid_state_producer_profiles.json').read_text());view=next(e['output64'] for e in unpack_records(producer['profiles'][0]) if e['kind']=='original_state_view_complete')
    out=[{**base,'label':'lookup_unmodified_baseline','instruction_budget':800000}]
    def add(label,count=1,nodes=None,first=-8,second=HEAP+0x100,uid=0,**extra):
        b=base if uid==0 else next(r['fixture'] for r in prior['profiles'] if r['fixture']['label']=='nonroot_ready_record_'+str(uid))
        out.append({**b,'label':label,'instruction_budget':800000,'prepare_lookup':True,'lookup_count':count,'lookup_nodes':nodes or [],'baseline_view64':view,'first_request_u64':first&MASK,'second_request_u64':second&MASK,
            'payload_hex':struct.pack('>IIIQQ',1,0x632b8d6e,1,first&MASK,second&MASK).hex(),**extra})
    for count in [0,1,2,3,4,8,16,31,32,255,256]:add('null_entries_'+str(count),count)
    for count in [0,1,4]:add('null_array_count'+str(count),count,null_array=True)
    add('null_nested_four',4,[{'null_nested':True}]*4)
    add('key_mismatch_four',4,[{'key':1234}]*4)
    add('uid_mismatch_four',4,[{'uid':501}]*4)
    for index in [0,1,3]:add('match_at_'+str(index),4,[None]*index+[{}])
    add('duplicate_matches',4,[None,{},None,{}])
    add('mixed_match_last',4,[{'null_nested':True},{'key':1234},{'uid':501},{}])
    for first in [-8,-6,-5,-4,-3,-2]:add('matched_first_'+str(first),nodes=[{}],first=first)
    for uid in [0,265,501]:add('matched_uid_'+str(uid),nodes=[{}],uid=uid)
    add('uid501_record0',nodes=[{'uid':0}],uid=501)
    for second in [0,1,MASK,0x0123456789abcdef]:add('second_'+hex(second),nodes=[{}],second=second)
    for first in [0,1,-1,1234,0x0123456789abcdef]:add('unsupported_first_'+str(first),nodes=[{}],first=first)
    return out


def main():
    s=Adid();checkpoint=json.loads((ROOT/'adid_peer_checkpoint.json').read_text());rows=[];functions={};instructions={}
    for f in fixtures():
        q=Lookup(s,f,checkpoint);r=q.run_continuation();r.update({'lookup_prepared':q.prepared,'lookup_reads':q.lookup_reads,'lookup_writes':q.lookup_writes,'nested_final_fields98':{str(x['index']):bytes(q.u.mem_read(x['address']+0x98,8)).hex() for x in q.regions if x['kind']=='nested'}})
        for x in r.pop('original_functions'):functions[x['start']]=x
        for x in r.pop('instruction_records'):instructions[x['ea']]=x
        rows.append(r);es=unpack_records(r);print(json.dumps({'label':f['label'],'stop':r['stop_reason'],'steps':r['steps'],'array_reads':[x['offset_bytes'] for x in q.lookup_reads if x['region']=='array'],'writes':q.lookup_writes,'reply':[e['payload_bytes'] for e in es if e.get('name')=='_xpc_dictionary_set_data']}),flush=True)
    out={'scope':__doc__,'thin_sha256':THIN_SHA,'profiles':rows,'original_functions':list(functions.values()),'original_instruction_records':list(instructions.values()),'generator_sha256':sha(Path(__file__).read_bytes()),
        'dependencies':{n:sha((ROOT/n).read_bytes()) for n in ['adid_reader.py','adid_state_codec.py','probe_adid_context_gates.py','probe_adid_iokit.py','probe_adid_requests.py','probe_adid_startup.py','probe_adid_receiver.py','adid_peer_checkpoint.json','adid_state_producer_profiles.json','adid_context_profiles.json']},'native_target_executed':False,'full_goal_complete':False}
    (ROOT/'adid_context_lookup_profiles.json').write_text(json.dumps(out,indent=2)+'\n')


if __name__=='__main__':main()
