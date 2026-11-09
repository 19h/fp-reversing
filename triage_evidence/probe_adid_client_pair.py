#!/usr/bin/env python3
"""Pair original CoreFP ADID client with retained provider error data.

Bounded private original-image execution with explicit XPC data/cleanup models.
No native target or IPC executes. Source-image compatibility is local, not live
endpoint pairing. O(C*(B+F+K)) time, O(B+F+C*K) space; inherited 30k-hook cap.
"""
import json
import base64
from pathlib import Path
import struct
import zlib
from unicorn import arm64_const as A
from corefp_fixups_reader import Pointers,ROOT,sha,THIN_SHA
from probe_corefp_secondary_client import Secondary,BASE,HEAP


class Pair(Secondary):
    def code(self,u,pc,n,data):
        im=self.binds.get(pc)
        if im and im['name']=='_xpc_dictionary_get_data':
            self.steps+=1;raw=bytes.fromhex(self.fixture['provider_response_hex']);ptr=0 if self.fixture.get('null_data') else HEAP+0xc000
            if ptr:u.mem_write(ptr,raw)
            length=self.fixture.get('provider_response_size',len(raw));u.mem_write(self.reg('x2'),struct.pack('<Q',length))
            self.records.append({'kind':'modeled_provider_response_data','callsite':hex(self.reg('lr')-4-BASE),'key':self.string(self.reg('x1')),
                'dictionary':hex(self.reg('x0')),'bytes':raw.hex(),'size_bytes':length,'result':hex(ptr),'native_IPC_executed':False})
            return self.ret(ptr)
        return super().code(u,pc,n,data)


def main():
    server=json.loads((ROOT/'adid_receiver_profiles.json').read_text())
    row=next(r for r in server['profiles'] if r['fixture']['label']=='initialized_path_number_1')
    records=row.get('records') or json.loads(zlib.decompress(base64.b64decode(row['records_zlib_base64'])))
    response=next(e for e in records if e.get('name')=='_xpc_dictionary_set_data')['payload_bytes'];assert response=='ffff4ff2'
    common={'allocator':'success','dictionary_result':'success','model_queue':True,'connection_result':'success','reply_kind':'dictionary','model_cleanup':True}
    fixtures=[]
    for v in (-8,-6,-5,-4,-3,-2):
        provider_row=next(r for r in server['profiles'] if r['fixture']['label']=='denied_selector_'+str(v))
        rr=provider_row.get('records') or json.loads(zlib.decompress(base64.b64decode(provider_row['records_zlib_base64'])))
        data=next(e for e in rr if e.get('name')=='_xpc_dictionary_set_data')['payload_bytes'];assert data==response
        fixtures.append({**common,'label':'original_provider_denial_selector_'+str(v),'selector_signed64':v,'provider_response_hex':data,'provider_source_profile':provider_row['fixture']['label']})
    fixtures+=[{**common,'label':'counterfactual_little_endian_response','selector_signed64':-8,'provider_response_hex':'f24fffff'},
        {**common,'label':'counterfactual_zero_status_only','selector_signed64':-8,'provider_response_hex':'00000000'},
        {**common,'label':'truncated_response3','selector_signed64':-8,'provider_response_hex':response,'provider_response_size':3},
        {**common,'label':'NULL_data_response','selector_signed64':-8,'provider_response_hex':response,'null_data':True}]
    s=Pointers();rows=[];functions={};instructions={}
    for f in fixtures:
        r=Pair(s,f).run_secondary()
        for v in r.pop('original_functions'):functions[v['start']]=v
        for v in r.pop('visited_instruction_records'):instructions[v['ea']]=v
        rows.append(r)
    out={'scope':__doc__,'CoreFP_thin_sha256':THIN_SHA,'provider_thin_sha256':server['source_thin_sha256'],
        'provider_response_source_profile':'initialized_path_number_1','provider_response_hex':response,'profiles':rows,
        'original_functions':list(functions.values()),'original_instruction_records':list(instructions.values()),
        'generator_sha256':sha(Path(__file__).read_bytes()),'dependencies':{n:sha((ROOT/n).read_bytes()) for n in ['probe_corefp_secondary_client.py','adid_receiver_profiles.json']},
        'native_target_executed':False,'full_goal_complete':False}
    (ROOT/'adid_client_pair_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
    for r in rows:print(json.dumps({'label':r['fixture']['label'],'stop':r['stop_reason'],'steps':r['steps'],'result_u32':hex(r['result_u32']),'last':r['records'][-1]}))


if __name__=='__main__':main()
