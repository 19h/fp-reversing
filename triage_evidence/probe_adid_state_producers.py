#!/usr/bin/env python3
"""Original state-word producer,word permutation and address-class controls.

Original full callback prefix; explicit owned relocation/input fixtures only.
Frozen API/PAC/vector models; no native target/host operation. Fixed constants
are checked as original prefix inputs,not whole-function/native invariants.
O(C*(B+F+K)) time/space with finite source-hook caps per case.
"""
import json
from pathlib import Path
import struct
from adid_reader import Adid,ROOT,sha,THIN_SHA
from probe_adid_context_gates import Gates
from probe_adid_receiver import HEAP
from probe_adid_startup import unpack_records
from adid_state_codec import close64


class Producers(Gates):
    def __init__(self,s,f,checkpoint):
        super().__init__(s,f,checkpoint);self.state_base=None
    def code(self,u,pc,n,data):
        if pc==0x100199778:
            cell=self.reg('sp')+0x3fb0;original=struct.unpack('<Q',u.mem_read(cell,8))[0]
            if 'codec_address' in self.fixture:
                address=self.fixture['codec_address'];target=bytes.fromhex(self.fixture.get('target_view64',''));raw=bytes.fromhex(self.fixture['raw_input64']) if 'raw_input64' in self.fixture else close64(target,address)
                u.mem_write(address,raw);u.mem_write(cell,struct.pack('<Q',address));self.records.append({'kind':'analyst_owned_state_fixture','pointer_cell':hex(cell),'original_pointer':hex(original),'new_pointer':hex(address),
                    'prepared_input64':raw.hex(),'target_view64':target.hex() if target else None,'native_valid_context_inferred':False})
            self.state_base=struct.unpack('<Q',u.mem_read(cell,8))[0]
            self.records.append({'kind':'original_state_producer_inputs','pc':hex(pc),'pointer_cell':hex(cell),'address':hex(self.state_base),'input64':bytes(u.mem_read(self.state_base,64)).hex(),
                'mul_u32':self.reg('w5'),'xor_u32':self.reg('w12'),'swap_mul_u32':self.reg('w3')})
        if pc==0x100199784:self.records.append({'kind':'original_state_word','pc':hex(pc),'address':hex(self.reg('x13')),'state_u32':self.reg('w14')})
        if pc==0x10019979c:
            self.records.append({'kind':'original_state_swap','pc':hex(pc),'address':hex(self.reg('x13')),'iteration_u32':self.reg('w12'),'selected_index_u32':self.reg('w15'),
                'state_u32':self.reg('w14'),'swap_mul_u32':self.reg('w3')})
        if pc==0x1001997d4:self.records.append({'kind':'original_state_after_swaps','pc':hex(pc),'address':hex(self.reg('x13')),'bytes64':bytes(u.mem_read(self.reg('x13'),64)).hex()})
        if pc==0x100199894:
            self.records.append({'kind':'original_state_view_complete','pc':hex(pc),'address':hex(self.state_base),'output64':bytes(u.mem_read(self.state_base,64)).hex()})
            if self.fixture.get('stop_after_state_view'):return self.stop('original_state_view_boundary')
        return super().code(u,pc,n,data)


def main():
    s=Adid();checkpoint=json.loads((ROOT/'adid_peer_checkpoint.json').read_text());gates=json.loads((ROOT/'adid_context_gate_profiles.json').read_text());base=gates['profiles'][0]['fixture']
    fixtures=[{**base,'label':'producer_complete_callback','instruction_budget':600000}, {**base,'label':'producer_original_boundary','stop_after_state_view':True,'instruction_budget':600000}]
    prior=json.loads((ROOT/'adid_context_profiles.json').read_text())
    for label in ['nonroot_ready_record_501','nonroot_ready_record_265']:
        old=next((r['fixture'] for r in prior['profiles'] if r['fixture']['label']==label),None)
        if old is not None:fixtures.append({**old,'label':'producer_'+label,'stop_after_state_view':True,'instruction_budget':600000})
    for low in range(0,256,8):
        view=bytes((i*37+low*11+7)&255 for i in range(64));fixtures.append({**base,'label':'owned_aligned_'+hex(low),'codec_address':HEAP+0x1c000+low,'target_view64':view.hex(),'stop_after_state_view':True,'instruction_budget':600000})
    for low in (1,2,7):
        raw=bytes((i*37+11)&255 for i in range(64));fixtures.append({**base,'label':'owned_unaligned_'+str(low),'codec_address':HEAP+0x1c000+low,'raw_input64':raw.hex(),'stop_after_state_view':True,'instruction_budget':600000})
    rows=[];functions={};instructions={}
    for f in fixtures:
        q=Producers(s,f,checkpoint);r=q.run_continuation()
        for x in r.pop('original_functions'):functions[x['start']]=x
        for x in r.pop('instruction_records'):instructions[x['ea']]=x
        rows.append(r);es=unpack_records(r);output=next((e['output64'] for e in es if e['kind']=='original_state_view_complete'),None)
        print(json.dumps({'label':f['label'],'stop':r['stop_reason'],'steps':r['steps'],'swaps':[e['selected_index_u32'] for e in es if e['kind']=='original_state_swap'],'target_matches':output==f.get('target_view64') if 'target_view64' in f else None}),flush=True)
    out={'scope':__doc__,'thin_sha256':THIN_SHA,'profiles':rows,'original_functions':list(functions.values()),'original_instruction_records':list(instructions.values()),'generator_sha256':sha(Path(__file__).read_bytes()),
        'dependencies':{n:sha((ROOT/n).read_bytes()) for n in ['adid_reader.py','adid_state_codec.py','probe_adid_context_gates.py','probe_adid_iokit.py','probe_adid_requests.py','probe_adid_startup.py','probe_adid_receiver.py','adid_peer_checkpoint.json','adid_context_gate_profiles.json','adid_context_profiles.json']},'native_target_executed':False,'full_goal_complete':False}
    (ROOT/'adid_state_producer_profiles.json').write_text(json.dumps(out,indent=2)+'\n')


if __name__=='__main__':main()
