#!/usr/bin/env python3
"""Stop original CoreFP MIG-style request builders at imported mach_msg.

Private Unicorn only; explicit reply-name and NDR-byte fixtures. Weak voucher
binding is absent or a no-op model. No send, receive, native loader/API or target
execution occurs. O(C*(B+F+K)) time, O(B+F+C*K) space for cases/image/fixups/
bounded instruction count. Entry reachability from protected exports is unknown.
"""
import hashlib
import json
from pathlib import Path
import struct
from unicorn import arm64_const as A
from corefp_fixups_reader import Pointers,ROOT,sha,THIN_SHA
from probe_corefp_exports import Probe,BASE,STACK,HEAP,BIND,DONE

SPECS=[(0x8ae0,0x8ba8,1200,64,220),(0x8d40,0x8e04,1201,164,44),
       (0x8ed4,0x8f90,1202,84,80),(0x90c8,0x914c,1203,24,60),
       (0x1590824,0x15908c8,1200,56,64)]


class Request(Probe):
    def __init__(self,s,f):
        super().__init__(s,{**f,'mode':'packet'})
        self.stub_ins={};self.stub_rows={};self.used_stubs={}
        for row in json.loads((ROOT/'corefp_import_calls.json').read_text())['stubs']:
            for ins in row['instructions']:
                at=int(ins['ea'],16);self.stub_ins[at]=ins;self.stub_rows[at]=row
        self.u.mem_write(STACK,b'\xa5'*0x40000)
        self.u.mem_write(HEAP+0x300,struct.pack('<I',2));self.u.mem_write(HEAP+0x400,bytes(range(16)))
        self.u.mem_write(HEAP+0x1000,bytes(range(128)))
        self.u.mem_write(BIND+175*16,bytes(range(8)))
        self.ndr_fixture=bytes(range(8)).hex()
        self.args={0x8ae0:[0x3141,0x11223344,HEAP+0x300,HEAP+0x1000,8,HEAP+0x400,HEAP+0x500,HEAP+0x600],
            0x8d40:[0x3141,0x11223344,HEAP+0x1000],
            0x8ed4:[0x3141,0x11223344,0x55667788,0x99aabbcc,HEAP+0x400,HEAP+0x1000,8,HEAP+0x500],
            0x90c8:[0x3141,HEAP+0x400,HEAP+0x500,HEAP+0x600,HEAP+0x700],
            0x1590824:[0x3141,HEAP+0x1000,8,HEAP+0x400,HEAP+0x500]}[f['entry']]
        if not f['voucher_present']:
            cell=0x1d1c5e8 if f['entry']==0x1590824 else 0x1d1c5d0
            assert s.decoded[cell]['import']['name']=='_voucher_mach_msg_set'
            self.u.mem_write(BASE+cell,struct.pack('<Q',0))
        # Permit original SIMD load/store copies in the bounded private image.
        self.u.reg_write(A.UC_ARM64_REG_CPACR_EL1,3<<20)
    def code(self,u,pc,n,data):
        at=pc-BASE
        if at in self.stub_ins:
            self.steps+=1;self.visited.append(at);i=self.stub_ins[at];row=self.stub_rows[at]
            self.used_stubs[row['address']]=row
            self.ins[at]={**i,'bytes':self.s.read(at,4).hex()}
            if i['mnemonic']=='braa':
                assert self.reg('x17')==BASE+int(row['pointer']['address'],16)
                self.records.append({'kind':'PAC_bypassed_original_import_stub','pc':hex(at),
                    'target':hex(self.reg('x16')),'modifier':hex(self.reg('x17'))})
                self.u.reg_write(A.UC_ARM64_REG_PC,self.reg('x16'))
            # ADRP/ADD/LDR execute original instructions in private pages.
            return
        im=self.binds.get(pc)
        if im and im['name']=='_mig_get_reply_port':
            self.steps+=1;value=self.fixture['reply_name_u32']
            self.records.append({'kind':'modeled_reply_port_name','name_u32':value,'native_port_allocated':False})
            self.u.reg_write(A.UC_ARM64_REG_X0,value);self.u.reg_write(A.UC_ARM64_REG_PC,self.reg('lr'));return
        if im and im['name']=='_voucher_mach_msg_set':
            self.steps+=1;self.records.append({'kind':'modeled_voucher_noop','message_pointer':hex(self.reg('x0')),'native_voucher_executed':False})
            self.u.reg_write(A.UC_ARM64_REG_PC,self.reg('lr'));return
        if im and im['name']=='_mach_msg':
            self.steps+=1;args=[self.reg('x'+str(i)) for i in range(7)];raw=bytes(u.mem_read(args[0],args[2]))
            self.records.append({'kind':'original_mach_msg_request_boundary','callsite':hex(self.reg('lr')-4-BASE),
                'args_x0_x6':[hex(v) for v in args],'message_bytes':raw.hex(),
                'header_u32':list(struct.unpack_from('<6I',raw)),'native_message_emitted':False})
            return self.stop('original_mach_msg_request_boundary')
        return super().code(u,pc,n,data)
    def run_request(self):
        for i,v in enumerate(self.args):self.u.reg_write(A.UC_ARM64_REG_X0+i,v)
        try:self.u.emu_start(BASE+self.fixture['entry'],DONE+4,count=30001)
        except Exception as e:
            if self.reason is None:self.reason='private_emulator_exception:'+str(e)
        h=hashlib.sha256()
        for pc in self.visited:h.update(struct.pack('<Q',pc));h.update(self.s.read(pc,4))
        return {'fixture':self.fixture,'input_args_x0_x7':[hex(v) for v in self.args],'NDR8_fixture_bytes':self.ndr_fixture,
            'stop_reason':self.reason,'steps':self.steps,'records':self.records,
            'visited_original_instructions':[hex(x) for x in self.visited],'original_instruction_bytes_sha256':h.hexdigest(),
            'original_functions':list(self.functions.values()),'visited_instruction_records':list(self.ins.values()),
            'original_auth_stubs':list(self.used_stubs.values())}


def main():
    s=Pointers();rows=[];functions={};instructions={}
    fixtures=[{'entry':e,'label':hex(e)+'_voucher_absent','voucher_present':False,'reply_name_u32':0x5173} for e,_,_,_,_ in SPECS]
    fixtures += [{'entry':0x8ae0,'label':'voucher_noop','voucher_present':True,'reply_name_u32':0x5173},
                 {'entry':0x8ae0,'label':'zero_reply_name','voucher_present':False,'reply_name_u32':0}]
    for f in fixtures:
        row=Request(s,f).run_request();ff=row.pop('original_functions');ii=row.pop('visited_instruction_records')
        row['original_function_starts']=[x['start'] for x in ff]
        for v in ff:functions[v['start']]=v
        for v in ii:instructions[v['ea']]=v
        rows.append(row)
    out={'scope':__doc__,'thin_sha256':THIN_SHA,'uuid':s.meta['uuid'],'profiles':rows,
        'original_functions':list(functions.values()),'visited_instruction_records':list(instructions.values()),
        'static_specs':[{'entry':hex(e),'callsite':hex(c),'request_id':i,'send_bytes':a,'receive_capacity_bytes':b} for e,c,i,a,b in SPECS],
        'generator_sha256':sha(Path(__file__).read_bytes()),'engine_sha256':sha((ROOT/'probe_corefp_exports.py').read_bytes()),
        'import_calls_sha256':sha((ROOT/'corefp_import_calls.json').read_bytes()),
        'fixup_inventory_sha256':sha((ROOT/'corefp_fixups_inventory.json').read_bytes()),
        'native_target_executed':False,'native_messages_emitted':False,'hardware_PAC_checked':False,'full_goal_complete':False}
    (ROOT/'corefp_mach_request_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
    for row in rows:print(json.dumps({'label':row['fixture']['label'],'reason':row['stop_reason'],'steps':row['steps'],'event':row['records'][-1]}))


if __name__=='__main__':main()
