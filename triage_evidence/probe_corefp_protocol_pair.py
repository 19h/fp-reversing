#!/usr/bin/env python3
"""Original CoreFP lookup/client versus original daemon MIG demultiplexer.

Separate private Unicorn images. Envelope size and task-local names are explicit
adapter fixtures;they do not model kernel rights/port identity. Request/reply
bodies and statuses come from source instructions. Counterfactual ID changes
are labeled and never patch an original file or native process. No host IPC,
target/native loader/API executes. Time O(C*(B+F+K)),space O(B+F+C*K),bounded
source visits per engine;daemon child has a2000-hook guard and range allowlist.
"""
import hashlib
import json
from pathlib import Path
import struct
from unicorn import arm64_const as A
from corefp_fixups_reader import Pointers,ROOT,sha,THIN_SHA
from probe_corefp_lookup import Lookup
from probe_corefp_exports import BASE
from daemon_rpc502_probe import Probe as DaemonBase,STACK,HALT,ar
from daemon_receive_tools import IMAGE,SOURCE,CS

RANGES=[(0x100004b80,0x100004c10),(0x100004918,0x100004ae4),
        (0x100004ae4,0x100004b80),(0x100006424,0x100006448)]


class DaemonMetadata(DaemonBase):
    def __init__(self,wire,request_id):
        super().__init__();self.visited=[];self.received=bytearray(wire)
        assert len(wire)==24 and struct.unpack_from('<I',wire,20)[0]==1203
        # Task-local names and received header shape are model inputs. No
        # native kernel name translation,rights or message delivery is claimed.
        struct.pack_into('<6I',self.received,0,18,24,0x6403,0x1403,0,request_id)
        self.request=STACK+0x1000;self.reply=STACK+0x2000
        self.u.mem_write(self.request,bytes(self.received));self.u.mem_write(self.reply,b'\xa5'*256)
    def hook(self,u,pc,n,data):
        if pc==HALT:return super().hook(u,pc,n,data)
        if self.steps>=2000:return self.stop('daemon_private_instruction_guard')
        if pc in self.imports:return self.stop('daemon_unmodeled_import_guard',name=self.imports[pc])
        if not any(a<=pc<z for a,z in RANGES):return self.stop('daemon_unreviewed_continuation_guard',pc=hex(pc))
        self.visited.append(pc)
        return super().hook(u,pc,n,data)
    def run_server(self):
        self.setreg(0,self.request);self.setreg(1,self.reply);self.setreg(30,HALT)
        self.u.reg_write(ar.UC_ARM64_REG_SP,STACK+0x78000)
        try:self.u.emu_start(0x100004b80,0,count=2001)
        except Exception as e:
            if self.stop_reason is None:self.stop_reason='daemon_private_emulator_exception:'+str(e)
        prefix=bytes(self.u.mem_read(self.reply,36));size=struct.unpack_from('<I',prefix,4)[0]
        assert size in (36,52),size
        reply=bytes(self.u.mem_read(self.reply,size));h=hashlib.sha256()
        for at in self.visited:h.update(struct.pack('<Q',at));h.update(IMAGE.read(at,4))
        return {'received_request_bytes':bytes(self.received).hex(),'reply_bytes':reply.hex(),'reply_size_bytes':size,
            'reply_status_signed32':struct.unpack_from('<i',reply,32)[0],'recognized_u32':self.reg(0),
            'stop_reason':self.stop_reason,'steps':self.steps,'records':self.records,'pac_bypasses':self.pac,
            'visited_original_instructions':[hex(a) for a in self.visited],'original_instruction_bytes_sha256':h.hexdigest(),
            'native_message_delivered':False}


class Pair(Lookup):
    def __init__(self,s,f):
        super().__init__(s,{'warm_once':True,'model_locks':True,'flag_u8':9,'tag_u32':0xba27,
            'bootstrap_results':[{'status_u32':0,'write_port_u32':0x5017}],**f})
        self.server_profiles=[]
    def code(self,u,pc,n,data):
        im=self.binds.get(pc)
        if im and im['name']=='_mach_msg':
            self.steps+=1;args=[self.reg('x'+str(j)) for j in range(7)];ptr=args[0];wire=bytes(u.mem_read(ptr,args[2]))
            assert args[1:]==[3,24,60,0x5173,0,0]
            server_id=self.fixture['server_request_id'];child=DaemonMetadata(wire,server_id).run_server();self.server_profiles.append(child)
            assert child['stop_reason']=='returned_to_fixture' and child['recognized_u32']==1
            reply=bytearray.fromhex(child['reply_bytes']);original_reply_id=struct.unpack_from('<I',reply,20)[0]
            struct.pack_into('<III',reply,0,0,len(reply),0)
            struct.pack_into('<I',reply,12,0x5173)
            if self.fixture.get('restore_client_reply_id'):struct.pack_into('<I',reply,20,1303)
            u.mem_write(ptr,bytes(reply));self.records.append({'kind':'source_daemon_reply_ABI_transfer',
                'callsite':hex(self.reg('lr')-4-BASE),'request_bytes':wire.hex(),'source_server_reply_bytes':child['reply_bytes'],
                'client_reply_bytes':bytes(reply).hex(),'server_request_id':server_id,'source_reply_id':original_reply_id,
                'counterfactual_request_id_change':server_id!=1203,'counterfactual_reply_id_change':bool(self.fixture.get('restore_client_reply_id')),
                'adapter_note':'Received sizes/names/bits are private fixtures;body bytes preserved exactly;transport return0 is modeled.',
                'native_transport_executed':False})
            return self.ret(0)
        if im and im['name'] in ('_mig_put_reply_port','_mig_dealloc_reply_port','_mach_msg_destroy'):
            self.steps+=1;self.records.append({'kind':'modeled_pair_cleanup','name':im['name'],
                'argument_x0':hex(self.reg('x0')),'native_cleanup_executed':False});return self.ret()
        return super().code(u,pc,n,data)


def main():
    s=Pointers();rows=[];functions={};instructions={}
    for fixture in [{'label':'original_ids','server_request_id':1203},
            {'label':'counterfactual_request_id_only','server_request_id':1204},
            {'label':'counterfactual_request_and_reply_ids','server_request_id':1204,'restore_client_reply_id':True}]:
        probe=Pair(s,fixture);row=probe.run_lookup();row['daemon_children']=probe.server_profiles
        ff=row.pop('original_functions');ii=row.pop('visited_instruction_records');row['original_function_starts']=[x['start'] for x in ff]
        for v in ff:functions[v['start']]=v
        for v in ii:instructions[v['ea']]=v
        rows.append(row)
    out={'scope':__doc__,'CoreFP_thin_sha256':THIN_SHA,'daemon_thin_sha256':sha(SOURCE.read_bytes()),
        'profiles':rows,'CoreFP_original_functions':list(functions.values()),'CoreFP_visited_instruction_records':list(instructions.values()),
        'daemon_original_ranges':[{'start':hex(a),'end':hex(z),'bytes':IMAGE.read(a,z-a).hex(),'sha256':sha(IMAGE.read(a,z-a))} for a,z in RANGES],
        'generator_sha256':sha(Path(__file__).read_bytes()),
        'dependencies':{name:sha((ROOT/name).read_bytes()) for name in ['probe_corefp_lookup.py','probe_corefp_mach_requests.py','probe_corefp_exports.py','daemon_rpc502_probe.py','daemon_receive_tools.py','daemon_receive_fixups.txt','corefp_fixups_inventory.json']},
        'native_target_executed':False,'hardware_PAC_checked':False,'full_goal_complete':False}
    (ROOT/'corefp_protocol_pair_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
    for row in rows:print(json.dumps({'label':row['fixture']['label'],'stop':row['stop_reason'],
        'record_status':row['record_after32_bytes'][:8],'outputs':row['output8_bytes'],'metadata':row['metadata_after_u32'],
        'client_results':[e for e in row['records'] if e['kind']=='original_metadata_client_result'],
        'daemon_replies':[(v['reply_size_bytes'],v['reply_status_signed32']) for v in row['daemon_children']]}))


if __name__=='__main__':main()
