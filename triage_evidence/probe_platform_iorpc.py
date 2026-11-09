#!/usr/bin/env python3
"""Original IORPC requests through declared local hierarchy and direct backend.
Registry/classes/PAC are premises; backend/transport models are explicit.
O(visits+effects), O(journals+private RAM); no native IPC/platform operations.
"""
import json,struct
from unicorn import arm64_const as ar
from probe_aes_platform_gate import Probe as Parent,DEV,CTRL,CONTEXT
from probe_aes_hardware_job import P,PROV
from probe_kernel_vm_mig import SP,HALT
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
PREFIX='platform_iorpc';THREAD=P+0x1b000;OUT=P+0x2f000;CUSTOM=P+0xe2000;DEFAULT=0xfffffe000c5957d4
METHODS={'clock':(0xfffffe0008cfa1e8,0xfffffe0008cf98e8,0xfffffe0008cb47c0,0x98ae300572af31c2,92,60),'power':(0xfffffe0008cfa2e4,0xfffffe0008cf9994,0xfffffe0008cb47f4,0xd33e8303066fa5d3,92,64),'psd':(0xfffffe0008cfa5fc,0xfffffe0008cf9b9c,0xfffffe0008cb4890,0x9817bbdfffd2803c,100,60)}
class Probe(Parent):
 def __init__(self,im,c,src,origin,producer=None):
  super().__init__(im,{'stage':'device','enable':1},src,origin,None,{'path':'aes_platform_gate_profiles.json','case':0});self.c=c;self.src=src;self.transport_producer=producer;self.rpc_frames=[];self.dispatch_frames=[];self.invoke_frames=[];self.thunk_frames=[];self.thread_frames=[];self.allowed +=[(int(s['start'],16),int(s['end'],16))for s in src['rpc_stubs']];self.all_objects +=[(OUT,16),(THREAD,0x400)]
  self.fixture(OUT,bytes([0xa5])*16);self.fixture(THREAD,bytes(0x378)+struct.pack('<Q',0x1122334455667788)+bytes(0x80));self.ensure(0xfffffe000cc08998,8);self.u.mem_write(0xfffffe000cc08998,bytes(8));self.image_initial.append({'address':'0xfffffe000cc08998','bytes_hex':'00'*8,'provenance':'Declared terminating AppleARMIODevice hierarchy; native initialization unknown'});self.ensure(0xfffffe0007f54318);self.u.mem_write(0xfffffe0007f54318,b'\x01');self.image_initial.append({'address':'0xfffffe0007f54318','bytes_hex':'01','provenance':'Declared local debug epoch, matching file byte; native value unknown'})
  method=c['method'];self.entry=METHODS[method][0];custom=CUSTOM if c.get('custom')else 0
  args=[DEV,1,0,custom]if method=='clock'else[DEV,1,0 if c.get('null_output')else OUT,0,custom]if method=='power'else[DEV,1,0,0xffffffff,0xffffffff,custom]
  for j,v in enumerate(args):self.set(j,v)
  self.set(30,HALT);self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV));self.trace_target=int(next(s for s in src['additional_slots']if s['name']=='trace_API')['pointer']['target'],16)
 def rpc_frame(self,a,reg,n):
  q=self.reg(reg);b=bytes(self.u.mem_read(q,32));message,reply,send,capacity,content=struct.unpack('<QQIIQ',b);return{**self.frame(a,n),'rpc_address':hex(q),'rpc32_hex':b.hex(),'message_address':hex(message),'reply_address':hex(reply),'send_size':send,'reply_capacity':capacity,'content_address':hex(content),'packet_hex':bytes(self.u.mem_read(message,capacity)).hex()}
 def code(self,u,a,n,d):
  self.flush()
  if a in [DEFAULT,CUSTOM]:
   f=self.rpc_frame(a,1,2);self.rpc_frames.append(f)
   if a==CUSTOM:
    if self.transport_producer is not None:
     b=bytearray.fromhex(self.transport_producer['final_rpc_buffers'][0]['bytes_hex']);patch=self.c.get('reply_patch')
     if patch:off,size,value=patch;b[off:off+size]=value.to_bytes(size,'little')
     self.effect(int(f['reply_address'],16),bytes(b),'Declared exact source-produced reply transfer with optional explicit field substitution')
    return self.modeled(a,'declared_custom_dispatch_model',self.c.get('transport_result',0))
  if a in [0xfffffe0008cf9500,0xfffffe0008cf9530]:self.dispatch_frames.append(self.rpc_frame(a,1,2))
  if a in [v[1]for v in METHODS.values()]:self.invoke_frames.append(self.rpc_frame(a,0,3))
  if a in [v[2]for v in METHODS.values()]:self.thunk_frames.append(self.frame(a,5 if a==METHODS['psd'][2]else 4 if a==METHODS['power'][2]else 3))
  if a==0xfffffe000c595a64:self.thread_frames.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'TPIDR_EL1':hex(u.reg_read(ar.UC_ARM64_REG_TPIDR_EL1)),'saved_thread_word_hex':bytes(u.mem_read(THREAD+0x378,8)).hex()})
  if self.c.get('backend_model')and a in [0xfffffe0008cb2d90,0xfffffe0008cb2da0,0xfffffe0008cb2dc0]:
   self.controller_calls.append(self.frame(a,4 if a==0xfffffe0008cb2da0 else 5 if a==0xfffffe0008cb2dc0 else 3))
   if a==0xfffffe0008cb2da0 and self.reg(3):self.effect(self.reg(3),struct.pack('<I',0x12345678),'Declared platform power output; native outcome unknown')
   return self.modeled(a,'declared_platform_backend_model',0)
  return super().code(u,a,n,d)
 def run(self):
  row=super().run();assert len(self.rpc_frames)==1;f=self.rpc_frames[0];row.update(rpc_frames=self.rpc_frames,dispatch_frames=self.dispatch_frames,invoke_frames=self.invoke_frames,thunk_frames=self.thunk_frames,thread_frames=self.thread_frames,source_reply_producer_case=self.c.get('reply_producer'),final_rpc_buffers=[{'address':f['reply_address'],'bytes_hex':bytes(self.u.mem_read(int(f['reply_address'],16),f['reply_capacity'])).hex()}],native_remote_transport_executed=False,runtime_metaclass_hierarchy_established=False);row['final_environment_globals'] +=[{'address':hex(a),'bytes_hex':bytes(self.u.mem_read(a,n)).hex()}for a,n in [(0xfffffe000cc08998,8),(0xfffffe0007f54318,1)]];return row
def main():
 im=Image();src=json.loads((ROOT/(PREFIX+'_source.json')).read_text());origin=json.loads((ROOT/'aes_platform_gate_profiles.json').read_text())['cases'][0];rows=[]
 def run(c):return Probe(im,{'on_thread':1,**c},src,origin,rows[c['reply_producer']]if'reply_producer'in c else None).run()
 for m in METHODS:rows.append(run({'method':m}))
 for m in METHODS:rows.append(run({'method':m,'backend_model':True}))
 rows.append(run({'method':'power','backend_model':True,'null_output':True}))
 for m in METHODS:rows.append(run({'method':m,'custom':True,'transport_result':0xe00002bc}))
 for m in METHODS:rows.append(run({'method':m,'custom':True}))
 for patch in [None,[4,4,61],[0x24,8,0],[0x20,4,1],[0x34,8,1]]:
  c={'method':'clock','custom':True,'reply_producer':3}
  if patch:c['reply_patch']=patch
  rows.append(run(c))
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in [PREFIX+'_source.json','aes_platform_gate_profiles.json','probe_aes_platform_gate.py','probe_aes_hardware_job.py','probe_aes_provider_queue.py','probe_aes_command_pool.py','probe_workloop_gate_attachment.py','probe_aes_command_gate.py','probe_kernel_vm_mig.py','kernel_vm_mig_tools.py']},'cases':rows,'native_target_executed':False,'native_IPC_executed':False,'native_registry_or_platform_effects_executed':False,'native_remote_transport_executed':False,'runtime_device_or_controller_identity_established':False,'runtime_metaclass_hierarchy_established':False,'hardware_PAC_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(len(r['source_visits'])for r in rows),'API_models':sum(len(r['API_models'])for r in rows)}),flush=True)
if __name__=='__main__':main()
