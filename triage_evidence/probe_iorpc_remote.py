#!/usr/bin/env python3
"""Original conditional service-to-server remote IORPC and declared transport.
Hierarchy/queue/port/conversion/reference/transport outcomes are premises.
O(visits+effects), O(journals+private RAM); no native Mach or port effects.
"""
import json,struct
from unicorn import arm64_const as ar
from probe_platform_iorpc import Probe as Parent,P,DEV,THREAD,OUT,METHODS
from probe_kernel_vm_mig import SP,HALT
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
PREFIX='iorpc_remote';EXP=P+0x60000;LINK=P+0x61000;SERVER=P+0x62000;QUEUE=P+0x63000;QDATA=P+0x64000;PORT=P+0x65000;REMOTE=0xfffffe000c595bf8;LOOKUP=0xfffffe000c596070;COPY=0xfffffe000bcd00bc;REQ=0xfffffe000c5962c0;CONVERT=0xfffffe000c5968d8;CLEANUP=0xfffffe000c596d64;RPC=0xfffffe000bcf59e0;SEND=0xfffffe000bcf55dc;RELEASE=0xfffffe000bcd0448
class Probe(Parent):
 def __init__(self,im,c,src,origin,request_producer,reply_producer):
  super().__init__(im,{'method':c['method'],'on_thread':1},src,origin);self.c=c;self.request_producer=request_producer;self.remote_reply_producer=reply_producer;self.remote_frames=[];self.lookup_frames=[];self.copy_frames=[];self.conversion_frames=[];self.transport_frames=[];self.release_frames=[];self.cleanup_frames=[];self.all_objects +=[(EXP,0x80),(LINK,0x80),(SERVER,0x200),(QUEUE,0x80),(QDATA,0x80),(PORT,0x100)]
  self.fixture(DEV+0x28,struct.pack('<Q',EXP));self.fixture(EXP+0x28,struct.pack('<Q',LINK));self.fixture(LINK,struct.pack('<Q',SERVER));self.fixture(SERVER,struct.pack('<Q',0xfffffe0007f56050));self.fixture(SERVER+0x48,struct.pack('<I',c.get('server_state',0)));self.fixture(SERVER+0xf8,struct.pack('<Q',0 if c.get('no_fallback')else QUEUE));self.fixture(QUEUE,struct.pack('<Q',0xfffffe0007f354a8));self.fixture(QUEUE+0x10,struct.pack('<Q',QDATA));self.fixture(QDATA+0x28,struct.pack('<Q',PORT))
  for a,b,why in [(0xfffffe000cc08998,struct.pack('<Q',0xfffffe000cb5c060),'Declared IOService ancestor shortcut; native initialized hierarchy unknown'),(0xfffffe000cb5c070,bytes(8),'Declared terminating IOService ancestry')]:self.ensure(a,8);self.u.mem_write(a,b);self.image_initial.append({'address':hex(a),'bytes_hex':b.hex(),'provenance':why})
  self.entrysp=SP
  if c.get('oneway_component'):
   f=request_producer['rpc_frames'][0];packet=bytearray.fromhex(f['packet_hex']);struct.pack_into('<Q',packet,0x3c,0x8d);self.fixture(int(f['rpc_address'],16),bytes.fromhex(f['rpc32_hex']));self.fixture(int(f['message_address'],16),bytes(packet));self.entry=REMOTE;self.set(0,SERVER);self.set(1,int(f['rpc_address'],16));self.entrysp=SP-0x800;self.u.reg_write(ar.UC_ARM64_REG_SP,self.entrysp)
  self.set(30,HALT);self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV))
 def code(self,u,a,n,d):
  self.flush()
  if a==REMOTE:
   if self.c.get('oneway_component'):self.rpc_frames.append(self.rpc_frame(a,1,2))
   self.remote_frames.append(self.rpc_frame(a,1,2))
  if a==LOOKUP:self.lookup_frames.append(self.frame(a,3));return self.modeled(a,'declared_queue_lookup_model',0 if self.c.get('lookup_NULL')else QUEUE)
  if a==COPY:self.copy_frames.append(self.frame(a,1));return self.modeled(a,'declared_port_reference_copy_model',0 if self.c.get('port_NULL')else PORT)
  if a==REQ:self.conversion_frames.append(self.frame(a,6));return self.modeled(a,'declared_request_object_conversion_model',0)
  if a==CONVERT:self.conversion_frames.append(self.frame(a,6));return self.modeled(a,'declared_reply_or_cleanup_conversion_model',self.c.get('reply_conversion_result',0)if self.reg(4)==1 else 0)
  if a==CLEANUP:self.cleanup_frames.append(self.frame(a,4));return self.modeled(a,'declared_reply_cleanup_model',0)
  if a in [RPC,SEND]:
   e=self.frame(a,6 if a==RPC else 5);e['packet_hex']=bytes(u.mem_read(self.reg(0),self.rpc_frames[0]['reply_capacity'])).hex();self.transport_frames.append(e)
   if self.c.get('frontier'):return self.stop('after_registration_component')
   result=self.c.get('transport_result',0);moved=self.c.get('message_moved',1 if result==0 else 0);self.effect(self.reg(5 if a==RPC else 4),struct.pack('<I',moved),'Declared message_moved output; native ownership transfer unproved')
   if a==RPC and result==0:
    packet=bytearray.fromhex(self.remote_reply_producer['final_rpc_buffers'][0]['bytes_hex'])
    if self.c.get('remote_error'):struct.pack_into('<I',packet,4,68);struct.pack_into('<Q',packet,0x2c,0x48);struct.pack_into('<I',packet,0x3c,0xe00002bc)
    self.effect(self.reg(0),bytes(packet),'Declared source-produced kernel reply; optional explicit remote-error record substitution')
   return self.modeled(a,'declared_kernel_transport_model',result)
  if a==RELEASE:self.release_frames.append(self.frame(a,1));return self.modeled(a,'declared_port_send_release_model',0)
  if a in [0xfffffe000c445200,0xfffffe000c4451d0]and self.reg(0)==QUEUE:
   self.release_frames.append(self.frame(a,1));return self.modeled(a,'declared_queue_retain_model'if a==0xfffffe000c445200 else'declared_queue_release_model',0)
  return super().code(u,a,n,d)
 def run(self):
  row=super().run();row['entry_SP']=hex(self.entrysp)
  if self.c.get('frontier'):row['boundary']['kind']='before_kernel_transport_body'
  row.update(remote_frames=self.remote_frames,queue_lookup_frames=self.lookup_frames,port_copy_frames=self.copy_frames,conversion_frames=self.conversion_frames,transport_frames=self.transport_frames,release_frames=self.release_frames,reply_cleanup_frames=self.cleanup_frames,external_request_packet_producer={'path':'platform_iorpc_profiles.json','case':{'clock':0,'power':1,'psd':2}[self.c['method']]}if self.c.get('oneway_component')else None,external_reply_packet_producer={'path':'platform_iorpc_profiles.json','case':{'clock':3,'power':4,'psd':5}[self.c['method']]},native_port_objects_observed=False);row['final_environment_globals'].append({'address':'0xfffffe000cb5c070','bytes_hex':bytes(self.u.mem_read(0xfffffe000cb5c070,8)).hex()});return row
def main():
 im=Image();src=json.loads((ROOT/(PREFIX+'_source.json')).read_text());origin=json.loads((ROOT/'aes_platform_gate_profiles.json').read_text())['cases'][0];old=json.loads((ROOT/'platform_iorpc_profiles.json').read_text())['cases'];rows=[]
 def run(c):
  j={'clock':0,'power':1,'psd':2}[c['method']];return Probe(im,{'on_thread':1,**c},src,origin,old[j],old[j+3]).run()
 for m in METHODS:rows.append(run({'method':m,'frontier':True}))
 for m in METHODS:rows.append(run({'method':m}))
 for c in [{'transport_result':0x10000003},{'transport_result':0x10000003,'message_moved':1},{'lookup_NULL':True,'frontier':True},{'lookup_NULL':True,'no_fallback':True},{'server_state':1,'no_fallback':True},{'port_NULL':True},{'remote_error':True},{'reply_conversion_result':1},{'oneway_component':True},{'oneway_component':True,'transport_result':0x10000003}]:rows.append(run({'method':'clock',**c}))
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in [PREFIX+'_source.json','platform_iorpc_profiles.json','aes_platform_gate_profiles.json','probe_platform_iorpc.py','probe_aes_platform_gate.py','probe_aes_hardware_job.py','probe_aes_provider_queue.py','probe_aes_command_pool.py','probe_workloop_gate_attachment.py','probe_aes_command_gate.py','probe_kernel_vm_mig.py','kernel_vm_mig_tools.py']},'cases':rows,'native_target_executed':False,'native_IPC_executed':False,'native_registry_or_platform_effects_executed':False,'native_remote_transport_executed':False,'native_port_objects_observed':False,'runtime_device_or_controller_identity_established':False,'runtime_metaclass_hierarchy_established':False,'hardware_PAC_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(len(r['source_visits'])for r in rows),'API_models':sum(len(r['API_models'])for r in rows)}),flush=True)
if __name__=='__main__':main()
