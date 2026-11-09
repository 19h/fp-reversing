#!/usr/bin/env python3
"""Source converters, IOMachPort miss/hit and private port counter path.
Allocation/locks/object references/port creation/transport remain premises.
O(visits+effects), O(journals+private RAM); no native port or IPC effects.
"""
import json,struct
from unicorn import arm64_const as ar
from probe_iorpc_remote import Probe as Parent,P,DEV,THREAD,SERVER,PORT,REQ,CONVERT
from probe_aes_platform_gate import Probe as Collector
from probe_aes_command_gate import Probe as SourceCPU
from probe_kernel_vm_mig import SP,HALT
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
PREFIX='iorpc_object_conversion';OPORT=P+0x66000;NODE=P+0x67000;LOCK=P+0x68000;AUX=P+0x69000;ZONE=P+0x6a000;BUFFER=P+0x6b000;DECOY=P+0x6c000;GET=0xfffffe000c56114c;NEW=0xfffffe000c561300;ASSOC=0xfffffe000bcf4fa0;RESOLVE=0xfffffe000be351d0;MAKE=0xfffffe000bccfc94;BUCKETS=0xfffffe000cb53478;META=0xfffffe000cb53450;COUNTER=0xfffffe000cb5b638;LOCKCELL=0xfffffe000cba3ab8;HINT=0xfffffe000cb0bc50;AUXCELL=0xfffffe0007e5ca50
def bucket(a):
 x=((a>>4)*0x5052acdb)&0xffffffff;return(x^int.from_bytes(x.to_bytes(4,'little'),'big'))&0xfff
DECOY_OBJECT=next(a for a in range(P+0x70000,P+0xd0000,16)if bucket(a)==bucket(DEV))
def port_bytes():
 b=bytearray(256);b[0:2]=bytes([0x29,1]);struct.pack_into('<I',b,4,1);struct.pack_into('<Q',b,0x50,NODE);return bytes(b)
class Probe(Parent):
 def __init__(self,im,c,src,origin,packet_origin,old,producer=None):
  super().__init__(im,{'on_thread':1,'method':c.get('method','clock'),**c},src,origin,old[0],old[{'clock':3,'power':4,'psd':5}[c.get('method','clock')]]);self.c={'on_thread':1,'method':'clock',**c};self.original_producer=producer;self.packet_origin=packet_origin;self.object_frames=[];self.object_refs=[];self.lock_frames=[];self.alloc_frames=[];self.new_nodes=[];self.all_objects=[(a,0x600 if a==THREAD else n)for a,n in self.all_objects]+[(OPORT,256),(NODE,40),(LOCK,64),(AUX,16),(ZONE,16),(BUFFER,256),(DECOY,40)]
  if producer is None:
   for a,b in [(OPORT,port_bytes()),(NODE,b'\x5a'*40),(LOCK,bytes(64)),(AUX,b'\xa5'*16),(ZONE,struct.pack('<QQ',P+0x6a100,0)),(DECOY,bytes(40))]:self.fixture(a,b)
  self.fixture(THREAD+0x518,struct.pack('<I',0x1234));self.fixture(BUFFER,bytes(256));table=bytearray(32768)
  for a,b in [(LOCKCELL,struct.pack('<Q',LOCK)),(HINT,bytes(4)),(META,bytes(40)),(BUCKETS,bytes(table)),(0xfffffe0007f50418,bytes(8)),(AUXCELL,struct.pack('<Q',ZONE))]:self.image_fixture(a,b,'Declared private registry/zone epoch; native initialization unknown')
  if producer is not None:
   for e in origin['final_registry_globals']:self.image_fixture(int(e['address'],16),bytes.fromhex(e['bytes_hex']),'Exact source-produced registry epoch transfer')
  if c.get('collision'):
   b=bytearray(40);struct.pack_into('<QQ',b,0x10,NODE,0);struct.pack_into('<Q',b,0x20,DECOY_OBJECT);self.fixture(DECOY,bytes(b));self.image_fixture(BUCKETS+8*bucket(DEV),struct.pack('<Q',DECOY),'Declared collision node preceding source-created node')
  stage=c.get('stage','remote');self.component=stage!='remote'
  if self.component:
   packet=bytearray.fromhex(packet_origin['transport_frames'][0]['packet_hex']if stage=='restore'else old[0]['rpc_frames'][0]['packet_hex']);self.buffer_size=len(packet);self.content=BUFFER+0x34
   if c.get('null_object'):struct.pack_into('<Q',packet,0x4c,0)
   self.fixture(BUFFER,bytes(packet));self.entry=CONVERT if stage=='restore'else REQ;args=[SERVER,BUFFER,self.content,92,c.get('restore',0)if stage=='restore'else c.get('consume',0),c.get('release',0)if stage=='restore'else P+0x6a008]
   for j,v in enumerate(args):self.set(j,v)
   self.entrysp=SP-0x800;self.u.reg_write(ar.UC_ARM64_REG_SP,self.entrysp)
  self.set(30,HALT);self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV))
 def image_fixture(self,a,b,why):self.ensure(a,len(b));self.u.mem_write(a,b);self.image_initial.append({'address':hex(a),'bytes_hex':b.hex(),'provenance':why})
 def write(self,u,t,a,n,v,d):
  if(a,n)in [(META+0x24,4),(BUCKETS+8*bucket(DEV),8)]:
   e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'address':hex(a),'size_bytes':n};self.writes.append(e);self.pending.append(e);return
  return super().write(u,t,a,n,v,d)
 def code(self,u,a,n,d):
  self.flush()
  if a in [REQ,CONVERT]:
   e=self.frame(a,6);e['packet_hex']=bytes(u.mem_read(self.reg(1),128 if self.component else self.rpc_frames[0]['reply_capacity'])).hex();self.conversion_frames.append(e);return SourceCPU.code(self,u,a,n,d)
  if a in [GET,NEW,ASSOC,RESOLVE,MAKE,0xfffffe000be35a54,0xfffffe000c49f41c]:
   self.object_frames.append(self.frame(a,2 if a in [GET,RESOLVE,0xfffffe000be35a54,0xfffffe000c49f41c]else 3 if a==ASSOC else 1))
   if a==GET and self.c.get('object_port_NULL'):return self.modeled(a,'declared_object_port_NULL_model',0)
  if a==0xfffffe000bcfe5b8:
   assert[self.reg(j)for j in [1,2]]==[40,0x41004];self.alloc_frames.append(self.frame(a,4));self.new_nodes.append(hex(NODE));self.effect(NODE,bytes(40),'Declared zeroed 40-byte IOMachPort allocation');return self.modeled(a,'declared_IOMachPort_allocation_model',NODE)
  if a==0xfffffe000bd75c64:self.alloc_frames.append(self.frame(a,3));assert self.reg(2)==0x8004;return self.modeled(a,'declared_port_aux_allocation_model',AUX)
  if a==0xfffffe000bcf4a5c:
   self.alloc_frames.append(self.frame(a,4));assert[self.reg(j)for j in range(4)]==[NODE,0x129,AUX,0];self.effect(OPORT,port_bytes(),'Declared active type-0x29 port with IOMachPort backlink; native constructor unexecuted');return self.modeled(a,'declared_typed_port_creation_model',OPORT)
  if a in [0xfffffe000bccc128,0xfffffe000bd0ab18]:self.lock_frames.append(self.frame(a,1));return self.modeled(a,'declared_port_lock_no_effect_model'if a==0xfffffe000bccc128 else'declared_port_unlock_no_effect_model',0)
  if a in [0xfffffe000c445200,0xfffffe000c4451d0,0xfffffe000c444fa8]and self.reg(0)in [NODE,DEV]:
   self.object_refs.append(self.frame(a,2 if a==0xfffffe000c444fa8 else 1));return self.modeled(a,'declared_object_reference_no_effect_model',0)
  return super().code(u,a,n,d)
 def run(self):
  if not self.component:row=super().run()
  else:
   row=Collector.run(self);row.update(rpc_frames=[],dispatch_frames=[],invoke_frames=[],thunk_frames=[],thread_frames=[],final_rpc_buffers=[{'address':hex(BUFFER),'bytes_hex':bytes(self.u.mem_read(BUFFER,self.buffer_size)).hex()}],remote_frames=[],queue_lookup_frames=[],port_copy_frames=[],conversion_frames=self.conversion_frames,transport_frames=[],release_frames=self.release_frames,reply_cleanup_frames=[],native_remote_transport_executed=False,runtime_metaclass_hierarchy_established=False);row['final_environment_globals'] +=[{'address':hex(a),'bytes_hex':bytes(self.u.mem_read(a,n)).hex()}for a,n in [(0xfffffe000cc08998,8),(0xfffffe0007f54318,1),(0xfffffe000cb5c070,8)]]
  row.update(source_producer_case=self.original_producer,external_source_producer=None if self.original_producer is not None else {'path':'aes_platform_gate_profiles.json','case':0},entry_SP=hex(self.entrysp),object_conversion_frames=self.object_frames,object_reference_frames=self.object_refs,port_lock_frames=self.lock_frames,object_allocation_frames=self.alloc_frames,new_IOMachPort_nodes=self.new_nodes,registry_producer_case=self.original_producer,packet_producer_case=self.c.get('packet_case'),final_registry_globals=[{'address':hex(a),'bytes_hex':bytes(self.u.mem_read(a,n)).hex()}for a,n in [(LOCKCELL,8),(HINT,4),(META,40),(BUCKETS,32768),(0xfffffe0007f50418,8),(AUXCELL,8)]],native_port_objects_observed=False,native_object_port_registry_effects_executed=False)
  return row
def main():
 im=Image();src=json.loads((ROOT/(PREFIX+'_source.json')).read_text());base=json.loads((ROOT/'aes_platform_gate_profiles.json').read_text())['cases'][0];old=json.loads((ROOT/'platform_iorpc_profiles.json').read_text())['cases'];rows=[]
 def run(c,producer=None):return Probe(im,c,src,base if producer is None else rows[producer],rows[c['packet_case']]if'packet_case'in c else None,old,producer).run()
 rows.append(run({'method':'clock'}));rows.append(run({'method':'clock'},0));rows.append(run({'method':'power'},0));rows.append(run({'method':'psd'},0));rows.append(run({'method':'clock','frontier':True},0));rows.append(run({'method':'clock','transport_result':0x10000003},0));rows.append(run({'method':'clock','transport_result':0x10000003,'message_moved':1},0));rows.append(run({'method':'clock','remote_error':True},0));rows.append(run({'stage':'export','consume':1},0));rows.append(run({'stage':'export','null_object':True},0))
 for restore,release in [(1,1),(1,0),(0,1),(0,0)]:rows.append(run({'stage':'restore','restore':restore,'release':release,'packet_case':4},4))
 rows.append(run({'method':'clock','collision':True},0));rows.append(run({'stage':'export','object_port_NULL':True},0))
 flags=['native_target_executed','native_IPC_executed','native_registry_or_platform_effects_executed','native_remote_transport_executed','native_port_objects_observed','native_object_port_registry_effects_executed','runtime_device_or_controller_identity_established','runtime_metaclass_hierarchy_established','hardware_PAC_executed','idb_mutated','full_goal_complete']
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in [PREFIX+'_source.json','aes_platform_gate_profiles.json','platform_iorpc_profiles.json','probe_iorpc_remote.py','probe_platform_iorpc.py','probe_aes_platform_gate.py','probe_aes_hardware_job.py','probe_aes_provider_queue.py','probe_aes_command_pool.py','probe_workloop_gate_attachment.py','probe_aes_command_gate.py','probe_kernel_vm_mig.py','kernel_vm_mig_tools.py']},'cases':rows,**{k:False for k in flags}};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(len(r['source_visits'])for r in rows),'API_models':sum(len(r['API_models'])for r in rows)}),flush=True)
if __name__=='__main__':main()
