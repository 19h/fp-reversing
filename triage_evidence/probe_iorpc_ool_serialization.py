#!/usr/bin/env python3
"""Original SetProperties/OOL binary emission with explicit lower boundaries.
Collection initialization, VM, references, transport and parser outcomes modeled.
O(visits+effects), O(journals+private RAM); no native VM/IPC/parser operation.
"""
import json,struct
from unicorn import arm64_const as ar
from probe_iorpc_object_conversion import Probe as Parent,P,DEV,SERVER,REQ,CONVERT
from probe_aes_platform_gate import Probe as Collector
from probe_aes_command_gate import Probe as SourceCPU
from probe_kernel_vm_mig import SP,HALT
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
PREFIX='iorpc_ool_serialization';DIC=P+0x70000;PAIRS=P+0x70100;SER=P+0x71000;A0=P+0x72000;A1=P+0x72100;AB0=P+0x73000;AB1=P+0x73800;MD=P+0x74000;MB=P+0x74100;KEY=P+0x75000;KB=P+0x75080;VALUE=P+0x75100;VB=P+0x75180;COPY=P+0x76000;MAPPED=P+0x77000;RESTORED=P+0x7b000;CTX=P+0x7c000;PACKET=P+0x7c100;TEXT=P+0x80000;CUSTOM=P+0xe4000;HANDLER=P+0xe4100;VMCOUNT=0xfffffe000cb5b630;MAPOBJ=P+0x7d000;RPC=0xfffffe000bcf59e0
class Probe(Parent):
 def __init__(self,im,c,src,origin,old,rows):
  super().__init__(im,{'method':'clock'},src,origin,None,old,0);self.c={'on_thread':1,'method':'clock',**c};self.rows=rows;self.arrays=[];self.serial_frames=[];self.vm_frames=[];self.handler_frames=[];self.parser_frames=[];self.serialized=[];self.stage=c['stage'];self.component=True;self.all_objects +=[(DIC,64),(PAIRS,64),(SER,128),(A0,64),(A1,64),(AB0,2048),(AB1,128),(MD,64),(MB,512),(KEY,64),(KB,64),(VALUE,64),(VB,256),(COPY,64),(MAPPED,16384),(RESTORED,64),(CTX,32),(PACKET,256),(TEXT,16384),(MAPOBJ,256)];self.meta={n:int(src['serialization_definitions']['__ZN'+n+'10gMetaClassE'][0]['address'],16)for n in ['11OSSerialize','7OSArray','6OSData','12OSDictionary','8OSSymbol','8OSString']};self.v={n:int(src['serialization_definitions']['__ZTV'+n][0]['address'],16)+16 for n in ['11OSSerialize','7OSArray','12OSDictionary','6OSData','8OSSymbol']};self.targets={(s['class'],s['offset']):int(s['pointer']['target'],16)for s in src['serialization_slots']}
  for n in ['11OSSerialize','7OSArray','6OSData']:
   meta=self.meta[n];v=int(src['serialization_definitions']['__ZTVN'+n+'9MetaClassE'][0]['address'],16)+16;self.image_fixture(meta,struct.pack('<Q',v),'Declared runtime metaclass vptr for factory call')
  for n in ['12OSDictionary','8OSSymbol','8OSString']:
   parent=self.meta['8OSString']if n=='8OSSymbol'else 0;self.image_fixture(self.meta[n]+0x10,struct.pack('<Q',parent),'Declared compatible class hierarchy; native initialization unknown')
  self.image_fixture(VMCOUNT,bytes(8),'Declared private serialized-buffer accounting epoch zero');self.image_fixture(0xfffffe0007f860a8,struct.pack('<Q',MAPOBJ),'Declared runtime kernel_map value; native identity unknown');self.fixture(MAPOBJ,bytes(256))
  for a,n,v in [(DIC,64,self.v['12OSDictionary']),(RESTORED,64,self.v['12OSDictionary']),(KEY,64,self.v['8OSSymbol']),(VALUE,64,self.v['6OSData'])]:self.fixture(a,struct.pack('<QI',v,1)+bytes(n-12))
  payload=bytes((j*37+11)&255 for j in range(c.get('payload_length',0)));self.payload=payload;count=int('payload_length'in c);self.fixture(DIC+0x10,struct.pack('<III',4,count,4));self.fixture(DIC+0x20,struct.pack('<Q',PAIRS));self.fixture(PAIRS,struct.pack('<QQ',KEY,VALUE));self.fixture(KEY+0xc,struct.pack('<I',4<<14));self.fixture(KEY+0x10,struct.pack('<Q',KB));self.fixture(KB,b'key\0');self.fixture(VALUE+0xc,struct.pack('<IIIQ',len(payload),256,256,VB));self.fixture(VB,payload);self.buffer_address=None;self.buffer_capacity=128
  if self.stage in ['build','full']:
   self.entry=0xfffffe000c4a41a8;args=[DEV,0 if c.get('null_dictionary')else DIC,CUSTOM if self.stage=='build'else 0]
  else:
   producer=rows[c['packet_case']];f=producer['rpc_frames'][0]if self.stage=='invoke'else producer['transport_frames'][0];packet=bytes.fromhex(f['packet_hex']);self.fixture(PACKET,packet);self.buffer_address=PACKET;self.fixture(CTX,struct.pack('<QQIIQ',PACKET,PACKET,108,128,PACKET+0x44));self.entry=0xfffffe000c4a3290 if self.stage=='invoke'else CONVERT;args=[CTX,DEV,HANDLER]if self.stage=='invoke'else[SERVER,PACKET,PACKET+0x44,108,1,1];self.entrysp=SP-0x800;self.u.reg_write(ar.UC_ARM64_REG_SP,self.entrysp)
   if self.stage=='inverse':
    self.incoming_bytes=bytes.fromhex(producer['serialization_records'][0]['bytes_hex']);self.fixture(COPY+0x20,struct.pack('<Q',len(self.incoming_bytes)))
  for j,v in enumerate(args):self.set(j,v)
  self.set(30,HALT);self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV))
 def write(self,u,t,a,n,v,d):
  if(a,n)==(VMCOUNT,8):e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'address':hex(a),'size_bytes':n};self.writes.append(e);self.pending.append(e);return
  return super().write(u,t,a,n,v,d)
 def bytestring(self,a):
  out=bytearray()
  for j in range(4096):
   self.ensure(a+j);v=self.u.mem_read(a+j,1)[0]
   if v==0:return bytes(out)
   out.append(v)
  raise AssertionError('unterminated private/source string')
 def code(self,u,a,n,d):
  self.flush()
  if a==CUSTOM:
   f=self.rpc_frame(a,1,2);self.rpc_frames.append(f);self.buffer_address=int(f['message_address'],16);return self.stop('after_registration_component')
  if a==0xfffffe000c5957d4:self.buffer_address=int.from_bytes(bytes(u.mem_read(self.reg(1),8)),'little')
  if a==0xfffffe000c4a3290:self.invoke_frames.append(self.rpc_frame(a,0,3))
  if a==HANDLER:self.handler_frames.append(self.frame(a,2));return self.modeled(a,'declared_SetProperties_handler_result',0)
  if a in [0xfffffe000c488ca0,0xfffffe000c47d014,0xfffffe000c47d618,0xfffffe000c489088,0xfffffe000c488ed0]:self.serial_frames.append(self.frame(a,6 if a==0xfffffe000c488ed0 else 4 if a==0xfffffe000c488ca0 else 2))
  factories={self.targets[('__ZTVN11OSSerialize9MetaClassE',0xa8)]:(SER,self.v['11OSSerialize'],128),self.targets[('__ZTVN7OSArray9MetaClassE',0xa8)]:((A0 if not self.arrays else A1),self.v['7OSArray'],64),self.targets[('__ZTVN6OSData9MetaClassE',0xa8)]:(MD,self.v['6OSData'],64)}
  if a in factories:
   if a==self.targets[('__ZTVN6OSData9MetaClassE',0xa8)]and self.c.get('no_index_data'):return self.modeled(a,'declared_optional_index_allocation_NULL',0)
   dest,v,size=factories[a]
   if dest in [A0,A1]:self.arrays.append(dest)
   self.effect(dest,struct.pack('<QI',v,1)+bytes(size-12),'Declared nominal collection allocation, native constructor unexecuted');return self.modeled(a,'declared_serializer_collection_allocation',dest)
  if a==self.targets[('__ZTV7OSArray',0x1d0)]:
   dest=self.reg(0);capacity=self.reg(1);self.effect(dest+0x10,struct.pack('<IIIIQ',capacity,0,capacity,0,AB0 if dest==A0 else AB1),'Declared initialized memo-array storage');return self.modeled(a,'declared_memo_array_initialization',1)
  if a==self.targets[('__ZTV6OSData',0x138)]and self.reg(0)==MD:self.effect(MD+0xc,struct.pack('<IIIQQ',0,256,256,MB,0),'Declared initialized serializer index buffer');return self.modeled(a,'declared_index_data_initialization',1)
  if a==0xfffffe000bdc08e0:
   self.vm_frames.append(self.frame(a,6));self.modeled(a,'declared_serializer_VM_allocation',0);self.set(1,TEXT);self.models[-1]['after_registers31'][1]=hex(TEXT);self.models[-1]['return_register_X1']=hex(TEXT);return
  if a==0xfffffe000c647f10:
   dest,source,size=[self.reg(j)for j in range(3)];assert P<=dest<=dest+size<=P+0x100000
   if size:self.ensure(source,size);self.effect(dest,bytes(u.mem_read(source,size)),'Declared standard memcpy/memmove byte effects')
   return self.modeled(a,'declared_private_memory_copy',dest)
  if a==0xfffffe000c66051c:
   left,right=self.bytestring(self.reg(0)),self.bytestring(self.reg(1));return self.modeled(a,'declared_strcmp_result',0 if left==right else 1)
  if a in [0xfffffe000c445200,0xfffffe000c4451d0,0xfffffe000c444fa8,self.targets[('__ZTV12OSDictionary',0x50)],self.targets[('__ZTV8OSSymbol',0x48)],self.targets[('__ZTV8OSSymbol',0x50)]]and self.reg(0)in [DIC,KEY,VALUE,SER,A0,A1,MD,RESTORED]:self.object_refs.append(self.frame(a,2 if a in [0xfffffe000c444fa8,self.targets[('__ZTV12OSDictionary',0x50)],self.targets[('__ZTV8OSSymbol',0x48)],self.targets[('__ZTV8OSSymbol',0x50)]]else 1));return self.modeled(a,'declared_serialized_object_reference',0)
  if a==0xfffffe000bdd15a4:
   e=self.frame(a,5);e['bytes_hex']=bytes(u.mem_read(self.reg(1),self.reg(2))).hex();self.serialized.append(e);self.vm_frames.append(self.frame(a,5));self.effect(COPY+0x20,struct.pack('<Q',self.reg(2)),'Declared VM-copy extent');self.effect(self.reg(4),struct.pack('<Q',COPY),'Declared VM-copy result');return self.modeled(a,'declared_serialized_VM_copyin',0)
  if a==RPC:
   e=self.frame(a,6);e['packet_hex']=bytes(u.mem_read(self.reg(0),128)).hex();self.transport_frames.append(e)
   if self.c.get('frontier'):return self.stop('after_registration_component')
   result=self.c.get('transport_result',0);self.effect(self.reg(5),struct.pack('<I',self.c.get('message_moved',1 if result==0 else 0)),'Declared transport ownership signal')
   if not result:self.effect(self.reg(0),bytes.fromhex(self.rows[1]['final_rpc_buffers'][0]['bytes_hex']),'Exact source-produced SetProperties adapter reply')
   return self.modeled(a,'declared_SetProperties_transport',result)
  if a==0xfffffe000bdcb374:self.vm_frames.append(self.frame(a,5));self.effect(self.reg(1),struct.pack('<Q',MAPPED),'Declared copied-out address');self.effect(MAPPED,self.incoming_bytes,'Exact emitted bytes supplied to mapped consumer');return self.modeled(a,'declared_serialized_VM_copyout',0)
  if a==0xfffffe000c488964:self.parser_frames.append(self.frame(a,6))
  if a==0xfffffe000c489b18:
   e=self.frame(a,6);e['bytes_hex']=bytes(u.mem_read(self.reg(0),self.reg(1))).hex();self.parser_frames.append(e)
   if self.c.get('parser_frontier'):return self.stop('after_registration_component')
   return self.modeled(a,'declared_binary_parser_object',RESTORED)
  if a==0xfffffe000bdc1ec0:self.vm_frames.append(self.frame(a,3));return self.modeled(a,'declared_serialized_mapping_deallocation',0)
  return super().code(u,a,n,d)
 def run(self):
  row=Collector.run(self);row.update(source_producer_case=None,external_source_producer={'path':'iorpc_object_conversion_profiles.json','case':0},entry_SP=hex(self.entrysp),rpc_frames=self.rpc_frames,dispatch_frames=self.dispatch_frames,invoke_frames=self.invoke_frames,thunk_frames=self.thunk_frames,thread_frames=self.thread_frames,remote_frames=self.remote_frames,queue_lookup_frames=self.lookup_frames,port_copy_frames=self.copy_frames,conversion_frames=self.conversion_frames,transport_frames=self.transport_frames,release_frames=self.release_frames,reply_cleanup_frames=self.cleanup_frames,object_conversion_frames=self.object_frames,object_reference_frames=self.object_refs,port_lock_frames=self.lock_frames,object_allocation_frames=self.alloc_frames,new_IOMachPort_nodes=self.new_nodes,serialization_frames=self.serial_frames,serialization_records=self.serialized,serialization_VM_frames=self.vm_frames,SetProperties_handler_frames=self.handler_frames,serialization_parser_frames=self.parser_frames,final_rpc_buffers=[{'address':hex(self.buffer_address),'bytes_hex':bytes(self.u.mem_read(self.buffer_address,128)).hex()}],final_registry_globals=[{'address':hex(a),'bytes_hex':bytes(self.u.mem_read(a,n)).hex()}for a,n in [(0xfffffe000cba3ab8,8),(0xfffffe000cb0bc50,4),(0xfffffe000cb53450,40),(0xfffffe000cb53478,32768),(0xfffffe0007f50418,8),(0xfffffe0007e5ca50,8)]],final_serialization_globals=[{'address':hex(a),'bytes_hex':bytes(self.u.mem_read(a,n)).hex()}for a,n in [(VMCOUNT,8),(0xfffffe0007f860a8,8)]],external_actor_producer={'path':'iorpc_object_conversion_profiles.json','case':0},native_remote_transport_executed=False,native_port_objects_observed=False,native_object_port_registry_effects_executed=False,runtime_metaclass_hierarchy_established=False,native_serialized_VM_or_parser_effects_executed=False)
  if self.c.get('frontier'):row['boundary']['kind']='before_kernel_transport_body'
  elif self.c.get('parser_frontier'):row['boundary']['kind']='before_binary_parser_body'
  elif self.stage=='build':row['boundary']['kind']='before_custom_dispatch'
  return row
def main():
 im=Image();src=json.loads((ROOT/(PREFIX+'_source.json')).read_text());origin=json.loads((ROOT/'iorpc_object_conversion_profiles.json').read_text())['cases'][0];old=json.loads((ROOT/'platform_iorpc_profiles.json').read_text())['cases'];rows=[]
 def run(c):return Probe(im,c,src,origin,old,rows).run()
 configs=[{'stage':'build'},{'stage':'invoke','packet_case':0},{'stage':'full','frontier':True},{'stage':'full'}]+[{'stage':'full','payload_length':n,'frontier':True}for n in [0,1,3,4,5]]+[{'stage':'full','payload_length':32},{'stage':'full','null_dictionary':True,'frontier':True},{'stage':'full','payload_length':5,'transport_result':0x10000003},{'stage':'full','payload_length':5,'transport_result':0x10000003,'message_moved':1},{'stage':'inverse','packet_case':8},{'stage':'inverse','packet_case':8,'parser_frontier':True},{'stage':'inverse','packet_case':4},{'stage':'full','no_index_data':True,'frontier':True},{'stage':'full','no_index_data':True,'payload_length':5,'frontier':True},{'stage':'inverse','packet_case':17},{'stage':'inverse','packet_case':17,'parser_frontier':True}]
 for c in configs:
  r=run(c);rows.append(r);print(json.dumps({'case':len(rows)-1,'boundary':r['boundary']['kind'],'PC':r['boundary']['pc'],'visits':len(r['source_visits'])}),flush=True)
 flags=['native_target_executed','native_IPC_executed','native_registry_or_platform_effects_executed','native_remote_transport_executed','native_port_objects_observed','native_object_port_registry_effects_executed','native_serialized_VM_or_parser_effects_executed','runtime_device_or_controller_identity_established','runtime_metaclass_hierarchy_established','hardware_PAC_executed','idb_mutated','full_goal_complete'];out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in [PREFIX+'_source.json','iorpc_object_conversion_profiles.json','platform_iorpc_profiles.json','probe_iorpc_object_conversion.py','probe_iorpc_remote.py','probe_platform_iorpc.py','probe_aes_platform_gate.py','probe_aes_hardware_job.py','probe_aes_provider_queue.py','probe_aes_command_pool.py','probe_workloop_gate_attachment.py','probe_aes_command_gate.py','probe_kernel_vm_mig.py','kernel_vm_mig_tools.py']},'cases':rows,**{k:False for k in flags}};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
