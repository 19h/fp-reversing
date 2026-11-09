#!/usr/bin/env python3
"""Original typed property/cast and device/controller wrapper components.
Registry objects, gate tables, class metadata, tracing and PAC are premises.
O(visits+effects), O(journals+private RAM); no native registry/platform operations.
"""
import json,struct,hashlib
from unicorn import arm64_const as ar
from probe_aes_hardware_job import Probe as Parent,P,PROV
from probe_kernel_vm_mig import SP,HALT
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
PREFIX='aes_platform_gate';DEV=P+0x2a000;DATA=P+0x2b000;STRING=P+0x2b100;CLOCKS=P+0x2c000;POWERS=P+0x2c100;SERVICES=P+0x2c200;CTRL=P+0x2d000;CONTEXT=P+0x2e000;GDEBUG=0xfffffe000caac518;KDEBUG=0xfffffe000cb5c400
class Probe(Parent):
 def __init__(self,im,c,src,origin,producer,external=None):
  super().__init__(im,{'stage':'lease','on_thread':1},src,origin,producer,external);self.c=c;self.end=None;self.casts=[];self.properties=[];self.device_calls=[];self.controller_calls=[];self.clock_returns=[];self.traces=[];self.device_enable=[];self.aes_enable=[];self.all_objects=[(a,0xa00 if a==PROV else n)for a,n in self.all_objects]+[(DEV,0x100),(DATA,0x80),(STRING,0x80),(CLOCKS,16),(POWERS,16),(SERVICES,16),(CTRL,0x100),(CONTEXT,16)];self.allowed +=[(int(s['start'],16),int(s['end'],16))for s in src['platform_stubs']]
  self.fixture(DEV,struct.pack('<Q',0xfffffe0007ff24e0));self.fixture(CTRL,struct.pack('<Q',0xfffffe0007ff1a68));self.fixture(DATA,struct.pack('<Q',0xfffffe0007f31568)+bytes([c.get('data_tail_byte',0)])*120);self.fixture(STRING,struct.pack('<Q',0xfffffe0007f34760))
  for a,b in [(DEV+0x88,struct.pack('<Q',CTRL)),(DEV+0xa0,struct.pack('<I',c.get('clock_count',1))),(DEV+0xa8,struct.pack('<Q',CLOCKS)),(DEV+0xb0,struct.pack('<I',1)),(DEV+0xb8,struct.pack('<Q',POWERS)),(DEV+0xd0,struct.pack('<Q',SERVICES)),(DEV+0xd8,struct.pack('<I',c.get('service_count',1))),(DEV+0xf0,struct.pack('<Q',CONTEXT)),(CLOCKS,struct.pack('<I',0x123)),(POWERS,struct.pack('<I',0x456)),(SERVICES,struct.pack('<I',0xa0000789)),(CONTEXT,b'gate-fixture\0')]:self.fixture(a,b)
  for name in ['data','string']:
   a=int(src['metaclasses'][name],16)+0x10;self.ensure(a,8);self.u.mem_write(a,bytes(8));self.image_initial.append({'address':hex(a),'bytes_hex':'00'*8,'provenance':'Declared terminating superclass link; native hierarchy initialization unknown'})
  self.ensure(GDEBUG,8);self.ensure(KDEBUG,4)
  if c.get('trace_enabled'):
   for a,b in [(GDEBUG+1,b'\x04'),(KDEBUG,struct.pack('<I',1))]:self.ensure(a,len(b));self.u.mem_write(a,b);self.image_initial.append({'address':hex(a),'bytes_hex':b.hex(),'provenance':'Declared tracing predicate inputs; native values unknown'})
  stage=c['stage']
  if stage=='provider_cast':self.entry=0xfffffe0009d4eb10;self.end=0xfffffe0009d4eb2c;self.set(19,DATA if c.get('wrong_type')else DEV);self.set(20,PROV)
  elif stage=='capability':
   self.entry=0xfffffe0009d4ef54;self.end=0xfffffe0009d4ef90;self.set(19,DEV);self.set(20,PROV);self.set(22,int(src['metaclasses']['data'],16));self.set(23,DEV|(0xcda1<<48))
  elif stage=='device':self.entry=0xfffffe0009d4f650;self.set(0,PROV);self.set(1,c['enable'])
  else:assert stage=='AES_enable';self.entry=0xfffffe0009d4f964;self.set(0,PROV);self.set(1,1);self.fixture(PROV+0x1f8,b'\0')
  self.set(30,HALT);self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV))
 def frame(self,a,n):return {'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments':[hex(self.reg(j))for j in range(n)]}
 def code(self,u,a,n,d):
  self.flush()
  if a==0xfffffe000c442080:self.casts.append(self.frame(a,2))
  if a==0xfffffe000c4c79ec:
   self.ensure(self.reg(1),14);e=self.frame(a,2);e['key14_hex']=bytes(u.mem_read(self.reg(1),14)).hex();self.properties.append(e);value={'absent':0,'data':DATA,'string':STRING}[self.c['property_kind']];return self.modeled(a,'declared_registry_property_model',value)
  if a==0xfffffe0009d4f650:self.device_enable.append(self.frame(a,2))
  if a==0xfffffe0009d4f964:self.aes_enable.append(self.frame(a,2))
  if a in [0xfffffe0008cb39b8,0xfffffe0008cb3ac8,0xfffffe0008cb3894]:self.device_calls.append(self.frame(a,{0xfffffe0008cb39b8:3,0xfffffe0008cb3ac8:4,0xfffffe0008cb3894:5}[a]))
  if a in [0xfffffe0008cb2d90,0xfffffe0008cb2da0,0xfffffe0008cb2dc0]:self.controller_calls.append(self.frame(a,{0xfffffe0008cb2d90:3,0xfffffe0008cb2da0:4,0xfffffe0008cb2dc0:5}[a]))
  if a==0xfffffe0009d4f6f4:self.clock_returns.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'raw_X0':hex(self.reg(0))})
  if a==self.trace_target:self.traces.append(self.frame(a,6));return self.modeled(a,'kernel_trace_no_effect_model',0)
  if a==0xfffffe0009d4fa20:return self.stop('before_activation_register_base')
  return super().code(u,a,n,d)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=50000);self.flush();assert self.reason in ['after_registration_component','returned','before_activation_register_base'],self.boundary
  env=[(GDEBUG,8),(KDEBUG,4),*[(int(self.src['metaclasses'][name],16)+0x10,8)for name in ['data','string']]]
  return {'configuration':self.c,'source_producer_case':self.origin,'external_source_producer':self.external,'entry_PC':hex(self.entry),'entry_SP':hex(SP),'entry_registers31':self.entry_regs,'entry_NZCV':self.entry_NZCV,'initial_TPIDR_EL1':hex(self.u.reg_read(ar.UC_ARM64_REG_TPIDR_EL1)),'private_RAM':{'address':hex(P),'size_bytes':0x100000,'initial_byte':0,'native_owner_extents_established':False},'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'logical_authentication':self.auth,'indirect_edges':self.indirect,'maintenance_frames':self.maintenance,'system_context_reads':self.system_reads,'action_frames':self.action_frames,'pool_frames':self.pool_frames,'pool_action_statuses':self.pool_statuses,'pool_sleep_frontiers':self.sleep,'command_allocations':self.allocated,'driver_quantum_frontiers':self.quantum,'job_allocations':self.jobs,'DMA_allocations':self.dmas,'DMA_factory_frames':self.factories,'DMA_options_frames':self.specs,'inner_pool_frames':self.inner_frames,'job_base_frames':self.base_frames,'cast_frames':self.casts,'property_frames':self.properties,'device_method_frames':self.device_calls,'controller_method_frames':self.controller_calls,'clock_return_frames':self.clock_returns,'trace_frames':self.traces,'device_enable_frames':self.device_enable,'AES_enable_frames':self.aes_enable,'final_environment_globals':[{'address':hex(a),'bytes_hex':bytes(self.u.mem_read(a,n)).hex()}for a,n in env],'final_source_globals':[{'address':hex(a),'bytes_hex':bytes(self.u.mem_read(a,n)).hex()}for a,n in [(0xfffffe000cb5b638,8),(0xfffffe000cb52ea8,64)]],'final_objects':[{'address':hex(a),'bytes_hex':bytes(self.u.mem_read(a,n)).hex()}for a,n in self.all_objects],'final_RAM_sha256':hashlib.sha256(bytes(self.u.mem_read(P,0x100000))).hexdigest(),'boundary':self.boundary,'native_target_executed':False,'native_IPC_executed':False,'native_registry_or_platform_effects_executed':False,'hardware_PAC_executed':False,'runtime_device_or_controller_identity_established':False,'idb_mutated':False,'full_goal_complete':False}
def main():
 im=Image();src=json.loads((ROOT/(PREFIX+'_source.json')).read_text());Probe.trace_target=int(next(s for s in src['additional_slots']if s['name']=='trace_API')['pointer']['target'],16);origin=json.loads((ROOT/'aes_hardware_job_profiles.json').read_text())['cases'][0];external={'path':'aes_hardware_job_profiles.json','case':0};rows=[]
 def run(c,producer=None):
  p=Probe(im,{'on_thread':1,**c},src,origin if producer is None else rows[producer],producer,external if producer is None else None);p.src=src;return p.run()
 rows.append(run({'stage':'provider_cast'}));rows.append(run({'stage':'provider_cast','wrong_type':True}))
 for c in [{'property_kind':'absent'},{'property_kind':'data'},{'property_kind':'string'},{'property_kind':'data','data_tail_byte':0x5a}]:rows.append(run({'stage':'capability',**c},0))
 for producer,enable in [(2,1),(2,0),(3,1),(3,0)]:rows.append(run({'stage':'device','enable':enable},producer))
 rows.append(run({'stage':'device','enable':1,'clock_count':0},2));rows.append(run({'stage':'device','enable':1,'service_count':0},3));rows.append(run({'stage':'AES_enable'},2));rows.append(run({'stage':'AES_enable'},3));rows.append(run({'stage':'device','enable':1,'trace_enabled':True},2))
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in [PREFIX+'_source.json','aes_hardware_job_profiles.json','probe_aes_hardware_job.py','probe_aes_provider_queue.py','probe_aes_command_pool.py','probe_workloop_gate_attachment.py','probe_aes_command_gate.py','probe_kernel_vm_mig.py','kernel_vm_mig_tools.py']},'cases':rows,'native_target_executed':False,'native_IPC_executed':False,'native_registry_or_platform_effects_executed':False,'hardware_PAC_executed':False,'runtime_device_or_controller_identity_established':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(len(r['source_visits'])for r in rows),'API_models':sum(len(r['API_models'])for r in rows)}),flush=True)
if __name__=='__main__':main()
