#!/usr/bin/env python3
"""Original typed wrapper and IOCommand construction with explicit backend boundary.
Zeroed backend objects/class bookkeeping/PAC are models. No native allocation.
O(visits+effects), O(journals+private RAM).
"""
import json,struct,hashlib
from unicorn import arm64_const as ar
from probe_aes_command_pool import Probe as Parent,P,CARRIERS
from probe_aes_command_gate import Probe as SourceCPU
from probe_kernel_vm_mig import SP,HALT
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
PREFIX='aes_carrier_initialization';VIEW=0xfffffe000858a4a8;COUNTER=0xfffffe000cb5b638;CMD=CARRIERS[-1]
class Probe(Parent):
 def __init__(self,im,c,src,origin):
  super().__init__(im,{'stage':'seed','on_thread':1},src,origin,None,{'path':'aes_command_pool_profiles.json','case':0});self.c=c;self.alloc_frames=[];self.backend_frontiers=[];self.construct_frames=[];self.ensure(COUNTER,8);self.u.mem_write(COUNTER,bytes(8));self.image_initial.append({'address':hex(COUNTER),'bytes_hex':'00'*8,'provenance':'Declared private allocation-accounting epoch starts at zero'})
  if c['stage']=='frontier':self.entry=0xfffffe000c4458c4;self.end=None;self.set(0,VIEW);self.set(1,c['requested_bytes'])
  elif c['stage']=='constructor':self.entry=c['entry'];self.end=None;self.fixture(CMD,bytes([c['initial_byte']])*144);self.set(0,CMD);self.set(1,0xfffffe000cce14e0)
  else:
   for a in CARRIERS:self.fixture(a,bytes([0x5a])*144)
  self.set(30,HALT);self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV))
 def write(self,u,t,a,n,v,d):
  if a==COUNTER and n==8:
   e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'address':hex(a),'size_bytes':n};self.writes.append(e);self.pending.append(e);return
  return super().write(u,t,a,n,v,d)
 def code(self,u,a,n,d):
  self.flush()
  if a==0xfffffe000c4458c4:
   self.alloc_frames.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments2':[hex(self.reg(j))for j in range(2)]});return SourceCPU.code(self,u,a,n,d)
  if a==0xfffffe000c51fb58:
   self.construct_frames.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments2':[hex(self.reg(j))for j in range(2)],'before144_hex':bytes(u.mem_read(self.reg(0),144)).hex()});return SourceCPU.code(self,u,a,n,d)
  if a in [0xfffffe000bcfeb8c,0xfffffe000bcfe5b8]:
   if self.c['stage']=='frontier':self.backend_frontiers.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments4':[hex(self.reg(j))for j in range(4)]});return self.stop('before_allocation_backend')
   assert a==0xfffffe000bcfeb8c and[self.reg(j)for j in range(2)]==[VIEW,4]and len(self.allocated)<32;result=CARRIERS[len(self.allocated)];self.allocated.append({'address':hex(result),'requested_bytes':144,'before_source_visit_index':len(self.visits)});self.effect(result,bytes(144),'Declared zeroed allocation backend result; native allocator not executed');return self.modeled(a,'typed_command_backend_zero_model',result)
  return super().code(u,a,n,d)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=50000);self.flush();assert self.reason in ['returned','after_registration_component','before_allocation_backend'],self.boundary
  return {'configuration':self.c,'source_producer_case':None,'external_source_producer':self.external,'entry_PC':hex(self.entry),'entry_SP':hex(SP),'entry_registers31':self.entry_regs,'entry_NZCV':self.entry_NZCV,'initial_TPIDR_EL1':hex(self.u.reg_read(ar.UC_ARM64_REG_TPIDR_EL1)),'private_RAM':{'address':hex(P),'size_bytes':0x100000,'initial_byte':0,'native_owner_extents_established':False},'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'logical_authentication':self.auth,'indirect_edges':self.indirect,'maintenance_frames':self.maintenance,'system_context_reads':self.system_reads,'action_frames':self.action_frames,'pool_frames':self.pool_frames,'pool_action_statuses':self.pool_statuses,'pool_sleep_frontiers':self.sleep,'command_allocations':self.allocated,'allocation_frames':self.alloc_frames,'backend_frontiers':self.backend_frontiers,'constructor_frames':self.construct_frames,'final_counter_hex':bytes(self.u.mem_read(COUNTER,8)).hex(),'final_objects':[{'address':hex(a),'bytes_hex':bytes(self.u.mem_read(a,n)).hex()}for a,n in self.all_objects],'final_RAM_sha256':hashlib.sha256(bytes(self.u.mem_read(P,0x100000))).hexdigest(),'boundary':self.boundary,'native_target_executed':False,'native_IPC_executed':False,'native_allocation_executed':False,'hardware_PAC_executed':False,'authentic_completion_status_established':False,'idb_mutated':False,'full_goal_complete':False}
def main():
 im=Image();src=json.loads((ROOT/(PREFIX+'_source.json')).read_text());origin=json.loads((ROOT/'aes_command_pool_profiles.json').read_text())['cases'][0];rows=[]
 for size in [0,143,144,145,0xffffffff,0x100000000,0xffffffffffffffff]:rows.append(Probe(im,{'stage':'frontier','requested_bytes':size},src,origin).run())
 for entry in [0xfffffe000abfc1cc,0xfffffe000abfc204,0xfffffe000abfc388,0xfffffe000abfc3e4]:
  for fill in [0,0x5a]:rows.append(Probe(im,{'stage':'constructor','entry':entry,'initial_byte':fill},src,origin).run())
 rows.append(Probe(im,{'stage':'seed','on_thread':1},src,origin).run())
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in [PREFIX+'_source.json','aes_command_pool_profiles.json','probe_aes_command_pool.py','probe_workloop_gate_attachment.py','probe_aes_command_gate.py','probe_kernel_vm_mig.py','kernel_vm_mig_tools.py']},'cases':rows,'native_target_executed':False,'native_IPC_executed':False,'native_allocation_executed':False,'hardware_PAC_executed':False,'authentic_completion_status_established':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(len(r['source_visits'])for r in rows),'API_models':sum(len(r['API_models'])for r in rows)}),flush=True)
if __name__=='__main__':main()
