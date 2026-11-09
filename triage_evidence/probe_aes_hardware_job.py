#!/usr/bin/env python3
"""Source inner pool/jobs and IODMA factory/legacy spec to declared mapper backend.
Allocator, reference/lock, mapper initialization and PAC premises are explicit.
O(visits+effects), O(journals+private RAM); no native allocation, mapping or DMA.
"""
import json,struct,hashlib
from unicorn import arm64_const as ar
from probe_aes_provider_queue import Probe as Parent,P,PROV,LOOP,POOL
from probe_aes_command_gate import Probe as SourceCPU,GV
from probe_kernel_vm_mig import SP,HALT
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
PREFIX='aes_hardware_job';HPOOL=P+0x25000;HGATE=P+0x26000;HEXP=P+0x27000;MAPPER=P+0x28000;SEGS=P+0x29000;JOBS=[P+0x40000+j*0x100 for j in range(32)];DMAS=[P+0x50000+j*0x100 for j in range(64)];DMETA=0xfffffe000cb52ea8;COUNTER=0xfffffe000cb5b638;OUTPUT=0xfffffe000c529dd8;DV=0xfffffe0007f411f8
class Probe(Parent):
 def __init__(self,im,c,src,origin,producer,external=None):
  super().__init__(im,{'stage':'binding','on_thread':1},src,origin,producer,external);self.c=c;self.end=None;self.jobs=[];self.dmas=[];self.factories=[];self.specs=[];self.inner_frames=[];self.base_frames=[];self.all_objects +=[(HPOOL,0x100),(HGATE,0x80),(HEXP,0x40),(MAPPER,0x40),(SEGS,64),*[(a,64)for a in JOBS],*[(a,120)for a in DMAS]];self.allowed +=[(int(s['start'],16),int(s['end'],16))for s in src['driver_stubs']]
  for a,b,why in [(DMETA,struct.pack('<Q',0xfffffe0007f41450),'Nominal DMA metaclass vptr; file word zero'),(DMETA+0x24,bytes(4),'Declared private metaclass-count epoch zero'),(COUNTER,bytes(8),'Declared private requested-byte accounting epoch zero')]:self.ensure(a,len(b));self.u.mem_write(a,b);self.image_initial.append({'address':hex(a),'bytes_hex':b.hex(),'provenance':why})
  for e in origin.get('final_source_globals',[]):
   a=int(e['address'],16);b=bytes.fromhex(e['bytes_hex']);self.ensure(a,len(b));self.u.mem_write(a,b);self.image_initial.append({**e,'provenance':'Exact source-produced global snapshot; native epoch unestablished'})
  stage=c['stage']
  if stage in ['seed','factory']:
   for a,n in [*[(a,64)for a in JOBS],*[(a,120)for a in DMAS]]:self.fixture(a,bytes([0x5a])*n)
  if stage=='seed':self.entry=0xfffffe0009d4f1e8;self.end=0xfffffe0009d4f360;self.set(20,PROV);self.fixture(PROV+0x1b8,struct.pack('<Q',MAPPER))
  elif stage=='lease':self.entry=0xfffffe000c51ff48;self.set(0,HPOOL);self.set(1,0)
  elif stage=='return':self.entry=0xfffffe000c51fe7c;self.set(0,HPOOL);self.set(1,JOBS[-1])
  elif stage=='factory':
   self.entry=0xfffffe000c529b0c
   for j,v in enumerate([OUTPUT,0,0,0,0,1,MAPPER,0]):self.set(j,v)
  else:
   assert stage=='output';self.entry=OUTPUT;self.fixture(SEGS,bytes([0xa5])*64)
   for j,v in enumerate([DMAS[0],c['address'],c['length'],SEGS,c['index']]):self.set(j,v)
  self.set(30,HALT);self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV))
 def write(self,u,t,a,n,v,d):
  if(a,n)in [(COUNTER,8),(DMETA+0x24,4)]:
   e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'address':hex(a),'size_bytes':n};self.writes.append(e);self.pending.append(e);return
  return super().write(u,t,a,n,v,d)
 def code(self,u,a,n,d):
  self.flush()
  if a==0xfffffe000c5203c4:
   assert self.reg(0)==0xfffffe000cb52de0;self.effect(HPOOL,struct.pack('<Q',0xfffffe0007f40058),'Declared nominal inner-pool allocation');return self.modeled(a,'inner_pool_allocation_model',HPOOL)
  if a==0xfffffe000c51eb40:
   assert self.reg(0)==0xfffffe000cb52db8;self.effect(HGATE,struct.pack('<Q',GV),'Declared nominal inner-pool gate allocation');return self.modeled(a,'inner_gate_allocation_model',HGATE)
  if a==0xfffffe000bcfeb8c:
   if self.reg(0)==0xfffffe0007e55c58:return self.modeled(a,'inner_gate_extension_model',HEXP)
   assert[self.reg(j)for j in range(2)]==[0xfffffe00082fe528,4]and len(self.jobs)<32;result=JOBS[len(self.jobs)];self.jobs.append({'address':hex(result),'before_source_visit_index':len(self.visits),'requested_bytes':64});self.effect(result,bytes(64),'Declared zeroed 64-byte job backend result');return self.modeled(a,'job_zeroed_backend_model',result)
  if a==0xfffffe000bcfe5b8:
   assert[self.reg(j)for j in range(4)]==[0xfffffe0007f36938,120,0x41004,0]and len(self.dmas)<64;result=DMAS[len(self.dmas)];self.dmas.append({'address':hex(result),'before_source_visit_index':len(self.visits),'requested_bytes':120});self.effect(result,bytes(120),'Declared zeroed 120-byte DMA object backend result');return self.modeled(a,'DMA_zeroed_backend_model',result)
  if a==0xfffffe000c4458c4:return SourceCPU.code(self,u,a,n,d)
  if a==0xfffffe000c51fb58:
   assert self.reg(0)in JOBS and self.reg(1)==0xfffffe000cc68c88;self.base_frames.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments2':[hex(self.reg(j))for j in range(2)]});return SourceCPU.code(self,u,a,n,d)
  if a==0xfffffe000c4434ec:assert self.reg(0)==0xfffffe000cc68c88;return self.modeled(a,'job_class_bookkeeping_model',0)
  if a==0xfffffe000c445200 and self.reg(0)==HGATE:return self.modeled(a,'inner_gate_retain_model',0)
  if a==0xfffffe000c529b0c:self.factories.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments8':[hex(self.reg(j))for j in range(8)]})
  if a==0xfffffe000c529048 and self.c.get('allocation_NULL'):return self.modeled(a,'DMA_meta_NULL_model',0)
  if a==0xfffffe000c526b48:
   self.specs.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments6':[hex(self.reg(j))for j in range(6)],'options40_hex':bytes(u.mem_read(self.reg(2),40)).hex()});return self.modeled(a,'DMA_options_init_no_effect_model',self.c.get('init_result',1))
  if a==0xfffffe000c4451d0 and self.reg(0)in DMAS:return self.modeled(a,'DMA_release_no_effect_model',0)
  if a in [0xfffffe000c51fd90,0xfffffe000c51fcec]and self.reg(0)==HPOOL:
   self.inner_frames.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments5':[hex(self.reg(j))for j in range(5)],'gate48_hex':bytes(u.mem_read(HGATE+0x48,8)).hex()});return SourceCPU.code(self,u,a,n,d)
  return super().code(u,a,n,d)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=100000);self.flush();assert self.reason in ['returned','after_registration_component'],self.boundary
  return {'configuration':self.c,'source_producer_case':self.origin,'external_source_producer':self.external,'entry_PC':hex(self.entry),'entry_SP':hex(SP),'entry_registers31':self.entry_regs,'entry_NZCV':self.entry_NZCV,'initial_TPIDR_EL1':hex(self.u.reg_read(ar.UC_ARM64_REG_TPIDR_EL1)),'private_RAM':{'address':hex(P),'size_bytes':0x100000,'initial_byte':0,'native_owner_extents_established':False},'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'logical_authentication':self.auth,'indirect_edges':self.indirect,'maintenance_frames':self.maintenance,'system_context_reads':self.system_reads,'action_frames':self.action_frames,'pool_frames':self.pool_frames,'pool_action_statuses':self.pool_statuses,'pool_sleep_frontiers':self.sleep,'command_allocations':self.allocated,'driver_quantum_frontiers':self.quantum,'job_allocations':self.jobs,'DMA_allocations':self.dmas,'DMA_factory_frames':self.factories,'DMA_options_frames':self.specs,'inner_pool_frames':self.inner_frames,'job_base_frames':self.base_frames,'final_source_globals':[{'address':hex(a),'bytes_hex':bytes(self.u.mem_read(a,n)).hex()}for a,n in [(COUNTER,8),(DMETA,64)]],'final_objects':[{'address':hex(a),'bytes_hex':bytes(self.u.mem_read(a,n)).hex()}for a,n in self.all_objects],'final_RAM_sha256':hashlib.sha256(bytes(self.u.mem_read(P,0x100000))).hexdigest(),'boundary':self.boundary,'native_target_executed':False,'native_IPC_executed':False,'native_allocation_or_DMA_executed':False,'hardware_PAC_executed':False,'runtime_candidate_identity_established':False,'idb_mutated':False,'full_goal_complete':False}
def main():
 im=Image();src=json.loads((ROOT/(PREFIX+'_source.json')).read_text());origin=json.loads((ROOT/'aes_synchronous_wait_profiles.json').read_text())['cases'][2];rows=[];external={'path':'aes_synchronous_wait_profiles.json','case':2}
 rows.append(Probe(im,{'stage':'seed','on_thread':1},src,origin,None,external).run());rows.append(Probe(im,{'stage':'lease','on_thread':1},src,rows[0],0).run());rows.append(Probe(im,{'stage':'return','on_thread':1},src,rows[1],1).run())
 for c in [{'init_result':1},{'init_result':0},{'allocation_NULL':True}]:rows.append(Probe(im,{'stage':'factory','on_thread':1,**c},src,origin,None,external).run())
 for index,address,length in [(0,0,0),(1,0x100000,4096),(3,0x123456789abcdef0,0x1020304050607080),(2,0x100000000,32768)]:rows.append(Probe(im,{'stage':'output','index':index,'address':address,'length':length,'on_thread':1},src,origin,None,external).run())
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in [PREFIX+'_source.json','aes_synchronous_wait_profiles.json','probe_aes_provider_queue.py','probe_aes_command_pool.py','probe_workloop_gate_attachment.py','probe_aes_command_gate.py','probe_kernel_vm_mig.py','kernel_vm_mig_tools.py']},'cases':rows,'native_target_executed':False,'native_IPC_executed':False,'native_allocation_or_DMA_executed':False,'hardware_PAC_executed':False,'runtime_candidate_identity_established':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(len(r['source_visits'])for r in rows),'API_models':sum(len(r['API_models'])for r in rows)}),flush=True)
if __name__=='__main__':main()
