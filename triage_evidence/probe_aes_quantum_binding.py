#!/usr/bin/env python3
"""Source public request to inner-job/binding frontier and separate transfer inputs.
Declared enabled state and API/record outcomes; no native cache, mapper or device.
O(visits+effects), O(journals+private RAM).
"""
import json,struct,hashlib
from unicorn import arm64_const as ar
from probe_aes_hardware_job import Probe as Parent,P,PROV,HPOOL,HGATE,JOBS,DMAS
from probe_aes_provider_queue import D0,D1,KEY,IV,QUANTUM
from probe_aes_command_gate import Probe as SourceCPU
from probe_kernel_vm_mig import SP,HALT
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
PREFIX='aes_quantum_binding';CMD=P+0x31f00;CONFIG=0xfffffe0009d4fcf8;ENABLE=0xfffffe0009d4f964;TRANSFER=0xfffffe0009d51168
class Probe(Parent):
 def __init__(self,im,c,src,origin,producer,external=None):
  super().__init__(im,{'stage':'lease','on_thread':1},src,origin,producer,external);self.c=c;self.end=None;self.quantum_calls=[];self.enable_calls=[];self.config_calls=[];self.transfer_calls=[];self.bind_calls=[];self.cache_calls=[];self.clear_calls=[];self.segment_calls=[];self.frontiers=[];self.segment_ordinal=0;self.all_objects=[(a,0xa00 if a==PROV else n)for a,n in self.all_objects]
  if c['stage']=='perform':
   self.entry=0xfffffe000abff358
   for a in [D0,D1]:self.fixture(a,struct.pack('<Q',0xfffffe0007f85d80))
   self.fixture(KEY,struct.pack('<I',128)+bytes(0x5c));self.fixture(IV,bytes(16));self.fixture(PROV+0x1f8,bytes([c.get('enabled_state',1)]));self.fixture(SP,struct.pack('<QQQ',c.get('offsetB',0),0,0))
   for j,v in enumerate([PROV,D0,D0 if c.get('same_descriptor')else D1,c['length'],IV,c['operation'],KEY,c.get('offsetA',0)]):self.set(j,v)
  else:
   assert c['stage']=='transfer';self.entry=TRANSFER
   for j,v in enumerate([PROV,0,0,DMAS[-2],DMAS[-1],c['offsetA'],c['offsetB'],c['remaining']]):self.set(j,v)
  self.set(30,HALT);self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV))
 def frame(self,a,n):return {'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments':[hex(self.reg(j))for j in range(n)],'carrier144_hex':bytes(self.u.mem_read(CMD,144)).hex(),'job64_hex':bytes(self.u.mem_read(JOBS[-1],64)).hex()}
 def code(self,u,a,n,d):
  self.flush()
  if a==QUANTUM:self.quantum_calls.append(self.frame(a,2));return SourceCPU.code(self,u,a,n,d)
  if a==ENABLE:self.enable_calls.append(self.frame(a,2))
  if a in [0xfffffe0009d4f650,0xfffffe0009d4fa50]:self.frontiers.append(self.frame(a,2));return self.stop('before_device_enable'if a==0xfffffe0009d4f650 else'before_disable_register_base')
  if a==CONFIG:
   self.config_calls.append(self.frame(a,3))
   if 'configuration_error'in self.c:return self.modeled(a,'declared_configuration_error_no_effect_model',self.c['configuration_error'])
   return self.stop('before_AES_configuration')
  if a==TRANSFER:self.transfer_calls.append(self.frame(a,8))
  if a==0xfffffe0009d5127c:self.frontiers.append(self.frame(a,8));return self.stop('before_transfer_register_base')
  if a in [0xfffffe0009d513b4,0xfffffe0009d51388]:self.frontiers.append(self.frame(a,4));return self.stop('before_segment_error_assertion')
  if a==0xfffffe000c528964:self.bind_calls.append(self.frame(a,3));return self.modeled(a,'DMA_bind_no_effect_model',self.c.get('binding_result',0))
  if a==0xfffffe000c52887c:self.clear_calls.append(self.frame(a,2));return self.modeled(a,'DMA_clear_no_effect_model',0)
  if a==0xfffffe000c531be4:self.cache_calls.append(self.frame(a,4));return self.modeled(a,'descriptor_operation_no_effect_model',self.c.get('cache_result',0))
  if a==self.segment_target:
   j=self.segment_ordinal;self.segment_ordinal+=1;offsetp,segmentp,countp=[self.reg(k)for k in [1,2,3]];offset=int.from_bytes(bytes(u.mem_read(offsetp,8)),'little');length=self.c['segment_lengths'][j];address=[0x100000,0x200000][j];result=self.c.get('segment_results',[0,0])[j];e=self.frame(a,4);e.update(input_offset=offset,input_count=int.from_bytes(bytes(u.mem_read(countp,4)),'little'),declared_record={'address':address,'length':length},declared_result=result);self.segment_calls.append(e)
   if result==0:
    self.effect(offsetp,struct.pack('<Q',offset+length),'Declared segment cursor result');self.effect(segmentp,struct.pack('<QQ',address,length),'Declared 16-byte segment input record');self.effect(countp,struct.pack('<I',1),'Declared one-segment count')
   return self.modeled(a,'declared_segment_record_model',result)
  return super().code(u,a,n,d)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=50000);self.flush();assert self.reason in ['before_AES_configuration','before_device_enable','before_disable_register_base','before_transfer_register_base','before_segment_error_assertion','returned'],self.boundary
  return {'configuration':self.c,'source_producer_case':self.origin,'external_source_producer':self.external,'entry_PC':hex(self.entry),'entry_SP':hex(SP),'entry_registers31':self.entry_regs,'entry_NZCV':self.entry_NZCV,'initial_TPIDR_EL1':hex(self.u.reg_read(ar.UC_ARM64_REG_TPIDR_EL1)),'private_RAM':{'address':hex(P),'size_bytes':0x100000,'initial_byte':0,'native_owner_extents_established':False},'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'logical_authentication':self.auth,'indirect_edges':self.indirect,'maintenance_frames':self.maintenance,'system_context_reads':self.system_reads,'action_frames':self.action_frames,'pool_frames':self.pool_frames,'pool_action_statuses':self.pool_statuses,'pool_sleep_frontiers':self.sleep,'command_allocations':self.allocated,'driver_quantum_frontiers':self.quantum,'job_allocations':self.jobs,'DMA_allocations':self.dmas,'DMA_factory_frames':self.factories,'DMA_options_frames':self.specs,'inner_pool_frames':self.inner_frames,'job_base_frames':self.base_frames,'quantum_calls':self.quantum_calls,'enable_calls':self.enable_calls,'configuration_calls':self.config_calls,'transfer_calls':self.transfer_calls,'binding_calls':self.bind_calls,'cache_operation_calls':self.cache_calls,'clear_calls':self.clear_calls,'segment_calls':self.segment_calls,'effect_frontiers':self.frontiers,'final_source_globals':[{'address':hex(a),'bytes_hex':bytes(self.u.mem_read(a,n)).hex()}for a,n in [(0xfffffe000cb5b638,8),(0xfffffe000cb52ea8,64)]],'final_objects':[{'address':hex(a),'bytes_hex':bytes(self.u.mem_read(a,n)).hex()}for a,n in self.all_objects],'final_RAM_sha256':hashlib.sha256(bytes(self.u.mem_read(P,0x100000))).hexdigest(),'boundary':self.boundary,'native_target_executed':False,'native_IPC_executed':False,'native_DMA_or_cache_effects_executed':False,'native_device_or_crypto_executed':False,'hardware_PAC_executed':False,'runtime_candidate_identity_established':False,'idb_mutated':False,'full_goal_complete':False}
def main():
 im=Image();src=json.loads((ROOT/(PREFIX+'_source.json')).read_text());Probe.segment_target=int(next(s for s in src['additional_slots']if s['name']=='DMA_segments')['pointer']['target'],16);origin=json.loads((ROOT/'aes_hardware_job_profiles.json').read_text())['cases'][0];external={'path':'aes_hardware_job_profiles.json','case':0};rows=[]
 configs=[{'length':32,'operation':0},{'length':64,'operation':1,'offsetA':16,'offsetB':32},{'length':65536,'operation':0},{'length':32,'operation':0,'binding_result':0xe00002bc,'cache_result':0xe00002bc},{'length':32,'operation':0,'configuration_error':0xe00002bc},{'length':32,'operation':0,'enabled_state':0}]
 for c in configs:rows.append(Probe(im,{'stage':'perform','on_thread':1,**c},src,origin,None,external).run())
 for c in [{'remaining':32,'offsetA':0,'offsetB':0,'segment_lengths':[64,16]},{'remaining':64,'offsetA':32,'offsetB':16,'segment_lengths':[32,128]},{'remaining':16,'offsetA':0,'offsetB':0,'segment_lengths':[32,64]},{'remaining':0,'offsetA':0,'offsetB':0,'segment_lengths':[32,32]},{'remaining':32,'offsetA':0,'offsetB':0,'segment_lengths':[32,32],'segment_results':[0xe00002bc,0]},{'remaining':32,'offsetA':0,'offsetB':0,'segment_lengths':[32,32],'segment_results':[0,0xe00002bc]}]:
  producer=1 if c['offsetA']==32 else 0;rows.append(Probe(im,{'stage':'transfer','on_thread':1,**c},src,rows[producer],producer).run())
 rows.append(Probe(im,{'stage':'perform','on_thread':1,'length':32,'operation':0,'same_descriptor':True},src,origin,None,external).run())
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in [PREFIX+'_source.json','aes_hardware_job_profiles.json','probe_aes_hardware_job.py','probe_aes_provider_queue.py','probe_aes_command_pool.py','probe_workloop_gate_attachment.py','probe_aes_command_gate.py','probe_kernel_vm_mig.py','kernel_vm_mig_tools.py']},'cases':rows,'native_target_executed':False,'native_IPC_executed':False,'native_DMA_or_cache_effects_executed':False,'native_device_or_crypto_executed':False,'hardware_PAC_executed':False,'runtime_candidate_identity_established':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(len(r['source_visits'])for r in rows),'API_models':sum(len(r['API_models'])for r in rows)}),flush=True)
if __name__=='__main__':main()
