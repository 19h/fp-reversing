#!/usr/bin/env python3
"""Source-built pool through saved synchronous caller and declared event handoff.
No native scheduler/device effects. O(visits+effects), O(journals+private RAM).
"""
import json,struct,hashlib
from unicorn import arm64_const as ar
from probe_aes_provider_queue import Probe as Parent,P,PROV,GATE,D0,D1,QUANTUM
from probe_aes_command_gate import Probe as SourceCPU
from probe_workloop_gate_attachment import WLLOCK,THREAD
from probe_kernel_vm_mig import SP,HALT
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
PREFIX='aes_synchronous_wait';CMD=P+0x31f00;SLEEP=0xfffffe000bd0c8f4;WAKE=0xfffffe000bd2b480;COUNT=0xfffffe000bd2b4ac
class Probe(Parent):
 def __init__(self,im,c,src,origin,producer,external=None,suspended=None):
  stage=c['stage'];base={'stage':stage if stage in ['hardware_config','limits','binding']else'perform','on_thread':1,'length':32,'operation':0};super().__init__(im,base,src,origin,producer,external);self.c=c;self.submissions=[];self.sleep_frames=[];self.wake_frames=[];self.wake_counts=[];self.resume_reads=[];self.suspended=suspended;self.entry_sp=SP
  if stage=='wait':self.fixture(WLLOCK+0x20,struct.pack('<I',3))
  elif stage.startswith('completion'):
   self.entry=0xfffffe000abfd174;self.end=None;self.set(0,PROV);self.set(1,CMD);self.fixture(CMD+0x78,struct.pack('<I',c['event_status']))
  elif stage=='resume':
   self.entry=SLEEP;self.end=None;b=suspended['boundary'];self.entry_sp=int(b['SP'],16);self.u.reg_write(ar.UC_ARM64_REG_SP,self.entry_sp)
   for j,v in enumerate(b['registers31']):self.set(j,int(v,16))
   self.u.reg_write(ar.UC_ARM64_REG_NZCV,int(b['NZCV'],16));ss=suspended['suspended_stack'];self.fixture(int(ss['address'],16),bytes.fromhex(ss['bytes_hex']))
  elif stage=='not_owner':self.entry=0xfffffe000c51e1d4;self.end=None;self.set(0,GATE);self.set(1,CMD);self.set(2,0);self.fixture(WLLOCK+0x18,bytes(8))
  elif stage=='wake_one':self.entry=0xfffffe000c51e19c;self.end=None;self.set(0,GATE);self.set(1,CMD);self.set(2,1)
  if stage!='resume':self.set(30,HALT)
  self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV))
 def frame(self,a,n):return {'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments':[hex(self.reg(j))for j in range(n)],'lock_owner_hex':bytes(self.u.mem_read(WLLOCK+0x18,8)).hex(),'lock_depth_hex':bytes(self.u.mem_read(WLLOCK+0x20,4)).hex(),'carrier144_hex':bytes(self.u.mem_read(CMD,144)).hex()}
 def code(self,u,a,n,d):
  self.flush();stage=self.c['stage']
  if a==QUANTUM:
   assert stage=='wait';self.submissions.append(self.frame(a,2));return self.modeled(a,'opaque_submission_return_no_effect_model',0x1122334455667788)
  if a==0xfffffe000c51e1d4:return SourceCPU.code(self,u,a,n,d)
  if a==SLEEP:
   self.sleep_frames.append(self.frame(a,4))
   if stage=='wait':return self.stop('before_kernel_sleep')
   assert stage=='resume';return self.modeled(a,'declared_scheduler_return_no_effect_model',self.c['sleep_result'])
  if a==WAKE:
   self.wake_frames.append(self.frame(a,3))
   if stage=='completion_return':return self.modeled(a,'kernel_wakeup_no_effect_model',0)
  if a==COUNT:self.wake_counts.append(self.frame(a,5));return self.stop('before_waitqueue_lookup')
  if a==0xfffffe000c519b38:self.resume_reads.append({'pc':hex(a),'source_visit_index':len(self.visits),'TPIDR_EL1':hex(u.reg_read(ar.UC_ARM64_REG_TPIDR_EL1))})
  if a==0xfffffe000c534a2c:assert[self.reg(j)for j in range(2)]in [[D0,0],[D1,0]];return self.modeled(a,'descriptor_complete_no_effect_model',0)
  if a==0xfffffe000abff924:return self.stop('before_nonzero_sleep_assertion')
  if a==0xfffffe000c62a2b0:return self.stop('before_not_owner_assertion')
  return super().code(u,a,n,d)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=50000);self.flush();assert self.reason in ['after_registration_component','before_kernel_sleep','before_waitqueue_lookup','returned','before_nonzero_sleep_assertion','before_not_owner_assertion'],self.boundary
  stack=None
  if self.c['stage']=='wait':
   a=int(self.boundary['SP'],16);stack={'address':hex(a),'bytes_hex':bytes(self.u.mem_read(a,SP+24-a)).hex(),'end_exclusive':hex(SP+24),'provenance':'Exact source-produced suspended caller stack, before kernel sleep body'}
  return {'configuration':self.c,'source_producer_case':self.origin,'external_source_producer':self.external,'suspended_context_case':3 if self.suspended else None,'suspended_stack':stack,'entry_PC':hex(self.entry),'entry_SP':hex(self.entry_sp),'entry_registers31':self.entry_regs,'entry_NZCV':self.entry_NZCV,'initial_TPIDR_EL1':hex(THREAD),'private_RAM':{'address':hex(P),'size_bytes':0x100000,'initial_byte':0,'native_owner_extents_established':False},'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'logical_authentication':self.auth,'indirect_edges':self.indirect,'maintenance_frames':self.maintenance,'system_context_reads':self.system_reads,'action_frames':self.action_frames,'pool_frames':self.pool_frames,'pool_action_statuses':self.pool_statuses,'pool_sleep_frontiers':self.sleep,'command_allocations':self.allocated,'driver_quantum_frontiers':self.quantum,'submission_frames':self.submissions,'kernel_sleep_frames':self.sleep_frames,'kernel_wakeup_frames':self.wake_frames,'wake_count_frames':self.wake_counts,'resume_system_context_reads':self.resume_reads,'final_objects':[{'address':hex(a),'bytes_hex':bytes(self.u.mem_read(a,n)).hex()}for a,n in self.all_objects],'final_RAM_sha256':hashlib.sha256(bytes(self.u.mem_read(P,0x100000))).hexdigest(),'boundary':self.boundary,'scheduler_effects_executed':False,'authentic_completion_status_established':False,'native_target_executed':False,'native_IPC_executed':False,'hardware_PAC_executed':False,'idb_mutated':False,'full_goal_complete':False}
def main():
 im=Image();src=json.loads((ROOT/(PREFIX+'_source.json')).read_text());published=json.loads((ROOT/'aes_carrier_initialization_profiles.json').read_text());rows=[]
 rows.append(Probe(im,{'stage':'hardware_config','on_thread':1},src,published['cases'][15],None,{'path':'aes_carrier_initialization_profiles.json','case':15}).run())
 for stage in ['limits','binding']:rows.append(Probe(im,{'stage':stage,'on_thread':1},src,rows[-1],len(rows)-1).run())
 rows.append(Probe(im,{'stage':'wait','on_thread':1},src,rows[2],2).run());rows.append(Probe(im,{'stage':'completion_frontier','event_status':0,'on_thread':1},src,rows[3],3).run())
 for status in [0,0xe00002bc]:rows.append(Probe(im,{'stage':'completion_return','event_status':status,'on_thread':1},src,rows[3],3).run())
 for origin,result in [(5,0),(6,0),(5,1)]:rows.append(Probe(im,{'stage':'resume','sleep_result':result,'on_thread':1},src,rows[origin],origin,suspended=rows[3]).run())
 rows.append(Probe(im,{'stage':'not_owner','on_thread':1},src,rows[2],2).run());rows.append(Probe(im,{'stage':'wake_one','on_thread':1},src,rows[2],2).run())
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in [PREFIX+'_source.json','aes_carrier_initialization_profiles.json','probe_aes_provider_queue.py','probe_aes_command_pool.py','probe_workloop_gate_attachment.py','probe_aes_command_gate.py','probe_kernel_vm_mig.py','kernel_vm_mig_tools.py']},'cases':rows,'scheduler_effects_executed':False,'authentic_completion_status_established':False,'native_target_executed':False,'native_IPC_executed':False,'hardware_PAC_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(len(r['source_visits'])for r in rows),'API_models':sum(len(r['API_models'])for r in rows)}),flush=True)
if __name__=='__main__':main()
