#!/usr/bin/env python3
"""Declared submission-return and completion-event consumers on source carriers.
No hardware result or device IRQ is generated. O(visits+effects), O(journals+RAM).
"""
import json,struct,hashlib
from unicorn import arm64_const as ar
from probe_aes_provider_queue import Probe as Parent,P,PROV,GATE,POOL,D0,D1,CTX,CALLBACK,QUANTUM
from probe_kernel_vm_mig import SP,HALT
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
PREFIX='aes_completion_contract';CMD=P+0x31f00;SUBMISSION_X0=0x1122334455667788
class Probe(Parent):
 def __init__(self,im,c,src,origin,producer,external=None):
  request={'stage':'perform','on_thread':1,'length':32 if c['stage']=='wakeup_event'else 65536,'operation':0,'callback':c['stage']!='wakeup_event'}
  super().__init__(im,request,src,origin,producer,external);self.c=c;self.submissions=[];self.callbacks=[];self.wakeups=[]
  if c['stage']!='admission':self.entry=0xfffffe000abfd174;self.set(0,PROV);self.set(1,CMD);self.fixture(CMD+0x78,struct.pack('<I',c['event_status']))
  self.set(30,HALT);self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV))
 def code(self,u,a,n,d):
  self.flush()
  if a==QUANTUM and self.c['stage']=='admission':
   self.submissions.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments2':[hex(self.reg(j))for j in range(2)],'carrier144_hex':bytes(u.mem_read(CMD,144)).hex(),'declared_return_register':hex(SUBMISSION_X0),'AES_result_supplied':False});return self.modeled(a,'opaque_submission_return_no_effect_model',SUBMISSION_X0)
  if a==0xfffffe000c534a2c:assert[self.reg(j)for j in range(2)]in [[D0,0],[D1,0]];return self.modeled(a,'descriptor_complete_no_effect_model',0)
  if a==CALLBACK:
   self.callbacks.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments2':[hex(self.reg(j))for j in range(2)],'pool_head_hex':bytes(u.mem_read(POOL+0x10,8)).hex(),'carrier144_hex':bytes(u.mem_read(CMD,144)).hex()});return self.modeled(a,'completion_callback_no_effect_model',0)
  if a==0xfffffe000c51e19c:
   self.wakeups.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments3':[hex(self.reg(j))for j in range(3)],'carrier144_hex':bytes(u.mem_read(CMD,144)).hex()});return self.stop('before_completion_wakeup')
  return super().code(u,a,n,d)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=50000);self.flush();assert self.reason in ['returned','before_driver_quantum','before_completion_wakeup'],self.boundary
  return {'configuration':self.c,'source_producer_case':self.origin,'external_source_producer':self.external,'declared_completion_event':None if self.c['stage']=='admission'else{'status_u32':hex(self.c['event_status']),'field_offset':0x78,'hardware_origin_established':False},'entry_PC':hex(self.entry),'entry_SP':hex(SP),'entry_registers31':self.entry_regs,'entry_NZCV':self.entry_NZCV,'initial_TPIDR_EL1':hex(self.u.reg_read(ar.UC_ARM64_REG_TPIDR_EL1)),'private_RAM':{'address':hex(P),'size_bytes':0x100000,'initial_byte':0,'native_owner_extents_established':False},'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'logical_authentication':self.auth,'indirect_edges':self.indirect,'maintenance_frames':self.maintenance,'system_context_reads':self.system_reads,'action_frames':self.action_frames,'pool_frames':self.pool_frames,'pool_action_statuses':self.pool_statuses,'pool_sleep_frontiers':self.sleep,'command_allocations':self.allocated,'driver_quantum_frontiers':self.quantum,'submission_return_frames':self.submissions,'completion_callback_frames':self.callbacks,'completion_wakeup_frontiers':self.wakeups,'final_objects':[{'address':hex(a),'bytes_hex':bytes(self.u.mem_read(a,n)).hex()}for a,n in self.all_objects],'final_RAM_sha256':hashlib.sha256(bytes(self.u.mem_read(P,0x100000))).hexdigest(),'boundary':self.boundary,'hardware_origin_executed':False,'authentic_completion_status_established':False,'native_target_executed':False,'native_IPC_executed':False,'hardware_PAC_executed':False,'idb_mutated':False,'full_goal_complete':False}
def main():
 im=Image();src=json.loads((ROOT/(PREFIX+'_source.json')).read_text());published=json.loads((ROOT/'aes_provider_queue_profiles.json').read_text());rows=[]
 rows.append(Probe(im,{'stage':'admission','on_thread':1},src,published['cases'][2],None,{'path':'aes_provider_queue_profiles.json','case':2}).run());rows.append(Probe(im,{'stage':'partial_event','event_status':0,'on_thread':1},src,rows[0],0).run());rows.append(Probe(im,{'stage':'error_event','event_status':0xe00002bc,'on_thread':1},src,rows[0],0).run());rows.append(Probe(im,{'stage':'total_event','event_status':0,'on_thread':1},src,rows[1],1).run());rows.append(Probe(im,{'stage':'wakeup_event','event_status':0xe00002bc,'on_thread':1},src,published['cases'][3],None,{'path':'aes_provider_queue_profiles.json','case':3}).run())
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in [PREFIX+'_source.json','aes_provider_queue_profiles.json','probe_aes_provider_queue.py','probe_aes_command_pool.py','probe_workloop_gate_attachment.py','probe_aes_command_gate.py','probe_kernel_vm_mig.py','kernel_vm_mig_tools.py']},'cases':rows,'hardware_origin_executed':False,'authentic_completion_status_established':False,'native_target_executed':False,'native_IPC_executed':False,'hardware_PAC_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(len(r['source_visits'])for r in rows),'API_models':sum(len(r['API_models'])for r in rows)}),flush=True)
if __name__=='__main__':main()
