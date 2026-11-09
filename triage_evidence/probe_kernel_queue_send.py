#!/usr/bin/env python3
"""Continue original generated-reply caller through real queue/post/insertion.
Private queue/receiver/thread frames, logical PAC and scheduler/lock callbacks
are explicit models. No native queue, scheduler, IPC or authentication executes.
O(cases*visits) time, O(one private map+journals) space.
"""
import json,struct
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT
from capture_daemon_record720 import sha
from kernel_vm_mig_tools import Image
from probe_kernel_reply_send import Probe as Parent,P,REPLY,DEST,THREAD
from recover_kernel_queue_send import QUEUE,ENQUEUE,COPY_SIZE,TRAILER_SIZE,IDENTIFY,RESUME,CLEAR,TASK,PREPARE,ASSERT_WAIT
Q=DEST+0x28;WAITER=P+0x28000;TASKOBJ=P+0x2a000;STATS=P+0x2c000;NODE1=P+0x30000;NODE2=P+0x32000;TURN=P+0x34000
class Probe(Parent):
 def __init__(self,image,cfg):
  super().__init__(image,cfg);self.qauth=[];self.cuts=[];self.lookup_index=0;self.allowed_queue=[(a,int(image.k.function(a)['end'],16))for a in [QUEUE,ENQUEUE,COPY_SIZE,TRAILER_SIZE]];self.u.reg_write(ar.UC_ARM64_REG_TPIDR_EL1,THREAD);self.sysregs=[{'register':'TPIDR_EL1','value':hex(THREAD)}]
  self.fixture(self.header,struct.pack('<I',cfg['remote_bits']));self.fixture(REPLY+0x3e,bytes([cfg['message_qos']]));self.fixture(REPLY+0x30,struct.pack('<H',cfg['aux_size']));self.fixture(DEST+0x15,bytes([cfg['waitq_valid']]));self.fixture(Q+0x10,struct.pack('<HH',cfg['msgcount'],cfg['qlimit']));self.fixture(Q+8,struct.pack('<II',cfg['sequence'],0xabcdef12));self.fixture(THREAD+0x1b8,struct.pack('<H',0));self.fixture(TASKOBJ+0x3d0,struct.pack('<Q',STATS));self.fixture(STATS,struct.pack('<Q',cfg['initial_sent_counter']));self.fixture(WAITER+0x3a0,struct.pack('<I',cfg['receiver_state']));self.fixture(WAITER+0x390,struct.pack('<Q',cfg['receiver_options']));self.fixture(WAITER+0x388,struct.pack('<II',cfg['receiver_limit'],cfg['receiver_aux_limit']));self.fixture(WAITER+0x3b8,struct.pack('<Q',0xa5a5a5a5));self.fixture(WAITER+0x3a4,struct.pack('<I',0x5a5a5a5a))
  self.fixture(DEST+0x70,struct.pack('<Q',TURN));self.fixture(TURN+0x18,struct.pack('<Q',0))
  nodes=cfg['node_qos'];addresses=[NODE1,NODE2][:len(nodes)]
  if nodes:
   self.fixture(Q,struct.pack('<Q',addresses[0]))
   for j,(a,qos)in enumerate(zip(addresses,nodes,strict=True)):self.fixture(a,struct.pack('<QQ',addresses[(j+1)%len(nodes)],addresses[(j-1)%len(nodes)]));self.fixture(a+0x3e,bytes([qos]))
 def code(self,u,a,n,d):
  self.flush()
  if a in [0xfffffe000bcc7250,0xfffffe000bcc7ed4,0xfffffe000bcc7e34,0xfffffe000bcc7e48,0xfffffe000bcc7e60]:self.cuts.append({'pc':hex(a),'source_visit_index':len(self.visits),'X0':hex(self.reg(0))})
  callbacks={RESUME:('receiver_resume_model',0),CLEAR:('waitq_clear_promotion_model',0),TASK:('current_task_model',TASKOBJ),PREPARE:('turnstile_prepare_model',TURN),ASSERT_WAIT:('assert_wait_result_model',self.c['wait_result']),0xfffffe000bcce310:('send_inheritor_update_model',0),0xfffffe000bd69f7c:('turnstile_cleanup_model',0),0xfffffe000bd68a7c:('turnstile_complete_model',0)}
  if a==IDENTIFY:
   answers=self.c['receiver_returns'];answer=answers[self.lookup_index]if self.lookup_index<len(answers)else 0;self.lookup_index+=1;return self.model(a,'identify_receiver_model',WAITER if answer else 0)
  if a in callbacks:return self.model(a,*callbacks[a])
  if any(lo<=a<hi for lo,hi in self.allowed_queue):
   raw=bytes(u.mem_read(a,4));assert raw==self.image.k.read(a,4);ins=next(self.image.k.cs.disasm(raw,a));self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()})
   if ins.mnemonic in ['pacibsp','autibsp']:u.reg_write(ar.UC_ARM64_REG_PC,a+4)
   elif ins.mnemonic=='retab':u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30))
   elif ins.mnemonic=='autda':self.logical_auth.append({'pc':hex(a),'pointer':hex(self.reg(16)),'modifier':hex(self.reg(17)),'native_authentication_executed':False});u.reg_write(ar.UC_ARM64_REG_PC,a+4)
   elif ins.mnemonic=='pacda':self.qauth.append({'pc':hex(a),'pointer':hex(self.reg(17)),'modifier':hex(self.reg(16)),'native_authentication_executed':False});u.reg_write(ar.UC_ARM64_REG_PC,a+4)
   assert ins.mnemonic not in ['svc','hvc','smc','blraa','brk'],(hex(a),ins.mnemonic)
   return
  return super().code(u,a,n,d)
 def run(self):
  r=super().run();r['source_return_cuts']=self.cuts;r['logical_data_signing']=self.qauth;r['private_system_register_fixtures']=self.sysregs;r['queue_storage_hex']=bytes(self.u.mem_read(Q,0x20)).hex();r['reply_links_hex']=bytes(self.u.mem_read(REPLY,16)).hex();r['node_storage']=[{'address':hex(a),'bytes_hex':bytes(self.u.mem_read(a,0x40)).hex()}for a in [NODE1,NODE2][:len(self.c['node_qos'])]];r['receiver_storage_hex']=bytes(self.u.mem_read(WAITER+0x380,0xb0)).hex();r['sent_counter']=int.from_bytes(bytes(self.u.mem_read(STATS,8)),'little');return r
def configurations():
 base={'kind':'reply','route':'A','storage_class':0,'dest_low3':3,'object_refs':2,'effective_options':0,'inherited_scalar':0,'preflight_status':0,'queue_status':0,'null_reply':False,'remote_bits':0x12,'message_qos':7,'node_qos':[],'msgcount':0,'qlimit':8,'sequence':0xffffffff,'initial_sent_counter':0xffffffffffffffff,'waitq_valid':1,'receiver_state':0x10004001,'receiver_options':0,'receiver_limit':44,'receiver_aux_limit':0,'receiver_returns':[],'aux_size':0,'wait_result':1}
 rows=[]
 for route in ['A','B']:
  for cls in range(4):
   for nodes,qos in [([],0),([3],2),([3],3),([3],7),([2,4],3),([2,4],7),([4,2],3),([4,2],7)]:rows.append({**base,'case':'enqueue','route':route,'storage_class':cls,'node_qos':nodes,'msgcount':len(nodes),'message_qos':qos})
   for case,changes in [('non_receive_waiter',{'receiver_state':0}),('direct',{}),('direct_aux',{'aux_size':7,'receiver_aux_limit':7,'receiver_options':1<<32}),('too_small_take',{'receiver_limit':43}),('too_small_retry',{'receiver_limit':43,'receiver_options':4}),('linear_combined',{'receiver_options':1<<60,'receiver_limit':44}),('linear_aux_too_large',{'receiver_options':(1<<60)|4,'receiver_limit':44,'aux_size':1}),('invalid_waitq',{'waitq_valid':0})]:rows.append({**base,'case':case,'route':route,'storage_class':cls,'receiver_returns':[1,0],**changes})
  for case,changes in [('full_send_once',{'msgcount':8}),('full_always',{'msgcount':8,'remote_bits':0x13,'effective_options':0x10000}),('full_poll',{'msgcount':8,'remote_bits':0x13,'effective_options':0x10}),('kernel_full',{'msgcount':0xfffe,'remote_bits':0x13}),('kernel_full_poll',{'msgcount':0xfffe,'effective_options':0x10}),('wait_awakened',{'msgcount':8,'remote_bits':0x13,'wait_result':0}),('wait_timeout',{'msgcount':8,'remote_bits':0x13,'wait_result':1}),('wait_interrupted',{'msgcount':8,'remote_bits':0x13,'wait_result':2}),('wait_restart',{'msgcount':8,'remote_bits':0x13,'wait_result':3})]:rows.append({**base,'case':case,'route':route,**changes})
 return rows
if __name__=='__main__':
 image=Image();rows=[]
 for j,cfg in enumerate(configurations()):
  r=Probe(image,cfg).run();rows.append(r);print(j,cfg['case'],r['boundary']['kind'],len(r['source_visits']),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['kernel_queue_send_source.json','probe_kernel_reply_send.py','probe_kernel_vm_mig.py','kernel_vm_mig_tools.py']},'kernel_sha256':image.k.sha256,'cases':rows,'native_target_executed':False,'native_IPC_executed':False,'native_MAC_or_PAC_executed':False,'continuous_original_queue_path_executed_in_private_model':True,'full_goal_complete':False};(ROOT/'kernel_queue_send_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'visits':sum(len(r['source_visits'])for r in rows)}),flush=True)
