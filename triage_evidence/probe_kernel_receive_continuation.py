#!/usr/bin/env python3
"""Original async receive producer -> block prefix -> sender -> continuation fragment.
O(image+visits+RAM+effects), O(image+RAM+journals). Call/CPU/frame/stack contexts,
allocator/primitive effects and logical PAC remain declared. No native scheduler,
context-key programming, receive copyout or actual FairPlay transport executes.
"""
import json,struct
from unicorn import arm64_const as ar
from probe_kernel_waitq_enqueue import Phase,PORT,INNER,RECV,THREAD,PSP,simd
from probe_kernel_waitq_receiver import Probe as Sender
from probe_kernel_vm_mig import Probe as CPU,P,HALT
from probe_rpc502_vm_handoff import compressed,decode
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
PREFIX='kernel_receive_continuation';BLOCK=0xfffffe000bd28f6c;SELECT=0xfffffe000bd29140;DISPATCH=0xfffffe000bd2a1d0;CALLBACK=0xfffffe000bcc89bc;RESULTS=0xfffffe000bcdcc7c;STACK=P+0xe6000
CONFIGS=[{'interruptibility':2,'thread_limit':2,'priority':31,'has_continuation':0,'capacity':44},{'interruptibility':2,'thread_limit':2,'priority':31,'has_continuation':1,'capacity':44},{'interruptibility':2,'thread_limit':2,'priority':31,'has_continuation':1,'capacity':43},{'interruptibility':2,'thread_limit':2,'priority':31,'has_continuation':1,'capacity':44,'DAIF_mask':0x200},{'interruptibility':2,'thread_limit':0,'priority':31,'has_continuation':1,'capacity':44},{'interruptibility':2,'thread_limit':2,'priority':31,'has_continuation':1,'capacity':44,'abort_flags':0x10}]
class Setup(Phase):
 def __init__(self,im,src,c,kind,base,globals,origin):
  super().__init__(im,src,c,kind,base,globals,origin);self.csigs=[];self.blockframes=[]
  if kind=='port_init'and c['capacity']!=44:self.overlay(RECV+0x388,struct.pack('<I',c['capacity']),'Declared receive capacity variant before original initialization and wait setup')
  if kind=='receive_wait':self.set(4,c['has_continuation'])
  self.entry_regs=[hex(self.reg(j))for j in range(31)]
 def code(self,u,a,n,d):
  self.flush()
  if a in[BLOCK,SELECT]:self.blockframes.append({'pc':hex(a),'source_visit_index':len(self.visits),'arguments8':[hex(self.reg(j))for j in range(8)],'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'receiver1536_hex':bytes(u.mem_read(RECV,1536)).hex(),'DAIF_mask':hex(u.reg_read(ar.UC_ARM64_REG_PSTATE)&0x3c0)})
  if a==SELECT:return self.stop('before_original_scheduler_selection')
  if a==BLOCK:return CPU.code(self,u,a,n,d)
  if a>=0xfffffe0000000000:
   raw=bytes(u.mem_read(a,4));i=next(self.image.k.cs.disasm(raw,a))
   if i.mnemonic=='pacia':assert i.op_str=='x16, x17'and raw==self.image.k.read(a,4);self.csigs.append({'pc':hex(a),'pointer':hex(self.reg(16)),'modifier':hex(self.reg(17))});self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  return super().code(u,a,n,d)
 def run(self):r=super().run();r.update(logical_code_signing=self.csigs,block_frames=self.blockframes);return r
class Dispatch(Phase):
 def __init__(self,im,src,c,parent,family,variant):
  self.variant=variant;self.family=family;super().__init__(im,src,{'DAIF_mask':int(parent['final_DAIF_mask'],16)},'port_unlock',decode(parent['final_private_RAM']),parent['final_image_globals'],{'path':PREFIX+'_profiles.json','consumer':family});self.kind='continuation_dispatch';self.archauth=[];self.edges=[];self.dframes=[];self.entry=DISPATCH
  self.overlay(RECV+0x158,struct.pack('<Q',STACK),'Declared logical authenticated kernel-stack top for continuation entry')
  for off,key in[(0xd8,'wait_result'),(0x3a0,'receive_status'),(0x1f8,'thread_state')]:
   if key in variant:self.overlay(RECV+off,struct.pack('<I',variant[key]),'Controlled continuation field variant; not a newly observed scheduler result')
  for off,key in[(0x1d0,'context_B'),(0x1d8,'context_A')]:
   if key in variant:self.overlay(RECV+off,struct.pack('<Q',variant[key]),'Declared synthetic context selector; no native key material')
  for off,key in[(0x200,'cached_context_B'),(0x208,'cached_context_A')]:
   if key in variant:self.overlay(P+0xb4000+off,struct.pack('<Q',variant[key]),'Declared synthetic processor context-cache selector')
  cont=int.from_bytes(bytes(self.u.mem_read(RECV+0xe0,8)),'little');param=int.from_bytes(bytes(self.u.mem_read(RECV+0xe8,8)),'little');assert cont==CALLBACK;self.set(0,0);self.set(19,RECV);self.set(21,cont);self.set(25,param);self.entry_regs=[hex(self.reg(j))for j in range(31)];self.c={'source_family':family,'variant':variant,'DAIF_mask':int(parent['final_DAIF_mask'],16)}
 def code(self,u,a,n,d):
  self.flush()
  if a in[DISPATCH,0xfffffe000be8b3c4,0xfffffe000bc9c300,0xfffffe000bc9c3bc,CALLBACK,0xfffffe000bcdd12c,RESULTS]:self.dframes.append({'pc':hex(a),'source_visit_index':len(self.visits),'arguments8':[hex(self.reg(j))for j in range(8)],'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'FP':hex(self.reg(29)),'receiver1536_hex':bytes(u.mem_read(RECV,1536)).hex(),'DAIF_mask':hex(u.reg_read(ar.UC_ARM64_REG_PSTATE)&0x3c0)})
  if a==RESULTS:return self.stop('before_original_user_receive_results')
  if a==0xfffffe000c62a2b0:return self.stop('before_original_continuation_guard')
  if a in[0xfffffe000bc9c338,0xfffffe000bc9c380]:return self.stop('before_original_context_key_programming')
  if a==0xfffffe000bc9c314:
   raw=bytes(u.mem_read(a,4));assert raw==self.image.k.read(a,4);self.archauth.append({'pc':hex(a),'pointer':hex(self.reg(5)),'modifier':hex(self.reg(6))});self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  if a==0xfffffe000bc9c3c8:
   raw=bytes(u.mem_read(a,4));assert raw==self.image.k.read(a,4);self.edges.append({'pc':hex(a),'target':hex(self.reg(20)),'modifier':hex(self.reg(21)),'arguments2':[hex(self.reg(0)),hex(self.reg(1))]});self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});self.set(30,a+4);u.reg_write(ar.UC_ARM64_REG_PC,self.reg(20));return
  return super().code(u,a,n,d)
 def run(self):r=super().run();r.update(logical_stack_authentication=self.archauth,logical_continuation_edges=self.edges,dispatch_frames=self.dframes,family=self.family,variant=self.variant);return r
def main():
 im=Image();src=json.loads((ROOT/(PREFIX+'_source.json')).read_text());ns=json.loads((ROOT/'kernel_send_right_lifecycle_profiles.json').read_text())['cases'][11];seed=json.loads((ROOT/'kernel_waitq_receiver_profiles.json').read_text())['cases'][1];up=json.loads((ROOT/'kernel_waitq_enqueue_profiles.json').read_text());base=decode(up['cases'][0]['initial_state_transfer']);rows=[];consumers=[];dispatches=[]
 for family,c in enumerate(CONFIGS):
  ram=base;globals=seed['initial_image_fixtures'];origin={'path':'kernel_waitq_enqueue_profiles.json','case':0,'epoch':'Exact prepared entry RAM before producer overlays'}
  for kind in['port_init','port_unlock','turnstile_allocate','receive_wait']:
   r=Setup(im,src,c,kind,ram,globals,origin).run();r['family']=family;rows.append(r);ram=decode(r['final_private_RAM']);globals=r['final_image_globals'];origin={'path':PREFIX+'_profiles.json','case':len(rows)-1};print(json.dumps({'case':len(rows)-1,'family':family,'kind':kind,'visits':len(r['source_visits']),'boundary':r['boundary']['kind']}),flush=True)
  sender=Sender(im,{'receivers':[{'capacity':c['capacity']}],'interrupt_mask':c.get('DAIF_mask',0x3c0)},src,ns);sender.u.mem_write(P,ram);sender.image_initial=[]
  for e in globals:sender.image_fixture(int(e['address'],16),bytes.fromhex(e['bytes_hex']),'Exact original block-prefix producer global transfer')
  r=sender.run();metadata={k:r.pop(k)for k in['memory_overlays','allocation_environment_overlays','queue_environment_overlays','waitq_environment_overlays','initial_private_fixtures']};r.update(initial_state_transfer={**origin,**compressed(ram)},initial_private_fixtures=[],preparation_metadata_not_reapplied=metadata,family=family,producer_configuration=c);consumers.append(r);print(json.dumps({'consumer':family,'visits':len(r['source_visits']),'boundary':r['boundary']['kind']}),flush=True)
 variants=[(1,{}),(2,{}),(3,{}),(4,{}),(1,{'thread_state':0x84}),(1,{'wait_result':1}),(1,{'wait_result':2}),(1,{'wait_result':3}),(1,{'wait_result':0xffffffff}),(1,{'receive_status':0x10004001}),(1,{'receive_status':0x1000400e}),(1,{'context_B':1}),(1,{'context_A':2}),(1,{'context_B':0x55,'cached_context_B':0x55,'context_A':0x66,'cached_context_A':0x66})]
 for family,v in variants:
  r=Dispatch(im,src,v,consumers[family],family,v).run();dispatches.append(r);print(json.dumps({'dispatch':len(dispatches)-1,'family':family,'variant':v,'visits':len(r['source_visits']),'boundary':r['boundary']['kind']}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[PREFIX+'_source.json','kernel_waitq_enqueue_profiles.json','kernel_waitq_receiver_profiles.json','kernel_send_right_lifecycle_profiles.json','probe_kernel_waitq_enqueue.py','probe_kernel_waitq_receiver.py','probe_kernel_kmsg_queue.py','probe_kernel_kmsg_allocation.py','probe_kernel_notification_send.py','probe_kernel_vm_mig.py','probe_rpc502_vm_handoff.py','kernel_vm_mig_tools.py']},'cases':rows,'consumers':consumers,'dispatches':dispatches,**{k:False for k in FLAGS}};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
