#!/usr/bin/env python3
"""Source notification with original nested waitq selection and identified release.
O(visits+RAM+effects), O(image+RAM+journals). Nested waitq/thread/CPU-slot/DAIF
contexts are declared; blocked-thread scheduler and invalid context stop at source.
"""
import json,struct
from unicorn import arm64_const as ar
from probe_kernel_kmsg_queue import Probe as Parent,PORT,THREAD,RECV,QUEUE
from probe_kernel_vm_mig import Probe as CPU,P,SIZE
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
PREFIX='kernel_waitq_receiver';SELECT=0xfffffe000bd6cf80;CORE=0xfffffe000bd6c660;STAGE=0xfffffe000bd6cbcc;RESUME=0xfffffe000bd6d0d4;SCHED=0xfffffe000bd26ba8;INNER=P+0xb5000;SCRATCH=0xfffffe000cac74e0
class Probe(Parent):
 def __init__(self,im,c,src,producer):
  super().__init__(im,c,src,producer);self.wconfig=c;self.wenv=[];self.wframes=[];self.current_receiver=0;self.interrupt_before=[];self.entrymask=c.get('interrupt_mask',0x3c0);self.u.reg_write(ar.UC_ARM64_REG_PSTATE,(self.u.reg_read(ar.UC_ARM64_REG_PSTATE)&~0x3c0)|self.entrymask)
  self.wfixture(PORT+0x10,struct.pack('<I',3),'Declared outer port waitq type3');self.wfixture(PORT+0x18,struct.pack('<Q',INNER),'Declared nested waitq pointer');self.wfixture(PORT+0x20,bytes(8),'Declared no port-set link chain');raw=bytearray(24);struct.pack_into('<IIQ',raw,0,1 if c.get('backend')=='fifo'else 2,0x144,self.receivers[0]if self.receivers else 0);self.wfixture(INNER,bytes(raw),'Declared nested type1 FIFO or type2 singleton queue')
  for j,a in enumerate(self.receivers):
   spec=c['receivers'][j];link=struct.pack('<QQ',self.receivers[(j+1)%len(self.receivers)],self.receivers[(j-1)%len(self.receivers)])if c.get('backend')=='fifo'else bytes(16);self.wfixture(a,link,'Declared initial waitq circular links or singleton heap links');self.wfixture(a+0x10,bytes(8),'Declared singleton priority-node word');self.wfixture(a+0x18,struct.pack('<Q',spec.get('event',0)),'Declared wait event');self.wfixture(a+0x28,struct.pack('<Q',spec.get('waitq',PORT+0x10)),'Declared waitq identity');self.wfixture(a+0xa8,bytes(8),'Declared free receiver spin lock');self.wfixture(a+0xb0,struct.pack('<Q',0x11),'Declared receiver spin-lock type marker');self.wfixture(a+0x1f8,struct.pack('<I',spec.get('thread_state',5)),'Declared thread state bits0 and2, or blocked-state prefix')
  self.image_fixture(SCRATCH,bytes(48),'Declared unoccupied CPU0 selection scratch slots')
 def wfixture(self,a,b,why):self.wenv.append({'address':hex(a),'before_hex':bytes(self.u.mem_read(a,len(b))).hex(),'after_hex':b.hex(),'reason':why});self.fixture(a,b)
 def write(self,u,t,a,n,v,d):
  assert P<=a<a+n<=P+SIZE or SCRATCH<=a<a+n<=SCRATCH+48,(hex(a),n);e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'address':hex(a),'size_bytes':n};self.writes.append(e);self.pending.append(e)
 def code(self,u,a,n,d):
  self.flush()
  if a in[SELECT,CORE,STAGE,RESUME,SCHED,0xfffffe000bd6cfc8,0xfffffe000bd6d0b8,0xfffffe000bd6d134,0xfffffe000bd6d168,0xfffffe000bcc7dfc,0xfffffe000bcc8014,0xfffffe000bcc7de4]:
   if a==STAGE:self.current_receiver=self.reg(1)
   if a==RESUME:self.current_receiver=self.reg(0)
   r=self.current_receiver;self.wframes.append({'pc':hex(a),'source_visit_index':len(self.visits),'arguments8':[hex(self.reg(j))for j in range(8)],'thread_nesting':int.from_bytes(bytes(u.mem_read(THREAD+0x1c8,4)),'little'),'DAIF_mask':hex(u.reg_read(ar.UC_ARM64_REG_PSTATE)&0x3c0),'inner24_hex':bytes(u.mem_read(INNER,24)).hex(),'scratch48_hex':bytes(u.mem_read(SCRATCH,48)).hex(),'receiver_address':hex(r),'receiver1536_hex':bytes(u.mem_read(r,0x600)).hex()if r else None})
  if a==SELECT:self.selections+=1;return CPU.code(self,u,a,n,d)
  if a==RESUME:self.wakeups.append(hex(self.reg(0)));return CPU.code(self,u,a,n,d)
  if a==SCHED and not int.from_bytes(bytes(u.mem_read(self.reg(0)+0x1f8,4)),'little')&4:return self.stop('before_original_blocked_thread_scheduler')
  if a==0xfffffe000c62a2b0:return self.stop('before_original_waitq_or_scheduler_guard')
  return super().code(u,a,n,d)
 def run(self):
  r=super().run();r.update(configuration=self.wconfig,waitq_environment_overlays=self.wenv,waitq_frames=self.wframes,entry_DAIF_mask=hex(self.entrymask),final_DAIF_mask=hex(self.u.reg_read(ar.UC_ARM64_REG_PSTATE)&0x3c0),final_inner24_hex=bytes(self.u.mem_read(INNER,24)).hex(),final_scratch48_hex=bytes(self.u.mem_read(SCRATCH,48)).hex());return r
def main():
 im=Image();src=json.loads((ROOT/(PREFIX+'_source.json')).read_text());producer=json.loads((ROOT/'kernel_send_right_lifecycle_profiles.json').read_text())['cases'][11];configs=[{}, {'receivers':[{'capacity':44}]},{'receivers':[{'capacity':43}]},{'receivers':[{'capacity':43,'options':4}]},{'backend':'fifo','receivers':[{'capacity':43,'options':4},{'capacity':44}]},{'backend':'fifo','receivers':[{'event':1},{'capacity':44}]},{'backend':'fifo','receivers':[{'waitq':PORT+0x110},{'capacity':44}]},{'interrupt_mask':0x200,'receivers':[{'capacity':44}]},{'receivers':[{'thread_state':1,'capacity':44}]},{'interrupt_mask':0,'receivers':[{'capacity':44}]},{'backend':'fifo','receivers':[{'event':1}]}];rows=[]
 for c in configs:
  r=Probe(im,c,src,producer).run();rows.append(r);print(json.dumps({'case':len(rows)-1,'configuration':c,'visits':len(r['source_visits']),'boundary':r['boundary']['kind'],'nesting':r['final_queue_thread_nesting'],'mask':r['final_DAIF_mask']}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[PREFIX+'_source.json','kernel_send_right_lifecycle_profiles.json','kernel_kmsg_queue_profiles.json','probe_kernel_kmsg_queue.py','probe_kernel_kmsg_allocation.py','probe_kernel_notification_send.py','probe_kernel_vm_mig.py','probe_rpc502_vm_handoff.py','kernel_vm_mig_tools.py','recover_kernel_send_right_lifecycle.py']},'cases':rows,**{k:False for k in FLAGS}};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
