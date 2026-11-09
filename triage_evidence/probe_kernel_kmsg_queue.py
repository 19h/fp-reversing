#!/usr/bin/env python3
"""Actual no-senders producer through original construction, queue and caller return.
O(visits+RAM+effects), O(image+RAM+journals). Port/owner/receiver/queue epochs and
waitq selection/wakeup, preflight/hash/tag/copy/destruction remain explicit models.
"""
import json,struct
from unicorn import arm64_const as ar
from probe_kernel_kmsg_allocation import NotificationProbe as Parent
from probe_kernel_vm_mig import Probe as CPU,P,SIZE
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
PREFIX='kernel_kmsg_queue';QUEUE=0xfffffe000bcc7c34;PORTLOCK=0xfffffe000bccc128;UNLOCK=0xfffffe000bd0ab18;KMSG=P+0xd0000;PORT=P+0xc0000;MQ=PORT+0x28;THREAD=P+0x2c000;OWNER=P+0x30000;TASK=P+0x3c000;QSTATS=P+0xb9000;RECV=P+0x60000;OLD=P+0xd8000
class Probe(Parent):
 def __init__(self,im,c,src,producer):
  super().__init__(im,{'phase':'notification','storage_class':0,**c},src,producer);self.qconfig=c;self.qenv=[];self.qframes=[];self.qvariant=None;self.selections=0;self.wakeups=[];self.receivers=[]
  self.qfixture(PORT+0x14,struct.pack('<I',0x144),'Declared initialized valid port ticket lock');self.qfixture(MQ+8,struct.pack('<IIHH',7,0x303,c.get('count',c.get('old_messages',0)),c.get('limit',16)),'Declared sequence, opaque receive-identity word, count and limit');self.qfixture(THREAD+0x420,struct.pack('<Q',OWNER),'Declared current-thread owner link');self.qfixture(OWNER,struct.pack('<Q',THREAD),'Declared owner backlink');self.qfixture(OWNER+0x28,struct.pack('<Q',TASK),'Declared owner task pointer');self.qfixture(TASK+0x3d0,struct.pack('<Q',QSTATS),'Declared per-CPU task send-accounting base');self.qfixture(QSTATS,bytes(8),'Declared selected task send counter');self.qfixture(THREAD+0x211,b'\0','Declared no waitq cleanup work flag')
  meta_base=int.from_bytes(bytes(self.u.mem_read(0xfffffe0007e66f00,8)),'little')
  for a,kind in[(PORT,22),(OWNER,3)]:self.qfixture(meta_base+((a>>10)&0xffffffff0),struct.pack('<H',kind),'Declared allocation/type metadata for port or owner')
  self.image_fixture(0xfffffe0007e66ea0,struct.pack('<QQ',P,P+SIZE),'Declared owner address bounds');self.image_fixture(0xfffffe0007e6d038,struct.pack('<I',0x40000),'Declared owner geometry multiplier from earlier task accessor component')
  n=c.get('old_messages',0)
  if n:
   self.qfixture(MQ,struct.pack('<Q',OLD),'Declared nonempty circular queue head')
   for j in range(n):
    raw=bytearray(256);struct.pack_into('<QQ',raw,0,OLD+((j+1)%n)*0x100,OLD+((j-1)%n)*0x100);raw[0x3e]=[2,5][j];self.qfixture(OLD+j*0x100,bytes(raw),'Declared prior circular queue element')
  for j,spec in enumerate(c.get('receivers',[])):
   a=RECV+j*0x1000;self.receivers.append(a);raw=bytearray(0x600);struct.pack_into('<II',raw,0x388,spec.get('capacity',44),spec.get('aux_capacity',0));struct.pack_into('<Q',raw,0x390,spec.get('options',0));struct.pack_into('<I',raw,0x3a0,spec.get('state',0x10004001));self.qfixture(a,bytes(raw),'Declared receiver wait state, options and receive capacities')
 def qfixture(self,a,b,why):self.qenv.append({'address':hex(a),'before_hex':bytes(self.u.mem_read(a,len(b))).hex(),'after_hex':b.hex(),'reason':why});self.fixture(a,b)
 def code(self,u,a,n,d):
  self.flush()
  if a==QUEUE and self.qvariant is None:
   before=[hex(self.reg(j))for j in range(4)];patches=[];regs=[]
   for j,key in[(2,'queue_options'),(3,'timeout')]:
    if key in self.qconfig:regs.append({'register':'X'+str(j),'before':hex(self.reg(j)),'after':hex(self.qconfig[key])});self.set(j,self.qconfig[key])
   for ptr,b in ([(KMSG+0x40,struct.pack('<I',(int.from_bytes(bytes(u.mem_read(KMSG+0x40,4)),'little')&~31)|self.qconfig['disposition']))]if'disposition'in self.qconfig else[])+([(KMSG+0x3e,bytes([self.qconfig['priority']]))]if'priority'in self.qconfig else[]):
    patches.append({'address':hex(ptr),'before_hex':bytes(u.mem_read(ptr,len(b))).hex(),'after_hex':b.hex()});u.mem_write(ptr,b)
   self.qvariant={'pc':hex(a),'before_source_visit_index':len(self.visits),'before_arguments4':before,'after_arguments4':[hex(self.reg(j))for j in range(4)],'registers':regs,'patches':patches,'interpretation':'Controlled queue-entry ABI/internal-header variants; no new authentic notification input is asserted'}
  if a in[QUEUE,PORTLOCK,0xfffffe000bcc2bc4,0xfffffe000bcc4bb4,0xfffffe000bcc2068,0xfffffe000bcc7ed4,0xfffffe000bcc81f0,0xfffffe000bcc822c]:self.qframes.append({'pc':hex(a),'source_visit_index':len(self.visits),'arguments8':[hex(self.reg(j))for j in range(8)],'port144_hex':bytes(u.mem_read(PORT,144)).hex(),'kmsg64_hex':bytes(u.mem_read(KMSG,64)).hex(),'task_send_counter':int.from_bytes(bytes(u.mem_read(QSTATS,8)),'little'),'thread_nesting':int.from_bytes(bytes(u.mem_read(THREAD+0x1c8,4)),'little')})
  if a in[QUEUE,PORTLOCK,UNLOCK]:return CPU.code(self,u,a,n,d)
  if a==0xfffffe000bd6cf80:
   assert self.reg(0)==PORT+0x10;idx=self.selections;self.selections+=1;return self.model(a,'declared_waitq_receiver_selection',self.receivers[idx]if idx<len(self.receivers)else 0)
  if a==0xfffffe000bd6d0d4:self.wakeups.append(hex(self.reg(0)));return self.model(a,'declared_waitq_receiver_wakeup',0)
  if a==0xfffffe000bcca948:return self.stop('before_original_large_queue_policy')
  if a in[0xfffffe000bd68474,0xfffffe000bd6e0fc,0xfffffe000bd6e22c]:return self.stop('before_original_sender_wait_or_wakeup')
  if a in[0xfffffe000c6340d8,0xfffffe000c6340fc,0xfffffe000c6343c0,0xfffffe000bd0abac,0xfffffe000c63aec8]:return self.stop('before_original_type_lock_or_nesting_guard')
  return super().code(u,a,n,d)
 def run(self):
  r=super().run();r.update(configuration=self.qconfig,generator_component='actual_notification_queue',queue_environment_overlays=self.qenv,queue_entry_variant=self.qvariant,queue_frames=self.qframes,waitq_selections=self.selections,waitq_wakeup_arguments=self.wakeups,final_queue_task_send_counter=int.from_bytes(bytes(self.u.mem_read(QSTATS,8)),'little'),final_queue_thread_nesting=int.from_bytes(bytes(self.u.mem_read(THREAD+0x1c8,4)),'little'),final_queue_receivers=[{'address':hex(a),'bytes1536_hex':bytes(self.u.mem_read(a,0x600)).hex()}for a in self.receivers],final_old_queue_elements=[{'address':hex(OLD+j*0x100),'bytes256_hex':bytes(self.u.mem_read(OLD+j*0x100,256)).hex()}for j in range(self.qconfig.get('old_messages',0))]);return r
def main():
 im=Image();src=json.loads((ROOT/(PREFIX+'_source.json')).read_text());producer=json.loads((ROOT/'kernel_send_right_lifecycle_profiles.json').read_text())['cases'][11];configs=[{}, {'old_messages':2},{'old_messages':2,'priority':7},{'receivers':[{'capacity':44}]},{'receivers':[{'capacity':43}]},{'receivers':[{'capacity':43,'options':4}]},{'receivers':[{'capacity':43,'options':4},{'capacity':44}]},{'receivers':[{'capacity':48,'options':1<<24}]},{'count':1,'limit':1},{'count':1,'limit':1,'queue_options':0x10,'disposition':17},{'count':0xfffe,'limit':0xfffe},{'count':0xfffe,'limit':0xfffe,'queue_options':0x10},{'count':0xfffd,'limit':0xfffd},{'count':1,'limit':1,'queue_options':0},{'count':1,'limit':1,'queue_options':0,'disposition':17},{'count':0xfffe,'limit':0xffff}];rows=[]
 for c in configs:
  r=Probe(im,c,src,producer).run();rows.append(r);print(json.dumps({'case':len(rows)-1,'configuration':c,'visits':len(r['source_visits']),'boundary':r['boundary']['kind'],'count':int.from_bytes(bytes.fromhex(r['final_destination144_hex'])[0x38:0x3a],'little'),'task_send_counter':r['final_queue_task_send_counter']}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[PREFIX+'_source.json','kernel_send_right_lifecycle_profiles.json','kernel_kmsg_allocation_profiles.json','probe_kernel_kmsg_allocation.py','probe_kernel_notification_send.py','probe_kernel_vm_mig.py','probe_rpc502_vm_handoff.py','kernel_vm_mig_tools.py','recover_kernel_send_right_lifecycle.py']},'cases':rows,**{k:False for k in FLAGS}};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
