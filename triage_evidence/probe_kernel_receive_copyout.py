#!/usr/bin/env python3
"""Original receive frontend -> async wait -> sender -> continuation/results/copyout.
O(image+visits+RAM+effects), O(image+RAM+journals). Namespace/owner/map/SMR epochs,
stack/fragment inputs, byte-copy/protection outcomes, hashes and raw retirement
remain declared; no native target, IPC, VM or context-switch operation executes.
"""
import json,struct
from unicorn import arm64_const as ar
from probe_kernel_receive_continuation import Setup as BaseSetup,Dispatch as BaseDispatch,BLOCK,SELECT,RESULTS,STACK
from probe_kernel_waitq_receiver import Probe as BaseSender
from probe_kernel_waitq_enqueue import simd
from probe_kernel_vm_mig import Probe as CPU,P,SIZE,HALT
from probe_rpc502_vm_handoff import compressed,decode
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
PREFIX='kernel_receive_copyout';PORT=P+0xc0000;INNER=P+0xb5000;RECV=P+0x60000;OWNER=P+0x70000;TASK=P+0x74000;MAP=P+0x78000;USER=P+0x90000;SMR=P+0x9c000;SPACE=P+0xdd000;TABLE=0x400000100000;KMSG=P+0xd0000;MAKE=0xfffffe000bcd0694;FRONT=0xfffffe000bcdd4e4
CONFIGS=[{'interruptibility':2,'thread_limit':2,'priority':31,'has_continuation':1,'capacity':44,'receive_options':2},{'interruptibility':2,'thread_limit':2,'priority':31,'has_continuation':1,'capacity':3072,'receive_options':0x7000006},{'interruptibility':2,'thread_limit':2,'priority':31,'has_continuation':1,'capacity':44,'receive_options':2,'copyout_result':14},{'interruptibility':2,'thread_limit':2,'priority':31,'has_continuation':1,'capacity':44,'receive_options':2,'retain_file_validation':True}]
class Aux:
 def ensure(self,a,n=1):
  if TABLE<=a<a+n<=TABLE+4096:
   if TABLE not in self.pages:self.u.mem_map(TABLE,4096);self.u.mem_write(TABLE,bytes(4096));self.pages.add(TABLE)
   return
  return super().ensure(a,n)
class Setup(Aux,BaseSetup):
 def __init__(self,im,src,c,kind,base,globals,origin):
  k='port_unlock'if kind=='make_send_once'else kind;super().__init__(im,src,c,k,base,globals,origin);self.kind=kind;self.frontframes=[]
  if kind=='port_init':
   meta=int.from_bytes(bytes(self.u.mem_read(0xfffffe0007e66f00,8)),'little');owner=bytearray(56);struct.pack_into('<Q',owner,0,RECV);struct.pack_into('<Q',owner,0x28,TASK)
   extras=[(RECV+0x420,struct.pack('<Q',OWNER)),(OWNER,bytes(owner)),(TASK+0x318,struct.pack('<Q',SPACE)),(RECV+0x428,struct.pack('<Q',MAP)),(MAP+0x18,struct.pack('<Q',0xffffffffffffffff)),(MAP+0x2c,struct.pack('<I',14)),(SPACE+0x48,struct.pack('<Q',TABLE|5)),(USER,b'\xa5'*8192)]
   extras.extend((meta+((a>>10)&0xffffffff0),struct.pack('<H',kind))for a,kind in[(OWNER,3),(KMSG,24),(INNER,28)])
   for a,b in extras:self.overlay(a,b,'Declared receiver owner/task/map/namespace/typed allocation and user-buffer epoch')
   table=bytearray(4096);struct.pack_into('<QIIQ',table,24*3,PORT,0x20001,0,0);self.image_fixture(TABLE,bytes(table));self.image_fixture(0xfffffe000caac348,struct.pack('<Q',0x100));self.image_fixture(0xfffffe000caac350,struct.pack('<Q',SMR))
   if not c.get('retain_file_validation'):self.image_fixture(0xfffffe000caec6b0,bytes.fromhex(src['zone_validation_source']['bytes8_hex']))
  if kind=='make_send_once':self.entry=MAKE;self.set(0,PORT)
  if kind=='receive_wait':
   self.entry=FRONT
   for j,x in enumerate([USER,0,c['receive_options'],0,0,c['capacity'],0,0x303]):self.set(j,x)
  self.entry_regs=[hex(self.reg(j))for j in range(31)]
 def code(self,u,a,n,d):
  self.flush()
  if a in[FRONT,0xfffffe000bcc8cf4,0xfffffe000bcdd568,0xfffffe000bcdd6d0,SELECT]:self.frontframes.append({'pc':hex(a),'source_visit_index':len(self.visits),'arguments8':[hex(self.reg(j))for j in range(8)],'port144_hex':bytes(u.mem_read(PORT,144)).hex(),'receiver1536_hex':bytes(u.mem_read(RECV,1536)).hex(),'SMR_slot16_hex':bytes(u.mem_read(SMR,16)).hex()})
  if a>=0xfffffe0000000000:
   raw=bytes(u.mem_read(a,4));i=next(self.image.k.cs.disasm(raw,a))
   if i.mnemonic=='autda':assert i.op_str=='x16, x17'and raw==self.image.k.read(a,4);self.auth.append({'pc':hex(a),'pointer':hex(self.reg(16)),'modifier':hex(self.reg(17))});self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  return super().code(u,a,n,d)
 def run(self):r=super().run();r.update(frontend_frames=self.frontframes,final_user8192_hex=bytes(self.u.mem_read(USER,8192)).hex());return r
class Sender(Aux,BaseSender):pass
class Finish(Aux,BaseDispatch):
 def __init__(self,im,src,c,parent,family):
  super().__init__(im,src,c,parent,family,{});self.c={**self.c,'copyout_result':c.get('copyout_result',0)};self.copyeffects=[];self.hashes=[];self.resultframes=[]
 def code(self,u,a,n,d):
  self.flush()
  if a in[RESULTS,0xfffffe000bcdce14,0xfffffe000bcc4e98,0xfffffe000bcc62d0,0xfffffe000bcc67a4,0xfffffe000bcdcff4,0xfffffe000be80980]:self.resultframes.append({'pc':hex(a),'source_visit_index':len(self.visits),'arguments8':[hex(self.reg(j))for j in range(8)],'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'port144_hex':bytes(u.mem_read(PORT,144)).hex(),'inner96_hex':bytes(u.mem_read(INNER,96)).hex(),'receiver1536_hex':bytes(u.mem_read(RECV,1536)).hex(),'user8192_hex':bytes(u.mem_read(USER,8192)).hex(),'result_record40_hex':bytes(u.mem_read(self.reg(2),40)).hex()if a==0xfffffe000bcc62d0 else None})
  if a>=0xfffffe0000000000 and a!=0xfffffe000bc9c314:
   raw=bytes(u.mem_read(a,4));i=next(self.image.k.cs.disasm(raw,a))
   if i.mnemonic=='autda':assert i.op_str=='x16, x17'and raw==self.image.k.read(a,4);self.auth.append({'pc':hex(a),'pointer':hex(self.reg(16)),'modifier':hex(self.reg(17))});self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  if a==RESULTS:return CPU.code(self,u,a,n,d)
  if a==0xfffffe000be80980:return self.stop('before_original_return_to_user')
  if a==0xfffffe000be7798c:
   src,dst,count=self.reg(0),self.reg(1),self.reg(2);result=self.c['copyout_result'];e={'pc':hex(a),'before_source_visit_index':len(self.visits),'source':hex(src),'destination':hex(dst),'size_bytes':count,'source_hex':bytes(u.mem_read(src,count)).hex(),'before_hex':bytes(u.mem_read(dst,count)).hex(),'result':hex(result)};assert USER<=dst<=dst+count<=USER+8192
   if not result:u.mem_write(dst,bytes(u.mem_read(src,count)))
   e['after_hex']=bytes(u.mem_read(dst,count)).hex();self.copyeffects.append(e);return self.model(a,'declared_user_copyout_effect',result)
  if a==0xfffffe000bc9d90c:self.hashes.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments4':[hex(self.reg(j))for j in range(4)],'bytes_hex':bytes(u.mem_read(self.reg(0),self.reg(1))).hex()});return self.model(a,'opaque_keyed_hash_result',0x123456789abcdef0)
  if a==0xfffffe000bd74fcc:return self.model(a,'declared_raw_zone_deallocation',0)
  if a in[0xfffffe000c6298e4,0xfffffe000c633aa0,0xfffffe000c641fa8,0xfffffe000c641fd8,0xfffffe000c629938]:return self.stop('before_original_copyout_validation_guard')
  return super().code(u,a,n,d)
 def run(self):r=super().run();r.update(user_copyout_effects=self.copyeffects,opaque_copyout_hash_inputs=self.hashes,receive_results_frames=self.resultframes,final_user8192_hex=bytes(self.u.mem_read(USER,8192)).hex());return r
def main():
 im=Image();src=json.loads((ROOT/(PREFIX+'_source.json')).read_text());ns=json.loads((ROOT/'kernel_send_right_lifecycle_profiles.json').read_text())['cases'][11];seed=json.loads((ROOT/'kernel_waitq_receiver_profiles.json').read_text())['cases'][1];up=json.loads((ROOT/'kernel_waitq_enqueue_profiles.json').read_text());base=decode(up['cases'][0]['initial_state_transfer']);rows=[];consumers=[];finishes=[]
 for family,c in enumerate(CONFIGS):
  ram=base;globals=seed['initial_image_fixtures'];origin={'path':'kernel_waitq_enqueue_profiles.json','case':0,'epoch':'Prepared producer entry'}
  for kind in['port_init','port_unlock','turnstile_allocate','make_send_once','receive_wait']:
   r=Setup(im,src,c,kind,ram,globals,origin).run();r['family']=family;rows.append(r);ram=decode(r['final_private_RAM']);globals=r['final_image_globals'];origin={'path':PREFIX+'_profiles.json','case':len(rows)-1};print(json.dumps({'case':len(rows)-1,'family':family,'kind':kind,'visits':len(r['source_visits']),'boundary':r['boundary']['kind']}),flush=True)
  sender=Sender(im,{'receivers':[{'capacity':c['capacity']}],'interrupt_mask':0x3c0},src,ns);sender.u.mem_write(P,ram);sender.image_initial=[]
  for e in globals:sender.image_fixture(int(e['address'],16),bytes.fromhex(e['bytes_hex']),'Exact original frontend/ownership producer global transfer')
  r=sender.run();metadata={k:r.pop(k)for k in['memory_overlays','allocation_environment_overlays','queue_environment_overlays','waitq_environment_overlays','initial_private_fixtures']};r.update(initial_state_transfer={**origin,**compressed(ram)},initial_private_fixtures=[],preparation_metadata_not_reapplied=metadata,family=family,producer_configuration=c);consumers.append(r);print(json.dumps({'consumer':family,'visits':len(r['source_visits']),'boundary':r['boundary']['kind']}),flush=True)
  r=Finish(im,src,c,consumers[family],family).run();r['initial_state_transfer']['path']=PREFIX+'_profiles.json';finishes.append(r);print(json.dumps({'finish':family,'visits':len(r['source_visits']),'boundary':r['boundary']['kind'],'pc':r['boundary']['pc']}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[PREFIX+'_source.json','kernel_receive_continuation_profiles.json','kernel_waitq_enqueue_profiles.json','kernel_waitq_receiver_profiles.json','kernel_send_right_lifecycle_profiles.json','probe_kernel_receive_continuation.py','probe_kernel_waitq_enqueue.py','probe_kernel_waitq_receiver.py','probe_kernel_kmsg_queue.py','probe_kernel_kmsg_allocation.py','probe_kernel_notification_send.py','probe_kernel_vm_mig.py','probe_rpc502_vm_handoff.py','kernel_vm_mig_tools.py']},'cases':rows,'consumers':consumers,'finishes':finishes,**{k:False for k in FLAGS}};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
