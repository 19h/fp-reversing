#!/usr/bin/env python3
"""Original post-dispatch reply-send components with actual trailer setup.
Entry frames, storage/destination objects and helper/hash/send returns are
explicit private models. No native kernel, queue, MAC, IPC or PAC executes.
O(cases*source visits) time, O(one private map+journals) space.
"""
import json,struct
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT
from capture_daemon_record720 import sha
from probe_kernel_vm_mig import Probe as Base,P,SIZE,HALT,SP
from kernel_vm_mig_tools import Image
from recover_kernel_reply_send import SEND,TRAILER_INIT,TRAILER_PTR,HASH_FN,DISPATCH,LOCK,UNLOCK,PREFLIGHT,QUEUE,FAILURE,DESTROY,FINAL_REF
REQ=P+0x10000;REPLY=P+0x12000;HEADER=P+0x14000;DATA=P+0x16000;DEST=P+0x18000;INPORT=P+0x1a000;THREAD=P+0x1c000;KSPACE=P+0x20000;USPACE=P+0x22000
class Probe(Base):
 def __init__(self,image,config):
  super().__init__(image,'stub',{'port_class':'null','bits':0,'request_size':56,'address':0,'size':0,'body_placement':'joined'});self.u.mem_write(P,bytes(SIZE));self.initial=[];self.kind=config['kind'];self.c=config;self.hashes=[];self.logical_auth=[];self.dispatches=0;self.allowed=[(SEND,0xfffffe000bcc751c),(TRAILER_INIT,0xfffffe000bcc42f0),(TRAILER_PTR,0xfffffe000bcc219c)]
  for j in range(31):self.set(j,0)
  self.fixture(SP+0x58,struct.pack('<Q',HALT));self.fixture(REPLY+0x3f,bytes([config['storage_class']<<6]));self.fixture(REPLY+0xe8,struct.pack('<Q',HEADER));self.fixture(REPLY+0xf0,struct.pack('<Q',DATA));header=REPLY+0x40 if config['storage_class']<2 else HEADER;self.header=header;body=DATA if config['storage_class']&1 else header+32;self.trailer=body+12;self.fixture(header,struct.pack('<IIQQII',0x12,44,DEST,0,0,4901));self.fixture(body,bytes.fromhex('0000000001000000')+struct.pack('<I',0));self.fixture(self.trailer,bytes([0xa5])*68);self.fixture(DEST+1,bytes([config['dest_low3']]));self.fixture(DEST+4,struct.pack('<I',config['object_refs']));self.fixture(DEST+0x48,struct.pack('<Q',USPACE));self.set(19,REQ);self.set(20,INPORT);self.set(21,config['effective_options']);self.set(22,config['inherited_scalar']);self.set(23,THREAD);self.set(24,0);self.set(26,0);self.set(30,HALT);self.u.reg_write(ar.UC_ARM64_REG_SP,SP)
  self.ensure(0xfffffe0007e62b68,8);self.u.mem_write(0xfffffe0007e62b68,struct.pack('<Q',KSPACE));self.image_initial=[{'address':'0xfffffe0007e62b68','bytes_hex':struct.pack('<Q',KSPACE).hex(),'provenance':'declared kernel-space pointer; native value unknown'}]
  if self.kind=='cleanup':self.entry=0xfffffe000bcc7254;self.set(19,REPLY);self.set(20,DEST);self.set(24,config['queue_status']);self.set(26,config['reply_mode'])
  else:self.entry=0xfffffe000bcc7338 if config['route']=='A'else 0xfffffe000bcc73a0
  self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV))
 def code(self,u,a,n,d):
  from unicorn import arm64_const as ar
  self.flush()
  if a==HALT:return self.stop('returned')
  if a==DISPATCH:
   self.dispatches+=1
   if self.dispatches>1:return self.stop('before_nested_dispatch')
   return self.model(a,'kernel_object_dispatch_model',0 if self.c['null_reply']else REPLY)
  if a==HASH_FN:
   payload=bytes(u.mem_read(self.reg(0),self.reg(1))).hex();event={'pc':hex(a),'before_source_visit_index':len(self.visits),'address':hex(self.reg(0)),'size_bytes':self.reg(1),'bytes_hex':payload,'seed':hex(self.reg(2)),'mode':self.reg(3)};self.hashes.append(event);value=[0x123456789abcdef0,0xfedcba9876543210][len(self.hashes)-1];return self.model(a,'opaque_hash_return_model',value)
  callbacks={LOCK:('destination_lock_model',0),UNLOCK:('destination_unlock_model',0),PREFLIGHT:('send_preflight_model',self.c.get('preflight_status',0)),QUEUE:('queue_send_model',self.c['queue_status']),FAILURE:('send_failure_helper_model',0),DESTROY:('message_destroy_model',0),FINAL_REF:('last_object_reference_model',0)}
  if a in callbacks:return self.model(a,*callbacks[a])
  if not any(x<=a<z for x,z in self.allowed):return self.stop('before_unmodeled_code')
  raw=bytes(u.mem_read(a,4));assert raw==self.image.k.read(a,4);ins=next(self.image.k.cs.disasm(raw,a));self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()})
  if ins.mnemonic in ['pacibsp','autibsp']:u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  elif ins.mnemonic=='autda':self.logical_auth.append({'pc':hex(a),'pointer':hex(self.reg(16)),'modifier':hex(self.reg(17)),'native_authentication_executed':False});u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  elif ins.mnemonic=='retab':u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30))
  assert ins.mnemonic not in ['svc','hvc','smc','blraa','brk'],(hex(a),ins.mnemonic)
 def run(self):
  r=super().run();r['opaque_hash_inputs']=self.hashes;r['logical_data_authentication']=self.logical_auth;r['reply_header']=hex(self.header);r['reply_trailer']={'address':hex(self.trailer),'bytes_hex':bytes(self.u.mem_read(self.trailer,68)).hex()};r['reply_signature_word']=bytes(self.u.mem_read(REPLY+0x38,4)).hex();r['destination_counter']=int.from_bytes(bytes(self.u.mem_read(DEST+4,4)),'little');return r
def main():
 image=Image();rows=[];base={'kind':'reply','route':'A','storage_class':0,'dest_low3':3,'object_refs':2,'effective_options':0x10001,'inherited_scalar':0,'preflight_status':0,'queue_status':0,'null_reply':False}
 for route in ['A','B']:
  cfg={**base,'route':route,'null_reply':True};rows.append(Probe(image,cfg).run())
  for cls in range(4):
   for refs in [1,2]:
    for low,status in [(0,0),*[(3,x)for x in [0,5,0x10000003,0x10000004,0x10000007,0x1000000d]]]:
     cfg={**base,'route':route,'storage_class':cls,'dest_low3':low,'object_refs':refs,'queue_status':status,'effective_options':0x10001 if cls&1==0 else 0x400003,'inherited_scalar':cls*7+1};r=Probe(image,cfg).run();rows.append(r)
 for flag in [0,1]:
  for refs in [1,2]:
   for status in [0,5,0x10000003,0x10000004,0x10000007,0x1000000d]:
    cfg={**base,'kind':'cleanup','reply_mode':flag,'object_refs':refs,'queue_status':status};rows.append(Probe(image,cfg).run())
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['kernel_reply_send_source.json','probe_kernel_vm_mig.py','kernel_vm_mig_tools.py']},'kernel_sha256':image.k.sha256,'cases':rows,'native_target_executed':False,'native_IPC_executed':False,'native_MAC_or_PAC_executed':False,'full_goal_complete':False};(ROOT/'kernel_reply_send_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'visits':sum(len(r['source_visits'])for r in rows),'boundaries':sorted(set(r['boundary']['kind']for r in rows))}),flush=True)
if __name__=='__main__':main()
