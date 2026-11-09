#!/usr/bin/env python3
"""Fresh-CPU original run-loop replay without importing the run-loop probe.
O(image+visits+RAM+journals) time/space. Shared frozen loader, explicit helper
contracts and logical authentication; no native IPC, TSD or thread execution.
"""
import base64,hashlib,struct,zlib
from unicorn import arm64_const as A
from daemon_receive_tools import CS
from replay_cf_daemon_request import Replay as Parent,B,USER,OOL,REPLY,OBJ,RL,MODE,SRC,OUT,HALT,CF_STACK
from recover_cf_daemon_request import HELPERS
from recover_cf_runloop_handoff import CacheView,initial_max_engine
from recover_cf_receive import RUN
from recover_dispatch_voucher_hooks import DISPATCH_INIT
from recover_cf_receive_voucher import MACH
LOW=B-0x200000;LOW_SIZE=0x200000;ENTRY_SP=USER+0xc80;RUN_SP=USER-0xd0;DICT=B+0xad000
MODELS={0x18054808c:100,0x180588804:0,0x184832bc8:0,0x184758240:0,0x184758504:0,0x18471b500:0,0x1846ddde4:0,0x1846ddc8c:SRC,MACH:0}
def unpack(e,address,size):
 b=zlib.decompress(base64.b64decode(e['zlib_base64']));assert e['address']==hex(address)and len(b)==e['size_bytes']==size and hashlib.sha256(b).hexdigest()==e['sha256'];return b
class Replay(Parent):
 def __init__(self,p,k,source):
  self.defer_frame=True;super().__init__(p,k,source);self.u=initial_max_engine(self.u,self.hook,self.read_hook,self.write_hook);self.u.mem_map(LOW,LOW_SIZE);self.u.mem_write(LOW,b'\xa5'*LOW_SIZE)
  self.u.mem_write(USER,b'\xa5'*8192);self.u.mem_write(OOL,b'\xa5'*16384);self.u.mem_write(MODE,bytes(512));self.u.mem_write(MODE+0x80,struct.pack('<Q',DICT));self.u.mem_write(MODE+0x88,struct.pack('<I',int(k['receive_name'],16)));self.u.mem_write(DICT,bytes(64))
  for a,v in CacheView(source).pointers.items():self.u.mem_write(a,struct.pack('<Q',v))
  for j in range(31):self.setreg(j,0)
  self.setreg(30,HALT);self.u.reg_write(A.UC_ARM64_REG_SP,ENTRY_SP);self.u.reg_write(A.UC_ARM64_REG_NZCV,0x40000000);self.defer_frame=False;self.check_frame(p['entry']);self.transition=False;self.rfi=self.rmi=self.kti=0
 def check_frame(self,f):
  if not getattr(self,'defer_frame',False):return super().check_frame(f)
 def check_run_frame(self,f):
  self.check_frame(f)
  for a,n,key in((RUN_SP+0x68,8,'native_buffer_pointer8_hex'),(RUN_SP+0x64,4,'native_live_name4_hex'),(RUN_SP+0x50,8,'native_reply8_hex'),(RUN_SP+0x78,8,'native_voucher_state8_hex'),(RUN_SP+0x70,8,'native_voucher_copy8_hex'),(USER,148,'user148_hex')):assert f[key]==bytes(self.u.mem_read(a,n)).hex()
  self.counts['original_runloop_frame_and_local_buffer_checks']+=1
 def hook(self,u,a,n,d):
  self.finish_writes()
  if a==HALT and not self.transition:
   e=self.p['initializer_handoff'];self.check_frame(e['before']);assert self.seq==11 and self.reg(0)==0
   for at,size,key in((B,0x100000,'private_RAM_sha256'),(LOW,LOW_SIZE,'lower_stack_sha256')):assert e[key]==hashlib.sha256(bytes(u.mem_read(at,size))).hexdigest()
   for j,v in enumerate((RL,MODE,1)):self.setreg(j,v)
   self.setreg(30,HALT);u.reg_write(A.UC_ARM64_REG_Q0,0x7ff0000000000000);u.reg_write(A.UC_ARM64_REG_PC,RUN);self.check_frame(e['after']);self.transition=True;self.counts['initializer_return_and_public_runloop_entry_handoffs_checked']+=1;return
  if self.rfi<len(self.p['runloop_frames']):
   f=self.p['runloop_frames'][self.rfi]
   if f['pc']==hex(a)and f['source_visit_index']==self.seq:self.check_run_frame(f);self.rfi+=1
  if a in MODELS:
   e=self.p['imports'][self.mi];self.mi+=1;assert e==self.p['runloop_models'][self.rmi];self.rmi+=1;assert e['pc']==hex(a)and e['before_source_visit_index']==self.seq;self.check_frame(e['before']);target=self.reg(30);assert e['return_pc']==hex(target);value=MODELS[a];patches=[]
   if a==0x1846ddc8c:assert self.reg(0)==DICT;value=SRC if self.reg(1)==int(self.origin['receive_name'],16)else 0
   if a==MACH:
    assert[self.reg(j)for j in range(7)]==[USER,0x07000806,0,3072,int(self.origin['receive_name'],16),0xffffffff,0];self.check_run_frame(self.p['kernel_transfers'][self.kti]);self.kti+=1;patches=[(USER,bytes.fromhex(self.origin['final_user8192_hex'])[:148]),(OOL,bytes.fromhex(self.origin['final_OOL16384_hex'])[:29])]
   assert e['result']==hex(value)and len(e['patches'])==len(patches)
   for(at,raw),saved in zip(patches,e['patches'],strict=True):assert saved=={'address':hex(at),'before_hex':bytes(u.mem_read(at,len(raw))).hex(),'after_hex':raw.hex()};u.mem_write(at,raw);self.counts['kernel_return_transfer_bytes_checked']+=len(raw)
   for j in range(18):self.setreg(j,((j+1)*0x123456789abcdef)^0x8b3dc651)
   self.setreg(0,value);u.reg_write(A.UC_ARM64_REG_NZCV,0xf0000000)
   if a==0x18471b500:u.reg_write(A.UC_ARM64_REG_Q0,0)
   u.reg_write(A.UC_ARM64_REG_PC,target);self.check_frame(e['after']);self.counts['declared_runloop_runtime_contracts_checked']+=1;return
  if self.cfi<len(self.p['CF_frames']):
   f=self.p['CF_frames'][self.cfi]
   if f['pc']==hex(a)and f['source_visit_index']==self.seq:
    self.check_frame(f)
    for at,size,key in((USER,148,'user148_hex'),(OUT,8,'generic_reply8_hex'),(OBJ,160,'CF_object160_hex'),(SRC,256,'source256_hex')):assert f[key]==bytes(u.mem_read(at,size)).hex()
    self.cfi+=1;self.counts['CF_daemon_complete_ABI_object_and_message_frames_checked']+=1
  if a==HALT:
   assert self.p['boundary']['kind']=='original_runloop_returned'and self.seq==len(self.p['source_visits']);self.check_frame(self.p['boundary']);self.done=True;u.emu_stop();return
  if a==CF_STACK or a in HELPERS:return super().hook(u,a,n,d)
  f=next((f for f in self.source['CF_functions']+self.source['import_stubs']if int(f['start'],16)<=a<int(f['end'],16)),None)
  if f:
   raw=bytes(u.mem_read(a,4));off=a-int(f['start'],16);assert raw==bytes.fromhex(f['bytes'])[off:off+4]and self.p['source_visits'][self.seq]=={'pc':hex(a),'bytes_hex':raw.hex()};self.current=self.seq;self.seq+=1;self.counts['original_instruction_visits_checked']+=1;self.counts['cache_instruction_visits_checked']+=1;i=next(CS.disasm(raw,a));op=i.mnemonic
   if op in('pacibsp','autibsp','paciza','autia','xpaci'):u.reg_write(A.UC_ARM64_REG_PC,a+4);self.counts['logical_authentication_steps_checked']+=1
   elif op=='retab':u.reg_write(A.UC_ARM64_REG_PC,self.reg(30));self.counts['logical_authentication_steps_checked']+=1
   elif op in('braa','braaz','blraa','blraaz'):
    j=int(i.op_str.split(',')[0].strip()[1:]);target=self.reg(j)
    if op.startswith('blr'):self.setreg(30,a+4)
    u.reg_write(A.UC_ARM64_REG_PC,target);self.counts['logical_authentication_steps_checked']+=1
   else:assert op not in('svc','hvc','smc','brk','mrs','msr')and not op.startswith(('pac','aut','xpac'))
   return
  return super().hook(u,a,n,d)
 def run(self):
  self.u.emu_start(DISPATCH_INIT,0,count=30000);self.finish_writes();assert self.done and self.transition and self.seq==len(self.p['source_visits'])and self.ri==len(self.p['source_reads'])and self.wi==len(self.p['source_writes'])and self.mi==len(self.p['imports'])and self.hi==len(self.p['handoffs'])and self.ai==len(self.p['application_frames'])and self.cfi==len(self.p['CF_frames'])and self.rmi==len(self.p['runloop_models'])and self.rfi==len(self.p['runloop_frames'])and self.kti==len(self.p['kernel_transfers'])==1 and not self.p['CF_logical_PAC']
  for at,size,key in((B,0x100000,'final_private_RAM'),(LOW,LOW_SIZE,'final_lower_stack')):assert unpack(self.p[key],at,size)==bytes(self.u.mem_read(at,size));self.counts['whole_final_private_RAM_bytes_checked']+=size
  for a,n,key in((USER,8192,'final_user8192_hex'),(OOL,16384,'final_OOL16384_hex'),(REPLY,384,'reply384_hex')):assert self.p[key]==bytes(self.u.mem_read(a,n)).hex();self.counts['complete_final_buffer_bytes_checked']+=n
  if self.application_checked:assert self.p['final_argument_record120_hex']==bytes(self.u.mem_read(int(self.p['argument_record_address'],16),120)).hex()
  assert self.application_checked==(self.p['boundary']['kind']=='before_pthread_self');self.counts['final_boundaries_checked']+=1;return dict(self.counts)
