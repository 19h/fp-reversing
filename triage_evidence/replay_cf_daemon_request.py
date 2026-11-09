#!/usr/bin/env python3
"""Independent CF/daemon/library source replay; no CF composition-probe import.
O(image+visits+RAM+journals), O(image+RAM+journals). Primitive CF models,
logical PAC and selected cache pairing remain explicit premises.
"""
import hashlib,struct
import unicorn as uc
from unicorn import arm64_const as A
from daemon_receive_tools import CS
from replay_daemon_request_application import Replay as Parent
from replay_daemon_request_consumption import B,USER,OOL,REPLY,OBJ,STACK,STACK_SIZE,HALT
from recover_cf_daemon_request import HELPERS
from recover_cf_receive import DO_SOURCE,PERFORM
RL=B+0xa0000;MODE=B+0xa4000;SRC=B+0xa8000;OUT=B+0xac000;ALLOC=B+0xb0000;GUARD=B+0xb2000;CF_STACK=0x60000f0000
class Replay(Parent):
 def __init__(self,p,origin,source):
  self.setting_up=True;super().__init__(p,origin,source);self.cfi=0;self.cpi=0
  for row in source['CF_original_pages']:
   a=int(row['address'],16);self.u.mem_map(a,4096);self.u.mem_write(a,bytes.fromhex(row['bytes_hex']))
  plan=[(a,bytes(n))for a,n in((OBJ,160),(RL,8192),(MODE,128),(SRC,256))]+[(a,struct.pack('<Q',v))for a,v in((OBJ+0x30,0x100425f78),(SRC+8,8),(SRC+0x70,OBJ),(SRC+0xa8,PERFORM),(GUARD,0x6a39c82e1d4075b0))]+[(OUT,b'\xa5'*8)]
  assert p['CF_initial_private_overlays']==[{'address':hex(a),'bytes_hex':b.hex()}for a,b in plan]
  for a,b in plan:self.u.mem_write(a,b)
  gl=[(0x1ed891742,b'\x02'),(0x1e01c88a8,struct.pack('<Q',GUARD)),(0x1e0261ea0,struct.pack('<Q',ALLOC)),(0x1e21210e0,struct.pack('<Q',CF_STACK))]
  assert len(p['CF_runtime_global_overlays'])==len(gl)
  for(a,b),e in zip(gl,p['CF_runtime_global_overlays'],strict=True):assert e['address']==hex(a)and e['before_hex']==bytes(self.u.mem_read(a,len(b))).hex()and e['after_hex']==b.hex();self.u.mem_write(a,b)
  self.imports[CF_STACK]='framework/private_stack_probe'
  for j in range(31):self.setreg(j,0)
  for j,v in enumerate((RL,MODE,SRC,USER,80,OUT)):self.setreg(j,v)
  self.setreg(30,HALT);self.u.reg_write(A.UC_ARM64_REG_SP,STACK+0x78000);self.u.reg_write(A.UC_ARM64_REG_NZCV,0x40000000);self.setting_up=False;self.check_frame(p['entry']);self.counts['independent_CF_private_and_global_fixture_bytes_checked']+=sum(len(b)for a,b in plan+gl)
 def check_frame(self,f):
  if not getattr(self,'setting_up',False):return super().check_frame(f)
 def hook(self,u,a,n,d):
  self.finish_writes()
  if self.cfi<len(self.p['CF_frames']):
   f=self.p['CF_frames'][self.cfi]
   if f['pc']==hex(a)and f['source_visit_index']==self.seq:
    self.check_frame(f)
    for at,size,key in((USER,148,'user148_hex'),(OUT,8,'generic_reply8_hex'),(OBJ,160,'CF_object160_hex'),(SRC,256,'source256_hex')):assert f[key]==bytes(u.mem_read(at,size)).hex()
    self.cfi+=1;self.counts['CF_daemon_complete_ABI_object_and_message_frames_checked']+=1
  if a==HALT:
   assert self.seq==len(self.p['source_visits'])and self.p['boundary']['kind']=='CF_source_returned';self.check_frame(self.p['boundary']);self.done=True;u.emu_stop();return
  if a==CF_STACK or a in HELPERS:
   e=self.p['imports'][self.mi];self.mi+=1;assert e['pc']==hex(a)and e['before_source_visit_index']==self.seq;self.check_frame(e['before']);target=self.reg(30);assert e['return_pc']==hex(target)
   if a==CF_STACK:assert e['name']=='framework/private_stack_probe'and e['result']is None
   else:
    assert e['name']==HELPERS[a];result=self.reg(0)if a==0x1846db030 else 0;assert e['result']==hex(result)
    for j in range(18):self.setreg(j,((j+1)*0x123456789abcdef)^0x8b3dc651)
    self.setreg(0,result);u.reg_write(A.UC_ARM64_REG_NZCV,0xf0000000)
   u.reg_write(A.UC_ARM64_REG_PC,target);self.check_frame(e['after']);self.counts['explicit_CF_primitive_and_stack_contracts_checked']+=1;return
  f=next((f for f in self.source['CF_functions']if int(f['start'],16)<=a<int(f['end'],16)),None)
  if f:
   off=a-int(f['start'],16);raw=bytes(u.mem_read(a,4));assert raw==bytes.fromhex(f['bytes'])[off:off+4]and self.p['source_visits'][self.seq]=={'pc':hex(a),'bytes_hex':raw.hex()};current=self.seq;self.current=self.seq;self.seq+=1;self.counts['original_instruction_visits_checked']+=1;self.counts['cached_CF_instruction_visits_checked']+=1;i=next(CS.disasm(raw,a));op=i.mnemonic
   if op in('pacibsp','autibsp','paciza','autia','xpaci','retab','blraa','blraaz'):
    e=self.p['CF_logical_PAC'][self.cpi];self.cpi+=1;assert e=={'pc':hex(a),'source_visit_index':current,'mnemonic':op,'operands':i.op_str,'registers31':[hex(self.reg(j))for j in range(31)],'SP':hex(u.reg_read(A.UC_ARM64_REG_SP))};self.counts['CF_logical_authentication_inputs_checked']+=1
    if op=='retab':u.reg_write(A.UC_ARM64_REG_PC,self.reg(30))
    elif op.startswith('blr'):
     j=int(i.op_str.split(',')[0].strip()[1:]);target=self.reg(j);self.setreg(30,a+4);u.reg_write(A.UC_ARM64_REG_PC,target)
    else:u.reg_write(A.UC_ARM64_REG_PC,a+4)
   else:assert op not in('svc','hvc','smc','brk')and not op.startswith(('pac','aut','xpac'))
   return
  return super().hook(u,a,n,d)
 def run(self):
  self.u.emu_start(DO_SOURCE,0,count=30000);self.finish_writes();assert self.done and self.seq==len(self.p['source_visits'])and self.ri==len(self.p['source_reads'])and self.wi==len(self.p['source_writes'])and self.mi==len(self.p['imports'])and self.hi==len(self.p['handoffs'])and self.ai==len(self.p['application_frames'])and self.cfi==len(self.p['CF_frames'])and self.cpi==len(self.p['CF_logical_PAC'])
  assert self.application_checked==(self.p['boundary']['kind']=='before_pthread_self')
  for a,n,key in((USER,8192,'final_user8192_hex'),(OOL,16384,'final_OOL16384_hex'),(REPLY,384,'reply384_hex'),(OUT,8,'final_generic_reply8_hex'),(OBJ,160,'final_CF_object160_hex'),(SRC,256,'final_source256_hex')):assert self.p[key]==bytes(self.u.mem_read(a,n)).hex();self.counts['complete_final_buffer_bytes_checked']+=n
  for a,n,key in((B,0x100000,'final_private1048576_sha256'),(STACK,STACK_SIZE,'final_stack524288_sha256')):assert self.p[key]==hashlib.sha256(bytes(self.u.mem_read(a,n))).hexdigest();self.counts['whole_private_RAM_bytes_checked']+=n
  for e in self.p['final_CF_runtime_globals']:assert e['bytes_hex']==bytes(self.u.mem_read(int(e['address'],16),len(e['bytes_hex'])//2)).hex();self.counts['complete_CF_runtime_global_cells_checked']+=1
  if self.application_checked:assert self.p['final_argument_record120_hex']==bytes(self.u.mem_read(int(self.p['argument_record_address'],16),120)).hex()
  self.counts['final_boundaries_checked']+=1;return self.counts
