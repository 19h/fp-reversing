#!/usr/bin/env python3
"""Independent original-cache receive/voucher replay and exact kernel transfers.
No consumer-probe import. O(image+visits+RAM+journals), O(image+RAM+journals).
Mach/task transfer remains a contract; no native operations or hardware PAC.
"""
from unicorn import arm64_const as A
from replay_kernel_vm_mig import Replay as Parent
from replay_rpc502_vm_handoff import decode
from recover_cf_receive_voucher import MACH,INIT,ROOTCELL
from recover_cf_receive import SERVICE
B=0x6500000000;USER=B+0x1000;OOL=B+0x4000;BUF=B+0xb2000;LIVE=B+0xb4000;STATE=B+0xb6000;COPY=B+0xb8000;TABLE=B+0xbc000;HALT=B+0xe0000
class Replay(Parent):
 def __init__(self,view,p,k):super().__init__(view,p);self.k=k;self.fi=0;self.ti=0;self.transition_checked=False
 def check_frame(self,f):
  assert f['source_visit_index']==self.seq and f['registers31']==[hex(self.reg(j))for j in range(31)]and f['SP']==hex(self.u.reg_read(A.UC_ARM64_REG_SP))and f['NZCV']==hex(self.u.reg_read(A.UC_ARM64_REG_NZCV))and f['Q_registers32']==[hex(self.u.reg_read(getattr(A,'UC_ARM64_REG_Q'+str(j))))for j in range(32)]
  for a,n,key in((USER,148,'user148_hex'),(OOL,29,'OOL29_hex'),(ROOTCELL,8,'hook_root8_hex'),(STATE,8,'voucher_state8_hex'),(COPY,8,'voucher_copy8_hex'),(LIVE,8,'live_name8_hex')):self.ensure(a,n);assert f[key]==bytes(self.u.mem_read(a,n)).hex()
  self.counts['complete_receive_voucher_CPU_and_record_frames_checked']+=1
 def write(self,u,t,a,n,v,d):
  e=self.writes[self.current][self.wc];assert e['before_hex']==bytes(u.mem_read(a,n)).hex();self.counts['ordered_write_before_images_checked']+=1;return super().write(u,t,a,n,v,d)
 def code(self,u,a,n,d):
  self.finish()
  tr=self.p['initializer_to_CF_call']
  if tr and a==HALT and self.seq==tr['before']['source_visit_index']and not self.transition_checked:
   self.check_frame(tr['before']);assert decode(tr['private_RAM_before'])==bytes(u.mem_read(B,0x100000))and self.reg(0)==0 and int.from_bytes(bytes(u.mem_read(ROOTCELL,8)),'little')==TABLE
   for j,v in enumerate((int(self.k['receive_name'],16),BUF,LIVE,0xffffffff,STATE,COPY)):u.reg_write(getattr(A,'UC_ARM64_REG_X'+str(j)),v)
   u.reg_write(A.UC_ARM64_REG_X30,HALT);u.reg_write(A.UC_ARM64_REG_PC,SERVICE);self.check_frame(tr['after']);self.transition_checked=True;self.counts['original_initializer_return_and_public_CF_call_handoffs_checked']+=1;return
  if self.fi<len(self.p['frames']):
   f=self.p['frames'][self.fi]
   if f['pc']==hex(a)and f['source_visit_index']==self.seq:self.check_frame(f);self.fi+=1
  if a==MACH:
   e=self.p['kernel_return_transfers'][self.ti];self.ti+=1;assert e['pc']==hex(a)and e['before_source_visit_index']==self.seq and e['arguments8']==[hex(self.reg(j))for j in range(8)]and self.reg(0)==USER and self.reg(1)==0x07000806 and self.reg(2)==0 and self.reg(3)==3072 and self.reg(4)==int(self.k['receive_name'],16)and self.reg(5)==0xffffffff and self.reg(6)==0
   want=[(USER,bytes.fromhex(self.k['final_user8192_hex'])[:148]),(OOL,bytes.fromhex(self.k['final_OOL16384_hex'])[:29])];assert len(e['patches'])==2
   for patch,(at,data)in zip(e['patches'],want,strict=True):assert patch['address']==hex(at)and patch['before_hex']==bytes(u.mem_read(at,len(data))).hex()and patch['after_hex']==data.hex();u.mem_write(at,data);self.counts['exact_kernel_to_CF_transfer_bytes_checked']+=len(data)
   assert self.models[self.mi]['return_value']==self.k['boundary']['registers31'][0];self.counts['original_kernel_status_and_CF_Mach_ABI_contracts_checked']+=1
  if self.seq<len(self.p['source_visits'])and a==int(self.p['source_visits'][self.seq]['pc'],16):
   raw=bytes(u.mem_read(a,4));i=next(self.image.k.cs.disasm(raw,a))
   if i.mnemonic in('braa','braaz'):
    assert raw==self.image.k.read(a,4)and raw.hex()==self.p['source_visits'][self.seq]['bytes_hex'];self.current=self.seq;self.seq+=1;self.rc=self.wc=0;u.reg_write(A.UC_ARM64_REG_PC,self.reg(int(i.op_str.split(',')[0].strip()[1:])));self.counts['source_visits_checked']+=1;self.counts['logical_cache_branch_authentication_steps_checked']+=1;return
  return super().code(u,a,n,d)
 def run(self):
  super().run();assert self.fi==len(self.p['frames'])and self.ti==1 and self.transition_checked==(self.p['configuration']['table_mode']=='published_null_callbacks')and decode(self.p['final_private_RAM'])==bytes(self.u.mem_read(B,0x100000));self.counts['whole_final_private_RAM_bytes_checked']+=0x100000
  for a,n,key in((ROOTCELL,8,'final_hook_root8_hex'),(USER,8192,'final_user8192_hex'),(OOL,16384,'final_OOL16384_hex'),(BUF,8,'final_buffer_pointer8_hex'),(LIVE,8,'final_live_name8_hex'),(STATE,8,'final_voucher_state8_hex'),(COPY,8,'final_voucher_copy8_hex')):assert self.p[key]==bytes(self.u.mem_read(a,n)).hex();self.counts['complete_final_receive_and_global_buffer_bytes_checked']+=n
  return dict(self.counts)
