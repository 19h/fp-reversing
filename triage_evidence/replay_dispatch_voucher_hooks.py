#!/usr/bin/env python3
"""Independent original installer/hook replay; no installed-table probe import.
O(image+visits+RAM+journals), O(image+RAM+journals). Caller/Mach transitions
and logical cache authentication remain explicit; no native operations.
"""
from unicorn import arm64_const as A
from replay_cf_receive_voucher import Replay as Parent,B,USER,OOL,BUF,LIVE,STATE,COPY,HALT
from replay_kernel_vm_mig import Replay as CoreReplay
from replay_rpc502_vm_handoff import decode
from recover_dispatch_voucher_hooks import TABLE,DISPATCH_INIT
from recover_cf_receive_voucher import ROOTCELL
from recover_cf_receive import SERVICE
class Replay(Parent):
 def code(self,u,a,n,d):
  self.finish();tr=self.p['initializer_to_CF_call']
  if tr and a==HALT and self.seq==tr['before']['source_visit_index']and not self.transition_checked:
   assert self.seq==11;self.check_frame(tr['before']);assert self.reg(0)==0 and decode(tr['private_RAM_before'])==bytes(u.mem_read(B,0x100000))and int.from_bytes(bytes(u.mem_read(ROOTCELL,8)),'little')==TABLE
   for j,v in enumerate((int(self.k['receive_name'],16),BUF,LIVE,0xffffffff,STATE,COPY)):u.reg_write(getattr(A,'UC_ARM64_REG_X'+str(j)),v)
   u.reg_write(A.UC_ARM64_REG_X30,HALT);u.reg_write(A.UC_ARM64_REG_PC,SERVICE);self.check_frame(tr['after']);self.transition_checked=True;self.counts['original_dispatch_installer_return_and_public_CF_call_handoffs_checked']+=1;return
  return super().code(u,a,n,d)
 def run(self):
  CoreReplay.run(self);assert self.fi==len(self.p['frames'])and self.ti==1 and self.transition_checked and self.p['entry_PC']==hex(DISPATCH_INIT)and decode(self.p['final_private_RAM'])==bytes(self.u.mem_read(B,0x100000));self.counts['whole_final_private_RAM_bytes_checked']+=0x100000
  for a,n,key in((ROOTCELL,8,'final_hook_root8_hex'),(USER,8192,'final_user8192_hex'),(OOL,16384,'final_OOL16384_hex'),(BUF,8,'final_buffer_pointer8_hex'),(LIVE,8,'final_live_name8_hex'),(STATE,8,'final_voucher_state8_hex'),(COPY,8,'final_voucher_copy8_hex')):assert self.p[key]==bytes(self.u.mem_read(a,n)).hex();self.counts['complete_final_receive_and_global_buffer_bytes_checked']+=n
  return dict(self.counts)
class ClearReplay(CoreReplay):
 def run(self):
  super().run();assert self.p['final_user8192_hex']==bytes(self.u.mem_read(USER,8192)).hex()and decode(self.p['final_private_RAM'])==bytes(self.u.mem_read(B,0x100000));self.counts['whole_final_clear_private_RAM_bytes_checked']+=0x100000;return dict(self.counts)
