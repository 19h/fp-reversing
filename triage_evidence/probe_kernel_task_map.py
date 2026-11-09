#!/usr/bin/env python3
"""Original named accessors, Mach send prefix and task/thread map replacement.
Private owner/zone/lock/map state and lower VM/switch callbacks are premises.
O(visits) time, O(private RAM+journals) space. No native target or VM/IPC effect.
"""
import json,struct
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT
from kernel_vm_mig_tools import Image
from capture_daemon_record720 import sha
from probe_kernel_vm_mig import Probe as Base,P,SIZE,SP,HALT
from recover_kernel_task_map import FUNCTIONS
CTX=P+0x10000;SPACE=P+0x28000;CUR=P+0x2c000;REMOTE=P+0x2d000;OWNCUR=P+0x30000;OWNREC=P+0x34000;TASK=P+0x3c000;OLD=P+0x48000;OTHER=P+0x4a000;NEW=P+0x50000;CPU=P+0x6000;META=P+0x90000
def pack(v,n=8):return v.to_bytes(n,'little')
class Probe(Base):
 def __init__(self,image,cfg):
  super().__init__(image,'stub',{'port_class':'null','bits':0,'request_size':56,'address':0,'size':0,'body_placement':'joined'});self.kind=cfg['kind'];self.c=cfg;self.u.mem_write(P,bytes(SIZE));self.initial=[];self.image_initial=[];self.auth=[];self.sign=[]
  for j in range(31):self.set(j,0)
  self.set(30,HALT);self.u.reg_write(ar.UC_ARM64_REG_TPIDR_EL1,CUR);self.recipient=CUR if cfg.get('recipient','current')=='current'else REMOTE;self.fixture(CUR+0x420,pack(OWNCUR));self.fixture(OWNCUR,pack(CUR));self.fixture(OWNCUR+0x28,pack(TASK));self.fixture(REMOTE+0x420,pack(OWNREC));self.fixture(OWNREC,pack(REMOTE));self.fixture(OWNREC+0x28,pack(TASK));self.fixture(CUR+0x1c0,pack(CPU));self.fixture(CUR+0x518,pack(7,4));self.fixture(TASK+0x318,pack(SPACE))
  meta_base=META-((OWNCUR>>10)&0xffffffff0)
  for a in [OWNCUR,OWNREC]:self.fixture(meta_base+((a>>10)&0xffffffff0),pack(3,2))
  for a,b in [(0xfffffe0007e66ea0,struct.pack('<QQ',P,P+SIZE)),(0xfffffe0007e6d038,pack(0x40000,4)),(0xfffffe0007e66f00,pack(meta_base)),(0xfffffe000cb0bc50,pack(0,4))]:self.ensure(a,len(b));self.u.mem_write(a,b);self.image_initial.append({'address':hex(a),'bytes_hex':b.hex(),'provenance':'private owner geometry and uncontended-lock state'})
  self.allowed=[(a,int(image.k.function(a)['end'],16))for a in FUNCTIONS]
  if self.kind=='replace':
   self.entry=0xfffffe000bd7e78c;old=OLD if cfg['old_nonnull']else 0;new=NEW if cfg['new_nonnull']else 0;self.fixture(TASK+0x28,pack(old));self.fixture(TASK+0x6c8,pack(cfg['task_bit4']<<4,4));self.fixture(CUR+0x428,pack(OTHER));self.fixture(self.recipient+0x428,pack(old));self.fixture(NEW+0x10,struct.pack('<QQ',P+0x70000,P+0x78000));self.fixture(NEW+0xb0,pack(cfg['new_bit25']<<25,4));self.fixture(NEW+0xb8,pack(TASK));self.set(0,TASK);self.set(1,self.recipient);self.set(2,new)
  else:
   taskmap=0 if cfg['task_map_null']else OLD;current=OLD if cfg['current_alias']else OTHER;self.fixture(TASK+0x28,pack(taskmap));self.fixture(CUR+0x428,pack(current));self.fixture(OLD+0xb0,pack(cfg['task_bit25']<<25,4));self.fixture(OTHER+0xb0,pack(cfg['current_bit25']<<25,4))
   if self.kind=='current_task':self.entry=0xfffffe000bd41ac4
   elif self.kind=='task_map':self.entry=0xfffffe000bd7e658;self.set(0,TASK)
   else:
    assert self.kind=='send_prefix';self.entry=0xfffffe000bcdd350;context=bytearray(88);struct.pack_into('<6I',context,0,0x80000012,0,203,0,0,602);struct.pack_into('<I',context,24,2);struct.pack_into('<QQII',context,32,P+0x20000,0,384,0);self.fixture(CTX,bytes(context));self.set(0,CTX)
  self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV))
 def code(self,u,a,n,d):
  self.flush()
  if a==HALT:return self.stop('returned')
  if self.kind=='send_prefix'and a==0xfffffe000bcc24a4:return self.stop('before_message_allocation')
  callbacks={0xfffffe000be63ea0:'lower_map_switch_request',0xfffffe000bd098c8:'map_lock_model',0xfffffe000bdc3c2c:'map_range_remove_request',0xfffffe000bdc37f8:'removed_entry_release_model'}
  if a in callbacks:return self.model(a,callbacks[a],0)
  assert any(lo<=a<hi for lo,hi in self.allowed),hex(a);raw=bytes(u.mem_read(a,4));assert raw==self.image.k.read(a,4);i=next(self.image.k.cs.disasm(raw,a));self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()})
  if i.mnemonic in ['pacibsp','autibsp']:u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  elif i.mnemonic=='retab':u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30))
  elif i.mnemonic=='autda':self.auth.append({'pc':hex(a),'pointer':hex(self.reg(16)),'modifier':hex(self.reg(17)),'native_authentication_executed':False});u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  elif i.mnemonic=='pacda':self.sign.append({'pc':hex(a),'pointer':hex(self.reg(17)),'modifier':hex(self.reg(16)),'native_authentication_executed':False});u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  assert i.mnemonic not in ['svc','hvc','smc','brk','blraa']
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=20000);self.flush();assert self.reason in ['returned','before_message_allocation'],self.boundary
  state={n:hex(int.from_bytes(self.u.mem_read(a,w),'little'))for n,a,w in [('task_map',TASK+0x28,8),('recipient_map',self.recipient+0x428,8),('current_map',CUR+0x428,8),('new_flags',NEW+0xb0,4),('new_associated',NEW+0xb8,8),('task_lock',TASK+8,8),('preemption',CUR+0x1c8,4)]}
  return {'kind':self.kind,'configuration':self.c,'entry_PC':hex(self.entry),'entry_SP':hex(SP),'entry_registers31':self.entry_regs,'entry_NZCV':self.entry_NZCV,'private_RAM':{'address':hex(P),'size_bytes':SIZE,'initial_byte':0},'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'logical_data_authentication':self.auth,'logical_data_signing':self.sign,'private_system_register_fixtures':[{'register':'TPIDR_EL1','value':hex(CUR)}],'boundary':self.boundary,'return_X0':hex(self.reg(0)),'final_state':state,'native_target_executed':False,'native_VM_effects_executed':False,'hardware_PAC_executed':False}

def views():
 out=[]
 for bit in [0,1]:
  out.append({'task_map_null':False,'current_alias':True,'task_bit25':bit,'current_bit25':bit})
  for current in [0,1]:out.append({'task_map_null':False,'current_alias':False,'task_bit25':bit,'current_bit25':current})
 for current in [0,1]:out.append({'task_map_null':True,'current_alias':False,'task_bit25':0,'current_bit25':current})
 return out
def replacements():
 for recipient in ['current','remote']:
  for old in [False,True]:
   for new in [False,True]:
    if not new and recipient=='current':continue
    for active in ([0,1]if new else[1]):
     for bit in ([0,1]if new else[0]):yield {'kind':'replace','recipient':recipient,'old_nonnull':old,'new_nonnull':new,'task_bit4':active,'new_bit25':bit}
if __name__=='__main__':
 image=Image();rows=[];groups=[]
 for vi,view in enumerate(views()):
  ids=[]
  for kind in ['current_task','task_map','send_prefix']:r=Probe(image,{**view,'kind':kind,'view_index':vi}).run();ids.append(len(rows));rows.append(r)
  groups.append(ids)
 for c in replacements():r=Probe(image,c).run();rows.append(r);print(len(rows)-1,c,r['return_X0'],flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['kernel_task_map_source.json','probe_kernel_vm_mig.py','kernel_vm_mig_tools.py']},'cases':rows,'accessor_send_groups':groups,'native_target_executed':False,'native_VM_effects_executed':False,'native_IPC_executed':False,'native_thread_synchronization_established':False,'complete_FairPlay_round_trip_established':False,'full_goal_complete':False};(ROOT/'kernel_task_map_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(len(r['source_visits'])for r in rows)}),flush=True)
