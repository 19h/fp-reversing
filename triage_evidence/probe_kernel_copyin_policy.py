#!/usr/bin/env python3
"""Original policy predicate, owner lookup, copyin gate and startup parser.
Private map/task/thread/zone and boot records are premises. No native changes.
O(visits) time, O(private RAM+journals) space; no host boot/VM/IPC operation.
"""
import json,struct
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT
from kernel_vm_mig_tools import Image
from capture_daemon_record720 import sha
from probe_kernel_vm_mig import Probe as Base,P,SIZE,SP,HALT
from recover_kernel_copyin_policy import FUNCTIONS,G
MAP=P+0x2a000;THREAD=P+0x2c000;OWNER=P+0x34000;TASK=P+0x3c000;ASSOC=P+0x40000;KTASK=P+0x44000;META=P+0x90000;BOOT=P+0x6000;OUT=P+0x10000
def pack(x,n=8):return x.to_bytes(n,'little')
class Probe(Base):
 def __init__(self,image,cfg):
  super().__init__(image,'stub',{'port_class':'null','bits':0,'request_size':56,'address':0,'size':0,'body_placement':'joined'});self.kind=cfg['kind'];self.c=cfg;self.u.mem_write(P,bytes(SIZE));self.initial=[];self.image_initial=[];self.auth=[];self.ia=[];self.cuts=[];self.u.reg_write(ar.UC_ARM64_REG_TPIDR_EL1,THREAD)
  for j in range(31):self.set(j,0)
  self.set(30,HALT);self.allowed=[(a,int(image.k.function(a)['end'],16))for a in FUNCTIONS]
  globals_=[(G,pack(2 if self.kind=='startup'else cfg['enforcement'],4))]
  if self.kind=='startup':
   self.entry=0xfffffe000c6306e0;self.set(0,0xfffffe000ca881c0);self.fixture(BOOT+0x6c,cfg['private_boot_text'].encode()+b'\0'+bytes(64));globals_.append((0xfffffe0007f8b6e8,pack(BOOT)))
  else:
   self.entry=0xfffffe000bdc6bc8 if self.kind=='predicate'else 0xfffffe000bdd15a4
   self.fixture(MAP+0x10,struct.pack('<QQ',P,P+SIZE));self.fixture(MAP+0x2c,bytes([14]));self.fixture(MAP+0xb0,pack(cfg['source_bit']<<25,4));self.fixture(THREAD+0x420,pack(OWNER if cfg['owner_present']else 0));self.fixture(THREAD+0x480,pack(cfg['thread_bit']<<1,2));self.fixture(OWNER,pack(THREAD));self.fixture(OWNER+0x28,pack({'null':0,'kernel':KTASK,'task':TASK}[cfg['task_result']]));self.fixture(TASK+0x28,pack(ASSOC if cfg['associated_present']else 0));self.fixture(ASSOC+0xb3,bytes([cfg['associated_bit']<<1]));self.fixture(META,pack(3,2))
   globals_ +=[(0xfffffe0007f8b5f0,pack(cfg['variant'],4)),(0xfffffe0007f8b0a0,pack(KTASK)),(0xfffffe0007e66ea0,struct.pack('<QQ',P,P+SIZE)),(0xfffffe0007e6d038,pack(0x40000,4)),(0xfffffe0007e66f00,pack(META-((OWNER>>10)&0xffffffff0)))]
   self.set(0,MAP)
   if self.kind=='gate':self.set(1,P+0x50000);self.set(2,37);self.set(3,1|(cfg['source_bit']<<9));self.set(4,OUT)
  for a,b in globals_:self.ensure(a,len(b));self.u.mem_write(a,b);self.image_initial.append({'address':hex(a),'bytes_hex':b.hex(),'provenance':'declared private global/binding state; file defaults recorded separately'})
  self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV))
 def write(self,u,t,a,n,v,d):
  if G<=a<a+n<=G+4:
   e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'address':hex(a),'size_bytes':n};self.writes.append(e);self.pending.append(e);return
  return super().write(u,t,a,n,v,d)
 def code(self,u,a,n,d):
  self.flush()
  if a==HALT:return self.stop('returned')
  if self.kind=='gate'and a in [0xfffffe000bcfe5b8,0xfffffe000be3218c]:return self.stop('buffer_factory'if a==0xfffffe000bcfe5b8 else'policy_range_validation')
  if a==0xfffffe000bd08980:return self.model(a,'map_read_lock_model',0)
  if a==0xfffffe000c5e48a4:self.cuts.append({'pc':hex(a),'source_visit_index':len(self.visits),'arguments5':[hex(self.reg(j))for j in range(5)]})
  assert any(lo<=a<hi for lo,hi in self.allowed),hex(a);raw=bytes(u.mem_read(a,4));assert raw==self.image.k.read(a,4);i=next(self.image.k.cs.disasm(raw,a));self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()})
  if i.mnemonic in ['pacibsp','autibsp']:u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  elif i.mnemonic=='retab':u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30))
  elif i.mnemonic=='autda':self.auth.append({'pc':hex(a),'pointer':hex(self.reg(16)),'modifier':hex(self.reg(17)),'native_authentication_executed':False});u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  elif i.mnemonic in ['pacia','blraa']:
   assert a in [0xfffffe000c5e49dc,0xfffffe000c5e4ddc,0xfffffe000c5e4e7c];target=self.reg(16 if i.mnemonic=='pacia'else 19);assert target==0xfffffe000c5e4f50 and self.reg(17)==0xba5;self.ia.append({'pc':hex(a),'operation':i.mnemonic,'target':hex(target),'modifier':'0xba5','native_authentication_executed':False})
   if i.mnemonic=='blraa':self.set(30,a+4);u.reg_write(ar.UC_ARM64_REG_PC,target)
   else:u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  assert i.mnemonic not in ['svc','hvc','smc','brk','pacda']
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=30000);self.flush();assert self.reason in ['returned','buffer_factory','policy_range_validation'],self.boundary
  return {'kind':self.kind,'configuration':self.c,'entry_PC':hex(self.entry),'entry_SP':hex(SP),'entry_registers31':self.entry_regs,'entry_NZCV':self.entry_NZCV,'private_RAM':{'address':hex(P),'size_bytes':SIZE,'initial_byte':0},'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'logical_data_authentication':self.auth,'logical_instruction_authentication':self.ia,'parser_entries':self.cuts,'private_system_register_fixtures':[{'register':'TPIDR_EL1','value':hex(THREAD)}],'boundary':self.boundary,'return_u32':self.reg(0)&0xffffffff,'final_policy_u32':int.from_bytes(bytes(self.u.mem_read(G,4)),'little'),'native_target_executed':False,'native_boot_configuration_changed':False,'native_VM_effects_executed':False,'hardware_PAC_executed':False}

def configurations():
 base={'owner_present':True,'task_result':'task','associated_present':True,'associated_bit':0,'thread_bit':0,'variant':0}
 contexts=[('no_owner',{'owner_present':False}),('null_task',{'task_result':'null'}),('kernel_task',{'task_result':'kernel'}),('null_associated',{'associated_present':False}),('associated_clear',{}),('associated_set',{'associated_bit':1}),('associated_set_thread',{'associated_bit':1,'thread_bit':1}),('variant19_clear',{'variant':19}),('variant19_set_thread',{'variant':19,'associated_bit':1,'thread_bit':1})]
 for g in [0,1,2]:
  for source in [0,1]:
   for label,change in contexts:yield {**base,**change,'enforcement':g,'source_bit':source,'context':label}
if __name__=='__main__':
 image=Image();rows=[];pairs=[]
 for cfg in configurations():
  pair=[]
  for kind in ['predicate','gate']:
   r=Probe(image,{**cfg,'kind':kind}).run();pair.append(len(rows));rows.append(r)
  pairs.append(pair);print(len(pairs)-1,cfg['enforcement'],cfg['source_bit'],cfg['context'],rows[pair[0]]['return_u32'],rows[pair[1]]['boundary']['kind'],flush=True)
 for label,text in [('absent','unrelated=3'),('present1','vm_map_cow_defeatured_enforce=1'),('present2','vm_map_cow_defeatured_enforce=2')]:
  r=Probe(image,{'kind':'startup','case':label,'private_boot_text':text}).run();rows.append(r);print(label,r['final_policy_u32'],len(r['source_visits']),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['kernel_copyin_policy_source.json','probe_kernel_vm_mig.py','kernel_vm_mig_tools.py']},'cases':rows,'predicate_gate_pairs':pairs,'native_target_executed':False,'native_boot_configuration_changed':False,'native_VM_effects_executed':False,'native_IPC_executed':False,'full_goal_complete':False};(ROOT/'kernel_copyin_policy_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(len(r['source_visits'])for r in rows)}),flush=True)
