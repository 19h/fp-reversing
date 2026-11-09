#!/usr/bin/env python3
"""Independent original scheduling/collection/Mach-wrapper/consumer replay.
No scheduling-probe import. Stateful lower contracts are recomputed from call
arguments. O(image+visits+RAM+journals) time/space; no native IPC or CF runtime.
"""
import hashlib,struct
from unicorn import arm64_const as A
from daemon_receive_tools import CS
from replay_cf_runloop_handoff import Replay as Parent,unpack,B,USER,OOL,OBJ,RL,MODE,SRC,DICT,LOW,LOW_SIZE,HALT,ENTRY_SP,REPLY
from recover_cf_source_scheduling import ADD,GETPORT,DSET,DGET,FIND,SETADD,CONTAINS,BAGADD,HELPERS,TYPE_TRAP,INSERT_TRAP,TASK_CELL
from recover_cf_receive import RUN
from recover_cf_receive_voucher import MACH
from recover_dispatch_voucher_hooks import DISPATCH_INIT
NAME=B+0xae000;SET0=B+0xaf000;SET1=B+0xaf100;BAG=B+0xaf200;PSET=0x503;TASK=0x103
NEWFUNCS={ADD,GETPORT,DSET,DGET,FIND,SETADD,CONTAINS,BAGADD,0x18054a938,0x180549f50}
class Replay(Parent):
 def __init__(self,p,k,s):
  super().__init__(p,k,s);self.config=p['configuration'];self.dictionary={};self.collections={SET0:set(),SET1:set(),BAG:set()};self.members=set();self.bag_counts={};self.pi=self.sfi=self.smi=self.rri=0;self.port=0 if self.config['zero_port']else int(k['receive_name'],16)
  for a in(NAME,SET0,SET1,BAG):self.u.mem_write(a,bytes(64))
  for a,v in((MODE+0x60,SET0),(MODE+0x68,SET1),(SRC+0x60,BAG),(SRC+0x68,1),(SRC+0xa0,GETPORT),(SRC+8,8 if self.config['valid']else 0)):self.u.mem_write(a,struct.pack('<Q',v))
  self.u.mem_write(MODE+0x88,struct.pack('<I',PSET));self.u.mem_write(OBJ+0x14,struct.pack('<I',self.port));self.u.mem_write(TASK_CELL,struct.pack('<I',TASK));self.u.mem_write(0x1ed891720,b'\0');self.u.mem_write(DICT+0x12,struct.pack('<H',1));self.u.mem_write(DICT+0x1a,b'\x01')
 def state(self):return{'dictionary':{hex(k):hex(v)for k,v in sorted(self.dictionary.items())},'collections':{hex(k):[hex(v)for v in sorted(values)]for k,values in self.collections.items()},'members':[[hex(a),hex(b)]for a,b in sorted(self.members)],'bag_counts':{hex(k):v for k,v in sorted(self.bag_counts.items())}}
 def check_schedule_frame(self,f):
  self.check_frame(f);assert f['model_state']==self.state()
  for a,n,key in((MODE,512,'mode512_hex'),(SRC,256,'source256_hex'),(OBJ,160,'CF_object160_hex')):assert f[key]==bytes(self.u.mem_read(a,n)).hex()
  self.counts['scheduling_CPU_object_and_state_frames_checked']+=1
 def consume_model(self,a,result,patches):
  e=self.p['imports'][self.mi];self.mi+=1;assert e==self.p['runloop_models'][self.rmi];self.rmi+=1;assert e['pc']==hex(a)and e['before_source_visit_index']==self.seq;self.check_frame(e['before']);target=self.reg(30);assert e['return_pc']==hex(target)and e['result']==hex(result)and len(e['patches'])==len(patches)
  for(at,raw),saved in zip(patches,e['patches'],strict=True):assert saved=={'address':hex(at),'before_hex':bytes(self.u.mem_read(at,len(raw))).hex(),'after_hex':raw.hex()};self.u.mem_write(at,raw);self.counts['stateful_lower_model_patch_bytes_checked']+=len(raw)
  for j in range(18):self.setreg(j,((j+1)*0x123456789abcdef)^0x8b3dc651)
  self.setreg(0,result);self.u.reg_write(A.UC_ARM64_REG_NZCV,0xf0000000);self.u.reg_write(A.UC_ARM64_REG_PC,target);self.check_frame(e['after']);return e
 def hook(self,u,a,n,d):
  self.finish_writes()
  if self.rri<len(self.p['registration_returns']):
   f=self.p['registration_returns'][self.rri]
   if a==HALT and f['source_visit_index']==self.seq:self.check_schedule_frame(f);self.rri+=1
  if a==HALT and self.pi<len(self.p['public_handoffs']):
   e=self.p['public_handoffs'][self.pi];self.check_frame(e['before']);assert e['model_state']==self.state()
   for at,size,key in((B,0x100000,'private_RAM_sha256'),(LOW,LOW_SIZE,'lower_stack_sha256')):assert e[key]==hashlib.sha256(bytes(u.mem_read(at,size))).hexdigest()
   if self.pi==0:assert self.seq==11 and e['kind']=='installer_to_AddSource';target=ADD;args=(RL,SRC,NAME)
   elif self.config['mode']=='duplicate_source':assert e['kind']=='repeat_AddSource';target=ADD;args=(RL,SRC,NAME)
   else:assert self.config['mode']=='schedule_then_run'and e['kind']=='AddSource_to_runloop';target=RUN;args=(RL,MODE,1);self.transition=True
   for j,v in enumerate(args):self.setreg(j,v)
   self.setreg(30,HALT)
   if target==RUN:u.reg_write(A.UC_ARM64_REG_Q0,0x7ff0000000000000)
   u.reg_write(A.UC_ARM64_REG_PC,target);self.check_frame(e['after']);self.pi+=1;self.counts['public_registration_and_runloop_handoffs_checked']+=1;return
  if self.sfi<len(self.p['scheduling_frames']):
   f=self.p['scheduling_frames'][self.sfi]
   if f['pc']==hex(a)and f['source_visit_index']==self.seq:self.check_schedule_frame(f);self.sfi+=1
  if a==HALT and self.config['mode']!='schedule_then_run':assert self.seq==len(self.p['source_visits'])and self.p['boundary']['kind']=='source_registration_returned';self.check_frame(self.p['boundary']);self.done=True;u.emu_stop();return
  if a==MACH:
   assert[self.reg(j)for j in range(7)]==[USER,0x07000806,0,3072,PSET,0xffffffff,0]and(PSET,int(self.origin['receive_name'],16))in self.members;self.check_run_frame(self.p['kernel_transfers'][self.kti]);self.kti+=1;self.consume_model(a,0,[(USER,bytes.fromhex(self.origin['final_user8192_hex'])[:148]),(OOL,bytes.fromhex(self.origin['final_OOL16384_hex'])[:29])]);self.counts['declared_portset_kernel_packet_transfers_checked']+=1;return
  if a in HELPERS:
   before=self.state();x=[self.reg(j)for j in range(9)];result=0;patches=[]
   if a==0x184833380:assert x[0]==RL
   elif a==0x184833694:assert x[0]==RL;result=43
   elif a==0x1848316fc:assert x[:3]==[RL,NAME,1];result=MODE
   elif a==0x184833260:assert x[0]in(17,18)and x[1]in self.collections.keys()|{DICT}
   elif a==0x1846dcd84:assert x[0]==DICT;self.dictionary[x[1]]=x[2]
   elif a==0x1846fb710:assert x[0]in self.collections;result=int(x[1]in self.collections[x[0]])
   elif a==0x1846fb960:
    assert x[0]in self.collections and x[1]==x[2];self.collections[x[0]].add(x[1])
    if x[0]==BAG:self.bag_counts[x[1]]=self.bag_counts.get(x[1],0)+1
   elif a==0x18489b724:assert x[0]==DICT;value=self.dictionary.get(x[1],0);patches=[(x[8],struct.pack('<4Q',0,x[1],value,int(bool(value))))]
   elif a==TYPE_TRAP:
    assert x[:2]==[TASK,self.port];result=4 if self.config['zero_port']else 0
    if not result:patches=[(x[2],struct.pack('<I',0x20000))]
   elif a==INSERT_TRAP:
    assert x[:3]==[TASK,self.port,PSET];result=self.config['insert_status']
    if not result:self.members.add((PSET,self.port))
   e=self.consume_model(a,result,patches);assert e==self.p['scheduling_models'][self.smi]and e['name']==HELPERS[a]and e['model_state_before']==before and e['model_state_after']==self.state();self.smi+=1;self.counts['stateful_scheduling_lower_contracts_recomputed']+=1;return
  f=next((f for f in self.source['CF_functions']if int(f['start'],16)in NEWFUNCS and int(f['start'],16)<=a<int(f['end'],16)),None)
  if f:
   raw=bytes(u.mem_read(a,4));off=a-int(f['start'],16);assert raw==bytes.fromhex(f['bytes'])[off:off+4]and self.p['source_visits'][self.seq]=={'pc':hex(a),'bytes_hex':raw.hex()};self.current=self.seq;self.seq+=1;self.counts['original_instruction_visits_checked']+=1;self.counts['original_scheduling_collection_Mach_wrapper_visits_checked']+=1;i=next(CS.disasm(raw,a));op=i.mnemonic
   if op in('pacibsp','autibsp','paciza','autia','xpaci'):u.reg_write(A.UC_ARM64_REG_PC,a+4)
   elif op=='retab':u.reg_write(A.UC_ARM64_REG_PC,self.reg(30))
   elif op in('blraa','blraaz','braa','braaz'):
    j=int(i.op_str.split(',')[0].strip()[1:]);target=self.reg(j)
    if op.startswith('blr'):self.setreg(30,a+4)
    u.reg_write(A.UC_ARM64_REG_PC,target)
   else:assert op not in('svc','hvc','smc','brk','mrs','msr')and not op.startswith(('pac','aut','xpac'))
   return
  return super().hook(u,a,n,d)
 def run(self):
  self.u.emu_start(DISPATCH_INIT,0,count=30000);self.finish_writes();assert self.done and self.seq==len(self.p['source_visits'])and self.ri==len(self.p['source_reads'])and self.wi==len(self.p['source_writes'])and self.mi==len(self.p['imports'])and self.hi==len(self.p['handoffs'])and self.ai==len(self.p['application_frames'])and self.cfi==len(self.p['CF_frames'])and self.rmi==len(self.p['runloop_models'])and self.rfi==len(self.p['runloop_frames'])and self.kti==len(self.p['kernel_transfers'])and self.pi==len(self.p['public_handoffs'])and self.smi==len(self.p['scheduling_models'])and self.sfi==len(self.p['scheduling_frames'])and self.rri==len(self.p['registration_returns'])==self.config['repeat']
  assert self.p['final_model_state']==self.state()and self.p['final_task_cell8_hex']==bytes(self.u.mem_read(TASK_CELL,8)).hex()
  for at,size,key in((B,0x100000,'final_private_RAM'),(LOW,LOW_SIZE,'final_lower_stack')):assert unpack(self.p[key],at,size)==bytes(self.u.mem_read(at,size));self.counts['whole_final_private_RAM_bytes_checked']+=size
  for a,n,key in((USER,8192,'final_user8192_hex'),(OOL,16384,'final_OOL16384_hex'),(REPLY,384,'reply384_hex')):assert self.p[key]==bytes(self.u.mem_read(a,n)).hex()
  if self.application_checked:assert self.p['final_argument_record120_hex']==bytes(self.u.mem_read(int(self.p['argument_record_address'],16),120)).hex()
  self.counts['final_boundaries_checked']+=1;return dict(self.counts)
