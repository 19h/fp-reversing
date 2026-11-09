#!/usr/bin/env python3
"""Independent fresh-CPU original mode/queue/port/callback replay.
No mode-probe import. O(image+visits+RAM+journals) time/space. Lower runtime
contracts are recomputed; native CF/kernel coupling and hardware PAC unknown.
"""
import hashlib,struct
from unicorn import arm64_const as A
from daemon_receive_tools import CS
from replay_kernel_portset_delivery import CFReplay as Parent
from replay_cf_runloop_handoff import unpack,LOW,LOW_SIZE
from replay_cf_source_scheduling import B,USER,MODE,RL,SRC,SET0,SET1,DICT,NAME,HALT
from recover_cf_mode_construction import COPYMODE,SETGET,ROOTCREATE,ROOTINIT,ROOTGET,CALLBACK,FORK,ALLOC_TRAP,CONSTRUCT_TRAP,MK,BOUNDARIES
from recover_cf_source_scheduling import INSERT_TRAP
from recover_cf_receive import RUN
from recover_dispatch_voucher_hooks import DISPATCH_INIT
REGISTRY=B+0xb4000;QUEUE=B+0xb6000;TLS=B+0xb7000;TIMER_SOURCE=B+0xb8000;BLOCK=B+0xb9000;BYREF=B+0xb9100;ROOT_PORT=0x607;TIMER_PORT=0x707;WAKE_PORT=0x807
NEWFUNCS={COPYMODE,SETGET,CALLBACK,ROOTCREATE,ROOTINIT,ROOTGET,0x185549410,FORK,0x180549ee0,0x180548e9c,MK}
FATALS={0x1848d3ee4:'portset_allocation',0x1848d4020:'root_port_zero',0x1848d3fd0:'root_member',0x1848d400c:'timer_port_zero',0x1848d3fe4:'timer_member',0x1848d3ff8:'wake_port_or_member',0x185522f38:'fork_flag_bit1'}
class Replay(Parent):
 def __init__(self,p,k,s):
  super().__init__(p,k,s);assert p['mode_configuration']==p['configuration'];self.collections[REGISTRY]=set();self.mfi=self.mmi=self.mri=self.source_set_allocs=0;self.u.mem_write(MODE,bytes(512));self.u.mem_write(MODE+200,b'\xa5');self.u.mem_write(RL+0xa68,struct.pack('<Q',REGISTRY));self.u.mem_write(RL+0x50,struct.pack('<I',WAKE_PORT));self.u.mem_write(REGISTRY,bytes(64));self.u.mem_write(REGISTRY+0x12,struct.pack('<H',1));self.u.mem_write(REGISTRY+0x1a,b'\x01')
  for a,n in((QUEUE,120),(TLS,64),(TIMER_SOURCE,128),(BLOCK,40),(BYREF,32)):self.u.mem_write(a,bytes(n))
  self.u.mem_write(QUEUE+120,b'\xa5');self.u.mem_write(TLS+0x18,struct.pack('<Q',0x100));self.u.mem_write(TLS+0x20,struct.pack('<Q',self.config.get('tls_priority_word',0)));self.u.reg_write(A.UC_ARM64_REG_TPIDRRO_EL0,TLS);assert p['private_TPIDRRO_EL0']==hex(TLS)
  if self.config['mode']=='fork_flag2':self.u.mem_write(0x1ed8999d0,b'\x02')
 def mode_frame(self,f):
  self.check_frame(f);assert f['model_state']==self.state()
  for a,n,key in((MODE,512,'mode512_hex'),(QUEUE,128,'queue128_hex'),(0x1ed8999d0,1,'fork_flag1_hex'),(0x1ed8991c0,8,'queue_serial_counter8_hex')):assert f[key]==bytes(self.u.mem_read(a,n)).hex()
  self.counts['mode_queue_state_and_CPU_frames_checked']+=1
 def mode_call(self,a,name,result,patches=(),extra=None,before=None):
  if before is None:before=self.state()
  e=self.consume_model(a,result,patches);assert e==self.p['mode_models'][self.mmi]and e['name']==name and e['model_state_before']==before and e['model_state_after']==self.state();self.mmi+=1
  for k,v in(extra or{}).items():assert e[k]==v
  self.counts['declared_mode_runtime_contracts_recomputed']+=1
 def hook(self,u,a,n,d):
  self.finish_writes();cfg=self.config['mode']
  if self.mfi<len(self.p['mode_frames']):
   f=self.p['mode_frames'][self.mfi]
   if f['pc']==hex(a)and f['source_visit_index']==self.seq:self.mode_frame(f);self.mfi+=1
  if a in FATALS:
   assert self.seq==len(self.p['source_visits'])and self.p['boundary']['kind']=='before_original_mode_failure_'+FATALS[a]and self.p['boundary']['pc']==hex(a);self.check_frame(self.p['boundary']);self.done=True;u.emu_stop();return
  if a==HALT:
   if self.rri<len(self.p['registration_returns']):
    f=self.p['registration_returns'][self.rri]
    if f['source_visit_index']==self.seq:self.check_schedule_frame(f);self.rri+=1
   if self.mri<len(self.p['mode_returns']):
    f=self.p['mode_returns'][self.mri]
    if f['source_visit_index']==self.seq:self.mode_frame(f);self.mri+=1
   if self.pi<len(self.p['public_handoffs']):
    e=self.p['public_handoffs'][self.pi];self.check_frame(e['before']);assert e['model_state']==self.state()
    for at,size,key in((B,0x100000,'private_RAM_sha256'),(LOW,LOW_SIZE,'lower_stack_sha256')):assert e[key]==hashlib.sha256(bytes(u.mem_read(at,size))).hexdigest()
    kind=e['kind']
    if kind=='installer_to_AddSource':assert self.pi==0 and cfg in('schedule_then_run','repeat_mode');target=0x18472d934;args=(RL,SRC,NAME)
    elif kind=='repeat_AddSource':assert cfg=='repeat_mode';target=0x18472d934;args=(RL,SRC,NAME)
    elif kind=='AddSource_to_runloop':assert cfg in('schedule_then_run','repeat_mode');target=RUN;args=(RL,MODE,1);self.transition=True
    elif kind=='installer_to_internal_CopyMode':assert self.pi==0 and cfg not in('schedule_then_run','repeat_mode');target=COPYMODE;args=(RL,NAME,0 if cfg=='no_create'else 1)
    else:assert kind=='CopyMode_to_timer_callback'and cfg=='timer_callback';target=CALLBACK;args=(BLOCK,)
    for j,v in enumerate(args):self.setreg(j,v)
    self.setreg(30,HALT)
    if target==RUN:u.reg_write(A.UC_ARM64_REG_Q0,0x7ff0000000000000)
    u.reg_write(A.UC_ARM64_REG_PC,target);self.check_frame(e['after']);self.pi+=1;self.counts['complete_function_entry_handoffs_checked']+=1;return
   assert self.seq==len(self.p['source_visits'])and self.p['boundary']['kind']in('original_runloop_returned','original_CopyMode_returned','original_mode_timer_handler_returned');self.check_frame(self.p['boundary']);self.done=True;u.emu_stop();return
  if a==0x18489b724 and self.reg(0)==REGISTRY:
   key=self.reg(1);name=int.from_bytes(bytes(u.mem_read(key+0x50,8)),'little');found=next((v for v in self.collections[REGISTRY]if int.from_bytes(bytes(u.mem_read(v+0x50,8)),'little')==name),0);return self.mode_call(a,'mode_registry_bucket_contract',0,[(self.reg(8),struct.pack('<4Q',0,key,found,int(bool(found))))])
  if a==INSERT_TRAP and self.reg(1)!=self.port:
   port=self.reg(1);assert self.reg(0)==0x103 and self.reg(2)==self.facility and port in(ROOT_PORT,TIMER_PORT,WAKE_PORT);bad={'root_member_error':ROOT_PORT,'timer_member_error':TIMER_PORT,'wake_member_error':WAKE_PORT}.get(cfg);value=4 if port==bad else 0;before=self.state()
   if not value:self.members.add((self.facility,port))
   return self.mode_call(a,'declared_mode_control_port_member',value,before=before)
  if a in BOUNDARIES:
   x=[self.reg(j)for j in range(9)];value=0;patches=[];extra=None
   if a==0x1846dc364:assert x[1]==44
   elif a==0x1846da4dc:assert x[1:4]==[44,184,0];value=0 if cfg=='runtime_null'else MODE
   elif a==0x1846df2ec:assert x[1]==NAME;value=NAME
   elif a==0x1805887c8:assert x[1]==2
   elif a==0x1805884cc:assert x[0]==MODE+0x10
   elif a==0x1855140c8:assert x[:2]==[0x1ed897df0,120];value=QUEUE;patches=[(QUEUE,struct.pack('<Q',x[0]))]
   elif a==ALLOC_TRAP:
    assert x[:2]==[0x103,3];ret=self.origin['pset_stage_returns'][0];value=4 if cfg=='pset_error'else int(ret['registers31'][0],16)
    if not value:patches=[(x[2],struct.pack('<I',self.facility))]
    extra={'kernel_allocate_oracle':{'case':self.config['kernel_case'],'return_source_visit_index':ret['source_visit_index'],'name':hex(self.facility)}if not value else None}
   elif a==CONSTRUCT_TRAP:assert x[0]==0x103 and x[2]==QUEUE;patches=[(x[3],struct.pack('<I',ROOT_PORT))];extra={'original_options16_hex':bytes(u.mem_read(x[1],16)).hex()}
   elif a==MK:value=0 if cfg=='timer_zero'else TIMER_PORT
   elif a==0x18552896c:assert x[0]==0x1e24b2310 and x[1:4]==[0,0,QUEUE];value=TIMER_SOURCE
   elif a==0x18552955c:
    assert x[0]==TIMER_SOURCE;raw=bytearray(u.mem_read(x[1],40));by=int.from_bytes(raw[32:40],'little');br=bytearray(u.mem_read(by,32));extra={'original_block40_hex':raw.hex(),'original_byref32_hex':br.hex()};assert int.from_bytes(br[24:32],'little')==MODE+0xa8;br[8:16]=struct.pack('<Q',BYREF);raw[32:40]=struct.pack('<Q',BYREF);patches=[(BLOCK,bytes(raw)),(BYREF,bytes(br))]
   elif a==0x185528b10:assert x[:4]==[TIMER_SOURCE,0xffffffffffffffff,0xffffffffffffffff,0x141]
   elif a==0x185514684:assert x[0]==TIMER_SOURCE
   elif a==0x18550ebf8:assert x[1]==8
   elif a==0x184716d78:assert x[1]==0;value=SET0 if self.source_set_allocs==0 else SET1;self.source_set_allocs+=1
   elif a==0x1846dbcac:assert x[1:4]==[0,0,0];value=DICT
   return self.mode_call(a,BOUNDARIES[a],value,patches,extra)
  f=next((f for f in self.source['CF_functions']if int(f['start'],16)in NEWFUNCS and int(f['start'],16)<=a<int(f['end'],16)),None)
  if f:
   raw=bytes(u.mem_read(a,4));off=a-int(f['start'],16);assert raw==bytes.fromhex(f['bytes'])[off:off+4]and self.p['source_visits'][self.seq]=={'pc':hex(a),'bytes_hex':raw.hex()};self.current=self.seq;self.seq+=1;self.counts['original_instruction_visits_checked']+=1;self.counts['original_mode_queue_and_callback_visits_checked']+=1;i=next(CS.disasm(raw,a));op=i.mnemonic
   if op in('pacibsp','autibsp','paciza','autia','autda','pacia','pacda','xpaci','xpacd'):u.reg_write(A.UC_ARM64_REG_PC,a+4)
   elif op=='retab':u.reg_write(A.UC_ARM64_REG_PC,self.reg(30))
   elif op in('blraa','blraaz','braa','braaz'):
    j=int(i.op_str.split(',')[0].strip()[1:]);target=self.reg(j)
    if op.startswith('blr'):self.setreg(30,a+4)
    u.reg_write(A.UC_ARM64_REG_PC,target)
   elif op=='mrs':assert i.op_str=='x21, tpidrro_el0'and u.reg_read(A.UC_ARM64_REG_TPIDRRO_EL0)==TLS
   else:assert op not in('svc','hvc','smc','brk','msr')and not op.startswith(('pac','aut','xpac'))
   return
  return super().hook(u,a,n,d)
 def run(self):
  self.u.emu_start(DISPATCH_INIT,0,count=30000);self.finish_writes();assert self.done and self.seq==len(self.p['source_visits'])and self.ri==len(self.p['source_reads'])and self.wi==len(self.p['source_writes'])and self.mi==len(self.p['imports'])and self.hi==len(self.p['handoffs'])and self.ai==len(self.p['application_frames'])and self.cfi==len(self.p['CF_frames'])and self.rmi==len(self.p['runloop_models'])and self.rfi==len(self.p['runloop_frames'])and self.kti==len(self.p['kernel_transfers'])and self.pi==len(self.p['public_handoffs'])and self.smi==len(self.p['scheduling_models'])and self.sfi==len(self.p['scheduling_frames'])and self.rri==len(self.p['registration_returns'])and self.mfi==len(self.p['mode_frames'])and self.mmi==len(self.p['mode_models'])and self.mri==len(self.p['mode_returns'])
  assert self.p['final_model_state']==self.state()
  for at,size,key in((B,0x100000,'final_private_RAM'),(LOW,LOW_SIZE,'final_lower_stack')):assert unpack(self.p[key],at,size)==bytes(self.u.mem_read(at,size));self.counts['whole_final_private_RAM_bytes_checked']+=size
  for at,size,key in((MODE,512,'final_mode512_hex'),(QUEUE,128,'final_queue128_hex'),(BLOCK,40,'final_block40_hex'),(BYREF,32,'final_byref32_hex'),(0x1ed8999d0,1,'final_fork_flag1_hex'),(0x1ed8991c0,8,'final_queue_serial_counter8_hex')):assert self.p[key]==bytes(self.u.mem_read(at,size)).hex();self.counts['complete_constructed_objects_and_globals_bytes_checked']+=size
  if self.application_checked:assert self.p['final_argument_record120_hex']==bytes(self.u.mem_read(int(self.p['argument_record_address'],16),120)).hex()
  self.counts['final_boundaries_checked']+=1;return dict(self.counts)
