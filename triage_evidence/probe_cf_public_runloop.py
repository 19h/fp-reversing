#!/usr/bin/env python3
"""Original public CF entry, indexed mode publication, TSD and cleanup.
One private CF epoch; lower runtime/hash/name/locks/ObjC/dispatch/POSIX/receive,
TSD registration and declared daemon callback effects remain explicit.
No native IPC/thread/PAC or daemon callback body. O(V*F+J+H*R),O(I+J+R).
"""
import json,struct
from unicorn import arm64_const as A
from daemon_receive_tools import ROOT,CS
from probe_cf_source0_scheduler import Probe as Parent
from probe_cf_descriptor_source_factory import FDO
from probe_cf_source_scheduling import B,RL,MODE,SRC,SET0,HALT,NAME
from probe_cf_mode_construction import TLS
from probe_cf_wake_send_wrapper import Probe as Wrapper,MACH
from recover_cf_public_runloop import P,FLAGS,sha,FUNCS,FATALS,SPEC,INMODE,PUBLICRUN,WITH,CLEAN,STOP
from recover_cf_descriptor_source_factory import DAEMON
from recover_cf_source_wake_callers import WAKE
from recover_cf_runloop_wake_port import DEFAULT
COMMON=DEFAULT+0x20;TSD=B+0xcb000;PREVIOUS=B+0xcc000;STOP_RETURN=HALT+0x200
POINTS=FUNCS|set(FATALS)|{0x184831b98,0x184831ba0,0x184831bbc,0x184831bc0,0x184831c0c,0x184831c10,0x184832a28,0x184832a48,0x184832a4c,0x184758804,0x18475891c}
class Probe(Parent):
 def __init__(self,c,k,s):
  super().__init__(c,k,s);self.public_frames=[];self.public_initial=[];self.public_variant=None;self.effects=[];self.effect_stack=[];self.effect_done=False;self.public_call_started=False;self.active_run_sp=None;self.active_user=None
  raw=bytearray(1128);struct.pack_into('<Q',raw,8+10*8,RL)
  for at,b in((TSD,bytes(raw)+b'\xa5'),(TLS+0x1b8,struct.pack('<Q',TSD)),(PREVIOUS,bytes(64)+b'\xa5'),(0x1eb15a448,b'\xff'*8)):
   self.public_initial.append({'address':hex(at),'before_hex':bytes(self.u.mem_read(at,len(b))).hex(),'after_hex':b.hex()});self.u.mem_write(at,b)
 def pf(self,a):return{'pc':hex(a),**self.frame('public_runloop'),'stage':self.stage,'runloop2720_hex':bytes(self.u.mem_read(RL,2720)).hex(),'mode512_hex':bytes(self.u.mem_read(MODE,512)).hex(),'TSD1128_hex':bytes(self.u.mem_read(TSD,1128)).hex(),'model_state':self.state(),'pool_stack':[hex(v)for v in self.pool_stack]}
 def public_prepare(self):
  e={'before':self.pf(HALT),'patches':[]};cfg=self.config;changes=[]
  if cfg.get('depth'):changes.append((RL+0x54,bytes([cfg['depth']])))
  if cfg.get('previous_mode'):changes.append((RL+0xa60,struct.pack('<Q',PREVIOUS)))
  if cfg.get('deallocating'):changes.append((RL+8,struct.pack('<Q',int.from_bytes(bytes(self.u.mem_read(RL+8,8)),'little')|4)))
  if cfg.get('forked'):changes.append((0x1ed891720,b'\x01'))
  if cfg.get('empty_mode'):changes.append((SET0+0x14,bytes(4)));self.collections[SET0].clear()
  for at,b in changes:e['patches'].append({'address':hex(at),'before_hex':bytes(self.u.mem_read(at,len(b))).hex(),'after_hex':b.hex()});self.u.mem_write(at,b)
  e['after']=self.pf(HALT);self.public_variant=e
 def public_lower(self,a):
  x=[self.reg(j)for j in range(9)]
  if a==0x1846df588:
   assert x[0]in(DEFAULT,COMMON,NAME)and x[1]in(DEFAULT,COMMON,NAME);return self.mode_model(a,'declared_runloop_mode_name_equality',int(x[0]==x[1]))or True
  if a==0x184833694 and x[0]==RL and self.stage=='runloop'and self.config.get('bad_type'):return self.mode_model(a,'declared_public_runloop_type44',44)or True
  return False
 def begin_effect(self):
  e={'kind':'declared_daemon_callback_requests_original_CFRunLoopStop','before':self.pf(DAEMON)};self.effects.append(e);self.effect_stack.append(e);self.effect_done=True;self.setreg(0,RL);self.setreg(30,STOP_RETURN);self.u.reg_write(A.UC_ARM64_REG_PC,STOP);e['entry']=self.pf(STOP)
 def finish_effect(self):
  e=self.effect_stack.pop();e['original_Stop_return']=self.pf(STOP_RETURN);f=e['before']
  for j,v in enumerate(f['registers31']):self.setreg(j,int(v,16))
  for j,v in enumerate(f['Q_registers32']):self.u.reg_write(getattr(A,'UC_ARM64_REG_Q'+str(j)),int(v,16))
  self.u.reg_write(A.UC_ARM64_REG_SP,int(f['SP'],16));self.u.reg_write(A.UC_ARM64_REG_NZCV,int(f['NZCV'],16));self.u.reg_write(A.UC_ARM64_REG_PC,DAEMON);self.phase='runloop';e['declared_callback_resume']=self.pf(DAEMON)
 def run_frame(self,a):
  sp=self.active_run_sp;assert sp is not None;user=self.active_user
  return{'pc':hex(a),**self.frame('runloop_stage'),'runloop_frame_base':hex(sp),'receive_buffer_address':hex(user),'native_buffer_pointer8_hex':bytes(self.u.mem_read(sp+0x68,8)).hex(),'native_live_name4_hex':bytes(self.u.mem_read(sp+0x64,4)).hex(),'native_reply8_hex':bytes(self.u.mem_read(sp+0x50,8)).hex(),'native_voucher_state8_hex':bytes(self.u.mem_read(sp+0x78,8)).hex(),'native_voucher_copy8_hex':bytes(self.u.mem_read(sp+0x70,8)).hex(),'user148_hex':bytes(self.u.mem_read(user,148)).hex()}
 def hook(self,u,a,n,d):
  self.flush()
  from recover_cf_receive import RUN
  if a==RUN:self.active_run_sp=self.u.reg_read(A.UC_ARM64_REG_SP)-0xd50;self.active_user=self.active_run_sp+0xd0
  if a==STOP_RETURN:return self.finish_effect()
  if a==DAEMON and self.config.get('callback_stop')and not self.effect_done:return self.begin_effect()
  if a==WAKE and self.effect_stack:self.phase='wakeup'
  if a in POINTS:self.public_frames.append(self.pf(a))
  if a in FATALS:return self.finish('before_original_public_runloop_'+FATALS[a],a)
  if a==HALT and self.stage=='fd_register':
   self.registration_returns.append(self.schedule_frame(a));self.factory_returns.append(self.ff(a));self.prepare();self.public_prepare();kind=self.config['entry'];name={'default':DEFAULT,'common':COMMON,'null':0,'missing':NAME}[self.config.get('mode_name','default')];args=(RL,name,self.config.get('boolean',1))if kind=='specific'else(name,self.config.get('boolean',1))if kind=='inmode'else();target=SPEC if kind=='specific'else INMODE if kind=='inmode'else PUBLICRUN;self.public_call_started=True;self.start(target,args,'registered_source_to_public_'+kind,'runloop');self.u.reg_write(A.UC_ARM64_REG_Q0,0x7ff0000000000000);self.public[-1]['after']=self.frame('public_entry');return
  if a==HALT and self.stage=='runloop':return self.finish('original_public_runloop_returned',a)
  if a==MACH and self.effect_stack and self.reg(1)==0x11:return Wrapper.hook(self,u,a,n,d)
  if a==MACH and self.stage=='runloop':
   args=[self.reg(j)for j in range(7)]
   if args==[self.active_user,0x07000906,0,3072,self.facility,0,0]:return self.mode_model(a,'declared_public_runloop_nonblocking_receive_timeout',0x10004003,extra={'arguments7':[hex(v)for v in args]})
   assert args==[self.active_user,0x07000806,0,3072,self.facility,0xffffffff,0],([hex(v)for v in args],hex(self.reg(30)));return self.finish('before_original_public_runloop_idle_receive',a)
  if self.public_lower(a):return
  f=next((f for f in self.source['CF_functions']if int(f['start'],16)in FUNCS and int(f['start'],16)<=a<int(f['end'],16)),None)
  if f:
   raw=bytes(u.mem_read(a,4));assert raw==bytes.fromhex(f['bytes'])[a-int(f['start'],16):a-int(f['start'],16)+4];i=next(CS.disasm(raw,a));self.current=len(self.visits);self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});op=i.mnemonic
   if op in('pacibsp','autibsp','paciza','autia','autiza','autda','pacia','pacda','xpaci','xpacd'):u.reg_write(A.UC_ARM64_REG_PC,a+4)
   elif op=='retab':u.reg_write(A.UC_ARM64_REG_PC,self.reg(30))
   elif op in('blraa','blraaz','braa','braaz'):
    target=self.reg(int(i.op_str.split(',')[0].strip()[1:]))
    if op.startswith('blr'):self.setreg(30,a+4)
    u.reg_write(A.UC_ARM64_REG_PC,target)
   elif op=='mrs':assert i.op_str=='x20, tpidrro_el0'and u.reg_read(A.UC_ARM64_REG_TPIDRRO_EL0)==TLS
   else:assert op not in('svc','hvc','smc','brk','msr')and not op.startswith(('pac','aut','xpac')),(hex(a),op)
   return
  return super().hook(u,a,n,d)
 def run(self):
  r=super().run();assert self.public_call_started and not self.effect_stack;r.update(public_RUN_frames=self.public_frames,active_RUN_frame_base=None if self.active_run_sp is None else hex(self.active_run_sp),active_receive_buffer=None if self.active_user is None else hex(self.active_user),public_initial=self.public_initial,declared_public_field_variants=self.public_variant,declared_callback_effects=self.effects,final_TSD1129_hex=bytes(self.u.mem_read(TSD,1129)).hex(),final_warning_once8_hex=bytes(self.u.mem_read(0x1eb15a448,8)).hex());return r

def configs():
 rows=[('specific_ready',{}),('specific_stale',{'perform_ready':False}),('specific_EIO',{'poll_error':5}),('specific_stop',{'callback_stop':True}),('inmode_ready',{'entry':'inmode'}),('inmode_stop',{'entry':'inmode','callback_stop':True}),('Run_stop',{'entry':'run','callback_stop':True}),('no_pending',{'enable_ready':False}),('missing_mode',{'mode_name':'missing'}),('common_mode',{'mode_name':'common'}),('null_mode',{'mode_name':'null'}),('deallocating',{'deallocating':True}),('depth1_previous',{'depth':1,'previous_mode':True}),('depth253_stop',{'depth':253,'callback_stop':True}),('depth254',{'depth':254}),('depth255',{'depth':255}),('wrong_type',{'bad_type':True}),('fork_diagnostic',{'forked':True}),('boolean2',{'boolean':2}),('boolean0_stop',{'boolean':0,'callback_stop':True}),('empty_mode',{'empty_mode':True})]
 for label,more in rows:yield{'kernel_case':2,'mode':'schedule_then_run','repeat':1,'wake_case':'waiting','send_status':0,'aux':False,'trap_results':[0]if more.get('callback_stop')else[],'label':label,'events':[],'bag_multiplicity':1,'copy_null':False,'enable_ready':True,'perform_ready':True,'entry':'specific',**more}
if __name__=='__main__':
 s=json.loads((ROOT/(P+'_source.json')).read_text());k=json.loads((ROOT/'cf_runloop_wake_port_profiles.json').read_text())['kernel_cases'][2];cs={**s['CF_source'],'root_caller_options':s['root_caller_options']};rows=[]
 for c in configs():
  try:r=Probe(c,k,cs).run()
  except Exception as e:print('FAILED',c['label'],type(e).__name__,str(e),flush=True);raise
  rows.append(r);print(c['label'],len(r['source_visits']),r['boundary']['kind'],r['boundary']['registers31'][0],flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[P+'_source.json','recover_'+P+'.py','probe_cf_source0_scheduler.py','cf_runloop_wake_port_profiles.json']},'cases':rows,**{k:False for k in FLAGS}};(ROOT/(P+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
