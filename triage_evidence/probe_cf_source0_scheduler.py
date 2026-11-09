#!/usr/bin/env python3
"""Original CF source0 collection -> timestamp clear -> Perform -> RUN return.
Descriptor creation/registration are original; source hash metadata and buckets,
CF raw/runtime/dispatch/POSIX, ObjC pool and daemon callback returns are declared.
No native scheduler/IPC/PAC or daemon callback body. O(V*F+J+H*R),O(I+J+R).
"""
import json,struct
from unicorn import arm64_const as A
from daemon_receive_tools import ROOT,CS
from probe_cf_descriptor_source_factory import Probe as Parent,FDO,READ,WRITE
from probe_cf_source_scheduling import B,RL,MODE,SRC,SET0,HALT
from recover_cf_source0_scheduler import P,FLAGS,sha,FUNCS,DO,ONE,CALLOUT,TYPE,END
from recover_cf_descriptor_source_factory import DAEMON
from recover_cf_receive import RUN
from recover_cf_receive_voucher import MACH
POOL=B+0xca000
POINTS=FUNCS|{0x1847571b8,0x1847571bc,0x184758804,0x184758808,0x184758818,0x184758864,0x1847588b0,0x1847588b4,0x1847586dc,0x184758900,0x18475891c,0x184758920}
class Probe(Parent):
 def __init__(self,c,k,s):
  super().__init__(c,k,s);self.scheduler_frames=[];self.scheduler_patches=None;self.callback_calls=[];self.pool_stack=[];self.pool_events=[];self.late_variants=[];self.u.mem_write(POOL,bytes(64)+b'\xa5')
 def sf(self,a):return{'pc':hex(a),**self.frame('source0_scheduler'),'stage':self.stage,'source184_hex':bytes(self.u.mem_read(SRC,184)).hex(),'descriptor112_hex':bytes(self.u.mem_read(FDO,112)).hex(),'source_set64_hex':bytes(self.u.mem_read(SET0,64)).hex(),'model_state':self.state(),'pool_stack':[hex(v)for v in self.pool_stack]}
 def prepare(self):
  e={'before':self.sf(HALT),'patches':[]};cfg=self.config;changes=[]
  if cfg.get('source_valid')is False:changes.append((SRC+8,struct.pack('<Q',int.from_bytes(bytes(self.u.mem_read(SRC+8,8)),'little')&~8)))
  if cfg.get('source_version'):changes.append((SRC+0x68,struct.pack('<Q',cfg['source_version'])))
  if cfg.get('clear_signal'):changes.append((SRC+0x58,bytes(8)))
  if cfg.get('null_perform'):changes.append((SRC+0xb0,bytes(8)))
  if cfg.get('pool_disabled'):changes.append((RL+0xa99,b'\0'))
  for at,raw in changes:e['patches'].append({'address':hex(at),'before_hex':bytes(self.u.mem_read(at,len(raw))).hex(),'after_hex':raw.hex()});self.u.mem_write(at,raw)
  e['after']=self.sf(HALT);self.scheduler_patches=e
 def scheduler_lower(self,a):
  x=[self.reg(j)for j in range(9)];before=self.state();name=None;value=0;patches=[];extra={}
  if a==0x1846da4dc and x[1]==46:
   assert x[2:4]==[168,0];name='declared_source0_runtime_header_type46';value=SRC;raw=bytearray(184);struct.pack_into('<Q',raw,8,46<<8);patches=[(SRC,bytes(raw))]
  elif a==0x1846fb960 and x[0]==SET0:
   assert x[1:3]==[SRC,SRC];name='declared_source0_hash_add_and_count';self.collections[SET0].add(SRC);patches=[(SET0+0x14,struct.pack('<I',len(self.collections[SET0]))),(SET0+0x1a,b'\x01')]
  elif a==0x18471c584 and x[0]==SET0:
   assert x[1]==0 and self.collections[SET0]=={SRC};name='declared_source0_hash_bucket';patches=[(x[8],struct.pack('<4Q',0,SRC,SRC,1))]
  elif a==0x184833260 and x[:2]==[46,SRC]:name='declared_source0_nonObjC_type46';value=0
  elif a==0x188076e60:
   assert not self.pool_stack;name='declared_objc_autorelease_pool_push';value=POOL;self.pool_stack.append(value);extra={'pool_stack_after':[hex(v)for v in self.pool_stack]};self.pool_events.append({'operation':'push','token':hex(value),'source_visit_index':len(self.visits)})
  elif a==0x188076e50:
   assert self.pool_stack==[x[0]];name='declared_objc_autorelease_pool_pop';self.pool_events.append({'operation':'pop','token':hex(x[0]),'source_visit_index':len(self.visits)});self.pool_stack.pop();extra={'pool_stack_after':[]}
  elif a==DAEMON:
   assert self.stage=='runloop'and x[:3]==[FDO,self.config.get('enable_mask',1),0];entry=self.sf(a);entry['arguments3']=[hex(v)for v in x[:3]];self.callback_calls.append(entry);name='declared_daemon_descriptor_void_callback_return';extra={'callback_arguments3':entry['arguments3']}
  if name:self.mode_model(a,name,value,patches,{'model_state_before':before,**extra});return True
  return False
 def lower(self,a):
  if a==0x188086d70 and self.stage=='runloop':
   self.stage='perform'
   try:return super().lower(a)
   finally:self.stage='runloop'
  return super().lower(a)
 def hook(self,u,a,n,d):
  self.flush()
  if a==ONE and self.config.get('late_change'):
   e={'before':self.sf(a),'patches':[]};kind=self.config['late_change'];at=SRC+(8 if kind=='invalidate'else 0x58);b=struct.pack('<Q',int.from_bytes(bytes(u.mem_read(at,8)),'little')&~8)if kind=='invalidate'else bytes(8);e['patches'].append({'address':hex(at),'before_hex':bytes(u.mem_read(at,8)).hex(),'after_hex':b.hex()});u.mem_write(at,b);e['after']=self.sf(a);self.late_variants.append(e)
  if a in POINTS:self.scheduler_frames.append(self.sf(a))
  if a==HALT and self.stage=='fd_register':
   self.registration_returns.append(self.schedule_frame(a));self.factory_returns.append(self.ff(a));self.prepare();return self.start(RUN,(RL,MODE,1),'AddSource0_to_original_RUN','runloop')
  if a==HALT and self.stage=='runloop':return self.finish('original_source0_RUN_returned',a)
  if a==MACH and self.stage=='runloop':
   from probe_cf_runloop_handoff import USER
   args=[self.reg(j)for j in range(7)]
   if args==[USER,0x07000906,0,3072,self.facility,0,0]:return self.mode_model(a,'declared_source0_nonblocking_receive_timeout',0x10004003,extra={'arguments7':[hex(v)for v in args]})
   assert args==[USER,0x07000806,0,3072,self.facility,0xffffffff,0],([hex(v)for v in args],hex(self.reg(30)));return self.finish('before_original_source0_idle_receive',a)
  if self.scheduler_lower(a):return
  f=next((f for f in self.source['CF_functions']if int(f['start'],16)in FUNCS and int(f['start'],16)<=a<int(f['end'],16)),None)
  if f:
   raw=bytes(u.mem_read(a,4));assert raw==bytes.fromhex(f['bytes'])[a-int(f['start'],16):a-int(f['start'],16)+4];i=next(CS.disasm(raw,a));self.current=len(self.visits);self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});op=i.mnemonic
   if op in('pacibsp','autibsp','paciza','autia','autiza','autda','pacia','pacda','xpaci','xpacd'):u.reg_write(A.UC_ARM64_REG_PC,a+4)
   elif op=='retab':u.reg_write(A.UC_ARM64_REG_PC,self.reg(30))
   elif op in('blraa','blraaz','braa','braaz'):
    target=self.reg(int(i.op_str.split(',')[0].strip()[1:]))
    if op.startswith('blr'):self.setreg(30,a+4)
    u.reg_write(A.UC_ARM64_REG_PC,target)
   else:assert op not in('svc','hvc','smc','brk','mrs','msr')and not op.startswith(('pac','aut','xpac')),(hex(a),op)
   return
  return super().hook(u,a,n,d)
 def run(self):
  r=super().run();assert not self.pool_stack;r.update(scheduler_frames=self.scheduler_frames,declared_late_source_variants=self.late_variants,declared_scheduler_field_variants=self.scheduler_patches,daemon_callback_return_calls=self.callback_calls,declared_pool_events=self.pool_events,final_pool_stack=[],final_source_set64_hex=bytes(self.u.mem_read(SET0,64)).hex(),final_pool65_hex=bytes(self.u.mem_read(POOL,65)).hex());return r

def configs():
 rows=[('read_ready',{}),('read_stale',{'perform_ready':False}),('write_ready',{'enable_mask':2}),('both_ready',{'enable_mask':3}),('read_EINTR',{'poll_error':4}),('read_EAGAIN',{'poll_error':35}),('read_EIO',{'poll_error':5}),('no_pending',{'enable_ready':False}),('invalid_source',{'source_valid':False}),('version1_diagnostic',{'source_version':1}),('cleared_signal',{'clear_signal':True}),('null_perform',{'null_perform':True}),('pool_disabled',{'pool_disabled':True}),('cached_source',{'source_repeat':2}),('invalidated_after_collection',{'late_change':'invalidate'}),('cleared_after_collection',{'late_change':'unsignal'})]
 for label,more in rows:yield{'kernel_case':2,'mode':'schedule_then_run','repeat':1,'wake_case':'waiting','send_status':0,'aux':False,'trap_results':[],'label':label,'events':[],'bag_multiplicity':1,'copy_null':False,'enable_ready':True,'perform_ready':True,**more}
if __name__=='__main__':
 s=json.loads((ROOT/(P+'_source.json')).read_text());k=json.loads((ROOT/'cf_runloop_wake_port_profiles.json').read_text())['kernel_cases'][2];cs={**s['CF_source'],'root_caller_options':s['root_caller_options']};rows=[]
 for c in configs():
  try:r=Probe(c,k,cs).run()
  except Exception as e:print('FAILED',c['label'],type(e).__name__,str(e),flush=True);raise
  rows.append(r);print(c['label'],len(r['source_visits']),r['boundary']['kind'],len(r['daemon_callback_return_calls']),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[P+'_source.json','recover_'+P+'.py','probe_cf_descriptor_source_factory.py','cf_runloop_wake_port_profiles.json']},'cases':rows,**{k:False for k in FLAGS}};(ROOT/(P+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
