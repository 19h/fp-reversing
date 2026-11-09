#!/usr/bin/env python3
"""Original constructed mode -> finite declared control receives -> service.
Control packets are synthetic ABI fixtures, never original-kernel outputs.
Empty root/timer/mode bodies execute; retain/release/cardinality remain declared.
"""
import json,struct
from unicorn import arm64_const as A
from daemon_receive_tools import ROOT,CS
from probe_cf_mode_construction import Probe as Parent,B,MODE,RL,QUEUE,TLS,BLOCK,CALLBACK,HALT
from probe_cf_runloop_handoff import USER
from recover_cf_receive import RUN
from recover_cf_receive_voucher import MACH
from recover_cf_control_port_dispatch import P,FLAGS,sha,ROOTPERFORM,TIMERS,ARM,EMPTY,BOUNDARIES
NEWFUNCS={ROOTPERFORM,TIMERS,ARM,EMPTY}
PORTS={'root':0x607,'timer':0x707,'wake':0x807}
POINTS={0x184757310,0x184757324,0x184757330,0x1847573e4,0x1847573f8,0x184757548,0x184757574,0x1847575a0,0x1847575c4,0x1847576f4,0x1847577b0,ROOTPERFORM,0x1855226e8,TIMERS,0x18477210c,ARM,0x18471cf4c,EMPTY,0x184756e68}
def configurations():
 return[{'kernel_case':j,'control_sequence':[],'timer_callback_before_run':False}for j in(0,2)]+[{'kernel_case':2,'control_sequence':seq,'timer_callback_before_run':armed}for seq,armed in[(['wake'],False),(['timer'],False),(['root'],False),(['root'],True),(['wake','timer','root'],False),(['root','root'],False)]]+[{'kernel_case':2,'control_sequence':['wake'],'timer_callback_before_run':False,'control_message_id':0x7f021234}]
def control_packet(kind,message_id=0):
 name=PORTS[kind];return struct.pack('<6I',0,24,0,name,0,message_id)+struct.pack('<2I',0,68)+bytes(60)
class Probe(Parent):
 def __init__(self,c,k,s):
  super().__init__({'kernel_case':c['kernel_case'],'mode':'schedule_then_run','repeat':1,**c},k,s);self.control_models=[];self.control_frames=[];self.callback_returns=[];self.control_cursor=0;self.control_code={int(i['ea'],16):bytes.fromhex(f['bytes'])[4*j:4*j+4]for f in s['CF_functions']if int(f['start'],16)in NEWFUNCS for j,i in enumerate(f['instructions'])}
 def control_frame(self,a):return{'pc':hex(a),**self.frame('control_dispatch_stage'),'mode512_hex':bytes(self.u.mem_read(MODE,512)).hex(),'queue128_hex':bytes(self.u.mem_read(QUEUE,128)).hex(),'model_state':self.state(),'control_cursor':self.control_cursor}
 def control_model(self,a,name,result,patches=(),extra=None):
  self.mode_model(a,name,result,patches,extra);self.control_models.append(self.mode_models[-1])
 def hook(self,u,a,n,d):
  self.flush()
  if a==HALT and self.phase=='registration'and self.config['timer_callback_before_run']:
   self.registration_returns.append(self.schedule_frame(a));self.phase='callback_before_run';return self.public_call(CALLBACK,(BLOCK,),'AddSource_to_control_timer_callback')
  if a==HALT and self.phase=='callback_before_run':
   self.callback_returns.append(self.control_frame(a));self.phase='runloop';return self.public_call(RUN,(RL,MODE,1),'control_timer_callback_to_runloop')
  if a in POINTS:self.control_frames.append(self.control_frame(a))
  if a==MACH and self.control_cursor<len(self.config['control_sequence']):
   assert[self.reg(j)for j in range(7)]==[USER,0x07000806,0,3072,self.facility,0xffffffff,0];kind=self.config['control_sequence'][self.control_cursor];assert(self.facility,PORTS[kind])in self.members;self.control_cursor+=1;return self.control_model(a,'declared_control_port_receive',0,[(USER,control_packet(kind,self.config.get('control_message_id',0)))],{'control_kind':kind,'control_ordinal':self.control_cursor,'packet_provenance':'synthetic 24-byte header and 68-byte zero audit trailer; no kernel producer'})
  if a in BOUNDARIES:
   assert self.reg(0)==QUEUE if a!=0x18472907c else self.reg(0)in self.collections;value=len(self.collections[self.reg(0)])if a==0x18472907c else 0;return self.control_model(a,BOUNDARIES[a],value)
  if a in self.control_code:
   raw=bytes(u.mem_read(a,4));assert raw==self.control_code[a];self.current=len(self.visits);self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});i=next(CS.disasm(raw,a));op=i.mnemonic
   if op in('pacibsp','autibsp','autda','xpacd','pacia','pacda','paciza','autia','xpaci'):u.reg_write(A.UC_ARM64_REG_PC,a+4)
   elif op=='retab':u.reg_write(A.UC_ARM64_REG_PC,self.reg(30))
   elif op in('blraa','blraaz','braa','braaz'):
    j=int(i.op_str.split(',')[0].strip()[1:]);target=self.reg(j)
    if op.startswith('blr'):self.setreg(30,a+4)
    u.reg_write(A.UC_ARM64_REG_PC,target)
   else:assert op not in('svc','hvc','smc','brk','mrs','msr')and not op.startswith(('pac','aut','xpac')),(hex(a),op)
   return
  return super().hook(u,a,n,d)
 def run(self):
  r=super().run();assert self.control_cursor==len(self.config['control_sequence']);r.update(control_models=self.control_models,control_frames=self.control_frames,callback_returns=self.callback_returns,final_control_cursor=self.control_cursor);return r
if __name__=='__main__':
 s=json.loads((ROOT/(P+'_source.json')).read_text());ks=json.loads((ROOT/'kernel_portset_delivery_profiles.json').read_text())['kernel_cases'][:4];rows=[]
 for c in configurations():
  r=Probe(c,ks[c['kernel_case']],s).run();rows.append(r);print(c,r['boundary']['kind'],len(r['source_visits']),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[P+'_source.json','cf_mode_construction_source.json','kernel_portset_delivery_profiles.json','probe_cf_mode_construction.py','recover_'+P+'.py']},'kernel_cases':ks,'cases':rows,**FLAGS};(ROOT/(P+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
