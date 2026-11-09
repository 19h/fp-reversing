#!/usr/bin/env python3
"""Original AddSource -> dictionary/set wrappers -> original run-loop consumer.
Collection backends and Mach traps are explicit stateful models. Original
instructions create association arguments; no native source registration or IPC.
O(image+visits+RAM+journals) time/space. Public call transitions only.
"""
import json,struct,hashlib
from unicorn import arm64_const as A
from daemon_receive_tools import ROOT,CS
from probe_cf_runloop_handoff import Probe as Parent,B,USER,OOL,OBJ,RL,MODE,SRC,DICT,LOW,LOW_SIZE,HALT,ENTRY_SP
from recover_cf_source_scheduling import P,FLAGS,sha,ADD,GETPORT,DSET,DGET,FIND,SETADD,CONTAINS,BAGADD,HELPERS,TYPE_TRAP,INSERT_TRAP,TASK_CELL
from recover_cf_receive import RUN
from recover_cf_receive_voucher import MACH
NAME=B+0xae000;SET0=B+0xaf000;SET1=B+0xaf100;BAG=B+0xaf200;PSET=0x503;TASK=0x103
NEWFUNCS={ADD,GETPORT,DSET,DGET,FIND,SETADD,CONTAINS,BAGADD,0x18054a938,0x180549f50}
POINTS={ADD,0x18472d9dc,0x18472d9f8,0x18472dbd0,0x18472dbe8,0x18472dc00,0x18472dc18,0x18472dc1c,0x18472dc50,DSET,DGET,FIND,GETPORT}
def configurations():
 return[{'kernel_case':j,'mode':'schedule_then_run','insert_status':0,'repeat':1,'valid':True,'zero_port':False}for j in(2,0,3,1)]+[{'kernel_case':j,'mode':'insert_error','insert_status':4,'repeat':1,'valid':True,'zero_port':False}for j in(2,0,3,1)]+[{'kernel_case':2,'mode':name,'insert_status':0,'repeat':repeat,'valid':valid,'zero_port':zero}for name,repeat,valid,zero in[('duplicate_source',2,True,False),('invalid_source',1,False,False),('zero_port',1,True,True)]]
class Probe(Parent):
 def __init__(self,c,k,s):
  super().__init__(c['kernel_case'],k,s);self.config=c;self.phase='installer';self.public=[];self.registration_returns=[];self.schedule_frames=[];self.schedule_models=[];self.add_calls=0;self.dictionary={};self.collections={SET0:set(),SET1:set(),BAG:set()};self.members=set();self.bag_counts={};self.port=0 if c['zero_port']else int(k['receive_name'],16)
  for a in(NAME,SET0,SET1,BAG):self.u.mem_write(a,bytes(64))
  for a,v in((MODE+0x60,SET0),(MODE+0x68,SET1),(SRC+0x60,BAG),(SRC+0x68,1),(SRC+0xa0,GETPORT),(SRC+8,8 if c['valid']else 0)):self.u.mem_write(a,struct.pack('<Q',v))
  self.u.mem_write(MODE+0x88,struct.pack('<I',PSET));self.u.mem_write(OBJ+0x14,struct.pack('<I',self.port));self.u.mem_write(TASK_CELL,struct.pack('<I',TASK));self.u.mem_write(0x1ed891720,b'\0');self.u.mem_write(DICT+0x12,struct.pack('<H',1));self.u.mem_write(DICT+0x1a,b'\x01')
 def state(self):return{'dictionary':{hex(k):hex(v)for k,v in sorted(self.dictionary.items())},'collections':{hex(k):[hex(v)for v in sorted(values)]for k,values in self.collections.items()},'members':[[hex(a),hex(b)]for a,b in sorted(self.members)],'bag_counts':{hex(k):v for k,v in sorted(self.bag_counts.items())}}
 def schedule_frame(self,a):return{'pc':hex(a),**self.frame('scheduling_stage'),'model_state':self.state(),'mode512_hex':bytes(self.u.mem_read(MODE,512)).hex(),'source256_hex':bytes(self.u.mem_read(SRC,256)).hex(),'CF_object160_hex':bytes(self.u.mem_read(OBJ,160)).hex()}
 def public_call(self,a,args,label):
  e={'kind':label,'before':self.frame('public_return'),'private_RAM_sha256':hashlib.sha256(bytes(self.u.mem_read(B,0x100000))).hexdigest(),'lower_stack_sha256':hashlib.sha256(bytes(self.u.mem_read(LOW,LOW_SIZE))).hexdigest(),'model_state':self.state()};self.public.append(e)
  for j,v in enumerate(args):self.setreg(j,v)
  self.setreg(30,HALT)
  if a==RUN:self.u.reg_write(A.UC_ARM64_REG_Q0,0x7ff0000000000000)
  self.u.reg_write(A.UC_ARM64_REG_PC,a);e['after']=self.frame('public_entry')
 def hook(self,u,a,n,d):
  self.flush()
  if a==HALT and self.phase!='runloop':
   if self.phase=='installer':self.phase='registration';self.add_calls=1;return self.public_call(ADD,(RL,SRC,NAME),'installer_to_AddSource')
   self.registration_returns.append(self.schedule_frame(a))
   if self.add_calls<self.config['repeat']:self.add_calls+=1;return self.public_call(ADD,(RL,SRC,NAME),'repeat_AddSource')
   if self.config['mode']=='schedule_then_run':self.phase='runloop';return self.public_call(RUN,(RL,MODE,1),'AddSource_to_runloop')
   return self.finish('source_registration_returned',a)
  if a in POINTS:self.schedule_frames.append(self.schedule_frame(a))
  if a==MACH:
   assert[self.reg(j)for j in range(7)]==[USER,0x07000806,0,3072,PSET,0xffffffff,0]and(PSET,int(self.input['receive_name'],16))in self.members;self.kernel_transfers.append(self.run_frame(a));return self.runtime_model(a,'selected_kernel_packet_to_declared_portset_receive',0,[(USER,bytes.fromhex(self.input['final_user8192_hex'])[:148]),(OOL,bytes.fromhex(self.input['final_OOL16384_hex'])[:29])])
  if a in HELPERS:
   state=self.state();result=0;patches=[];x=[self.reg(j)for j in range(9)]
   if a==0x184833694:assert x[0]==RL;result=43
   elif a==0x1848316fc:assert x[:3]==[RL,NAME,1];result=MODE
   elif a==0x184833260:assert x[0]in(17,18)and x[1]in self.collections.keys()|{DICT}
   elif a==0x1846dcd84:assert x[0]==DICT;self.dictionary[x[1]]=x[2]
   elif a==0x1846fb710:assert x[0]in self.collections;result=int(x[1]in self.collections[x[0]])
   elif a==0x1846fb960:
    assert x[0]in self.collections and x[1]==x[2];self.collections[x[0]].add(x[1])
    if x[0]==BAG:self.bag_counts[x[1]]=self.bag_counts.get(x[1],0)+1
   elif a==0x18489b724:assert x[0]==DICT;v=self.dictionary.get(x[1],0);patches=[(x[8],struct.pack('<4Q',0,x[1],v,int(bool(v))))]
   elif a==TYPE_TRAP:
    assert x[:2]==[TASK,self.port];result=4 if self.config['zero_port']else 0
    if not result:patches=[(x[2],struct.pack('<I',0x20000))]
   elif a==INSERT_TRAP:
    assert x[:3]==[TASK,self.port,PSET];result=self.config['insert_status']
    if not result:self.members.add((PSET,self.port))
   self.runtime_model(a,HELPERS[a],result,patches);e=self.events[-1];e['model_state_before']=state;e['model_state_after']=self.state();self.schedule_models.append(e);return
  f=next((f for f in self.source['CF_functions']if int(f['start'],16)in NEWFUNCS and int(f['start'],16)<=a<int(f['end'],16)),None)
  if f:
   raw=bytes(u.mem_read(a,4));off=a-int(f['start'],16);assert raw==bytes.fromhex(f['bytes'])[off:off+4];i=next(CS.disasm(raw,a));self.current=len(self.visits);self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()})
   if i.mnemonic in('pacibsp','autibsp','paciza','autia','xpaci'):u.reg_write(A.UC_ARM64_REG_PC,a+4)
   elif i.mnemonic=='retab':u.reg_write(A.UC_ARM64_REG_PC,self.reg(30))
   elif i.mnemonic in('blraa','blraaz','braa','braaz'):
    j=int(i.op_str.split(',')[0].strip()[1:]);target=self.reg(j)
    if i.mnemonic.startswith('blr'):self.setreg(30,a+4)
    u.reg_write(A.UC_ARM64_REG_PC,target)
   else:assert i.mnemonic not in('svc','hvc','smc','brk','mrs','msr')and not i.mnemonic.startswith(('pac','aut','xpac')),(hex(a),i.mnemonic)
   return
  return super().hook(u,a,n,d)
 def run(self):
  r=super().run();r.update(configuration=self.config,public_handoffs=self.public,registration_returns=self.registration_returns,scheduling_frames=self.schedule_frames,scheduling_models=self.schedule_models,final_model_state=self.state(),final_task_cell8_hex=bytes(self.u.mem_read(TASK_CELL,8)).hex());return r
if __name__=='__main__':
 s=json.loads((ROOT/(P+'_source.json')).read_text());ks=json.loads((ROOT/'cf_runloop_handoff_profiles.json').read_text())['kernel_cases'];rows=[]
 for c in configurations():
  r=Probe(c,ks[c['kernel_case']],s).run();rows.append(r);print(c['mode'],c['kernel_case'],r['boundary']['kind'],len(r['source_visits']),r['final_model_state'],flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[P+'_source.json','cf_runloop_handoff_profiles.json','probe_cf_runloop_handoff.py','recover_'+P+'.py']},'kernel_cases':ks,'cases':rows,**FLAGS};(ROOT/(P+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
