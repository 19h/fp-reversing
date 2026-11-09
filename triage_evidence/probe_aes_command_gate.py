#!/usr/bin/env python3
"""Private source components: gate initialization, registration and owner dispatch.
API/PAC/attachment premises are explicit. O(visits+effects), O(source journals+RAM).
"""
import json,struct,hashlib
from unicorn import arm64_const as ar
from probe_kernel_vm_mig import Probe as Base,P,SP,HALT
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
PREFIX='aes_command_gate';PROV=P+0x10000;GATE=P+0x11000;EXP=P+0x12000;LOOP=P+0x13000;POOL=P+0x14000;CMD=P+0x15000
AV=0xfffffe0008588380;GV=0xfffffe0007f3fbb0;WV=0xfffffe0007f3f638;PV=0xfffffe0007f40058;ACTION=0xfffffe000abfd2d8
OBJECTS=[(PROV,0x200),(GATE,0x80),(EXP,0x40),(LOOP,0x100),(POOL,0x100),(CMD,0x90)]
class Probe(Base):
 def __init__(self,im,c,src,origin=None,producer=None):
  super().__init__(im,'selector',{'id':0});self.c=c;self.initial=[];self.indirect=[];self.auth=[];self.action_frames=[];self.effects=[];self.origin=producer;self.end=None
  self.allowed=[(int(r['start'],16),int(r['end'],16))for r in src['functions']]+[(0xfffffe000abffa94,0xfffffe000abffae4)]
  if origin:
   for e in origin['final_objects']:self.fixture(int(e['address'],16),bytes.fromhex(e['bytes_hex']))
  else:
   for a,v in [(PROV,AV),(GATE,GV),(LOOP,WV),(POOL,PV)]:self.fixture(a,struct.pack('<Q',v))
   self.fixture(PROV+0xc0,struct.pack('<Q',LOOP))
  stage=c['stage']
  if stage=='init':self.entry=0xfffffe000c51e6e8;args=[GATE,PROV,0]
  elif stage=='registration':self.entry=0xfffffe000abfc598;self.end=0xfffffe000abfc70c;args=[];self.set(19,PROV)
  else:
   self.entry=0xfffffe000c51e680 if stage=='runCommand'else 0xfffffe000c51e408;args=[GATE,CMD,0,0,0]if stage=='runCommand'else[GATE,0 if c.get('null_action')else ACTION,CMD,0,0,0]
   if c.get('no_loop'):self.fixture(GATE+0x30,bytes(8))
  for j,v in enumerate(args):self.set(j,v)
  self.set(30,HALT);self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV))
 def effect(self,a,b,reason):self.effects.append({'address':hex(a),'before_hex':bytes(self.u.mem_read(a,len(b))).hex(),'after_hex':b.hex(),'reason':reason});self.u.mem_write(a,b)
 def modeled(self,a,name,result):
  effects=self.effects;self.effects=[];self.model(a,name,result);self.models[-1]['memory_effects']=effects
 def code(self,u,a,n,d):
  self.flush()
  if a==HALT:return self.stop('returned')
  if a==self.end:return self.stop('after_registration_component')
  if a==0xfffffe000bcfeb8c:return self.modeled(a,'expansion_allocation_model',EXP)
  if a==0xfffffe000c57b280:return self.modeled(a,'owner_auxiliary_NULL_model',0)
  if a==0xfffffe000c51f3f0:
   assert[self.reg(j)for j in range(2)]==[PROV,0]and self.reg(19)==PROV;return self.modeled(a,'source_initialized_gate_factory_model',GATE)
  if a==0xfffffe000c51a244:
   assert[self.reg(j)for j in range(2)]==[LOOP,GATE];self.effect(GATE+0x30,struct.pack('<Q',LOOP),'Declared attachment effect; addEventSource body is not executed');return self.modeled(a,'attach_gate_model',0)
  if a==0xfffffe000c520c24:assert self.reg(0)==LOOP;return self.modeled(a,'pool_factory_model',POOL)
  if a==0xfffffe000c519c7c:assert self.reg(0)==LOOP;return self.modeled(a,'close_gate_no_effect_model',0)
  if a==0xfffffe000c51a3a8:assert self.reg(0)==LOOP;return self.modeled(a,'on_thread_model',self.c['on_thread'])
  if a==0xfffffe000c519d24:assert self.reg(0)==LOOP;return self.modeled(a,'open_gate_no_effect_model',0)
  if a==ACTION:
   self.action_frames.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments8':[hex(self.reg(j))for j in range(8)],'gate48_hex':bytes(u.mem_read(GATE+0x48,8)).hex(),'return_pc':hex(self.reg(30))})
   if 'action_result'in self.c:return self.modeled(a,'action_result_model',self.c['action_result'])
   return self.stop('before_queue_action')
  if not any(x<=a<z for x,z in self.allowed):return self.stop('before_unmodeled_code')
  raw=bytes(u.mem_read(a,4));assert raw==self.image.k.read(a,4);i=next(self.image.k.cs.disasm(raw,a));self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()})
  if i.mnemonic in ['autda','autia','pacia','pacda','xpaci','xpacd','pacibsp','autibsp']:
   self.auth.append({'pc':hex(a),'source_visit_index':len(self.visits)-1,'mnemonic':i.mnemonic,'operands':i.op_str,'registers18':[hex(self.reg(j))for j in range(18)]});return u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  if i.mnemonic=='retab':return u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30))
  if i.mnemonic in ['braa','blraa']:
   x,y=[int(t.strip()[1:])for t in i.op_str.split(',')];target=self.reg(x);self.indirect.append({'pc':hex(a),'source_visit_index':len(self.visits)-1,'kind':i.mnemonic,'target':hex(target),'modifier':hex(self.reg(y))})
   if i.mnemonic=='blraa':self.set(30,a+4)
   return u.reg_write(ar.UC_ARM64_REG_PC,target)
  assert i.mnemonic not in ['svc','hvc','smc','brk'],(hex(a),i.mnemonic)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=20000);self.flush();assert self.reason in ['returned','after_registration_component','before_queue_action'],self.boundary
  objects=[{'address':hex(a),'bytes_hex':bytes(self.u.mem_read(a,n)).hex()}for a,n in OBJECTS]
  return {'configuration':self.c,'source_producer_case':self.origin,'entry_PC':hex(self.entry),'entry_SP':hex(SP),'entry_registers31':self.entry_regs,'entry_NZCV':self.entry_NZCV,'private_RAM':{'address':hex(P),'size_bytes':0x100000,'initial_byte':0,'native_owner_extents_established':False},'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'logical_authentication':self.auth,'indirect_edges':self.indirect,'action_frames':self.action_frames,'final_objects':objects,'final_RAM_sha256':hashlib.sha256(bytes(self.u.mem_read(P,0x100000))).hexdigest(),'boundary':self.boundary,'native_target_executed':False,'native_IPC_executed':False,'hardware_PAC_executed':False,'idb_mutated':False,'full_goal_complete':False}
def main():
 im=Image();src=json.loads((ROOT/(PREFIX+'_source.json')).read_text());rows=[]
 rows.append(Probe(im,{'stage':'init'},src).run());rows.append(Probe(im,{'stage':'registration'},src,rows[0],0).run())
 for c in [{'stage':'runAction','on_thread':1},{'stage':'runAction','on_thread':0},{'stage':'runAction','on_thread':1,'action_result':0},{'stage':'runAction','on_thread':0,'action_result':4},{'stage':'runCommand'},{'stage':'runAction','no_loop':True},{'stage':'runAction','null_action':True}]:rows.append(Probe(im,c,src,rows[1],1).run())
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in [PREFIX+'_source.json','probe_kernel_vm_mig.py','kernel_vm_mig_tools.py']},'cases':rows,'native_target_executed':False,'native_IPC_executed':False,'hardware_PAC_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(len(r['source_visits'])for r in rows),'boundaries':[r['boundary']['kind']for r in rows]}),flush=True)
if __name__=='__main__':main()
