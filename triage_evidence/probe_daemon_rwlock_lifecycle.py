#!/usr/bin/env python3
"""Original paired rwlock creation and state09 publication,plus isolated guard.
Caller roots,initial cells,malloc returns and pthread statuses are private
fixtures. No native allocation,pthread,Mach,IOKit or PAC executes. O(B+C*(V+E+JF))
time,O(B+C*(V+E)+F+4096J) space. Opaque allocated bytes remain unknown.
"""
import hashlib,json,itertools,struct
from pathlib import Path
from unicorn import arm64_const as ar
from probe_daemon_iokit_errors import Errors
from probe_daemon_iokit_sync import cases as base_cases,P,PRIMARY,FALLBACK,STATE
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS
from daemon_import_bindings import binding
ENTRY=0x1002dab28;HELPER=0x10043a240;SECOND=0x1010c5748;TABLE=0x101039ef0;STOP=P+0xf600
RANGES=[(ENTRY,0x1002dad84),(HELPER,0x10043a420),(0x1001937e4,0x10019388c),(0x100130f60,0x100130fdc),(0x1003131a4,0x1003131cc),(0x10014d86c,0x10014d8b4),(0x100276ba0,0x100276be0),(0x1002c67e0,0x1002c6824),(0x100269a88,0x100269ab8),(0x10014d328,0x10014d33c),(0x1001a84bc,0x1001a84d8),(0x1002097dc,0x1002097f4),(0x1001c0128,0x1001c014c),(0x1001f1f98,0x1001f200c)]
CALLS={0x1002dac48:PRIMARY,0x1002dad48:SECOND};APIS={0x10019385c:('malloc',0x10109ff58,0x6aa4),0x100130fcc:('rwlock_init',0x1010a0dd0,0xa027)}
class Lifecycle(Errors):
 def __init__(self,c):
  super().__init__(c);self.life_models=[];self.creator_calls=[];self.creator_returns=[];self.C=P+0x8000+c['placement'];self.CFP=self.C+0x600;self.R=self.CFP-0xd8;self.active=0;self.heap=[P+0x2000,P+0x3000];self.isolated=c.get('isolated',False)
  self.initial=[e for e in self.initial if not any(int(e['address'],16)<h+200 and int(e['address'],16)+len(bytes.fromhex(e['bytes_hex']))>h for h in self.heap)]
  for h in self.heap:self.u.mem_write(h,b'\xa5'*200);self.known[h-P:h-P+200]=bytes(200);self.prov[h-P:h-P+200]=bytes(200)
  self.image_initial_fixtures=[e for e in self.image_initial_fixtures if int(e['address'],16)not in [PRIMARY,FALLBACK,STATE]]
  for a,b in [(PRIMARY,struct.pack('<Q',c['old_cell'])),(SECOND,struct.pack('<Q',c['old_cell'])),(STATE,bytes([c['initial_state']]))]:self.page(a);self.u.mem_write(a,b);self.image_initial_fixtures.append({'address':hex(a),'bytes_hex':b.hex(),'provenance':3})
  self.u.mem_write(FALLBACK,struct.pack('<Q',FIXUPS[FALLBACK]['target']))
  for off,v in [(0x390,0x1010b7d48),(0x398,0x1010c4670),(0x378,0x100e99a00),(0x370,0x100f4e390),(0x368,0x100fc4230),(0x360,0x101031fa0),(0x350,0x100e99700),(0x348,0x100f4e190)]:self.fixture(self.C+off,struct.pack('<Q',v))
  for j,v in [(19,0x6293),(20,TABLE),(29,self.CFP),(30,STOP)]:self.set(j,v)
  self.u.reg_write(ar.UC_ARM64_REG_SP,self.C);self.fixture(STOP,bytes.fromhex('1f2003d5'));self.entry_regs=[self.reg(j)for j in range(31)]
  if self.isolated:
   r=self.R&0xffffffff;k=((r^0xdc40790b)*0x5973a279)&0xffffffff;self.fixture(self.R,struct.pack('<I',(0xaed7-k)&0xffffffff));self.fixture(self.R+8,struct.pack('<Q',0));self.set(0,self.R)
  self.entry_regs=[self.reg(j)for j in range(31)]
 def write(self,u,access,a,n,v,d):
  if a in [PRIMARY,SECOND,0x1010c5040]and n==8:
   e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':self.seq-1,'address':hex(a),'size_bytes':n};self.writes.append(e);self.pending.append(e);return
  return super().write(u,access,a,n,v,d)
 def api(self,u,a):
  name,slot,div=APIS[a];assert self.reg(8)==0x7c100000 and self.reg(17)==div;params=[self.reg(j)for j in range(8)];cfg=self.c['steps'][self.active]
  if name=='malloc':assert params[0]==200;ret=self.heap[self.active]if cfg['malloc_nonnull']else 0
  else:assert params[:2]==[self.heap[self.active],0];ret=cfg['init_status'];assert bytes(u.mem_read(params[0],8))==bytes(8)
  self.visit(a);self.life_models.append({'pc':hex(a),'source_visit_index':self.seq-1,'name':name,'step':self.active,'binding':binding(slot),'registers8':[hex(v)for v in params],'returned_value':hex(ret),'modeled_writes':[],'native_target_executed':False,'import_guest_target':'0x7c100000','scope':'Original import binding/slot and discriminator identify API;shared opaque guest target is not native address.'});self.set(0,ret)
  for j in range(1,18):self.set(j,0xf000000000000000+j*0x1111)
  u.reg_write(ar.UC_ARM64_REG_NZCV,0xf0000000);self.set(30,a+4);u.reg_write(ar.UC_ARM64_REG_PC,a+4)
 def code(self,u,a,n,d):
  self.flush()
  if a==STOP:return self.stop_at(a,'after_isolated_null_cell_creator')
  if a==0x1003062a4:return self.stop_at(a,'before_creator_caller_join')
  if a in APIS:return self.api(u,a)
  if a in CALLS:
   self.active=0 if a==0x1002dac48 else 1;assert self.reg(8)==HELPER and self.reg(17)==0x8c6d and self.reg(0)==self.R;self.creator_calls.append({'pc':hex(a),'source_visit_index':self.seq,'step':self.active,'record':self.snapshot(self.R,20),'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'registers31':[hex(self.reg(j))for j in range(31)]});self.visit(a);self.set(30,a+4);return u.reg_write(ar.UC_ARM64_REG_PC,HELPER)
  if a in [pc+4 for pc in CALLS]:
   p=self.creator_calls[-1];assert u.reg_read(ar.UC_ARM64_REG_SP)==int(p['SP'],16)and [hex(self.reg(j))for j in range(19,30)]==p['registers31'][19:30];self.creator_returns.append({'pc':hex(a),'source_visit_index':self.seq,'step':p['step'],'record':self.snapshot(self.R,20),'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP))})
  if not any(x<=a<a+4<=z for x,z in RANGES):return super().code(u,a,n,d)
  i=next(self.dec.disasm(IMAGE.read(a,4),a));m=i.mnemonic;assert m not in ['bl','blr','blraa','br','svc','hvc','smc'];self.visit(a)
  if m=='braa':
   target=self.reg(int(i.op_str.split(',',1)[0][1:]));assert any(x<=target<z for x,z in RANGES)or target==0x1003062a4,(hex(a),hex(target));self.edges.append({'pc':hex(a),'source_visit_index':self.seq-1,'target':hex(target),'modifier16':hex(self.reg(17))});return u.reg_write(ar.UC_ARM64_REG_PC,target)
  if m in ['pacibsp','paciasp','autibsp','autiasp']:return u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  if m in ['ret','retab','retaa']:return u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30))
 def run(self):
  a=HELPER if self.isolated else ENTRY;self.page(a);self.u.emu_start(a,0,count=6000);self.flush();assert self.reason in ['before_creator_caller_join','after_isolated_null_cell_creator'];r=self.base_report();r.update(sync_models=self.sync_models,status_calls=self.status_calls,status_returns=self.status_returns,isolated=self.isolated,lifecycle_models=self.life_models,creator_calls=self.creator_calls,creator_returns=self.creator_returns,creator_record=self.snapshot(self.R,20),caller_SP=hex(self.C),caller_FP=hex(self.CFP),entry_registers31=[hex(x)for x in self.entry_regs],primary_value=hex(int.from_bytes(self.u.mem_read(PRIMARY,8),'little')),secondary_value=hex(int.from_bytes(self.u.mem_read(SECOND,8),'little')),heap_snapshots=[self.snapshot(h,200)for h in self.heap],saved_primary_cell_pointer=self.snapshot(self.F+0x50,8),outer_result_word=self.snapshot(self.F+0x60,4),outer_input_record=self.snapshot(P+0x2000,8));return r
def cases():
 base=next(base_cases());opts=[{'malloc_nonnull':False,'init_status':0}]+[{'malloc_nonnull':True,'init_status':v}for v in [0,12,16,22,0xffffffff]]
 for a,b,placement,old,state in itertools.product(opts,opts,[0,0x100],[0,P+0x5000],[0,10]):
  c=json.loads(json.dumps(base));c.update(steps=[a,b],placement=placement,old_cell=old,initial_state=state,isolated=False);yield c
 for placement in [0,0x100]:
  c=json.loads(json.dumps(base));c.update(steps=opts[:1],placement=placement,old_cell=0,initial_state=0,isolated=True);yield c
def main():
 rows=[]
 for j,c in enumerate(cases()):
  f=Lifecycle(c);rows.append(f.run());del f
  if j%32==0:print(json.dumps({'cases_completed':j+1}),flush=True)
 sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in ['probe_daemon_iokit_errors.py','probe_daemon_iokit_sync.py','probe_daemon_iokit_class.py','probe_daemon_iokit_objects.py','probe_daemon_query_fallback.py','probe_daemon_query_state.py','probe_daemon_iokit_census.py','daemon_receive_tools.py','daemon_import_bindings.py','daemon_receive_fixups.txt']},'source_sha256':sha(SOURCE),'cases':rows,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_rwlock_lifecycle_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(len(r['source_visits'])for r in rows)}),flush=True)
if __name__=='__main__':main()
