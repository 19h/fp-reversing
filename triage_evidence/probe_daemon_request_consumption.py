#!/usr/bin/env python3
"""Transfer exact produced user buffers into original daemon callback execution.
Cross-task/framework entry, private stack/object, logical PAC and reply malloc
remain explicit premises. Stop before application or request destruction.
O(image+visits+buffers+journals), O(image+private RAM+journals). No host IPC.
"""
import json,struct
import unicorn as uc
from unicorn import arm64_const as ar
from daemon_rpc502_probe import Probe as Loader,STACK,STACK_SIZE,HALT
from daemon_receive_tools import ROOT,IMAGE,CS
from recover_daemon_request_consumption import P,FLAGS,sha
B=0x6500000000;USER=B+0x1000;OOL=B+0x4000;REPLY=B+0x80000;OBJ=B+0x90000
class Probe(Loader):
 def __init__(self,index,row,source):
  super().__init__();self.index=index;self.input=row;self.source=source;self.visits=[];self.reads=[];self.write_events=[];self.pending=[];self.events=[];self.frames=[];self.boundary=None;self.current=-1
  self.u.reg_write(ar.UC_ARM64_REG_CPACR_EL1,3<<20)
  self.u.mem_map(B,0x100000);self.u.mem_write(STACK,bytes([0xa5])*STACK_SIZE)
  self.u.mem_write(USER,bytes.fromhex(row['final_user8192_hex']));self.u.mem_write(OOL,bytes.fromhex(row['final_OOL16384_hex']));self.u.mem_write(REPLY,bytes([0xa5])*384)
  for j in range(31):self.setreg(j,0)
  for j,v in enumerate([OBJ,USER,80,0]):self.setreg(j,v)
  self.setreg(30,HALT);self.u.reg_write(ar.UC_ARM64_REG_SP,STACK+0x78000);self.u.reg_write(ar.UC_ARM64_REG_NZCV,0x40000000)
  self.entry=self.frame('callback_entry');self.allowed=[(int(r['start'],16),int(r['end'],16))for r in source['ranges']]
 def frame(self,label):
  return {'label':label,'source_visit_index':len(self.visits),'registers31':[hex(self.reg(j))for j in range(31)],'SP':hex(self.u.reg_read(ar.UC_ARM64_REG_SP)),'NZCV':hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV)),'Q_registers32':[hex(self.u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j))))for j in range(32)]}
 def flush(self):
  for e in self.pending:e['after_hex']=bytes(self.u.mem_read(int(e['address'],16),e['size_bytes'])).hex()
  self.pending=[]
 def write_hook(self,u,t,a,n,v,d):
  e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':self.current,'address':hex(a),'size_bytes':n,'before_hex':bytes(u.mem_read(a,n)).hex()};self.write_events.append(e);self.pending.append(e)
 def read_hook(self,u,t,a,n,v,d):
  self.reads.append({'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':self.current,'address':hex(a),'size_bytes':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()})
 def finish(self,kind,pc):
  self.boundary={'kind':kind,'pc':hex(pc),**self.frame('boundary')};self.u.emu_stop()
 def hook(self,u,a,n,d):
  self.flush()
  if a==HALT:return self.finish('callback_returned',a)
  if a==0x100422d48:return self.finish('before_application',a)
  if a in self.imports:
   name=self.imports[a];e={'name':name,'pc':hex(a),'before_source_visit_index':len(self.visits),'before':self.frame('before_import')};self.events.append(e)
   if name=='libSystem/_mach_msg_destroy':return self.finish('before_request_destroy',a)
   assert name=='libSystem/_malloc'and self.reg(0)==384,(name,self.reg(0))
   ret=self.reg(30)
   for j in range(18):self.setreg(j,((j+1)*0x123456789abcdef)^0x8b3dc651)
   self.setreg(0,REPLY);u.reg_write(ar.UC_ARM64_REG_NZCV,0xf0000000);u.reg_write(ar.UC_ARM64_REG_PC,ret);e['after']=self.frame('after_import');e['return_pc']=hex(ret);e['result']=hex(REPLY);return
  assert any(lo<=a<hi for lo,hi in self.allowed),('unreviewed',hex(a))
  raw=bytes(u.mem_read(a,4));assert raw==IMAGE.read(a,4);i=next(CS.disasm(raw,a));self.current=len(self.visits);self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()})
  if a in [0x100005274,0x1000050c8,0x1000051f8,0x10006ce34]:self.frames.append({'pc':hex(a),**self.frame('handoff')})
  if i.mnemonic in ['pacibsp','paciasp','autibsp','autiasp','xpaclri','bti']:u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  elif i.mnemonic in ['retab','retaa']:u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30))
  elif i.mnemonic in ['braa','braaz','brab','brabz','blraa','blraaz','blrab','blrabz']:
   reg=int(i.op_str.split(',')[0].strip()[1:]);target=self.reg(reg)
   if i.mnemonic.startswith('blr'):self.setreg(30,a+4)
   u.reg_write(ar.UC_ARM64_REG_PC,target)
  else:assert not i.mnemonic.startswith(('pac','aut','xpac'))and i.mnemonic not in ['svc','hvc','smc','brk'],(hex(a),i.mnemonic)
 def run(self):
  self.u.emu_start(0x100425f78,0,count=30000);self.flush();assert self.boundary is not None
  out={'kernel_case_index':self.index,'configuration':self.input['configuration'],'entry':self.entry,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.write_events,'imports':self.events,'handoffs':self.frames,'boundary':self.boundary,'final_user8192_hex':bytes(self.u.mem_read(USER,8192)).hex(),'final_OOL16384_hex':bytes(self.u.mem_read(OOL,16384)).hex(),'reply384_hex':bytes(self.u.mem_read(REPLY,384)).hex(),'final_stack524288_sha256':__import__('hashlib').sha256(bytes(self.u.mem_read(STACK,STACK_SIZE))).hexdigest(),'image_writes':[e for e in self.write_events if 0x100000000<=int(e['address'],16)<0x102000000]}
  if self.boundary['kind']=='before_application':
   sp=self.u.reg_read(ar.UC_ARM64_REG_SP);out.update({'application_arguments8':[hex(self.reg(j))for j in range(8)],'application_stack_arguments5':[hex(int.from_bytes(bytes(self.u.mem_read(sp+j*8,8)),'little'))for j in range(5)],'application_audit32_hex':bytes(self.u.mem_read(self.reg(6),32)).hex()})
  out['final_private1048576_sha256']=__import__('hashlib').sha256(bytes(self.u.mem_read(B,0x100000))).hexdigest()
  return out
if __name__=='__main__':
 src=json.loads((ROOT/(P+'_source.json')).read_text());prior=json.loads((ROOT/'kernel_request_delivery_profiles.json').read_text());rows=[]
 for j,row in enumerate(prior['cases']):
  r=Probe(j,row,src).run();rows.append(r);print(j,r['boundary']['kind'],len(r['source_visits']),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in [P+'_source.json','kernel_request_delivery_profiles.json','daemon_rpc502_probe.py','daemon_receive_tools.py','recover_'+P+'.py']},'cases':rows,**FLAGS};(ROOT/(P+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'visits':sum(len(r['source_visits'])for r in rows)}),flush=True)
