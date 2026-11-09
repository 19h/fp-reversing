#!/usr/bin/env python3
"""Continuous original callback -> application -> selected cached libbsm body.
Only malloc, stack-check preservation, logical PAC and library pairing are
premises. Stop before pthread identity. O(image+visits+journals+RAM) time/space.
No native service, loader, API, IPC or filesystem operations execute.
"""
import hashlib,json,struct
import unicorn as uc
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,IMAGE,CS
from probe_daemon_request_consumption import Probe as Parent,B,USER,OOL,REPLY,STACK,STACK_SIZE,HALT
from recover_daemon_request_application import P,BSM,SLOT,FLAGS,sha
POINTS={0x100023938,0x100023a74,0x10065ffd8,0x10061a2d0,0x1007fc57c,0x10046f89c,BSM,0x1007fc758,0x1005c18c8}
class Probe(Parent):
 def __init__(self,index,row,source):
  super().__init__(index,row,source);self.application_handoff=None;self.application_frames=[];self.stack_checks=[];self.audit_record=None;self.binding={'slot':hex(SLOT),'before_logical_hex':bytes(self.u.mem_read(SLOT,8)).hex(),'after_logical_hex':struct.pack('<Q',BSM).hex()};self.u.mem_write(SLOT,struct.pack('<Q',BSM))
  f=source['cache_function'];lo=int(f['start'],16);hi=int(f['end'],16);self.allowed.append((lo,hi));self.cache_range=(lo,hi);raw=bytes.fromhex(f['bytes'])
  for a in range(lo&~4095,(hi+4095)&~4095,4096):self.u.mem_map(a,4096,uc.UC_PROT_READ|uc.UC_PROT_EXEC)
  self.u.mem_write(lo,raw)
 def snap(self,label):
  return {'pc':hex(self.u.reg_read(ar.UC_ARM64_REG_PC)),**self.frame(label),'private1048576_sha256':hashlib.sha256(bytes(self.u.mem_read(B,0x100000))).hexdigest(),'stack524288_sha256':hashlib.sha256(bytes(self.u.mem_read(STACK,STACK_SIZE))).hexdigest()}
 def hook(self,u,a,n,d):
  self.flush()
  if a==HALT:return self.finish('callback_returned',a)
  if a==0x100422d48:self.application_handoff=self.snap('continuous_application_entry')
  if a in POINTS:
   f={'pc':hex(a),**self.frame('application_stage')};sp=u.reg_read(ar.UC_ARM64_REG_SP)
   if a==0x100023938:
    self.audit_record=self.reg(1)-0x28;f['audit_copy_arguments3']=[hex(self.reg(j))for j in range(3)];f['audit_source32_hex']=bytes(u.mem_read(self.reg(0),32)).hex()
   if self.audit_record is not None:f['argument_record_address']=hex(self.audit_record);f['argument_record120_hex']=bytes(u.mem_read(self.audit_record,120)).hex()
   if a==0x100023a74:f['control_record_address']=hex(self.reg(0));f['control_record32_hex']=bytes(u.mem_read(self.reg(0),32)).hex()
   if a in (BSM,0x1007fc758):f['stack_argument0_hex']=bytes(u.mem_read(sp,8)).hex()
   if a==BSM:f['audit_input32_hex']=bytes(u.mem_read(self.reg(0),32)).hex();f['PID_output_address']=hex(self.reg(6))
   if a==0x10046f89c:f['copy_arguments3']=[hex(self.reg(j))for j in range(3)];f['copy_source32_hex']=bytes(u.mem_read(self.reg(0),32)).hex()
   self.application_frames.append(f)
  if a in self.imports:
   name=self.imports[a]
   if name=='libSystem/_pthread_self':
    self.events.append({'name':name,'pc':hex(a),'before_source_visit_index':len(self.visits),'before':self.frame('before_import')});return self.finish('before_pthread_self',a)
   if name=='libSystem/___chkstk_darwin':
    e={'name':name,'pc':hex(a),'before_source_visit_index':len(self.visits),'before':self.frame('before_import'),'return_pc':hex(self.reg(30)),'model':'preserve all registers and memory; no native stack probe'};self.events.append(e);self.stack_checks.append(e);u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30));e['after']=self.frame('after_import');return
   return super().hook(u,a,n,d)
  assert any(lo<=a<hi for lo,hi in self.allowed),('unreviewed',hex(a));raw=bytes(u.mem_read(a,4))
  if not self.cache_range[0]<=a<self.cache_range[1]:assert raw==IMAGE.read(a,4)
  else:off=a-self.cache_range[0];assert raw==bytes.fromhex(self.source['cache_function']['bytes'])[off:off+4]
  i=next(CS.disasm(raw,a));self.current=len(self.visits);self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()})
  if a in (0x100005274,0x1000050c8,0x1000051f8):self.frames.append({'pc':hex(a),**self.frame('handoff')})
  if i.mnemonic in ('pacibsp','paciasp','autibsp','autiasp','xpaclri','bti'):u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  elif i.mnemonic in ('retab','retaa'):u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30))
  elif i.mnemonic in ('braa','braaz','brab','brabz','blraa','blraaz','blrab','blrabz'):
   j=int(i.op_str.split(',')[0].strip()[1:]);target=self.reg(j)
   if i.mnemonic.startswith('blr'):self.setreg(30,a+4)
   u.reg_write(ar.UC_ARM64_REG_PC,target)
  else:assert not i.mnemonic.startswith(('pac','aut','xpac'))and i.mnemonic not in ('svc','hvc','smc','brk'),(hex(a),i.mnemonic)
 def run(self):
  r=super().run();assert self.boundary['kind']=='before_pthread_self'and self.application_handoff is not None;r.update(application_handoff=self.application_handoff,application_frames=self.application_frames,stack_check_contracts=self.stack_checks,logical_library_binding=self.binding,final_argument_record120_hex=bytes(self.u.mem_read(self.audit_record,120)).hex(),argument_record_address=hex(self.audit_record));return r
if __name__=='__main__':
 src=json.loads((ROOT/(P+'_source.json')).read_text());old=json.loads((ROOT/'kernel_request_delivery_profiles.json').read_text());rows=[]
 for j in (1,3):
  r=Probe(j,old['cases'][j],src).run();rows.append(r);print(j,r['boundary']['kind'],len(r['source_visits']),len(r['stack_check_contracts']),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in [P+'_source.json','kernel_request_delivery_profiles.json','probe_daemon_request_consumption.py','daemon_rpc502_probe.py','recover_'+P+'.py']},'cases':rows,**FLAGS};(ROOT/(P+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'visits':sum(len(r['source_visits'])for r in rows)}),flush=True)
