#!/usr/bin/env python3
"""Compose captured caller arguments through original wrappers to provider call.

Nominal receiver/descriptor fixtures and abstract authentication only. Stops
before provider BLRAA; no provider code, crypto, native I/O or key/IV read.
"""
import hashlib,json,struct
from pathlib import Path
from unicorn import arm64_const as ar
from kext_port_tools import ROOT,SOURCE,IMAGE,CS
from probe_kext_aes_handoff import Handoff
from probe_kext_buffer_cleanup import OBJ,PROV,STACK,HALT,FLAG,SERVICE,DESC,BYTES
SAMPLE_CELL=0xfffffe000ccc7860;SAMPLE_OBJECT=OBJ+0x100;BRIDGE=0xfffffe000a509fe8
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
class Composed(Handoff):
 def __init__(self):
  super().__init__();source=json.loads((ROOT/'sample_descriptor_contracts.json').read_text());f=next(f for f in source['functions']if int(f['start'],16)==BRIDGE);a,z=int(f['start'],16),int(f['end'],16);[self.u.mem_map(page,4096)for page in range(a&~4095,(z+4095)&~4095,4096)];raw=IMAGE.read(a,z-a);assert raw.hex()==f['bytes_hex'];self.u.mem_write(a,raw);self.ranges.append((a,z));self.decoded.update({i.address:i for i in CS.disasm(raw,a)});self.u.mem_write(SAMPLE_OBJECT,struct.pack('<Q',0xfffffe0007f446c0))
 def code(self,u,a,n,d):
  self.flush()
  if a in self.decoded and self.decoded[a].mnemonic=='blraa':
   target=self.reg(int(self.decoded[a].op_str.split(',')[0][1:]))
   if target==self.perform:
    assert bytes(u.mem_read(a,4))==IMAGE.read(a,4);sp=u.reg_read(ar.UC_ARM64_REG_SP);assert all(self.stack_known[sp-STACK:sp-STACK+24]);self.observation={'pc':hex(a),'target':hex(target),'registers8':[hex(self.reg(i))for i in range(8)],'SP':hex(sp),'stack24_hex':bytes(u.mem_read(sp,24)).hex(),'source_visit_index':len(self.visits),'target_executed':False};return self.stop('before_provider_call')
  return super().code(u,a,n,d)
 def read(self,u,access,a,n,v,d):
  if(a,n)==(SAMPLE_CELL,8):self.reads.append({'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'address':hex(a),'size_bytes':n,'bytes_hex':bytes(u.mem_read(a,n)).hex(),'source_visit_index':len(self.visits)-1});return
  return super().read(u,access,a,n,v,d)
 def run_boundary(self,boundary):
  self.case={'outcome':'provider_boundary'};self.reason=None;self.visits=[];self.reads=[];self.writes=[];self.pending=[];self.calls=[];self.retired=set();self.abstracted=[];self.stack_known=bytearray(4096);self.observation=None
  for i in range(31):self.u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(i)),0)
  self.u.reg_write(ar.UC_ARM64_REG_SP,STACK+0xf00);self.u.reg_write(ar.UC_ARM64_REG_X30,HALT)
  for i,v in enumerate(boundary['registers8']):self.u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(i)),int(v,16))
  for a,v,n in[(FLAG,1,1),(SERVICE,PROV,8),(DESC,OBJ,8),(BYTES,0,8),(SAMPLE_CELL,SAMPLE_OBJECT,8)]:self.u.mem_write(a,v.to_bytes(n,'little'))
  self.u.emu_start(int(boundary['target'],16),0,count=512);self.flush();assert self.reason=='before_provider_call',self.reason;assert not self.calls
  return {'input_boundary':boundary,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'abstracted_authentication':self.abstracted,'provider_observation':self.observation,'nominal_provider':hex(PROV),'nominal_global_descriptor':hex(OBJ),'nominal_sample_descriptor':hex(SAMPLE_OBJECT),'native_API_executed':False,'crypto_operation_executed':False,'provider_code_executed':False}
def main():
 p=json.loads((ROOT/'sample_transfer_profiles.json').read_text());q=Composed();rows=[]
 for i,r in enumerate(p['cases']):
  for b in r['crypto_boundaries']:record=q.run_boundary(b);record['source_case_index']=i;rows.append(record)
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in['sample_transfer_profiles.json','probe_kext_aes_handoff.py','probe_kext_buffer_cleanup.py','sample_descriptor_contracts.json','kext_aes_handoff_contracts.json']},'cases':rows,'native_target_executed':False,'crypto_operation_executed':False,'full_goal_complete':False};(ROOT/'sample_transfer_handoff_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'composed_cases':len(rows),'source_visits':sum(len(r['source_visits'])for r in rows)}),flush=True)
if __name__=='__main__':main()
