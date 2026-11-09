#!/usr/bin/env python3
"""Original daemon MIG502 guards and argument marshalling on kernel-model bytes.
Stops before application execution or before error-path global access.
O(cases*guard visits) time, O(one private map+journals) space. No host IPC.
"""
import json
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,IMAGE,CS
from capture_daemon_record720 import sha
from probe_kernel_vm_mig import Probe as Base,P,SIZE,SP,HALT
USER=P+0x50000;OOL=P+0x70000;REPLY=P+0x80000
class View:
 def __init__(self):self.k=self;self.cs=CS
 def read(self,a,n):return IMAGE.read(a,n)
 def logical_page(self,a):return IMAGE.read(a,4096)
class Probe(Base):
 def __init__(self,view,cfg,kernel_case):
  super().__init__(view,'stub',{'port_class':'null','bits':0,'request_size':56,'address':0,'size':0,'body_placement':'joined'});self.kind='daemon_guard';self.c=cfg;self.u.mem_write(P,bytes(SIZE));self.initial=[];self.image_initial=[];self.fixture(USER,bytes.fromhex(kernel_case['private_user_buffer_hex']));self.fixture(OOL,bytes.fromhex(kernel_case['mapped_payload_hex']));self.fixture(REPLY,bytes([0xa5])*384)
  for j in range(31):self.set(j,0)
  self.set(0,USER);self.set(1,REPLY);self.set(30,HALT);self.entry=0x1000050c8;self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV));self.allowed=[(self.entry,0x1000051fc)]
 def code(self,u,a,n,d):
  self.flush()
  if a==0x1000051f8:return self.stop('before_application')
  if a in [0x100005164,0x100005180,0x100005138]:return self.stop('guard_error',{'error_signed':int.from_bytes(bytes(u.mem_read(REPLY+0x20,4)),'little',signed=True)})
  assert any(lo<=a<hi for lo,hi in self.allowed),hex(a);raw=bytes(u.mem_read(a,4));assert raw==IMAGE.read(a,4);i=next(CS.disasm(raw,a));self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()})
  if i.mnemonic in ['pacibsp','autibsp']:u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  assert i.mnemonic not in ['svc','hvc','smc','brk','bl','blraa'],(hex(a),i.mnemonic)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=20000);self.flush();assert self.reason in ['before_application','guard_error'];r={'kind':self.kind,'configuration':self.c,'entry_PC':hex(self.entry),'entry_SP':hex(SP),'entry_registers31':self.entry_regs,'entry_NZCV':self.entry_NZCV,'private_RAM':{'address':hex(P),'size_bytes':SIZE,'initial_byte':0},'initial_private_fixtures':self.initial,'initial_image_fixtures':[],'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':[],'boundary':self.boundary,'native_target_executed':False,'hardware_PAC_executed':False,'full_goal_complete':False}
  if self.reason=='before_application':r['application_arguments8']=[hex(self.reg(j))for j in range(8)];r['application_stack_arguments5']=[hex(int.from_bytes(bytes(self.u.mem_read(self.u.reg_read(ar.UC_ARM64_REG_SP)+8*j,8)),'little'))for j in range(5)];r['audit_argument_hex']=bytes(self.u.mem_read(self.reg(6),32)).hex()
  return r
if __name__=='__main__':
 kernel=json.loads((ROOT/'rpc502_receive_bridge_profiles.json').read_text());view=View();rows=[]
 for j,r in enumerate(kernel['cases']):p=Probe(view,{'kernel_case_index':j},r).run();rows.append(p);print(j,p['boundary']['kind'],len(p['source_visits']),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['rpc502_receive_bridge_source.json','rpc502_receive_bridge_profiles.json','probe_kernel_vm_mig.py','daemon_receive_tools.py']},'cases':rows,'native_target_executed':False,'native_IPC_executed':False,'native_framework_forwarding_established':False,'full_goal_complete':False};(ROOT/'rpc502_receive_bridge_daemon_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'visits':sum(len(r['source_visits'])for r in rows)}),flush=True)
