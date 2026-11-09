#!/usr/bin/env python3
"""Original kernel delivery at actual CF options/capacity; original CF receive
and libkernel voucher bodies consume the exact outputs through an explicit
Mach-call/task transfer contract. O(source+visits+RAM+journals) time/space.
No native Mach/VM, thread, runtime table installation or target execution.
"""
import json,struct,hashlib
from daemon_receive_tools import ROOT
from recover_cf_receive_voucher import P,FLAGS,sha
from probe_kernel_request_delivery import Probe as KernelProbe
from kernel_vm_mig_tools import Image
from probe_cf_daemon_request import Probe as DispatchProbe
from probe_kernel_vm_mig import Probe as CPU,P as B,SIZE,SP,HALT
from probe_rpc502_vm_handoff import compressed
from recover_cf_receive_voucher import CacheView,MACH,REVERT,ADOPT,INIT,ROOTCELL
from recover_cf_receive import SERVICE
from unicorn import arm64_const as A
USER=B+0x1000;OOL=B+0x4000;BUF=B+0xb2000;LIVE=B+0xb4000;STATE=B+0xb6000;COPY=B+0xb8000;TABLE=B+0xbc000
class Consumer(CPU):
 def __init__(self,source,index,kernel,mode):
  self.source=source;self.kernel=kernel;self.index=index;self.mode=mode;super().__init__(CacheView(source),'selector',{'id':0});self.kind='CF_receive_voucher';self.c={'kernel_producer':index,'table_mode':mode};self.initial=[];self.image_initial=[];self.frames=[];self.patches=[];self.transition=None;self.phase='initializer'if mode=='published_null_callbacks'else'service';self.allowed=[(int(f['start'],16),int(f['end'],16))for f in source['functions']+source['import_stubs']]
  for a,b in[(USER,b'\xa5'*8192),(OOL,b'\xa5'*16384),(BUF,struct.pack('<Q',USER)),(LIVE,b'\xa5'*8),(STATE,b'\xff'*8),(COPY,b'\xa5'*8),(TABLE,bytes(48))]:self.fixture(a,b)
  self.ensure(ROOTCELL,8)
  for j in range(31):self.set(j,0)
  self.set(30,HALT);self.u.reg_write(A.UC_ARM64_REG_SP,SP);self.u.reg_write(A.UC_ARM64_REG_NZCV,0x40000000)
  if self.phase=='initializer':self.set(0,TABLE);self.entry=INIT
  else:self.cf_arguments();self.entry=SERVICE
  self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(A.UC_ARM64_REG_NZCV))
 def cf_arguments(self):
  for j,v in enumerate((int(self.kernel['receive_name'],16),BUF,LIVE,0xffffffff,STATE,COPY)):self.set(j,v)
  self.set(30,HALT)
 def frame(self,a):
  return {'pc':hex(a),'phase':self.phase,'source_visit_index':len(self.visits),'registers31':[hex(self.reg(j))for j in range(31)],'SP':hex(self.u.reg_read(A.UC_ARM64_REG_SP)),'NZCV':hex(self.u.reg_read(A.UC_ARM64_REG_NZCV)),'Q_registers32':[hex(self.u.reg_read(getattr(A,'UC_ARM64_REG_Q'+str(j))))for j in range(32)],'user148_hex':bytes(self.u.mem_read(USER,148)).hex(),'OOL29_hex':bytes(self.u.mem_read(OOL,29)).hex(),'hook_root8_hex':bytes(self.u.mem_read(ROOTCELL,8)).hex(),'voucher_state8_hex':bytes(self.u.mem_read(STATE,8)).hex(),'voucher_copy8_hex':bytes(self.u.mem_read(COPY,8)).hex(),'live_name8_hex':bytes(self.u.mem_read(LIVE,8)).hex()}
 def write(self,u,t,a,n,v,d):
  assert B<=a<a+n<=B+SIZE or(a==ROOTCELL and n==8);e={'pc':hex(u.reg_read(A.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'address':hex(a),'size_bytes':n,'before_hex':bytes(u.mem_read(a,n)).hex()};self.writes.append(e);self.pending.append(e)
 def code(self,u,a,n,d):
  self.flush()
  if a==HALT:
   if self.phase=='initializer':
    self.transition={'before':self.frame(a),'private_RAM_before':compressed(bytes(u.mem_read(B,SIZE)))};assert self.reg(0)==0;self.phase='service';self.cf_arguments();self.transition['after']=self.frame(SERVICE);u.reg_write(A.UC_ARM64_REG_PC,SERVICE);return
   return self.stop('CF_receive_helper_returned')
  if a in(INIT,SERVICE,0x184758ac4,MACH,REVERT,ADOPT,0x184758b98):self.frames.append(self.frame(a))
  if a==MACH:
   assert[self.reg(j)for j in range(7)]==[USER,0x07000806,0,3072,int(self.kernel['receive_name'],16),0xffffffff,0];event={'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments8':[hex(self.reg(j))for j in range(8)],'patches':[]}
   for at,data in((USER,bytes.fromhex(self.kernel['final_user8192_hex'])[:148]),(OOL,bytes.fromhex(self.kernel['final_OOL16384_hex'])[:29])):event['patches'].append({'address':hex(at),'before_hex':bytes(u.mem_read(at,len(data))).hex(),'after_hex':data.hex()});u.mem_write(at,data)
   self.patches.append(event);return self.model(a,'exact_original_kernel_delivery_return_contract',int(self.kernel['boundary']['registers31'][0],16))
  assert any(lo<=a<hi for lo,hi in self.allowed),hex(a);raw=bytes(u.mem_read(a,4));assert raw==self.image.k.read(a,4);i=next(self.image.k.cs.disasm(raw,a));self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()})
  if i.mnemonic in('pacibsp','autibsp'):u.reg_write(A.UC_ARM64_REG_PC,a+4)
  elif i.mnemonic=='retab':u.reg_write(A.UC_ARM64_REG_PC,self.reg(30))
  elif i.mnemonic in('braa','braaz'):u.reg_write(A.UC_ARM64_REG_PC,self.reg(int(i.op_str.split(',')[0].strip()[1:])))
  else:assert i.mnemonic not in('svc','hvc','smc','brk','blraa')and not i.mnemonic.startswith(('pac','aut','xpac')),(hex(a),i.mnemonic)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=5000);self.flush();assert self.reason=='CF_receive_helper_returned'
  return {'kind':self.kind,'configuration':self.c,'entry_PC':hex(self.entry),'entry_SP':hex(SP),'entry_registers31':self.entry_regs,'entry_NZCV':self.entry_NZCV,'private_RAM':{'address':hex(B),'size_bytes':SIZE,'initial_byte':0},'initial_private_fixtures':self.initial,'initial_image_fixtures':[],'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'boundary':self.boundary,'initializer_to_CF_call':self.transition,'frames':self.frames,'kernel_return_transfers':self.patches,'final_private_RAM':compressed(bytes(self.u.mem_read(B,SIZE))),'final_hook_root8_hex':bytes(self.u.mem_read(ROOTCELL,8)).hex(),'final_user8192_hex':bytes(self.u.mem_read(USER,8192)).hex(),'final_OOL16384_hex':bytes(self.u.mem_read(OOL,16384)).hex(),'final_buffer_pointer8_hex':bytes(self.u.mem_read(BUF,8)).hex(),'final_live_name8_hex':bytes(self.u.mem_read(LIVE,8)).hex(),'final_voucher_state8_hex':bytes(self.u.mem_read(STATE,8)).hex(),'final_voucher_copy8_hex':bytes(self.u.mem_read(COPY,8)).hex(),**FLAGS}
def produce_kernel():
 im=Image();src=json.loads((ROOT/'kernel_request_delivery_source.json').read_text());old=json.loads((ROOT/'kernel_request_delivery_profiles.json').read_text());rows=[]
 for j,loan in enumerate(old['loans']):
  cfg={'producer':j,'capacity':3072,'options':0x07000806};r=KernelProbe(im,src,cfg,loan).run();assert r['boundary']['kind']=='receive_frontend_returned'and r['boundary']['registers31'][0]=='0x0';rows.append(r);print('kernel',j,len(r['source_visits']),r['user_byte_copy_contracts'][-1]['arguments3'],flush=True)
 return rows
if __name__=='__main__':
 src=json.loads((ROOT/(P+'_source.json')).read_text());rows=produce_kernel();consumers=[]
 for j,k in enumerate(rows):
  for mode in('file_default','published_null_callbacks'):
   r=Consumer(src,j,k,mode).run();consumers.append(r);print('CF',j,mode,len(r['source_visits']),r['boundary']['registers31'][0],flush=True)
 dispatch_source=json.loads((ROOT/'cf_daemon_request_source.json').read_text());dispatch=[]
 for j,k in enumerate(rows):
  received=consumers[2*j];assert received['final_user8192_hex']==k['final_user8192_hex']and received['final_OOL16384_hex']==k['final_OOL16384_hex'];supplied={**k,'final_user8192_hex':received['final_user8192_hex'],'final_OOL16384_hex':received['final_OOL16384_hex']};r=DispatchProbe(j,supplied,dispatch_source).run();r['CF_receive_case_index']=2*j;dispatch.append(r);print('dispatch',j,r['boundary']['kind'],len(r['source_visits']),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[P+'_source.json','kernel_request_delivery_profiles.json','kernel_request_delivery_source.json','probe_kernel_request_delivery.py','probe_kernel_vm_mig.py','kernel_vm_mig_tools.py','recover_'+P+'.py','probe_cf_daemon_request.py','cf_daemon_request_source.json']},'kernel_cases':rows,'cases':consumers,'dispatch_cases':dispatch,**FLAGS};(ROOT/(P+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
