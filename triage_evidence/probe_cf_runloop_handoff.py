#!/usr/bin/env python3
"""Original run-loop entry -> receive/voucher -> lookup/source -> actual daemon.
Declared clocks/no-pending-work/dictionary/runtime contracts; exact original
kernel return transfer. No native run loop, IPC, TSD or hardware PAC executes.
O(image+visits+RAM+journals), O(image+RAM+journals). No internal PC/record edits.
"""
import json,struct,hashlib
from unicorn import arm64_const as A
from daemon_receive_tools import ROOT,CS
from probe_cf_daemon_request import Probe as Parent,POINTS,B,USER,OOL,REPLY,OBJ,RL,MODE,SRC,OUT,STACK,STACK_SIZE,HALT
from recover_cf_runloop_handoff import P,FLAGS,sha,CacheView,initial_max_engine
from recover_cf_receive import RUN
from recover_dispatch_voucher_hooks import DISPATCH_INIT
from recover_cf_receive_voucher import MACH
from probe_rpc502_vm_handoff import compressed
LOW=B-0x200000;LOW_SIZE=0x200000;ENTRY_SP=USER+0xc80;RUN_SP=USER-0xd0;DICT=B+0xad000
EXTRA={0x18054808c:('mach_absolute_ticks_100',100),0x180588804:('not_main_thread',0),0x184832bc8:('iteration_trace_noop',0),0x184758240:('no_pending_blocks',0),0x184758504:('no_pending_source0',0),0x18471b500:('absolute_seconds_zero',0),0x1846ddde4:('TSD_set_prior_null',0),0x1846ddc8c:('declared_source_dictionary',SRC)}
RUN_POINTS={RUN,0x18475730c,0x184757310,0x184757548,0x1847576f4,0x184757718,0x18475771c,0x184757720,0x1847577b0,0x1847577d8,0x184756ef4}
class Probe(Parent):
 def __init__(self,j,k,src):
  super().__init__(j,k,src);self.u=initial_max_engine(self.u,self.hook,self.read_hook,self.write_hook);self.u.mem_map(LOW,LOW_SIZE);self.u.mem_write(LOW,b'\xa5'*LOW_SIZE);self.u.mem_write(USER,b'\xa5'*8192);self.u.mem_write(OOL,b'\xa5'*16384);self.u.mem_write(MODE,bytes(512));self.u.mem_write(MODE+0x80,struct.pack('<Q',DICT));self.u.mem_write(MODE+0x88,struct.pack('<I',int(k['receive_name'],16)));self.u.mem_write(DICT,bytes(64));self.cache_view=CacheView(src)
  for a,v in self.cache_view.pointers.items():self.u.mem_write(a,struct.pack('<Q',v))
  for j in range(31):self.setreg(j,0)
  self.setreg(30,HALT);self.u.reg_write(A.UC_ARM64_REG_SP,ENTRY_SP);self.u.reg_write(A.UC_ARM64_REG_NZCV,0x40000000);self.entry=self.frame('original_voucher_installer_entry');self.phase='installer';self.run_frames=[];self.run_models=[];self.kernel_transfers=[];self.initializer_handoff=None
 def run_frame(self,a):
  return {'pc':hex(a),**self.frame('runloop_stage'),'native_buffer_pointer8_hex':bytes(self.u.mem_read(RUN_SP+0x68,8)).hex(),'native_live_name4_hex':bytes(self.u.mem_read(RUN_SP+0x64,4)).hex(),'native_reply8_hex':bytes(self.u.mem_read(RUN_SP+0x50,8)).hex(),'native_voucher_state8_hex':bytes(self.u.mem_read(RUN_SP+0x78,8)).hex(),'native_voucher_copy8_hex':bytes(self.u.mem_read(RUN_SP+0x70,8)).hex(),'user148_hex':bytes(self.u.mem_read(USER,148)).hex()}
 def runtime_model(self,a,name,result,patches=()):
  e={'name':name,'pc':hex(a),'before_source_visit_index':len(self.visits),'before':self.frame('before_import'),'return_pc':hex(self.reg(30)),'result':hex(result),'patches':[]};self.events.append(e);self.run_models.append(e);target=self.reg(30)
  for at,b in patches:e['patches'].append({'address':hex(at),'before_hex':bytes(self.u.mem_read(at,len(b))).hex(),'after_hex':b.hex()});self.u.mem_write(at,b)
  for j in range(18):self.setreg(j,((j+1)*0x123456789abcdef)^0x8b3dc651)
  self.setreg(0,result);self.u.reg_write(A.UC_ARM64_REG_NZCV,0xf0000000)
  if a==0x18471b500:self.u.reg_write(A.UC_ARM64_REG_Q0,0)
  self.u.reg_write(A.UC_ARM64_REG_PC,target);e['after']=self.frame('after_import')
 def hook(self,u,a,n,d):
  self.flush()
  if a==HALT:
   if self.phase=='installer':
    self.initializer_handoff={'before':self.frame('initializer_return'),'private_RAM_sha256':hashlib.sha256(bytes(u.mem_read(B,0x100000))).hexdigest(),'lower_stack_sha256':hashlib.sha256(bytes(u.mem_read(LOW,LOW_SIZE))).hexdigest()};self.phase='runloop'
    for j,v in enumerate((RL,MODE,1)):self.setreg(j,v)
    self.setreg(30,HALT);u.reg_write(A.UC_ARM64_REG_Q0,0x7ff0000000000000);u.reg_write(A.UC_ARM64_REG_PC,RUN);self.initializer_handoff['after']=self.frame('runloop_public_call');return
   return self.finish('original_runloop_returned',a)
  if a in RUN_POINTS:self.run_frames.append(self.run_frame(a))
  if a==MACH:
   assert[self.reg(j)for j in range(7)]==[USER,0x07000806,0,3072,int(self.input['receive_name'],16),0xffffffff,0];patches=[(USER,bytes.fromhex(self.input['final_user8192_hex'])[:148]),(OOL,bytes.fromhex(self.input['final_OOL16384_hex'])[:29])];self.kernel_transfers.append(self.run_frame(a));return self.runtime_model(a,'exact_original_kernel_return',0,patches)
  if a in EXTRA:
   name,value=EXTRA[a]
   if a==0x1846ddc8c:assert self.reg(0)==DICT;value=SRC if self.reg(1)==int(self.input['receive_name'],16)else 0
   return self.runtime_model(a,name,value)
  if a in POINTS and a!=0x100425f78:self.cf_frames.append({'pc':hex(a),**self.frame('CF_daemon_handoff'),'user148_hex':bytes(u.mem_read(USER,148)).hex(),'generic_reply8_hex':bytes(u.mem_read(OUT,8)).hex(),'CF_object160_hex':bytes(u.mem_read(OBJ,160)).hex(),'source256_hex':bytes(u.mem_read(SRC,256)).hex()})
  f=next((f for f in self.source['CF_functions']+self.source['import_stubs']if int(f['start'],16)<=a<int(f['end'],16)),None)
  if f:
   # Existing CF primitive contracts retain their original observers.
   from recover_cf_daemon_request import HELPERS
   if a in HELPERS:return super().hook(u,a,n,d)
   raw=bytes(u.mem_read(a,4));off=a-int(f['start'],16);assert raw==bytes.fromhex(f['bytes'])[off:off+4];i=next(CS.disasm(raw,a));self.current=len(self.visits);self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()})
   if i.mnemonic in('pacibsp','autibsp','paciza','autia','xpaci'):u.reg_write(A.UC_ARM64_REG_PC,a+4)
   elif i.mnemonic=='retab':u.reg_write(A.UC_ARM64_REG_PC,self.reg(30))
   elif i.mnemonic in('braa','braaz','blraa','blraaz'):
    j=int(i.op_str.split(',')[0].strip()[1:]);target=self.reg(j)
    if i.mnemonic.startswith('blr'):self.setreg(30,a+4)
    u.reg_write(A.UC_ARM64_REG_PC,target)
   else:assert i.mnemonic not in('svc','hvc','smc','brk','mrs','msr')and not i.mnemonic.startswith(('pac','aut','xpac')),(hex(a),i.mnemonic)
   return
  return super().hook(u,a,n,d)
 def run(self):
  self.u.emu_start(DISPATCH_INIT,0,count=30000);self.flush();assert self.boundary is not None
  return {'kernel_case_index':self.index,'entry_PC':hex(DISPATCH_INIT),'entry':self.entry,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.write_events,'imports':self.events,'handoffs':self.frames,'CF_frames':self.cf_frames,'CF_models':self.cf_models,'CF_logical_PAC':self.cf_pac,'boundary':self.boundary,'application_handoff':self.application_handoff,'application_frames':self.application_frames,'stack_check_contracts':self.stack_checks,'logical_library_binding':self.binding,'CF_initial_private_overlays':self.cf_initial,'CF_runtime_global_overlays':self.cf_globals,'runloop_frames':self.run_frames,'runloop_models':self.run_models,'initializer_handoff':self.initializer_handoff,'kernel_transfers':self.kernel_transfers,'final_lower_stack':{**compressed(bytes(self.u.mem_read(LOW,LOW_SIZE))), 'address':hex(LOW)},'final_private_RAM':compressed(bytes(self.u.mem_read(B,0x100000))),'final_user8192_hex':bytes(self.u.mem_read(USER,8192)).hex(),'final_OOL16384_hex':bytes(self.u.mem_read(OOL,16384)).hex(),'reply384_hex':bytes(self.u.mem_read(REPLY,384)).hex(),**({'argument_record_address':hex(self.audit_record),'final_argument_record120_hex':bytes(self.u.mem_read(self.audit_record,120)).hex()}if self.audit_record else{}),**FLAGS}
if __name__=='__main__':
 src=json.loads((ROOT/(P+'_source.json')).read_text());ks=json.loads((ROOT/'dispatch_voucher_hooks_profiles.json').read_text())['kernel_cases'];rows=[]
 for j in(2,0,3,1):
  r=Probe(j,ks[j],src).run();rows.append(r);print('case',j,r['boundary']['kind'],r['boundary']['registers31'][0],len(r['source_visits']),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[P+'_source.json','dispatch_voucher_hooks_profiles.json','probe_cf_daemon_request.py','recover_'+P+'.py']},'kernel_cases':ks,'cases':rows,**FLAGS};(ROOT/(P+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
