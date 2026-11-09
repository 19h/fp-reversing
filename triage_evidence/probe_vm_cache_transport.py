#!/usr/bin/env python3
"""Private original-cache VM wrapper/fast-trap/MIG request fixtures.
All SVCs are intercepted, helpers/logging are explicit callbacks, and the
Mach2 send stops before its SVC. Cache provenance is not daemon-runtime
version attestation. O(cases*visits) time, O(private CPU map+journals) space.
"""
import json,struct,hashlib
import unicorn as uc
from unicorn import arm64_const as ar
import probe_user_trap_interfaces as parent
from bootpolicy_cache_reader import Cache,Dylib,ROOT,CS
from capture_daemon_record720 import sha
parent.ENTRY_NAMES=['_vm_deallocate','_mach_vm_deallocate','_mach_msg2_internal','_mach_msg2_trap']
parent.EXTRA_FUNCTIONS=[0x180547a8c,0x18056f104]
class Probe(parent.Probe):
 def __init__(self,cache,lib,args,status,reply,logger):
  self.reply=reply;self.visits=[];self.callback_models=[];self.request=None;self.reads=[];self.writes=[];self.pending=[]
  super().__init__(cache,lib,'_vm_deallocate',args,trap_results=None if status is None else[status],logger=logger)
  self.input_seeds.update({'reply_name_model':hex(reply),'callback_caller_clobbers':'explicit arbitrary x0..x17/NZCV; preserved x18..x29','cache_runtime_matches_daemon':False})
  self.seeded_data.append((0x1eb065de0,8));self.u.mem_write(0x1eb065de0,cache.read(0x1eb065de0,8));self.u.mem_map(0x18057d000,4096,uc.UC_PROT_READ);self.u.mem_write(0x18057d000,cache.read(0x18057d000,4096))
 def callback(self,a,label,result):
  ret=self.reg(30);event={'pc':hex(a),'name':label,'arguments8':[hex(self.reg(i))for i in range(8)],'return_pc':hex(ret),'result':hex(result),'native_callback_executed':False};self.callback_models.append(event)
  for j in range(18):self.setreg(j,((j+1)*0x123456789abcdef)^self.reply)
  self.setreg(0,result);self.u.reg_write(ar.UC_ARM64_REG_NZCV,0xf0000000 if self.reply&1 else 0);event['after_registers31']=[hex(self.reg(j))for j in range(31)];event['after_NZCV']=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV));self.u.reg_write(ar.UC_ARM64_REG_PC,ret)
 def flush(self):
  for e in self.pending:e['after_hex']=bytes(self.u.mem_read(int(e['address'],16),e['size_bytes'])).hex()
  self.pending=[]
 def read(self,u,t,a,n,v,d):
  self.reads.append({'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'address':hex(a),'size_bytes':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()});return super().read(u,t,a,n,v,d)
 def write(self,u,t,a,n,v,d):
  e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'address':hex(a),'size_bytes':n};self.writes.append(e);self.pending.append(e);return super().write(u,t,a,n,v,d)
 def code(self,u,a,n,d):
  self.flush()
  if a==parent.LOGGER:return self.callback(a,'private_syscall_logger',0xabcdef)
  if a==0x180547f00:return self.callback(a,'modeled_mig_get_reply_port',self.reply)
  if a==0x18056f174:
   at=self.reg(0);self.request={'call_pc':hex(a),'call_target':hex(0x18055a894),'buffer':hex(at),'bytes_hex':bytes(u.mem_read(at,48)).hex(),'arguments8':[hex(self.reg(j))for j in range(8)]}
  if any(x<=a<z for x,z in self.allowed):
   raw=bytes(u.mem_read(a,4));assert raw==self.cache.read(a,4);ins=next(CS.disasm(raw,a))
   if ins.mnemonic=='svc'and self.reg(16)==((1<<64)-47):
    assert self.request is not None;return self.stop('mach2_request_frontier',pc=hex(a),arguments8=[hex(self.reg(j))for j in range(8)],request_bytes_hex=bytes(u.mem_read(int(self.request['buffer'],16),48)).hex(),host_svc_executed=False)
   self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()})
   if a==0x180549844:
    assert ins.mnemonic=='blraaz'and ins.op_str=='x8'and self.reg(8)==parent.LOGGER;self.steps+=1;self.pac.append({'pc':hex(a),'instruction':'blraaz','target':hex(parent.LOGGER)});self.setreg(30,a+4);u.reg_write(ar.UC_ARM64_REG_PC,parent.LOGGER);return
  return super().code(u,a,n,d)
 def run(self):
  r=super().run();self.flush();r['source_visits']=self.visits;r['source_reads']=self.reads;r['source_writes']=self.writes;r['callback_models']=self.callback_models;r['request']=self.request;return r
def main():
 c=Cache();d=Dylib(c,'/usr/lib/system/libsystem_kernel.dylib');rows=[]
 for args,reply in [([0x123403,0,0],0x456),([0xffffffff,0x6500000000,4096],0xabc),([1,(1<<64)-1,(1<<64)-1],0xffffffff)]:
  for logger in [False,True]:
   for status in [None,0,5,0xffffffff,0x10000003]:
    r=Probe(c,d,args,status,reply,logger).run();rows.append(r);assert r['stop_reason']in ['svc_boundary','returned','mach2_request_frontier'],r;print(json.dumps({'args':args,'reply':reply,'logger':logger,'status':status,'stop':r['stop_reason'],'visits':len(r['source_visits'])}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['probe_user_trap_interfaces.py','bootpolicy_cache_reader.py']},'cache_uuid':c.uuid,'library_uuid':d.uuid,'profiles':rows,'native_target_executed':False,'native_IPC_executed':False,'daemon_runtime_version_match_established':False,'full_goal_complete':False};(ROOT/'daemon_vm_cleanup_cache_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
