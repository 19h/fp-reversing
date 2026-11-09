#!/usr/bin/env python3
"""Original kext wrapper control flow under explicit external-result models.

Opaque key/IV/data values are never dereferenced. No provider implementation,
crypto, data copy, allocator, preparation, reference or native API executes.
PAC is abstracted; declared call results do not prove accepted operations.
O(C*I+E) time/space, 512 original-instruction cap per independent case.
"""
import hashlib,json,struct
from pathlib import Path
import unicorn as uc
from unicorn import arm64_const as ar
from kext_port_tools import ROOT,SOURCE,IMAGE,CS
from probe_kext_buffer_cleanup import Cleanup,OBJ,PROV,STACK,HALT,BVT,FLAG,SERVICE,DESC,BYTES
AESVT=0xfffffe0008588380
ENTRIES={'copied':0xfffffe000a5081b0,'shared':0xfffffe000a5083d8,'global':0xfffffe000a508484,'descriptors':0xfffffe000a508534}
LENGTHS=[0,16,0x100000011,0xffffffffffffffff];OPS=[0,1,0x1234567800000004,0xffffffffffffffff]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def cases():
 n=0
 for kind in['shared','global','descriptors']:
  for v in range(4):
   for status in[0,1,0xe00002bc,0x100000000]:
    yield {'case':n,'kind':kind,'vector':v,'provider_return64':status,'outcome':'provider_result','readiness8':v&1};n+=1
 for v in range(4):
  for outcome in['exact','provider_error','prepare_error','copy_mismatch','copy_high','complete_error','release_error','factory_null','upper_status']:
   yield {'case':n,'kind':'copied','vector':v,'provider_return64':0xe00002bc if outcome=='provider_error'else 0x100000000 if outcome=='upper_status'else 0,'outcome':outcome,'readiness8':v&1};n+=1
 yield {'case':n,'kind':'copied','vector':1,'provider_return64':0,'outcome':'init_failure','readiness8':0}
def inputs(c):
 v=c['vector'];key=0x1111222233334444+v;iv=0x2222333344445555+v;src=0x3333444455556666+v;dst=0x4444555566667777+v;offa=0x5555666677778888+v;offb=0x6666777788889999+v;length=LENGTHS[v];op=OPS[v]
 if c['kind']=='copied':return[key,iv,src,dst,length,op,offa,offb]
 if c['kind']in['shared','global']:return[key,iv,length,op,src,dst,offa,offb]
 return[src,dst,length,iv,op,key,offa,offb]
class Handoff(Cleanup):
 def __init__(self):
  super().__init__();self.newcontract=json.loads((ROOT/'kext_aes_handoff_contracts.json').read_text());self.ranges=[]
  for r in self.newcontract['functions']:
   if r['entry']!='com.apple.driver.FairPlayIOKit'or int(r['start'],16)not in{*ENTRIES.values(),0xfffffe000a508c78}:continue
   a,z=int(r['start'],16),int(r['end'],16);raw=IMAGE.read(a,z-a);self.u.mem_write(a,raw);self.ranges.append((a,z));self.decoded.update({i.address:i for i in CS.disasm(raw,a)})
  self.u.mem_map(AESVT&~4095,4096);self.u.mem_write(PROV,struct.pack('<Q',AESVT));self.targets={}
  for e in self.newcontract['nominal_slots']:
   if(e['kind']=='aes'and e['offset_from_vptr']==0x890)or e['kind']=='buffer':
    a=int(e['slot'],16);target=int(e['target'],16);self.u.mem_write(a,struct.pack('<Q',target));self.targets[target]=e
  self.perform=next(a for a,e in self.targets.items()if e['kind']=='aes');self.readbytes=next(a for a,e in self.targets.items()if e['kind']=='buffer'and e['offset_from_vptr']==0x208)
 def record(self,pc,kind,target):
  e={'pc':hex(pc),'kind':kind,'target':hex(target),'source_visit_index':len(self.visits)-1,'registers8':[hex(self.reg(i))for i in range(8)],'SP':hex(self.u.reg_read(ar.UC_ARM64_REG_SP)),'native_API_executed':False};self.calls.append(e);return e
 def model_return(self,u,a,value,e):e['declared_return64']=hex(value);u.reg_write(ar.UC_ARM64_REG_X0,value&((1<<64)-1));u.reg_write(ar.UC_ARM64_REG_X30,a+4);u.reg_write(ar.UC_ARM64_REG_PC,a+4)
 def code(self,u,a,n,d):
  self.flush()
  if a==HALT:return self.stop('return')
  if not any(x<=a<a+4<=z for x,z in self.ranges):return self.stop('code_extent')
  assert bytes(u.mem_read(a,4))==IMAGE.read(a,4);self.visits.append(hex(a));i=self.decoded[a];m=i.mnemonic
  if m in['bti','pacibsp','autda']:
   if m!='bti':self.abstracted.append({'pc':hex(a),'instruction':m})
   return u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  if m=='retab':self.abstracted.append({'pc':hex(a),'instruction':m});return u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30))
  if m=='bl':
   t=int(i.op_str[1:],16)
   if t==0xfffffe000a508c78:return
   if t==0xfffffe000a508030:
    assert self.case['outcome']=='init_failure';e=self.record(a,'init_result',t);return self.model_return(u,a,0xffffffd8,e)
   if t==0xfffffe000a69f204:
    e=self.record(a,'withBytes_result',t);self.allocated=self.case['outcome']!='factory_null';return self.model_return(u,a,OBJ if self.allocated else 0,e)
   if t==0xfffffe000a69f0d4:
    e=self.record(a,'log_result',t);return self.model_return(u,a,0,e)
   return self.stop('unmodeled_direct_call')
  if m=='blraa':
   target=self.reg(int(i.op_str.split(',')[0][1:]));assert target in self.targets;entry=self.targets[target];off=entry['offset_from_vptr'];kind='provider_result'if target==self.perform else{0x208:'readBytes_result',0x218:'prepare_result',0x220:'complete_result',0x28:'release_result'}[off];e=self.record(a,kind,target);outcome=self.case['outcome'];value=0
   if kind=='provider_result':
    sp=u.reg_read(ar.UC_ARM64_REG_SP);assert all(self.stack_known[sp-STACK:sp-STACK+24]);e['stack24_hex']=bytes(u.mem_read(sp,24)).hex();value=self.case['provider_return64']
   elif kind=='prepare_result':value=0xe00002bc if outcome=='prepare_error'else 0
   elif kind=='readBytes_result':
    length=LENGTHS[self.case['vector']]&0xffffffff;value=(length^1)if outcome=='copy_mismatch'else length+(1<<32)if outcome=='copy_high'else length
   elif kind=='complete_result':value=0xe00002bc if outcome=='complete_error'else 0
   elif kind=='release_result':self.retired.add(OBJ);value=0xffffffffffffffff if outcome=='release_error'else 0
   return self.model_return(u,a,value,e)
  if m in['brk','svc','hvc','smc']:return self.stop('system_or_trap_boundary')
 def read(self,u,access,a,n,value,d):
  if(a,n)==(AESVT+0x890,8)or(a,n)in{(BVT+0x208,8),(BVT+0x218,8)}:self.reads.append({'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'address':hex(a),'size_bytes':n,'bytes_hex':bytes(u.mem_read(a,n)).hex(),'source_visit_index':len(self.visits)-1});return
  return super().read(u,access,a,n,value,d)
 def run(self,c):
  self.case=c;self.reason=None;self.visits=[];self.reads=[];self.writes=[];self.pending=[];self.calls=[];self.retired=set();self.abstracted=[];self.stack_known=bytearray(4096);self.allocated=False
  for j in range(31):self.u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(j)),0)
  self.u.reg_write(ar.UC_ARM64_REG_SP,STACK+0xf00);self.u.reg_write(ar.UC_ARM64_REG_X30,HALT)
  for i,v in enumerate(inputs(c)):self.u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(i)),v)
  for a,v,n in[(FLAG,c['readiness8'],1),(SERVICE,0 if c['outcome']=='init_failure'else PROV,8),(DESC,OBJ,8),(BYTES,0,8)]:self.u.mem_write(a,v.to_bytes(n,'little'))
  self.u.emu_start(ENTRIES[c['kind']],0,count=512);self.flush();self.reason=self.reason or'instruction_budget';assert self.reason=='return',self.reason
  return {'input':c,'entry_arguments8':[hex(v)for v in inputs(c)],'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'modeled_calls':self.calls,'abstracted_authentication':self.abstracted,'return64':hex(self.reg(0)),'final_globals':{hex(a):bytes(self.u.mem_read(a,n)).hex()for a,n in[(FLAG,1),(SERVICE,8),(DESC,8),(BYTES,8)]},'allocation_declared':self.allocated,'retired_in_model':[hex(a)for a in sorted(self.retired)],'stop_reason':self.reason,'native_API_executed':False,'accepted_operation_proved':False}
def main():
 g=Handoff();rows=[g.run(c)for c in cases()];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in['kext_port_tools.py','probe_kext_buffer_cleanup.py','kext_buffer_contracts.json','kext_aes_handoff_contracts.json']},'cases':rows,'native_target_executed':False,'key_data_contents_recovered':False,'native_resource_effects_proved':False,'full_goal_complete':False};(ROOT/'kext_aes_handoff_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(len(r['source_visits'])for r in rows),'provider_call_records':sum(e['kind']=='provider_result'for r in rows for e in r['modeled_calls'])}),flush=True)
if __name__=='__main__':main()
