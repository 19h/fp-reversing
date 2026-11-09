#!/usr/bin/env python3
"""Original kext close-wrapper prefix in a bounded private guest.

File-defined initial data and one explicit warm flag are conditional fixtures,
not native initialization. Stack guard is modeled. PAC is bypassed. All other
external calls/system instructions stop before execution. No target API runs.
O(B+V+E) time/space, 20000-instruction cap per independent ABI case.
"""
import hashlib,json,struct
from pathlib import Path
import unicorn as uc
from unicorn import arm64_const as ar
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,SYMBOLS
from resolve_kernel_collection_interfaces import commands
STACK=0x6000000000;HALT=STACK+0x20000;ENTRY=0xfffffe000a5bff88;WARM=0xfffffe000ccca078
class Close:
 def __init__(self,token,warm):
  self.token=token;self.warm=warm;self.events=[];self.calls=[];self.active_calls=[];self.visits=[];self.pool={};self.reads=[];self.input_reads=[];self.writes=[];self.pending=[];self.reason=None;self.decoded={};self.code=[];self.data=[];self.u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);self.u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);pages=set()
  for at,cmd,n in commands(IMAGE.data,0):
   if cmd!=0x19:continue
   name=IMAGE.data[at+8:at+24].split(b'\0')[0].decode();va,vm,off,extent=struct.unpack_from('<4Q',IMAGE.data,at+24);pages.update(range(va&~4095,(va+vm+4095)&~4095,4096));(self.code if name=='__TEXT_EXEC'else self.data).append((va,va+vm))
  self.symbols={int(e['address'],16):e.get('exact_symbols',[])for e in SYMBOLS};self.external_pages={a&~4095 for a in self.symbols}-pages
  for a in sorted(pages|self.external_pages|{0xfffffe000cacb000}):self.u.mem_map(a,4096)
  for va,off,n in IMAGE.segments:self.u.mem_write(va,IMAGE.data[off:off+n])
  self.u.mem_map(STACK,0x21000);self.u.mem_write(0xfffffe000cacb000,struct.pack('<Q',0x123456789abcdef0));self.u.mem_write(WARM,bytes([warm]));self.u.reg_write(ar.UC_ARM64_REG_SP,STACK+0x1f000);self.setreg(0,token);self.setreg(30,HALT)
  self.u.hook_add(uc.UC_HOOK_CODE,self.hook);self.u.hook_add(uc.UC_HOOK_MEM_READ,self.read);self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.write);self.u.hook_add(uc.UC_HOOK_MEM_UNMAPPED,self.unmapped)
 def reg(self,n):return self.u.reg_read(getattr(ar,'UC_ARM64_REG_X'+str(n)))
 def setreg(self,n,v):self.u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(n)),v&((1<<64)-1))
 def stop(self,reason,**kw):self.reason=reason;self.events.append({'kind':reason,**kw});self.u.emu_stop()
 def flush(self):
  for e in self.pending:e['after_hex']=bytes(self.u.mem_read(int(e['address'],16),e['size_bytes'])).hex()
  self.pending=[]
 def hook(self,u,a,n,d):
  self.flush()
  if self.active_calls and a==int(self.calls[self.active_calls[-1]]['return_pc'],16):
   call=self.calls[self.active_calls.pop()];ptr=int(call['registers31'][0],16)
   try:prefix=bytes(u.mem_read(ptr,32)).hex()
   except uc.UcError:prefix=None
   call.update(return_source_visit_index=len(self.visits),returned_X0=hex(self.reg(0)),returned_prefix32_hex=prefix)
  if a==HALT:return self.stop('wrapper_return',X0_return_u64=hex(self.reg(0)))
  if not any(x<=a<a+4<=z for x,z in self.code):return self.stop('external_call_boundary',target=hex(a),symbols=self.symbols.get(a,[]),return_pc=hex(self.reg(30)),arguments=[hex(self.reg(j))for j in range(8)])
  raw=IMAGE.read(a,4);assert bytes(u.mem_read(a,4))==raw;self.pool[a]=raw;self.visits.append(a)
  if a not in self.decoded:self.decoded[a]=next(CS.disasm(raw,a))
  i=self.decoded[a];m=i.mnemonic
  if m in['bl','blr','blraa','blrab','blraaz','blrabz']:
   target=int(i.op_str[1:],16)if m=='bl'else self.reg(int(i.op_str.split(',')[0][1:]));p=self.reg(0)
   try:prefix=bytes(u.mem_read(p,32)).hex()
   except uc.UcError:prefix=None
   self.calls.append({'pc':hex(a),'target':hex(target),'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'source_visit_index':len(self.visits)-1,'return_pc':hex(a+4),'registers31':[hex(self.reg(j))for j in range(31)],'X0_prefix32_hex':prefix,'observer_bytes_not_definedness_proof':True});self.active_calls.append(len(self.calls)-1)
  if m in['braa','brab','braaz','brabz','blraa','blrab','blraaz','blrabz']:
   target=self.reg(int(i.op_str.split(',')[0][1:]));self.events.append({'kind':'PAC_branch_bypass','pc':hex(a),'target':hex(target)})
   if m.startswith('blr'):self.setreg(30,a+4)
   return u.reg_write(ar.UC_ARM64_REG_PC,target)
  if m in['pacibsp','paciasp','autibsp','autiasp','bti']:return u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  if m in['retab','retaa']:return u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30))
  if m.startswith(('pac','aut','xpac')):return self.stop('unmodeled_PAC',pc=hex(a),mnemonic=m)
  if m in['svc','hvc','smc']:return self.stop('system_instruction_boundary',pc=hex(a),mnemonic=m)
 def read(self,u,access,a,n,value,d):
  e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'address':hex(a),'size_bytes':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()}
  if STACK<=a<a+n<=STACK+0x21000:self.reads.append(e)
  if a<=WARM<a+n or a<=0xfffffe000cccca58<a+n:self.input_reads.append(e)
 def write(self,u,access,a,n,value,d):
  e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'address':hex(a),'size_bytes':n};self.writes.append(e);self.pending.append(e)
 def unmapped(self,u,access,a,n,value,d):self.stop('unmapped_boundary',pc=hex(u.reg_read(ar.UC_ARM64_REG_PC)),address=hex(a),size_bytes=n);return False
 def run(self):
  try:self.u.emu_start(ENTRY,0,count=20000)
  except uc.UcError as e:
   if self.reason is None:self.reason='unicorn_error';self.events.append({'kind':self.reason,'message':str(e)})
  self.flush();self.reason=self.reason or'instruction_budget';return {'token_input_u64':hex(self.token),'warm_flag':self.warm,'scope':__doc__,'stop_reason':self.reason,'source_visits':[hex(a)for a in self.visits],'calls':self.calls,'incomplete_call_indices':self.active_calls,'stack_reads':self.reads,'declared_input_reads':self.input_reads,'source_writes':self.writes,'events':self.events,'native_target_executed':False,'native_API_executed':False,'idb_mutated':False}
def main():
 rows=[];pool={}
 for token,warm in[(0,1),(1,1),(0x12345678,1),(0x100000001,1),(1,0)]:
  q=Close(token,warm);r=q.run();rows.append(r);pool.update(q.pool);print('CASE',hex(token),warm,r['stop_reason'],len(r['source_visits']),[(e['pc'],e['target'])for e in r['calls']][-6:],r['events'][-1:],flush=True)
 out={'scope':__doc__,'generator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'source_sha256':hashlib.sha256(SOURCE.read_bytes()).hexdigest(),'dependencies':{n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest()for n in['kext_port_tools.py','verify_interface_contracts.py','resolve_kernel_collection_interfaces.py','kernel_collection_interfaces.json']},'cases':rows,'source_instructions':[{'ea':hex(a),'bytes':b.hex(),'mnemonic':next(CS.disasm(b,a)).mnemonic,'operands':next(CS.disasm(b,a)).op_str}for a,b in sorted(pool.items())],'native_target_executed':False,'full_goal_complete':False};(ROOT/'kext_close_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
