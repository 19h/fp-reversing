#!/usr/bin/env python3
"""Original startup-to-constructor composition and source-produced failure forks.
O(visits+effects), O(unique PCs+critical effects+RAM+one startup snapshot).
No native IOKit, crypto, IPC, allocator, clock, lock or PAC operation.
"""
import hashlib,json,struct
from unicorn import arm64_const as ar
from probe_kext_provider_initialize import Probe as Startup,P,SP,HALT,BSS,TABLE
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_kext_constructor_request import sha
PREFIX='kext_startup_hardware_bridge';CTOR=0xfffffe000a66a7e0;NAME=P+0x90000;OUT=P+0x81000;OUTSLOT=SP-0x88;DICT=P+0xd0000;PROVIDER=P+0xd0700;DESC=P+0xd0800;TASK=P+0xd0900;BUFFER=P+0xb0000
FLAGS={0xfffffe000cccea88:1,0xfffffe000ccca078:1,0xfffffe000ccceb00:1,0xfffffe000ccceb08:8,0xfffffe000ccceb10:8,0xfffffe000ccc7848:8,0xfffffe000cccca58:8}
class Probe(Startup):
 def __init__(self,im,c,origin=None):
  super().__init__(im,{});self.c=c;self.origin=origin;self.bias=0;self.auth=[];self.bridge_effects=[];self.bridge_reads=[];self.timeout=[];self.aes_calls=[];self.startup_snapshot=None
  env=[(0xfffffe0007efa630,struct.pack('<Q',P+0xd0200)),(0xfffffe0007f860a8,struct.pack('<Q',P+0xd0300)),(0xfffffe0007e6d9c0,struct.pack('<I',14)),(0xfffffe0007f8b0a0,struct.pack('<Q',TASK))]
  for a,b in env:self.ensure(a,len(b));self.u.mem_write(a,b);self.image_initial.append({'address':hex(a),'bytes_hex':b.hex(),'provenance':'Explicit runtime environment premise before original startup'})
  self.fixture(NAME,b'/private/fixture/application\0');self.fixture(OUT,bytes([0xa5])*8)
  if origin is not None:
   s=origin;ram=bytes.fromhex(s['RAM_hex']);bss=bytes.fromhex(s['BSS_hex']);assert hashlib.sha256(ram).hexdigest()==s['RAM_sha256']and hashlib.sha256(bss).hexdigest()==s['BSS_sha256'];self.u.mem_write(P,ram);self.ensure(BSS,len(bss));self.u.mem_write(BSS,bss);self.initial=[{'address':hex(P),'bytes_hex':s['RAM_hex'],'provenance':'Exact original startup-produced RAM; no reset or owner reconstruction'}];self.image_initial.append({'address':hex(BSS),'bytes_hex':s['BSS_hex'],'provenance':'Exact original startup-produced BSS'});self.cursor=s['resource_state']['cursor'];self.locks={int(a,16):dict(v)for a,v in s['resource_state']['locks'].items()};self.lock_alive=any(v['alive']for v in self.locks.values());self.bias=s['model_count'];self.phase=1;self.entry=CTOR
   for j,v in enumerate(s['registers31']):self.set(j,int(v,16))
   for j,v in enumerate(s['Q32']):self.u.reg_write(getattr(ar,'UC_ARM64_REG_Q'+str(j)),int(v,16))
   self.u.reg_write(ar.UC_ARM64_REG_FPCR,s['FPCR']);self.u.reg_write(ar.UC_ARM64_REG_FPSR,s['FPSR']);self.caller()
  self.entry_locks={hex(a):v.copy()for a,v in self.locks.items()}
  self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV));self.initial_Q32=[hex(self.u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j))))for j in range(32)];self.initial_FPCR=self.u.reg_read(ar.UC_ARM64_REG_FPCR);self.initial_FPSR=self.u.reg_read(ar.UC_ARM64_REG_FPSR)
 def caller(self):
  assert self.u.reg_read(ar.UC_ARM64_REG_SP)==SP
  for j in range(18):self.set(j,0)
  for j,v in enumerate([NAME,0x100000c,0,1,1,OUT]):self.set(j,v)
  self.set(30,HALT);self.u.reg_write(ar.UC_ARM64_REG_NZCV,0)
 def model(self,a,symbol,result):
  ordinal=self.bias+len(self.models)+1;ret=self.reg(30);e={'pc':hex(a),'before_source_visit_index':len(self.visits),'symbol':symbol,'arguments8':[hex(self.reg(j))for j in range(8)],'return_pc':hex(ret),'return_value':hex(result),'model_ordinal':ordinal,'native_effects_executed':False};self.models.append(e)
  for j in range(18):self.set(j,((j+1)*0x123456789abcdef)^ordinal*0x8b3dc651)
  self.set(0,result);self.u.reg_write(ar.UC_ARM64_REG_NZCV,0xf0000000 if ordinal&1 else 0);e['after_registers31']=[hex(self.reg(j))for j in range(31)];e['after_NZCV']=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV));self.u.reg_write(ar.UC_ARM64_REG_PC,ret)
 def flush(self):
  pending=list(self.pending);super().flush()
  for e in pending:
   a=int(e['address'],16);n=e['size_bytes']
   if any(a<t+z and t<a+n for t,z in [(OUT,8),(OUTSLOT,4),*FLAGS.items()]):self.bridge_effects.append({**e,'phase':self.phase})
 def read(self,u,t,a,n,v,d):
  super().read(u,t,a,n,v,d)
  if any(a<x+z and x<a+n for x,z in [(OUTSLOT,4),*FLAGS.items()]):self.bridge_reads.append({'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'address':hex(a),'size_bytes':n,'bytes_hex':bytes(u.mem_read(a,n)).hex(),'phase':self.phase})
 def foreign(self,a):
  if a==0xfffffe000c4ba154 and self.reg(0)!=0xfffffe000847bea0:
   v=self.reg(0);size=struct.unpack('<I',self.image.k.read(v+44,4))[0]&0xffffff;result=self.cursor;self.cursor+=(size+4095)&~4095;assert self.cursor<P+0x70000;self.allocs.append({'kind':'typed_other','view':hex(v),'address':hex(result),'size_bytes':size,'phase':self.phase});return self.modeled(a,'typed_other_model',result)
  return super().foreign(a)
 def snapshot(self):
  self.ensure(BSS,0x10000);ram=bytes(self.u.mem_read(P,0x100000));bss=bytes(self.u.mem_read(BSS,0x10000))
  return {'RAM_hex':ram.hex(),'BSS_hex':bss.hex(),'RAM_sha256':hashlib.sha256(ram).hexdigest(),'BSS_sha256':hashlib.sha256(bss).hexdigest(),'registers31':[hex(self.reg(j))for j in range(31)],'SP':hex(SP),'NZCV':hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV)),'Q32':[hex(self.u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j))))for j in range(32)],'FPCR':self.u.reg_read(ar.UC_ARM64_REG_FPCR),'FPSR':self.u.reg_read(ar.UC_ARM64_REG_FPSR),'resource_state':{'cursor':self.cursor,'locks':{hex(a):v.copy()for a,v in self.locks.items()}},'model_count':self.bias+len(self.models),'before_source_visit_index':len(self.visits),'output_slot4_hex':bytes(self.u.mem_read(OUTSLOT,4)).hex()}
 def code(self,u,a,n,d):
  self.flush()
  if a==HALT and self.phase==0:
   assert self.reg(0)==0;self.startup_snapshot=self.snapshot();s=self.startup_snapshot;e={k:s[k]for k in ['registers31','SP','NZCV','RAM_sha256','BSS_sha256','before_source_visit_index']};e.update(phase=0,pc=hex(HALT),entry_PC=hex(CTOR));self.returns.append({k:e[k]for k in ['phase','before_source_visit_index','registers31','SP','NZCV']});self.phase=1;self.caller();e['after_registers31']=[hex(self.reg(j))for j in range(31)];e['after_NZCV']='0x0';self.transitions.append(e);return u.reg_write(ar.UC_ARM64_REG_PC,CTOR)
  if a in [0xfffffe000a508094,0xfffffe000a5080f0,0xfffffe000a50815c,0xfffffe000a5084c4]:
   raw=bytes(u.mem_read(a,4));assert raw==self.image.k.read(a,4);i=next(self.image.k.cs.disasm(raw,a));assert(i.mnemonic,i.op_str)==('autda','x16, x17');self.dec[a]=i;self.auth.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'pointer':hex(self.reg(16)),'modifier':hex(self.reg(17)),'phase':self.phase});self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});return u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  if a==0xfffffe000c4ece88:
   assert[self.reg(j)for j in range(2)]==[0xfffffe000790ba3c,0];return self.modeled(a,'matching_dictionary_model',DICT)
  if a==0xfffffe000c4eb5d8:
   assert self.reg(0)==DICT;timeout=bytes(u.mem_read(self.reg(1),8));assert timeout==bytes.fromhex('0000000001000000');self.timeout.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'address':hex(self.reg(1)),'bytes_hex':timeout.hex()})
   if self.c['variant']=='absent':return self.modeled(a,'absent_provider_model',0)
   self.effect(PROVIDER,struct.pack('<Q',0xfffffe0008588380),'Declared nominal IOAESAccelerator vptr, not native object construction');return self.modeled(a,'nominal_provider_model',PROVIDER)
  if a==0xfffffe000c445200:assert self.reg(0)==PROVIDER;return self.modeled(a,'retain_no_effect_model',0)
  if a==0xfffffe000c526070:
   assert[self.reg(j)for j in range(4)]==[TASK,0x13,81920,16384]
   if self.c['variant']=='descriptor_null':return self.modeled(a,'descriptor_NULL_model',0)
   self.effect(DESC,struct.pack('<Q',0xfffffe0007f85d80),'Declared nominal IOBufferMemoryDescriptor vptr');return self.modeled(a,'nominal_descriptor_model',DESC)
  if a==0xfffffe000c5353b4:assert[self.reg(j)for j in range(2)]==[DESC,0];return self.modeled(a,'prepare_model',4 if self.c['variant']=='prepare_error'else 0)
  if a==0xfffffe000c524b60:assert self.reg(0)==DESC;return self.modeled(a,'buffer_address_model',BUFFER)
  if a==0xfffffe000c647f10:
   dst,src,size=[self.reg(j)for j in range(3)];assert P<=src<src+size<=P+0x100000 and P<=dst<dst+size<=P+0x100000 and(dst+size<=src or src+size<=dst);self.effect(dst,bytes(u.mem_read(src,size)),'Explicit disjoint private memcpy model');return self.modeled(a,'memcpy_model',dst)
  if a==0xfffffe000c4babac and self.phase==1:return self.modeled(a,'diagnostic_logger_no_effect_model',0)
  if a==0xfffffe000abff358:
   self.aes_calls.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments8':[hex(self.reg(j))for j in range(8)],'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'stack24_hex':bytes(u.mem_read(u.reg_read(ar.UC_ARM64_REG_SP),24)).hex(),'IV16_hex':bytes(u.mem_read(self.reg(4),16)).hex(),'buffer32_sha256':hashlib.sha256(bytes(u.mem_read(BUFFER,32))).hexdigest()})
   if self.c['variant']=='hardware_error':return self.modeled(a,'hardware_nonzero_result_model',4)
  return super().code(u,a,n,d)
 def run(self):
  self.ensure(self.entry)
  for batch in range(20):
   self.u.emu_start(self.entry if batch==0 else self.u.reg_read(ar.UC_ARM64_REG_PC),0,count=500000)
   if self.reason is not None:break
   print(json.dumps({'variant':self.c['variant'],'source_visits':len(self.visits),'phase':self.phase,'still_running':True}),flush=True)
  self.flush();assert self.reason==('before_external_code'if self.c['variant']=='frontier'else'wrapper_return'),self.boundary
  for a,n in [*FLAGS.items(),(0xfffffe000cccda68,8),(0xfffffe000ccceaf8,4)]:self.ensure(a,n)
  self.ensure(BSS,0x10000)
  return {'configuration':self.c,'entry_PC':hex(self.entry),'entry_phase':0 if self.origin is None else 1,'entry_SP':hex(SP),'entry_registers31':self.entry_regs,'entry_NZCV':self.entry_NZCV,'initial_Q32':self.initial_Q32,'initial_FPCR':self.initial_FPCR,'initial_FPSR':self.initial_FPSR,'initial_model_count':self.bias,'initial_lock_owners':self.entry_locks,'private_RAM':{'address':hex(P),'size_bytes':0x100000,'initial_byte':0},'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,'fingerprints':{k:getattr(self,k).result()for k in ['visits','reads','writes','edges','calls']},'original_PC_coverage':[{'pc':hex(a),'bytes_hex':bytes(self.dec[a].bytes).hex(),'count':count}for a,count in sorted(self.visits.pcs.items())],'API_models':self.models,'allocations':self.allocs,'critical_effects':self.critical,'critical_cell_reads':list(self.cell_reads.values()),'table_read_bounds':[hex(v)for v in self.table_read_bounds]if self.table_read_bounds else None,'declared_call_transitions':self.transitions,'returns':self.returns,'boundary':self.boundary,'final_cells_hex':{hex(a):bytes(self.u.mem_read(a,n)).hex()for a,n in [(0xfffffe000cccda68,8),(0xfffffe000ccceaf8,4),(0xfffffe000cccea88,8),(0xfffffe000ccceab8,8),(0xfffffe000ccca078,1)]},'final_table512_hex':bytes(self.u.mem_read(TABLE,512)).hex(),'final_RAM_sha256':hashlib.sha256(bytes(self.u.mem_read(P,0x100000))).hexdigest(),'final_BSS_sha256':hashlib.sha256(bytes(self.u.mem_read(BSS,0x10000))).hexdigest(),'startup_snapshot':self.startup_snapshot,'source_producer_case':None if self.origin is None else 0,'logical_data_authentication':self.auth,'bridge_effects':self.bridge_effects,'bridge_reads':self.bridge_reads,'timeouts':self.timeout,'AES_boundaries':self.aes_calls,'final_flags_hex':{hex(a):bytes(u).hex()for a,n in FLAGS.items()for u in [self.u.mem_read(a,n)]},'final_output8_hex':bytes(self.u.mem_read(OUT,8)).hex(),'final_output_slot4_hex':bytes(self.u.mem_read(OUTSLOT,4)).hex(),'final_buffer32_hex':bytes(self.u.mem_read(BUFFER,32)).hex(),'final_params104_hex':bytes(self.u.mem_read(P+0x25000,104)).hex(),'final_lock_owners':{hex(a):v for a,v in self.locks.items()},'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False}
def main():
 im=Image();rows=[];origin=None
 for variant in ['frontier','absent','descriptor_null','prepare_error','hardware_error']:
  row=Probe(im,{'variant':variant},origin).run();rows.append(row)
  if origin is None:origin=row['startup_snapshot']
  print(json.dumps({'variant':variant,'source_visits':row['fingerprints']['visits']['count'],'boundary':row['boundary']['pc'],'result':row['boundary']['registers31'][0]}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in [PREFIX+'_source.json','probe_kext_provider_initialize.py','probe_kernel_vm_mig.py','kernel_vm_mig_tools.py']},'cases':rows,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
