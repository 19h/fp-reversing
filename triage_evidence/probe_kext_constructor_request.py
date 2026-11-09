#!/usr/bin/env python3
"""Continuous original constructor prefixes in private RAM, explicit API models.
O(image bytes+source visits+fixture bytes), O(image bytes+private RAM+journals).
No native target/API/IPC/PAC/IDB effects. Stop before common MIG transport.
"""
import json,struct
from unicorn import arm64_const as ar
from probe_kernel_vm_mig import Probe as Base,P,SP,HALT
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_kext_constructor_request import sha
PREFIX='kext_constructor_request';F=P+0x10000;NAME=P+0x90000;OUT=P+0x81000;HOST=P+0x82000;PORT=P+0x83000;KMAP=P+0x84000;IMAP=P+0x85000;COPY=P+0x86000;STAGING=P+0x70000
class Probe(Base):
 def __init__(self,im,c):
  super().__init__(im,'selector',{'id':0});self.initial=[];self.c=c;self.entry=0xfffffe000a66a7e0;self.calls=[];self.allocs=[];self.edges=[];self.snapshots=[];self.cursor=P+0x20000
  e=next(e for e in im.k.entries if e['name']=='com.apple.driver.FairPlayIOKit');self.allowed=[(s['address'],s['address']+s['vm_size'])for s in e['segments']if s['name']=='__TEXT_EXEC']+[(0xfffffe000bcf5f18,0xfffffe000bcf5f24)]
  self.name=bytes(0x21+j%90 for j in range(c['length']))+b'\0';self.fixture(NAME,self.name);self.fixture(OUT,bytes.fromhex('a5'*8));self.fixture(STAGING,bytes([0xa5])*0x10001)
  for a,b in [(0xfffffe000ccca078,b'\1'),(0xfffffe000cccca58,bytes(8)),(0xfffffe0007efa630,struct.pack('<Q',IMAP)),(0xfffffe0007f860a8,struct.pack('<Q',KMAP)),(0xfffffe0007e6d9c0,struct.pack('<I',c['page_shift']))]:
   self.ensure(a,len(b));self.u.mem_write(a,b);self.image_initial.append({'address':hex(a),'bytes_hex':b.hex(),'provenance':'Explicit private initialized/map/page-shift premise, not runtime observation'})
  for j in range(31):self.set(j,0)
  for j,v in enumerate([NAME,c['cpu_type'],c['cpu_subtype'],c['origin'],c['mode'],OUT]):self.set(j,v)
  self.set(30,HALT);self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV));self.effects=[]
 def write(self,u,t,a,n,v,d):
  assert P<=a<a+n<=P+0x100000 or 0xfffffe000ccc0000<=a<a+n<=0xfffffe000ccd0000,(hex(a),n)
  e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'address':hex(a),'size_bytes':n};self.writes.append(e);self.pending.append(e)
 def effect(self,a,b,reason):
  self.effects.append({'address':hex(a),'before_hex':bytes(self.u.mem_read(a,len(b))).hex(),'after_hex':b.hex(),'reason':reason});self.u.mem_write(a,b)
 def modeled(self,a,name,result):
  effects=self.effects;self.effects=[];self.model(a,name,result);self.models[-1]['memory_effects']=effects
 def code(self,u,a,n,d):
  self.flush()
  if a==HALT:return self.stop('wrapper_return')
  if not any(x<=a<a+4<=z for x,z in self.allowed):return self.stop('before_external_code')
  if a in [0xfffffe000a60ab2c,0xfffffe000a60af44,0xfffffe000a60b498,0xfffffe000a60b624,0xfffffe000a60b71c,0xfffffe000a60b8a8]:self.snapshots.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'registers31':[hex(self.reg(j))for j in range(31)],'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP))})
  raw=bytes(u.mem_read(a,4));assert raw==self.image.k.read(a,4);i=next(self.image.k.cs.disasm(raw,a));self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()})
  if i.mnemonic in ['pacibsp','autibsp','retab']:return u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30)if i.mnemonic=='retab'else a+4)
  if i.mnemonic in ['braa','blraa']:
   rr=[int(v.strip()[1:])for v in i.op_str.split(',')];assert rr[1]==17;target=self.reg(rr[0]);self.edges.append({'pc':hex(a),'visit':len(self.visits)-1,'kind':i.mnemonic,'target':hex(target),'modifier':hex(self.reg(17))})
   if i.mnemonic=='blraa':
    self.set(30,a+4);self.calls.append({'pc':hex(a),'target':hex(target),'args8':[hex(self.reg(j))for j in range(8)]})
    if target==0xfffffe000c4b9a08:
     size=self.reg(0);align=self.reg(1);assert not self.allocs and size==0x4000 and align==64;self.allocs.append({'kind':'aligned','address':hex(F),'size_bytes':size});return self.modeled(a,'aligned_allocation_model',F)
    if target in [0xfffffe000c4ba154,0xfffffe000c4ba60c]:
     v=self.reg(0);size=(struct.unpack('<I',self.image.k.read(v+44,4))[0]&0xffffff)if target==0xfffffe000c4ba154 else v;result=self.cursor;self.cursor+=(size+4095)&~4095;assert self.cursor<P+0x70000;self.allocs.append({'kind':'typed'if target==0xfffffe000c4ba154 else'data','view':hex(v)if target==0xfffffe000c4ba154 else None,'address':hex(result),'size_bytes':size});return self.modeled(a,'allocation_model',result)
    if target==0xfffffe000bcf27ac:return self.modeled(a,'host_priv_self_model',HOST)
    if target==0xfffffe000bcf258c:
     assert self.reg(0)==HOST and self.reg(1)&0xffffffff==0xffffffff and self.reg(2)in [17,34];self.effect(self.reg(3),struct.pack('<Q',PORT),'Opaque kernel port object result');return self.modeled(a,'host_special_port_model',0)
    if target==0xfffffe000bc9db70:
     assert self.reg(0)==NAME;return self.modeled(a,'strlen_model',self.c['length'])
    if target==0xfffffe000a508e04:
     assert self.reg(0)==IMAP and self.reg(2)<=0x10000;self.staging_extent=self.reg(2);self.effect(self.reg(1),struct.pack('<Q',STAGING),'Opaque staging allocation result');return self.modeled(a,'kmem_alloc_model',0)
    if target==0xfffffe000c647f10:
     dst,src,size=[self.reg(j)for j in range(3)];assert src==NAME and dst==STAGING and size==len(self.name);self.effect(dst,bytes(u.mem_read(src,size)),'Explicit disjoint memcpy model');return self.modeled(a,'memcpy_model',dst)
    if target==0xfffffe000a508e2c:
     assert self.reg(0)==IMAP and self.reg(1)==STAGING and self.reg(2)==len(self.name)and self.reg(3)==0;self.effect(self.reg(4),struct.pack('<Q',COPY),'Opaque vm_map_copy_t result; no native VM effects');return self.modeled(a,'vm_map_copyin_model',0)
   return u.reg_write(ar.UC_ARM64_REG_PC,target)
  assert i.mnemonic not in ['svc','hvc','smc','brk','autda']
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=400000);self.flush();assert self.reason=='before_external_code',self.boundary
  extent=getattr(self,'staging_extent',0);ptr=self.reg(0);message=bytes(self.u.mem_read(ptr,88)).hex()if int(self.boundary['pc'],16)==0xfffffe000bcf5e28 else None
  return {'configuration':self.c,'entry_PC':hex(self.entry),'entry_SP':hex(SP),'entry_registers31':self.entry_regs,'entry_NZCV':self.entry_NZCV,'private_RAM':{'address':hex(P),'size_bytes':0x100000,'initial_byte':0,'native_owner_extents_established':False},'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'logical_edges':self.edges,'calls':self.calls,'snapshots':self.snapshots,'allocations':self.allocs,'boundary':self.boundary,'staging_extent_bytes':extent,'staging_final_hex':bytes(self.u.mem_read(STAGING,extent+1)).hex(),'name_final_hex':bytes(self.u.mem_read(NAME,len(self.name))).hex(),'output_handle_final_hex':bytes(self.u.mem_read(OUT,8)).hex(),'message88_hex':message,'native_target_executed':False,'hardware_PAC_executed':False,'idb_mutated':False,'full_goal_complete':False}
def main():
 im=Image();configs=[]
 for p in [12,14]:
  for n in [0,1,28,4095,4096,4097,16383,16384]:configs.append(dict(page_shift=p,length=n,cpu_type=0x100000c,cpu_subtype=0,origin=1,mode=1))
 configs.append(dict(page_shift=16,length=28,cpu_type=0x100000c,cpu_subtype=0,origin=1,mode=1))
 for mode in [0,2,0xffffffff,0x100000001,0x100000000]:configs.append(dict(page_shift=14,length=28,cpu_type=0x100000c,cpu_subtype=0,origin=1,mode=mode))
 for cpu,sub,origin in [(0x1000007,3,0),(0x100000c,2,0xffffffffffffffff),(0x123456780100000c,0x1234567800000002,0x100000001)]:configs.append(dict(page_shift=14,length=28,cpu_type=cpu,cpu_subtype=sub,origin=origin,mode=1))
 rows=[]
 for j,c in enumerate(configs):
  r=Probe(im,c).run();rows.append(r);print(json.dumps({'case':j,'configuration':c,'boundary':r['boundary']['pc'],'visits':len(r['source_visits']),'allocation':r['staging_extent_bytes']}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['probe_kernel_vm_mig.py','kernel_vm_mig_tools.py',PREFIX+'_source.json']},'kernel_sha256':im.k.sha256,'cases':rows,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
