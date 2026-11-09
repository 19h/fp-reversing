#!/usr/bin/env python3
"""Original cmam7f initialization and cached/failure paths, streaming fingerprints.
O(source visits+effects), O(unique PCs+critical effects+private RAM); no full
trace retained. Allocator/lock/time/logger effects are explicit private models.
"""
import hashlib,json,struct
from collections import Counter
from unicorn import arm64_const as ar
from probe_kernel_vm_mig import Probe as Base,P,SP,HALT
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_kext_constructor_request import sha
PREFIX='kext_provider_initialize';ENTRY=0xfffffe000a5a38cc;F=P+0x10000;ARENA=P+0x20000;TABLE=P+0x21000;LOCK=P+0x82000;BSS=0xfffffe000ccc0000
CELLS={0xfffffe000cccda68:8,0xfffffe000ccceaf8:4,0xfffffe000cccea88:8,0xfffffe000ccceab8:8,0xfffffe000ccca078:1}
class Digest:
 def __init__(self,kind):self.kind=kind;self.count=0;self.size=0;self.h=hashlib.sha256();self.pcs=Counter()
 def __len__(self):return self.count
 def append(self,e):
  self.count+=1;pc=int(e['pc'],16);self.pcs[pc]+=1
  if self.kind=='visits':b=struct.pack('<Q',pc)+bytes.fromhex(e['bytes_hex'])
  elif self.kind in ['reads','writes']:
   v=bytes.fromhex(e['bytes_hex'if self.kind=='reads'else'after_hex']);b=struct.pack('<QQIQ',pc,int(e['address'],16),e['size_bytes'],e['source_visit_index'])+v;self.size+=e['size_bytes']
  elif self.kind=='edges':b=struct.pack('<QQQQB',pc,e['visit'],int(e['target'],16),int(e['modifier'],16),1 if e['kind']=='blraa'else 2)
  else:b=struct.pack('<QQ8Q',pc,int(e['target'],16),*[int(v,16)for v in e['args8']])
  self.h.update(b)
 def result(self):return {'count':self.count,'data_bytes':self.size,'sha256':self.h.hexdigest()}
class Probe(Base):
 def __init__(self,im,c):
  super().__init__(im,'selector',{'id':0});self.initial=[];self.entry=ENTRY;self.c=c;self.visits=Digest('visits');self.reads=Digest('reads');self.writes=Digest('writes');self.edges=Digest('edges');self.calls=Digest('calls');self.dec={};self.allocs=[];self.critical=[];self.cell_reads={};self.transitions=[];self.returns=[];self.cursor=TABLE;self.depth=0;self.lock_alive=False;self.locks={};self.effects=[];self.phase=0;self.table_read_bounds=None
  e=next(e for e in im.k.entries if e['name']=='com.apple.driver.FairPlayIOKit');self.allowed=[(s['address'],s['address']+s['vm_size'])for s in e['segments']if s['name']=='__TEXT_EXEC']
  for j in range(31):self.set(j,0)
  self.set(30,HALT);self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV))
 def effect(self,a,b,reason):
  assert P<=a<a+len(b)<=P+0x100000;self.effects.append({'address':hex(a),'before_hex':bytes(self.u.mem_read(a,len(b))).hex(),'after_hex':b.hex(),'reason':reason});self.u.mem_write(a,b)
 def modeled(self,a,name,result):
  effects=self.effects;self.effects=[];self.model(a,name,result);self.models[-1]['memory_effects']=effects;self.models[-1]['phase']=self.phase
 def flush(self):
  for e in self.pending:
   a=int(e['address'],16);e['after_hex']=bytes(self.u.mem_read(a,e['size_bytes'])).hex();self.writes.append(e)
   if a in CELLS or TABLE<=a<TABLE+512 or(e['size_bytes']==8 and int.from_bytes(bytes.fromhex(e['after_hex']),'little')in self.locks):self.critical.append({**e,'phase':self.phase})
  self.pending=[]
 def write(self,u,t,a,n,v,d):
  assert P<=a<a+n<=P+0x100000 or BSS<=a<a+n<=BSS+0x10000,(hex(a),n)
  self.pending.append({'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'address':hex(a),'size_bytes':n})
 def read(self,u,t,a,n,v,d):
  e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'address':hex(a),'size_bytes':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()};self.reads.append(e)
  if a in CELLS:
   key=(e['pc'],e['address'],n,e['bytes_hex']);r=self.cell_reads.setdefault(key,{**e,'count':0});r['count']+=1
  if TABLE<=a<TABLE+512:self.table_read_bounds=[a,a+n]if self.table_read_bounds is None else[min(a,self.table_read_bounds[0]),max(a+n,self.table_read_bounds[1])]
 def foreign(self,a):
  args=[self.reg(j)for j in range(8)];x=args[0]
  if a==0xfffffe000c4b9a08:
   assert args[:2]==[16384,64];self.allocs.append({'kind':'aligned','address':hex(F),'size_bytes':16384,'phase':self.phase});return self.modeled(a,'aligned_allocation_model',F)
  if a==0xfffffe000c4ba154:
   assert x==0xfffffe000847bea0;self.allocs.append({'kind':'typed','view':hex(x),'address':hex(ARENA),'size_bytes':4096,'phase':self.phase});return self.modeled(a,'typed_allocation_model',ARENA)
  if a in [0xfffffe000c4ba60c,0xfffffe000c4b9428]:
   size=x;fail=(a==0xfffffe000c4ba60c and size==self.c.get('fail_data_size'));result=0 if fail else self.cursor
   if not fail:self.cursor+=(size+4095)&~4095
   assert self.cursor<P+0x70000;self.allocs.append({'kind':'data'if a==0xfffffe000c4ba60c else'generic','address':hex(result),'size_bytes':size,'phase':self.phase});return self.modeled(a,'data_allocation_model'if a==0xfffffe000c4ba60c else'generic_allocation_model',result)
  if a==0xfffffe000c4bb23c:
   result=0 if self.c.get('fail_lock')else LOCK+256*len(self.locks)
   if result:self.locks[result]={'depth':0,'alive':True}
   self.lock_alive=any(v['alive']for v in self.locks.values());return self.modeled(a,'lock_allocation_model',result)
  if a in [0xfffffe000bd040f0,0xfffffe000bd054c4,0xfffffe000c4bb2c4]:
   assert x in self.locks and self.locks[x]['alive'];lock=self.locks[x]
   if a==0xfffffe000bd040f0:assert lock['depth']==0;lock['depth']=1;name='lock_model'
   elif a==0xfffffe000bd054c4:assert lock['depth']==1;lock['depth']=0;name='unlock_model'
   else:assert lock['depth']==0;lock['alive']=False;name='lock_free_model'
   self.depth=sum(v['depth']for v in self.locks.values());self.lock_alive=any(v['alive']for v in self.locks.values());return self.modeled(a,name,0)
  if a in [0xfffffe000c4ba368,0xfffffe000c4b9a24,0xfffffe000c4ba84c,0xfffffe000c4b94b8]:return self.modeled(a,'free_no_effect_model',0)
  if a==0xfffffe000c4babac:assert x==0xfffffe000790caf5;return self.modeled(a,'logger_no_effect_model',0)
  if a==0xfffffe000bce3a8c:
   self.effect(x,struct.pack('<Q',1700000000),'Declared seconds64');self.effect(args[1],struct.pack('<I',123456),'Declared microseconds32');return self.modeled(a,'calendar_time_model',0)
  return False
 def code(self,u,a,n,d):
  self.flush()
  if a==HALT:
   self.returns.append({'phase':self.phase,'before_source_visit_index':len(self.visits),'registers31':[hex(self.reg(j))for j in range(31)],'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'NZCV':hex(u.reg_read(ar.UC_ARM64_REG_NZCV))})
   if self.c.get('repeat')and self.phase==0:
    self.ensure(BSS,0x10000)
    e={**self.returns[-1],'pc':hex(a),'entry_PC':hex(ENTRY),'RAM_sha256':hashlib.sha256(bytes(u.mem_read(P,0x100000))).hexdigest(),'BSS_sha256':hashlib.sha256(bytes(u.mem_read(BSS,0x10000))).hexdigest()};self.phase=1
    for j in range(18):self.set(j,0)
    self.set(30,HALT);u.reg_write(ar.UC_ARM64_REG_NZCV,0);e['after_registers31']=[hex(self.reg(j))for j in range(31)];e['after_NZCV']='0x0';self.transitions.append(e);return u.reg_write(ar.UC_ARM64_REG_PC,ENTRY)
   return self.stop('wrapper_return')
  foreign={0xfffffe000c4b9a08,0xfffffe000c4ba154,0xfffffe000c4ba60c,0xfffffe000c4b9428,0xfffffe000c4bb23c,0xfffffe000bd040f0,0xfffffe000bd054c4,0xfffffe000c4bb2c4,0xfffffe000c4ba368,0xfffffe000c4b9a24,0xfffffe000c4ba84c,0xfffffe000c4b94b8,0xfffffe000c4babac,0xfffffe000bce3a8c}
  if a in foreign:self.foreign(a);return
  if not any(x<=a<a+4<=z for x,z in self.allowed):return self.stop('before_external_code')
  raw=bytes(u.mem_read(a,4));i=self.dec.get(a)
  if i is None:i=next(self.image.k.cs.disasm(self.image.k.read(a,4),a));self.dec[a]=i
  assert raw==bytes(i.bytes);self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()})
  if i.mnemonic in ['pacibsp','autibsp','retab']:return u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30)if i.mnemonic=='retab'else a+4)
  if i.mnemonic in ['braa','blraa']:
   rr=[int(v.strip()[1:])for v in i.op_str.split(',')];target=self.reg(rr[0]);modifier=self.reg(rr[1]);self.edges.append({'pc':hex(a),'visit':len(self.visits)-1,'kind':i.mnemonic,'target':hex(target),'modifier':hex(modifier)})
   if i.mnemonic=='blraa':self.set(30,a+4);self.calls.append({'pc':hex(a),'target':hex(target),'args8':[hex(self.reg(j))for j in range(8)]})
   return u.reg_write(ar.UC_ARM64_REG_PC,target)
  assert i.mnemonic not in ['svc','hvc','smc','brk','autda']
 def run(self):
  self.ensure(self.entry)
  for batch in range(20):
   self.u.emu_start(self.entry if batch==0 else self.u.reg_read(ar.UC_ARM64_REG_PC),0,count=500000)
   if self.reason is not None:break
   print(json.dumps({'case':self.c,'visits':len(self.visits),'batch':batch,'still_running':True}),flush=True)
  self.flush();assert self.reason=='wrapper_return',self.boundary
  for a,n in CELLS.items():self.ensure(a,n)
  self.ensure(BSS,0x10000)
  return {'configuration':self.c,'entry_PC':hex(ENTRY),'entry_SP':hex(SP),'entry_registers31':self.entry_regs,'entry_NZCV':self.entry_NZCV,'private_RAM':{'address':hex(P),'size_bytes':0x100000,'initial_byte':0},'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,'fingerprints':{k:getattr(self,k).result()for k in ['visits','reads','writes','edges','calls']},'original_PC_coverage':[{'pc':hex(a),'bytes_hex':bytes(self.dec[a].bytes).hex(),'count':count}for a,count in sorted(self.visits.pcs.items())],'API_models':self.models,'allocations':self.allocs,'critical_effects':self.critical,'critical_cell_reads':list(self.cell_reads.values()),'table_read_bounds':[hex(v)for v in self.table_read_bounds]if self.table_read_bounds else None,'declared_call_transitions':self.transitions,'returns':self.returns,'boundary':self.boundary,'final_cells_hex':{hex(a):bytes(self.u.mem_read(a,n)).hex()for a,n in CELLS.items()},'final_table512_hex':bytes(self.u.mem_read(TABLE,512)).hex(),'final_RAM_sha256':hashlib.sha256(bytes(self.u.mem_read(P,0x100000))).hexdigest(),'final_BSS_sha256':hashlib.sha256(bytes(self.u.mem_read(BSS,0x10000))).hexdigest(),'final_lock_depth':self.depth,'final_lock_owners':{hex(a):v for a,v in self.locks.items()},'final_lock_alive':self.lock_alive,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False}
def main():
 im=Image();rows=[]
 for c in [{'repeat':True},{'fail_lock':True},{'fail_data_size':512},{'fail_data_size':29}]:
  r=Probe(im,c).run();rows.append(r);print(json.dumps({'case':c,'visits':r['fingerprints']['visits']['count'],'returns':[v['registers31'][0]for v in r['returns']],'cells':r['final_cells_hex']}),flush=True)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in [PREFIX+'_source.json','probe_kernel_vm_mig.py','kernel_vm_mig_tools.py']},'cases':rows,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
