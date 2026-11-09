#!/usr/bin/env python3
"""Original page wrapper -> dispatcher -> linked lookup -> consumer components.
Private declared registry/record state and allocator/free models only. No native
allocation/VM/crypto/PAC operation. O(image bytes+visits), O(image bytes+journals).
"""
import json,struct
from unicorn import arm64_const as ar
from probe_kernel_vm_mig import Probe as Base,P,SP,HALT
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_kext_page_context import sha
PREFIX='kext_page_context';F=P+0x10000;C=P+0x20000;PARAM=P+0x22000;O=P+0x24000;O2=P+0x24400;R=P+0x25000;M=P+0x28000;SRC=P+0x30000;DST=P+0x34000;CELL=0xfffffe000cccca58
class Probe(Base):
 def __init__(self,im,cfg):
  super().__init__(im,'selector',{'id':0});self.kind='page';self.c=cfg;self.initial=[];self.image_initial=[];self.edges=[];self.snapshots=[];self.entry=0xfffffe000a5a4bc0
  e=next(e for e in im.k.entries if e['name']=='com.apple.driver.FairPlayIOKit');self.allowed=[(s['address'],s['address']+s['vm_size'])for s in e['segments']if s['name']=='__TEXT_EXEC']
  self.fixture(F,bytes(0x4000));self.fixture(C,bytes(0x1000));self.fixture(PARAM,bytes(104));self.fixture(M,bytes([0x5a])*0x4000);self.fixture(SRC,bytes([0x11])*0x4000);self.fixture(DST,bytes([0xa5])*0x4000)
  token=cfg['token_u64']&0xffffffff;reg=cfg['registry'];target=O2 if reg=='tail'else O
  for a,node_token,nextptr in [(O,token if reg=='head'else token^1,O2 if reg=='tail'else 0),(O2,token,0)]:
   b=bytearray(0x400);struct.pack_into('<II',b,0,0x42059342,node_token^0x31ae0066);struct.pack_into('<Q',b,0x10,nextptr);b[0x28]=cfg['owner_flags28'];struct.pack_into('<Q',b,0x2e8,R if cfg['child_present']and a==target else 0);struct.pack_into('<I',b,0x2f0,152 if cfg['child_present']and a==target else 0);self.fixture(a,bytes(b))
  b=bytearray(152);struct.pack_into('<I',b,0,cfg['marker']);struct.pack_into('<Q',b,8,cfg['record_word8']);struct.pack_into('<QQ',b,0x20,cfg['word20'],cfg['word28']);struct.pack_into('<I',b,0x40,cfg['word40']);struct.pack_into('<QI',b,0x48,M,cfg['mapped_extent']);self.fixture(R,bytes(b))
  self.ensure(CELL,8);data=struct.pack('<Q',0 if reg=='null'else O);self.u.mem_write(CELL,data);self.image_initial.append({'address':hex(CELL),'bytes_hex':data.hex(),'provenance':'Private linked registry premise; no native initialization established.'})
  warm=0xfffffe000ccca078;self.ensure(warm,1);self.u.mem_write(warm,b'\1');self.image_initial.append({'address':hex(warm),'bytes_hex':'01','provenance':'Explicit warm-flag premise, not a proved consistent native initialization state.'})
  for j in range(31):self.set(j,0)
  for j,v in enumerate([cfg['token_u64'],cfg['offset'],SRC,DST]):self.set(j,v)
  self.set(30,HALT);self.u.reg_write(ar.UC_ARM64_REG_NZCV,0);self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(0)
 def write(self,u,t,a,n,v,d):
  assert P<=a<a+n<=P+0x100000 or 0xfffffe000ccc0000<=a<a+n<=0xfffffe000ccd0000,(hex(a),n)
  self.pending.append({'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'address':hex(a),'size_bytes':n});self.writes.append(self.pending[-1])
 def snapshot(self,a,label):
  e={'pc':hex(a),'label':label,'before_source_visit_index':len(self.visits),'registers31':[hex(self.reg(j))for j in range(31)]}
  if label=='dispatch':e['F64_hex']=bytes(self.u.mem_read(F,64)).hex();ap=int.from_bytes(self.u.mem_read(F+0x28,8),'little');e['argument_record32_hex']=bytes(self.u.mem_read(ap,32)).hex();e['argument_record_address']=hex(ap)
  if label in ['lookup_call','lookup_return']:ap=self.reg(0)if label=='lookup_call'else self.reg(24);e['lookup_record_address']=hex(ap);e['lookup_record24_hex']=bytes(self.u.mem_read(ap,24)).hex()
  self.snapshots.append(e)
 def code(self,u,a,n,d):
  self.flush()
  if a in [HALT,0xfffffe000a60cc4c,0xfffffe000a60e0fc]:return self.stop({HALT:'wrapper_return',0xfffffe000a60cc4c:'record_ABCD_frontier',0xfffffe000a60e0fc:'mapped_metadata_frontier'}[a])
  labels={0xfffffe000a5a4f00:'dispatch',0xfffffe000a60a024:'lookup_call',0xfffffe000a60a028:'lookup_return',0xfffffe000a60a060:'offset_guard',0xfffffe000a60cb9c:'child_read',0xfffffe000a60dd48:'range_guard',0xfffffe000a60e080:'extent_guard',0xfffffe000a60e0c4:'owner_flag_guard',0xfffffe000a60e0d8:'mapped_pointer_read'}
  if a in labels:self.snapshot(a,labels[a])
  if not any(x<=a<a+4<=z for x,z in self.allowed):return self.stop('unmodeled_external_boundary')
  raw=bytes(u.mem_read(a,4));assert raw==self.image.k.read(a,4);i=next(self.image.k.cs.disasm(raw,a));self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()})
  if i.mnemonic in ['pacibsp','autibsp','retab']:return u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30)if i.mnemonic=='retab'else a+4)
  if i.mnemonic in ['braa','blraa']:
   t=self.reg(int(i.op_str.split(',')[0][1:]));self.edges.append({'pc':hex(a),'visit':len(self.visits)-1,'kind':i.mnemonic,'target':hex(t),'modifier':hex(self.reg(17))})
   if i.mnemonic=='blraa':
    self.set(30,a+4)
    if t in [0xfffffe000c4b9a08,0xfffffe000c4ba154,0xfffffe000c4ba368,0xfffffe000c4b9a24]:
     if t==0xfffffe000c4b9a08:assert a==0xfffffe000a5a4d54 and(self.reg(0),self.reg(1))==(0x4000,0x40);result=F
     elif t==0xfffffe000c4ba154:assert self.reg(0)in [0xfffffe000847bea0,0xfffffe000847b760];result=C if self.reg(0)==0xfffffe000847bea0 else PARAM
     else:result=0
     return self.model(a,'declared_allocator_or_free_model',result)
   return u.reg_write(ar.UC_ARM64_REG_PC,t)
  assert i.mnemonic not in ['svc','hvc','smc','brk','autda']
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=30000);self.flush();assert self.reason in ['wrapper_return','record_ABCD_frontier','mapped_metadata_frontier'],self.boundary
  return {'kind':'page','configuration':self.c,'entry_PC':hex(self.entry),'entry_SP':hex(SP),'entry_registers31':self.entry_regs,'entry_NZCV':self.entry_NZCV,'private_RAM':{'address':hex(P),'size_bytes':0x100000,'initial_byte':0},'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'logical_edges':self.edges,'snapshots':self.snapshots,'boundary':self.boundary,'final_F64_hex':bytes(self.u.mem_read(F,64)).hex(),'final_R152_hex':bytes(self.u.mem_read(R,152)).hex(),'destination4096_sha256':__import__('hashlib').sha256(bytes(self.u.mem_read(DST,4096))).hexdigest(),'native_target_executed':False,'native_VM_effects_executed':False,'native_crypto_executed':False,'hardware_PAC_executed':False,'idb_mutated':False,'full_goal_complete':False}
def main():
 im=Image();rows=[];base={'child_present':True,'marker':0xbeefed02,'record_word8':0,'word20':0,'word28':2,'word40':0,'mapped_extent':0x1000,'owner_flags28':0x80}
 for registry in ['null','miss','head','tail']:
  for token in [0,1,0x100000001,0xffffffff]:
   for offset in [0,0x1000,1,1<<44]:rows.append(Probe(im,{**base,'registry':registry,'token_u64':token,'offset':offset}).run())
 for extra in [{'child_present':False},{'marker':0},{'record_word8':0xabcd},{'owner_flags28':0}]:rows.append(Probe(im,{**base,'registry':'head','token_u64':1,'offset':0,**extra}).run())
 for count in [0,1,2,0x1000]:
  for offset in [0,0x1000,0x2000]:rows.append(Probe(im,{**base,'registry':'head','token_u64':1,'offset':offset,'word28':count}).run())
 for offset in [0,0x1000,0x2000]:rows.append(Probe(im,{**base,'registry':'head','token_u64':1,'offset':offset,'word28':0x1000,'word40':32}).run())
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['probe_kernel_vm_mig.py','kernel_vm_mig_tools.py',PREFIX+'_source.json']},'cases':rows,'native_target_executed':False,'native_VM_effects_executed':False,'native_crypto_executed':False,'hardware_PAC_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n');from collections import Counter;print(json.dumps({'cases':len(rows),'visits':sum(len(r['source_visits'])for r in rows),'boundaries':dict(Counter(r['boundary']['kind']for r in rows))}),flush=True)
if __name__=='__main__':main()
