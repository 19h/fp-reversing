#!/usr/bin/env python3
"""Original close entry through lookup, VM requests, unlink, overwrite and return.
Explicit warm/private list/object premises; no native VM/free/PAC effects.
Two compositions call close after a completed private page-error path through a
declared outer caller transition. O(image bytes+visits), O(image+journals).
"""
import hashlib,json,struct
from unicorn import arm64_const as ar
from probe_kernel_vm_mig import Probe as Base,P,SP,HALT
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_kext_context_retirement import sha
PREFIX='kext_context_retirement';NODES=[P+0x20000,P+0x21000,P+0x22000];R=P+0x24000;M=P+0x28000;AUX=P+0x2c000;KMAP=P+0x30000;F=P+0x40000;C=P+0x50000;PARAM=P+0x52000;SRC=P+0x60000;DST=P+0x64000;CELL=0xfffffe000cccca58
SHAPES={'singleton':([0],0),'head':([0,1],0),'tail':([0,1],1),'middle':([0,1,2],1),'miss':([0,1],None),'null':([],None)}
class Probe(Base):
 def __init__(self,im,cfg):
  super().__init__(im,'selector',{'id':0});self.kind='retirement';self.c=cfg;self.initial=[];self.image_initial=[];self.edges=[];self.snapshots=[];self.transitions=[];self.phase='page'if cfg['page_preface']else'close';self.entry=0xfffffe000a5a4bc0 if self.phase=='page'else 0xfffffe000a5bff88
  ent=next(e for e in im.k.entries if e['name']=='com.apple.driver.FairPlayIOKit');self.allowed=[(s['address'],s['address']+s['vm_size'])for s in ent['segments']if s['name']=='__TEXT_EXEC'];indices,self.target_index=SHAPES[cfg['placement']];self.nodes=[NODES[j]for j in indices];self.target=NODES[self.target_index]if self.target_index is not None else 0;token=cfg['token_u64']&0xffffffff
  for pos,a in enumerate(self.nodes):
   b=bytearray(1088);tok=token if a==self.target else token^(pos+1);struct.pack_into('<IIQQ',b,0,0x42059342,tok^0x31ae0066,self.nodes[pos-1]if pos else 0,self.nodes[pos+1]if pos+1<len(self.nodes)else 0);b[0x28]=0 if cfg['page_preface']=='owner_flag'else 0x80;struct.pack_into('<Q',b,0x2e8,R if a==self.target and cfg['resource']!='none'else 0);struct.pack_into('<I',b,0x2f0,152 if a==self.target and cfg['resource']!='none'else 0);struct.pack_into('<I',b,0x2f8,0x6487a9a6);self.fixture(a,bytes(b))
  primary=cfg['resource']in ['primary','both'];secondary=cfg['resource']in ['secondary','both'];b=bytearray(152);struct.pack_into('<I',b,0,0xbeefed02);struct.pack_into('<QQ',b,0x20,0,2);struct.pack_into('<QI',b,0x48,M if primary else 0,4096);struct.pack_into('<QI',b,0x58,AUX if secondary else 0,512);self.fixture(R,bytes(b))
  for a,n,byte in [(M,0x4000,0x5a),(AUX,0x4000,0x3c),(F,0x4000,0),(C,0x1000,0),(PARAM,104,0),(SRC,0x4000,0x11),(DST,0x4000,0xa5)]:self.fixture(a,bytes([byte])*n)
  for a,b in [(CELL,struct.pack('<Q',self.nodes[0]if self.nodes else 0)),(0xfffffe000ccca078,b'\1'),(0xfffffe0007f860a8,struct.pack('<Q',KMAP)),(0xfffffe0007e6d9c0,struct.pack('<I',14))]:self.ensure(a,len(b));self.u.mem_write(a,b);self.image_initial.append({'address':hex(a),'bytes_hex':b.hex(),'provenance':'Explicit private warm/registry/map/page-shift premise; native state unknown.'})
  for j in range(31):self.set(j,0)
  self.set(0,cfg['token_u64']);self.set(30,HALT)
  if self.phase=='page':self.set(1,1 if cfg['page_preface']=='offset'else 0);self.set(2,SRC);self.set(3,DST)
  self.u.reg_write(ar.UC_ARM64_REG_NZCV,0);self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV='0x0'
 def write(self,u,t,a,n,v,d):
  assert P<=a<a+n<=P+0x100000 or 0xfffffe000ccc0000<=a<a+n<=0xfffffe000ccd0000,(hex(a),n)
  e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'address':hex(a),'size_bytes':n};self.writes.append(e);self.pending.append(e)
 def snap(self,a,label):
  e={'pc':hex(a),'label':label,'phase':self.phase,'before_source_visit_index':len(self.visits),'registers31':[hex(self.reg(j))for j in range(31)],'SP':hex(self.u.reg_read(ar.UC_ARM64_REG_SP))}
  if label=='lookup':p=self.reg(0);e['record_address']=hex(p);e['record24_hex']=bytes(self.u.mem_read(p,24)).hex()
  self.snapshots.append(e)
 def transition(self):
  e={'pc':hex(HALT),'before_source_visit_index':len(self.visits),'before_registers31':[hex(self.reg(j))for j in range(31)],'SP':hex(self.u.reg_read(ar.UC_ARM64_REG_SP)),'before_NZCV':hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV)),'page_return_u32':hex(self.reg(0)&0xffffffff),'nodes_hex':{hex(a):bytes(self.u.mem_read(a,1088)).hex()for a in self.nodes},'record152_hex':bytes(self.u.mem_read(R,152)).hex(),'head_hex':bytes(self.u.mem_read(CELL,8)).hex(),'memory_effect':'none; declared outer caller supplies token for a new close invocation'}
  assert self.u.reg_read(ar.UC_ARM64_REG_SP)==SP
  for j in range(18):self.set(j,0xc200000000000000|j)
  self.set(0,self.c['token_u64']);self.set(30,HALT);self.u.reg_write(ar.UC_ARM64_REG_NZCV,0xa0000000);e['after_registers31']=[hex(self.reg(j))for j in range(31)];e['after_NZCV']='0xa0000000';e['entry_PC']='0xfffffe000a5bff88';self.transitions.append(e);self.phase='close';self.u.reg_write(ar.UC_ARM64_REG_PC,0xfffffe000a5bff88)
 def code(self,u,a,n,d):
  self.flush()
  if a==HALT:
   if self.phase=='page':return self.transition()
   return self.stop('close_return')
  labels={0xfffffe000a5c0a48:'lookup',0xfffffe000a5c0a4c:'lookup_return',0xfffffe000a5c0d8c:'child_load',0xfffffe000a5c119c:'owner_unlink',0xfffffe000a5c14b8:'overwrite_entry',0xfffffe000a5c15e0:'owner_free'}
  if a in labels and(a!=0xfffffe000a5c14b8 or not any(e['label']=='overwrite_entry'for e in self.snapshots)):self.snap(a,labels[a])
  if not any(x<=a<a+4<=z for x,z in self.allowed):return self.stop('unmodeled_external_boundary')
  raw=bytes(u.mem_read(a,4));assert raw==self.image.k.read(a,4);i=next(self.image.k.cs.disasm(raw,a));self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()})
  if i.mnemonic in ['pacibsp','autibsp','retab']:return u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30)if i.mnemonic=='retab'else a+4)
  if i.mnemonic in ['braa','blraa']:
   target=self.reg(int(i.op_str.split(',')[0][1:]));self.edges.append({'pc':hex(a),'visit':len(self.visits)-1,'kind':i.mnemonic,'target':hex(target),'modifier':hex(self.reg(17)),'phase':self.phase})
   if i.mnemonic=='blraa':
    self.set(30,a+4)
    if target in [0xfffffe000a508e14,0xfffffe000a508e1c,0xfffffe000c4ba368,0xfffffe000c4b9a08,0xfffffe000c4ba154,0xfffffe000c4b9a24]:
     if target in [0xfffffe000a508e14,0xfffffe000a508e1c]:result=self.c['VM_return']
     elif target==0xfffffe000c4b9a08:assert self.phase=='page'and a==0xfffffe000a5a4d54;result=F
     elif target==0xfffffe000c4ba154:assert self.phase=='page'and self.reg(0)in [0xfffffe000847bea0,0xfffffe000847b760];result=C if self.reg(0)==0xfffffe000847bea0 else PARAM
     else:result=0
     return self.model(a,'declared_cleanup_or_page_allocation_model',result)
   return u.reg_write(ar.UC_ARM64_REG_PC,target)
  assert i.mnemonic not in ['svc','hvc','smc','brk','autda']
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=100000);self.flush();assert self.reason=='close_return',self.boundary
  return {'kind':'context_retirement','configuration':self.c,'entry_PC':hex(self.entry),'entry_SP':hex(SP),'entry_registers31':self.entry_regs,'entry_NZCV':self.entry_NZCV,'private_RAM':{'address':hex(P),'size_bytes':0x100000,'initial_byte':0},'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'logical_edges':self.edges,'snapshots':self.snapshots,'declared_call_transitions':self.transitions,'boundary':self.boundary,'target_owner':hex(self.target),'final_head_hex':bytes(self.u.mem_read(CELL,8)).hex(),'final_nodes_hex':{hex(a):bytes(self.u.mem_read(a,1088)).hex()for a in self.nodes},'final_record152_hex':bytes(self.u.mem_read(R,152)).hex(),'destination4096_sha256':hashlib.sha256(bytes(self.u.mem_read(DST,4096))).hexdigest(),'native_target_executed':False,'native_VM_effects_executed':False,'native_free_executed':False,'hardware_PAC_executed':False,'idb_mutated':False,'full_goal_complete':False}
def main():
 im=Image();rows=[];base={'placement':'singleton','resource':'both','token_u64':1,'VM_return':0,'page_preface':''}
 for shape in ['singleton','head','tail','middle']:
  for resource in ['none','empty','primary','secondary','both']:rows.append(Probe(im,{**base,'placement':shape,'resource':resource}).run())
 for resource in ['primary','both']:rows.append(Probe(im,{**base,'resource':resource,'VM_return':4}).run())
 rows.append(Probe(im,{**base,'token_u64':0x100000001}).run());rows.append(Probe(im,{**base,'placement':'middle','token_u64':0xffffffff}).run())
 for shape in ['miss','null']:rows.append(Probe(im,{**base,'placement':shape}).run())
 for mode in ['owner_flag','offset']:rows.append(Probe(im,{**base,'page_preface':mode}).run())
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['probe_kernel_vm_mig.py','kernel_vm_mig_tools.py',PREFIX+'_source.json']},'cases':rows,'native_target_executed':False,'native_VM_effects_executed':False,'native_free_executed':False,'hardware_PAC_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'visits':sum(len(r['source_visits'])for r in rows),'overwrite_stores':sum(e['pc']=='0xfffffe000a5c1520'for r in rows for e in r['source_writes']),'compositions':sum(bool(r['declared_call_transitions'])for r in rows)}),flush=True)
if __name__=='__main__':main()
