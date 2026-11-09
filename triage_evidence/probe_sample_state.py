#!/usr/bin/env python3
"""Original state setup with declared opaque inputs and pure-memory helper code.

Private Unicorn only. Descriptor/hardware results remain models; native task,
mapping, provider, crypto and IPC operations never execute. Unknown calls stop.
"""
import hashlib,json,struct
from pathlib import Path
from unicorn import arm64_const as ar
from probe_kext_close import Close,STACK
from probe_sample_caller import Caller,case
from kext_port_tools import ROOT,SOURCE,IMAGE,CS
CLEAR=0xfffffe000a687d64;CLEAR_END=0xfffffe000a687ecc
COPY=0xfffffe000a508cf4;ALLOC=0xfffffe000c4ba60c;FREE=0xfffffe000c4ba84c;ARENA=STACK+0x8000
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
class State(Caller):
 def __init__(self,c):
  super().__init__(c);self.pure_calls=[];self.memory_models=[];self.state_reads=[];self.header=STACK+0x3000;self.obj=c['object64'];header=bytearray(0x80);header[1]=c['header_byte1'];header[0x38]=c['header_byte38']
  header[2:18]=bytes((i+0x31)&255 for i in range(16));header[0x12:0x22]=bytes((i+0x91)&255 for i in range(16));header[0x39:0x59]=bytes((i+0x61)&255 for i in range(32));self.header_fixture=bytes(header);self.u.mem_write(self.header,self.header_fixture);self.known[self.header-STACK:self.header-STACK+len(header)]=b'\1'*len(header)
  obj=bytearray([c['object_fill_byte']]*0x140);struct.pack_into('<II',obj,0xc0,0,0);self.object_fixture=bytes(obj);self.u.mem_write(self.obj,self.object_fixture)
  self.u.mem_write(ARENA,bytes([0xcc])*8192)
 def hook(self,u,a,n,d):
  if self.reason:return
  if CLEAR<=a<CLEAR_END:
   if a not in self.decoded:self.decoded[a]=next(CS.disasm(IMAGE.read(a,4),a))
   ins=self.decoded[a];assert ins.mnemonic not in['bl','blraa','blr','svc','hvc','smc'];return Close.hook(self,u,a,n,d)
  if a==0xfffffe000a6252dc:
   assert self.reg(8)==CLEAR;self.pure_calls.append({'pc':hex(a),'target':hex(CLEAR),'source_visit_index':len(self.visits),'arguments3':[hex(self.reg(j))for j in range(3)],'original_helper_executed_in_private_guest':True});return Close.hook(self,u,a,n,d)
  if 0xfffffe000a6247a4<=a<0xfffffe000a626648:
   if a not in self.decoded:self.decoded[a]=next(CS.disasm(IMAGE.read(a,4),a))
   ins=self.decoded[a]
   if ins.mnemonic=='blraa':
    target=self.reg(int(ins.op_str.split(',')[0][1:]))
    if target in[COPY,ALLOC,FREE]:
     self.flush();obs={'pc':hex(a),'target':hex(target),'source_visit_index':len(self.visits),'arguments3':[hex(self.reg(j))for j in range(3)],'target_executed':False}
     if target==COPY:
      dst,src,length=[self.reg(j)for j in range(3)]
      if(dst,src,length)not in[(self.obj+4,self.header+2,16),(self.obj+0x2c,self.header+0x39,32),(self.obj+0xb0,self.header+0x12,16)]:
       obs['kind']='additional_copy_boundary';self.memory_models.append(obs);return self.stop('additional_copy_boundary',**{k:v for k,v in obs.items()if k!='kind'})
      assert all(self.known[src-STACK:src-STACK+length]);data=bytes(u.mem_read(src,length));obs.update(kind='opaque_copy_model',source_hex=data.hex(),before_destination_hex=bytes(u.mem_read(dst,length)).hex(),after_destination_hex=data.hex());u.mem_write(dst,data);self.known[dst-STACK:dst-STACK+length]=b'\1'*length;result=dst
     elif target==ALLOC:
      assert self.reg(0)==8192;result=self.case['workspace_result64'];obs.update(kind='workspace_allocation_model',requested_bytes=8192,result64=hex(result),initial_workspace_defined=False)
     else:
      assert self.reg(0)==ARENA and self.reg(1)==8192;result=0xdead0000feed0000;obs.update(kind='workspace_free_model',pointer64=hex(ARENA),extent64=8192,void_return_register_fixture=hex(result))
     self.memory_models.append(obs);raw=IMAGE.read(a,4);assert bytes(u.mem_read(a,4))==raw;self.pool[a]=raw;self.visits.append(a);self.setreg(0,result);self.setreg(30,a+4);u.reg_write(ar.UC_ARM64_REG_PC,a+4);return
  return super().hook(u,a,n,d)
 def read(self,u,access,a,n,v,d):
  super().read(u,access,a,n,v,d)
  for name,base,extent in[('header',self.header,0x80),('object',self.obj,0x140),('workspace',ARENA,8192)]:
   if base<=a<a+n<=base+extent:self.state_reads.append({'region':name,'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'offset':a-base,'size_bytes':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()})
 def run(self):
  r=super().run();r['scope']=__doc__;r.update(pure_memory_calls=self.pure_calls,memory_models=self.memory_models,state_reads=self.state_reads,header_fixture_hex=self.header_fixture.hex(),object_fixture_hex=self.object_fixture.hex(),final_object_hex=bytes(self.u.mem_read(self.obj,0x140)).hex());return r
def cases():
 for code in range(256):
  for flag in[0,1]:
   for workspace in[0,ARENA]:
    c=case(0);c['modeled_results'].update(initialize=0,complete=0);c.update(header_byte1=code,header_byte38=flag,object_fill_byte=0xa5,workspace_result64=workspace);yield c
 for code in[0,1,2,3,255]:
  for flag in[0,1]:
   for workspace in[0,ARENA]:
    c=case(1);c['modeled_results'].update(initialize=0,complete=0);c.update(header_byte1=code,header_byte38=flag,object_fill_byte=0xa5,workspace_result64=workspace);yield c
def main():
 rows=[];pool={}
 for c in cases():q=State(c);r=q.run();rows.append(r);pool.update(q.pool)
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in['probe_kext_close.py','probe_sample_caller.py','sample_caller_contracts.json']},'cases':rows,'source_instructions':[{'ea':hex(a),'bytes_hex':b.hex(),'mnemonic':next(CS.disasm(b,a)).mnemonic,'operands':next(CS.disasm(b,a)).op_str}for a,b in sorted(pool.items())],'native_target_executed':False,'full_goal_complete':False};(ROOT/'sample_state_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'stops':{s:sum(r['stop_reason']==s for r in rows)for s in sorted({r['stop_reason']for r in rows})},'tail_targets':{t:sum(r['helper_observations'][-1]['target']==t for r in rows)for t in sorted({r['helper_observations'][-1]['target']for r in rows})}}),flush=True)
if __name__=='__main__':main()
