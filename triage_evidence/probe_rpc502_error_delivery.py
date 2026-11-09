#!/usr/bin/env python3
"""Original receive callback with the observed RPC502 error as an API boundary.

The protected application is abstracted at its public entry, returning the
unchanged observed ffff5bd9. Explicit reply allocation, output poison, destroy,
send and free models never execute native APIs. PAC is inherited/bypassed.
This composes an observed result with original serialization/control flow;
it is not an end-to-end worker/transport execution or native ownership proof.
O(C*(B+F+V+E)) time/space for eight bounded callback fixtures.
"""
import hashlib,json,struct
from pathlib import Path
from daemon_rpc502_probe import Probe,STACK,HALT,ar,uc
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS

REQUEST=0x5700000000;NAME=REQUEST+0x1000;REPLY=0x5800000000
ERROR=0xffff5bd9

class ErrorDelivery(Probe):
 def __init__(self,disposition,remote,send_result):
  self.observations=[];self.original={};self.visits=[];self.fixups={};self.pending=[];self.stores=[];self.alloc=False;self.disposition=disposition;self.remote=remote;self.send_result=send_result
  super().__init__()
  self.u.mem_map(REQUEST,0x2000);self.u.mem_map(REPLY,0x1000);self.u.mem_write(NAME,b'/synt/fixture.bin\0')
  request=bytearray(148);struct.pack_into('<6I',request,0,0x80000000|disposition,80,remote,0x4567,0,502);struct.pack_into('<I',request,24,1);struct.pack_into('<Q',request,28,NAME);struct.pack_into('<I',request,36,0x01000100);struct.pack_into('<I',request,40,18);request[44:52]=bytes.fromhex('0000000001000000');struct.pack_into('<I',request,52,18);struct.pack_into('<3Q',request,56,0x100000c,2,1);struct.pack_into('<2I',request,80,0,68)
  self.initial_request=bytes(request);self.u.mem_write(REQUEST,self.initial_request);self.u.mem_write(REPLY,b'\xa5'*384)
 def flush_output(self):
  for e in self.pending:e['after_hex']=bytes(self.u.mem_read(int(e['address'],16),e['size_bytes'])).hex()
  self.pending=[]
 def event(self,kind,**kw):
  self.observations.append({'kind':kind,'source_site':hex(self.reg(30)-4),'args':[hex(self.reg(j))for j in range(8)],**kw})
 def hook(self,u,a,n,d):
  self.flush_output()
  if a==0x100422d48:
   # Exercise incidental output stores without giving them success semantics.
   sp=u.reg_read(ar.UC_ARM64_REG_SP);stack=struct.unpack('<5Q',bytes(u.mem_read(sp,40)));u.mem_write(self.reg(7),b'\x6d'*136);u.mem_write(stack[0],b'\x6d'*172)
   for p,v,fmt in[(stack[1],0xdead0000,'<Q'),(stack[2],123,'<I'),(stack[3],0xbeef0000,'<Q'),(stack[4],456,'<I')]:u.mem_write(p,struct.pack(fmt,v))
   self.event('abstract_application_return',status_u32=hex(ERROR),output_poison='6d fixed records;opaque address/count stores',stack_arguments=[hex(x)for x in stack]);return self.return_model(ERROR)
  if 0x100000000<=a<0x102000000:
   raw=IMAGE.read(a,4);assert bytes(u.mem_read(a,4))==raw;self.original[a]=raw;self.visits.append(a)
  name=self.imports.get(a)
  if name=='libSystem/_malloc':
   assert self.reg(0)==384 and not self.alloc;self.alloc=True;self.event('reply_allocate',size_bytes=384,pointer=hex(REPLY));return self.return_model(REPLY)
  if name=='libSystem/_mach_msg_destroy':
   assert self.reg(0)in[REQUEST,REPLY];self.event('destroy_request'if self.reg(0)==REQUEST else'destroy_reply',buffer_hex=bytes(u.mem_read(self.reg(0),148 if self.reg(0)==REQUEST else 384)).hex(),effect='request recorded;no native right/VM destruction');return self.return_model()
  if name=='libSystem/_mach_msg':
   assert self.reg(0)==REPLY;size=self.reg(2);self.event('send_request',size_bytes=size,wire_hex=bytes(u.mem_read(REPLY,size)).hex(),modeled_result_u32=hex(self.send_result));return self.return_model(self.send_result)
  if name=='libSystem/_free':
   assert self.reg(0)==REPLY;self.event('reply_free',buffer384_hex=bytes(u.mem_read(REPLY,384)).hex());return self.return_model()
  return super().hook(u,a,n,d)
 def read_hook(self,u,access,a,n,value,d):
  if a in FIXUPS:self.fixups[a]={'address':hex(a),'word_hex':IMAGE.read(a,8).hex(),'fixup':FIXUPS[a]}
  return super().read_hook(u,access,a,n,value,d)
 def write_hook(self,u,access,a,n,value,d):
  if REQUEST<=a<a+n<=REQUEST+148 or REPLY<=a<a+n<=REPLY+384:
   e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'address':hex(a),'size_bytes':n};self.stores.append(e);self.pending.append(e)
  return super().write_hook(u,access,a,n,value,d)
 def execute(self):
  self.setreg(1,REQUEST);self.setreg(2,80);self.setreg(30,HALT);self.u.reg_write(ar.UC_ARM64_REG_SP,STACK+0x78000)
  self.u.emu_start(0x100425f78,0,count=200000);self.flush_output();assert self.stop_reason=='returned_to_fixture',self.records[-2:]
  return {'fixture':{'disposition':self.disposition,'remote':self.remote,'send_result_u32':hex(self.send_result)},'initial_request_hex':self.initial_request.hex(),'final_request_hex':bytes(self.u.mem_read(REQUEST,148)).hex(),'events':self.observations,'source_stores':self.stores,'source_visits':[hex(a)for a in self.visits],'source_fixups':list(self.fixups.values()),'stop_reason':self.stop_reason,'PAC_model':self.pac,'native_target_executed':False}

def main():
 cases=[];pool={}
 for disp in[17,18]:
  for remote,results in[(0x1234,[0,0x10000003,0x10000004]),(0,[0])]:
   for result in results:
    q=ErrorDelivery(disp,remote,result);r=q.execute();cases.append(r)
    for a,b in q.original.items():pool[a]=b
    print('CASE',r['fixture'],[e['kind']for e in r['events']],flush=True)
 out={'scope':__doc__,'generator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'source_sha256':hashlib.sha256(SOURCE.read_bytes()).hexdigest(),'dependencies':{n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest()for n in['daemon_rpc502_probe.py','daemon_receive_tools.py','daemon_receive_fixups.txt']},'source_instructions':[{'ea':hex(a),'bytes':b.hex(),'mnemonic':next(CS.disasm(b,a)).mnemonic,'operands':next(CS.disasm(b,a)).op_str}for a,b in sorted(pool.items())],'cases':cases,'application_body_executed':False,'native_target_executed':False,'full_goal_complete':False}
 (ROOT/'rpc502_error_delivery_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
