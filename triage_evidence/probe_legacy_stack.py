#!/usr/bin/env python3
"""Original record wrappers/bridges and stack-probe helpers in a private guest.

Two inner record operations are explicit output/clobber models. Nonzero stack
displacements stop before the relocated output read. No native API/heap/lock,
provider, crypto, credential or target-file operation; PAC is abstracted.
O(C*(B+V+E)) time/retained space; each run has a 30000-visit bound.
"""
import gc,hashlib,json,struct
from pathlib import Path
import unicorn as uc
from unicorn import arm64_const as ar
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE,CS
P=0x6300000000;HALT=P+0x1f000;M64=(1<<64)-1
K=None;C=None
def contracts():
 global C
 if C is None:C=json.loads((ROOT/'legacy_stack_contracts.json').read_text())
 return C
def kernel():
 global K
 if K is None:K=Kernel()
 return K
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
class Bridge:
 def __init__(self,c):
  self.case=c;self.u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);self.u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);self.pages=set();self.u.mem_map(P,0x20000);self.u.mem_write(P,b'\xa5'*0x20000);self.known=bytearray(0x20000);self.provenance=bytearray(0x20000);self.ranges=[];self.visits=[];self.reads=[];self.writes=[];self.pending=[];self.calls=[];self.models=[];self.probe_reads=[];self.reason=None;self.outer_record=None;self.inner_record=None;self.seq=0;self.sp0=P+0x18000+c['placement'];self.flags_address=[]
  for va,off,n in IMAGE.segments:
   self.map_blank(va,va+n);self.u.mem_write(va,IMAGE.data[off:off+n])
  active={0xfffffe000a50c2b0,0xfffffe000a50e618,0xfffffe000a52fd18,0xfffffe000a570cf4,0xfffffe000a5a1cc4,0xfffffe000a5a1ccc}
  for f in contracts()['functions']:
   if int(f['start'],16)in active:self.ranges.append((int(f['start'],16),int(f['end'],16)))
  self.allowed=[]
  for j,row in enumerate(contracts()['mutable_globals']):
   a=int(row['address'],16);v=int.from_bytes(bytes.fromhex(row['original8_hex']),'little')if c['global_fixture']=='original'else 0 if c['global_fixture']=='zero'else(0x12345678a5a50000+j*0x111111111)&M64;self.u.mem_write(a,struct.pack('<Q',v));self.allowed.append((a,a+8))
  guard=contracts()['guard'];a=int(guard['address'],16);self.map_blank(a,a+8);self.u.mem_write(a,bytes.fromhex(guard['original8_hex']));self.guard=a
  for j in range(31):self.setreg(j,0x111100000000+j*0x1111)
  for j,v in enumerate(c['inputs8']):self.setreg(j,v)
  self.setreg(30,HALT);self.u.reg_write(ar.UC_ARM64_REG_SP,self.sp0);self.initial_displacement_seed=int.from_bytes(bytes(self.u.mem_read(0xfffffe000ccc2e88,8)),'little');self.u.hook_add(uc.UC_HOOK_CODE,self.code);self.u.hook_add(uc.UC_HOOK_MEM_READ,self.read);self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.write)
 def map_blank(self,a,z):
  for page in range(a&~4095,(z+4095)&~4095,4096):
   if page not in self.pages:self.u.mem_map(page,4096);self.pages.add(page)
 def reg(self,n):return self.u.reg_read(getattr(ar,'UC_ARM64_REG_X'+str(n)))
 def setreg(self,n,v):self.u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(n)),v&M64)
 def snapshot(self,a,n):return {'address':hex(a),'size_bytes':n,'bytes_hex':bytes(self.u.mem_read(a,n)).hex(),'known_mask_hex':self.known[a-P:a-P+n].hex(),'provenance_hex':self.provenance[a-P:a-P+n].hex()}
 def flush(self):
  for e in self.pending:e['after_hex']=bytes(self.u.mem_read(int(e['address'],16),e['size_bytes'])).hex()
  self.pending=[]
 def model_write(self,a,b):
  assert P<=a<a+len(b)<=P+0x20000;self.u.mem_write(a,b);self.known[a-P:a-P+len(b)]=b'\1'*len(b);self.provenance[a-P:a-P+len(b)]=b'\2'*len(b);return {'address':hex(a),'bytes_hex':b.hex(),'size_bytes':len(b)}
 def code(self,u,a,n,d):
  self.flush()
  delta=(self.case['delta_units32']&0xffff)<<4
  if a==HALT or a==0xfffffe000a50e874 and delta:
   self.reason='returned'if a==HALT else'before_relocated_output_read';self.boundary={'kind':self.reason,'pc':hex(a),'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'registers31':[hex(self.reg(j))for j in range(31)]};return u.emu_stop()
  assert any(x<=a<a+4<=z for x,z in self.ranges),('source escape',hex(a));raw=IMAGE.read(a,4);assert bytes(u.mem_read(a,4))==raw;self.visits.append({'pc':hex(a),'bytes_hex':raw.hex(),'source_visit_index':self.seq});self.seq+=1;i=next(CS.disasm(raw,a));m=i.mnemonic
  if a in[0xfffffe000a52fea4,0xfffffe000a570de8,0xfffffe000a570e68,0xfffffe000a570ee8,0xfffffe000a570ef8,0xfffffe000a50e874]:self.visits[-1]['observed_registers31']=[hex(self.reg(j))for j in range(31)];self.visits[-1]['observed_SP']=hex(u.reg_read(ar.UC_ARM64_REG_SP))
  if a in[0xfffffe000a50c4cc,0xfffffe000a50e860]:
   want=0xfffffe000a52fd18 if a==0xfffffe000a50c4cc else 0xfffffe000a570cf4;assert self.reg(8)==want and self.reg(17)==0x9d3a;self.outer_record=self.reg(0);self.calls.append({'kind':'outer_bridge','pc':hex(a),'target':hex(want),'modifier16':hex(self.reg(17)),'registers8':[hex(self.reg(j))for j in range(8)],'source_visit_index':self.seq-1,'record':self.snapshot(self.reg(0),32 if a==0xfffffe000a50c4cc else 64)})
  if a in[0xfffffe000a5302ac,0xfffffe000a570ee4]:
   want=0xfffffe000a55e8b0 if a==0xfffffe000a5302ac else 0xfffffe000a561344;assert self.reg(8)==want and m=='blraa';self.inner_record=self.reg(0);out=[];row={'kind':'inner_record_operation','pc':hex(a),'target':hex(want),'modifier16':hex(self.reg(17)),'registers8':[hex(self.reg(j))for j in range(8)],'source_visit_index':self.seq-1,'record_before':self.snapshot(self.reg(0),32 if a==0xfffffe000a5302ac else 64),'target_executed':False}
   if a==0xfffffe000a5302ac:out.append(self.model_write(self.reg(0)+16,struct.pack('<I',self.case['status32'])))
   else:
    row['local_state_before']=self.snapshot(self.reg(1),8);out.append(self.model_write(self.reg(0)+56,struct.pack('<I',self.case['status32'])));out.append(self.model_write(self.reg(1),struct.pack('<I',(self.initial_displacement_seed+self.case['delta_units32'])&0xffffffff)))
   row['modeled_writes']=out;row['record_after']=self.snapshot(self.reg(0),32 if a==0xfffffe000a5302ac else 64);self.models.append(row);self.setreg(0,0xdead0000feed0000)
   for j in range(1,18):self.setreg(j,0xf000000000000000+j*0x1111)
   u.reg_write(ar.UC_ARM64_REG_NZCV,0xf0000000);self.setreg(30,a+4);return u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  if m=='blraa':
   target=self.reg(8)if i.op_str.startswith('x8,')else self.reg(16);assert target in[0xfffffe000a52fd18,0xfffffe000a570cf4,0xfffffe000a5a1cc4],('unmodeled call',hex(a),hex(target));self.setreg(30,a+4);return u.reg_write(ar.UC_ARM64_REG_PC,target)
  assert m not in['bl','blr','blrab','braa','brab','svc','hvc','smc','mrs','casa','casl','brk'],('unmodeled boundary',hex(a),m)
  if m in['bti','pacibsp','paciasp','autibsp','autiasp']:return u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  if m in['retab','retaa']:return u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30))
  assert not m.startswith(('pac','aut','xpac'))
 def read(self,u,access,a,n,v,d):
  pc=u.reg_read(ar.UC_ARM64_REG_PC);probe=pc in[0xfffffe000a5a1cdc,0xfffffe000a5a1cf0]
  if P<=a<a+n<=P+0x20000:
   if probe:assert n==1;self.probe_reads.append({'pc':hex(pc),'address':hex(a),'source_visit_index':self.seq-1,'loaded_register':'wzr','mapped_private_page_only':True})
   else:assert all(self.known[a-P:a-P+n]),('undefined private value read',hex(pc),hex(a),n)
  else:assert a==self.guard or any(va<=a<a+n<=va+size for va,off,size in IMAGE.segments),('unmapped source read',hex(pc),hex(a),n)
  self.reads.append({'pc':hex(pc),'source_visit_index':self.seq-1,'address':hex(a),'size_bytes':n,'bytes_hex':bytes(u.mem_read(a,n)).hex(),'probe_only':probe})
 def write(self,u,access,a,n,v,d):
  if P<=a<a+n<=P+0x20000:self.known[a-P:a-P+n]=b'\1'*n;self.provenance[a-P:a-P+n]=b'\1'*n
  else:assert any(x<=a<a+n<=z for x,z in self.allowed),('global write escape',hex(a),n)
  e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':self.seq-1,'address':hex(a),'size_bytes':n};self.writes.append(e);self.pending.append(e)
 def run(self):
  start=0xfffffe000a50c2b0 if self.case['family']=='record32'else 0xfffffe000a50e618;self.u.emu_start(start,0,count=30000);self.flush();assert self.reason is not None,('visit bound',self.case)
  return {'input':self.case,'entry_SP':hex(self.sp0),'initial_displacement_seed64':hex(self.initial_displacement_seed),'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'source_calls':self.calls,'models':self.models,'probe_only_reads':self.probe_reads,'outer_record_after':self.snapshot(self.outer_record,32 if self.case['family']=='record32'else 64),'boundary':self.boundary,'undefined_private_value_reads':[],'native_API_executed':False,'inner_record_operations_executed':False,'native_reachability_proved':False}
def cases():
 profiles=[[0]*8,[(1<<64)-1]*8,[0x1234567887654321,0x13579bdf,0xfedcba9876543210,0xabcdef0112345678,0x2468ace0,0x33445566778899aa,0xdeadbeef,0x10203040]]
 for family in['record32','record64']:
  selected=profiles+[[*profiles[2][:1],profiles[2][1]+0x10000,*profiles[2][2:]]]if family=='record32'else profiles
  for inputs in selected:
   for globals in['original','zero','declared_noise']:
    for placement in[0,0x100]:
     for status in[0,0xffffffff]:
      for delta in([0]if family=='record32'else[0,1,0xffff,0x10000]):yield {'family':family,'inputs8':inputs,'global_fixture':globals,'placement':placement,'status32':status,'delta_units32':delta}
def main():
 rows=[]
 for j,c in enumerate(cases()):
  b=Bridge(c);rows.append(b.run());del b
  if j%12==0:gc.collect()
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['legacy_stack_contracts.json','kernel_native_reader.py','kext_port_tools.py']},'source_sha256':sha(SOURCE),'kernel_collection_sha256':kernel().sha256,'cases':rows,'native_target_executed':False,'cached_FairPlay_lock_publication_proved':False,'full_goal_complete':False};(ROOT/'legacy_stack_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(len(r['source_visits'])for r in rows)}),flush=True)
if __name__=='__main__':main()
