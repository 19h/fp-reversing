#!/usr/bin/env python3
"""Original media wrappers/factory with declared descriptor and API-result models.

No mapping, task access, copy, provider, crypto, reference or native API runs.
PAC is abstracted; runtime objects and allocation results are fixtures. The
sample AES bridge stops before its ordinary tail transfer into the AES wrapper.
O(C*I+E+B) time/space; 256 source-instruction cap per independent case.
"""
import hashlib,json,struct
from pathlib import Path
import unicorn as uc
from unicorn import arm64_const as ar
from kext_port_tools import ROOT,SOURCE,IMAGE,CS
from kernel_native_reader import Kernel
from recover_sample_descriptor import GROUPS
STACK=0x7d00000000;HALT=STACK+0x3000;ACTORS=[0x7c00000000+i*4096 for i in range(4)]
VT=0xfffffe0007f446c0;MVT=0xfffffe0007f42ff8;META=0xfffffe000cb53108;FACTORY=0xfffffe000c53a934
VECTORS=[(0,0),(0x123456789abcdef0,0x100000011),(0xfffffffffffffff0,0xffffffffffffffff)]
RESULTS=[0,1,0xe00002bc,0x100000000]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def cases():
 n=0
 for group in GROUPS:
  for vector in range(3):
   for task in[0,0xeeee111122223333]:
    for result in[False,True]:
     for old in[False,True]:yield {'case':n,'mode':'wrapper','group':group,'kind':'create','vector':vector,'task':task,'nonnull_result':result,'prior_global_nonnull':old};n+=1
  for result in RESULTS:yield {'case':n,'mode':'wrapper','group':group,'kind':'prepare','vector':1,'api_return64':result};n+=1
  for kind in['read','write']:
   for vector in range(3):
    for result in[0,0x100000000,0xffffffffffffffff]:yield {'case':n,'mode':'wrapper','group':group,'kind':kind,'vector':vector,'api_return64':result};n+=1
  for kind in['complete','release']:
   for result in[0,0xe00002bc,0x100000000]:yield {'case':n,'mode':'wrapper','group':group,'kind':kind,'vector':1,'api_return64':result};n+=1
 for pair in[(0,0),(ACTORS[2],ACTORS[2]),(ACTORS[2],ACTORS[3]),(0,ACTORS[3])]:yield {'case':n,'mode':'wrapper','kind':'pointer_equal','pointer_pair':list(pair)};n+=1
 for vector in range(4):yield {'case':n,'mode':'wrapper','kind':'samples_bridge','vector':vector};n+=1
 for vector in range(3):
  for task in[0,0xeeee111122223333]:
   for options in[2,3]:
    for state in['alloc_null',0,1,0x100000000,0x100000001]:yield {'case':n,'mode':'factory','kind':'withAddressRange','vector':vector,'task':task,'options':options,'allocator_or_init_result':state};n+=1
def entry_arguments(c):
 if c['kind']=='pointer_equal':return[0]*8
 if c['kind']=='samples_bridge':
  v=c['vector'];return[[0,16,0x100000011,0xffffffffffffffff][v],0x1111222233334444+v,[0,1,0x1234000000000004,0xffffffffffffffff][v],0x2222333344445555+v,0x3333444455556666+v,0x4444555566667777+v,0,0]
 a,n=VECTORS[c['vector']]
 if c['mode']=='factory':return[a,n,c['options'],c['task'],0,0,0,0]
 if c['kind']=='create':return[a,n,c['task'],0,0,0,0,0]
 if c['kind']in['read','write']:return[a,0x5555666677778888+c['vector'],n,0,0,0,0,0]
 return[0]*8
class Media:
 def __init__(self):
  self.c=json.loads((ROOT/'sample_descriptor_contracts.json').read_text());self.k=Kernel();self.u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);self.u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);self.records={int(r['start'],16):r for r in self.c['functions']};self.factory=next(r for r in self.c['kernel_functions']if r['start']==hex(FACTORY));self.ranges=[];self.decoded={};pages={STACK,STACK+4096,STACK+8192,HALT,VT&~4095,MVT&~4095,(MVT+0xa8)&~4095,META&~4095,0xfffffe000ccc7000,*ACTORS}
  for r in list(self.records.values())+[self.factory]:
   a,z=int(r['start'],16),int(r['end'],16);pages.update(range(a&~4095,(z+4095)&~4095,4096));self.ranges.append((a,z));raw=bytes.fromhex(r.get('bytes_hex',r.get('bytes')));self.decoded.update({i.address:i for i in CS.disasm(raw,a)})
  for a in sorted(pages):self.u.mem_map(a,4096)
  for r in list(self.records.values())+[self.factory]:self.u.mem_write(int(r['start'],16),bytes.fromhex(r.get('bytes_hex',r.get('bytes'))))
  for a in ACTORS:self.u.mem_write(a,struct.pack('<Q',VT))
  self.u.mem_write(META,struct.pack('<Q',MVT));self.targets={}
  for s in self.c['nominal_slots']:a,t=int(s['slot'],16),int(s['target'],16);self.u.mem_write(a,struct.pack('<Q',t));self.targets[t]=s['offset_from_vptr']
  self.u.hook_add(uc.UC_HOOK_CODE,self.code);self.u.hook_add(uc.UC_HOOK_MEM_READ,self.read);self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.write);self.u.hook_add(uc.UC_HOOK_MEM_UNMAPPED,self.unmapped)
 def reg(self,n):return self.u.reg_read(getattr(ar,'UC_ARM64_REG_X'+str(n)))
 def stop(self,why):self.reason=why;self.u.emu_stop()
 def flush(self):
  for e in self.pending:e['after_hex']=bytes(self.u.mem_read(int(e['address'],16),e['size_bytes'])).hex()
  self.pending=[]
 def model(self,u,pc,kind,target,tail=False,value=0):
  e={'pc':hex(pc),'kind':kind,'target':hex(target),'registers8':[hex(self.reg(i))for i in range(8)],'source_visit_index':len(self.visits)-1,'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'declared_return64':hex(value),'tail_transfer':tail,'native_API_executed':False}
  if kind=='init_result':
   pointer=self.reg(1);assert STACK<=pointer<pointer+16<=STACK+0x4000 and all(self.known[pointer-STACK:pointer-STACK+16]);e['range_pointer']=hex(pointer);e['range16_hex']=bytes(u.mem_read(pointer,16)).hex()
  self.calls.append(e);u.reg_write(ar.UC_ARM64_REG_X0,value&((1<<64)-1));destination=self.reg(30)if tail else pc+4
  if not tail:u.reg_write(ar.UC_ARM64_REG_X30,pc+4)
  u.reg_write(ar.UC_ARM64_REG_PC,destination)
 def code(self,u,a,n,d):
  self.flush()
  if a==HALT:return self.stop('return')
  if not any(x<=a<a+4<=z for x,z in self.ranges):return self.stop('code_extent')
  r=self.factory if self.case['mode']=='factory'else self.records[self.entry];reader=self.k.read if self.case['mode']=='factory'else IMAGE.read;assert bytes(u.mem_read(a,4))==reader(a,4);self.visits.append(hex(a));i=self.decoded[a];m=i.mnemonic
  if m in['bti','pacibsp','autda']:
   if m!='bti':self.auth.append({'pc':hex(a),'instruction':m})
   return u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  if m=='retab':self.auth.append({'pc':hex(a),'instruction':m});return u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30))
  if m=='bl':
   t=int(i.op_str[1:],16);assert t==0xfffffe000a69f1e4;actor=ACTORS[list(GROUPS).index(self.case['group'])];return self.model(u,a,'factory_result',0xfffffe000c53a934,value=actor if self.case['nonnull_result']else 0)
  if m=='b'and int(i.op_str[1:],16)==0xfffffe000a508534:
   self.bridge={'pc':hex(a),'target':'0xfffffe000a508534','registers8':[hex(self.reg(j))for j in range(8)],'target_executed':False};return self.stop('before_AES_bridge_target')
  if m in['blraa','braa']:
   t=self.reg(int(i.op_str.split(',')[0][1:]));assert t in self.targets;off=self.targets[t];tail=m=='braa'
   if self.case['mode']=='factory':
    state=self.case['allocator_or_init_result'];kind='allocation_result'if off==0xa8 else'init_result'if off==0x138 else'release_result';value=(0 if state=='alloc_null'else ACTORS[0])if kind=='allocation_result'else int(state)if kind=='init_result'else 0
   else:kind={0x218:'prepare_result',0x208:'read_result',0x210:'write_result',0x220:'complete_result',0x28:'release_result'}[off];value=self.case['api_return64']
   return self.model(u,a,kind,t,tail,value)
  if m in['svc','hvc','smc','brk']or m.startswith(('pac','aut','xpac')):return self.stop('unmodeled_instruction')
 def read(self,u,access,a,n,value,d):
  if STACK<=a<a+n<=STACK+0x4000:assert all(self.known[a-STACK:a-STACK+n])
  else:assert n==8 and(a in ACTORS or a==META or a in[GROUPS[g]['global']for g in GROUPS]or a in[int(s['slot'],16)for s in self.c['nominal_slots']]),(hex(a),n)
  self.reads.append({'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'address':hex(a),'size_bytes':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()})
 def write(self,u,access,a,n,value,d):
  if STACK<=a<a+n<=STACK+0x4000:self.known[a-STACK:a-STACK+n]=b'\1'*n
  else:assert n==8 and a in[GROUPS[g]['global']for g in GROUPS]
  e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'address':hex(a),'size_bytes':n,'source_visit_index':len(self.visits)-1};self.writes.append(e);self.pending.append(e)
 def unmapped(self,u,access,a,n,value,d):self.stop('unmapped');return False
 def run(self,c):
  self.case=c;self.reason=None;self.visits=[];self.reads=[];self.writes=[];self.pending=[];self.calls=[];self.auth=[];self.bridge=None;self.known=bytearray(0x4000);self.u.mem_write(STACK,b'\xa5'*0x4000)
  for j in range(31):self.u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(j)),0)
  self.u.reg_write(ar.UC_ARM64_REG_SP,STACK+0x2000);self.u.reg_write(ar.UC_ARM64_REG_X30,HALT)
  for j,v in enumerate(entry_arguments(c)):self.u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(j)),v)
  initial={}
  for i,g in enumerate(GROUPS):
   v=ACTORS[i]
   if c['kind']=='create'and c['group']==g:v=0x9999aaaabbbbcccc if c['prior_global_nonnull']else 0
   if c['kind']=='pointer_equal'and g in['input','output']:v=c['pointer_pair'][0 if g=='input'else 1]
   a=GROUPS[g]['global'];self.u.mem_write(a,struct.pack('<Q',v));initial[hex(a)]=hex(v)
  self.entry=FACTORY if c['mode']=='factory'else GROUPS[c['group']][c['kind']]if'group'in c else 0xfffffe000a509fc8 if c['kind']=='pointer_equal'else 0xfffffe000a509fe8
  self.u.emu_start(self.entry,0,count=256);self.flush();self.reason=self.reason or'instruction_budget';assert self.reason in['return','before_AES_bridge_target'],self.reason
  return {'input':c,'entry':hex(self.entry),'entry_arguments8':[hex(v)for v in entry_arguments(c)],'initial_globals':initial,'final_globals':{hex(GROUPS[g]['global']):hex(struct.unpack('<Q',self.u.mem_read(GROUPS[g]['global'],8))[0])for g in GROUPS},'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'modeled_calls':self.calls,'abstracted_authentication':self.auth,'bridge_observation':self.bridge,'return_register64':hex(self.reg(0)),'stop_reason':self.reason,'native_API_executed':False,'native_mapping_proved':False}
def main():
 g=Media();rows=[g.run(c)for c in cases()];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in['kext_port_tools.py','kernel_native_reader.py','recover_sample_descriptor.py','sample_descriptor_contracts.json']},'cases':rows,'native_target_executed':False,'native_mapping_proved':False,'complete_lifecycle_proved':False,'full_goal_complete':False};(ROOT/'sample_descriptor_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(len(r['source_visits'])for r in rows),'factory_cases':sum(r['input']['mode']=='factory'for r in rows)}),flush=True)
if __name__=='__main__':main()
