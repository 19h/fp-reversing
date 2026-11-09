#!/usr/bin/env python3
"""Original IOLibInit/group construction with original string helpers.

Private kernel-address guest only, PAC abstracted. Registry/resource calls are
explicit models. The phase>=4 registry-lock path stops before execution.
No native startup, registry, heap, lock, provider, crypto or IDB operation.
O(C*(B+V+E)) time/space with 30000 source visits per stage.
"""
import gc,hashlib,json,struct
from pathlib import Path
import unicorn as uc
from unicorn import arm64_const as ar
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,CS
P=0x6200000000;HALT=P+0xf000;GROUP=0xfffffe000cb524a8;CELL=0xfffffe000cb52628;READY=0xfffffe000cba36b0;FACILITY=0xfffffe000cb52610;MUTEX_CELL=READY+8;HEAD=READY+16;FLAGS=0xfffffe0007e635c8;PHASE=0xfffffe0007f8b5f0;INPUT_PTR=0xfffffe0007f860a8;INPUT_VECTOR=0xfffffe0007f36928;MAP=P+0x8000;MUTEX=P+0x9000;RW_OBJECT=P+0xa000
K=None;C=None
def kernel():
 global K
 if K is None:K=Kernel()
 return K
def contracts():
 global C
 if C is None:C=json.loads((ROOT/'iolib_group_contracts.json').read_text())
 return C
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
class Group:
 def __init__(self,c):
  self.case=c;self.k=kernel();self.u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);self.u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);self.pages=set();self.ranges=[];self.seq=0;self.known=bytearray(0x10000);self.u.mem_map(P,0x10000);self.allowed=[(GROUP,GROUP+328),(CELL,CELL+8),(READY,READY+1),(FACILITY,FACILITY+24),(MUTEX_CELL,MUTEX_CELL+8),(HEAD,HEAD+16)];active={0xfffffe000c4b91a8,0xfffffe000bd037e0,0xfffffe000be3e3c4,0xfffffe000bc9db70,0xfffffe000c647f10,0xfffffe000c4bb6e4,0xfffffe000c4bb780}
  for f in contracts()['functions']:
   if int(f['start'],16)in active:self.map(int(f['start'],16),int(f['end'],16));self.ranges.append((int(f['start'],16),int(f['end'],16)))
  for a,n in[(GROUP,0x188),(READY,32),(FLAGS,4),(PHASE,4),(0xfffffe00070da7ab,6),(INPUT_PTR,8),(INPUT_VECTOR,16),(0xfffffe000bd06180,4),(0xfffffe000bd062b8,4)]:self.map(a,a+n)
  for j in range(31):self.setreg(j,0x111100000000+j*0x1111)
  self.u.reg_write(ar.UC_ARM64_REG_SP,P+0xe000);self.setreg(30,HALT);self.u.mem_write(GROUP,bytes([c['fill']])*328);self.u.mem_write(CELL,bytes(8));self.u.mem_write(READY,bytes(32));self.u.mem_write(FACILITY,bytes(24));self.u.mem_write(FLAGS,struct.pack('<I',c['flags32']));self.u.mem_write(PHASE,struct.pack('<I',c['phase32']));self.env_pointer=0 if c['environment']=='file_zero'else P+0xb000;self.env_vector=bytes(16)if c['environment']=='file_zero'else struct.pack('<QQ',0x1234567887654321,0xfedcba9876543210);self.u.mem_write(INPUT_PTR,struct.pack('<Q',self.env_pointer));self.u.mem_write(INPUT_VECTOR,self.env_vector);self.u.hook_add(uc.UC_HOOK_CODE,self.code);self.u.hook_add(uc.UC_HOOK_MEM_READ,self.read);self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.write)
 def reg(self,n):return self.u.reg_read(getattr(ar,'UC_ARM64_REG_X'+str(n)))
 def setreg(self,n,v):self.u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(n)),v&((1<<64)-1))
 def map(self,a,z):
  for page in range(a&~4095,(z+4095)&~4095,4096):
   if page in self.pages:continue
   self.u.mem_map(page,4096);self.u.mem_write(page,self.k.read(page,4096));self.pages.add(page)
 def snapshot(self):return {'group328_hex':bytes(self.u.mem_read(GROUP,328)).hex(),'group_cell_hex':bytes(self.u.mem_read(CELL,8)).hex(),'ready32_hex':bytes(self.u.mem_read(READY,32)).hex(),'facility24_hex':bytes(self.u.mem_read(FACILITY,24)).hex()}
 def flush(self):
  for w in self.pending:w['after_hex']=bytes(self.u.mem_read(int(w['address'],16),w['size_bytes'])).hex()
  self.pending=[]
 def code(self,u,a,n,d):
  self.flush()
  boundary=None
  if a==HALT:boundary='returned'
  elif a==0xfffffe000bd03900:boundary='before_registry_lock_path'
  elif self.stage in['RW_allocate','RW_free']and a in[0xfffffe000bd06180,0xfffffe000bd062b8]:boundary='before_RW_core'
  if boundary:
   self.reason=boundary;self.boundary={'kind':boundary,'pc':hex(a),'registers31':[hex(self.reg(j))for j in range(31)]};return u.emu_stop()
  assert any(x<=a<a+4<=z for x,z in self.ranges),('source escape',hex(a));raw=self.k.read(a,4);assert bytes(u.mem_read(a,4))==raw;self.visits.append({'pc':hex(a),'bytes_hex':raw.hex(),'source_visit_index':self.seq});self.seq+=1;i=next(CS.disasm(raw,a));m=i.mnemonic
  models={0xfffffe000bd0392c:('registry',0xfffffe000bceb1d0,self.case['token32']),0xfffffe000c4b9210:('first_setup',0xfffffe000bdc1800,MAP),0xfffffe000c4b9224:('second_setup',0xfffffe000bddc5bc,0xdead0000feed0000),0xfffffe000c4b9238:('mutex_allocation',0xfffffe000bd03ec4,MUTEX)}
  if a in models:
   kind,target,result=models[a];assert m=='bl'and int(i.op_str[1:],16)==target;self.models.append({'kind':kind,'pc':hex(a),'target':hex(target),'registers8':[hex(self.reg(j))for j in range(8)],'source_visit_index':self.seq-1,'result_X0_fixture':hex(result),'target_executed':False});self.visits[-1]['target_modeled']=True;self.setreg(0,result)
   for j in range(1,18):self.setreg(j,0xf000000000000000+j*0x1111)
   u.reg_write(ar.UC_ARM64_REG_NZCV,0xf0000000);self.setreg(30,a+4);return u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  if m=='bl':assert int(i.op_str[1:],16)in[0xfffffe000bd037e0,0xfffffe000be3e3c4,0xfffffe000bc9db70,0xfffffe000c647f10],('unmodeled call',hex(a),i.op_str)
  assert m not in['blr','blraa','blrab','svc','hvc','smc','mrs','casa','casl','ldadd','brk'],('system/synchronization boundary',hex(a),m)
  if m in['bti','pacibsp','paciasp','autibsp','autiasp']:return u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  if m in['retab','retaa']:return u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30))
  assert not m.startswith(('pac','aut','xpac')),('PAC boundary',hex(a),m)
 def read(self,u,access,a,n,v,d):
  if P<=a<a+n<=P+0x10000:assert all(self.known[a-P:a-P+n]),('undefined private read',hex(a),n)
  self.reads.append({'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':self.seq-1,'address':hex(a),'size_bytes':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()})
 def write(self,u,access,a,n,v,d):
  if P<=a<a+n<=P+0x10000:self.known[a-P:a-P+n]=b'\1'*n
  else:assert any(x<=a<a+n<=z for x,z in self.allowed),('unmodeled global write',hex(a),n)
  w={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':self.seq-1,'address':hex(a),'size_bytes':n};self.writes.append(w);self.pending.append(w)
 def run_stage(self,name):
  self.stage=name;self.reason=None;self.visits=[];self.writes=[];self.reads=[];self.models=[];self.pending=[];before=self.snapshot();self.setreg(30,HALT);self.u.reg_write(ar.UC_ARM64_REG_SP,P+0xe000)
  start=0xfffffe000c4bb6e4 if name=='RW_allocate'else 0xfffffe000c4bb780 if name=='RW_free'else 0xfffffe000c4b91a8
  if name in['RW_allocate','RW_free']:self.setreg(0,RW_OBJECT);self.setreg(1,0xabcdef0112345678)
  self.u.emu_start(start,0,count=30000);self.flush();assert self.reason is not None,(name,'budget');return {'stage':name,'before':before,'after':self.snapshot(),'source_visits':self.visits,'source_writes':self.writes,'source_reads':self.reads,'models':self.models,'boundary':self.boundary,'private_undefined_reads':[],'native_API_executed':False,'registry_operation_executed':False,'synchronization_executed':False,'heap_backend_executed':False,'entry_reachability_proved':False}
 def run(self):
  stages=[self.run_stage('cold')]
  if self.reason=='returned':stages.extend([self.run_stage('warm_repeat'),self.run_stage('RW_allocate'),self.run_stage('RW_free')])
  return {'input':self.case,'environment_pointer64':hex(self.env_pointer),'environment_vector16_hex':self.env_vector.hex(),'stages':stages,'native_startup_proved':False,'cached_FairPlay_lock_publication_proved':False}
def cases():
 for flags in[0,0x10000,0x20000,0x30000]:
  for token in[0,1,0x1234,0xffff]:
   for fill in[0,0xa5]:
    for phase in[0,3]:
     for env in['file_zero','declared_values']:yield {'flags32':flags,'token32':token,'fill':fill,'phase32':phase,'environment':env}
 for flags in[0,0x10000,0x20000,0x30000]:
  for phase in[4,0xffffffff]:
   for fill in[0,0xa5]:yield {'flags32':flags,'token32':0,'fill':fill,'phase32':phase,'environment':'file_zero'}
def main():
 rows=[]
 for j,c in enumerate(cases()):
  g=Group(c);rows.append(g.run());del g
  if j%16==0:gc.collect()
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['kernel_native_reader.py','kext_port_tools.py','iolib_group_contracts.json']},'kernel_collection_sha256':kernel().sha256,'cases':rows,'native_target_executed':False,'native_startup_proved':False,'cached_FairPlay_lock_publication_proved':False,'full_goal_complete':False};(ROOT/'iolib_group_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'initial_states':len(rows),'source_stages':sum(len(r['stages'])for r in rows),'source_visits':sum(len(s['source_visits'])for r in rows for s in r['stages'])}),flush=True)
if __name__=='__main__':main()
