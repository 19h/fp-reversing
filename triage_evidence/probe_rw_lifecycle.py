#!/usr/bin/env python3
"""Original RW initialization/free-validation prefixes and kext candidates.

Private guest only. Nonnull synthetic allocation storage and two explicitly
modeled wrapper returns; no native allocation/free, lock, group accounting,
provider, crypto or IDB operation. PAC is abstracted. O(C*(B+V+E)) time/space.
"""
import hashlib,json,struct
from pathlib import Path
import unicorn as uc
from unicorn import arm64_const as ar
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE,CS
PRIVATE=0x6100000000;OBJ=PRIVATE+0x3000;ATTR=PRIVATE+0x4000;GROUP=PRIVATE+0x5000;WORDS=PRIVATE+0x6000;CELL=PRIVATE+0x7000;HALT=PRIVATE+0xf000
TABLE=0xfffffe000846c420;GROUP_CELL=0xfffffe000cb52628
K=None
def kernel():
 global K
 if K is None:K=Kernel()
 return K
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
class Prefix:
 def __init__(self,c,source_init=None):
  self.case=c;self.k=kernel();self.u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);self.u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);self.pages={};self.known=bytearray(0x10000);self.visits=[];self.writes=[];self.reads=[];self.pending=[];self.models=[];self.reason=None;self.initial_record=None;self.object=OBJ+c.get('placement',0);self.boundary=None;self.mode=c['mode'];self.u.mem_map(PRIVATE,0x10000)
  for j in range(31):self.setreg(j,0x110000000+0x1111*j)
  self.setreg(30,HALT);self.u.reg_write(ar.UC_ARM64_REG_SP,PRIVATE+0xe000)
  if self.mode=='initialize':
   self.start=0xfffffe000bd061a8;self.end=0xfffffe000bd061f0;self.map_range(self.start,self.end,'kernel');self.map_range(0xfffffe000700dd08,0xfffffe000700dd10,'kernel');self.map_range(0xfffffe0007e63610,0xfffffe0007e63614,'kernel');self.setreg(0,self.object);self.setreg(19,GROUP);self.setreg(20,0 if c['attribute32']is None else ATTR)
   if c['attribute32']is not None:self.seed(ATTR,struct.pack('<I',c['attribute32']))
   self.initial_record=bytes([c['fill']])*16;self.seed(self.object,self.initial_record)
  elif self.mode=='free_validation':
   assert source_init is not None;self.start=0xfffffe000bd062b8;self.end=0xfffffe000bd06320;self.map_range(self.start,self.end,'kernel');self.setreg(0,self.object);self.setreg(1,GROUP);self.initial_record=bytes.fromhex(source_init['final_object16_hex']);self.seed(self.object,self.initial_record)
  elif self.mode in['API_allocate','API_free']:
   self.start=0xfffffe000c4bb6e4 if self.mode=='API_allocate'else 0xfffffe000c4bb780;self.end=0xfffffe000bd06180 if self.mode=='API_allocate'else 0xfffffe000bd062b8;self.map_range(self.start,self.start+32,'kernel');self.map_range(GROUP_CELL,GROUP_CELL+8,'kernel');self.u.mem_write(GROUP_CELL,struct.pack('<Q',c['group64']));self.setreg(0,c['input_X0']);self.setreg(1,0xabcdef0112345678)
  elif self.mode=='allocation_candidate':
   self.start=0xfffffe000a530fc4;self.end=0xfffffe000a531054;self.map_range(self.start,self.end,'image');self.map_range(0xfffffe0008470000,0xfffffe0008472000,'image');self.map_range(0xfffffe00079171c0,0xfffffe00079172c0,'image');self.map_range(0xfffffe0007919bb0,0xfffffe0007919cb0,'image');self.setreg(21,c['state32']);self.setreg(22,TABLE);self.setreg(10,WORDS);self.setreg(14,WORDS+4);self.setreg(9,0x6c627538298d3f88);self.setreg(8,0xea5ebdeb);self.seed(WORDS,struct.pack('<2I',*c['obfuscation_words32']))
  elif self.mode=='free_clear_candidate':
   self.start=0xfffffe000a579364;self.end=0xfffffe000a5793c0;self.map_range(self.start,self.end,'image');self.map_range(0xfffffe0008471000,0xfffffe0008472000,'image');self.map_range(0xfffffe0007920c10,0xfffffe0007920d10,'image');self.map_range(0xfffffe00079170c0,0xfffffe00079171c0,'image');self.setreg(10,WORDS);self.setreg(14,WORDS+4);self.setreg(9,0x6c627538298d3f88);self.setreg(8,0xea5ebdeb);self.setreg(21,TABLE);self.setreg(20,CELL+c['placement']);self.setreg(0,self.object);self.seed(WORDS,struct.pack('<2I',*c['obfuscation_words32']));self.seed(CELL+c['placement'],struct.pack('<Q',self.object))
  else:raise AssertionError(self.mode)
  if self.mode in['API_allocate','API_free']:self.map_range(self.end,self.end+4,'kernel')
  self.u.hook_add(uc.UC_HOOK_CODE,self.code);self.u.hook_add(uc.UC_HOOK_MEM_READ,self.read);self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.write)
 def reg(self,n):return self.u.reg_read(getattr(ar,'UC_ARM64_REG_X'+str(n)))
 def setreg(self,n,v):self.u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(n)),v&((1<<64)-1))
 def seed(self,a,b):self.u.mem_write(a,b);self.known[a-PRIVATE:a-PRIVATE+len(b)]=b'\1'*len(b)
 def map_range(self,a,z,kind):
  for page in range(a&~4095,(z+4095)&~4095,4096):
   if page in self.pages:assert self.pages[page]==kind;continue
   self.u.mem_map(page,4096);raw=self.k.read(page,4096)if kind=='kernel'else IMAGE.read(page,4096);self.u.mem_write(page,raw);self.pages[page]=kind
 def flush(self):
  for e in self.pending:e['after_hex']=bytes(self.u.mem_read(int(e['address'],16),e['size_bytes'])).hex()
  self.pending=[]
 def code(self,u,a,n,d):
  self.flush()
  if a==self.end:self.boundary={'pc':hex(a),'registers31':[hex(self.reg(j))for j in range(31)]};self.reason='declared_boundary';return u.emu_stop()
  assert self.start<=a<self.end or self.mode in['API_allocate','API_free']and self.start<=a<self.start+32,('source escape',hex(a));kind=self.pages[a&~4095];raw=self.k.read(a,4)if kind=='kernel'else IMAGE.read(a,4);assert bytes(u.mem_read(a,4))==raw;self.visits.append({'pc':hex(a),'bytes_hex':raw.hex(),'source':kind});i=next(CS.disasm(raw,a));m=i.mnemonic
  if a in[0xfffffe000a531028,0xfffffe000a5793b8]:
   target=self.reg(8);want=0xfffffe000a508d7c if a==0xfffffe000a531028 else 0xfffffe000a508d84;assert m=='blraa'and target==want;self.models.append({'pc':hex(a),'target_wrapper':hex(target),'registers8':[hex(self.reg(j))for j in range(8)],'source_visit_index':len(self.visits)-1,'target_executed':False,'model':'nonnull opaque allocation result'if a==0xfffffe000a531028 else'void free returns; no object lifetime effect modeled'})
   result=self.object if a==0xfffffe000a531028 else self.case['void_X0_fixture'];self.setreg(0,result)
   for j in range(1,18):self.setreg(j,0xf000000000000000+0x1111*j)
   u.reg_write(ar.UC_ARM64_REG_NZCV,0xf0000000);self.setreg(30,a+4);return u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  assert m not in['bl','blr','blraa','blrab','svc','hvc','smc','brk'],('unmodeled boundary',hex(a),m)
  if m in['pacibsp','paciasp','bti']:return u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  assert not m.startswith(('aut','pac','xpac')),('PAC boundary',hex(a),m)
 def read(self,u,access,a,n,v,d):
  if PRIVATE<=a<a+n<=PRIVATE+0x10000:assert all(self.known[a-PRIVATE:a-PRIVATE+n]),('undefined private read',hex(a),n)
  self.reads.append({'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'address':hex(a),'size_bytes':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()})
 def write(self,u,access,a,n,v,d):
  assert PRIVATE<=a<a+n<=PRIVATE+0x10000,('non-private write',hex(a),n);self.known[a-PRIVATE:a-PRIVATE+n]=b'\1'*n;e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'address':hex(a),'size_bytes':n};self.writes.append(e);self.pending.append(e)
 def run(self):
  self.u.emu_start(self.start,0,count=20000);self.flush();assert self.reason=='declared_boundary';out={'input':self.case,'object_pointer':hex(self.object),'initial_object16_hex':None if self.initial_record is None else self.initial_record.hex(),'final_object16_hex':None if self.initial_record is None else bytes(self.u.mem_read(self.object,16)).hex(),'source_visits':self.visits,'source_writes':self.writes,'source_reads':self.reads,'models':self.models,'boundary':self.boundary,'private_undefined_reads':[],'native_API_executed':False,'group_accounting_executed':False,'heap_backend_executed':False,'entry_reachability_proved':False}
  if self.mode=='free_clear_candidate':out['final_pointer_cell_hex']=bytes(self.u.mem_read(CELL+self.case['placement'],8)).hex()
  return out
def init_cases():
 attrs=[None]+[flags|noise for flags in[0,0x10000,0x20000,0x30000]for noise in[0,0x80000000,0xfffcffff,0xa5a5]]
 for attr in attrs:
  for placement in[0,16]:
   for fill in[0,0xa5]:yield {'mode':'initialize','attribute32':attr,'placement':placement,'fill':fill}
def api_cases():
 for mode in['API_allocate','API_free']:
  for group in[0,GROUP,0xabcdef0112345678]:
   for x0 in[OBJ,0x1234567887654321]:yield {'mode':mode,'group64':group,'input_X0':x0}
def legacy_cases(c):
 for s in c['allocation_store_candidates']['states']:
  for words in[[0,0],[0xffffffff,0x12345678]]:yield {'mode':'allocation_candidate','state32':s['state32'],'obfuscation_words32':words}
 for placement in[0,16]:
  for words in[[0,0],[0xffffffff,0x12345678]]:
   for void in[0,0xdead0000feed0000]:yield {'mode':'free_clear_candidate','placement':placement,'obfuscation_words32':words,'void_X0_fixture':void}
def main():
 c=json.loads((ROOT/'rw_lifecycle_contracts.json').read_text());initial=[Prefix(q).run()for q in init_cases()];free=[]
 for j,r in enumerate(initial):
  q={'mode':'free_validation','placement':r['input']['placement']};n=Prefix(q,r).run();n['source_initialize_case_index']=j;free.append(n)
 api=[Prefix(q).run()for q in api_cases()];legacy=[Prefix(q).run()for q in legacy_cases(c)];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['kernel_native_reader.py','kext_port_tools.py','rw_lifecycle_contracts.json']},'source_sha256':sha(SOURCE),'kernel_collection_sha256':kernel().sha256,'initialize_cases':initial,'free_validation_cases':free,'API_prefixes':api,'legacy_candidates':legacy,'native_target_executed':False,'cached_cell_publication_proved':False,'full_goal_complete':False};(ROOT/'rw_lifecycle_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'initialize':len(initial),'free_validation':len(free),'API_prefixes':len(api),'legacy_candidates':len(legacy),'source_visits':sum(len(r['source_visits'])for r in initial+free+api+legacy)}),flush=True)
if __name__=='__main__':main()
