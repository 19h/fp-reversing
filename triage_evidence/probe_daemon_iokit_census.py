#!/usr/bin/env python3
"""Original daemon query22/query23 path with independent API response summaries.

Entry frame/phase/table/connection are explicit fixtures, not native open proof.
Source-only stores have provenance1, API values2, incoming fixtures3. Unknown
private reads stop. No IOKit/native port or protected operation executes.
O(B+C*(V+E+J*F)) time,O(B+C*(V+E)+J*4096+F) retained space;
J is demand pages,F fixup records;1000 visits per case,abstract PAC.
"""
import hashlib,json,struct,itertools
from pathlib import Path
import unicorn as uc
from unicorn import arm64_const as ar
from daemon_receive_tools import IMAGE,SOURCE,ROOT,FIXUPS,CS,TABLE
from daemon_import_bindings import binding
P=0x6400000000;LIMIT=P+0x10000;API=0x7c006800;JOIN=0x1003c39b0
RANGES=[(0x100364398,0x100364470),(0x100628754,0x10062876c),(0x1004ba914,0x1004baa18),(0x100332734,0x10033274c),(0x1004d6be4,0x1004d6c10)]
class Queries:
 def __init__(self,c):
  self.c=c;self.u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);self.u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);self.pages=set();self.u.mem_map(P,0x10000);self.u.mem_write(P,b'\xa5'*0x10000);self.known=bytearray(0x10000);self.prov=bytearray(0x10000);self.visits=[];self.reads=[];self.writes=[];self.pending=[];self.models=[];self.edges=[];self.seq=0;self.reason=None;self.F=P+0x8000+c['placement'];self.initial=[];self.fixups=[]
  for j in range(31):self.set(j,0x111100000000+j*0x1111)
  for j,v in[(19,P+0x2000),(21,0x9376),(22,0x1010b7d48),(23,0x1010c4670),(24,TABLE)]:self.set(j,v)
  self.u.reg_write(ar.UC_ARM64_REG_SP,self.F)
  for at,b in[(self.F+8,struct.pack('<QQ',P+0x4000,0x100e99a00)),(self.F+0x28,struct.pack('<Q',0x100f4e390)),(self.F+0x38,struct.pack('<Q',P+0x2000)),(P+0x4000,struct.pack('<I',0x5804))]:self.fixture(at,b)
  self.u.hook_add(uc.UC_HOOK_MEM_UNMAPPED,self.unmapped);self.u.hook_add(uc.UC_HOOK_CODE,self.code);self.u.hook_add(uc.UC_HOOK_MEM_READ,self.read);self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.write)
 def reg(self,j):return self.u.reg_read(getattr(ar,'UC_ARM64_REG_X'+str(j)))
 def set(self,j,v):self.u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(j)),v&((1<<64)-1))
 def fixture(self,a,b):self.u.mem_write(a,b);self.known[a-P:a-P+len(b)]=bytes([1])*len(b);self.prov[a-P:a-P+len(b)]=bytes([3])*len(b);self.initial.append({'address':hex(a),'bytes_hex':b.hex(),'provenance':3})
 def page(self,a):
  page=a&~4095
  if page in self.pages:return
  raw=bytearray(IMAGE.read(page,4096));self.u.mem_map(page,4096);self.pages.add(page)
  for at,r in FIXUPS.items():
   if page<=at<page+4096:
    target=r['target'];value=API if target=='IOKit/_IOConnectCallStructMethod'else target if isinstance(target,int)else 0x7c100000
    raw[at-page:at-page+8]=struct.pack('<Q',value)
  self.u.mem_write(page,bytes(raw))
 def unmapped(self,u,access,a,n,value,d):self.page(a);return True
 def flush(self):
  for e in self.pending:e['after_hex']=bytes(self.u.mem_read(int(e['address'],16),e['size_bytes'])).hex()
  self.pending=[]
 def snapshot(self,a,n):return {'address':hex(a),'size_bytes':n,'bytes_hex':bytes(self.u.mem_read(a,n)).hex(),'known_mask_hex':self.known[a-P:a-P+n].hex(),'provenance_hex':self.prov[a-P:a-P+n].hex()}
 def code(self,u,a,n,d):
  self.flush()
  if a==JOIN:self.reason='before_joint_query_consumer';self.boundary={'pc':hex(a),'registers31':[hex(self.reg(j))for j in range(31)],'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP))};return u.emu_stop()
  assert any(x<=a<a+4<=z for x,z in RANGES),('source escape',hex(a));raw=IMAGE.read(a,4);assert bytes(u.mem_read(a,4))==raw;i=next(CS.disasm(raw,a));self.visits.append({'pc':hex(a),'bytes_hex':raw.hex(),'source_visit_index':self.seq});self.seq+=1
  if i.mnemonic=='blraa':
   which=len(self.models);assert which<2 and a==[0x100364420,0x1004ba9c4][which]and self.reg(8)==API and self.reg(17)==0x7a6c;selector=22+which;assert[self.reg(j)for j in range(6)]==[0x5804,selector,0,0,self.F+(0x64 if which==0 else 0x6c),self.F+0x70]
   status,size=self.c['responses'][which];word=self.c['words'][which];writes=[]
   for at,b in[(self.F+0x70,struct.pack('<Q',size))]+([(self.reg(4),struct.pack('<I',word))]if status==0 and size==4 else[]):
    self.u.mem_write(at,b);self.known[at-P:at-P+len(b)]=bytes([1])*len(b);self.prov[at-P:at-P+len(b)]=bytes([2])*len(b);writes.append({'address':hex(at),'bytes_hex':b.hex()})
   self.models.append({'pc':hex(a),'source_visit_index':self.seq-1,'import_slot':'0x1010a0640','binding':binding(0x1010a0640),'selector':selector,'registers8':[hex(self.reg(j))for j in range(8)],'status32_fixture':hex(status),'returned_size64_fixture':hex(size),'value32_fixture':hex(word),'modeled_writes':writes,'native_target_executed':False});self.set(0,status)
   for j in range(1,18):self.set(j,0xf000000000000000+j*0x1111)
   u.reg_write(ar.UC_ARM64_REG_NZCV,0xf0000000);self.set(30,a+4);return u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  if i.mnemonic=='braa':
   r=int(i.op_str.split(',',1)[0][1:]);target=self.reg(r);assert any(x<=target<z for x,z in RANGES)or target==JOIN;self.edges.append({'pc':hex(a),'source_visit_index':self.seq-1,'target':hex(target),'modifier16':hex(self.reg(17))});return u.reg_write(ar.UC_ARM64_REG_PC,target)
  assert i.mnemonic not in['bl','blr','br','ret','retab','svc','hvc','smc']
 def read(self,u,access,a,n,value,d):
  if P<=a<a+n<=LIMIT:assert all(self.known[a-P:a-P+n]),('unknown private value',hex(u.reg_read(ar.UC_ARM64_REG_PC)),hex(a),n)
  raw=bytes(u.mem_read(a,n));row={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':self.seq-1,'address':hex(a),'size_bytes':n,'bytes_hex':raw.hex()}
  if a in FIXUPS:row['original_fixup']=FIXUPS[a];self.fixups.append({'address':hex(a),'original_fixup':FIXUPS[a]})
  self.reads.append(row)
 def write(self,u,access,a,n,value,d):
  assert P<=a<a+n<=LIMIT;self.known[a-P:a-P+n]=bytes([1])*n;self.prov[a-P:a-P+n]=bytes([1])*n;e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':self.seq-1,'address':hex(a),'size_bytes':n};self.writes.append(e);self.pending.append(e)
 def run(self):
  self.page(0x100364398);self.u.emu_start(0x100364398,0,count=1000);self.flush();assert self.reason=='before_joint_query_consumer'and len(self.models)==2
  return {'input':self.c,'frame_SP':hex(self.F),'initial_private_fixtures':self.initial,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'source_edges':self.edges,'source_fixup_reads':self.fixups,'boundary':self.boundary,'query_words':self.snapshot(self.F+0x64,12),'returned_size':self.snapshot(self.F+0x70,8),'native_target_executed':False,'native_port_identity_proved':False,'full_goal_complete':False}
def cases():
 responses=list(itertools.product([0,0xe00002c7],[4,3,0,0x100000004]))
 for a,b,placement,words in itertools.product(responses,responses,[0,0x100],[[0,0xffffffff],[0x13180000,0xaabbccdd]]):yield {'responses':[list(a),list(b)],'placement':placement,'words':words}
def main():
 rows=[]
 for j,c in enumerate(cases()):
  f=Queries(c);r=f.run();del f;rows.append(r)
  if j%32==0:print(json.dumps({'cases_completed':j+1}),flush=True)
 sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['daemon_receive_tools.py','daemon_import_bindings.py','daemon_receive_fixups.txt','verify_interface_contracts.py']},'source_sha256':sha(SOURCE),'cases':rows,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_iokit_census_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(len(r['source_visits'])for r in rows)}),flush=True)
if __name__=='__main__':main()
