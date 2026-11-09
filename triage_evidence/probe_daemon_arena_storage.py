#!/usr/bin/env python3
"""Declared nonnull 90000-byte malloc owner through original source consumers.
Allocated bytes stay unknown until source-written; no native malloc/PAC/API
executes. Earlier two dead loads retain their source certificates. O(B+C*
(V+events+JF+N)) time,O(B+C*(V+events)+N+4096J+F) space, N=90000 bytes.
"""
import base64,hashlib,json,struct,zlib
from pathlib import Path
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS
from daemon_import_bindings import binding
from probe_daemon_frame_entry import FrameEntry
from probe_daemon_arena_entry import ArenaEntry,cases as entry_cases,CALL,P
D=0x1010b5ef0;N=90000
RANGES=[(0x10032a4ec,0x10032a5e0),(0x100331de4,0x100331e3c),(0x100322418,0x10032246c)]
class Storage(ArenaEntry):
 def __init__(self,c):
  super().__init__(c);self.H=0x6500000000+c['heap_placement'];self.heap_known=bytearray(N);self.heap_prov=bytearray(N);self.u.mem_map(self.H,(N+4095)&~4095);self.u.mem_write(self.H,bytes([c['heap_backing_byte']])*N);self.allocation_models=[]
 def read(self,u,access,a,n,value,d):
  if self.H<=a<self.H+((N+4095)&~4095):
   assert a+n<=self.H+N,('outside declared allocation',hex(a),n)
   assert all(self.heap_known[a-self.H:a-self.H+n]),('unknown owner read',hex(u.reg_read(ar.UC_ARM64_REG_PC)),hex(a),n)
   self.reads.append({'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':self.seq-1,'address':hex(a),'size_bytes':n,'bytes_hex':bytes(u.mem_read(a,n)).hex(),'owner':'declared_arena_malloc'});return
  return super().read(u,access,a,n,value,d)
 def write(self,u,access,a,n,v,d):
  if self.H<=a<a+n<=self.H+N:
   self.heap_known[a-self.H:a-self.H+n]=bytes([1])*n;self.heap_prov[a-self.H:a-self.H+n]=bytes([1])*n
  elif not(D<=a<a+n<=D+88):return super().write(u,access,a,n,v,d)
  e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':self.seq-1,'address':hex(a),'size_bytes':n};self.writes.append(e);self.pending.append(e)
 def code(self,u,a,n,d):
  if a==CALL:
   self.flush();assert not self.allocation_models and self.reg(0)==N and self.reg(8)==0x7c100000 and self.reg(17)==0x6aa4;raw=IMAGE.read(a,4);assert bytes(u.mem_read(a,4))==raw;self.visits.append({'pc':hex(a),'bytes_hex':raw.hex(),'source_visit_index':self.seq});self.seq+=1
   preserved=lambda:{'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'X18_to_X29':[hex(self.reg(j))for j in range(18,30)],'D8_to_D15_low64':[hex(u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j)))&((1<<64)-1))for j in range(8,16)]}
   row={'pc':hex(a),'source_visit_index':self.seq-1,'name':'malloc','binding':binding(0x10109ff58),'registers8':[hex(self.reg(j))for j in range(8)],'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'preserved_before':preserved(),'returned_owner':hex(self.H),'owner_extent_bytes':N,'known_owner_bytes_at_return':0,'modeled_writes':[],'native_target_executed':False};self.allocation_models.append(row);self.set(0,self.H)
   for j in range(1,18):self.set(j,0xf000000000000000+j*0x1111)
   for j in range(32):
    reg=getattr(ar,'UC_ARM64_REG_Q'+str(j));old=u.reg_read(reg);v=(0xabcdef0123456789<<64)|((j+1)*0x1111111111111111&((1<<64)-1));u.reg_write(reg,((v>>64)<<64)|(old&((1<<64)-1))if 8<=j<16 else v)
   row['preserved_after']=preserved();u.reg_write(ar.UC_ARM64_REG_NZCV,0xf0000000);self.set(30,a+4);return u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  if not any(x<=a<a+4<=z for x,z in RANGES):return super().code(u,a,n,d)
  self.flush();raw=IMAGE.read(a,4);assert bytes(u.mem_read(a,4))==raw;i=next(CS.disasm(raw,a));self.visits.append({'pc':hex(a),'bytes_hex':raw.hex(),'source_visit_index':self.seq});self.seq+=1
  if i.mnemonic=='braa':
   t=self.reg(int(i.op_str.split(',',1)[0][1:]));self.edges.append({'pc':hex(a),'source_visit_index':self.seq-1,'target':hex(t),'modifier16':hex(self.reg(17))});self.snapshots.append({'pc':hex(a),'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'frame':self.snapshot(self.F,0xbe0)});self.page(t);return u.reg_write(ar.UC_ARM64_REG_PC,t)
  assert i.mnemonic not in ['bl','blr','blraa','br','ret','svc','hvc','smc']
 def run(self):
  r=FrameEntry.run(self);assert r['boundary']['pc']=='0x1003ecb8c'and len(self.allocation_models)==1;mask=bytearray(88)
  for w in self.writes:
   a=int(w['address'],16)
   if D<=a<a+w['size_bytes']<=D+88:mask[a-D:a-D+w['size_bytes']]=bytes([1])*w['size_bytes']
  enc=lambda b:base64.b64encode(zlib.compress(bytes(b))).decode()
  r.update(unknown_backing_storage=self.unknown_backing,dead_load_observations=self.dead_reads,cached_arena_words_at_boundary=[self.snapshot(self.F+off,8)for off in [0x5f8,0x540]],allocation_models=self.allocation_models,descriptor={'address':hex(D),'bytes_hex':bytes(self.u.mem_read(D,88)).hex(),'source_written_mask_hex':mask.hex()},heap_snapshot={'address':hex(self.H),'size_bytes':N,'initial_backing_byte':self.c['heap_backing_byte'],'bytes_zlib_base64':enc(self.u.mem_read(self.H,N)),'known_mask_zlib_base64':enc(self.heap_known),'provenance_mask_zlib_base64':enc(self.heap_prov),'known_byte_count':sum(bool(x)for x in self.heap_known),'unknown_byte_count':N-sum(bool(x)for x in self.heap_known)},readiness_hex=bytes(self.u.mem_read(0x1010c5798,1)).hex(),native_allocator_executed=False);return r
def cases():
 for c in entry_cases():
  i=[0,0xa5a5a5a5a5a5a5a5,0xffffffffffffffff,0x0123456789abcdef].index(c['unknown_words'][0])
  for hp in [0,0x100000]:yield {**c,'heap_placement':hp,'heap_backing_byte':[0xa5,0xcc,0,0xff][i]}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 rows=[]
 for j,c in enumerate(cases()):
  r=Storage(c).run();rows.append(r)
  if j%16==0:print(json.dumps({'cases_completed':j+1,'boundary':r['boundary']['pc'],'known_heap_bytes':r['heap_snapshot']['known_byte_count']}),flush=True)
 deps=['probe_daemon_arena_entry.py','probe_daemon_frame_entry.py','probe_daemon_iokit_census.py','daemon_receive_tools.py','daemon_receive_fixups.txt','daemon_import_bindings.py','daemon_arena_entry_proofs.json'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'cases':rows,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_arena_storage_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(len(r['source_visits'])for r in rows)}),flush=True)
if __name__=='__main__':main()
