#!/usr/bin/env python3
"""Original callback to first malloc, preserving unknown dead stack bytes.
Only two exact mapped LDR sites may observe unknown backing bits, authorized
by checked source liveness/noninterference artifacts. No field becomes known.
No instruction is skipped at either LDR; no imported API/PAC executes.
O(B+C*(V+JF)) time,O(B+C*(V+events)+4096J+F) space, 2000 visits/case.
"""
import hashlib,itertools,json,struct
from pathlib import Path
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS
from daemon_import_bindings import binding
from probe_daemon_frame_entry import FrameEntry,cases as base_cases,P
RANGES=[(0x1003b5724,0x1003b57d4),(0x1003c24b8,0x1003c24e4),(0x10032a464,0x10032a4ec)]
READS={0x1003b5738:0x5f8,0x1003b573c:0x540};CALL=0x10032a4e8
class ArenaEntry(FrameEntry):
 def __init__(self,c):
  proof=json.loads((ROOT/'daemon_arena_entry_proofs.json').read_text());assert len(proof['proofs'])==10 and all(x['result']=='unsat'for x in proof['proofs'])and proof['source_sha256']==hashlib.sha256(SOURCE.read_bytes()).hexdigest()
  super().__init__(c);self.dead_reads=[];self.unknown_backing=[]
  for off,word in zip([0x5f8,0x540],c['unknown_words']):
   b=struct.pack('<Q',word);self.u.mem_write(self.F+off,b);assert not any(self.known[self.F+off-P:self.F+off-P+8]);self.unknown_backing.append({'address':hex(self.F+off),'bytes_hex':b.hex(),'known_mask_hex':'00'*8,'scope':'Analysis backing bits only; no defined-value or source-producer claim.'})
 def read(self,u,access,a,n,value,d):
  pc=u.reg_read(ar.UC_ARM64_REG_PC)
  if pc in READS:
   assert a==self.F+READS[pc]and n==8 and not any(self.known[a-P:a-P+n]);e={'pc':hex(pc),'source_visit_index':self.seq-1,'address':hex(a),'size_bytes':n,'bytes_hex':bytes(u.mem_read(a,n)).hex(),'known_mask_hex':'00'*8,'classification':'dead-register-load; source-verified kill before any read or call'};self.reads.append(e);self.dead_reads.append(e);return
  return super().read(u,access,a,n,value,d)
 def write(self,u,access,a,n,v,d):
  if(a,n)==(0x1010b5ef0,8):
   e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':self.seq-1,'address':hex(a),'size_bytes':n};self.writes.append(e);self.pending.append(e);return
  return super().write(u,access,a,n,v,d)
 def code(self,u,a,n,d):
  if not any(x<=a<a+4<=z for x,z in RANGES):return super().code(u,a,n,d)
  self.flush()
  if a==CALL:
   assert self.reg(0)==90000 and self.reg(8)==0x7c100000 and self.reg(17)==0x6aa4;self.reason='before_first_arena_malloc';self.boundary={'pc':hex(a),'registers31':[hex(self.reg(j))for j in range(31)],'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP))};return u.emu_stop()
  raw=IMAGE.read(a,4);assert bytes(u.mem_read(a,4))==raw;i=next(CS.disasm(raw,a));self.visits.append({'pc':hex(a),'bytes_hex':raw.hex(),'source_visit_index':self.seq});self.seq+=1
  if i.mnemonic=='braa':
   t=self.reg(int(i.op_str.split(',',1)[0][1:]));assert t in [0x1003c24b8,0x10032a464];self.edges.append({'pc':hex(a),'source_visit_index':self.seq-1,'target':hex(t),'modifier16':hex(self.reg(17))});self.snapshots.append({'pc':hex(a),'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'frame':self.snapshot(self.F,0xbe0)});self.page(t);return u.reg_write(ar.UC_ARM64_REG_PC,t)
  assert i.mnemonic not in ['bl','blr','blraa','br','ret','svc','hvc','smc']
 def run(self):
  r=super().run();assert self.reason=='before_first_arena_malloc'and len(self.dead_reads)==2;r.update(unknown_backing_storage=self.unknown_backing,dead_load_observations=self.dead_reads,dead_words_at_boundary=[self.snapshot(self.F+off,8)for off in [0x5f8,0x540]],allocator_binding=binding(0x10109ff58),descriptor_prefix8_hex=bytes(self.u.mem_read(0x1010b5ef0,8)).hex(),allocator_executed=False);return r
def cases():
 for c in base_cases():
  if(c['gate'],c['flag'],c['marker'])!=(0x5d96,1,0):continue
  for a,b in [(0,0),(0xa5a5a5a5a5a5a5a5,0xa5a5a5a5a5a5a5a5),(0xffffffffffffffff,0xffffffffffffffff),(0x0123456789abcdef,0xfedcba9876543210)]:yield {**c,'unknown_words':[a,b]}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 rows=[]
 for c in cases():rows.append(ArenaEntry(c).run())
 deps=['probe_daemon_frame_entry.py','probe_daemon_iokit_census.py','daemon_receive_tools.py','daemon_receive_fixups.txt','daemon_import_bindings.py','daemon_arena_entry_contracts.json','daemon_arena_entry_proofs.json'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'cases':rows,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_arena_entry_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(len(r['source_visits'])for r in rows),'dead_load_observations':sum(len(r['dead_load_observations'])for r in rows)}),flush=True)
if __name__=='__main__':main()
