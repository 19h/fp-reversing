#!/usr/bin/env python3
"""Bounded original large-frame entry and CAS gate; private single-thread A64.
Incoming register bits, stack, writable image words and guard are fixtures.
PAC edges are abstracted; no target imports, Mach, IOKit or native code run.
Time O(B+C*(V+J*F)); space O(B+C*V+4096J+F), finite visit limit 2000.
"""
import hashlib,itertools,json,struct
from pathlib import Path
import unicorn as uc
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,CS,TABLE
from probe_daemon_iokit_census import Queries,P,LIMIT
from probe_daemon_rwlock_lifecycle import Lifecycle,cases as lifecycle_cases
ENTRY=0x10045053c;GATE=0x1010b5de0;GUARD=P+0x1000
RANGES=[(ENTRY,0x100450788),(0x10035df48,0x10035dfa8),(0x10032ba0c,0x10032bb8c),(0x1003308a0,0x1003308f0),(0x10046c73c,0x10046c780),(0x10032c590,0x10032cf74),(0x1002827d8,0x100282810),(0x1002bc394,0x1002bc3b8)]
RANGES += [(0x100478004,0x100478058)]
RANGES += [(0x1003ecb50,0x1003ecb8c)]
class FrameEntry(Queries):
 def __init__(self,c):
  super().__init__({'placement':c['placement']});self.c=c
  self.u.mem_write(P,b'\xa5'*0x10000);self.known[:]=bytes(0x10000);self.prov[:]=bytes(0x10000);self.initial=[]
  self.image_fixtures=[];self.atomics=[];self.snapshots=[]
  self.E=P+0xc000+c['placement'];self.F=self.E-0xbe0
  for j in range(31):self.set(j,(c['register_seed']+j*0x123456789ab)&((1<<64)-1))
  for j in range(32):self.u.reg_write(getattr(ar,'UC_ARM64_REG_Q'+str(j)),(c['register_seed']*(j+1))&((1<<128)-1))
  self.entry_regs=[self.reg(j)for j in range(31)];self.entry_q=[hex(self.u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j))))for j in range(32)]
  self.u.reg_write(ar.UC_ARM64_REG_SP,self.E);self.fixture(GUARD,struct.pack('<Q',c['guard']))
  for a,b in [(0x1010b1e18,struct.pack('<Q',GUARD)),(0x1010b7dd8,struct.pack('<Q',c['A'])),(0x1010c4670,struct.pack('<Q',c['B'])),(GATE,struct.pack('<I',c['gate'])),(0x1010b6cb8,struct.pack('<I',c.get('flag',1))),(0x1010c5798,bytes([c.get('marker',0)]))]:
   self.page(a);self.u.mem_write(a,b);self.image_fixtures.append({'address':hex(a),'bytes_hex':b.hex(),'provenance':3})
 def write(self,u,access,a,n,v,d):
  if P<=a<a+n<=LIMIT:return super().write(u,access,a,n,v,d)
  assert(a,n)in [(0x1010b7dd8,8),(0x1010c4670,8),(0x1010b6360,4),(GATE,4),(0x1010c5798,1)],('unexpected image store',hex(a),n)
  e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':self.seq-1,'address':hex(a),'size_bytes':n};self.writes.append(e);self.pending.append(e)
 def code(self,u,a,n,d):
  self.flush()
  for t in self.atomics:
   if a==int(t['pc'],16)+4 and 'after32'not in t:t.update(after32=bytes(u.mem_read(int(t['address'],16),4)).hex(),returned_expected_register32=hex(self.reg(t['expected_register'])&0xffffffff))
  if a==0x10035df48 and self.atomics:
   self.reason='before_retry_after_failed_CAS';self.boundary={'pc':hex(a),'registers31':[hex(self.reg(j))for j in range(31)],'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP))};return u.emu_stop()
  if not any(x<=a<a+4<=z for x,z in RANGES):
   self.reason='before_unselected_source';self.boundary={'pc':hex(a),'registers31':[hex(self.reg(j))for j in range(31)],'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP))};return u.emu_stop()
  raw=IMAGE.read(a,4);assert bytes(u.mem_read(a,4))==raw;i=next(CS.disasm(raw,a));self.visits.append({'pc':hex(a),'bytes_hex':raw.hex(),'source_visit_index':self.seq});self.seq+=1
  if a in [0x10035df84,0x1002bc398]:
   er,dr=(16,13)if a==0x10035df84 else(11,25)
   self.atomics.append({'pc':hex(a),'source_visit_index':self.seq-1,'address':hex(self.reg(7)),'expected_register':er,'expected32':hex(self.reg(er)&0xffffffff),'desired32':hex(self.reg(dr)&0xffffffff),'before32':bytes(u.mem_read(self.reg(7),4)).hex(),'scope':'Single-thread guest instruction; no concurrent ordering observed.'})
  if i.mnemonic=='braa':
   target=self.reg(int(i.op_str.split(',',1)[0][1:]));self.edges.append({'pc':hex(a),'source_visit_index':self.seq-1,'target':hex(target),'modifier16':hex(self.reg(17))});self.snapshots.append({'pc':hex(a),'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'frame':self.snapshot(self.F,0xbe0)});self.page(target);return u.reg_write(ar.UC_ARM64_REG_PC,target)
  if i.mnemonic=='pacibsp':return u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  assert i.mnemonic not in ['bl','blr','blraa','br','ret','retab','retaa','svc','hvc','smc']
 def run(self):
  self.page(ENTRY);self.u.emu_start(ENTRY,0,count=2000);self.flush()
  if self.reason is None:self.reason='bounded_gate_retry';self.boundary={'pc':hex(self.u.reg_read(ar.UC_ARM64_REG_PC)),'registers31':[hex(self.reg(j))for j in range(31)],'SP':hex(self.u.reg_read(ar.UC_ARM64_REG_SP))}
  return {'input':self.c,'entry_SP':hex(self.E),'frame_SP':hex(self.F),'entry_registers31':[hex(v)for v in self.entry_regs],'entry_Q_registers32':self.entry_q,'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_fixtures,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'source_edges':self.edges,'source_fixup_reads':self.fixups,'atomic_visits':self.atomics,'frame_snapshots':self.snapshots,'boundary':self.boundary,'stop_reason':self.reason,'native_target_executed':False,'full_goal_complete':False}
def cases():
 for ab,gate,placement,seed,flags in itertools.product([(0,0),(0x7804d3c03c4bf2ed,0xa231dd80f032aecb)],[0x5d96,0xa94ef,0,0xffffffff],[0,0x100],[0,0x9876543210fedcba],[(1,0),(0,0),(1,1)]):
  yield {'A':ab[0],'B':ab[1],'gate':gate,'placement':placement,'register_seed':seed,'guard':0xfedcba9876543210,'flag':flags[0],'marker':flags[1]}
class Fill(Queries):
 def __init__(self,c):
  super().__init__({'placement':0});self.c=c;self.D=P+0x6000+c['alignment'];self.ret=P+0xf000
  self.fixture(self.ret,bytes.fromhex('1f2003d5'))
  self.set(0,self.D);self.set(1,c['byte']);self.set(2,c['length']);self.set(30,self.ret)
 def code(self,u,a,n,d):
  self.flush()
  if a==self.ret:self.reason='returned';return u.emu_stop()
  assert 0x10046faf8<=a<a+4<=0x10046fc5c
  raw=IMAGE.read(a,4);assert bytes(u.mem_read(a,4))==raw;i=next(CS.disasm(raw,a));self.visits.append({'pc':hex(a),'bytes_hex':raw.hex(),'source_visit_index':self.seq});self.seq+=1
  assert i.mnemonic not in ['bl','blr','blraa','braa','svc','hvc','smc']
 def write(self,u,access,a,n,v,d):
  assert self.D<=a<a+n<=self.D+self.c['length'];return super().write(u,access,a,n,v,d)
 def run(self):
  self.page(0x10046faf8);self.u.emu_start(0x10046faf8,0,count=5000);self.flush();assert self.reason=='returned'
  return {'input':self.c,'destination':hex(self.D),'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'result_X0':hex(self.reg(0)),'bytes_hex':bytes(self.u.mem_read(self.D,self.c['length'])).hex(),'native_target_executed':False}
class CorrectedPair(Lifecycle):
 def __init__(self,c):
  super().__init__(c);self.CFP=self.C+0xbd0;self.R=self.CFP-0xd8;self.fixture(self.C+0x390,struct.pack('<Q',0x1010b7dd8));self.set(29,self.CFP);self.entry_regs=[self.reg(j)for j in range(31)]
def main():
 rows=[]
 for j,c in enumerate(cases()):
  f=FrameEntry(c);r=f.run();rows.append(r);del f
  if j%16==0:print(json.dumps({'cases_completed':j+1,'boundary':r['boundary']['pc'],'reason':r['stop_reason']}),flush=True)
 sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
 fills=[Fill({'alignment':a,'length':n,'byte':b}).run()for a,n,b in itertools.product(range(8),[0,1,2,3,4,5,6,7,8,9,15,16,31,63,64,65,1024],[0,0x5a])]
 pairs=[]
 for p,a,b in itertools.product([0,0x100],[0,16],[0,16]):
  c=next(lifecycle_cases());c.update(placement=p,steps=[{'malloc_nonnull':True,'init_status':a},{'malloc_nonnull':True,'init_status':b}]);pairs.append(CorrectedPair(c).run())
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in ['daemon_receive_tools.py','daemon_receive_fixups.txt','probe_daemon_iokit_census.py','probe_daemon_rwlock_lifecycle.py']},'source_sha256':sha(SOURCE),'cases':rows,'fill_cases':fills,'corrected_pair_cases':pairs,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_frame_entry_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'visits':sum(len(r['source_visits'])for r in rows),'fill_cases':len(fills),'corrected_pair_cases':len(pairs)}),flush=True)
if __name__=='__main__':main()
