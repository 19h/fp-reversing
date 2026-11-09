#!/usr/bin/env python3
"""Independent A64 execution of original cutpoint fragments using Unicorn.
No prior source executor is reused. Logical PAC checks table metadata, never
hardware authentication. malloc returns are declared private ABI outcomes.
O(cases*(visited instructions+mapped bytes)) time, O(one private map+outputs) space.
"""
import json,struct,hashlib,itertools
from pathlib import Path
from collections import Counter,defaultdict
import unicorn as uc
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,TABLE,FIXUPS
from recover_daemon_object_creation import sha
P=0x6800000000;SIZE=0x100000;A=P+0x1000;B=P+0x2000;MARK=P+0x3000;CELL=P+0x4000;OBJ=P+0x5000
IMPORTS={name:0x7c000000+256*j for j,name in enumerate(sorted({r['target']for r in FIXUPS.values()if isinstance(r['target'],str)}),1)};IMPORT=IMPORTS['libSystem/_malloc']
PAGES=defaultdict(list)
for a,r in FIXUPS.items():PAGES[a&~4095].append((a,r))
class Run:
 def __init__(self,c):
  self.c=c;self.u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);self.u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);self.pages=set();self.defined=set();self.fix=set();self.steps=[];self.reads=[];self.writes=[];self.edges=[];self.done=False;self.last_slot=None;self.api=[];self.F=P+0x10000+c.get('placement',0);self.pattern=c.get('pattern',0);self.u.mem_map(P,SIZE);self.u.mem_write(P,bytes([self.pattern])*SIZE)
  for j in range(31):self.set('x'+str(j),((j+1)*0x123456789abcdef^self.pattern)&((1<<64)-1))
  self.set('sp',self.F);self.set('x30',TABLE);self.set('x15',MARK);self.set('x4',CELL);self.set('w8',c.get('incoming',0x621b));self.set('x22',0x1122334455667788)
  for a,n,v in [(A,4,c.get('controller',0)),(B,4,0x87654321),(MARK,1,c.get('marker',1)),(CELL,8,c.get('lock',0))]:self.fixture(a,n,v)
  for o,v in [(0x2a88,A),(0x2a90,B),(0x2978,0x100fc4230),(0x2980,0x101031fa0),(0x2990,0x100f4e390),(0x2998,0x100e99a00),(0x29a0,TABLE),(0x2988,0x101031da0)]:self.fixture(self.F+o,8,v)
  self.fixture(self.F+0x2970,8,int.from_bytes(bytes([self.pattern])*8,'little'))
  if c['kind']=='setter':self.set('x0',c['phase64'])
  if c['kind']=='phase_negative':
   self.set('w9',0x5031);self.set('x28',A);self.set('x23',B);self.set('x14',0x100f4e390)
  self.u.hook_add(uc.UC_HOOK_MEM_UNMAPPED,self.missing);self.u.hook_add(uc.UC_HOOK_MEM_READ,self.read);self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.write);self.u.hook_add(uc.UC_HOOK_CODE,self.code)
 def reg(self,n):return self.u.reg_read(getattr(ar,'UC_ARM64_REG_'+n.upper()))
 def set(self,n,v):self.u.reg_write(getattr(ar,'UC_ARM64_REG_'+n.upper()),v)
 def fixture(self,a,n,v):self.u.mem_write(a,v.to_bytes(n,'little'));self.defined.update(range(a,a+n))
 def ensure(self,a,n=1):
  for pg in range(a&~4095,((a+n-1)&~4095)+4096,4096):
   if P<=pg<P+SIZE or pg in self.pages:continue
   raw=bytearray(IMAGE.read(pg,4096))
   for at,r in PAGES[pg]:
    t=r['target'];v=IMPORTS[t]if isinstance(t,str)else t;raw[at-pg:at-pg+8]=struct.pack('<Q',v)
   self.u.mem_map(pg,4096);self.u.mem_write(pg,bytes(raw));self.pages.add(pg)
 def missing(self,u,t,a,n,v,d):self.ensure(a,n);return True
 def read(self,u,t,a,n,v,d):
  if P<=a<P+SIZE:assert all(j in self.defined for j in range(a,a+n)),(hex(self.reg('pc')),hex(a),n)
  b=bytes(u.mem_read(a,n));self.reads.append((hex(self.reg('pc')),hex(a),n,b.hex()))
  if a in FIXUPS and n==8:self.fix.add(a);self.last_slot=a
 def write(self,u,t,a,n,v,d):
  assert P<=a<a+n<=P+SIZE;self.defined.update(range(a,a+n));self.writes.append((hex(self.reg('pc')),hex(a),n,hex(v&((1<<(8*n))-1))))
 def stop(self,a):self.done=True;self.boundary=a;self.u.emu_stop()
 def code(self,u,a,n,d):
  k=self.c['kind']
  stops={'marker':{0x100a03684},'allocation':{0x1006534e8,0x100987c84},'zero':{0x10097290c,0x100933c2c},'setter':{0x100c11650},'phase_negative':{0x100c116e0}}
  if a in stops[k]:return self.stop(a)
  raw=bytes(u.mem_read(a,4));assert raw==IMAGE.read(a,4);ins=next(CS.disasm(raw,a));self.steps.append((a,raw.hex()));assert len(self.steps)<300
  if ins.mnemonic in ['braa','blraa']:
   names=[s.strip()for s in ins.op_str.split(',')];target=self.reg(names[0]);disc=self.reg(names[1]);slot=self.last_slot;assert slot in FIXUPS;r=FIXUPS[slot];word=int.from_bytes(IMAGE.read(slot,8),'little');assert word>>63==1 and (word>>49)&3==0 and (word>>48)&1==0 and (word>>32)&65535==disc;assert target==(IMPORTS[r['target']]if isinstance(r['target'],str)else r['target']);e={'pc':hex(a),'slot':hex(slot),'target':hex(target),'modifier':hex(disc),'metadata_matches':True};self.edges.append(e)
   if ins.mnemonic=='blraa':
    assert a==0x100c116b0 and target==IMPORT and slot==0x10109ff58 and disc==0x6aa4 and self.reg('x0')==872
    before={n:self.reg(n)for n in ['sp']+['x'+str(j)for j in range(18,30)]};ret=OBJ if self.c['nonnull']else 0
    for j in range(1,18):self.set('x'+str(j),((j+7)*0x143256789abcdef^self.pattern)&((1<<64)-1))
    self.set('x0',ret);self.set('x30',a+4);self.set('nzcv',0xa0000000 if self.pattern else 0x50000000)
    assert all(self.reg(n)==v for n,v in before.items());self.api.append({'pc':hex(a),'requested_bytes':872,'returned':hex(ret),'preserved_GPR_and_SP_checked':len(before),'native_call_executed':False});self.set('pc',a+4);return
   self.ensure(target);self.set('pc',target);return
  assert ins.mnemonic not in ['bl','blr','svc','hvc','smc','ret','retab','retaa']
 def value(self,a,n):return int.from_bytes(self.u.mem_read(a,n),'little')
 def run(self):
  k=self.c['kind'];start=0x1009f735c if k=='setter'else 0x100c11650 if k=='phase_negative'else 0x100a035f0;self.ensure(start);self.u.emu_start(start,0,count=300);assert self.done
  critical={}
  if k=='marker':
   idx=0x9768|(self.c['marker']*0x93);slot=TABLE+idx*8;r=FIXUPS.get(slot);expected=(IMPORTS[r['target']]if isinstance(r['target'],str)else r['target'])if r else int.from_bytes(IMAGE.read(slot,8),'little');assert self.reg('w9')==0x471c and self.reg('w8')==0x471c and self.reg('x10')==expected;critical={'index':hex(idx),'phase_Q':'0x471c','marker':self.value(MARK,1)}
  if k=='allocation':
   ret=OBJ if self.c['nonnull']else 0;assert self.value(self.F+0x2c08,8)==ret and len(self.api)==1
   if ret:assert self.boundary==0x1006534e8 and self.value(self.F+0x2a68,8)==ret
   else:assert self.boundary==0x100987c84 and self.value(self.F+0x3554,4)==self.value(self.F+0x2f94,4)==0x74c29f35 and self.value(self.F+0x3580,8)==self.value(self.F+0x30e7,1)==0
   bank_reads=[r for r in self.reads if r[0]=='0x100c11680'];assert len(bank_reads)==1
   assert self.value(MARK,1)==1;critical={'saved_return':hex(ret),'post_malloc_index':hex(0x8068 if ret else 0x8050),'bank_input_byte':int(bank_reads[0][1],16)-0x100e99a00,'source_object_payload_writes':sum(OBJ<=int(w[1],16)<OBJ+872 for w in self.writes)};assert critical['source_object_payload_writes']==0
  if k=='zero':
   assert self.reg('x19')==0x100b280c8 and self.boundary==(0x100933c2c if self.c['lock']else 0x10097290c)and self.value(MARK,1)==0;critical={'callback':'0x100b280c8','cell_loaded':hex(self.c['lock']),'phase_Q':'0x471c'}
  if k=='setter':assert self.reg('x9')==self.c['phase64']and self.value(MARK,1)==1;critical={'phase64_preserved':hex(self.reg('x9')),'marker':1}
  if k=='phase_negative':
   slot=self.last_slot;word=int.from_bytes(IMAGE.read(slot,8),'little');assert self.reg('x17')==0xd254 and ((word>>32)&65535)!=0xd254;critical={'candidate_slot':hex(slot),'metadata_diversity':hex((word>>32)&65535),'required_modifier':'0xd254','logical_edge_rejected':True}
  hs=lambda v:hashlib.sha256(json.dumps(v,separators=(',',':')).encode()).hexdigest()
  return {'configuration':self.c,'entry_PC':hex(start),'entry_SP':hex(self.F),'boundary_PC':hex(self.boundary),'source_visits':len(self.steps),'source_visits_sha256':hs(self.steps),'read_effects':len(self.reads),'read_effects_sha256':hs(self.reads),'private_writes':self.writes,'logical_edges':self.edges,'used_fixups':[hex(x)for x in sorted(self.fix)],'modeled_allocator_calls':self.api,'critical':critical,'all_checks_pass':True}
def cases():
 for marker in range(256):yield {'kind':'marker','marker':marker}
 for low,nonnull,pattern in itertools.product(range(256),[False,True],[0,255]):yield {'kind':'allocation','marker':1,'controller':0x12340000|low,'nonnull':nonnull,'pattern':pattern,'placement':0x100 if pattern else 0}
 for lock,pattern,placement in itertools.product([0,0x690000f000],[0,255],[0,0x100]):yield {'kind':'zero','marker':0,'lock':lock,'pattern':pattern,'placement':placement}
 for high,pattern in itertools.product([0,0x12345678],[0,255]):yield {'kind':'setter','phase64':(high<<32)|0x471c,'pattern':pattern}
 for nonnull in [False,True]:yield {'kind':'phase_negative','nonnull':nonnull}
def main():
 rows=[];totals=Counter()
 for c in cases():
  r=Run(c).run();rows.append(r);totals.update({'cases':1,'source_visits':r['source_visits'],'read_effects':r['read_effects'],'write_effects':len(r['private_writes']),'logical_edges':len(r['logical_edges']),'modeled_allocator_calls':len(r['modeled_allocator_calls'])})
 deps=['daemon_object_creation_contracts.json','recover_daemon_object_creation.py','daemon_receive_tools.py','daemon_receive_fixups.txt'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'case_counts':dict(Counter(r['configuration']['kind']for r in rows)),'cases':rows,'verified_totals':dict(totals),'fixtures':{'private_base':hex(P),'size_bytes':SIZE,'SP':'P+10000+placement','marker':hex(MARK),'controller_owners':[hex(A),hex(B)],'lock_cell':hex(CELL),'allocation_token':hex(OBJ),'allocation_extent_bytes':872,'initial_GPRs':'declared deterministic private values; callee-saved preservation checked at malloc','undefined_private_reads':'rejected; only declared fixtures or earlier source stores can be read','native_allocation_or_frame':'unknown'},'all_checks_pass':True,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_object_creation_replays.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'case_counts':out['case_counts'],'verified_totals':dict(totals)}),flush=True)
if __name__=='__main__':main()
