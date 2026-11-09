#!/usr/bin/env python3
"""Source-rooted descriptor reader, acquisition/count/cleanup compositions.
Private local entry selects the known decoded acquisition control593D; caller
reachability and the nonzero-path phase W23 are not supplied. Original helper
and once-callback instructions execute in Unicorn; imported APIs/PAC do not.
O(cases*(mapped source+visits+effects)) time, O(largest run) space.
"""
import json,hashlib,struct,itertools
from pathlib import Path
from unicorn import arm64_const as ar
from probe_daemon_iokit_sync import Sync,cases as sync_cases,P,SYNC_IMPS,PRIMITIVES,ONCE,CALLBACK
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS,FIXUPS,POOL,TABLE
ENTRY=0x10021ecf4;G=0x1010c8218;BUFFER=P+0x3000
ROOT1=(0x100387df0,0x100387e40);ROOT2=(0x100387e68,0x100387e70)
CALLS={0x10021ee18:(0x10043e280,'descriptor_acquire'),0x10025c570:(0x1004423f8,'descriptor_cleanup')}
READER_RANGES=[(ENTRY,0x10021ee94),(0x10025c4e0,0x10025c580),(0x10025f0bc,0x10025f0e8)]
class Reader(Sync):
 def __init__(self,c):
  super().__init__(c);self.reader_models=[];self.reader_calls=[];self.reader_returns=[];self.primitive_effects=[];self.source_stage='root_producer';self.C=P+0xb000+c['placement'];self.CFP=self.C+0x1000;self.R=self.CFP-0x100;self.reader_pending=[];self.phase=0x43c9
  # Canonical fixture data; the slot bytes match the independently recovered
  # twenty-record constructor, rather than an inferred semantic C type.
  entry=struct.pack('<QQQQIIII',0,0,0,0xe3b88695c0d52dbc,0x9008b011,0x95bddb,0x95bddb,0x95bddb);self.fixture(BUFFER,entry*20)
  for a,b in [(G,struct.pack('<Q',c['descriptor']['pointer'])),(G+8,struct.pack('<I',c['descriptor']['count'])),(G+12,bytes(4)),(G+16,struct.pack('<Q',BUFFER))]:
   self.page(a);self.u.mem_write(a,b);self.image_initial_fixtures.append({'address':hex(a),'bytes_hex':b.hex(),'provenance':3});self.bss_known[a-(G&~4095):a-(G&~4095)+len(b)]=bytes([1])*len(b)
  for off,value in [(0xb70,0x1010b66a8),(0xb78,0x1010c4670)]:self.fixture(self.C+off,struct.pack('<Q',value))
  self.u.reg_write(ar.UC_ARM64_REG_SP,self.C);self.set(26,POOL);self.set(22,0x100e99a00);self.set(24,0x100f4e390)
  self.root_entry_registers=[hex(self.reg(j))for j in range(31)];self.root_entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV));self.root_registers=[]
 def reset_reader(self):
  self.source_stage='reader';self.set(25,self.phase);self.set(27,0x1010b66a8);self.set(28,TABLE);self.set(30,0xa5cd4cf);self.set(29,self.CFP);self.set(23,self.c['descriptor']['unestablished_phase_backing']);self.u.reg_write(ar.UC_ARM64_REG_SP,self.C);self.entry_registers=[hex(self.reg(j))for j in range(31)];self.reader_entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV))
 def primitive_return(self,u,pc):
  status=self.c['descriptor']['primitive_status']if PRIMITIVES[pc][0]in ['write_lock','unlock']else 0;high=0x12345678 if self.c['descriptor']['pattern']else 0;self.set(0,(high<<32)|(status&0xffffffff))
  for j in range(1,18):self.set(j,((0xf000000000000000+j*0x1111)^(self.c['descriptor']['pattern']*0x5a5a5a5a5a5a5a5a))&((1<<64)-1))
  u.reg_write(ar.UC_ARM64_REG_NZCV,0xa0000000 if self.c['descriptor']['pattern']else 0xf0000000);self.set(30,pc+4);self.primitive_effects.append({'pc':hex(pc),'after_source_visits':self.seq,'registers0_17':[hex(self.reg(j))for j in range(18)],'NZCV_after':hex(u.reg_read(ar.UC_ARM64_REG_NZCV))});u.reg_write(ar.UC_ARM64_REG_PC,pc+4)
 def primitive(self,u,a):
  # Frozen source helper/once logic is reused, while declared primitive return
  # values and caller-register backing are varied here.
  n=len(self.sync_models);r=super().primitive(u,a)
  if len(self.sync_models)>n:self.sync_models[-1]['returned_u32']=hex(self.c['descriptor']['primitive_status']if PRIMITIVES[a][0]in ['write_lock','unlock']else 0)
  return r
 def code(self,u,a,n,d):
  self.flush()
  if self.source_stage=='root_producer':
   if a==ROOT1[1]:
    self.root_registers.append({'after':hex(a),'source_visit_index':self.seq,'registers31':[hex(self.reg(j))for j in range(31)]});return u.reg_write(ar.UC_ARM64_REG_PC,ROOT2[0])
   if a==ROOT2[1]:
    self.root_registers.append({'after':hex(a),'source_visit_index':self.seq,'registers31':[hex(self.reg(j))for j in range(31)]});self.reset_reader();return u.reg_write(ar.UC_ARM64_REG_PC,ENTRY)
   assert any(lo<=a<hi for lo,hi in [ROOT1,ROOT2]);self.visit(a);return
  if a==0x10025f0e8:return self.stop_at(a,'before_use_of_unestablished_incoming_W23')
  if a==0x100246b84:return self.stop_at(a,'after_zero_count_cleanup_before_next_block')
  if a in CALLS:
   target,name=CALLS[a];assert self.reg(8)==target and self.reg(17)==0x6aa4 and self.reg(0)==self.R;row={'pc':hex(a),'source_visit_index':self.seq,'name':name,'target':hex(target),'record':self.snapshot(self.R,16),'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'saved_registers19_29':[hex(self.reg(j))for j in range(19,30)]};self.reader_calls.append(row);self.reader_pending.append(row);self.visit(a);self.set(30,a+4);return u.reg_write(ar.UC_ARM64_REG_PC,target)
  if a in [pc+4 for pc in CALLS]:
   row=self.reader_pending.pop();assert hex(u.reg_read(ar.UC_ARM64_REG_SP))==row['SP']and[hex(self.reg(j))for j in range(19,30)]==row['saved_registers19_29'];self.reader_returns.append({'pc':hex(a),'source_visit_index':self.seq,'name':row['name']})
  if any(lo<=a<hi for lo,hi in READER_RANGES):
   i=next(self.dec.disasm(IMAGE.read(a,4),a));assert i.mnemonic not in ['bl','blr','blraa','br','svc','hvc','smc'];self.visit(a)
   if i.mnemonic=='braa':
    target=self.reg(int(i.op_str.split(',',1)[0][1:]));self.edges.append({'pc':hex(a),'source_visit_index':self.seq-1,'target':hex(target),'modifier16':hex(self.reg(17))});return u.reg_write(ar.UC_ARM64_REG_PC,target)
   return
  return super().code(u,a,n,d)
 def run_reader(self):
  self.page(ROOT1[0]);self.u.emu_start(ROOT1[0],0,count=10000);self.flush();assert self.reason in ['before_use_of_unestablished_incoming_W23','after_zero_count_cleanup_before_next_block'];raw=self.base_report();r={k:raw[k]for k in ['input','initial_private_fixtures','initial_image_fixtures','source_visits','source_reads','source_writes','source_edges','source_fixup_reads','boundary']};r.update(configuration=self.c['descriptor'],sync_models=self.sync_models,reader_calls=self.reader_calls,reader_returns=self.reader_returns,root_entry_registers31=self.root_entry_registers,root_entry_NZCV=self.root_entry_NZCV,reader_entry_NZCV=self.reader_entry_NZCV,primitive_effects=self.primitive_effects,staged_source_transitions=[{'after_source_visit_index':r['source_visit_index'],'from_PC':r['after'],'to_PC':hex(ROOT2[0])if j==0 else hex(ENTRY),'fixture_transition_not_original_branch':True}for j,r in enumerate(self.root_registers)],root_registers=self.root_registers,reader_entry_registers31=self.entry_registers,caller_SP=hex(self.C),caller_FP=hex(self.CFP),record_address=hex(self.R),root_SP_offsets={hex(off):self.snapshot(self.C+off,8)for off in [0xb00,0xb08,0xb30,0xb38,0xb60,0xb68,0xb70,0xb78]},descriptor_after={'address':hex(G),'size_bytes':24,'bytes_hex':bytes(self.u.mem_read(G,24)).hex(),'known_mask_hex':self.bss_known[G-(G&~4095):G-(G&~4095)+24].hex(),'provenance':'declared descriptor fixture; source reads only'},array_after=self.snapshot(BUFFER,960),callback_pending=self.callback_pending is not None);assert not self.reader_pending and not self.callback_pending;return r

def cases():
 base=next(sync_cases())
 for count,selection,done,status,pattern in itertools.product([0,1,20,0xffffffff],['direct','fallback','none'],[False,True],[0,22],[0,1]):
  c=json.loads(json.dumps(base));pointer=P+0x5000 if selection=='direct'else 0;fallback=P+0x6000 if selection=='fallback'else 0;c.update(placement=pattern*0x100,sync={'primary':pointer,'fallback':fallback,'once_completed':done},descriptor={'count':count,'pointer':pointer,'selection':selection,'once_completed':done,'primitive_status':status,'pattern':pattern,'unestablished_phase_backing':0x12345678^pattern});yield c

def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 rows=[]
 for j,c in enumerate(cases()):
  v=Reader(c);rows.append(v.run_reader())
  if j%16==0:print(json.dumps({'cases_completed':j+1,'boundary':rows[-1]['boundary']['pc']}),flush=True)
 deps=['probe_daemon_iokit_sync.py','probe_daemon_iokit_class.py','daemon_receive_tools.py','daemon_import_bindings.py','daemon_receive_fixups.txt','daemon_context_lock_contracts.json'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'cases':rows,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_descriptor_readers_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(len(r['source_visits'])for r in rows)}),flush=True)
if __name__=='__main__':main()
