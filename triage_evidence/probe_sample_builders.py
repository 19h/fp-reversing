#!/usr/bin/env python3
"""Two original record-builder slices under explicit post-initializer frames.

Stops before calling the coordinator. Does not execute initializer, descriptor,
task, copy, crypto or IPC APIs. Frame reachability/alias preservation unproved.
"""
import hashlib,json,struct
from pathlib import Path
import unicorn as uc
from unicorn import arm64_const as ar
from probe_kext_close import Close,STACK
from probe_sample_caller import key64
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,TABLE,selected
SPEC={
 'first':{'start':0xfffffe000a64b348,'call':0xfffffe000a64b498,'fragment':0xfffffe000a64b284,'end':0xfffffe000a64b5b4,'parent':0xfffffe000a635208,'parent_end':0xfffffe000a666930,'key':0x73,'add':0xf1c,'left':0xfffffe0007949dd0,'right':0xfffffe000792fbc0},
 'second':{'start':0xfffffe000a68f510,'call':0xfffffe000a68f6b0,'fragment':0xfffffe000a68f448,'end':0xfffffe000a68f770,'parent':0xfffffe000a6890dc,'parent_end':0xfffffe000a69ecf8,'key':0x32,'add':0xe6a,'left':0xfffffe0007949ed0,'right':0xfffffe000792fec0}}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
class Builder(Close):
 def __init__(self,c):
  super().__init__(0,0);self.case=c;self.spec=SPEC[c['builder']];self.sp=STACK+0x15000;self.record=STACK+0x1000;self.observation=None;self.seeded=[];self.observed_reads=[];self.u.reg_write(ar.UC_ARM64_REG_SP,self.sp);self.setreg(29,self.sp+0x1100)
  self.seed(self.record,bytes(0x80));self.seed(STACK+0x3000,bytes(0x20));self.seed(STACK+0x5000,bytes(0x700));self.seed(STACK+0x2000,bytes(0x100))
  self.word(STACK+0x3010,c['task64']);self.word(STACK+0x55e0,c['samples_address64']);self.word(STACK+0x56f8,c['sizes_address64']);self.word(STACK+0x2000,c['source_count32'],4);self.word(STACK+0x2008,c['source_samples_length64'],4 if c['builder']=='first'else 8);self.word(STACK+0x2010,c['sizes_address64']);self.word(STACK+0x2018,c['samples_address64'])
  if c['builder']=='first':
   self.setreg(25,self.record);self.setreg(24,0x510);self.setreg(19,((0x510^0x513)*0x3e4)&0xffffffff);self.setreg(22,0xfffffe000ccc32f8);self.setreg(26,self.spec['left']);self.setreg(20,self.spec['right'])
   frame={0x738:STACK+0x3000,0x528:STACK+0x2000,0x530:STACK+0x2008,0xa28:STACK+0x5000,0x3a8:self.record^0x0f6f4af997099bc0,0x968:0x1111222233334444,0x960:0x5555666677778888,0x950:0x9999aaaabbbbcccc,0x958:0xddddeeeeffff0000,0xa30:0xfffffe000ccc3630,0xa60:TABLE}
  else:
   self.setreg(27,self.record);self.setreg(21,0x753);self.setreg(20,0x753-0x1bb);self.setreg(19,0x4d08a3fb);self.setreg(23,0x1111222233334444);self.setreg(24,0xddddeeeeffff0000);self.setreg(28,STACK+0x3000);self.setreg(25,0x9999aaaabbbbcccc);self.setreg(26,0xfffffe000ccc3630);self.setreg(22,0xfffffe000ccc32f8)
   frame={0x250:STACK+0x2000,0x258:STACK+0x2010,0x2a8:STACK+0x2018,0x460:c['source_samples_length64'],0x2d8:c['task64'],0x338:0x5555666677778888,0x3f8:self.spec['left'],0x400:self.spec['right'],0x440:TABLE}
  self.frame={hex(k):hex(v)for k,v in frame.items()}
  for off,v in frame.items():self.word(self.sp+off,v)
 def seed(self,a,b):self.u.mem_write(a,b);self.seeded.append((a,a+len(b)))
 def word(self,a,v,n=8):self.seed(a,(v&((1<<(8*n))-1)).to_bytes(n,'little'))
 def hook(self,u,a,n,d):
  self.flush()
  if a==self.spec['call']:
   ins=next(CS.disasm(IMAGE.read(a,4),a));assert ins.mnemonic=='blraa';self.observation={'pc':hex(a),'target':hex(self.reg(8)),'modifier':hex(self.reg(17)),'record_pointer':hex(self.reg(0)),'record_hex':bytes(u.mem_read(self.record,0x80)).hex()};return self.stop('before_coordinator_call')
  if not self.spec['start']<=a<self.spec['call']:return self.stop('source_extent_boundary',target=hex(a))
  ins=next(CS.disasm(IMAGE.read(a,4),a));assert ins.mnemonic not in['bl','blraa','blr','braa','svc','brk','ret','retab'];return super().hook(u,a,n,d)
 def read(self,u,access,a,n,value,d):
  if STACK<=a<a+n<=STACK+0x21000:assert any(x<=a<a+n<=z for x,z in self.seeded),(hex(a),n)
  self.observed_reads.append({'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'address':hex(a),'size_bytes':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()});return super().read(u,access,a,n,value,d)
 def run(self):
  self.u.emu_start(self.spec['start'],0,count=256);self.flush();assert self.reason=='before_coordinator_call';return {'input':self.case,'frame_qwords':self.frame,'record':hex(self.record),'source_visits':[hex(a)for a in self.visits],'source_reads':self.observed_reads,'source_writes':self.writes,'observation':self.observation,'stop_reason':self.reason,'native_API_executed':False,'frame_reachability_proved':False}
def cases():
 for builder in SPEC:
  for count in[0,1,0x80000000,0xffffffff]:
   for length in([0,1,0xffffffff]if builder=='first'else[0,0x100000001,0xffffffffffffffff]):
    for task in[0,0xabcdef0112345678]:yield {'builder':builder,'source_count32':count,'source_samples_length64':length,'task64':task,'sizes_address64':0x1234567887654321,'samples_address64':0x8765432112345678}
def main():
 rows=[Builder(c).run()for c in cases()];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in['probe_kext_close.py','probe_sample_caller.py','sample_caller_contracts.json']},'cases':rows,'native_target_executed':False,'full_goal_complete':False};(ROOT/'sample_caller_builder_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'builder_cases':len(rows),'source_visits':sum(len(r['source_visits'])for r in rows)}),flush=True)
if __name__=='__main__':main()
