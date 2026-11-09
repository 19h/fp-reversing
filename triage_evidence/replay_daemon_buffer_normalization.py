#!/usr/bin/env python3
"""Independent isolated A64 normalization: every destination/selector pairing.
O(cases*112) time, O(512+code-page+one case events) space. Native APIs/PAC absent.
The second source execution checks idempotence for every retained input.
"""
import hashlib,json,struct
from pathlib import Path
import unicorn as uc
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,IMAGE,SOURCE
START=0x100315488;END=0x100315648;PAGE=START&~4095;DATA=0x6900001000

def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def transform(words):
 a=words.copy()
 for j in range(16):
  i=4*j;a[i]=(a[i]|((~a[2*((a[i]>>1)&31)]<<16)&0xffffffff))&0xffffffff
 return a
class Isolated:
 def __init__(self):
  self.u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);self.u.mem_map(PAGE,4096);self.u.mem_write(PAGE,IMAGE.read(PAGE,4096));self.u.mem_map(DATA,4096);self.u.hook_add(uc.UC_HOOK_CODE,self.code);self.u.hook_add(uc.UC_HOOK_MEM_READ,self.read);self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.write)
 def code(self,u,a,n,d):
  assert START<=a<END and bytes(u.mem_read(a,4))==IMAGE.read(a,4);self.visits+=1
 def read(self,u,access,a,n,value,d):
  assert n==4;pc=u.reg_read(ar.UC_ARM64_REG_PC);j=(pc-START)//28;stage=(pc-START)%28;assert 0<=j<16 and stage in (0,12);expected=self.D+(4*j if stage==0 else 2*((self.expected[4*j]>>1)&31))*4;assert a==expected
  actual=int.from_bytes(bytes(u.mem_read(a,n)),'little');assert actual==self.expected[(a-self.D)//4];self.reads+=1
  if stage==12:self.selections.append({'destination_word':4*j,'table_word':(a-self.D)//4})
 def write(self,u,access,a,n,value,d):
  pc=u.reg_read(ar.UC_ARM64_REG_PC);j=(pc-START)//28;assert (pc-START)%28==24 and n==4 and a==self.D+j*16;old=self.expected[4*j];expected=(old|(~self.expected[2*((old>>1)&31)]<<16))&0xffffffff;assert value&0xffffffff==expected;self.expected[4*j]=expected;self.writes+=1
 def one(self,label,words,alignment,forced=None):
  self.D=DATA+alignment;raw=b''.join(v.to_bytes(4,'little')for v in words);self.u.mem_write(self.D,raw)
  initial=[(0x123456789abcdef*(j+1))&((1<<64)-1)for j in range(31)];initial[9]=self.D
  for j,v in enumerate(initial):self.u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(j)),v)
  self.u.reg_write(ar.UC_ARM64_REG_SP,DATA+0x800);self.u.reg_write(ar.UC_ARM64_REG_NZCV,0xa0000000);passes=[]
  reference=transform(words);immutable=words.copy()
  for j in range(16):immutable[4*j]=(words[4*j]|(~words[2*((words[4*j]>>1)&31)]<<16))&0xffffffff
  assert reference==immutable
  for phase in range(2):
   current=[int.from_bytes(bytes(self.u.mem_read(self.D+4*j,4)),'little')for j in range(128)];self.expected=current.copy();self.visits=self.reads=self.writes=0;self.selections=[];self.u.emu_start(START,END,count=120)
   actual=bytes(self.u.mem_read(self.D,512));assert actual==b''.join(v.to_bytes(4,'little')for v in reference)and self.expected==reference and self.visits==112 and self.reads==32 and self.writes==16
   assert self.u.reg_read(ar.UC_ARM64_REG_SP)==DATA+0x800 and self.u.reg_read(ar.UC_ARM64_REG_NZCV)==0xa0000000
   for j,v in enumerate(initial):
    if j not in (10,11):assert self.u.reg_read(getattr(ar,'UC_ARM64_REG_X'+str(j)))==v
   passes.append({'source_visits':self.visits,'read_events':self.reads,'write_events':self.writes,'selected_table_words':self.selections,'output_sha256':hashlib.sha256(actual).hexdigest()})
  return {'label':label,'alignment_offset_bytes':alignment,'input_sha256':hashlib.sha256(raw).hexdigest(),'forced_destination_selector':forced,'passes':passes,'idempotent':True,'all_checks_pass':True}
def main():
 machine=Isolated();rows=[]
 hashed=lambda seed:[int.from_bytes(hashlib.sha256(struct.pack('<II',seed,j)).digest()[:4],'little')for j in range(128)]
 for alignment in (0,4):
  for j in range(16):
   for selector in range(32):
    a=hashed(j*32+selector);a[4*j]=(a[4*j]&~0x3e)|(selector<<1);rows.append(machine.one('forced_pair',a,alignment,{'destination_index':j,'selector':selector}))
  for label,a in [('zeros',[0]*128),('ones',[0xffffffff]*128),('ascending',list(range(128))),('descending',list(range(127,-1,-1)))]:rows.append(machine.one(label,a,alignment))
  for seed in range(32):rows.append(machine.one('hash_pattern_'+str(seed),hashed(1000+seed),alignment))
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{'daemon_buffer_consumer_contracts.json':sha(ROOT/'daemon_buffer_consumer_contracts.json')},'source_sha256':sha(SOURCE),'cases':rows,'verified_counts':{'cases':len(rows),'source_passes':2*len(rows),'source_visits':224*len(rows),'read_events':64*len(rows),'write_events':32*len(rows),'forced_destination_selector_pairs':1024,'alignment_offsets':2},'native_target_executed':False,'all_checks_pass':True,'full_goal_complete':False};(ROOT/'daemon_buffer_normalization_replays.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out['verified_counts']),flush=True)
if __name__=='__main__':main()
