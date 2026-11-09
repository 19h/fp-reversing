#!/usr/bin/env python3
"""Independent isolated A64 execution of the complete 411-instruction window block.
Source code/data and abstract original fixups; declared scalar inputs only.
O(cases*411+image pages) time, O(mapped pages+case outputs) space. No native API/PAC.
"""
import hashlib,json,struct
from pathlib import Path
import unicorn as uc
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,POOL
from daemon_context_transfer_symbolic import loaded_bytes
START=0x1003f1390;END=0x1003f19fc;F=0x6a00004000;M=(1<<64)-1
KD=0xe2c06c277e3e38;KOFF=0x34936dc72afd2f98;KA=0x12af5504870a589f;KM=0xfff0c012a7a730ec

def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def compact(S,P,Q):
 v=(S-16)&M;n=v.bit_length()-1;k=min(n,15);L=1<<(k&63);delta=(1<<n)-32768 if n>=15 else 0;r=(Q&((v-L)&M))&~0xfff;address=(P+r)&M
 return {'v':v,'floor_log2':n,'window_length':L,'span_delta':delta,'offset':r,'address':address,'encoded_span':(delta+KD)&M,'encoded_offset':r^KOFF,'encoded_address':address^KA,'encoded_mask':(L-1)^KM,'containment_applicable':S>16 and P+S<=M,'containment':None if not(S>16 and P+S<=M)else P<=address and address+L<=P+S-16}
class Isolated:
 def __init__(self):
  self.u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);self.pages=set();self.u.mem_map(F,4096);self.pages.add(F);self.used_fixups=set();self.u.hook_add(uc.UC_HOOK_MEM_UNMAPPED,self.unmapped);self.u.hook_add(uc.UC_HOOK_CODE,self.code);self.u.hook_add(uc.UC_HOOK_MEM_READ,self.read);self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.write)
  for a in [START,0x1010c6800,0x1010ca2a8,0x1010b70d8,0x1010b83a0,0x1010b7dd8,0x1010c4670]:self.page(a)
 def page(self,a):
  pg=a&~4095
  if pg in self.pages:return
  raw=bytearray(loaded_bytes(pg,4096));self.u.mem_map(pg,4096);self.pages.add(pg)
  for address,rec in FIXUPS.items():
   if pg<=address<pg+4096:raw[address-pg:address-pg+8]=struct.pack('<Q',rec['target']if isinstance(rec['target'],int)else 0x7c100000)
  self.u.mem_write(pg,bytes(raw))
 def unmapped(self,u,access,a,n,value,d):self.page(a);return True
 def code(self,u,a,n,d):
  assert START<=a<END and bytes(u.mem_read(a,4))==IMAGE.read(a,4);self.visits+=1
 def read(self,u,access,a,n,value,d):
  self.reads+=1
  if n==8 and a in FIXUPS:self.used_fixups.add(a)
 def write(self,u,access,a,n,value,d):
  pc=u.reg_read(ar.UC_ARM64_REG_PC);assert (pc,a,n)in [(0x1003f1850,0x1010b70d8,8),(0x1003f18f8,0x1010b83a0,8),(0x1003f19dc,0x1010ca2a8,8),(0x1003f19f8,0x1010c6800,8)];self.writes.append({'pc':hex(pc),'address':hex(a),'size_bytes':n,'value':hex(value&M)})
 def one(self,S,P,Q,case_id):
  for j in range(31):self.u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(j)),(case_id*(j+1)*0x123456789ab)&M)
  self.u.reg_write(ar.UC_ARM64_REG_SP,F);self.u.reg_write(ar.UC_ARM64_REG_X9,0x8a9b8560);self.u.reg_write(ar.UC_ARM64_REG_X27,POOL)
  for address,value in [(0x1010c6800,S),(0x1010ca2a8,P),(0x1010b7dd8,case_id*0x12345678&M),(0x1010c4670,(case_id*0x12345678^0xabcdef01)&M),(F+0x390,0x1010b7dd8),(F+0x398,0x1010c4670),(F+0x350,0x100e99700),(F+0x348,0x100f4e190),(F+0x1f8,0x101031da0),(F+0x208,0x100e99900),(F+0x358,Q)]:self.u.mem_write(address,value.to_bytes(8,'little'))
  self.visits=self.reads=0;self.writes=[];self.u.emu_start(START,END,count=420);assert self.visits==411 and len(self.writes)==4 and self.u.reg_read(ar.UC_ARM64_REG_SP)==F
  expected=compact(S,P,Q);fields={0x1010b70d8:'encoded_span',0x1010b83a0:'encoded_offset',0x1010ca2a8:'encoded_address',0x1010c6800:'encoded_mask'}
  for address,key in fields.items():assert int.from_bytes(bytes(self.u.mem_read(address,8)),'little')==expected[key],(case_id,key)
  if expected['containment_applicable']:assert expected['containment']
  return {'inputs':{'S':hex(S),'P':hex(P),'Q':hex(Q)},'expected':{k:hex(v)if isinstance(v,int)and not isinstance(v,bool)and k!='floor_log2'else v for k,v in expected.items()},'source_visits':self.visits,'read_events':self.reads,'writes':self.writes,'all_checks_pass':True}
def main():
 size_set=set(range(19))|{0xe297a8,M}
 for j in range(64):
  for d in [15,16,17]:
   s=(1<<j)+d
   if s<=M:size_set.add(s)
 jobs=[]
 for S in sorted(size_set):
  for P in [0x100001058,(M-S)&M]:
   for Q in [0,M,int.from_bytes(hashlib.sha256(struct.pack('<QQ',S,P)).digest()[:8],'little')]:jobs.append((S,P,Q,'size_boundary'))
 mask=0xe21000;bits=[j for j in range(64)if mask>>j&1]
 for i in range(32):
  offset=sum(((i>>k)&1)<<b for k,b in enumerate(bits))
  for upper in [0,0xffffffff]:jobs.append((0xe297a8,0x100001058,offset|(upper<<32),'current_image_offset'))
 for j in range(64):jobs.append((0xe297a8,0x100001058,1<<j,'selection_bit'))
 for j in range(64):jobs.append((0xe297a8,0x100001058,int.from_bytes(hashlib.sha256(struct.pack('<Q',j)).digest()[:8],'little'),'hash_selection'))
 machine=Isolated();rows=[]
 for j,(S,P,Q,label)in enumerate(jobs):row=machine.one(S,P,Q,j);row['class']=label;rows.append(row)
 deps=['daemon_global_state_contracts.json','daemon_receive_tools.py','daemon_receive_fixups.txt'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'cases':rows,'used_fixups':[hex(a)for a in sorted(machine.used_fixups)],'verified_counts':{'cases':len(rows),'source_visits':411*len(rows),'source_read_events':sum(r['read_events']for r in rows),'source_write_events':4*len(rows),'distinct_size_inputs':len(size_set),'current_image_offsets':32,'upper_word_variants_per_offset':2},'all_checks_pass':True,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_global_state_replays.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out['verified_counts']),flush=True)
if __name__=='__main__':main()
