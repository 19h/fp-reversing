#!/usr/bin/env python3
"""Independent A64 check of callback-revisit source effects and unknown copies.
The original captured RAM is restored; physical variants preserve logical
origin aliases. Unknown bits remain unspecified, including copied values.
O(patterns*(snapshot+source visits+effects)) time, O(largest trace+RAM) space.
No native API, Mach/IOKit operation or pointer authentication executes.
"""
import json,zlib,base64,hashlib,struct
from pathlib import Path
from collections import Counter
import unicorn as uc
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,CS
from daemon_context_transfer_symbolic import P
from replay_daemon_context_transfer import evaluate,known

def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def raw(text):return zlib.decompress(base64.b64decode(text))
class Replay:
 def __init__(self,snapshot,trace,pattern):
  self.snap=snapshot;self.trace=trace;self.pattern=pattern;self.F=int(snapshot['frame_SP'],16);self.H=int(snapshot['arena_owner'],16);self.u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);self.u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);self.pages=set();self.backing={int(k):v for k,v in snapshot['inherited_unknown_backing'].items()};self.counts=Counter();self.index=0;self.previous=None;self.complete=False
  for region in snapshot['regions']:
   a=int(region['address'],16);b=raw(region['bytes_zlib_base64']);assert len(b)==region['size_bytes']and hashlib.sha256(b).hexdigest()==region['sha256'];self.u.mem_map(a,len(b),region['permissions']);self.u.mem_write(a,b);self.pages.update(range(a,a+len(b),4096))
  aliases={int(a,16):offset for a,offset in snapshot['unknown_stack_aliases'].items()}
  for owner in ['private_owner','heap_owner']:
   row=snapshot[owner];a=int(row['address'],16);mask=raw(row['known_mask_zlib_base64']);physical=bytearray(self.u.mem_read(a,row['size_bytes']))
   for j,k in enumerate(mask):
    if k:continue
    off=aliases.get(a+j,a+j-self.F)
    if off not in self.backing:self.backing[off]=physical[j]
    if pattern==1:self.backing[off]=0
    elif pattern==2:self.backing[off]=255
    elif pattern==3:self.backing[off]=(off*73+19)&255
    physical[j]=self.backing[off]
   self.u.mem_write(a,bytes(physical))
  for name,shape in snapshot['logical_registers'].items():self.u.reg_write(getattr(ar,'UC_ARM64_REG_'+name.upper()),int.from_bytes(evaluate(shape,self.backing),'little'))
  self.u.reg_write(ar.UC_ARM64_REG_NZCV,int(snapshot['NZCV'],16));self.u.hook_add(uc.UC_HOOK_CODE,self.code);self.u.hook_add(uc.UC_HOOK_MEM_READ,self.read);self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.write);self.u.hook_add(uc.UC_HOOK_MEM_UNMAPPED,self.unmapped)
 def page(self,a):
  from daemon_context_transfer_symbolic import loaded_bytes
  pg=a&~4095
  if pg in self.pages:return
  b=bytearray(loaded_bytes(pg,4096));self.u.mem_map(pg,4096);self.pages.add(pg)
  for at,r in FIXUPS.items():
   if pg<=at<pg+4096:b[at-pg:at-pg+8]=struct.pack('<Q',r['target']if isinstance(r['target'],int)else 0x7c100000)
  self.u.mem_write(pg,bytes(b))
 def unmapped(self,u,access,a,n,value,d):self.page(a);return True
 def register(self,name):return self.u.reg_read(getattr(ar,'UC_ARM64_REG_'+name.upper()))
 def finish(self):
  if self.previous is None:return
  row=self.previous;assert self.rcursor==len(self.reads)and self.wcursor==len(self.writes),(row['pc'],'memory event count')
  for name,shape in row['registers_after'].items():assert self.register(name)==int.from_bytes(evaluate(shape,self.backing),'little'),(row['pc'],name);self.counts['register_effects_checked']+=1
  if 'NZCV_after'in row:assert self.register('NZCV')&0xf0000000==row['NZCV_after'];self.counts['NZCV_effects_checked']+=1
  for e in row['events']:
   if e['kind']=='write':assert bytes(self.u.mem_read(int(e['address'],16),e['size_bytes']))==evaluate(e['value'],self.backing);self.counts['write_effects_checked']+=1;self.counts['unknown_copied_bytes_checked']+=known(e['value']).count(0)
  self.previous=None
 def code(self,u,a,n,d):
  self.finish()
  if self.index==len(self.trace['steps']):
   b=self.trace['boundary'];assert a==int(b['pc'],16)and self.register('SP')==int(b['SP'],16)
   for j,shape in enumerate(b['registers31']):assert self.register('X'+str(j))==int.from_bytes(evaluate(shape,self.backing),'little'),('boundary','X'+str(j))
   self.complete=True;return u.emu_stop()
  row=self.trace['steps'][self.index];assert a==int(row['pc'],16)and bytes(u.mem_read(a,4)).hex()==row['bytes_hex'],('source sequence',self.index,hex(a),row['pc']);self.index+=1;self.counts['source_visits']+=1;self.previous=row;self.reads=[];self.writes=[];self.rcursor=self.wcursor=0
  for e in row['events']:
   array=self.reads if e['kind']=='read'else self.writes;at=int(e['address'],16);array.extend((at+j,b)for j,b in enumerate(evaluate(e['value'],self.backing)))
  if row['mnemonic']=='pacibsp':
   assert 'return_auth_abstraction'in row;return u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  if row['mnemonic']in ['braa','blraa','retab','retaa']:
   target=int(row['target'],16)
   if row['mnemonic']in ['retab','retaa']:assert self.register('X30')==target
   else:
    i=next(CS.disasm(IMAGE.read(a,4),a));reg,modifier=[v.strip()for v in i.op_str.split(',',1)];assert self.register(reg)==target and self.register(modifier)==int(row['modifier16'],16)
   if row['mnemonic']=='blraa':self.u.reg_write(ar.UC_ARM64_REG_X30,a+4)
   self.page(target);return u.reg_write(ar.UC_ARM64_REG_PC,target)
 def read(self,u,access,a,n,value,d):
  actual=bytes(u.mem_read(a,n));assert self.reads[self.rcursor:self.rcursor+n]==[(a+j,b)for j,b in enumerate(actual)],('read',self.previous['pc'],hex(a),n);self.rcursor+=n;self.counts['read_bytes_checked']+=n
 def write(self,u,access,a,n,value,d):
  assert [at for at,b in self.writes[self.wcursor:self.wcursor+n]]==list(range(a,a+n)),('write',self.previous['pc'],hex(a),n);self.wcursor+=n;self.counts['write_bytes_checked']+=n
 def run(self):
  self.u.emu_start(int(self.snap['boundary']['pc'],16),0,count=len(self.trace['steps'])+10);assert self.complete and self.index==len(self.trace['steps']);return {'pattern':self.pattern,'verified_counts':dict(self.counts),'boundary':self.trace['boundary'],'all_checks_pass':True,'native_target_executed':False}
def main():
 snapshot=json.loads((ROOT/'daemon_callback_revisit_snapshot.json').read_text());profile=json.loads((ROOT/'daemon_callback_revisit_profiles.json').read_text());b=raw(profile['payload_zlib_base64']);assert hashlib.sha256(b).hexdigest()==profile['payload_sha256'];trace=json.loads(b);assert not trace['definitions'],'SSA-valued replay requires explicit concretization';rows=[]
 for pattern in range(4):row=Replay(snapshot,trace,pattern).run();rows.append(row);print(json.dumps({'pattern':pattern,'source_visits':row['verified_counts']['source_visits'],'all_checks_pass':True}),flush=True)
 deps=['daemon_callback_revisit_snapshot.json','daemon_callback_revisit_profiles.json','replay_daemon_context_transfer.py','daemon_receive_tools.py','daemon_receive_fixups.txt'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'cases':rows,'all_checks_pass':True,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_callback_revisit_replays.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'total_source_visits':sum(v['verified_counts']['source_visits']for v in rows)}),flush=True)
if __name__=='__main__':main()
