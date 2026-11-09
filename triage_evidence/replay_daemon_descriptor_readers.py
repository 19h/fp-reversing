#!/usr/bin/env python3
"""Independent fresh Unicorn replay of staged descriptor-reader compositions.
Original bytes, actual reads/writes, selected logical edges and API arguments
are compared. Fixture PC transitions and imported API effects remain explicit.
O(C*(J*F+V+E)) time for C cases,J pages,F fixups,V visits,E effects;
O(F+largest run+mapped RAM) space.
"""
import json,hashlib,struct
from pathlib import Path
from collections import Counter,defaultdict
import unicorn as uc
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,CS
from daemon_import_bindings import binding
from probe_daemon_iokit_class import P,TASK,GUARD,API,IMPS,NEW_IMPS

SYNC={'libSystem/_pthread_once':0x7c007600,'libSystem/_pthread_rwlock_wrlock':0x7c007700,'libSystem/_pthread_rwlock_unlock':0x7c007800}
APIS={0x10043e508:('acquire_once',0x10109fe80,0x8489),0x100442650:('cleanup_once',0x10109fe80,0x8489),0x100361df4:('write_lock',0x1010a0a00,0x4c4d),0x100208efc:('unlock',0x1010a0d78,0x5431)}
INTERNAL={0x10021ee18:(0x10043e280,0x6aa4),0x10025c570:(0x1004423f8,0x6aa4),0x10040ee2c:(0x10044fc34,0x5c15)}
def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
class Replay:
 def __init__(self,r):
  self.r=r;self.u=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);self.u.ctl_set_cpu_model(ar.UC_CPU_ARM64_MAX);self.pages=set();self.index=0;self.counts=Counter();self.pending=[];self.callback=None;self.effects={(int(e['pc'],16),e['after_source_visits']):e for e in r['primitive_effects']};self.reads=defaultdict(list);self.writes=defaultdict(list);self.rc=self.wc=0;self.current=None
  for k,key in [('source_reads',self.reads),('source_writes',self.writes)]:
   for e in r[k]:key[e['source_visit_index']].append(e)
  self.models={m['source_visit_index']:m for m in r['sync_models']};self.edges={m['source_visit_index']:m for m in r['source_edges']};self.u.mem_map(P,65536);self.u.mem_write(P,b'\xa5'*65536)
  for row in r['initial_private_fixtures']+r['initial_image_fixtures']:
   a=int(row['address'],16);b=bytes.fromhex(row['bytes_hex']);self.ensure(a,len(b));self.u.mem_write(a,b)
  self.seed(r['root_entry_registers31']);self.u.reg_write(ar.UC_ARM64_REG_SP,int(r['caller_SP'],16));self.u.reg_write(ar.UC_ARM64_REG_NZCV,int(r['root_entry_NZCV'],16))
  self.u.hook_add(uc.UC_HOOK_MEM_UNMAPPED,self.missing);self.u.hook_add(uc.UC_HOOK_MEM_READ,self.read);self.u.hook_add(uc.UC_HOOK_MEM_WRITE,self.write);self.u.hook_add(uc.UC_HOOK_CODE,self.code)
 def reg(self,j):return self.u.reg_read(getattr(ar,'UC_ARM64_REG_X'+str(j)))
 def seed(self,values):
  for j,v in enumerate(values):self.u.reg_write(getattr(ar,'UC_ARM64_REG_X'+str(j)),int(v,16))
 def ensure(self,a,n=1):
  for pg in range(a&~4095,((a+n-1)&~4095)+4096,4096):
   if P<=pg<P+65536 or pg in self.pages:continue
   assert 0x100000000<=pg<0x102000000,hex(pg)
   b=bytearray(b'\xa5'*4096)if pg==0x1010c8000 else bytearray(IMAGE.read(pg,4096))
   for at,e in FIXUPS.items():
    if pg<=at<pg+4096:
     t=e['target'];v=TASK+0x7bf13863 if at==0x1010a39c8 else GUARD if t=='libSystem/___stack_chk_guard'else API if t=='IOKit/_IOConnectCallStructMethod'else SYNC[t]if t in SYNC else NEW_IMPS[t]if t in NEW_IMPS else IMPS[t]if t in IMPS else t if isinstance(t,int)else 0x7c100000;b[at-pg:at-pg+8]=struct.pack('<Q',v)
   self.u.mem_map(pg,4096);self.pages.add(pg);self.u.mem_write(pg,bytes(b))
 def missing(self,u,t,a,n,v,d):self.ensure(a,n);return True
 def finish(self):
  for e in self.pending:assert bytes(self.u.mem_read(int(e['address'],16),e['size_bytes'])).hex()==e['after_hex'];self.counts['source_writes_checked']+=1
  self.pending=[]
  if self.current is not None:assert self.rc==len(self.reads[self.current])and self.wc==len(self.writes[self.current]),(self.current,self.rc,self.wc)
  self.current=None
 def read(self,u,t,a,n,v,d):
  rows=self.reads[self.current];assert self.rc<len(rows),(self.current,hex(a),n);e=rows[self.rc];self.rc+=1;assert(e['address'],e['size_bytes'],e['bytes_hex'])==(hex(a),n,bytes(u.mem_read(a,n)).hex());self.counts['source_reads_checked']+=1
 def write(self,u,t,a,n,v,d):
  rows=self.writes[self.current];assert self.wc<len(rows);e=rows[self.wc];self.wc+=1;assert(e['address'],e['size_bytes'])==(hex(a),n);self.pending.append(e)
 def effect(self,pc):
  e=self.effects[(pc,self.index)];self.seed(e['registers0_17']);self.u.reg_write(ar.UC_ARM64_REG_NZCV,int(e['NZCV_after'],16));self.u.reg_write(ar.UC_ARM64_REG_X30,pc+4);self.u.reg_write(ar.UC_ARM64_REG_PC,pc+4);self.counts['declared_API_returns_checked']+=1
 def code(self,u,a,n,d):
  self.finish()
  if self.callback is not None and a==P+0xf200:
   m,sp,saved=self.callback;assert u.reg_read(ar.UC_ARM64_REG_SP)==sp-256 and[self.reg(j)for j in range(19,30)]==saved and self.index==m['callback_source_visit_end'];self.callback=None;u.reg_write(ar.UC_ARM64_REG_SP,sp);return self.effect(int(m['pc'],16))
  for j,row in enumerate(self.r['root_registers']):
   if self.index==row['source_visit_index']and a==int(row['after'],16):
    assert[hex(self.reg(k))for k in range(31)]==row['registers31'];tr=self.r['staged_source_transitions'][j];assert tr['fixture_transition_not_original_branch'];self.counts['fixture_PC_transitions']+=1
    if j==1:self.seed(self.r['reader_entry_registers31']);u.reg_write(ar.UC_ARM64_REG_NZCV,int(self.r['reader_entry_NZCV'],16));u.reg_write(ar.UC_ARM64_REG_SP,int(self.r['caller_SP'],16))
    return u.reg_write(ar.UC_ARM64_REG_PC,int(tr['to_PC'],16))
  if self.index==len(self.r['source_visits']):
   b=self.r['boundary'];assert hex(a)==b['pc']and hex(u.reg_read(ar.UC_ARM64_REG_SP))==b['SP']and[hex(self.reg(j))for j in range(31)]==b['registers31'];self.counts['final_boundaries_checked']+=1;return u.emu_stop()
  row=self.r['source_visits'][self.index];assert row['source_visit_index']==self.index and row['pc']==hex(a);b=IMAGE.read(a,4);assert b.hex()==row['bytes_hex']and bytes(u.mem_read(a,4))==b;ins=next(CS.disasm(b,a));self.current=self.index;self.rc=self.wc=0;self.index+=1;self.counts['source_visits']+=1
  if a in APIS:
   m=self.models[self.current];name,slot,div=APIS[a];assert m['name']==name and m['binding']==binding(slot)and self.reg(8)==SYNC[FIXUPS[slot]['target']]and self.reg(17)==div and [hex(self.reg(j))for j in range(8)]==m['registers8'];self.counts['modeled_API_calls_checked']+=1
   if m.get('callback_invoked'):
    sp=u.reg_read(ar.UC_ARM64_REG_SP);assert int(m['callback_entry_SP'],16)==sp-256;self.callback=(m,sp,[self.reg(j)for j in range(19,30)]);u.reg_write(ar.UC_ARM64_REG_SP,sp-256);u.reg_write(ar.UC_ARM64_REG_X30,P+0xf200);return u.reg_write(ar.UC_ARM64_REG_PC,0x10040ebd4)
   return self.effect(a)
  if a in INTERNAL:
   target,modifier=INTERNAL[a];assert self.reg(8)==target and self.reg(17)==modifier;u.reg_write(ar.UC_ARM64_REG_X30,a+4);self.counts['logical_internal_calls_checked']+=1;return u.reg_write(ar.UC_ARM64_REG_PC,target)
  if ins.mnemonic=='braa':
   args=[x.strip()for x in ins.op_str.split(',')];target=self.reg(int(args[0][1:]));modifier=self.reg(int(args[1][1:]));e=self.edges[self.current];assert e['pc']==hex(a)and e['target']==hex(target)and int(e['modifier16'],16)==modifier;self.counts['logical_branches_checked']+=1;return u.reg_write(ar.UC_ARM64_REG_PC,target)
  if ins.mnemonic in ['ret','retab','retaa']:self.counts['logical_returns_checked']+=1;return u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30))
  if ins.mnemonic in ['pacibsp','paciasp','autibsp','autiasp','paciza']:self.counts['logical_PAC_instructions']+=1;return u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  assert ins.mnemonic not in ['bl','blr','blraa','br','svc','hvc','smc'],(hex(a),ins.mnemonic)
 def run(self):
  start=int(self.r['source_visits'][0]['pc'],16);self.ensure(start);self.u.emu_start(start,0,count=20000);self.finish();assert self.index==len(self.r['source_visits'])and self.callback is None and self.counts['final_boundaries_checked']==1
  return {'configuration':self.r['configuration'],'boundary':self.r['boundary']['pc'],'verified_counts':dict(self.counts),'all_checks_pass':True}
def main():
 p=json.loads((ROOT/'daemon_descriptor_readers_profiles.json').read_text());rows=[];totals=Counter()
 for j,r in enumerate(p['cases']):
  out=Replay(r).run();rows.append(out);totals.update(out['verified_counts'])
  if j%24==0:print(json.dumps({'replays_completed':j+1}),flush=True)
 deps=['daemon_descriptor_readers_profiles.json','daemon_receive_tools.py','daemon_import_bindings.py','probe_daemon_iokit_class.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'cases':rows,'verified_totals':dict(totals),'all_checks_pass':True,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_descriptor_readers_replays.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'totals':dict(totals)}),flush=True)
if __name__=='__main__':main()
