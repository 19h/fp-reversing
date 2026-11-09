#!/usr/bin/env python3
"""Full selected IOKit error continuations and isolated common status adapter.
External calls retain frozen explicit summaries; all status-adapter instructions
execute from original bytes. No native target/API/Mach/PAC operation executes.
O(B+C*(V+E+JF)) time,O(B+C*(V+E)+F+4096J) space.
"""
import hashlib,json,struct,itertools,random
from pathlib import Path
from unicorn import arm64_const as ar
from probe_daemon_iokit_sync import Sync,cases as sync_cases,P,PRIMARY,FALLBACK,OUTER_RETURN
from daemon_receive_tools import ROOT,SOURCE,IMAGE
STATUS=0x100422a60;STOP=P+0xf500
RANGES=[(0x10062fb74,0x10062fc80),(0x100318cc0,0x100318db8),(0x1004bdb24,0x1004bdc78),(STATUS,0x100422bcc),(0x10011959c,0x100119638),(0x1002cb160,0x1002cb250),(0x1001ddc64,0x1001ddd18),(0x100202e14,0x100202eb4),(0x1000d44ac,0x1000d4558),(0x10003b414,0x10003b4ac),(0x10004e43c,0x10004e450),(0x10013b168,0x10013b178)]
CALLS={0x10062fc68:'main_port',0x100318d98:'matching_services',0x1004bdc5c:'service_open'}
class Errors(Sync):
 def __init__(self,c):
  self.status_calls=[];self.status_returns=[];super().__init__(c)
 def write(self,u,access,a,n,v,d):
  if a==0x1010c52d8 and n==8:
   e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':self.seq-1,'address':hex(a),'size_bytes':n};self.writes.append(e);self.pending.append(e);return
  return super().write(u,access,a,n,v,d)
 def code(self,u,a,n,d):
  self.flush()
  if a==STOP:return self.stop_at(a,'before_isolated_status_caller')
  if a in {p+4 for p in CALLS}:
   self.status_returns.append({'pc':hex(a),'source_visit_index':self.seq,'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'result':self.snapshot(self.F+0x60,4)})
  if a in CALLS:
   assert self.reg(8)==STATUS and self.reg(17)==0xd3f1 and self.reg(0)==self.F+0xa8;self.status_calls.append({'pc':hex(a),'source_visit_index':self.seq,'origin':CALLS[a],'target':hex(STATUS),'modifier16':'0xd3f1','record':self.snapshot(self.reg(0),16),'registers8':[hex(self.reg(j))for j in range(8)],'caller_SP':hex(u.reg_read(ar.UC_ARM64_REG_SP))});self.visit(a);self.set(30,a+4);return u.reg_write(ar.UC_ARM64_REG_PC,STATUS)
  if not any(x<=a<a+4<=z for x,z in RANGES):return super().code(u,a,n,d)
  i=next(self.dec.disasm(IMAGE.read(a,4),a));m=i.mnemonic;assert m not in ['bl','blr','blraa','br','svc','hvc','smc'];self.visit(a)
  if m=='braa':
   t=self.reg(int(i.op_str.split(',',1)[0][1:]));assert any(x<=t<z for x,z in RANGES)or t in [0x100383b00,0x100483c6c],(hex(a),hex(t));self.edges.append({'pc':hex(a),'source_visit_index':self.seq-1,'target':hex(t),'modifier16':hex(self.reg(17))});return u.reg_write(ar.UC_ARM64_REG_PC,t)
  if m in ['ret','retab','retaa']:return u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30))
 def run(self):
  r=super().run();assert r['outer_returned'];r.update(status_calls=self.status_calls,status_returns=self.status_returns,isolated=False);return r
class Isolated(Errors):
 def __init__(self,c):
  super().__init__(c);self.R=P+0x4000+c['placement'];self.O=P+0x6000+c['placement'];r=self.R&0xffffffff;k=((r^0x8515cfbd)*0xc7f6dca7)&0xffffffff;s=c['isolated_status'];self.fixture(self.R,struct.pack('<QII',self.O,((s^0x8b3dc651)-k)&0xffffffff,(0x952a+k)&0xffffffff));self.fixture(STOP,bytes.fromhex('1f2003d5'));self.set(0,self.R);self.set(30,STOP);self.u.reg_write(ar.UC_ARM64_REG_SP,self.F);self.status_entry_registers=[self.reg(j)for j in range(31)]
 def run(self):
  self.page(STATUS);self.u.emu_start(STATUS,0,count=3000);self.flush();assert self.reason=='before_isolated_status_caller';r=self.base_report();r.update(status_calls=[],status_returns=[],sync_models=self.sync_models,internal_calls=self.internal_calls,class_entry=self.class_entry,isolated=True,status_entry_registers31=[hex(x)for x in self.status_entry_registers],status_entry_SP=hex(self.F),status_input_record=self.snapshot(self.R,16),status_output_word=self.snapshot(self.O,4),saved_primary_cell_pointer=self.snapshot(self.F+0x50,8),outer_result_word=self.snapshot(self.F+0x60,4),outer_input_record=self.snapshot(P+0x2000,8));return r
def expected(s):
 signed=s if s<0x80000000 else s-(1<<32)
 return ((s+0x67)^0x74c29fae)&0xffffffff if 1<=signed<=99 else s^0x8b3dc651 if -49998<=signed<=-42001 else 0x74c29fc9
BOUNDARIES=sorted({s&0xffffffff for s in [1,2,98,99,100,101,254,255,256,257,0x7fffffff,0x80000000,-1,-2,-41999,-42000,-42001,-42002,-49997,-49998,-49999,-50000]})
def composed_cases():
 cs=list(sync_cases());prior=json.loads((ROOT/'daemon_iokit_sync_profiles.json').read_text())['cases']
 keep={0,4,632,636,*range(664,684)}|{j for j,r in enumerate(prior)if not r['outer_returned']}
 for j in sorted(keep):
  c=json.loads(json.dumps(cs[j]));c['prior_sync_index']=j;yield c
 base=cs[0]
 for origin,s,placement in itertools.product(['main_port','matching_services','service_open'],BOUNDARIES,[0,0x100]):
  c=json.loads(json.dumps(base));c.update(placement=placement,status_case={'origin':origin,'status_u32':s});c['sync']['once_completed']=bool(placement)
  if origin=='main_port':c['prefix']['main_status']=s
  elif origin=='matching_services':c['IO']['matching_status']=s
  else:c['IO']['open_status']=s
  yield c
def isolated_cases():
 rng=random.Random(0x422a60);values=sorted({0,*range(1,100),*BOUNDARIES,*[rng.getrandbits(32)for _ in range(256)]});base=next(sync_cases())
 for s,placement in itertools.product(values,[0,0x100]):
  c=json.loads(json.dumps(base));c.update(placement=placement,isolated_status=s);yield c
def main():
 groups={}
 for name,source,cls in [('composed',composed_cases(),Errors),('isolated',isolated_cases(),Isolated)]:
  rows=[]
  for j,c in enumerate(source):
   f=cls(c);r=f.run();rows.append(r);del f
   if j%32==0:print(json.dumps({'group':name,'cases_completed':j+1}),flush=True)
  groups[name+'_cases']=rows
 sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in ['probe_daemon_iokit_sync.py','daemon_iokit_sync_profiles.json','probe_daemon_iokit_class.py','probe_daemon_iokit_objects.py','probe_daemon_query_fallback.py','probe_daemon_query_state.py','probe_daemon_iokit_census.py','daemon_receive_tools.py','daemon_import_bindings.py','daemon_receive_fixups.txt']},'source_sha256':sha(SOURCE),**groups,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_iokit_errors_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({k:{'cases':len(v),'visits':sum(len(r['source_visits'])for r in v)}for k,v in groups.items()}),flush=True)
if __name__=='__main__':main()
