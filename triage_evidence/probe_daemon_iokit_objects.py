#!/usr/bin/env python3
"""Original discovery/open/query/object-release chain with explicit API summaries.

Entry is after nonnull matching-dictionary creation,not full daemon entry.
IOKit returns/output writes,task-self storage and PAC are explicit fixtures.
Stop before common cleanup's unknown pointer or selected error continuation.
O(B+C*(V+E+J*F)) time,O(B+C*(V+E)+F+4096J) space; no native API.
"""
import hashlib,json,itertools,struct
from pathlib import Path
from unicorn import arm64_const as ar
from probe_daemon_query_fallback import Fallback,cases as query_cases
from probe_daemon_query_state import STATE,GUARD
from probe_daemon_iokit_census import P,API
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,TABLE,POOL
from daemon_import_bindings import binding
ENTRY=0x1003f94ec;TASK=P+0xf100;DICT=P+0x3000
RANGES=[(ENTRY,0x1003f95c4),(0x10036c42c,0x10036c4d0),(0x100478af8,0x100478c5c),(0x1004a89f4,0x1004a8a1c),(0x100483c6c,0x100483cd4)]
IMPS={'IOKit/_IOServiceGetMatchingServices':0x7c007000,'IOKit/_IOIteratorNext':0x7c007100,'IOKit/_IOServiceOpen':0x7c007200,'IOKit/_IOObjectRelease':0x7c007300}
CALLS={0x1003f9594:('matching_services',0x1010a0d88,0xa027),0x10036c4a4:('iterator_next',0x1010a0e38,0xd62a),0x100478bb0:('service_open',0x1010a0b48,0xe82b),0x100478c2c:('service_release',0x1010a0240,0xbe7e),0x100483cc0:('iterator_release',0x1010a0240,0xbe7e)}
FRONTIERS={0x100318cc0:'before_matching_error_continuation',0x1004bdb24:'before_open_error_continuation',0x100383b00:'before_common_cleanup_unknown_pointer'}
class Objects(Fallback):
 def __init__(self,c):
  super().__init__(c);self.io_models=[];self.query_entry=None;self.io=c['IO'];self.initial=[e for e in self.initial if int(e['address'],16)!=P+0x4000];self.image_initial_fixtures=[e for e in self.image_initial_fixtures if int(e['address'],16)!=STATE+4];self.u.mem_write(STATE+4,IMAGE.read(STATE+4,4))
  for j,v in[(0,DICT),(19,0x101031ea0),(20,0x100fc4230),(21,0x101031fa0),(25,0x100fc4130),(27,POOL),(28,0xb606)]:self.set(j,v)
  for a,b in[(self.F+0x40,struct.pack('<QQ',0x100e99800,0x100f4e290)),(self.F+0x7c,struct.pack('<I',self.io['main_port'])),(TASK,struct.pack('<I',self.io['task_port']))]:self.fixture(a,b)
 def page(self,a):
  pg=a&~4095
  if pg in self.pages:return
  raw=bytearray(IMAGE.read(pg,4096));self.u.mem_map(pg,4096);self.pages.add(pg)
  for at,r in FIXUPS.items():
   if pg<=at<pg+4096:
    t=r['target'];v=TASK+0x7bf13863 if at==0x1010a39c8 else GUARD if t=='libSystem/___stack_chk_guard'else API if t=='IOKit/_IOConnectCallStructMethod'else IMPS[t]if t in IMPS else t if isinstance(t,int)else 0x7c100000;raw[at-pg:at-pg+8]=struct.pack('<Q',v)
  self.u.mem_write(pg,bytes(raw))
 def io_call(self,a):
  name,slot,div=CALLS[a];b=binding(slot);target=IMPS[FIXUPS[slot]['target']];assert self.reg(8)==target and self.reg(17)==div;writes=[];params=[self.reg(j)for j in range(8)]
  if name=='matching_services':
   assert params[:3]==[self.io['main_port'],DICT,self.F+0x68];result=self.io['matching_status']
   if result==0:writes=[(self.F+0x68,struct.pack('<I',self.io['iterator']))]
  elif name=='iterator_next':assert params[0]==self.io['iterator'];result=self.io['service']
  elif name=='service_open':
   assert params[:4]==[self.io['service'],self.io['task_port'],0,STATE+4];result=self.io['open_status']
   if result==0:writes=[(STATE+4,struct.pack('<I',0x5804))]
  elif name=='service_release':assert params[0]==self.io['service'];result=self.io['release_statuses'][0]
  else:assert params[0]==self.io['iterator'];result=self.io['release_statuses'][1]
  self.visit(a);out=[]
  for at,raw in writes:
   self.u.mem_write(at,raw)
   if P<=at<at+len(raw)<=P+0x10000:self.known[at-P:at-P+len(raw)]=b'\1'*len(raw);self.prov[at-P:at-P+len(raw)]=b'\2'*len(raw)
   out.append({'address':hex(at),'bytes_hex':raw.hex()})
  self.io_models.append({'pc':hex(a),'source_visit_index':self.seq-1,'name':name,'binding':b,'registers8':[hex(v)for v in params],'returned_u32':hex(result),'modeled_writes':out,'native_target_executed':False});self.set(0,result)
  for j in range(1,18):self.set(j,0xf000000000000000+j*0x1111)
  self.u.reg_write(ar.UC_ARM64_REG_NZCV,0xf0000000);self.set(30,a+4);self.u.reg_write(ar.UC_ARM64_REG_PC,a+4)
 def code(self,u,a,n,d):
  self.flush()
  if a in FRONTIERS:return self.stop_at(a,FRONTIERS[a])
  if a==0x100364398:self.query_entry={'pc':hex(a),'source_visit_index':self.seq,'registers31':[hex(self.reg(j))for j in range(31)],'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP))}
  if a in CALLS:return self.io_call(a)
  if not any(x<=a<a+4<=z for x,z in RANGES):return super().code(u,a,n,d)
  ins=next(self.dec.disasm(IMAGE.read(a,4),a));assert ins.mnemonic not in['bl','blr','blraa','br','ret','retab','svc','hvc','smc'];self.visit(a)
  if ins.mnemonic=='braa':
   target=self.reg(int(ins.op_str.split(',',1)[0][1:]));assert any(x<=target<z for x,z in RANGES)or target in FRONTIERS or target==0x100364398,(hex(a),hex(target));self.edges.append({'pc':hex(a),'source_visit_index':self.seq-1,'target':hex(target),'modifier16':hex(self.reg(17))});return u.reg_write(ar.UC_ARM64_REG_PC,target)
 def run(self):
  self.page(ENTRY);self.u.emu_start(ENTRY,0,count=5000);self.flush();assert self.reason in FRONTIERS.values()
  mask=bytearray(24);events=[]
  for row in self.image_initial_fixtures:
   a=int(row['address'],16)
   for j in range(a,a+len(bytes.fromhex(row['bytes_hex']))):
    if STATE<=j<STATE+24:mask[j-STATE]=3
  for m in self.io_models:
   for e in m['modeled_writes']:events.append((m['source_visit_index'],int(e['address'],16),len(bytes.fromhex(e['bytes_hex'])),2))
  for e in self.writes:events.append((e['source_visit_index'],int(e['address'],16),e['size_bytes'],1))
  for ix,a,n,p in sorted(events):
   for j in range(a,a+n):
    if STATE<=j<STATE+24:mask[j-STATE]=p
  return {'input':self.c,'frame_SP':hex(self.F),'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial_fixtures,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'IOKit_models':self.io_models,'source_edges':self.edges,'source_fixup_reads':self.fixups,'query_entry':self.query_entry,'preceding_query_boundary':self.query_boundary,'boundary':self.boundary,'helper_call':self.helper_call,'query_words':self.snapshot(self.F+0x64,12),'iterator_cell':self.snapshot(self.F+0x68,4),'connection_saved_pointer':self.snapshot(self.F+8,8),'returned_size':self.snapshot(self.F+0x70,8),'query_state_record':self.snapshot(self.record,20),'record_before_helper':self.record_before_call,'fallback_record':getattr(self,'fallback_record',None),'state_cache':{'address':hex(STATE),'size_bytes':24,'bytes_hex':bytes(self.u.mem_read(STATE,24)).hex(),'provenance_mask_hex':mask.hex()},'fallback_calls':self.fallback_calls,'fallback_input_record':self.fallback_input_record,'fallback_access_record':self.fallback_access_record,'cache_before_fallback':self.cache_before_fallback,'fallback_returned':self.fallback_returned,'state_before_final_marker':self.state_before_final_marker,'helper_returned':self.helper_returned,'native_target_executed':False,'native_port_identity_proved':False,'full_goal_complete':False}

def cases():
 base={'main_port':0x27,'task_port':0x103,'matching_status':0,'iterator':0x11223344,'service':0x1234,'open_status':0,'release_statuses':[0,0]}
 for case in query_cases():
  c=json.loads(json.dumps(case));c['IO']=dict(base);yield c
 q=next(query_cases())
 for match,service,opened,releases,placement in itertools.product([0,0xe00002c7],[0,0xe1234567],[0,1,0xe00002c7,0xffffffff],[[0,0],[0xe00002c7,0xe00002c7]],[0,0x100]):
  c=json.loads(json.dumps(q));c.update(placement=placement,object_case='discovery_status_and_width_control',IO={'main_port':0xf0000027,'task_port':0xf0000103,'matching_status':match,'iterator':0xf1234567,'service':service,'open_status':opened,'release_statuses':releases});yield c

 for released,placement in itertools.product([0,0xe00002c7],[0,0x100]):
  c=json.loads(json.dumps(q));c.update(placement=placement,object_case='success_with_null_iterator',IO={'main_port':0x27,'task_port':0x103,'matching_status':0,'iterator':0,'service':0,'open_status':0,'release_statuses':[0,released]});yield c

def main():
 rows=[]
 for j,c in enumerate(cases()):
  f=Objects(c);rows.append(f.run());del f
  if j%32==0:print(json.dumps({'cases_completed':j+1}),flush=True)
 sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['probe_daemon_query_fallback.py','probe_daemon_query_state.py','probe_daemon_iokit_census.py','daemon_receive_tools.py','daemon_import_bindings.py','daemon_receive_fixups.txt']},'source_sha256':sha(SOURCE),'cases':rows,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_iokit_objects_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(len(r['source_visits'])for r in rows)}),flush=True)
if __name__=='__main__':main()
