#!/usr/bin/env python3
"""Full selected daemon entry through acquisition,I/O and returning cleanup.

BSS primary/fallback pointer values,once state and callback stack placement are
explicit private fixtures. Source callback executes when the model invokes it;
no native synchronization,IOKit,Mach or PAC operation executes.
O(B+C*(V+E+J*F)) time,O(B+C*(V+E)+F+4096J) space.
"""
import hashlib,json,struct,itertools
from pathlib import Path
from unicorn import arm64_const as ar
from probe_daemon_iokit_class import Matching,cases as class_cases,NAME,P,TASK,GUARD,API,IMPS,NEW_IMPS,STATE,DICT
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS
from daemon_import_bindings import binding
ENTRY=0x1004601d0;PRIMARY=0x1010c8240;FALLBACK=0x1010b9638;ONCE=0x1010b8cd0;CALLBACK=0x10040ebd4;OBJ=P+0x2000;OUTER_RETURN=P+0xf300;CALLBACK_RETURN=P+0xf200
SYNC_IMPS={'libSystem/_pthread_once':0x7c007600,'libSystem/_pthread_rwlock_wrlock':0x7c007700,'libSystem/_pthread_rwlock_unlock':0x7c007800}
RANGES=[(ENTRY,0x100460428),(0x1003ccf9c,0x1003cd0d8),(0x10043e280,0x10043e574),(0x1001e2d28,0x1001e2da0),(0x100361db4,0x100361e2c),(0x1000d3738,0x1000d3758),(CALLBACK,0x10040ee54),(0x10044fc34,0x10044fc38),(0x100383b00,0x100383bb4),(0x1004423f8,0x100442688),(0x100309d18,0x100309da8),(0x100208e90,0x100208f0c),(0x1002a78b8,0x1002a78d8),(0x100336fcc,0x100337008)]
INTERNAL={0x1003cd07c:(0x10043e280,0x6aa4,'acquire_adapter'),0x100383ba0:(0x1004423f8,0x6aa4,'cleanup_adapter'),0x10040ee2c:(0x10044fc34,0x5c15,'callback_leaf_RET')}
PRIMITIVES={0x10043e508:('acquire_once',0x10109fe80,0x8489),0x100442650:('cleanup_once',0x10109fe80,0x8489),0x100361df4:('write_lock',0x1010a0a00,0x4c4d),0x100208efc:('unlock',0x1010a0d78,0x5431)}
class Sync(Matching):
 def __init__(self,c):
  self.bss_known=bytearray(4096);self.sync_models=[];self.internal_calls=[];self.callback_pending=None;self.class_entry=None
  super().__init__(c);self.completed_once={ONCE}if c['sync']['once_completed']else set()
  rows=[e for e in self.initial if self.F<=int(e['address'],16)<self.F+0x130];self.initial=[e for e in self.initial if e not in rows]
  for e in rows:
   a=int(e['address'],16);n=len(bytes.fromhex(e['bytes_hex']));self.u.mem_write(a,b'\xa5'*n);self.known[a-P:a-P+n]=bytes(n);self.prov[a-P:a-P+n]=bytes(n)
  self.page(PRIMARY)
  for a,v in[(PRIMARY,c['sync']['primary']),(FALLBACK,c['sync']['fallback'])]:
   self.page(a);b=struct.pack('<Q',v);self.u.mem_write(a,b);self.image_initial_fixtures.append({'address':hex(a),'bytes_hex':b.hex(),'provenance':3})
   if a==PRIMARY:self.bss_known[a-(a&~4095):a-(a&~4095)+8]=b'\1'*8
  key=(((OBJ&0xffffffff)^0x966e5812)*0x592e2f77)&0xffffffff;self.fixture(OBJ,struct.pack('<I',(0x5784+key)&0xffffffff));self.fixture(OUTER_RETURN,bytes.fromhex('1f2003d5'));self.fixture(CALLBACK_RETURN,bytes.fromhex('1f2003d5'))
  self.set(0,OBJ);self.set(30,OUTER_RETURN);self.u.reg_write(ar.UC_ARM64_REG_SP,self.F+0x130);self.entry_registers=[self.reg(j)for j in range(31)];self.entry_SP=self.F+0x130
 def page(self,a):
  pg=a&~4095
  if pg in self.pages:return
  raw=bytearray(b'\xa5'*4096)if pg==PRIMARY&~4095 else bytearray(IMAGE.read(pg,4096));self.u.mem_map(pg,4096);self.pages.add(pg)
  for at,r in FIXUPS.items():
   if pg<=at<pg+4096:
    t=r['target'];v=TASK+0x7bf13863 if at==0x1010a39c8 else GUARD if t=='libSystem/___stack_chk_guard'else API if t=='IOKit/_IOConnectCallStructMethod'else SYNC_IMPS[t]if t in SYNC_IMPS else NEW_IMPS[t]if t in NEW_IMPS else IMPS[t]if t in IMPS else t if isinstance(t,int)else 0x7c100000;raw[at-pg:at-pg+8]=struct.pack('<Q',v)
  self.u.mem_write(pg,bytes(raw))
 def read(self,u,access,a,n,value,d):
  if PRIMARY&~4095<=a<a+n<=(PRIMARY&~4095)+4096:assert all(self.bss_known[a-(PRIMARY&~4095):a-(PRIMARY&~4095)+n]),('unknown BSS read',hex(a),n)
  return super().read(u,access,a,n,value,d)
 def write(self,u,access,a,n,v,d):
  if any(a==x and n==8 for x in[0x1010b8e48,0x1010b66a8,0x1010b6738,0x1010c5088]):
   e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':self.seq-1,'address':hex(a),'size_bytes':n};self.writes.append(e);self.pending.append(e);return
  return super().write(u,access,a,n,v,d)
 def primitive_return(self,u,pc):
  self.set(0,0)
  for j in range(1,18):self.set(j,0xf000000000000000+j*0x1111)
  u.reg_write(ar.UC_ARM64_REG_NZCV,0xf0000000);self.set(30,pc+4);u.reg_write(ar.UC_ARM64_REG_PC,pc+4)
 def primitive(self,u,a):
  name,slot,div=PRIMITIVES[a];assert self.reg(8)==SYNC_IMPS[FIXUPS[slot]['target']]and self.reg(17)==div;params=[self.reg(j)for j in range(8)];row={'pc':hex(a),'source_visit_index':self.seq,'name':name,'binding':binding(slot),'registers8':[hex(x)for x in params],'caller_SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'returned_u32':'0x0','modeled_writes':[],'native_target_executed':False};self.visit(a);self.sync_models.append(row)
  if name.endswith('once'):
   assert params[:2]==[ONCE,CALLBACK];row['callback_invoked']=ONCE not in self.completed_once
   if row['callback_invoked']:
    assert self.callback_pending is None;self.callback_pending={'model':row,'return_pc':a,'SP':u.reg_read(ar.UC_ARM64_REG_SP),'callee_saved':[self.reg(j)for j in range(19,30)]};row['callback_entry_SP']=hex(u.reg_read(ar.UC_ARM64_REG_SP)-0x100);row['callback_source_visit_begin']=self.seq;u.reg_write(ar.UC_ARM64_REG_SP,u.reg_read(ar.UC_ARM64_REG_SP)-0x100);self.set(30,CALLBACK_RETURN);return u.reg_write(ar.UC_ARM64_REG_PC,CALLBACK)
  return self.primitive_return(u,a)
 def code(self,u,a,n,d):
  self.flush()
  if a==CALLBACK_RETURN:
   p=self.callback_pending;assert p and u.reg_read(ar.UC_ARM64_REG_SP)==p['SP']-0x100 and[self.reg(j)for j in range(19,30)]==p['callee_saved'];p['model']['callback_source_visit_end']=self.seq;self.completed_once.add(ONCE);self.callback_pending=None;u.reg_write(ar.UC_ARM64_REG_SP,p['SP']);return self.primitive_return(u,p['return_pc'])
  if a==OUTER_RETURN:return self.stop_at(a,'before_external_caller_after_outer_return')
  if a==0x100461c30:self.class_entry={'pc':hex(a),'source_visit_index':self.seq}
  if a in PRIMITIVES:return self.primitive(u,a)
  if a in INTERNAL:
   target,div,name=INTERNAL[a];assert self.reg(8)==target and self.reg(17)==div;self.internal_calls.append({'pc':hex(a),'source_visit_index':self.seq,'name':name,'target':hex(target),'registers8':[hex(self.reg(j))for j in range(8)],'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP))});self.visit(a);self.set(30,a+4);return u.reg_write(ar.UC_ARM64_REG_PC,target)
  if not any(x<=a<a+4<=z for x,z in RANGES):return super().code(u,a,n,d)
  ins=next(self.dec.disasm(IMAGE.read(a,4),a));m=ins.mnemonic;assert m not in['bl','blr','blraa','br','svc','hvc','smc'];self.visit(a)
  if m=='braa':
   t=self.reg(int(ins.op_str.split(',',1)[0][1:]));assert any(x<=t<z for x,z in RANGES)or t==0x100461c30,(hex(a),hex(t));self.edges.append({'pc':hex(a),'source_visit_index':self.seq-1,'target':hex(t),'modifier16':hex(self.reg(17))});return u.reg_write(ar.UC_ARM64_REG_PC,t)
  if m in['pacibsp','paciasp','autibsp','autiasp','paciza']:return u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  if m in['ret','retab','retaa']:return u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30))
 def run(self):
  self.page(ENTRY);self.u.emu_start(ENTRY,0,count=8000);self.flush();assert self.reason in['before_external_caller_after_outer_return','before_main_port_error_continuation','before_matching_error_continuation','before_open_error_continuation'];r=self.base_report();r.update(sync_models=self.sync_models,internal_calls=self.internal_calls,class_entry=self.class_entry,entry_registers31=[hex(x)for x in self.entry_registers],entry_SP=hex(self.entry_SP),outer_input_record=self.snapshot(OBJ,8),saved_primary_cell_pointer=self.snapshot(self.F+0x50,8),outer_result_word=self.snapshot(self.F+0x60,4),primary_cell={'address':hex(PRIMARY),'bytes_hex':bytes(self.u.mem_read(PRIMARY,8)).hex()},fallback_cell={'address':hex(FALLBACK),'bytes_hex':bytes(self.u.mem_read(FALLBACK,8)).hex()},callback_pending=self.callback_pending is not None,outer_returned=self.reason=='before_external_caller_after_outer_return');return r

 def base_report(self):
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
  return {'input':self.c,'frame_SP':hex(self.F),'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial_fixtures,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'IOKit_models':self.io_models,'prefix_models':self.prefix_models,'source_edges':self.edges,'source_fixup_reads':self.fixups,'objects_entry':self.objects_entry,'query_entry':self.query_entry,'preceding_query_boundary':self.query_boundary,'boundary':self.boundary,'helper_call':self.helper_call,'class_buffer':self.snapshot(self.F+0x89,31),'class_call_snapshot':self.class_call_snapshot,'main_port_cell':self.snapshot(self.F+0x7c,4),'saved_input_and_tables':self.snapshot(self.F+0x38,24),'query_words':self.snapshot(self.F+0x64,12),'iterator_cell':self.snapshot(self.F+0x68,4),'connection_saved_pointer':self.snapshot(self.F+8,8),'returned_size':self.snapshot(self.F+0x70,8),'query_state_record':self.snapshot(self.record,20),'record_before_helper':self.record_before_call,'fallback_record':getattr(self,'fallback_record',None),'state_cache':{'address':hex(STATE),'size_bytes':24,'bytes_hex':bytes(self.u.mem_read(STATE,24)).hex(),'provenance_mask_hex':mask.hex()},'fallback_calls':self.fallback_calls,'fallback_input_record':self.fallback_input_record,'fallback_access_record':self.fallback_access_record,'cache_before_fallback':self.cache_before_fallback,'fallback_returned':self.fallback_returned,'state_before_final_marker':self.state_before_final_marker,'helper_returned':self.helper_returned,'native_target_executed':False,'native_port_identity_proved':False,'full_goal_complete':False}

def cases():
 for x in class_cases():
  c=json.loads(json.dumps(x));c['sync']={'primary':P+0x5000,'fallback':0,'once_completed':False};yield c
 base=next(class_cases())
 for primary,fallback,done,placement,version in itertools.product([0],[0,P+0x6000],[False,True],[0,0x100],[0,0x2e1e0100]):
  c=json.loads(json.dumps(base));c.update(placement=placement,sync_case='lock_selection_and_once_control',words=[version,0],sync={'primary':primary,'fallback':fallback,'once_completed':done});yield c
 for done,placement in itertools.product([False,True],[0,0x100]):
  c=json.loads(json.dumps(base));c.update(placement=placement,sync_case='primary_over_fallback',sync={'primary':P+0x5000,'fallback':P+0x6000,'once_completed':done});yield c

def main():
 rows=[]
 for j,c in enumerate(cases()):
  f=Sync(c);rows.append(f.run());del f
  if j%32==0:print(json.dumps({'cases_completed':j+1}),flush=True)
 sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['probe_daemon_iokit_class.py','probe_daemon_iokit_objects.py','probe_daemon_query_fallback.py','probe_daemon_query_state.py','probe_daemon_iokit_census.py','daemon_receive_tools.py','daemon_import_bindings.py','daemon_receive_fixups.txt']},'source_sha256':sha(SOURCE),'cases':rows,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_iokit_sync_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(len(r['source_visits'])for r in rows)}),flush=True)
if __name__=='__main__':main()
