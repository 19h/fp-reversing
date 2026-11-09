#!/usr/bin/env python3
"""Source query-state record/cache continuation under explicit frame premises.

Private original A64 instructions; incoming state09,connection5804 and opaque
stack guard are declared fixtures. API/PAC summaries are explicit. Stop before
unknown iterator data or the zero-capability fallback call; no native target.
O(B+C*(V+E+J*F)) time,O(B+C*(V+E)+F+4096*J) retained space.
"""
import hashlib,json,struct
from pathlib import Path
from unicorn import arm64_const as ar
from probe_daemon_iokit_census import Queries,cases,P,JOIN
from daemon_receive_tools import ROOT,SOURCE,IMAGE,CS
class State(Queries):
 def __init__(self,c):
  super().__init__(c);self.set(29,self.F+0x120);self.set(19,0x101031ea0);self.fixture(self.F+0x20,struct.pack('<Q',0x100fc4130));self.query_boundary=None;self.helper_call=None;self.record=self.F+0xa8
# Extended source execution is deliberately separate from the initial call frontier.
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_MEM
from daemon_receive_tools import FIXUPS
STATE=0x1010b6380;GUARD=P+0xf000;GUARD_VALUE=0x5d0ff00dcafed00d
EXTENDED=[(JOIN,0x1003c3b04),(0x100013ac0,0x100013d3c),(0x1000898d8,0x100089908),(0x1000115a0,0x100011678),(0x100483c6c,0x100483cd4)]
class FullState(State):
 def __init__(self,c):
  super().__init__(c);self.page(STATE);self.image_initial_fixtures=[]
  for a,b in[(STATE,b'\x09'),(STATE+4,struct.pack('<I',0x5804))]:self.u.mem_write(a,b);self.image_initial_fixtures.append({'address':hex(a),'bytes_hex':b.hex(),'provenance':3})
  self.fixture(self.F+8,struct.pack('<Q',STATE+4));self.fixture(self.F+0x58,struct.pack('<Q',STATE));self.fixture(GUARD,struct.pack('<Q',GUARD_VALUE));self.extra_calls=[];self.helper_entered=False;self.helper_returned=False;self.unknown=None;self.record_before_call=None;self.dec=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);self.dec.detail=True
 def page(self,a):
  page=a&~4095
  if page in self.pages:return
  raw=bytearray(IMAGE.read(page,4096));self.u.mem_map(page,4096);self.pages.add(page)
  for at,r in FIXUPS.items():
   if page<=at<page+4096:
    t=r['target'];v=GUARD if t=='libSystem/___stack_chk_guard'else 0x7c006800 if t=='IOKit/_IOConnectCallStructMethod'else t if isinstance(t,int)else 0x7c100000;raw[at-page:at-page+8]=struct.pack('<Q',v)
  self.u.mem_write(page,bytes(raw))
 def stop_at(self,a,reason):
  self.flush();self.reason=reason;self.boundary={'pc':hex(a),'kind':reason,'registers31':[hex(self.reg(j))for j in range(31)],'SP':hex(self.u.reg_read(ar.UC_ARM64_REG_SP))};self.u.emu_stop()
 def visit(self,a):
  raw=IMAGE.read(a,4);assert bytes(self.u.mem_read(a,4))==raw;self.visits.append({'pc':hex(a),'bytes_hex':raw.hex(),'source_visit_index':self.seq});self.seq+=1
 def code(self,u,a,n,d):
  self.flush()
  if a==JOIN and self.query_boundary is None:self.query_boundary={'pc':hex(a),'registers31':[hex(self.reg(j))for j in range(31)],'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP))}
  if self.query_boundary is None:return Queries.code(self,u,a,n,d)
  if a==0x1003c3ae8:
   assert self.reg(0)==self.record and self.reg(8)==0x100013ac0 and self.reg(17)==0xf08f;self.record_before_call=self.snapshot(self.record,20);self.helper_call={'pc':hex(a),'source_visit_index':self.seq,'target':hex(self.reg(8)),'modifier16':hex(self.reg(17)),'registers8':[hex(self.reg(j))for j in range(8)],'target_executed':True};self.helper_entered=True;self.visit(a);self.set(30,a+4);return u.reg_write(ar.UC_ARM64_REG_PC,self.reg(8))
  if a==0x1003c3aec:self.helper_returned=True
  if not any(x<=a<a+4<=z for x,z in EXTENDED):return self.stop_at(a,'before_undeclared_state_continuation')
  ins=next(self.dec.disasm(IMAGE.read(a,4),a));m=ins.mnemonic
  if m in['ldr','ldp','ldur','ldrb','ldrh','ldurb','ldurh']:
   op=next((o for o in ins.operands if o.type==ARM64_OP_MEM),None)
   if op is not None:
    base=ins.reg_name(op.mem.base);at=(u.reg_read(ar.UC_ARM64_REG_SP)if base=='sp'else self.reg(29 if base=='fp'else int(base[1:])))+op.mem.disp
    if op.mem.index:
     name=ins.reg_name(op.mem.index);v=self.reg(int(name[1:]));v=v&0xffffffff if name.startswith('w')else v;at+=v<<op.shift.value
    dest=ins.reg_name(ins.operands[0].reg);size=(1 if m in['ldrb','ldurb']else 2 if m in['ldrh','ldurh']else 4 if dest.startswith('w')else 8)*(2 if m=='ldp'else 1)
    if P<=at<at+size<=P+0x10000 and not all(self.known[at-P:at-P+size]):self.unknown={'pc':hex(a),'operands':ins.op_str,'snapshot':self.snapshot(at,size)};return self.stop_at(a,'before_uninitialized_saved_iterator_read')
  if m=='blraa':
   self.fallback_record=self.snapshot(self.reg(0),16)
   row={'pc':hex(a),'source_visit_index':self.seq,'target':hex(self.reg(int(ins.op_str.split(',',1)[0][1:]))),'modifier16':hex(self.reg(17)),'registers8':[hex(self.reg(j))for j in range(8)],'target_executed':False};self.extra_calls.append(row);return self.stop_at(a,'before_zero_capability_fallback_call')
  if m=='bl':return self.stop_at(a,'before_unmodeled_direct_state_call')
  self.visit(a)
  if m=='braa':
   target=self.reg(int(ins.op_str.split(',',1)[0][1:]));assert any(x<=target<z for x,z in EXTENDED);self.edges.append({'pc':hex(a),'source_visit_index':self.seq-1,'target':hex(target),'modifier16':hex(self.reg(17))});return u.reg_write(ar.UC_ARM64_REG_PC,target)
  if m in['bti','pacibsp','paciasp','autibsp','autiasp']:return u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  if m in['ret','retab','retaa']:return u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30))
 def write(self,u,access,a,n,v,d):
  if P<=a<a+n<=P+0x10000:return super().write(u,access,a,n,v,d)
  assert any(x<=a<a+n<=z for x,z in[(0x1010b9028,0x1010b9030),(0x1010c4670,0x1010c4678),(STATE,STATE+1),(STATE+8,STATE+24)]),('image write escape',hex(u.reg_read(ar.UC_ARM64_REG_PC)),hex(a),n);e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':self.seq-1,'address':hex(a),'size_bytes':n};self.writes.append(e);self.pending.append(e)
 def run(self):
  self.page(0x100364398);self.u.emu_start(0x100364398,0,count=3000);self.flush();assert self.reason in['before_zero_capability_fallback_call','before_uninitialized_saved_iterator_read']and self.helper_entered
  assert self.boundary['pc']==('0x100483ca8'if self.helper_returned else'0x100011674')
  mask=bytearray(24)
  for row in self.image_initial_fixtures:
   a=int(row['address'],16)
   for j in range(a,a+len(bytes.fromhex(row['bytes_hex']))):
    if STATE<=j<STATE+24:mask[j-STATE]=3
  for row in self.writes:
   a=int(row['address'],16)
   for j in range(a,a+row['size_bytes']):
    if STATE<=j<STATE+24:mask[j-STATE]=1
  return {'input':self.c,'frame_SP':hex(self.F),'source_entry_register_adjustments':{'X19':'0x101031ea0','X29':hex(self.F+0x120)},'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial_fixtures,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'source_edges':self.edges,'source_fixup_reads':self.fixups,'preceding_query_boundary':self.query_boundary,'boundary':self.boundary,'helper_call':self.helper_call,'unexecuted_calls':self.extra_calls,'query_words':self.snapshot(self.F+0x64,12),'returned_size':self.snapshot(self.F+0x70,8),'query_state_record':self.snapshot(self.record,20),'record_before_helper':self.record_before_call,'fallback_record':getattr(self,'fallback_record',None),'state_cache':{'address':hex(STATE),'size_bytes':24,'bytes_hex':bytes(self.u.mem_read(STATE,24)).hex(),'provenance_mask_hex':mask.hex()},'uninitialized_read_boundary':self.unknown,'helper_returned':self.helper_returned,'native_target_executed':False,'internal_record_helper_executed':True,'full_goal_complete':False}
def full_cases():
 yield from cases()
 base=next(cases())
 for placement in[0,0x100]:
  for version in[0,0x13180000,0x12345678,0x123456ff]:
   c=json.loads(json.dumps(base));c.update(placement=placement,words=[version,0],state_case='accepted_zero_capabilities');yield c

def full_main():
 rows=[]
 for j,c in enumerate(full_cases()):
  f=FullState(c);rows.append(f.run());del f
  if j%32==0:print(json.dumps({'cases_completed':j+1}),flush=True)
 sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
 out={'scope':'Private source execution through initial query-state stores and declared return/fallback frontiers. Original PAC/return authentication abstracted; incoming guard and state fixtures explicit. No native target/API executes.','generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['probe_daemon_iokit_census.py','daemon_receive_tools.py','daemon_import_bindings.py','daemon_receive_fixups.txt']},'source_sha256':sha(SOURCE),'cases':rows,'native_target_executed':False,'full_goal_complete':False}
 (ROOT/'daemon_query_state_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
 print(json.dumps({'cases':len(rows),'source_visits':sum(len(r['source_visits'])for r in rows)}),flush=True)
if __name__=='__main__':full_main()
