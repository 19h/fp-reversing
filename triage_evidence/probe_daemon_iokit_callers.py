#!/usr/bin/env python3
"""Two conditional caller record/consumer paths composed with original init.
Caller bank/table/controller/saved-stack roots are explicit local premises;
their upstream producers and native reachability remain unknown. All selected
callee source and frozen API/primitive summaries execute as previously pinned.
O(B+C*(V+E+JF)) time,O(B+C*(V+E)+F+4096J) space; no native target/PAC.
"""
import hashlib,json,struct,itertools
from pathlib import Path
from unicorn import arm64_const as ar
from probe_daemon_iokit_errors import Errors,composed_cases as error_cases
from probe_daemon_iokit_sync import P,ENTRY as INIT,OUTER_RETURN,cases as sync_cases
from daemon_receive_tools import ROOT,SOURCE,IMAGE,TABLE
SITES={'313':{'start':0x100313428,'call':0x1003134d4,'end':0x10031350c,'phase_reg':21,'phase':0x665d,'R_offset':0x98},'AF':{'start':0x100afed54,'call':0x100afedd4,'end':0x100afee10,'phase_reg':22,'phase':0x4468,'R_offset':0x98}}
class Caller(Errors):
 def __init__(self,c):
  super().__init__(c);self.site=SITES[c['caller']];self.C=self.F+0x130;self.CFP=self.C+0x600;self.CR=self.CFP-0x98;self.init_call=None;self.init_return=None;self.init_entry=None;self.input_before_init=None
  self.set(29,self.CFP);self.u.reg_write(ar.UC_ARM64_REG_SP,self.C);self.set(self.site['phase_reg'],self.site['phase'])
  if c['caller']=='313':
   for j,v in [(12,0x1010b7d48),(13,0x1010c4670),(25,TABLE)]:self.set(j,v)
   self.fixture(self.C+0x190,struct.pack('<QQ',0x101031fa0,0x100fc4230));self.fixture(self.C+0x274,struct.pack('<I',0xaabbccdd))
  else:
   for j,v in [(12,0x1010c4670),(13,0x1010b7d48),(14,0x100fc4130),(15,0x101031ea0),(27,TABLE)]:self.set(j,v)
   self.fixture(self.C+0x1b8,struct.pack('<QQ',0x100e99800,0x100f4e290));self.fixture(self.C+0x2b8,struct.pack('<Q',TABLE))
  self.caller_entry_registers=[self.reg(j)for j in range(31)]
 def code(self,u,a,n,d):
  self.flush();s=self.site
  if a==INIT and self.init_call is not None:
   self.init_entry={'pc':hex(a),'source_visit_index':self.seq,'registers31':[hex(self.reg(j))for j in range(31)],'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP))};self.input_before_init=self.snapshot(self.CR,8)
  if a==s['call']:
   assert self.reg(8)==INIT and self.reg(17)==0xa74 and self.reg(0)==self.CR;self.init_call={'pc':hex(a),'source_visit_index':self.seq,'target':hex(INIT),'modifier16':'0xa74','record':self.snapshot(self.CR,8),'registers31':[hex(self.reg(j))for j in range(31)],'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP))};self.visit(a);self.set(30,a+4);return u.reg_write(ar.UC_ARM64_REG_PC,INIT)
  if a==s['call']+4:
   self.init_return={'pc':hex(a),'source_visit_index':self.seq,'registers31':[hex(self.reg(j))for j in range(31)],'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'record':self.snapshot(self.CR,8)};assert self.init_return['SP']==self.init_call['SP']and self.init_return['registers31'][19:30]==self.init_call['registers31'][19:30]
  if not s['start']<=a<a+4<=s['end']:return super().code(u,a,n,d)
  i=next(self.dec.disasm(IMAGE.read(a,4),a));m=i.mnemonic;assert m not in ['bl','blr','blraa','br','ret','retab','svc','hvc','smc'];self.visit(a)
  if m=='braa':
   target=self.reg(int(i.op_str.split(',',1)[0][1:]));self.edges.append({'pc':hex(a),'source_visit_index':self.seq-1,'target':hex(target),'modifier16':hex(self.reg(17))});return self.stop_at(target,'before_caller_selected_continuation')
 def run(self):
  self.page(self.site['start']);self.u.emu_start(self.site['start'],0,count=10000);self.flush();assert self.reason=='before_caller_selected_continuation'and self.init_call and self.init_return and self.init_entry;r=self.base_report();r.update(sync_models=self.sync_models,internal_calls=self.internal_calls,class_entry=self.class_entry,status_calls=self.status_calls,status_returns=self.status_returns,isolated=False,caller=self.c['caller'],caller_SP=hex(self.C),caller_FP=hex(self.CFP),caller_entry_registers31=[hex(x)for x in self.caller_entry_registers],init_call=self.init_call,init_entry=self.init_entry,init_return=self.init_return,init_input_before=self.input_before_init,caller_record=self.snapshot(self.CR,8),saved_primary_cell_pointer=self.snapshot(self.F+0x50,8),outer_result_word=self.snapshot(self.F+0x60,4),outer_input_record=self.snapshot(self.CR,8));return r
def cases():
 cs=list(error_cases());kept={0,1,2,14,46,68,91,92,93,96,100,120,135,150,180,220,223}
 for caller,j in itertools.product(['313','AF'],sorted(kept)):
  c=json.loads(json.dumps(cs[j]));c.update(caller=caller,prior_error_index=j);yield c
 direct=list(sync_cases())
 for caller,j in itertools.product(['313','AF'],[16,128,144]):
  c=json.loads(json.dumps(direct[j]));c.update(caller=caller,prior_sync_direct_index=j);yield c
def main():
 rows=[]
 for j,c in enumerate(cases()):
  f=Caller(c);rows.append(f.run());del f
  if j%16==0:print(json.dumps({'cases_completed':j+1}),flush=True)
 sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in ['probe_daemon_iokit_errors.py','daemon_iokit_errors_profiles.json','probe_daemon_iokit_sync.py','probe_daemon_iokit_class.py','probe_daemon_iokit_objects.py','probe_daemon_query_fallback.py','probe_daemon_query_state.py','probe_daemon_iokit_census.py','daemon_receive_tools.py','daemon_receive_fixups.txt']},'source_sha256':sha(SOURCE),'cases':rows,'native_target_executed':False,'native_upstream_reachability_proved':False,'full_goal_complete':False};(ROOT/'daemon_iokit_callers_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(len(r['source_visits'])for r in rows)}),flush=True)
if __name__=='__main__':main()
