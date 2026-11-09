#!/usr/bin/env python3
"""Nonnull data-allocation continuations of selector18, stopping before entropy.

The inherited two allocator returns and new input/output data returns change
registers only. Private backing remains unknown until original source stores.
WZR probes discard values. No entropy, input-content, native heap or IPC
operation executes. O(C*(B+V+E)) time/space,30000 source visits/case; abstract PAC.
"""
import hashlib,json
from pathlib import Path
from unicorn import arm64_const as ar
from capstone.arm64 import ARM64_OP_MEM
from probe_lskd_core_input import Input,cases as prior_cases,WORK,AUX,P,HALT,kernel
from kext_port_tools import ROOT,SOURCE
DATA=P+0x30000;RESULT=P+0x50000;INPUT=P+0x20000;END=P+0x60000
class Buffers(Input):
 def __init__(self,c):
  super().__init__(c);self.u.mem_map(P+0x20000,0x40000);self.u.mem_write(P+0x20000,b'\xa5'*0x40000);self.known.extend(bytes(0x40000));self.provenance.extend(bytes(0x40000));self.ranges.extend([(0xfffffe000a54409c,0xfffffe000a544164),(0xfffffe000a58c3bc,0xfffffe000a58c478)]);self.data_boundary=None;self.data_call=None;self.buffer_edges=[]
 def code(self,u,a,n,d):
  self.flush()
  if a==0xfffffe000a56d228:
   self.data_boundary={'kind':'before_unmodeled_core_call','pc':hex(a),'SP':hex(u.reg_read(ar.UC_ARM64_REG_SP)),'registers31':[hex(self.reg(j))for j in range(31)]};self.data_call={'pc':hex(a),'source_visit_index':self.seq,'target':hex(self.reg(8)),'registers8':[hex(self.reg(j))for j in range(8)],'target_executed':False};assert self.reg(8)==0xfffffe000c4ba60c and self.reg(0)==self.case['inputs8'][1]&0xffffffff and 16<=self.reg(0)<=65536;return self.register_return(a,self.reg(8),'input_data_nonnull_register_return',DATA)
  if self.data_boundary is None:return super().code(u,a,n,d)
  if a==0xfffffe000a544120 and self.case['inputs8'][3]&0xffffffff==3072:
   assert self.reg(8)==0xfffffe000c4ba60c and self.reg(0)==3072;return self.register_return(a,self.reg(8),'output_data_nonnull_register_return',RESULT)
  if a in[0xfffffe000a56d264,0xfffffe000a544160]:
   target=self.reg(8);assert target==(0xfffffe000a54409c if a==0xfffffe000a56d264 else 0xfffffe000a58c3bc);self.buffer_edges.append({'pc':hex(a),'source_visit_index':self.seq,'target':hex(target),'modifier16':hex(self.reg(17)),'registers31':[hex(self.reg(j))for j in range(31)],'target_executed':True});self.visit(a);return u.reg_write(ar.UC_ARM64_REG_PC,target)
  if any(x<=a<a+4<=z for x,z in self.ranges):
   ins=next(self.decoder.disasm(kernel().read(a,4),a))
   if ins.mnemonic in['ldr','ldp','ldur','ldrb','ldrh','ldurb','ldurh']:
    op=next((x for x in ins.operands if x.type==ARM64_OP_MEM),None)
    if op is not None:
     base=ins.reg_name(op.mem.base);at=(u.reg_read(ar.UC_ARM64_REG_SP)if base=='sp'else self.reg(29 if base=='fp'else int(base[1:])))+op.mem.disp
     if op.mem.index:
      name=ins.reg_name(op.mem.index);idx=self.reg(int(name[1:]));idx=idx&0xffffffff if name.startswith('w')else idx;at+=idx<<op.shift.value
     dest=ins.reg_name(ins.operands[0].reg);width=(1 if ins.mnemonic in['ldrb','ldurb']else 2 if ins.mnemonic in['ldrh','ldurh']else 4 if dest.startswith(('w','s'))else 16 if dest.startswith(('q','v'))else 8)*(2 if ins.mnemonic=='ldp'else 1)
     if P+0x20000<=at<at+width<=END and not all(self.known[at-P:at-P+width]):self.unknown_read={'pc':hex(a),'operands':ins.op_str,'snapshot':self.snapshot(at,width)};return self.stop(a,'before_uninitialized_extended_private_read')
  return super().code(u,a,n,d)
 def run(self):
  r=super().run();length=self.case['inputs8'][1]&0xffffffff;r.update(preceding_data_boundary=self.data_boundary,preceding_data_call=self.data_call,buffer_edges=self.buffer_edges,input_data_buffer=self.snapshot(DATA,length),output_data_buffer=self.snapshot(RESULT,3072),source_input_buffer=self.snapshot(INPUT,length)if self.case.get('buffer_fixture')else None,entropy_operation_executed=False,input_content_read=False,model_memory_writes=0);return r
def cases():
 previous=[c for c in prior_cases()if c['inputs8'][0]!=0 and 16<=c['inputs8'][1]&0xffffffff<=65536];assert len(previous)==24;yield from previous
 for c in previous:
  v=json.loads(json.dumps(c));v['inputs8'][:6]=[INPUT,c['inputs8'][1],P+0x6000,3072,P+0x1000,P+0x1008];v['buffer_fixture']='disjoint_request_regions';yield v

def main():
 rows=[]
 for j,c in enumerate(cases()):
  f=Buffers(c);r=f.run();del f;rows.append(r);print(json.dumps({'case':j+1,'source_visits':len(r['source_visits']),'boundary':r['boundary']['kind'],'pc':r['boundary']['pc'],'last_call':r['additional_calls'][-1:]}),flush=True)
 sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['probe_lskd_core_input.py','probe_lskd_core_workspace.py','probe_lskd_writers.py','probe_legacy_stack.py','legacy_stack_contracts.json','kernel_native_reader.py','kext_port_tools.py']},'kernel_collection_sha256':kernel().sha256,'source_sha256':sha(SOURCE),'cases':rows,'model_memory_writes':0,'native_target_executed':False,'entropy_operation_executed':False,'full_goal_complete':False};(ROOT/'lskd_input_buffers_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
