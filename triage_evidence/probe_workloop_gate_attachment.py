#!/usr/bin/env python3
"""Original workloop/internal-gate construction fragment and source attachment.
Allocator/reference/lock outcomes and runtime metadata/flag premises are explicit.
O(visits+effects), O(source journals+private RAM); no target operations.
"""
import json,struct
from unicorn import arm64_const as ar
from probe_aes_command_gate import Probe as Parent,OBJECTS,P,PROV,GATE,EXP,LOOP,POOL,CMD,GV
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
PREFIX='workloop_gate_attachment';WLEXP=P+0x17000;IGATE=P+0x18000;IEXP=P+0x19000;MAINT=0xfffffe000c51a604;STAT=0xfffffe000c57b280;FLAG=0xfffffe000cb5b6e0;WLLOCK=P+0x1a000;THREAD=P+0x1b000
class Probe(Parent):
 def __init__(self,im,c,src,origin=None,producer=None):
  stage=c['stage'];mapped='init'if stage in ['outer_init','statistics']else'registration'if stage in ['loop_fragment','provider']else'runAction'
  super().__init__(im,{'stage':mapped,**{k:v for k,v in c.items()if k!='stage'}},src,origin,producer);self.c=c;self.maintenance=[];self.system_reads=[];self.u.reg_write(ar.UC_ARM64_REG_TPIDR_EL1,THREAD);self.all_objects=[*OBJECTS,(WLEXP,0x40),(IGATE,0x80),(IEXP,0x40),(WLLOCK,0x40)]
  if origin is None:self.fixture(LOOP+0x10,struct.pack('<Q',WLLOCK));self.fixture(WLLOCK+0x18,struct.pack('<Q',THREAD))
  self.ensure(FLAG);b=bytes([c.get('feature_byte',0)]);self.u.mem_write(FLAG,b);self.image_initial.append({'address':hex(FLAG),'bytes_hex':b.hex(),'provenance':'Explicit inactive instrumentation predicate; runtime value unknown'})
  if stage=='loop_fragment':
   self.entry=0xfffffe000c51af98;self.end=0xfffffe000c51b0a8;self.set(19,LOOP);self.fixture(LOOP+0x40,struct.pack('<Q',WLEXP));a=0xfffffe000cb52db8;self.ensure(a,8);b=struct.pack('<Q',0xfffffe0007f3fe28);self.u.mem_write(a,b);self.image_initial.append({'address':hex(a),'bytes_hex':b.hex(),'provenance':'Nominal runtime gate metaclass vptr; original file vptr zero'})
  elif stage in ['detach','reattach','duplicate']:
   self.entry=0xfffffe000c51a1fc if stage=='detach'else 0xfffffe000c51a244;self.set(0,LOOP);self.set(1,GATE)
  elif stage=='statistics':self.entry=STAT;self.set(0,PROV)
  self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV))
 def code(self,u,a,n,d):
  self.flush()
  if a==0xfffffe000c51eb40:
   assert self.reg(0)==0xfffffe000cb52db8;self.effect(IGATE,struct.pack('<Q',GV),'Declared nominal IOCommandGate allocation, not native metaclass execution');return self.modeled(a,'internal_gate_allocation_model',IGATE)
  if a==0xfffffe000bcfeb8c:
   assert self.reg(0)==0xfffffe0007e55c58;return self.modeled(a,'gate_extension_allocation_model',EXP if self.c['stage']=='outer_init'else IEXP)
  if a in [0xfffffe000c445200,0xfffffe000c4451d0]:
   assert self.reg(0)in [GATE,IGATE];return self.modeled(a,'retain_no_effect_model'if a==0xfffffe000c445200 else'release_no_effect_model',0)
  if a==0xfffffe000c51a398:self.system_reads.append({'pc':hex(a),'source_visit_index':len(self.visits),'TPIDR_EL1':hex(u.reg_read(ar.UC_ARM64_REG_TPIDR_EL1))})
  if a==MAINT:self.maintenance.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments5':[hex(self.reg(j))for j in range(5)],'inner_gate48_hex':bytes(u.mem_read(IGATE+0x48,8)).hex(),'return_pc':hex(self.reg(30))})
  # Bypass only the parent's former external-call interception; execute these
  # original PAC prologues and every following original body instruction.
  if a in [STAT,0xfffffe000c51a244]or(a in {0xfffffe000c51a718,0xfffffe000c51a74c,0xfffffe000c51a814,0xfffffe000c51a848}):
   raw=bytes(u.mem_read(a,4));assert raw==self.image.k.read(a,4);i=next(self.image.k.cs.disasm(raw,a));assert i.mnemonic in ['pacibsp','paciza'];self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});self.auth.append({'pc':hex(a),'source_visit_index':len(self.visits)-1,'mnemonic':i.mnemonic,'operands':i.op_str,'registers18':[hex(self.reg(j))for j in range(18)]});return u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  return super().code(u,a,n,d)
 def run(self):
  row=super().run();row['maintenance_frames']=self.maintenance;row['initial_TPIDR_EL1']=hex(THREAD);row['system_context_reads']=self.system_reads;row['final_objects']=[{'address':hex(a),'bytes_hex':bytes(self.u.mem_read(a,n)).hex()}for a,n in self.all_objects];return row
def main():
 im=Image();src=json.loads((ROOT/(PREFIX+'_source.json')).read_text());rows=[]
 rows.append(Probe(im,{'stage':'outer_init'},src).run());rows.append(Probe(im,{'stage':'loop_fragment','on_thread':1},src,rows[0],0).run());rows.append(Probe(im,{'stage':'provider','on_thread':1},src,rows[1],1).run());rows.append(Probe(im,{'stage':'dispatch','on_thread':1},src,rows[2],2).run());rows.append(Probe(im,{'stage':'detach','on_thread':1},src,rows[2],2).run());rows.append(Probe(im,{'stage':'reattach','on_thread':1},src,rows[4],4).run());rows.append(Probe(im,{'stage':'duplicate','on_thread':1},src,rows[2],2).run());rows.append(Probe(im,{'stage':'provider','on_thread':0},src,rows[1],1).run())
 for b in [2,254]:rows.append(Probe(im,{'stage':'statistics','feature_byte':b},src).run())
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in [PREFIX+'_source.json','probe_aes_command_gate.py','probe_kernel_vm_mig.py','kernel_vm_mig_tools.py']},'cases':rows,'native_target_executed':False,'native_IPC_executed':False,'hardware_PAC_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(len(r['source_visits'])for r in rows),'models':sum(len(r['API_models'])for r in rows)}),flush=True)
if __name__=='__main__':main()
