#!/usr/bin/env python3
"""Original pool construction, 32-carrier seeding and object-preserving leases.
Allocator/constructor/reference/lock/PAC premises are explicit; no target effects.
O(visits+effects), O(journals+private RAM).
"""
import json,struct,hashlib
from unicorn import arm64_const as ar
from probe_workloop_gate_attachment import Probe as Parent,P,PROV,GATE,LOOP,POOL,GV,THREAD
from probe_kernel_vm_mig import SP,HALT
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
PREFIX='aes_command_pool';PGATE=P+0x1c000;PGEXP=P+0x1d000;CARRIERS=[P+0x30000+0x100*j for j in range(32)];PV=0xfffffe0007f40058;CV=0xfffffe0008588d98
class Probe(Parent):
 def __init__(self,im,c,src,origin,producer,external=None):
  super().__init__(im,{'stage':'provider','on_thread':1},src,origin,producer);self.c=c;self.end=None;self.external=external;self.pool_frames=[];self.pool_statuses=[];self.sleep=[];self.allocated=[];self.all_objects+=[(PGATE,0x80),(PGEXP,0x40),*[(a,144)for a in CARRIERS]];self.allowed +=[(int(s['start'],16),int(s['end'],16))for s in src['seed_stubs']]
  for a,v in [(0xfffffe000cb52db8,0xfffffe0007f3fe28),(0xfffffe000cb52de0,0xfffffe0007f40218)]:self.ensure(a,8);b=struct.pack('<Q',v);self.u.mem_write(a,b);self.image_initial.append({'address':hex(a),'bytes_hex':b.hex(),'provenance':'Nominal runtime metaclass vptr; original file word zero'})
  stage=c['stage']
  if stage=='factory':self.entry=0xfffffe000c520c24;self.set(0,LOOP)
  elif stage=='seed':self.entry=0xfffffe000abfc704;self.end=0xfffffe000abfc7ac;self.set(19,PROV);self.set(0,POOL)
  elif stage=='return':self.entry=0xfffffe000c51fe7c;self.set(0,POOL);self.set(1,int(origin['boundary']['registers31'][0],16))
  else:self.entry=0xfffffe000c51ff48;self.set(0,POOL);self.set(1,c['block'])
  self.set(30,HALT);self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV))
 def code(self,u,a,n,d):
  self.flush()
  if a==0xfffffe000c5203c4:
   assert self.reg(0)==0xfffffe000cb52de0;self.effect(POOL,struct.pack('<Q',PV),'Declared nominal pool allocation, not native metaclass execution');return self.modeled(a,'pool_allocation_model',POOL)
  if a==0xfffffe000c51eb40:
   assert self.reg(0)==0xfffffe000cb52db8;self.effect(PGATE,struct.pack('<Q',GV),'Declared nominal pool-gate allocation');return self.modeled(a,'pool_gate_allocation_model',PGATE)
  if a==0xfffffe000bcfeb8c:assert self.reg(0)==0xfffffe0007e55c58;return self.modeled(a,'pool_gate_extension_model',PGEXP)
  if a==0xfffffe000c445200:assert self.reg(0)==PGATE;return self.modeled(a,'pool_gate_retain_no_effect_model',0)
  if a==0xfffffe000c4458c4:
   assert[self.reg(j)for j in range(2)]==[0xfffffe000858a4a8,144]and len(self.allocated)<32;result=CARRIERS[len(self.allocated)];self.allocated.append({'address':hex(result),'requested_bytes':144,'before_source_visit_index':len(self.visits)});return self.modeled(a,'command_allocation_model',result)
  if a==0xfffffe000c51fb58:assert self.reg(0)in CARRIERS and self.reg(1)==0xfffffe000cce14e0;return self.modeled(a,'command_base_constructor_model',self.reg(0))
  if a==0xfffffe000c4434ec:assert self.reg(0)==0xfffffe000cce14e0;return self.modeled(a,'command_class_bookkeeping_model',0)
  if a in [0xfffffe000c520c24,0xfffffe000c51f3f0]:
   raw=bytes(u.mem_read(a,4));assert raw==self.image.k.read(a,4);i=next(self.image.k.cs.disasm(raw,a));assert i.mnemonic=='pacibsp';self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});self.auth.append({'pc':hex(a),'source_visit_index':len(self.visits)-1,'mnemonic':i.mnemonic,'operands':i.op_str,'registers18':[hex(self.reg(j))for j in range(18)]});return u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  if a in [0xfffffe000c51fd90,0xfffffe000c51fcec]:self.pool_frames.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments5':[hex(self.reg(j))for j in range(5)],'gate48_hex':bytes(u.mem_read(PGATE+0x48,8)).hex()})
  if a==0xfffffe000c51e4fc and self.reg(21)==PGATE:self.pool_statuses.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'raw_X0':hex(self.reg(0))})
  if a==0xfffffe000c51e1d4:
   self.sleep.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments3':[hex(self.reg(j))for j in range(3)],'gate48_hex':bytes(u.mem_read(PGATE+0x48,8)).hex()});return self.stop('before_pool_sleep')
  return super().code(u,a,n,d)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=50000);self.flush();assert self.reason in ['returned','after_registration_component','before_pool_sleep'],self.boundary
  return {'configuration':self.c,'source_producer_case':self.origin,'external_source_producer':self.external,'entry_PC':hex(self.entry),'entry_SP':hex(SP),'entry_registers31':self.entry_regs,'entry_NZCV':self.entry_NZCV,'initial_TPIDR_EL1':hex(THREAD),'private_RAM':{'address':hex(P),'size_bytes':0x100000,'initial_byte':0,'native_owner_extents_established':False},'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'logical_authentication':self.auth,'indirect_edges':self.indirect,'maintenance_frames':self.maintenance,'system_context_reads':self.system_reads,'action_frames':self.action_frames,'pool_frames':self.pool_frames,'pool_action_statuses':self.pool_statuses,'pool_sleep_frontiers':self.sleep,'command_allocations':self.allocated,'final_objects':[{'address':hex(a),'bytes_hex':bytes(self.u.mem_read(a,n)).hex()}for a,n in self.all_objects],'final_RAM_sha256':hashlib.sha256(bytes(self.u.mem_read(P,0x100000))).hexdigest(),'boundary':self.boundary,'native_target_executed':False,'native_IPC_executed':False,'hardware_PAC_executed':False,'idb_mutated':False,'full_goal_complete':False}
def main():
 im=Image();src=json.loads((ROOT/(PREFIX+'_source.json')).read_text());published=json.loads((ROOT/'workloop_gate_attachment_profiles.json').read_text());rows=[]
 rows.append(Probe(im,{'stage':'factory','on_thread':1},src,published['cases'][2],None,{'path':'workloop_gate_attachment_profiles.json','case':2}).run());rows.append(Probe(im,{'stage':'seed','on_thread':1},src,rows[0],0).run());rows.append(Probe(im,{'stage':'lease','block':1,'on_thread':1},src,rows[1],1).run());rows.append(Probe(im,{'stage':'return','on_thread':1},src,rows[2],2).run());rows.append(Probe(im,{'stage':'lease','block':0,'on_thread':1},src,rows[1],1).run())
 for ordinal in range(1,33):rows.append(Probe(im,{'stage':'drain','block':0,'ordinal':ordinal,'on_thread':1},src,rows[-1],len(rows)-1).run())
 rows.append(Probe(im,{'stage':'wait','block':1,'on_thread':1},src,rows[-1],len(rows)-1).run())
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in [PREFIX+'_source.json','workloop_gate_attachment_profiles.json','probe_workloop_gate_attachment.py','probe_aes_command_gate.py','probe_kernel_vm_mig.py','kernel_vm_mig_tools.py']},'cases':rows,'native_target_executed':False,'native_IPC_executed':False,'hardware_PAC_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(len(r['source_visits'])for r in rows),'API_models':sum(len(r['API_models'])for r in rows)}),flush=True)
if __name__=='__main__':main()
