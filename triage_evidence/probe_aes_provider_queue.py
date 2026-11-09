#!/usr/bin/env python3
"""Source-configured nominal provider: real packing/pool/queue to driver entry.
Descriptor, class, ordinary metadata and PAC premises are explicit. No crypto.
O(visits+effects), O(journals+private RAM).
"""
import json,struct,hashlib
from unicorn import arm64_const as ar
from probe_aes_command_pool import Probe as Parent,P,PROV,GATE,LOOP,POOL,PGATE,CARRIERS
from probe_kernel_vm_mig import SP,HALT
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
PREFIX='aes_provider_queue';D0=P+0x20000;D1=P+0x21000;KEY=P+0x22000;IV=P+0x23000;CALLBACK=P+0xe1000;CTX=P+0x24000;QUANTUM=0xfffffe0009d50a28
class Probe(Parent):
 def __init__(self,im,c,src,origin,producer,external=None):
  super().__init__(im,{'stage':'lease','block':1,'on_thread':1},src,origin,producer,external);self.c=c;self.end=None;self.quantum=[];self.provider_frames=[];self.all_objects +=[(D0,0x100),(D1,0x100),(KEY,0x60),(IV,16),(CTX,16)];self.allowed.append((0xfffffe000abffaf4,0xfffffe000abffb04))
  stage=c['stage']
  if stage=='hardware_config':self.entry=0xfffffe0009d4f32c;self.end=0xfffffe0009d4f340;self.set(20,PROV);self.fixture(PROV,struct.pack('<Q',0xfffffe00082fd878))
  elif stage=='limits':self.entry=0xfffffe000abfc4ac;self.end=0xfffffe000abfc598;self.set(19,PROV)
  elif stage=='binding':self.entry=0xfffffe000abfc598;self.end=0xfffffe000abfc644;self.set(19,PROV)
  else:
   self.entry=0xfffffe000abff358
   for a in [D0,D1]:self.fixture(a,struct.pack('<Q',0xfffffe0007f85d80))
   self.fixture(KEY,struct.pack('<I',128)+bytes(0x5c));self.fixture(IV,bytes(16));self.fixture(SP,struct.pack('<QQQ',c.get('offsetB',0),CALLBACK if c.get('callback')else 0,CTX if c.get('callback')else 0))
   args=[PROV,D0,D1 if c.get('separate')else D0,c['length'],IV,c['operation'],KEY,c.get('offsetA',0)]
   for j,v in enumerate(args):self.set(j,v)
  self.set(30,HALT);self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV))
 def code(self,u,a,n,d):
  self.flush()
  if a==0xfffffe000c5353b4:assert[self.reg(j)for j in range(2)]in [[D0,0],[D1,0]];return self.modeled(a,'descriptor_prepare_model',0)
  if a==0xfffffe000c53c2c4:assert self.reg(0)in [D0,D1];return self.modeled(a,'descriptor_physical_address_model',0x100000 if self.reg(0)==D0 else 0x200000)
  if a==0xfffffe000abfd2d8:
   self.action_frames.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments8':[hex(self.reg(j))for j in range(8)],'gate48_hex':bytes(u.mem_read(GATE+0x48,8)).hex(),'return_pc':hex(self.reg(30))});raw=bytes(u.mem_read(a,4));assert raw==self.image.k.read(a,4);i=next(self.image.k.cs.disasm(raw,a));assert(i.mnemonic,i.op_str)==('bti','c');self.visits.append({'pc':hex(a),'bytes_hex':raw.hex()});return u.reg_write(ar.UC_ARM64_REG_PC,a+4)
  if a==QUANTUM:
   self.quantum.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments2':[hex(self.reg(j))for j in range(2)],'carrier144_hex':bytes(u.mem_read(self.reg(1),144)).hex(),'provider_busy_byte':bytes(u.mem_read(PROV+0x110,1)).hex(),'provider_gate48_hex':bytes(u.mem_read(GATE+0x48,8)).hex(),'pool_gate48_hex':bytes(u.mem_read(PGATE+0x48,8)).hex()});return self.stop('before_driver_quantum')
  return super().code(u,a,n,d)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=50000);self.flush();assert self.reason in ['after_registration_component','before_driver_quantum'],self.boundary
  return {'configuration':self.c,'source_producer_case':self.origin,'external_source_producer':self.external,'entry_PC':hex(self.entry),'entry_SP':hex(SP),'entry_registers31':self.entry_regs,'entry_NZCV':self.entry_NZCV,'initial_TPIDR_EL1':hex(self.u.reg_read(ar.UC_ARM64_REG_TPIDR_EL1)),'private_RAM':{'address':hex(P),'size_bytes':0x100000,'initial_byte':0,'native_owner_extents_established':False},'initial_private_fixtures':self.initial,'initial_image_fixtures':self.image_initial,'source_visits':self.visits,'source_reads':self.reads,'source_writes':self.writes,'API_models':self.models,'logical_authentication':self.auth,'indirect_edges':self.indirect,'maintenance_frames':self.maintenance,'system_context_reads':self.system_reads,'action_frames':self.action_frames,'pool_frames':self.pool_frames,'pool_action_statuses':self.pool_statuses,'pool_sleep_frontiers':self.sleep,'command_allocations':self.allocated,'driver_quantum_frontiers':self.quantum,'final_objects':[{'address':hex(a),'bytes_hex':bytes(self.u.mem_read(a,n)).hex()}for a,n in self.all_objects],'final_RAM_sha256':hashlib.sha256(bytes(self.u.mem_read(P,0x100000))).hexdigest(),'boundary':self.boundary,'native_target_executed':False,'native_IPC_executed':False,'hardware_PAC_executed':False,'idb_mutated':False,'full_goal_complete':False}
def main():
 im=Image();src=json.loads((ROOT/(PREFIX+'_source.json')).read_text());published=json.loads((ROOT/'aes_command_pool_profiles.json').read_text());rows=[]
 rows.append(Probe(im,{'stage':'hardware_config','on_thread':1},src,published['cases'][1],None,{'path':'aes_command_pool_profiles.json','case':1}).run());rows.append(Probe(im,{'stage':'limits','on_thread':1},src,rows[0],0).run());rows.append(Probe(im,{'stage':'binding','on_thread':1},src,rows[1],1).run())
 for c in [{'length':32,'operation':0},{'length':64,'operation':1,'separate':True,'offsetA':16,'offsetB':32},{'length':16,'operation':0,'callback':True},{'length':65536,'operation':0}]:rows.append(Probe(im,{'stage':'perform','on_thread':1,**c},src,rows[2],2).run())
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in [PREFIX+'_source.json','aes_command_pool_profiles.json','probe_aes_command_pool.py','probe_workloop_gate_attachment.py','probe_aes_command_gate.py','probe_kernel_vm_mig.py','kernel_vm_mig_tools.py']},'cases':rows,'native_target_executed':False,'native_IPC_executed':False,'hardware_PAC_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(rows),'source_visits':sum(len(r['source_visits'])for r in rows),'API_models':sum(len(r['API_models'])for r in rows)}),flush=True)
if __name__=='__main__':main()
