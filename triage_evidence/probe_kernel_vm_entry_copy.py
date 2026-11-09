#!/usr/bin/env python3
"""Original entry-copy and resumed held-context cleanup/type2 publication.
Entry-zone allocation, store position, map locks/removal and retirement remain
premises. O(visits+RAM+effects), O(RAM+journals). No native VM/IPC operation.
"""
import json,struct
from unicorn import arm64_const as ar
from probe_kernel_vm_range_cursor import Probe as Parent,P,SIZE,SP,HALT,MAP,THREAD,ENTRY,START,END
from probe_rpc502_vm_handoff import compressed,decode
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from replay_kernel_vm_range_cursor import Replay as HeldReplay
PREFIX='kernel_vm_entry_copy';COPY=P+0x68000;NEW=ENTRY+64;EZ=P+0xb0000;EA=P+0xb0100
class Probe(Parent):
 def __init__(self,im,c,src,seed,held,simd,producer=None,producer_index=None):
  super().__init__(im,{'stage':'type2','empty_store':False},src,seed);self.c.update(c);self.entry_frames=[];self.new_entries=[];self.entry_copy_return=[];self.resume=None;self.q_initial=None
  if c['mode']=='resume':
   raw=decode(held['final_private_RAM']);self.u.mem_write(P,raw);self.initial=[];self.resume={'path':'kernel_vm_range_cursor_profiles.json','case':23,**held['final_private_RAM']}
   for e in held['final_auxiliary_regions']:self.fixture(int(e['address'],16),bytes.fromhex(e['bytes_hex']))
   self.image_initial=[]
   for e in held['final_image_globals']:self.image_fixture(int(e['address'],16),bytes.fromhex(e['bytes_hex']),'Exact held-prefix final-global transfer')
   b=held['boundary'];self.entry=int(b['pc'],16);self.current_cursor=int(held['cursor_address'],16);self.u.reg_write(ar.UC_ARM64_REG_SP,int(b['SP'],16));self.u.reg_write(ar.UC_ARM64_REG_NZCV,int(b['NZCV'],16))
   for j,x in enumerate(b['registers31']):self.set(j,int(x,16))
   for j,x in enumerate(simd):self.u.reg_write(getattr(ar,'UC_ARM64_REG_Q'+str(j)),int(x,16))
   self.q_initial=simd
  elif c['mode']=='factory':
   self.fixture(ENTRY+0x38,struct.pack('<I',c['entry_flags']));self.fixture(NEW,b'\xa5'*64);self.fixture(EZ,bytes(64));self.fixture(EZ+0x34,struct.pack('<H',64));self.fixture(EA,bytes(16));self.image_fixture(0xfffffe000caec140,struct.pack('<QQ',EZ,EA),'Declared entry-zone pair, native zone identity unknown')
  if c['mode']=='discard':
   self.u.mem_write(P,decode(producer['final_private_RAM']));self.initial=[];self.resume={'producer_case':producer_index,**producer['final_private_RAM']}
   for e in producer['final_auxiliary_regions']:self.fixture(int(e['address'],16),bytes.fromhex(e['bytes_hex']))
   self.image_initial=[]
   for e in producer['final_image_globals']:self.image_fixture(int(e['address'],16),bytes.fromhex(e['bytes_hex']),'Exact produced-list component global transfer')
   for j in range(31):self.set(j,0)
   self.active=c['descriptor_index'];self.current_cursor=int(producer['cursor_address'],16);self.entry=0xfffffe000bdc6308;self.set(0,COPY+c['descriptor_index']*0x1000);self.set(30,HALT);self.u.reg_write(ar.UC_ARM64_REG_SP,SP)
  self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV));self.actual_entry_SP=hex(self.u.reg_read(ar.UC_ARM64_REG_SP))
 def code(self,u,a,n,d):
  self.flush()
  if a in[0xfffffe000bdd21fc,0xfffffe000bdc6728,0xfffffe000bdee258,0xfffffe000bde11e0,0xfffffe000be3431c,0xfffffe000be344c8,0xfffffe000bdd014c,0xfffffe000bde1248,0xfffffe000be304e8]:
   count={0xfffffe000bdd21fc:4,0xfffffe000bdee258:5,0xfffffe000be344c8:1,0xfffffe000bdd014c:5}.get(a,2);self.entry_frames.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments':[hex(self.reg(j))for j in range(count)]})
  if a==0xfffffe000bdd17f4:self.entry_copy_return.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments':[hex(self.reg(0))],'new_entry64_hex':bytes(u.mem_read(NEW,64)).hex(),'copy_header48_hex':bytes(u.mem_read(COPY,48)).hex()})
  if a==0xfffffe000bdd21fc:
   self.cursor_frames.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments':[hex(self.reg(j))for j in range(4)],'cursor128_hex':bytes(u.mem_read(self.reg(0),128)).hex()});self.current_cursor=self.reg(0);return self.source_instruction(a)
  if a==0xfffffe000bd75c64 and self.reg(30)==0xfffffe000bdd22b8:
   self.new_entries.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments':[hex(self.reg(j))for j in range(3)],'address':hex(NEW)});assert[self.reg(j)for j in range(3)]==[EZ,EA,0x8004];return self.model(a,'declared_entry_zone_allocation',NEW)
  if a==0xfffffe000bdd014c:self.model(a,'declared_type2_source_removal',0);return
  try:return super().code(u,a,n,d)
  except AssertionError as e:
   if e.args==(hex(a),)and not any(lo<=a<hi for lo,hi in self.allowed):return self.stop('before_uncaptured_code',{'arguments':[hex(self.reg(j))for j in range(8)]})
   raise
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=60000);self.flush();assert self.reason in['returned','before_uncaptured_code','before_original_assertion','before_indirect_call'],self.boundary;row=self.collect();row.update(entry_SP=self.actual_entry_SP,initial_state_transfer=self.resume,entry_Q_registers32=self.q_initial,entry_copy_frames=self.entry_frames,entry_copy_return_frames=self.entry_copy_return,new_entry_allocations=self.new_entries,new_entry64_hex=bytes(self.u.mem_read(NEW,64)).hex(),working_copy_header48_hex=bytes(self.u.mem_read(COPY,48)).hex(),message392_hex=bytes(self.u.mem_read(self.header,392)).hex());return row

def main():
 im=Image();src=json.loads((ROOT/(PREFIX+'_source.json')).read_text());held=json.loads((ROOT/'kernel_vm_range_cursor_profiles.json').read_text())['cases'][23];seed=json.loads((ROOT/'rpc502_reply_copyin_profiles.json').read_text())['cases'][42];proof=HeldReplay(im,held);proof_counts=proof.run();simd=[hex(proof.u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j))))for j in range(32)];rows=[]
 for c in [{'mode':'resume'}]+[{'mode':'factory','entry_flags':v}for v in[0,0x10,0x100,0x110]]:
  row=Probe(im,c,src,seed,held,simd).run();rows.append(row);print(json.dumps({'case':len(rows)-1,'configuration':c,'boundary':row['boundary'],'visits':len(row['source_visits'])}),flush=True)
 for descriptor_index in[0,1]:
  producer=4 if descriptor_index==0 else len(rows)-1;row=Probe(im,{'mode':'discard','descriptor_index':descriptor_index},src,seed,held,simd,rows[producer],producer).run();rows.append(row);print(json.dumps({'case':len(rows)-1,'descriptor_index':descriptor_index,'boundary':row['boundary'],'visits':len(row['source_visits'])}),flush=True)
 deps=[PREFIX+'_source.json','kernel_vm_range_cursor_profiles.json','rpc502_reply_copyin_profiles.json','probe_kernel_vm_range_cursor.py','probe_rpc502_vm_handoff.py','probe_rpc502_reply_copyin.py','probe_kernel_vm_mig.py','replay_kernel_vm_range_cursor.py','replay_rpc502_vm_handoff.py','replay_kernel_reply_send.py','replay_kernel_vm_mig.py','kernel_vm_mig_tools.py'];out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'held_prefix_fresh_replay':proof_counts,'held_Q_registers32':simd,'cases':rows,'native_target_executed':False,'native_VM_effects_executed':False,'native_retirement_executed':False,'native_namespace_conversion_executed':False,'native_IPC_executed':False,'hardware_PAC_executed':False,'idb_mutated':False,'complete_FairPlay_round_trip_established':False,'full_goal_complete':False};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
