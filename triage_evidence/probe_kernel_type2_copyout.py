#!/usr/bin/env python3
"""Exact produced type2 copies enter original copyout; explicit lower VM premises.
O(visits+RAM+effects), O(image+RAM+journals). No native target or kernel effect.
"""
import json,struct
from unicorn import arm64_const as ar
from probe_kernel_vm_entry_copy import Probe as Parent,P,SIZE,SP,HALT,MAP,THREAD,NEW,COPY
from probe_rpc502_vm_handoff import decode,OUT,KMAP,DEST
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
PREFIX='kernel_type2_copyout'
class Probe(Parent):
 def __init__(self,im,c,src,seed,producer,index=4):
  super().__init__(im,{'mode':'consumer'},src,seed,None,None);self.c.update(c);self.u.mem_write(P,decode(producer['final_private_RAM']));self.initial=[];self.resume={'path':'kernel_vm_entry_copy_profiles.json','case':index,**producer['final_private_RAM']};self.image_initial=[];self.consumer_frames=[]
  for e in producer['final_auxiliary_regions']:self.fixture(int(e['address'],16),bytes.fromhex(e['bytes_hex']))
  for e in producer['final_image_globals']:self.image_fixture(int(e['address'],16),bytes.fromhex(e['bytes_hex']),'Exact produced-type2 final-global transfer')
  for j in range(31):self.set(j,0)
  self.active=0;self.stage='copyout';self.entry=0xfffffe000bdd1574 if c.get('wrapper',True)else 0xfffffe000bdcb374
  args=[KMAP,OUT,COPY]if c.get('wrapper',True)else[KMAP,OUT,COPY,c.get('extent',32769),c['consume']]
  for j,x in enumerate(args):self.set(j,x)
  self.set(30,HALT);self.u.reg_write(ar.UC_ARM64_REG_SP,SP);self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV));self.actual_entry_SP=hex(SP)
 def code(self,u,a,n,d):
  self.flush()
  arities={0xfffffe000bdd1574:3,0xfffffe000bdcb374:5,0xfffffe000bdc7434:6,0xfffffe000bdcbfcc:5,0xfffffe000bdcc14c:5,0xfffffe000bde1300:5,0xfffffe000bdc8760:4,0xfffffe000bdc8ba4:4,0xfffffe000be2fac0:2,0xfffffe000bdde9ac:8,0xfffffe000bdcd914:3,0xfffffe000bddf0b0:2}
  if a in arities:self.consumer_frames.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments':[hex(self.reg(j))for j in range(arities[a])],'new_entry64_hex':bytes(u.mem_read(NEW,64)).hex(),'copy_header48_hex':bytes(u.mem_read(COPY,48)).hex()})
  if a==0xfffffe000bddf0b0:return self.stop('before_destination_store_search',{'store_context24_hex':bytes(u.mem_read(self.reg(0),24)).hex(),'arguments':[hex(self.reg(j))for j in range(2)],'native_destination_store_not_initialized':True})
  if a==0xfffffe000bdde9ac:
   if self.c.get('resolver_result')is None:return self.stop('before_lower_VM_resolver',{'captured_body_not_executed':True,'arguments':[hex(self.reg(j))for j in range(8)]})
   result=self.c['resolver_result'];return self.effect(a,'declared_type2_destination_resolver',result,[]if result else[(self.reg(7),struct.pack('<Q',DEST),'declared destination interval start')])
  if a==0xfffffe000bd75c64 and self.reg(30)in[0xfffffe000bdcb840,0xfffffe000bdcb8b4]:return self.model(a,'declared_type2_copyout_clone_allocation',P+0x6a000 if self.reg(30)==0xfffffe000bdcb840 else NEW+64)
  return super().code(u,a,n,d)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=60000);self.flush();assert self.reason in['returned','before_uncaptured_code','before_lower_VM_resolver','before_destination_store_search','before_original_assertion','before_indirect_call'],self.boundary
  row=self.collect();row.update(entry_SP=self.actual_entry_SP,initial_state_transfer=self.resume,entry_Q_registers32=self.q_initial,entry_copy_frames=self.entry_frames,entry_copy_return_frames=self.entry_copy_return,new_entry_allocations=self.new_entries,new_entry64_hex=bytes(self.u.mem_read(NEW,64)).hex(),working_copy_header48_hex=bytes(self.u.mem_read(COPY,48)).hex(),message392_hex=bytes(self.u.mem_read(self.header,392)).hex(),type2_consumer_frames=self.consumer_frames,output16_hex=bytes(self.u.mem_read(OUT,16)).hex(),destination_map256_hex=bytes(self.u.mem_read(KMAP,256)).hex(),cloned_entry64_hex=bytes(self.u.mem_read(NEW+64,64)).hex(),cloned_header48_hex=bytes(self.u.mem_read(P+0x6a000,48)).hex());return row
def main():
 im=Image();src=json.loads((ROOT/(PREFIX+'_source.json')).read_text());seed=json.loads((ROOT/'rpc502_reply_copyin_profiles.json').read_text())['cases'][42];producer=json.loads((ROOT/'kernel_vm_entry_copy_profiles.json').read_text())['cases'][4];rows=[]
 configs=[{'test':'exact_produced_copy'}]+[{'test':'declared_resolver','resolver_result':r,'wrapper':w,'consume':v}for r,w,v in [(3,True,1),(0,True,1),(0,False,0),(0,False,2),(0,False,3),(0xffffffff,True,1),(0x2e,True,1)]]+[{'test':'extent_mismatch','resolver_result':0,'wrapper':False,'consume':v,'extent':e}for v in[0,1]for e in[0,32768,32770]]
 for c in configs:
  row=Probe(im,c,src,seed,producer).run();rows.append(row);print(json.dumps({'case':len(rows)-1,'configuration':c,'boundary':row['boundary'],'visits':len(row['source_visits'])}),flush=True)
 deps=[PREFIX+'_source.json','kernel_vm_entry_copy_profiles.json','rpc502_reply_copyin_profiles.json','probe_kernel_vm_entry_copy.py','probe_kernel_vm_range_cursor.py','probe_rpc502_vm_handoff.py','probe_rpc502_reply_copyin.py','probe_kernel_vm_mig.py','kernel_vm_mig_tools.py'];out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'cases':rows,'native_target_executed':False,'native_VM_effects_executed':False,'native_IPC_executed':False,'native_retirement_executed':False,'native_namespace_conversion_executed':False,'hardware_PAC_executed':False,'idb_mutated':False,'complete_FairPlay_round_trip_established':False,'full_goal_complete':False};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
