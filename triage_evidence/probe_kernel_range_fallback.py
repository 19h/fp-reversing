#!/usr/bin/env python3
"""Original fallback and rollback consume exact source-produced reservation state.
Declared map flags/bounds/cache, allocation/lock/byte-move/retirement models and
separate call setup remain premises. O(visits+RAM+effects), O(image+RAM+journals).
No native VM/IPC effects or claim that a live caller triggers the abort.
"""
import json,struct
from unicorn import arm64_const as ar
from probe_kernel_range_resolver import Probe as Parent,P,SIZE,SP,HALT,KMAP,NEW,COPY,REC,STATE,RNG
from probe_kernel_map_store_init import ROOTPAGE,COUNTER
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
PREFIX='kernel_range_fallback'
class Probe(Parent):
 def __init__(self,im,c,src,seed,factory,producer,index=None):
  cfg={'environment':'declared','rng_seed':0x12345678}if index is None else{'environment':'inherited','phase':'lookup','query':c.get('query',0)};super().__init__(im,cfg,src,seed,factory,producer,index);self.c.update(c);self.fallback_frames=[];self.lower_returns=[];self.stop_after_reservation=c['phase']=='reserve';self.resume['path']='kernel_map_store_init_profiles.json'if index is None else PREFIX+'_profiles.json'
  if index is None:self.fixture(KMAP+0xb0,struct.pack('<I',c.get('map_flags',0)))
  if c['phase']=='rollback':
   result=producer['range_result_frames'][0];destination=int.from_bytes(bytes.fromhex(result['out_pair16_hex'])[:8],'little');self.entry=0xfffffe000bde01b0;args=[KMAP,destination|(1<<63 if c['token_kind']=='signed_address'else 0),0 if c['token_kind']=='zero'else REC]
  elif c['phase']=='lookup':self.entry=0xfffffe000bdc7274;args=[KMAP,c['query'],P+0xa1000]
  else:self.entry=0xfffffe000bdd1574;args=[KMAP,P+0x16000,COPY]
  for j in range(31):self.set(j,0)
  for j,x in enumerate(args):self.set(j,x)
  self.set(30,HALT);self.u.reg_write(ar.UC_ARM64_REG_SP,SP);self.entry_regs=[hex(self.reg(j))for j in range(31)];self.entry_NZCV=hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV));self.actual_entry_SP=hex(SP)
 def code(self,u,a,n,d):
  self.flush()
  if a==0xfffffe000bdc755c:self.lower_returns.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments':[hex(self.reg(0))]})
  arities={0xfffffe000bde01b0:3,0xfffffe000bde0334:2,0xfffffe000bde0578:3,0xfffffe000bdde280:7}
  if a in arities:self.fallback_frames.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments':[hex(self.reg(j))for j in range(arities[a])]})
  if a==0xfffffe000bddd5dc and self.c['phase']=='rollback':return self.source_or_stop(a)
  if a==0xfffffe000c6480c0 and(ROOTPAGE<=self.reg(0)<ROOTPAGE+4096 or self.reg(0)==REC):return self.effect(a,'declared_store_or_record_zeroing',0,[(self.reg(0),bytes(self.reg(1)),'argument-sized private store/record zeroing')])
  if a==0xfffffe000bdcb570 and self.stop_after_reservation:
   self.range_outputs.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments':[hex(self.reg(0))],'out_address':hex(self.range_out),'out_pair16_hex':bytes(u.mem_read(self.range_out,16)).hex(),'record32_hex':bytes(u.mem_read(REC,32)).hex()});return self.stop('before_post_reservation_validation',{'map_lock_is_modeled':True})
  return super().code(u,a,n,d)
 def run(self):
  self.ensure(self.entry);self.u.emu_start(self.entry,0,count=60000);self.flush();assert self.reason in['returned','before_post_reservation_validation','before_uncaptured_code','before_original_assertion','before_indirect_call'],self.boundary;row=self.collect()
  row.update(entry_SP=self.actual_entry_SP,initial_state_transfer=self.resume,entry_Q_registers32=self.q_initial,entry_copy_frames=self.entry_frames,entry_copy_return_frames=self.entry_copy_return,new_entry_allocations=self.new_entries,new_entry64_hex=bytes(self.u.mem_read(NEW,64)).hex(),working_copy_header48_hex=bytes(self.u.mem_read(COPY,48)).hex(),message392_hex=bytes(self.u.mem_read(self.header,392)).hex(),type2_consumer_frames=self.consumer_frames,output16_hex=bytes(self.u.mem_read(P+0x16000,16)).hex(),destination_map256_hex=bytes(self.u.mem_read(KMAP,256)).hex(),cloned_entry64_hex=bytes(self.u.mem_read(NEW+64,64)).hex(),cloned_header48_hex=bytes(self.u.mem_read(P+0x6a000,48)).hex(),map_constructor_frames=self.constructor_frames,root256_hex=bytes(self.u.mem_read(ROOTPAGE,256)).hex(),map_constructor_counter=int.from_bytes(bytes(self.u.mem_read(COUNTER,8)),'little'),range_allocator_frames=self.range_frames,range_result_frames=self.range_outputs,range_record32_hex=bytes(self.u.mem_read(REC,32)).hex(),range_record64_hex=bytes(self.u.mem_read(REC,64)).hex(),range_bucket448_hex=bytes(self.u.mem_read(STATE,448)).hex(),cached_rng_u64=int.from_bytes(bytes(self.u.mem_read(RNG,8)),'little'),fallback_frames=self.fallback_frames,lower_allocator_return_frames=self.lower_returns);return row
def main():
 im=Image();src=json.loads((ROOT/(PREFIX+'_source.json')).read_text());seed=json.loads((ROOT/'rpc502_reply_copyin_profiles.json').read_text())['cases'][42];factory=json.loads((ROOT/'kernel_vm_entry_copy_profiles.json').read_text())['cases'][4];constructed=json.loads((ROOT/'kernel_map_store_init_profiles.json').read_text())['cases'][0];rows=[]
 for c in [{'phase':'fallback','map_flags':v}for v in[8,0x100]]+[{'phase':'reserve','map_flags':0}]:
  row=Probe(im,c,src,seed,factory,constructed).run();rows.append(row);print(json.dumps({'case':len(rows)-1,'configuration':c,'boundary':row['boundary'],'visits':len(row['source_visits'])}),flush=True)
 for c in [{'phase':'rollback','token_kind':v}for v in['zero','signed_address','record']]:
  row=Probe(im,c,src,seed,factory,rows[2],2).run();rows.append(row);print(json.dumps({'case':len(rows)-1,'configuration':c,'boundary':row['boundary'],'visits':len(row['source_visits'])}),flush=True)
 for parent in[0,1,5,3,4]:
  start=int.from_bytes(bytes.fromhex(rows[parent]['output16_hex'])[:8],'little')if parent in[0,1]else P+0x80000
  queries=[start-1,start,start+49152-1,start+49152]if parent in[0,1]else([start,P,P+SIZE-1]if parent==5 else[start])
  for query in queries:
   c={'phase':'lookup','query':query};row=Probe(im,c,src,seed,factory,rows[parent],parent).run();rows.append(row);print(json.dumps({'case':len(rows)-1,'configuration':c,'boundary':row['boundary'],'visits':len(row['source_visits'])}),flush=True)
 deps=[PREFIX+'_source.json','kernel_map_store_init_profiles.json','kernel_vm_entry_copy_profiles.json','rpc502_reply_copyin_profiles.json','probe_kernel_range_resolver.py','probe_kernel_map_store_init.py','probe_kernel_type2_copyout.py','probe_kernel_vm_entry_copy.py','probe_kernel_vm_range_cursor.py','probe_rpc502_vm_handoff.py','probe_rpc502_reply_copyin.py','probe_kernel_vm_mig.py','kernel_vm_mig_tools.py'];out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'cases':rows,'native_target_executed':False,'native_VM_effects_executed':False,'native_IPC_executed':False,'native_retirement_executed':False,'native_namespace_conversion_executed':False,'hardware_PAC_executed':False,'idb_mutated':False,'complete_FairPlay_round_trip_established':False,'full_goal_complete':False};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
