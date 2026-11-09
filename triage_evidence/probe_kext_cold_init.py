#!/usr/bin/env python3
"""Cold close-wrapper continuation with explicit bounded typed allocation.

Extends the frozen private source engine. A104-byte nonnull allocation with
poison/unknown or zero/known output is an explicit external API model. Source
initializers run unchanged. Unknown heap reads or other native API calls stop.
No real allocator, target crypto/provider, IOKit, Mach or synchronization API.
O(B+V+E+S), 20000 original-instruction cap per independent fixture.
"""
import hashlib,json,struct
from pathlib import Path
from probe_kext_close import Close,ROOT,SOURCE,IMAGE,ar
HEAP=0x6100000000;DICTIONARY=0x6200000000;DESCRIPTOR=0xfffffe000847b460;ALLOC=0xfffffe000c4ba154;MATCH=0xfffffe000c4ece88;WAIT=0xfffffe000c4eb5d8;FREE=0xfffffe000c4ba368
class Cold(Close):
 def __init__(self,mode,stage='matching_boundary'):
  self.mode=mode;self.stage=stage;self.heap_known=bytearray(104);self.heap_events=[];self.heap_created=False;self.heap_retired=False;self.wait_observations=[]
  super().__init__(1,0)
 def hook(self,u,a,n,d):
  self.flush()
  if a==ALLOC:
   assert self.reg(0)==DESCRIPTOR and not self.heap_created;assert struct.unpack('<I',IMAGE.read(DESCRIPTOR+44,4))[0]==104
   u.mem_map(HEAP,4096);u.mem_write(HEAP,(b'\xa5'if self.mode=='poison_unknown'else b'\0')*104);self.heap_created=True
   if self.mode=='zero_known':self.heap_known[:]=b'\1'*104
   self.events.append({'kind':'typed_allocation_result_model','source_call':hex(self.reg(30)-4),'type_descriptor':hex(DESCRIPTOR),'declared_extent_bytes':104,'mode':self.mode,'pointer':hex(HEAP),'native_API_executed':False});self.setreg(0,HEAP);return u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30))
  if a==MATCH and self.stage!='matching_boundary':
   assert bytes(u.mem_read(self.reg(0),17)).split(b'\0')[0]==b'IOAESAccelerator'and self.reg(1)==0;self.events.append({'kind':'serviceMatching_result_model','source_call':hex(self.reg(30)-4),'opaque_dictionary':hex(DICTIONARY),'dictionary_bytes_unknown':True,'native_API_executed':False});self.setreg(0,DICTIONARY);return u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30))
  if a==WAIT:
   p=self.reg(1);raw=bytes(u.mem_read(p,8));self.wait_observations.append({'source_call':hex(self.reg(30)-4),'dictionary':hex(self.reg(0)),'timeout_pointer':hex(p),'timeout8_hex':raw.hex(),'words32':list(struct.unpack('<2I',raw))});assert self.reg(0)==DICTIONARY
   if self.stage in['provider_absent','provider_absent_retire']:self.events.append({'kind':'waitForService_result_model','result_pointer':'0x0','native_API_executed':False});self.setreg(0,0);return u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30))
  if a==FREE and self.stage=='provider_absent_retire':
   assert self.reg(0)==0xfffffe000847b3a0 and self.reg(1)==HEAP and not self.heap_retired;self.heap_retired=True;self.events.append({'kind':'typed_release_result_model','pointer':hex(HEAP),'descriptor':hex(self.reg(0)),'native_API_executed':False});self.setreg(0,0);return u.reg_write(ar.UC_ARM64_REG_PC,self.reg(30))
  return super().hook(u,a,n,d)
 def read(self,u,access,a,n,value,d):
  if self.heap_created and a<HEAP+4096 and a+n>HEAP:
   e={'kind':'source_heap_read','pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'offset_bytes':a-HEAP,'size_bytes':n,'bytes_hex':bytes(u.mem_read(a,n)).hex()};self.heap_events.append(e)
   if self.heap_retired:return self.stop('retired_typed_allocation_read',**{k:v for k,v in e.items()if k!='kind'})
   if not HEAP<=a<a+n<=HEAP+104:return self.stop('typed_allocation_extent_boundary',**{k:v for k,v in e.items()if k!='kind'})
   if not all(self.heap_known[a-HEAP:a-HEAP+n]):return self.stop('unknown_typed_allocation_byte',**{k:v for k,v in e.items()if k!='kind'})
  return super().read(u,access,a,n,value,d)
 def write(self,u,access,a,n,value,d):
  if self.heap_created and a<HEAP+4096 and a+n>HEAP:
   if self.heap_retired:return self.stop('retired_typed_allocation_write',address=hex(a),size_bytes=n)
   if not HEAP<=a<a+n<=HEAP+104:return self.stop('typed_allocation_write_extent_boundary',address=hex(a),size_bytes=n)
   self.heap_known[a-HEAP:a-HEAP+n]=b'\1'*n
  return super().write(u,access,a,n,value,d)
 def run(self):
  r=super().run();r.update(cold_scope=__doc__,allocation_mode=self.mode,continuation_stage=self.stage,allocation_created=self.heap_created,allocation_retired_in_model=self.heap_retired,allocation_known_mask_hex=self.heap_known.hex(),allocation_final_hex=bytes(self.u.mem_read(HEAP,104)).hex()if self.heap_created else None,source_heap_reads=self.heap_events,wait_observations=self.wait_observations,final_flag_byte_hex=bytes(self.u.mem_read(0xfffffe000ccca078,1)).hex(),final_global_pointer_hex=bytes(self.u.mem_read(0xfffffe000cccca58,8)).hex());return r
def main():
 rows=[];pool={}
 for mode in['poison_unknown','zero_known']:
  for stage in['matching_boundary','wait_boundary','provider_absent','provider_absent_retire']:
   q=Cold(mode,stage);r=q.run();rows.append(r);pool.update(q.pool);print('CASE',mode,stage,r['stop_reason'],len(r['source_visits']),r['events'][-1:],[(e['pc'],e['target'])for e in r['calls']][-5:],flush=True)
 out={'scope':__doc__,'generator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'source_sha256':hashlib.sha256(SOURCE.read_bytes()).hexdigest(),'dependencies':{n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest()for n in['probe_kext_close.py','kext_port_tools.py','kernel_collection_interfaces.json']},'cases':rows,'source_instructions':[{'ea':hex(a),'bytes':b.hex()}for a,b in sorted(pool.items())],'native_target_executed':False,'full_goal_complete':False};(ROOT/'kext_cold_init_profiles.json').write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
