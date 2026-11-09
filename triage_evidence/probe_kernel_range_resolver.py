#!/usr/bin/env python3
"""Original range allocator runs on exact constructed-map and produced-copy state.
Declared class bounds, empty bucket state, cached RNG and zeroed record allocator
remain premises. O(visits+RAM+effects), O(image+RAM+journals). No native VM/IPC.
"""
import json,struct
from unicorn import arm64_const as ar
from probe_kernel_map_store_init import Probe as Parent,P,SIZE,SP,HALT,ROOTPAGE,KMAP,NEW,COPY
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
PREFIX='kernel_range_resolver';STATE=0xfffffe000cb80d60;RNG=0xfffffe000cb810e0;BOUNDS=0xfffffe0007e69fe0;REC=NEW+128;RZ=P+0xb6000;RA=P+0xb6100
class Probe(Parent):
 def __init__(self,im,c,src,seed,factory,constructed,producer_index=None):
  super().__init__(im,{'phase':c.get('phase','copyout'),'query':c.get('query',0),'resolver_result':None},src,seed,factory,constructed,0 if producer_index is None else producer_index);self.c.update(c);self.range_frames=[];self.range_outputs=[];self.range_out=None;self.resume['path']='kernel_map_store_init_profiles.json'if producer_index is None else PREFIX+'_profiles.json'
  if c['environment']=='declared':
   for a,b in[(RZ,bytes(64)),(RZ+0x34,struct.pack('<H',64)),(RA,bytes(16))]:self.fixture(a,b)
   for a,b in[(BOUNDS,struct.pack('<QQ',P,P+SIZE)),(STATE,bytes(0x1c0)),(RNG,struct.pack('<Q',c['rng_seed'])),(0xfffffe000caec380,struct.pack('<QQ',RZ,RA))]:self.image_fixture(a,b,'Declared class6 bounds, empty buckets, cached random word and record-zone pair; native values unknown')
 def write(self,u,t,a,n,v,d):
  if STATE<=a<a+n<=STATE+0x1c0 or a==RNG:
   e={'pc':hex(u.reg_read(ar.UC_ARM64_REG_PC)),'source_visit_index':len(self.visits)-1,'address':hex(a),'size_bytes':n};self.writes.append(e);self.pending.append(e);return
  return super().write(u,t,a,n,v,d)
 def code(self,u,a,n,d):
  self.flush();arity={0xfffffe000bdde9ac:8,0xfffffe000bddee0c:7,0xfffffe000bdde280:7,0xfffffe000bdddbd8:7,0xfffffe000bde1300:5}
  if a in arity:self.range_frames.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments':[hex(self.reg(j))for j in range(arity[a])]})
  if a==0xfffffe000bdde9ac:self.range_out=self.reg(7);return self.source_instruction(a)
  if a==0xfffffe000bdcb570 and self.range_out is not None:self.range_outputs.append({'pc':hex(a),'before_source_visit_index':len(self.visits),'arguments':[hex(self.reg(0))],'out_address':hex(self.range_out),'out_pair16_hex':bytes(u.mem_read(self.range_out,16)).hex(),'record32_hex':bytes(u.mem_read(REC,32)).hex()})
  if a==0xfffffe000bd75c64 and self.reg(30)==0xfffffe000bddef60:return self.effect(a,'declared_zeroed_range_record_allocation',REC,[(REC,bytes(64),'declared zeroed 64-byte record observation extent; native zone size unknown')])
  return super().code(u,a,n,d)
 def run(self):
  row=super().run();row.update(range_allocator_frames=self.range_frames,range_result_frames=self.range_outputs,range_record32_hex=bytes(self.u.mem_read(REC,32)).hex(),range_record64_hex=bytes(self.u.mem_read(REC,64)).hex(),range_bucket448_hex=bytes(self.u.mem_read(STATE,0x1c0)).hex(),cached_rng_u64=int.from_bytes(bytes(self.u.mem_read(RNG,8)),'little'));return row
def main():
 im=Image();src=json.loads((ROOT/(PREFIX+'_source.json')).read_text());seed=json.loads((ROOT/'rpc502_reply_copyin_profiles.json').read_text())['cases'][42];factory=json.loads((ROOT/'kernel_vm_entry_copy_profiles.json').read_text())['cases'][4];constructed=json.loads((ROOT/'kernel_map_store_init_profiles.json').read_text())['cases'][0];rows=[]
 for c in [{'environment':'file'}]+[{'environment':'declared','rng_seed':v}for v in[0x12345678,0x87654321,0xffffffffffffffff,0x100000000]]:
  row=Probe(im,c,src,seed,factory,constructed).run();rows.append(row);print(json.dumps({'case':len(rows)-1,'configuration':c,'boundary':row['boundary'],'visits':len(row['source_visits'])}),flush=True)
 for parent in range(1,5):
  start=int.from_bytes(bytes.fromhex(rows[parent]['output16_hex'])[:8],'little')
  for query in[start-1,start,start+32768,start+49152-1,start+49152]:
   c={'environment':'inherited','phase':'lookup','query':query};row=Probe(im,c,src,seed,factory,rows[parent],parent).run();rows.append(row);print(json.dumps({'case':len(rows)-1,'configuration':c,'boundary':row['boundary'],'lookup':row['lookup_output'],'visits':len(row['source_visits'])}),flush=True)
 deps=[PREFIX+'_source.json','kernel_map_store_init_profiles.json','kernel_vm_entry_copy_profiles.json','rpc502_reply_copyin_profiles.json','probe_kernel_map_store_init.py','probe_kernel_type2_copyout.py','probe_kernel_vm_entry_copy.py','probe_kernel_vm_range_cursor.py','probe_rpc502_vm_handoff.py','probe_rpc502_reply_copyin.py','probe_kernel_vm_mig.py','kernel_vm_mig_tools.py'];out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'cases':rows,'native_target_executed':False,'native_VM_effects_executed':False,'native_IPC_executed':False,'native_retirement_executed':False,'native_namespace_conversion_executed':False,'hardware_PAC_executed':False,'idb_mutated':False,'complete_FairPlay_round_trip_established':False,'full_goal_complete':False};(ROOT/(PREFIX+'_profiles.json')).write_text(json.dumps(out,indent=2)+'\n')
if __name__=='__main__':main()
