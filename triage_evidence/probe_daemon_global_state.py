#!/usr/bin/env python3
"""Read-only source/A64 observation of post-buffer global codec boundaries.
Replays the complete sealed prefix and continuation. No native import/PAC
executes. O(prefix+source visits) time, O(prefix+owner+unique PCs) space.
"""
import json,hashlib
from pathlib import Path
from unicorn import arm64_const as ar
from unicorn import UcError
from daemon_receive_tools import ROOT,SOURCE
from probe_daemon_buffer_consumer import Consumer,INPUTS,unpack
POINTS={0x1003c21f8,0x1003c2228,0x1003c227c,0x100247528,0x100247554,0x1002475a0,0x1002475bc,0x10031ed34,0x1003875a0,0x1003f1390,0x1003f15dc,0x1003f15e0,0x1003f15fc,0x1003f167c,0x1003f1744,0x1003f176c,0x1003f17b0,0x1003f1850,0x1003f18f8,0x1003f19dc,0x1003f19f8,0x1003ecb98}
class Observed(Consumer):
 def __init__(self,*args):self.observations=[];super().__init__(*args)
 def code(self,u,a,n,d):
  if self.dynamic and a in POINTS:
   def observed_bytes(address):
    try:return bytes(u.mem_read(address,8)).hex()
    except UcError:return None
   self.observations.append({'pc':hex(a),'registers31':[hex(self.reg(j))for j in range(31)],'SP':hex(self.fullreg('sp')),'NZCV':hex(self.u.reg_read(ar.UC_ARM64_REG_NZCV)),'frame358_physical_hex':bytes(u.mem_read(self.F+0x358,8)).hex(),'frame5A0_physical_hex':bytes(u.mem_read(self.F+0x5a0,8)).hex(),'global6800_hex':observed_bytes(0x1010c6800),'globalA2A8_hex':observed_bytes(0x1010ca2a8),'known_status':'Checkpoint values are consumed only along the sealed known-input continuation; unknown frontier retains its pre-read register snapshot.'})
  return super().code(u,a,n,d)
def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 names=['daemon_arena_storage_profiles.json','daemon_context_transfer_profiles.json','daemon_entropy_return_profiles.json','daemon_seed_material_profiles.json','daemon_prng_output_profiles.json'];base,prior,entropy,material,output=[json.loads((ROOT/n).read_text())for n in names];index=17;pick=lambda q:unpack(next(v for v in q['cases']if v['prior_case_index']==index));cfg=next(v for v in INPUTS if v['name']=='reference');v=Observed(base['cases'][index]['input'],pick(prior),pick(entropy),pick(material),pick(output),cfg,3);row=v.run_consumer();row['prior_case_index']=index;prior_results=json.loads((ROOT/'daemon_buffer_consumer_profiles.json').read_text());reference=next(r for r in prior_results['cases']if r['prior_case_index']==index and r['values']['name']=='reference');assert row==reference
 deps=names+['daemon_buffer_consumer_profiles.json','probe_daemon_buffer_consumer.py'];result={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'prior_case_index':index,'values':cfg,'observations':v.observations,'full_continuation_matches_sealed_case':True,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_global_state_observations.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'observations':len(v.observations),'sealed_continuation_match':True}),flush=True)
if __name__=='__main__':main()
