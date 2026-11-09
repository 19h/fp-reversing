#!/usr/bin/env python3
"""Three explicit original-worker version/family inputs with boundary records.

Both files fixed before any guest instruction. New observations never alter
guest state. API/PAC declarations inherited;no native target/API/IDB action.
O(C*(B+V+E+S)) work/space;two isolated analysis processes,not agents.
"""
import base64,hashlib,json,multiprocessing,struct,zlib
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor
from probe_rpc502_policy_transition import PolicyProbe,ROOT,SOURCE
from probe_rpc502_body import file_for_body
POINTS={0x100747f6c,0x100747f90,0x100747fa8,0x100747fcc,0x100a7b00c,0x100a7b028,0x100a7b050,0x100919318,0x100919330,0x100919334,0x100919370,0x10097531c}
class PolicyContractProbe(PolicyProbe):
 def __init__(self,*args):self.policy_points=[];super().__init__(*args)
 def hook(self,u,a,n,d):
  self.flush()
  if a in POINTS:
   p=self.point(a)
   if a==0x10097531c:p.update(X9_record600=self.view(self.reg(9),0x600),X11_record600=self.view(self.reg(11),0x600))
   self.policy_points.append(p)
  return super().hook(u,a,n,d)
 def finish(self,r):
  r=super().finish(r);r.update(policy_points=self.policy_points,policy_cases_generator_sha256=sha(Path(__file__)));return r

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def cases():
 raw=SOURCE.read_bytes();body=bytes(x^0x98 for x in raw[0xee87f4:0xee87f4+719]);first=struct.pack('>6I',1,0,1,0,0,0)+bytes(40)
 return [{'label':'AAA_v'+str(v),'version':v,'first_hex':first.hex(),'body_hex':body.hex(),'second_hex':file_for_body(body,v=v,C=128,n=4096).hex(),'fixture':{'body_cpu_model':'MAX','worker_instruction_budget':32000000}}for v in [2,4,5]]
def run_case(c):
 q=PolicyContractProbe(bytes.fromhex(c['second_hex']),c['fixture'],bytes.fromhex(c['first_hex']));r=q.run();return r,q.instruction_bank

def main():
 pool={};rows=[]
 with ProcessPoolExecutor(max_workers=2,mp_context=multiprocessing.get_context('spawn'))as ex:
  for case,(r,bank)in zip(cases(),ex.map(run_case,cases(),buffersize=2)):
   for a,e in bank.items():assert a not in pool or pool[a]==e;pool[a]=e
   rows.append({'case':case,'payload_zlib_base64':base64.b64encode(zlib.compress(json.dumps(r,separators=(',',':')).encode())).decode()});print('CASE',case['label'],r['steps'],r['stop_reason'],r['records'][-1:],flush=True)
 deps=['probe_rpc502_policy_transition.py','probe_rpc502_auth.py','probe_rpc502_auth_cases.py','rpc502_auth_models.py','probe_rpc502_startup.py','rpc502_startup_tools.py','rpc502_startup_root.der','rpc502_startup_key_services.der','probe_rpc502_body.py','rpc502_body_fixtures.py','probe_rpc502_supp.py','probe_rpc502_supp_cases.py','probe_rpc502_parser.py','probe_rpc502_sidecar_contents.py','probe_rpc502_sidecar_copy.py','probe_rpc502_sidecar_mapping.py','probe_rpc502_sidecar_data.py','probe_rpc502_sidecar_metadata.py','probe_rpc502_sidecar_io.py','daemon_rpc502_context_probe.py','daemon_rpc502_probe.py','daemon_receive_tools.py','daemon_receive_fixups.txt']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in deps},'original_instruction_pool':list(pool.values()),'cases':rows,'native_target_executed':False,'full_goal_complete':False};(ROOT/'rpc502_policy_profiles.json').write_text(json.dumps(out,indent=2)+'\n');print('COUNTS',len(rows),len(pool),flush=True)
if __name__=='__main__':main()
