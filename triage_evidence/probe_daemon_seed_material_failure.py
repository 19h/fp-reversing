#!/usr/bin/env python3
"""Conditional no-output time-failure model and isolated A64 reader replay.
The API's failure-output behavior is unknown; no-output is a declared
hypothesis, not a native observation. Output bytes remain undefined.
O(C*(prefix+events)+patterns*3) time,O(largest journal) space.
"""
import hashlib,json
from pathlib import Path
import z3
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE,arm64_const as ar
from daemon_receive_tools import ROOT,SOURCE,IMAGE
from daemon_seed_material_symbolic import Material,TIME

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 base=json.loads((ROOT/'daemon_arena_storage_profiles.json').read_text());prior=json.loads((ROOT/'daemon_context_transfer_profiles.json').read_text());entropy=json.loads((ROOT/'daemon_entropy_return_profiles.json').read_text());rows=[]
 for c in entropy['cases']:
  index=c['prior_case_index'];v=Material.from_sealed(base['cases'][index],next(x for x in prior['cases']if x['prior_case_index']==index),c);assert all(v.F+0x680+j not in v.bytes for j in range(16));v.api(TIME,'api_failure_',z3.BitVecVal(0xffffffff,32));error=None
  try:v.run_from(TIME+4)
  except AssertionError as e:error=str(e)
  assert error and error.startswith("('transformed private unknown'")and v.pc==0x1002dc318 and len(v.steps)==3 and len(v.origins)==116 and not v.api_models[0]['events'];neworig=[{'address':hex(a),**o}for a,o in sorted(v.origins.items())if o['offset']in range(0x680,0x684)];assert len(neworig)==4
  replays=[]
  for word in [0,0xa5a5a5a5,0xffffffff,0x01234567]:
   u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);page=(TIME+4)&~4095;u.mem_map(page,4096);u.mem_write(page,IMAGE.read(page,4096));u.mem_map(v.F&~4095,0x2000);u.mem_write(v.F+0x680,word.to_bytes(4,'little'));u.reg_write(ar.UC_ARM64_REG_X22,v.F+0x670);u.reg_write(ar.UC_ARM64_REG_X0,0xffffffff);reads=[];writes=[];pcs=[]
   def code(uc,a,n,d):
    if a==0x1002dc318:uc.emu_stop();return
    pcs.append(hex(a))
   u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_READ,lambda uc,access,a,n,val,d:reads.append({'address':hex(a),'size_bytes':n}));u.hook_add(UC_HOOK_MEM_WRITE,lambda uc,access,a,n,val,d:writes.append({'address':hex(a),'size_bytes':n}));u.emu_start(TIME+4,0,count=4)
   assert pcs==['0x1002dc30c','0x1002dc310','0x1002dc314']and reads==[{'address':hex(v.F+0x680),'size_bytes':4}]and not writes and u.reg_read(ar.UC_ARM64_REG_W8)==word and u.reg_read(ar.UC_ARM64_REG_W25)==0xb9eece56 and u.reg_read(ar.UC_ARM64_REG_W0)==0xffffffff
   replays.append({'physical_backing_word':hex(word),'source_defined_input_bytes':0,'source_visits':pcs,'memory_reads':reads,'memory_writes':writes,'W8_after':hex(word),'W25_after':'0xb9eece56','status_after':'0xffffffff','native_target_executed':False})
  rows.append({'prior_case_index':index,'frame_SP':hex(v.F),'declared_model':'gettimeofday returns -1, makes no caller-output writes; errno/library side effects not modeled','time_output_source_defined_bytes':0,'time_output_size_bytes':16,'API_model':v.api_models[0],'new_unknown_byte_origins':neworig,'steps':v.steps,'frontier':{'pc':hex(v.pc),'reason':error,'unexecuted':True},'isolated_A64_replays':replays})
 deps=['daemon_seed_material_symbolic.py','daemon_context_transfer_profiles.json','daemon_entropy_return_profiles.json','daemon_arena_storage_profiles.json'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'cases':rows,'isolated_A64_replays':sum(len(x['isolated_A64_replays'])for x in rows),'native_failure_observed':False,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_seed_material_failure.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'contexts':len(rows),'isolated_A64_replays':out['isolated_A64_replays'],'native_failure_observed':False}),flush=True)
if __name__=='__main__':main()
