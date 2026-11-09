#!/usr/bin/env python3
"""Capture a verified pre-read callback boundary without assigning unknown bits.
O(prefix+continuation+mapped RAM) time, O(prefix+mapped RAM) space.
Full original-prefix replay first; no native API/PAC/IDB mutation executes.
"""
import json,hashlib,base64,zlib
from pathlib import Path
from unicorn import arm64_const as ar
from daemon_receive_tools import ROOT,SOURCE
from probe_daemon_buffer_consumer import Consumer,INPUTS,unpack
from daemon_context_transfer_symbolic import P

def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def pack(raw):return base64.b64encode(zlib.compress(bytes(raw))).decode()
def main():
 names=['daemon_arena_storage_profiles.json','daemon_context_transfer_profiles.json','daemon_entropy_return_profiles.json','daemon_seed_material_profiles.json','daemon_prng_output_profiles.json'];base,prior,entropy,material,output=[json.loads((ROOT/n).read_text())for n in names];index=17;pick=lambda q:unpack(next(v for v in q['cases']if v['prior_case_index']==index));cfg=next(v for v in INPUTS if v['name']=='reference');v=Consumer(base['cases'][index]['input'],pick(prior),pick(entropy),pick(material),pick(output),cfg,3);row=v.run_consumer();row['prior_case_index']=index;sealed=json.loads((ROOT/'daemon_buffer_consumer_profiles.json').read_text());reference=next(r for r in sealed['cases']if r['prior_case_index']==index and r['values']['name']=='reference');assert row==reference and row['boundary']['pc']=='0x1003ecb98'
 aliases={}
 for step in v.trace['steps']:
  for e in step['events']:
   if e['kind']!='write':continue
   address=int(e['address'],16)
   if not P<=address<address+e['size_bytes']<=P+0x10000:continue
   shape=e['value'];terms=shape.get('terms',list(bytes.fromhex(shape['hex']))if'hex'in shape else None);assert terms is not None
   for j,value in enumerate(terms):
    if isinstance(value,dict):aliases[address+j]=value['origin']
    else:aliases.pop(address+j,None)
 aliases={hex(a):off for a,off in aliases.items()if not v.known[a-P]and off!=a-v.F}
 logical={}
 for j,physical in enumerate(row['boundary']['registers31']):
  name='x'+str(j);shape={'hex':int(physical,16).to_bytes(8,'little').hex()}if v.register_known[name]else v.trace['boundary']['registers31'][j];assert v.register_known[name]or'terms'in shape;logical[name]=shape
 latest_q={}
 for step in v.trace['steps']:
  for name,shape in step['registers_after'].items():
   if name.startswith('q'):latest_q[name]=shape
 for j in range(32):
  name='q'+str(j);physical=v.u.reg_read(getattr(ar,'UC_ARM64_REG_Q'+str(j)));shape={'hex':physical.to_bytes(16,'little').hex()}if v.register_known[name]else latest_q[name];assert v.register_known[name]or'terms'in shape;logical[name]=shape
 logical['sp']={'hex':int(row['boundary']['SP'],16).to_bytes(8,'little').hex()}
 regions=[]
 for lo,hi,permissions in v.u.mem_regions():
  raw=bytes(v.u.mem_read(lo,hi-lo+1));regions.append({'address':hex(lo),'size_bytes':len(raw),'permissions':permissions,'sha256':hashlib.sha256(raw).hexdigest(),'bytes_zlib_base64':pack(raw)})
 deps=names+['daemon_buffer_consumer_profiles.json','probe_daemon_buffer_consumer.py','daemon_context_transfer_symbolic.py'];out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'prior_case_index':index,'values':cfg,'frame_SP':hex(v.F),'arena_owner':hex(v.H),'boundary':row['boundary'],'logical_registers':logical,'NZCV':hex(v.u.reg_read(ar.UC_ARM64_REG_NZCV)),'private_owner':{'address':hex(P),'size_bytes':0x10000,'known_mask_zlib_base64':pack(v.known)},'heap_owner':{'address':hex(v.H),'size_bytes':90000,'known_mask_zlib_base64':pack(v.heap_known)},'image_known_overrides':{hex(a):known for a,known in v.image_known.items()},'unknown_stack_aliases':aliases,'inherited_unknown_backing':{str(k):b for k,b in v.backing.items()},'regions':regions,'sealed_source_stream_sha256':row['source_stream_sha256'],'sealed_prefix_source_visits':row['prefix_verified_counts']['source_visits'],'sealed_continuation_source_visits':row['dynamic_counts']['source_visits'],'snapshot_is_before_unknown_read_effects':True,'unknown_backing_is_not_source_definition':True,'native_target_executed':False,'full_goal_complete':False};(ROOT/'daemon_callback_revisit_snapshot.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'regions':len(regions),'mapped_bytes':sum(r['size_bytes']for r in regions),'unknown_alias_bytes':len(aliases),'known_general_registers':sum('hex'in logical['x'+str(j)]for j in range(31)),'sealed_match':True}),flush=True)
if __name__=='__main__':main()
