#!/usr/bin/env python3
"""Fresh source recapture, independent CPU replay and response byte oracle.
Finite cases are evidence for their declared fixtures, not native reachability.
O(captured bytes+case visits) time, O(one private map+profiles) space.
"""
from collections import Counter
import json,struct
from daemon_receive_tools import ROOT
from capture_daemon_record720 import sha
from kernel_vm_mig_tools import Image
from replay_kernel_vm_mig import Replay
from replay_rpc502_bridge_daemon import View
from recover_rpc502_reply_bridge import recover

def u32(b,o):return int.from_bytes(b[o:o+4],'little')
def u64(b,o):return int.from_bytes(b[o:o+8],'little')
def expected(b,status):
 # Separately implemented declarative ABI oracle; never calls probe code.
 if status:return status&0xffffffff,False
 if u32(b,28)==71:return (-308)&0xffffffff,True
 if u32(b,28)!=602:return (-301)&0xffffffff,True
 if not(u32(b,0)&0x80000000):
  result=u32(b,40)
  return(result if u32(b,4)==44 and result!=0 and u64(b,8)==0 else(-300)&0xffffffff),True
 valid=u32(b,32)==2 and u32(b,4)==392 and u64(b,8)==0 and b[47]==b[63]==1 and u32(b,48)==u32(b,384)and u32(b,64)==u32(b,388)
 return(0 if valid else(-300)&0xffffffff),not valid

def main():
 src=json.loads((ROOT/'rpc502_reply_bridge_source.json').read_text());assert src==recover()
 prof=json.loads((ROOT/'rpc502_reply_bridge_profiles.json').read_text());assert prof['generator_sha256']==sha(ROOT/'probe_rpc502_reply_bridge.py')
 for n,h in prof['dependencies'].items():assert sha(ROOT/n)==h
 totals=Counter();ki=Image();dv=View();count=Counter()
 for j,r in enumerate(prof['cases']):
  totals.update(Replay(ki if r['kind']=='kext_reply'else dv,r).run());count[r['kind']]+=1
  b=bytes.fromhex(next(x['bytes_hex']for x in r['initial_private_fixtures']if int(x['address'],16)==int(r['entry_SP'],16)+8))if r['kind']=='kext_reply'else None
  if r['kind']=='kext_reply':
   status=r['configuration']['transport_status'];answer,destroy=expected(b,status);assert r['status_u32']==answer,(j,answer,r['status_u32']);models=[m['symbol']for m in r['API_models']]
   if status:assert models==(['MIG_put_noop_model']if status in [0x10000002,0x10000003,0x10000010]else['MIG_dealloc_noop_model'])
   else:assert models==(['message_destroy_request_only']if destroy else[])
   if answer==0:
    assert r['record0_hex']==b[76:212].hex()and r['record1_hex']==b[212:384].hex();want=struct.pack('<QIQI',u64(b,36),u32(b,48),u64(b,52),u32(b,64));assert r['OOL_outputs_hex']==want.hex();count['accepted']+=1
    # No data fetch from either OOL value; inline NDR and copy flags not inspected.
    assert not any(0x6500050000<=int(x['address'],16)<0x6500070000 for x in r['source_reads'])
   else:
    assert r['record0_hex']==('a5'*136)and r['record1_hex']==('a5'*172)and r['OOL_outputs_hex']==('a5'*24);count['outputs_unchanged']+=1
   if destroy:
    assert int(r['API_models'][0]['arguments8'][0],16)==int(r['entry_SP'],16)+8;count['destroy_requests']+=1
  elif r['kind']=='daemon_completion':
   cfg=r['configuration'];out=bytes.fromhex(r['reply_storage_hex']);status=cfg['application_status'];assert u32(out,20)==602 and u32(out,8)==203 and u32(out,12)==u32(out,16)==0
   if status:
    assert u32(out,0)==18 and u32(out,4)==36 and out[24:32]==bytes.fromhex('0000000001000000')and u32(out,32)==status&0xffffffff;count['simple_errors']+=1
   else:
    assert u32(out,0)==0x80000012 and u32(out,4)==384 and u32(out,24)==2 and u32(out,36)==u32(out,52)==0x01000101 and out[60:68]==bytes.fromhex('0000000001000000')and u32(out,40)==u32(out,376)==cfg['count0']and u32(out,56)==u32(out,380)==cfg['count1'];count['complex_emissions']+=1
 for join in prof['declared_transfers']:
  em=prof['cases'][join['emitter_case']];kr=prof['cases'][join['consumer_case']];u=bytes.fromhex(em['reply_storage_hex']);b=bytes.fromhex(next(x['bytes_hex']for x in kr['initial_private_fixtures']if int(x['address'],16)==int(kr['entry_SP'],16)+8));n=u32(u,4)
  assert b[32:n+8]==u[24:n]and u32(b,4)==n+8 and u32(b,28)==u32(u,20)and u64(b,8)==0 and not join['native_transfer_established'];count['declared_transfers']+=1
 assert count=={'demux_prefix':1,'daemon_completion':7,'kext_reply':28,'accepted':7,'outputs_unchanged':21,'destroy_requests':15,'complex_emissions':4,'simple_errors':3,'declared_transfers':7},dict(count)
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['rpc502_reply_bridge_source.json','rpc502_reply_bridge_profiles.json','recover_rpc502_reply_bridge.py','replay_kernel_vm_mig.py','replay_rpc502_bridge_daemon.py']},'verified_counts':dict(count),'independent_A64_replay':dict(totals),'source_recapture_match':True,'all_checks_pass':True,'native_target_executed':False,'native_IPC_executed':False,'native_application_execution_established':False,'native_descriptor_conversion_established':False,'native_OOL_cleanup_executed':False,'complete_FairPlay_round_trip_established':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'rpc502_reply_bridge_checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'counts':dict(count),'replay':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
