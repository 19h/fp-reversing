#!/usr/bin/env python3
"""Source-shaped context and original initial object/buffer/loop boundaries.
O(retained source events+selected original bytes) time/space; native AEE caller
and continuity from the common prelude remain unknown.
"""
import json,hashlib
from pathlib import Path
from daemon_receive_tools import ROOT,SOURCE,IMAGE,TABLE
from recover_daemon_object_creation import span,sha
from replay_daemon_descriptor_producers import unpack
def main():
 previous=json.loads((ROOT/'daemon_creation_predecessors_contracts.json').read_text());row=json.loads((ROOT/'daemon_object_consumers_profiles.json').read_text())['cases'][0];t=unpack(row);F=int(t['initial_SP'],16);memory={};writers={}
 def put(a,b,origin):
  for j,x in enumerate(b):memory[a+j]=x;writers[a+j]=origin
 for e in row['prefix']['initial_private_fixtures']:put(int(e['address'],16),bytes.fromhex(e['bytes_hex']),'retained initial caller fixture')
 for e in row['prefix']['source_writes']:put(int(e['address'],16),bytes.fromhex(e['after_hex']),e['pc'])
 for st in t['steps']:
  if st['pc']=='0x1009d077c':break
  for e in st['events']:
   if e['kind']=='write'and 'hex'in e['value']:put(int(e['address'],16),bytes.fromhex(e['value']['hex']),st['pc'])
 offsets=[0x2960,0x2968,0x2970,0x2978,0x2980,0x2988,0x2990,0x2998,0x2a78,0x2a80,0x2a88,0x2a90,0x29a0,0x3620,0x3690,0x26c8,0x26e8,0x2728,0x26d0]
 offsets=sorted(set(offsets)|{int(x['offset'],16)for x in previous['frame_target_epoch_stores']if x['size_bytes']==8});fields=[]
 for o in offsets:
  a=F+o;assert all(a+j in memory for j in range(8));b=bytes(memory[a+j]for j in range(8));fields.append({'offset':hex(o),'size_bytes':8,'bytes_hex':b.hex(),'u64':hex(int.from_bytes(b,'little')),'last_byte_writers':sorted({writers[a+j]for j in range(8)})})
 cursor=next(x for x in fields if x['offset']=='0x3620');assert cursor['u64']=='0x30'and cursor['last_byte_writers']==['0x100a59d80']
 specs=[('cursor_producer',0x100a59d74,0x100a59d84),('allocation_success',0x1006534bc,0x10065364c),('scratch_loop',0x100a19bb8,0x100a19cd8),('first_fields_buffer48',0x10094c688,0x10094c790),('classifier_consumer',0x10095784c,0x100957a58)]
 providers=[]
 for j,r in enumerate(json.loads((ROOT/'daemon_buffer_consumer_profiles.json').read_text())['cases'][:4]):
  data={}
  for e in r['consumer_events']:
   a=int(e['address'],16);nb=e['size_bytes'];key='after_hex'if e['kind']=='write'else'bytes_hex';b=bytes.fromhex(e[key])
   if 0x101000000<=a<a+nb<=0x102000000:
    for k,x in enumerate(b):data[a+k]=x
  read=lambda a,n:bytes(data[a+k]for k in range(n));state=read(0x1010c784c,2496);index=read(0x1010c67dc,4);counter=read(0x1010c8258,4)
  providers.append({'provider_case_index':j,'source_input':r['input'],'physical_pattern':r['pattern'],'source_stream_sha256':r['source_stream_sha256'],'state_address':'0x1010c784c','state_bytes_hex':state.hex(),'index32':int.from_bytes(index,'little'),'counter32':int.from_bytes(counter,'little'),'published_buffer512_hex':r['final_buffer_bytes_hex'],'encoded_window_mask64':hex(int.from_bytes(read(0x1010c6800,8),'little')),'encoded_window_base64':hex(int.from_bytes(read(0x1010ca2a8,8),'little')),'native_temporal_continuity':'unknown'})
 deps=['daemon_creation_predecessors_contracts.json','daemon_object_consumers_profiles.json','daemon_buffer_consumer_contracts.json','daemon_buffer_consumer_profiles.json']
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in deps},'source_sha256':sha(SOURCE),'retained_SP':hex(F),'retained_common_registers':previous['retained_source_contexts'][0]['common_end_registers'],'source_frame_fields':fields,'retained_cursor_write':next(e for e in row['prefix']['source_writes']if e['pc']=='0x100a59d80'),'spans':[span(n,a,z)for n,a,z in specs],'coherent_provider_snapshots':providers,'interface_leads':{'cache_pointer_cell':'0x1010c8268','mask32_cell':'0x1010c67d4','marker_cell':'0x1010c8254','candidate_classifier_field':'object+0xcc','candidate_buffer48_field':'object+0xd8','native_upstream_AEE_entry':'unknown'},'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'daemon_object_initialization_context.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'source_frame_fields':len(fields),'cursor_bytes':48,'source_spans':len(specs),'provider_snapshots':len(providers)}),flush=True)
if __name__=='__main__':main()
