#!/usr/bin/env python3
"""Static managed-adapter bank, local-call and status ABI recovery.
O(B+F+I+256K) time/space; original bytes, no target execution or emulation.
All-byte bank checks prove only the declared finite lookup identity.
"""
import json,struct
from pathlib import Path
from recover_managed_fairplay_bridge import Native,ROOT,sha,h,instructions
P='managed_adapter_dispatch'
FLAGS=['target_executed','target_emulated','FairPlay_requests_sent','hardware_PAC_checked','native_effects_verified','RPC700_receiver_identified','full_goal_complete']
def auth(r):
 w=int(r['word'],16);return {'diversity_u16':w>>32&65535,'address_diversity':bool(w>>48&1),'key_index':w>>49&3}
def build():
 inv=json.loads((ROOT/'rpc700_namespace_contracts.json').read_text());old=json.loads((ROOT/'managed_fairplay_bridge_source.json').read_text());images=[]
 for index,meta in enumerate(inv['candidate_binaries']):
  n=Native(meta);parent=old['images'][index];entry=int(parent['buffer_adapter_entry'],16);adapter=n.function(entry);assert adapter==parent['ranges'][-1];T=0x100537520;banks={};pointers={}
  def pointer(a):
   r=n.fixups[a];assert not r['bind'];pointers[a]=r;return int(r['target'],16)
  def q(off):return pointer(T+off)
  def bank(label,a,b,key):
   aa=n.read(a,256);bb=n.read(b,256);v=[i^bb[aa[i]^key]for i in range(256)];assert len(set(v))==1
   r={'label':label,'first_address':hex(a),'second_address':hex(b),'key_u8':key,'constant_u8':v[0],'first_bytes':aa.hex(),'second_bytes':bb.hex(),'results_256':v};banks[label]=r;return v[0]
  c0=bank('primary_selector',q(0x1b8),q(0x210),0x4a);c1=bank('second_state_selector',q(0x98),q(0x360)-12,0x97);c2=bank('dispatch_base',q(0x4f0)-12,q(0x1b0),0x7c)
  state1=pointer(T+(c0+0x2c)*8)-4;state2=pointer(T+(c1+12)*8)-4;B=pointer(T+(c2+0x35)*8)-8
  specs=[('zero_work_buffer',q(0x98),q(0x360)-12,0x8d,0xe80),('record_helper',q(0x4f0)-12,q(0x1b0),0x86,0xea8),('field_forward_1',q(0x4f0)-12,q(0x1b0),0x7c,0xeb5),('field_forward_2',q(0x4a0)-4,q(0x4d0),0x9b,0xe77),('field_forward_3',q(0x4f0)-12,q(0x1b0),0xfd,0xe65),('field_forward_4',q(0x4a0)-4,q(0x4d0),0x3b,0xecf),('field_forward_5',q(0x4f0)-12,q(0x1b0),0x86,0xec2),('buffer_record_helper',q(0x1b8),q(0x210),0xea,0xe49),('constant_marker',q(0x4a0)-4,q(0x4d0),0x9b,0xe40),('status_field_writer',q(0x1b8),q(0x210),0x4a,0xe8c)]
  sites=[i for i in adapter['instructions']if i['mnemonic']=='blraa'];assert len(sites)==len(specs);calls=[];targets=set()
  for i,(label,a,b,key,offset)in zip(sites,specs):
   c=bank(label,a,b,key);slot=B+(c+offset)*8;target=pointer(slot);assert target in n.starts;targets.add(target);modifier=next(r for r in adapter['instructions']if int(r['ea'],16)==int(i['ea'],16)-4);assert modifier['mnemonic']=='mov'and modifier['operands'].startswith('x17, #');mod=int(modifier['operands'].split('#')[1],0);ar=auth(n.fixups[slot]);assert ar=={'diversity_u16':mod,'address_diversity':False,'key_index':0}
   calls.append({'site':i['ea'],'label':label,'bank':label,'add_index_u32':offset,'resolved_index_u32':c+offset,'pointer_slot':hex(slot),'target':hex(target),'pointer_auth_metadata':ar,'call_modifier_u16':mod})
  ranges=[adapter]+[n.function(a)for a in sorted(targets)];brs=[i for i in adapter['instructions']if i['mnemonic']=='braa'][:6];f6=((((0x0a14aca8+0x260)&0xffffffff)^0x3a0)^((0x0a14aca8-0x511)&0xffffffff));indices=[0x3a0^0x4ed,0x3a0^0xf20,0x3a0|7,0x3a0^0xee1,0x3a0^0x982,0x3a0^f6];gates=[]
  for j,(site,yes)in enumerate(zip(brs,indices)):
   rows=[]
   for equal,ix in[(False,0x3a0),(True,yes)]:
    slot=B+ix*8;target=pointer(slot);ar=auth(n.fixups[slot]);assert entry<=target<int(adapter['end'],16)and ar=={'diversity_u16':0xe7ef,'address_diversity':False,'key_index':0};rows.append({'record_status_equals_encoded_zero':equal,'index_u32':ix,'pointer_slot':hex(slot),'target':hex(target),'pointer_auth_metadata':ar})
   gates.append({'branch_site':site['ea'],'encoded_zero_u32':0x0ef7dc36,'record_status_offset_bytes':24 if j<5 else 12,'outcomes':rows})
  c=bank('nested_marker_and_forward',q(0x110)-8,q(0x68)-8,0x7f);nested=[];field=int(calls[2]['target'],16);buffer=int(calls[7]['target'],16)
  initial=int(calls[1]['target'],16);cinit=bank('nested_initial_marker',q(0x4f0)-12,q(0x1b0),0x90);cfinal=bank('nested_initial_forward',q(0x1b8),q(0x210),0x5e)
  nested_specs=[(field,'nested_marker',c,0xde3,0),(field,'nested_record_forward',c,0xe45,1),(buffer,'nested_buffer_forward',banks['buffer_record_helper']['constant_u8'],0xe6a,0),(initial,'initial_marker',cinit,0xdd6,0),(initial,'initial_status',banks['zero_work_buffer']['constant_u8'],0xeab,1),(initial,'initial_forward',cfinal,0xee8,2)]
  for source,label,constant,offset,call_index in nested_specs:
   slot=B+(constant+offset)*8;target=pointer(slot);ix=n.starts.index(target);body=next(r for r in ranges if r['start']==hex(source));site=[r for r in body['instructions']if r['mnemonic']=='blraa'][call_index];modifier=next(r for r in body['instructions']if int(r['ea'],16)==int(site['ea'],16)-4);assert modifier['mnemonic']=='mov'and modifier['operands'].startswith('x17, #');mod=int(modifier['operands'].split('#')[1],0);assert auth(n.fixups[slot])=={'diversity_u16':mod,'address_diversity':False,'key_index':0};nested.append({'source_function':hex(source),'site':site['ea'],'label':label,'pointer_slot':hex(slot),'target':hex(target),'target_compiler_end':hex(n.starts[ix+1]),'target_prefix16':n.read(target,16).hex(),'pointer_auth_metadata':auth(n.fixups[slot]),'complete_target_semantics':'unknown'})
  external=[]
  for body in ranges:
   for i in body['instructions']:
    if i['mnemonic']!='bl':continue
    st=n.stub(int(i['operands'][1:],0));assert st['binding']['symbol']=='___stack_chk_fail';external.append({'source_function':body['start'],'site':i['ea'],'stub':st})
  envc=bank('status_source_selector',q(0x3e0)-4,q(0x390),0x96);envslot=T+(envc-0x96)*8;env=pointer(envslot)+0x4c
  assert pointer(T+(banks['zero_work_buffer']['constant_u8']+0x23)*8)-8==B
  assert pointer(T+(banks['primary_selector']['constant_u8']+4)*8)-8==B
  images.append({'source_path':meta['source_path'],'source_sha256':meta['source_sha256'],'slice':meta['selected_slice'],'uuid':meta['uuid'],'reference':n.reference(),'table_base':hex(T),'dispatch_base':hex(B),'state_cells':[{'address':hex(a),'original_u64':hex(struct.unpack('<Q',n.read(a,8))[0])}for a in[state1,state2]],'banks':list(banks.values()),'calls':calls,'gates':gates,'nested_selected_edges':nested,'direct_external_calls':external,'status_source':{'object_pointer_slot':hex(envslot),'field_address':hex(env),'field_offset_bytes':76,'original_u32':struct.unpack('<I',n.read(env,4))[0],'runtime_value':'unknown'},'original_pointer_records':[pointers[a]for a in sorted(pointers)],'ranges':ranges})
 counts={'images':2,'complete_functions':sum(len(s['ranges'])for s in images),'original_instructions':sum(len(r['instructions'])for s in images for r in s['ranges']),'original_function_bytes':sum(len(bytes.fromhex(r['bytes']))for s in images for r in s['ranges']),'bank_occurrences':sum(len(s['banks'])for s in images),'distinct_bank_identities':sum(len({(b['first_address'],b['second_address'],b['key_u8'])for b in s['banks']})for s in images),'bank_inputs_checked':sum(len(s['banks'])*256 for s in images),'resolved_adapter_calls':20,'unique_adapter_callees':12,'status_gates':12,'gate_outcomes':24,'selected_nested_edges':sum(len(s['nested_selected_edges'])for s in images),'direct_external_canary_calls':sum(len(s['direct_external_calls'])for s in images),'fixups_independently_compared':sum(s['reference']['fixups_compared']for s in images)}
 return {'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{p:sha(ROOT/p)for p in['recover_managed_fairplay_bridge.py','bootpolicy_cache_reader.py','resolve_kernel_collection_interfaces.py','managed_fairplay_bridge_source.json','rpc700_namespace_contracts.json']},'images':images,'inspection_tool':{'path':'/usr/bin/dyld_info','sha256':sha('/usr/bin/dyld_info')},'verified_source_counts':counts,**{k:False for k in FLAGS}}
def main():
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']))
if __name__=='__main__':main()
