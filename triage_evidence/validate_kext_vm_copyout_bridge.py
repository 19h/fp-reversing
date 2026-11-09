#!/usr/bin/env python3
"""Original kext/VM adapter ABI, complete call/return state and ownership requests.
O(image+visits+RAM+effects) time, O(image+RAM+journals) space. Conditional private
CPU components do not establish native IPC, allocator state or PAC authentication.
"""
import json,struct,hashlib
from collections import Counter
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT,IMAGE
from recover_aes_command_gate import sha
from replay_rpc502_vm_handoff import decode
from replay_kext_vm_copyout_bridge import VMReplay,KextReplay
P='kext_vm_copyout_bridge';R=0x6500000000;COPY=R+0x68000;BACK=R+0x78000;MAPPED=R+0xa8000;THREAD=R+0x2c000;KMAP=R+0x2e000;C=R+0x20000;CHILD=R+0x22000;PORT=R+0x83000;REQCOPY=R+0xb8000
FLAGS=['native_target_executed','native_VM_effects_executed','native_retirement_executed','native_namespace_conversion_executed','native_IPC_executed','hardware_PAC_executed','idb_mutated','complete_FairPlay_round_trip_established','full_goal_complete']
def val(b,o,n=8):return int.from_bytes(b[o:o+n],'little')
def globals_bytes(row,key):return{e['address']:e['bytes_hex']for e in row[key]}
def ram_at(r,a,n):return decode(r['final_private_RAM'])[a-R:a-R+n]
def main():
 im=Image();src=json.loads((ROOT/(P+'_source.json')).read_text());prof=json.loads((ROOT/(P+'_profiles.json')).read_text());counts=Counter();totals=Counter();summaries=[]
 for obj,name in[(src,'recover_'+P+'.py'),(prof,'probe_'+P+'.py')]:
  assert obj['generator_sha256']==sha(ROOT/name)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h
  assert all(obj[k]is False for k in FLAGS)
 assert im.k.sha256==src['kernel_sha256']and len(src['functions'])==23 and sum(len(f['instructions'])for f in src['functions'])==4492
 for f in src['functions']:
  a=int(f['start'],16);b=im.k.read(a,int(f['end'],16)-a)
  assert b.hex()==f['bytes']and im.k.symbols([a])[hex(a)]==f['exact_symbols']and[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in im.k.cs.disasm(b,a)]==f['instructions']
 assert len(src['kext_ranges'])==15 and sum(len(f['instructions'])for f in src['kext_ranges'])==4492
 for f in src['kext_ranges']:
  a=int(f['start'],16);n=int(f['end'],16)-a;b=im.k.read(a,n)
  assert b==IMAGE.read(a,n)and b.hex()==f['bytes_hex']and hashlib.sha256(b).hexdigest()==f['sha256']and[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in im.k.cs.disasm(b,a)]==f['instructions']
 bindings={int(e['adapter'],16):e for e in src['kext_VM_adapters']};assert len(bindings)==4
 for a,e in bindings.items():
  assert im.k.read(a,8).hex()==e['adapter_bytes8_hex']and im.k.read(int(e['stub_start'],16),16).hex()==e['stub_bytes16_hex']and im.pointer(int(e['pointer']['slot'],16))==e['pointer']and im.k.symbols([int(e['pointer']['target'],16)])[e['pointer']['target']]==e['target_exact_symbols'];counts['original_adapter_slot_bindings_checked']+=1
 for e in src['exact_instruction_roles'].values():assert im.k.read(int(e['pc'],16),4).hex()==e['bytes_hex']
 rows=prof['cases'];assert len(rows)==8;payload=bytes((17+37*j)&255 for j in range(4096));name=bytes(range(0x21,0x3d))+b'\0'
 producer=rows[0];header=ram_at(producer,COPY,48);assert val(header,0)==BACK and val(header,32)==4096 and val(header,44,4)==0x300 and ram_at(producer,BACK,4096)==payload
 assert ram_at(producer,R+0x69000,48)==b'\xa5'*48 and val(ram_at(producer,R+0x18040,392),52)==0;counts['source_produced_type3_object_and_empty_secondary_checked']=1
 prefix=rows[1];assert prefix['entry_PC']=='0xfffffe000a66a7e0'and prefix['initial_private_RAM_transfer']is None
 regions=prefix['VM_region_imports'];assert[(int(e['address'],16),e['size_bytes'])for e in regions]==[(R+0x2a000,256),(THREAD,0x600),(KMAP,256),(COPY,48),(BACK,4096),(R+0x86000,64),(R+0x88000,16),(R+0x9be00,0x400)]
 live=[(int(e['address'],16),e['size_bytes'])for e in prefix['allocations']]+[(R+0x70000,16384),(R+0x90000,29),(R+0x81000,8),(REQCOPY,8),(MAPPED,16384)]
 for k,e in enumerate(regions):
  a=int(e['address'],16);n=e['size_bytes'];assert e['producer_case']==0 and e['bytes_hex']==ram_at(producer,a,n).hex()==ram_at(prefix,a,n).hex()
  for f in regions[k+1:]:b=int(f['address'],16);assert a+n<=b or b+f['size_bytes']<=a
  for b,m in live:assert a+n<=b or b+m<=a
  counts['exact_disjoint_VM_region_imports_checked']+=1
 assert[(e['kind'],e['size_bytes'])for e in prefix['allocations']]==[('aligned',16384),('typed',4096),('data',172),('typed',152)]
 for a,h in globals_bytes(producer,'final_image_globals').items():assert globals_bytes(prefix,'initial_image_fixtures')[a]==h
 assert globals_bytes(prefix,'initial_image_fixtures')['0xfffffe0007f860a8']==struct.pack('<Q',KMAP).hex();counts['producer_globals_and_real_private_destination_map_checked']=1
 request=struct.pack('<IIQQIIIQII8sIQQQ',0x80001513,0,PORT,0,0,502,1,REQCOPY,0x01000100,29,bytes.fromhex('0000000001000000'),29,0x100000c,0,1)
 assert len(request)==88 and prefix['transport_request88_hex']==request.hex()and prefix['staging_extent_bytes']==16384 and prefix['staging_final_hex']==(name+bytes(16384-29)+b'\xa5').hex();counts['RPC502_request_and_separate_request_copy_identity_checked']=1
 reply=bytearray(392);struct.pack_into('<IIQQII',reply,0,0x80000000,392,0,0,0,602);struct.pack_into('<I',reply,32,2);struct.pack_into('<QII',reply,36,COPY,0x01000101,4096);struct.pack_into('<QII',reply,52,0,0x01000101,0);reply[68:76]=bytes.fromhex('0000000001000000');struct.pack_into('<I',reply,76,0xbeefed02);struct.pack_into('<II',reply,384,4096,0)
 assert prefix['declared_reply392_hex']==reply.hex();counts['declared_internal_reply_602_contract_checked']=1
 for m in prefix['API_models']:
  sym=m['symbol'];args=[int(v,16)for v in m['arguments8']];want=[];result=0
  if sym=='aligned_allocation_model':assert args[:2]==[16384,64];result=R+0x10000
  elif sym=='allocation_model':
   table={0xfffffe000a66aa1c:(0xfffffe000847bea0,R+0x20000),0xfffffe000a60aa40:(172,R+0x21000),0xfffffe000a60ab2c:(0xfffffe000847bd60,CHILD)};arg,result=table[int(m['pc'],16)];assert args[0]==arg
  elif sym=='host_priv_self_model':result=R+0x82000
  elif sym=='host_special_port_model':assert args[:4]==[R+0x82000,0xffffffff,17,C+0x18];want=[(C+0x18,struct.pack('<Q',PORT))]
  elif sym=='strlen_model':assert args[0]==R+0x90000;result=28
  elif sym=='kmem_alloc_model':assert args[:3]==[R+0x85000,C+0x80,16384];want=[(C+0x80,struct.pack('<Q',R+0x70000))]
  elif sym=='memcpy_model':assert args[:3]==[R+0x70000,R+0x90000,29];result=R+0x70000;want=[(args[0],name)]
  elif sym=='vm_map_copyin_model':assert args[:5]==[R+0x85000,R+0x70000,29,0,C+0x28];want=[(C+0x28,struct.pack('<Q',REQCOPY))]
  else:assert sym=='transport_reply_model'and args[:3]==[R+0xefa78,88,400];want=[(args[0],bytes(reply))]
  assert int(m['return_value'],16)==result and[(int(e['address'],16),bytes.fromhex(e['after_hex']))for e in m['memory_effects']]==want;counts['kext_prefix_primitive_effect_oracles_checked']+=1
 pairs=[(1,2),(2,3),(1,4),(4,5),(5,6),(6,7)]
 for a,b in pairs:
  before=rows[a];after=rows[b];transfer=after['initial_private_RAM_transfer'];assert transfer['producer_case']==a and decode(transfer)==decode(before['final_private_RAM'])
  assert after['entry_PC']==before['boundary']['pc']and after['entry_registers31']==before['boundary']['registers31']and after['entry_SP']==before['boundary']['SP']and after['entry_NZCV']==before['boundary']['NZCV']and after['entry_Q_registers32']==before['final_Q_registers32']
  assert globals_bytes(after,'initial_image_fixtures')==globals_bytes(before,'final_image_globals')and after['initial_private_fixtures']==[];counts['exact_full_RAM_GP_SP_NZCV_SIMD_global_call_return_transfers_checked']+=1
 for j in[2,4,6]:
  r=rows[j];a=int(r['entry_PC'],16);e=bindings[a];edge=r['logical_adapter_edges'];assert len(edge)==1 and edge[0]['pc']==hex(int(e['stub_start'],16)+12)and edge[0]['target']==e['pointer']['target']and edge[0]['modifier']==e['pointer']['slot']
  idx=edge[0]['source_visit_index'];assert idx==5 and r['source_visits'][idx+1]['pc']==e['pointer']['target'];counts['original_adapter_and_kernel_tail_transitions_checked']+=1
  assert r['boundary']['registers31'][18:]==r['entry_registers31'][18:]and r['boundary']['SP']==r['entry_SP']and r['boundary']['pc']==r['entry_registers31'][30]==r['bridge_return_PC']
  assert all(int(r['entry_Q_registers32'][q],16)&((1<<64)-1)==int(r['final_Q_registers32'][q],16)&((1<<64)-1)for q in range(8,16));counts['callee_saved_GP_SP_SIMD64_and_actual_return_PC_checked']+=1
  assert r['destination_map_refs']==3 and r['current_map']==hex(R+0x2a000);counts['restored_map_context_and_reference_fixture_checked']+=1
 assert prefix['boundary']['registers31'][:3]==[hex(KMAP),hex(R+0xefea0),hex(COPY)]and int(prefix['boundary']['registers31'][29],16)-0x80==R+0xefea0
 assert prefix['calls'][-1]['pc']=='0xfffffe000a60d61c'and prefix['calls'][-1]['target']=='0xfffffe000a508e34';counts['original_copyout_caller_dynamic_stack_output_ABI_checked']=1
 good=rows[2];bad=rows[4];assert good['boundary']['registers31'][0]=='0x0'and good['bridge_output_u64']==MAPPED and good['bridge_mapped4096_hex']==payload.hex()and ram_at(good,COPY,48)==bytes(48)
 assert bad['boundary']['registers31'][0]=='0x6'and bad['bridge_output_u64']==0 and ram_at(bad,COPY,48)==header and bad['bridge_backing4096_hex']==payload.hex()and bad['bridge_mapped4096_hex']==bytes(4096).hex();counts['copyout_success_consumption_and_error_preservation_checked']=1
 for j in[2,6]:
  r=rows[j];free=next(m for m in r['API_models']if m['symbol']=='backing_release_request');zone=next(m for m in r['API_models']if m['symbol']=='copy_header_release_request')
  assert free['arguments8'][:3]==['0xfffffe0007f8bfb0',hex(BACK),'0x1000']and zone['arguments8'][:4]==[hex(R+0x86000),hex(R+0x88000),hex(COPY),'0x30']and ram_at(r,COPY,48)==bytes(48);counts['backing_and_header_release_requests_checked']+=1
 child=bytearray(152);struct.pack_into('<I',child,0,0xbeefed02);struct.pack_into('<Q',child,0x48,MAPPED);struct.pack_into('<I',child,0x50,4096)
 wire=rows[3];assert wire['final_child152_hex']==child.hex()and wire['boundary']['pc']=='0xfffffe000a508e0c'and wire['boundary']['registers31'][:5]==[hex(KMAP),hex(MAPPED),hex(MAPPED+16384),'0x3','0x0']and wire['calls'][-1]['pc']=='0xfffffe000a6124c0'and not wire['API_models'];counts['installed_child_fields_and_page_rounded_wire_frontier_checked']=1
 failed=rows[5];assert failed['boundary']['pc']=='0xfffffe000a508e24'and failed['boundary']['registers31'][0]==hex(COPY)and failed['calls'][-1]['pc']=='0xfffffe000a611790'and failed['final_child152_hex']==prefix['final_child152_hex'];counts['original_error_to_discard_call_join_checked']=1
 release=rows[7];assert rows[6]['boundary']['pc']=='0xfffffe000a611794'and release['boundary']['pc']=='0xfffffe000bcd0448'and release['boundary']['registers31'][0]==hex(PORT)and release['calls'][-1]['pc']=='0xfffffe000a615f2c'and release['boundary']['registers31'][30]=='0xfffffe000a615f30'
 assert release['calls'][-2]['pc']=='0xfffffe000a615ed4'and release['calls'][-2]['args8'][:3]==[hex(R+0x85000),hex(R+0x70000),'0x4000']and[m['symbol']for m in release['API_models']]==['request_staging_free_model'];counts['discard_return_staging_free_and_destination_release_frontier_checked']=1
 assert im.k.symbols([0xfffffe000bcd0448])['0xfffffe000bcd0448'][0]['name']=='_ipc_port_release_send'
 for j in[1,3,5,7]:
  scratch=bytes.fromhex(rows[j]['final_scratch160_hex']);assert val(scratch,0x18)==PORT and val(scratch,0x28)==REQCOPY and val(scratch,0x90)==COPY;counts['port_request_copy_and_stale_reply_pointer_distinguished_checked']+=1
 for j,row in enumerate(rows):
  assert all(row[k]is False for k in FLAGS)
  for v in row['source_visits']:
   a=int(v['pc'],16);raw=im.k.read(a,4);assert raw.hex()==v['bytes_hex']
   if 0xfffffe000a000000<=a<0xfffffe000b000000:assert IMAGE.read(a,4)==raw
   counts['every_dynamic_original_instruction_recaptured']+=1
  for k,m in enumerate(row['API_models']):
   want=[hex(((i+1)*0x123456789abcdef)^((k+1)*0x8b3dc651))for i in range(18)];want[0]=m['return_value'];assert m['after_registers31'][:18]==want and int(m['after_NZCV'],16)==(0xf0000000 if(k+1)&1 else 0)and m['native_effects_executed']is False;counts['deterministic_volatile_clobber_models_checked']+=1
  totals.update((KextReplay if row['bridge_phase'].startswith('kext')else VMReplay)(im,row).run());summaries.append({'case':j,'phase':row['bridge_phase'],'visits':len(row['source_visits']),'models':len(row['API_models']),'boundary':row['boundary']['pc']});print(json.dumps({**summaries[-1],'independent_replay':'pass'}),flush=True)
 counts.update(cases=8,kernel_functions=23,kernel_captured_instructions=4492,kext_ranges=15,kext_captured_instructions=4492)
 deps=[P+'_source.json',P+'_profiles.json','replay_'+P+'.py','replay_rpc502_vm_handoff.py','replay_kernel_reply_send.py','replay_kext_constructor_request.py','replay_kernel_vm_mig.py','kernel_vm_mig_tools.py','kext_port_tools.py'];out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'source_recapture_match':True,'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'case_summaries':summaries,'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'verified_counts':dict(counts),'independent_A64_replay':dict(totals),'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
