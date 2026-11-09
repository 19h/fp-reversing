#!/usr/bin/env python3
"""Original allocation/initialization, borrowed span and failure frontiers.
Exact fixups, source ledgers and compile-only reconstructed layout checks.
O(source/profile bytes) time, O(source ledger + largest profile) space.
"""
import json,subprocess
from pathlib import Path
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,TABLE
from daemon_output_base_dispatch import CS
from daemon_import_bindings import binding
from capture_daemon_record720 import sha
from recover_daemon_descriptor_producers import verify_used_fixups
from recover_daemon_entitlement_flow import snapshot
FILES=['daemon_client_object_profiles.json','daemon_client_object_pair_profiles.json','daemon_client_object_cleanup_profiles.json']
SPANS=[('malloc32_pointer',0x10057014c,0x10057017c),('initialize32',0x1005596ac,0x100559724),('borrowed_pointer_gate',0x100559724,0x10055975c),('input_context',0x1006997a4,0x1006997f8),('malloc16_pointer',0x10069985c,0x10069988c),('initialize16',0x1008c3880,0x1008c38a4),('remaining_length',0x1006d54e8,0x1006d5538),('span_pointer_gate',0x1008cf2d8,0x1008cf328),('remaining_threshold',0x10076b268,0x10076b2a4),('borrowed_read_frontier',0x100670430,0x100670474),('allocation_failure_status',0x1004de1d4,0x1004de208),('outer_status_gate',0x1007fb760,0x1007fb7b0),('zero_output_stores',0x10057a770,0x10057a780),('cleanup_task_and_call',0x100477624,0x1004776d0)]
def recover():
 source={};used=set();rows=[];groups={n:json.loads((ROOT/n).read_text())for n in FILES}
 for group,p in groups.items():
  for c in p['cases']:
   alloc=c['client_object_allocations'];cut=alloc[0]['source_visit_index'];row={'group':group,'configuration':c['configuration'],'allocations':alloc,'boundary':c['boundary'],'allocation_API_events':[e for e in c['API_model_events']if e['pc']in ['0x100570148','0x100699858']],'post_allocation_edges':[e for e in c['logical_edges']if e['source_visit_index']>=cut],'post_allocation_writes':[e for e in c['source_writes']if e['source_visit_index']>=cut],'object':c.get('client_object_final'),'pair':c.get('client_pair_final'),'input_record':snapshot(c,0x6800001000,72),'frame_cells':{hex(off):snapshot(c,0x680004f230+off,n)for off,n in [(0x990,8),(0x82d8,8),(0x3650,8),(0x2ff8,8),(0x3818,8),(0x4d50,8),(0x7550,4),(0x44a4,4),(0x1930,8),(0x1a30,8),(0x7098,8)]}}
   rows.append(row)
   for e in c['source_visits']:
    at=int(e['pc'],16);assert IMAGE.read(at,4).hex()==e['bytes_hex'];source[e['pc']]=e['bytes_hex']
   for e in c['source_reads']:
    at=int(e['address'],16)
    if at in FIXUPS and e['size_bytes']==8:used.add(at)
 edges=[]
 for pc in [0x100570178,0x100559758,0x100699888,0x1008c38a0,0x1006d5534,0x1008cf324,0x10076b2a0]:
  found={(e['target'],e['modifier'])for r in rows for e in r['post_allocation_edges']if int(e['pc'],16)==pc}
  for target,modifier in sorted(found):
   candidates=[at for at in used if FIXUPS[at]['target']==int(target,16)and int.from_bytes(IMAGE.read(at,8),'little')>>32&65535==int(modifier,16)]
   assert len(candidates)==1,(hex(pc),target,candidates);at=candidates[0];word=int.from_bytes(IMAGE.read(at,8),'little');assert word>>63==1 and(word>>48)&7==0
   edges.append({'pc':hex(pc),'target':target,'modifier':modifier,'slot':hex(at),'index':hex((at-TABLE)//8),'original_word_hex':IMAGE.read(at,8).hex()})
 for label,pc,index,modifier in [('borrowed_pointer_NULL',0x100559758,0x6cd0,0xf2ab),('length_not_above_cursor',0x1006d5534,0xa62b,0xd638),('span_pointer_NULL',0x1008cf324,0x9b55,0x1758),('remaining_at_most_nine',0x10076b2a0,0x1a25,0x23e6)]:
  at=TABLE+8*index;w=int.from_bytes(IMAGE.read(at,8),'little');assert w>>63==1 and(w>>32)&65535==modifier and(w>>48)&7==0;used.add(at);edges.append({'label':label,'pc':hex(pc),'target':hex(FIXUPS[at]['target']),'modifier':hex(modifier),'slot':hex(at),'index':hex(index),'original_word_hex':IMAGE.read(at,8).hex(),'observed_in_profiles':False})
 extra=[('cleanup_owner_save',0x1005aa750,0x1005aa75c),('cleanup_task_address_size',0x100477640,0x100477654),('cleanup_size_codec',0x100477690,0x1004776a8)]
 spans=[{'name':n,'start':hex(a),'bytes_hex':IMAGE.read(a,z-a).hex(),'instructions':[{'pc':hex(i.address),'assembly':i.mnemonic+' '+i.op_str}for i in CS.disasm(IMAGE.read(a,z-a),a)]}for n,a,z in SPANS+extra]
 sdk=Path(subprocess.run(['xcrun','--sdk','macosx','--show-sdk-path'],check=True,capture_output=True,text=True).stdout.strip());cmd=['xcrun','--sdk','macosx','clang','-target','arm64e-apple-macos11.0','-isysroot',str(sdk),'-S','-emit-llvm','-O1','-Werror',str(ROOT/'daemon_client_object_sdk.c'),'-o',str(ROOT/'daemon_client_object_sdk.ll')];result=subprocess.run(cmd,capture_output=True,text=True);assert result.returncode==0,(result.stdout,result.stderr)
 ir=(ROOT/'daemon_client_object_sdk.ll').read_text();assert '@vm_deallocate(i32'in ir and'zext i32'in ir
 return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in FILES+['daemon_client_object_sdk.c','recover_daemon_entitlement_flow.py']},'groups':{n:len(p['cases'])for n,p in groups.items()},'source_spans':spans,'unique_visited_source':source,'profile_ledgers':rows,'dispatch_edges':edges,'original_fixups':verify_used_fixups(used),'binds':[binding(at)for at in sorted(used)if FIXUPS[at]['kind'].endswith('bind')],'SDK_layout':{'path':str(sdk),'command':cmd,'exit_code':result.returncode,'LLVM_file':'daemon_client_object_sdk.ll','LLVM_sha256':sha(ROOT/'daemon_client_object_sdk.ll'),'target_runtime_version_matched':False,'reconstructed_private_layout_is_not_an_exported_header':True},'native_target_executed':False,'native_allocator_executed':False,'native_owner_extents_established':False,'full_goal_complete':False}
if __name__=='__main__':
 r=recover();(ROOT/'daemon_client_object_contracts.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'groups':r['groups'],'unique_source':len(r['unique_visited_source']),'dispatch_edges':r['dispatch_edges'],'SDK_exit':r['SDK_layout']['exit_code']}),flush=True)
