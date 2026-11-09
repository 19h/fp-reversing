#!/usr/bin/env python3
"""Original Boolean key/record epochs, fixed-selector bridge ABI, shared
roots, state update, status and exact fixup/bank/layout evidence.
O(source/profile bytes) time, O(ledgers + largest profile) space.
Compile-only reconstructed SDK layout probe; no native target/framework/IPC.
"""
import json,subprocess
from pathlib import Path
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,POOL,TABLE,qword,selected
from capture_daemon_record720 import sha
from recover_daemon_descriptor_producers import verify_used_fixups
from daemon_import_bindings import binding
from recover_daemon_entitlement_flow import snapshot,copy_body
FILES=['daemon_boolean_chain_profiles.json','daemon_boolean_chain_mixed_profiles.json']
def recover():
 groups={n:json.loads((ROOT/n).read_text())for n in FILES};source={};used=set();rows=[];keys={}
 for group,p in groups.items():
  for c in p['cases']:
   for e in c['Boolean_adapters']:
    if'key'in e:keys[e['key']['ASCII']]=e['key']
   rows.append({'group':group,'configuration':c['configuration'],'source_visits':len(c['source_visits']),'boundary':c['boundary'],'Boolean_adapters':c['Boolean_adapters'],'state_writes':[e for e in c['source_writes']if e['address']=='0x6800055d0c'],'bridge_status_writes':[e for e in c['source_writes']if e['pc']=='0x1003fdcfc'],'bridge_status_reads':[e for e in c['source_reads']if e['pc']=='0x1007f7a88'],'bridge_phase_reads':[e for e in c['source_reads']if e['pc']=='0x1003455f0'],'final_state':snapshot(c,0x6800055d0c,4),'final_bridge_record':snapshot(c,0x680005fee8,24)})
   for s in c['source_visits']:
    at=int(s['pc'],16);assert IMAGE.read(at,4).hex()==s['bytes_hex'];source[s['pc']]=s['bytes_hex']
   for e in c['source_reads']:
    at=int(e['address'],16)
    if at in FIXUPS and e['size_bytes']==8:used.add(at)
 assert set(keys)=={'FairPlay-CoreML-Client','FairPlay-Classic-Client'}
 banks=[selected(0x100e99700,0x100f4e190,0x56,0x906,POOL,0xffffffffd0c4d1ee)];assert banks[0]['target']==hex(TABLE);l=(qword(POOL+0x6640)+0xffffffffdaeb98b6)&((1<<64)-1);r=(qword(POOL+0x4048)+0xffffffffb971d649)&((1<<64)-1);banks.append(selected(l,r,0x61,0xc69,POOL,0xffffffff8973db76));assert banks[1]['target']==keys['FairPlay-Classic-Client']['address']
 for b in banks:used.add(int(b['slot'],16))
 edges=[]
 for label,index,mod in [('state_pointer_NULL',0xb3d4,0x5cdc),('state_pointer_nonNULL',0xb3de,0x5cdc)]:
  at=TABLE+index*8;w=int.from_bytes(IMAGE.read(at,8),'little');assert w>>63==1 and(w>>32)&65535==mod and(w>>48)&7==0;used.add(at);edges.append({'label':label,'index':hex(index),'slot':hex(at),'modifier':hex(mod),'target':hex(FIXUPS[at]['target']),'original_word_hex':IMAGE.read(at,8).hex()})
 spans=[]
 for name,a,z in [('bridge_entry',0x1004586d8,0x100458710),('shared_root_update',0x1004587e4,0x100458824),('bridge_key_and_pointer',0x100458824,0x100458888),('pointer_index_scale',0x1004588c0,0x1004588d0),('pointer_index_join',0x1004588e0,0x100458904),('CoreML_return_and_Classic_setup',0x100345480,0x1003455e8),('pair_state_update',0x1003455e8,0x100345638),('bridge_status_route',0x100345638,0x100345674),('bridge_status_store',0x1003fdcfc,0x1003fdd38),('caller_status_load',0x1007f7a88,0x1007f7a8c),('caller_zero_phase',0x1008017b8,0x1008017d0),('caller_zero_compare',0x1008017ec,0x100801808)]:spans.append({'name':name,'start':hex(a),'bytes_hex':IMAGE.read(a,z-a).hex()})
 sample=next(c for c in groups[FILES[0]]['cases']if c['configuration']['Boolean_chain_model']=='boolean_true'and c['source_index']==0);copy=copy_body(sample,0x1003454f8);sdk=Path(subprocess.run(['xcrun','--sdk','macosx','--show-sdk-path'],check=True,capture_output=True,text=True).stdout.strip());cmd=['xcrun','--sdk','macosx','clang','-target','arm64e-apple-macos11.0','-isysroot',str(sdk),'-S','-emit-llvm','-O1','-Werror',str(ROOT/'daemon_boolean_chain_sdk.c'),'-o',str(ROOT/'daemon_boolean_chain_sdk.ll')];result=subprocess.run(cmd,capture_output=True,text=True);assert result.returncode==0,(result.stdout,result.stderr);ir=(ROOT/'daemon_boolean_chain_sdk.ll').read_text();assert 'xor i32'in ir and'load i32'in ir
 return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in FILES+['daemon_boolean_chain_sdk.c','daemon_secondary_result_proofs.json','recover_daemon_entitlement_flow.py']},'groups':{n:len(p['cases'])for n,p in groups.items()},'keys':keys,'source_spans':spans,'unique_visited_source':source,'profile_ledgers':rows,'banks':banks,'dispatch_edges':edges,'Classic_token_copy':copy,'original_fixups':verify_used_fixups(used),'binds':[binding(at)for at in sorted(used)if FIXUPS[at]['kind'].endswith('bind')],'SDK_layout':{'path':str(sdk),'command':cmd,'exit_code':result.returncode,'stdout':result.stdout,'stderr':result.stderr,'LLVM_file':'daemon_boolean_chain_sdk.ll','LLVM_sha256':sha(ROOT/'daemon_boolean_chain_sdk.ll'),'target_runtime_version_matched':False,'reconstructed_private_layout_is_not_an_exported_header':True},'native_target_executed':False,'host_API_executed':False,'full_goal_complete':False}
if __name__=='__main__':
 r=recover();(ROOT/'daemon_boolean_chain_contracts.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'groups':r['groups'],'keys':r['keys'],'unique_source':len(r['unique_visited_source']),'SDK_exit':r['SDK_layout']['exit_code']}),flush=True)
