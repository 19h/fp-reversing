#!/usr/bin/env python3
"""Original daemon ownership suffix, available-cache VM transport and KC trap.
Static source/bind/fixup capture and compile-only SDK ABI checks; no native
target/VM/free/IPC. O(source/profile bytes + KC fixups) time and space.
Available cache/KC identity does not attest the daemon's native runtime.
"""
import json,struct,subprocess
from pathlib import Path
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS
from daemon_import_bindings import binding
from capture_daemon_record720 import sha
from recover_daemon_descriptor_producers import verify_used_fixups
from recover_daemon_entitlement_flow import snapshot
from bootpolicy_cache_reader import Cache,Dylib
from kernel_native_reader import Kernel
from resolve_kernel_collection_interfaces import chained_rebases
FILES=['daemon_vm_cleanup_profiles.json','daemon_vm_cleanup_retire_profiles.json']
CACHE_FUNCTIONS=[0x18054a0b0,0x1805497a4,0x180547a8c,0x18056f104,0x180547f00,0x18055a894]
def recover():
 source={};used=set();rows=[]
 for group in FILES:
  p=json.loads((ROOT/group).read_text())
  for r in p['cases']:
   cut=r['VM_cleanup_returns'][0]['source_visit_index'];rows.append({'group':group,'configuration':r['configuration'],'VM_returns':r['VM_cleanup_returns'],'retirements':r.get('source_retirements',[]),'boundary':r['boundary'],'API_suffix':[e for e in r['API_model_events']if e['source_visit_index']>=cut],'source_suffix':r['source_visits'][cut+1:],'logical_edges_suffix':[e for e in r['logical_edges']if e['source_visit_index']>=cut],'writes_suffix':[e for e in r['source_writes']if e['source_visit_index']>=cut],'status_frame':snapshot(r,0x680004f230+0x44a4,4),'cleanup_owner':snapshot(r,0x680004f230+0x1930,8)})
   for e in r['source_visits']:
    at=int(e['pc'],16);assert IMAGE.read(at,4).hex()==e['bytes_hex'];source[e['pc']]=e['bytes_hex']
   for e in r['source_reads']:
    at=int(e['address'],16)
    if at in FIXUPS and e['size_bytes']==8:used.add(at)
 cache=Cache();lib=Dylib(cache,'/usr/lib/system/libsystem_kernel.dylib');umbrella=Dylib(cache,'/usr/lib/libSystem.B.dylib');assert cache.uuid=='2bd06591-e751-3e84-963f-b08dab6af23a'and lib.uuid=='f2bceb9a-0fec-3c92-b6ea-8e37157050a8';functions=[]
 for at in sorted(set(CACHE_FUNCTIONS+[lib.exports['_mach_msg2_trap']['address']])):
  f=lib.function(at);m=cache.mapping(at);f.update({'original_nlist':lib.symbols_at(at),'original_exports':[n for n,e in lib.exports.items()if e['address']==at],'source_file':m['path'],'source_offset':hex(m['off']+at-m['va'])});functions.append(f)
 reexports=[]
 for cmd,raw in umbrella.commands:
  if cmd==0x8000001f:
   off=struct.unpack_from('<I',raw,8)[0];reexports.append({'path':raw[off:].split(b'\0')[0].decode(),'command_bytes_hex':raw.hex()})
 assert any(x['path']==lib.path for x in reexports)
 constants=[{'address':hex(a),'bytes_hex':cache.read(a,n).hex(),'native_runtime_value_attested':False}for a,n in [(0x1eb065de0,8),(0x18057d628,8),(0x18057d758,8)]];assert lib.exports['_NDR_record']['address']==0x1eb065de0
 k=Kernel();base,rebases,metadata=chained_rebases(k.data);old=json.loads((ROOT/'kernel_dispatch_contracts.json').read_text());entry=old['mach_entries'][12];assert entry['name']=='_kernelrpc_mach_vm_deallocate_trap'and entry['argument_count']==3 and entry['u32_words']==5 and not entry['returns_port'];traprow=k.read(0xfffffe0007efb010+24*12,24);assert traprow[:8]==bytes.fromhex('0305000000000000')
 for n in ['handler_pointer','munger_pointer','name_pointer']:
  p=entry[n];off=int(p['file_offset'],16);assert off in metadata and metadata[off]=={key:value for key,value in p.items()if key not in ['slot','file_offset']}
 kfunctions=[k.function(0xfffffe000bcdb4ec),k.function(0xfffffe000bdc1ec0)];sdk=Path(subprocess.run(['xcrun','--sdk','macosx','--show-sdk-path'],check=True,capture_output=True,text=True).stdout.strip());cmd=['xcrun','--sdk','macosx','clang','-target','arm64e-apple-macos11.0','-isysroot',str(sdk),'-S','-emit-llvm','-O1','-Werror',str(ROOT/'daemon_vm_cleanup_sdk.c'),'-o',str(ROOT/'daemon_vm_cleanup_sdk.ll')];result=subprocess.run(cmd,capture_output=True,text=True);assert result.returncode==0,(result.stdout,result.stderr)
 return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in FILES+['daemon_vm_cleanup_cache_profiles.json','daemon_vm_cleanup_sdk.c','kernel_dispatch_contracts.json','bootpolicy_cache_reader.py']},'unique_visited_source':source,'profile_ledgers':rows,'original_fixups':verify_used_fixups(used),'binds':[binding(at)for at in sorted(used)if FIXUPS[at]['kind'].endswith('bind')],'cache':{'uuid':cache.uuid,'library_uuid':lib.uuid,'library_path':lib.path,'umbrella_uuid':umbrella.uuid,'umbrella_reexports':reexports,'functions':functions,'constants':constants,'source_files':{p:cache.files[p]for p in sorted(cache.used)},'daemon_runtime_version_match_established':False},'kernel':{'sha256':k.sha256,'trap_entry':entry,'trap_row_bytes_hex':traprow.hex(),'functions':kfunctions,'native_table_contents_attested':False},'SDK_layout':{'path':str(sdk),'command':cmd,'exit_code':result.returncode,'LLVM_file':'daemon_vm_cleanup_sdk.ll','LLVM_sha256':sha(ROOT/'daemon_vm_cleanup_sdk.ll'),'target_runtime_version_matched':False},'native_target_executed':False,'native_IPC_executed':False,'full_goal_complete':False}
if __name__=='__main__':
 r=recover();(ROOT/'daemon_vm_cleanup_contracts.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'unique_daemon_source':len(r['unique_visited_source']),'daemon_profiles':len(r['profile_ledgers']),'cache_functions':len(r['cache']['functions']),'kernel_functions':len(r['kernel']['functions']),'SDK_exit':r['SDK_layout']['exit_code']}),flush=True)
