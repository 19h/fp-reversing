#!/usr/bin/env python3
"""Original String-conversion/parser/control/output contracts and an explicit
join to separately captured host-libc reference values. SDK compile only.
O(source/profile bytes) time, O(ledgers + largest profile) space. No native
daemon/framework/IPC execution; host strtol reference execution is separate.
"""
import json,subprocess
from pathlib import Path
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,TABLE
from capture_daemon_record720 import sha
from recover_daemon_entitlement_flow import snapshot
from recover_daemon_descriptor_producers import verify_used_fixups
from daemon_import_bindings import binding
def recover():
 p=json.loads((ROOT/'daemon_secondary_string_profiles.json').read_text());reference=json.loads((ROOT/'daemon_secondary_string_reference.json').read_text());source={};used=set();rows=[]
 for c in p['cases']:
  conversion=next(e for e in c['API_model_events']if e['pc']=='0x10014c658');parser=next((e for e in c['API_model_events']if e['pc']=='0x10000a2e8'),None);cut=conversion['source_visit_index'];rows.append({'configuration':c['configuration'],'source_visits':len(c['source_visits']),'conversion_event':conversion,'parser_event':parser,'boundary':c['boundary'],'output_writes':[e for e in c['source_writes']if e['pc']=='0x100073fdc'],'marker_writes':[e for e in c['source_writes']if e['pc']=='0x100067240'],'state_writes':[e for e in c['source_writes']if e['pc']=='0x1007f797c'],'post_conversion_edges':[e for e in c['logical_edges']if e['source_visit_index']>cut],'post_conversion_API_models':[e for e in c['API_model_events']if e['source_visit_index']>cut],'output_word_at_boundary':snapshot(c,0x68000504b0,4)})
  for s in c['source_visits']:
   at=int(s['pc'],16);assert IMAGE.read(at,4).hex()==s['bytes_hex'];source[s['pc']]=s['bytes_hex']
  for e in c['source_reads']:
   at=int(e['address'],16)
   if at in FIXUPS and e['size_bytes']==8:used.add(at)
 edges=[]
 for label,index,mod in [('conversion_false',0x5946,0x8d17),('conversion_nonzero',0x596e,0x8d17),('end_pointer_NULL',0xa9a3,0x5ddc),('end_pointer_nonNULL',0xa9d6,0x5ddc),('end_byte_zero',0x1f1e,0xcb1a),('end_byte_nonzero',0x1f11,0xcb1a)]:
  at=TABLE+index*8;word=int.from_bytes(IMAGE.read(at,8),'little');assert word>>63==1 and(word>>32)&65535==mod and(word>>48)&7==0;used.add(at);edges.append({'label':label,'index':hex(index),'slot':hex(at),'modifier':hex(mod),'target':hex(FIXUPS[at]['target']),'original_word_hex':IMAGE.read(at,8).hex()})
 spans=[]
 for name,a,z in [('ASCII_arguments',0x10014c644,0x10014c65c),('conversion_result_gate',0x10014c65c,0x10014c688),('parser_arguments',0x10000a2d8,0x10000a2ec),('end_pointer_gate',0x10000a2ec,0x10000a310),('end_byte_gate',0x1000094e4,0x100009530),('output_narrowing_and_marker',0x100073fc0,0x100073ff0)]:spans.append({'name':name,'start':hex(a),'bytes_hex':IMAGE.read(a,z-a).hex()})
 sdk=Path(subprocess.run(['xcrun','--sdk','macosx','--show-sdk-path'],check=True,capture_output=True,text=True).stdout.strip());cmd=['xcrun','--sdk','macosx','clang','-target','arm64e-apple-macos11.0','-isysroot',str(sdk),'-S','-emit-llvm','-O1','-Werror',str(ROOT/'daemon_secondary_string_sdk.c'),'-o',str(ROOT/'daemon_secondary_string_sdk.ll')];r=subprocess.run(cmd,capture_output=True,text=True);assert r.returncode==0,(r.stdout,r.stderr);ir=(ROOT/'daemon_secondary_string_sdk.ll').read_text();assert '@strtol(ptr'in ir and'i32 noundef 10'in ir and'@CFStringGetCString'in ir and'i64 noundef 32'in ir;headers=[sdk/'usr/include/_stdlib.h',sdk/'usr/include/sys/errno.h',sdk/'System/Library/Frameworks/CoreFoundation.framework/Headers/CFString.h'];return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in ['daemon_secondary_string_profiles.json','daemon_secondary_string_reference.json','daemon_secondary_string_sdk.c','recover_daemon_entitlement_flow.py']},'source_spans':spans,'unique_visited_source':source,'profile_ledgers':rows,'dispatch_edges':edges,'host_reference_cases':reference['cases'],'host_reference_runtime':reference['host'],'original_fixups':verify_used_fixups(used),'binds':[binding(at)for at in sorted(used)if FIXUPS[at]['kind'].endswith('bind')],'SDK':{'path':str(sdk),'headers':[{'path':str(h),'sha256':sha(h)}for h in headers],'manual':reference['primary_manual'],'command':cmd,'exit_code':r.returncode,'stdout':r.stdout,'stderr':r.stderr,'LLVM_file':'daemon_secondary_string_sdk.ll','LLVM_sha256':sha(ROOT/'daemon_secondary_string_sdk.ll'),'target_runtime_version_matched':False},'native_target_executed':False,'host_framework_API_executed':False,'host_libc_reference_is_separate':True,'full_goal_complete':False}
if __name__=='__main__':
 r=recover();(ROOT/'daemon_secondary_string_contracts.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'profiles':len(r['profile_ledgers']),'unique_source':len(r['unique_visited_source']),'SDK_exit':r['SDK']['exit_code']}),flush=True)
