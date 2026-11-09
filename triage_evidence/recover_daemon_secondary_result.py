#!/usr/bin/env python3
"""Recover original second-result gates, type/convert ABIs, cleanup/state
ledgers, borrowed output-pointer provenance and next private-record/key use.
O(source/profile bytes) time, O(ledgers + largest profile) space. SDK compile
only; no native target/framework/IPC execution.
"""
import json,subprocess
from pathlib import Path
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,TABLE
from capture_daemon_record720 import sha
from recover_daemon_entitlement_flow import snapshot,copy_body
from recover_daemon_descriptor_producers import verify_used_fixups
from daemon_import_bindings import binding
FILES=['daemon_secondary_result_profiles.json','daemon_secondary_result_type_profiles.json']
def recover():
 groups={n:json.loads((ROOT/n).read_text())for n in FILES};source={};used=set();rows=[]
 for group,p in groups.items():
  for c in p['cases']:
   query=next(e for e in c['API_model_events']if e['pc']=='0x1002382e8');cut=query['source_visit_index'];out=0x68000504b0;markers=[e for e in c['source_writes']if e['address']=='0x680005ff00'and e['source_visit_index']>cut];rows.append({'group':group,'configuration':c['configuration'],'environment_index':c['source_index'],'query_event':query,'source_visits':len(c['source_visits']),'post_query_visits':len(c['source_visits'])-cut,'boundary':c['boundary'],'marker_writes':markers,'frame_state_writes':[e for e in c['source_writes']if e['address']=='0x6800055d0c'],'numeric_output':snapshot(c,out,4),'numeric_output_overlapping_reads':[e for e in c['source_reads']if int(e['address'],16)<out+4 and int(e['address'],16)+e['size_bytes']>out],'cleanup_requests':[e for e in c['API_model_events']if e['symbol']=='CoreFoundation/_CFRelease'and e['source_visit_index']>cut],'post_query_calls':[e for e in c['source_calls']if e['source_visit_index']>cut],'post_query_edges':[e for e in c['logical_edges']if e['source_visit_index']>cut]})
   for s in c['source_visits']:
    at=int(s['pc'],16);assert IMAGE.read(at,4).hex()==s['bytes_hex'];source[s['pc']]=s['bytes_hex']
   for e in c['source_reads']:
    at=int(e['address'],16)
    if at in FIXUPS and e['size_bytes']==8:used.add(at)
 edges=[]
 for label,index,mod in [('query_value_no_error',0x594b,0xe71c),('query_other',0x5949,0xe71c),('number_match',0xbb08,0x2420),('number_mismatch',0xbb3a,0x2420),('string_match',0x5946^(0x38f8+0x410),0x8d17),('string_mismatch',0x5946,0x8d17)]:
  at=TABLE+index*8;word=int.from_bytes(IMAGE.read(at,8),'little');assert word>>63==1 and(word>>32)&65535==mod and(word>>48)&7==0;used.add(at);edges.append({'label':label,'index':hex(index),'slot':hex(at),'modifier':hex(mod),'target':hex(FIXUPS[at]['target']),'original_word_hex':IMAGE.read(at,8).hex()})
 spans=[]
 for name,a,z in [('query_result_gate',0x1002382ec,0x100238328),('number_type_gate',0x10003b38c,0x10003b3b8),('string_type_gate',0x1000134a4,0x1000134c8),('number_convert',0x10000b724,0x10000b754),('string_buffer_arguments',0x10014c644,0x10014c65c),('numeric_success_state',0x1007f7950,0x1007f7980),('next_record_builder',0x1007f79f4,0x1007f7a3c),('borrowed_output_stores',0x10057a770,0x10057a780)]:spans.append({'name':name,'start':hex(a),'bytes_hex':IMAGE.read(a,z-a).hex()})
 sample=next(c for c in groups[FILES[1]]['cases']if c['configuration']['secondary_type_model']=='number_success'and c['source_index']==0);copies=[copy_body(sample,pc)for pc in [0x1007f79f0,0x100345354]];calls=[]
 for pc in [0x1007f7a84,0x10034547c]:
  e=next(e for e in sample['source_calls']if e['pc']==hex(pc));calls.append({'call':e,'record_at_call':snapshot(sample,int(e['arguments8'][0],16),24 if pc==0x1007f7a84 else 40,e['source_visit_index'])})
 at=0x100fd5565;literal=IMAGE.read(at,128).split(bytes(1),1)[0]+bytes(1);assert literal==b'FairPlay-CoreML-Client\0'
 sdk=Path(subprocess.run(['xcrun','--sdk','macosx','--show-sdk-path'],check=True,capture_output=True,text=True).stdout.strip());cmd=['xcrun','--sdk','macosx','clang','-target','arm64e-apple-macos11.0','-isysroot',str(sdk),'-S','-emit-llvm','-O1','-Werror',str(ROOT/'daemon_secondary_result_sdk.c'),'-o',str(ROOT/'daemon_secondary_result_sdk.ll')];r=subprocess.run(cmd,capture_output=True,text=True);assert r.returncode==0,(r.stdout,r.stderr);ir=(ROOT/'daemon_secondary_result_sdk.ll').read_text();assert '@CFNumberGetValue(ptr'in ir and'i64 noundef 3'in ir and'@CFStringGetCString'in ir and'i64 noundef 32'in ir and'i32 noundef 1536'in ir
 headers=[sdk/'System/Library/Frameworks/CoreFoundation.framework/Headers'/n for n in ['CFBase.h','CFNumber.h','CFString.h']];return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in FILES+['daemon_secondary_result_sdk.c','daemon_mig_handover_symbolic.json','recover_daemon_entitlement_flow.py']},'source_spans':spans,'unique_visited_source':source,'profile_ledgers':rows,'groups':{n:len(p['cases'])for n,p in groups.items()},'dispatch_edges':edges,'copy_paths':copies,'next_private_calls':calls,'next_key':{'address':hex(at),'text':'FairPlay-CoreML-Client','NUL_inclusive_bytes':len(literal),'bytes_hex':literal.hex(),'next_string_call_PC':'0x10033376c','third_query_executed':False},'original_fixups':verify_used_fixups(used),'binds':[binding(at)for at in sorted(used)if FIXUPS[at]['kind'].endswith('bind')],'SDK':{'path':str(sdk),'headers':[{'path':str(h),'sha256':sha(h)}for h in headers],'command':cmd,'exit_code':r.returncode,'stdout':r.stdout,'stderr':r.stderr,'LLVM_file':'daemon_secondary_result_sdk.ll','LLVM_sha256':sha(ROOT/'daemon_secondary_result_sdk.ll'),'target_runtime_version_matched':False},'native_target_executed':False,'host_API_executed':False,'full_goal_complete':False}
if __name__=='__main__':
 r=recover();(ROOT/'daemon_secondary_result_contracts.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'groups':r['groups'],'unique_source':len(r['unique_visited_source']),'next_key':r['next_key']['text'],'SDK_exit':r['SDK']['exit_code']}),flush=True)
