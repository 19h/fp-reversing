#!/usr/bin/env python3
"""Original source/bindings, constant key bytes, mode/read/write ledgers and
pinned installed-SDK compile evidence. O(source/profiles + 256 bank inputs)
time, O(unique source + ledger) space; no target/API/IPC execution.
"""
import bisect,json,subprocess
from pathlib import Path
from collections import Counter
import z3
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,POOL,TABLE,selected,qword
from capture_daemon_operation_heads import function_starts
from capture_daemon_record720 import sha
from prove_daemon_operation_heads import variables
from validate_daemon_record720_spill import parse_value
from recover_daemon_descriptor_producers import verify_used_fixups
from daemon_import_bindings import binding
def recover():
 profiles=json.loads((ROOT/'daemon_record40_consumer_profiles.json').read_text());parent=json.loads((ROOT/'daemon_mig_handover_symbolic.json').read_text());stage=next(c for c in parent['cases']if c['path_class']=='allnonnull');v=variables(stage);ram={int(r['address'],16):r['expression']for r in stage['final_defined_bytes']};base=0x680005b1f0;literal=b'com.apple.private.fpsd.client\0';byte_ledger=[]
 for j,b in enumerate(literal):
  x=z3.simplify(parse_value(ram[base+j],8,v));assert z3.is_bv_value(x)and x.as_long()==b;writers=[e for e in stage['effects']if e['kind']=='write'and int(e['address'],16)<=base+j<int(e['address'],16)+e['size_bytes']];assert writers;byte_ledger.append({'offset_bytes':j,'value':b,'last_writer_PC':writers[-1]['pc']})
 starts,_=function_starts();ix=bisect.bisect_left(starts,0x10046ef4c);assert starts[ix]==0x10046ef4c and starts[ix+1]==0x10046f89c;used=set();source={};summaries=[];mode_counts=Counter()
 for case in profiles['cases']:
  mode=case['configuration']['API_model_mode'];mode_counts[mode]+=1
  for st in case['source_visits']:
   pc=int(st['pc'],16);assert IMAGE.read(pc,4).hex()==st['bytes_hex'];source[st['pc']]=st['bytes_hex']
  for e in case['source_reads']:
   at=int(e['address'],16)
   if at in FIXUPS and e['size_bytes']==8:used.add(at)
  writes=[e for e in case['source_writes']if int(case['record_address'],16)<=int(e['address'],16)<int(case['record_address'],16)+40 or e['address']=='0x6800051f2f'];summaries.append({'mode':mode,'environment_index':case['source_index'],'source_visits':len(case['source_visits']),'boundary':case['boundary'],'output_writes':writes,'API_models':case['API_model_events'],'final_record':case['final_record']})
 mask=(1<<64)-1;calls=[]
 for name,pc,la,lb,ra,rb,key,add in [('CFStringCreateWithCStringNoCopy',0x10033376c,POOL+0x60f0,-0x58a4e9be,POOL+0x2240,-0x5e7b9ca,0xe4,0xcc78),('CFArrayGetValueAtIndex',0x10046f658,POOL+0x29c8,-0x55a6e8c7,POOL+0x4c18,-0x75079233,0xa3,0xce99),('CFNumberGetTypeID',0x10046f6c4,POOL+0x1658,-0x5918054b,POOL+0x26a0,-0x62f83f4e,0x78,0xcd5b),('CFGetTypeID',0x10046f744,POOL+0x60f0,-0x58a4e9be,POOL+0x2240,-0x5e7b9ca,0x6c,0xcb9f)]:
  l=(qword(la)+lb)&mask;r=(qword(ra)+rb)&mask;bank=selected(l,r,key,add,TABLE);assert bank['target']=='CoreFoundation/_'+name;bank.update({'call_PC':hex(pc),'name':name,'actual_8BB2_path_established':pc==0x10033376c});calls.append(bank);used.add(int(bank['slot'],16))
 sdk=Path(subprocess.run(['xcrun','--sdk','macosx','--show-sdk-path'],check=True,capture_output=True,text=True).stdout.strip());headers=[sdk/'System/Library/Frameworks/CoreFoundation.framework/Headers/CFString.h',sdk/'System/Library/Frameworks/CoreFoundation.framework/Headers/CFBase.h',sdk/'System/Library/Frameworks/Security.framework/Headers/SecTask.h'];cmd=['xcrun','--sdk','macosx','clang','-target','arm64e-apple-macos11.0','-isysroot',str(sdk),'-S','-emit-llvm','-O1','-Werror',str(ROOT/'daemon_record40_consumer_sdk.c'),'-o',str(ROOT/'daemon_record40_consumer_sdk.ll')];result=subprocess.run(cmd,capture_output=True,text=True);assert result.returncode==0,(result.stdout,result.stderr);ir=(ROOT/'daemon_record40_consumer_sdk.ll').read_text();assert '@SecTaskCreateWithAuditToken(ptr'in ir and'i64 32'in ir and'@CFStringCreateWithCStringNoCopy'in ir and'i32 noundef 1536'in ir
 source_spans=[]
 for name,a,z in [('callee_entry',0x10046ef4c,0x10046f140),('record_key_input',0x10046f070,0x10046f09c),('record_key_decode',0x10046f09c,0x10046f0b0),('allocator_and_string_call',0x1003336f8,0x100333770),('task_call_arguments',0x10047d998,0x10047d9b0),('query_call_arguments',0x1002b7718,0x1002b772c),('result_marker_write',0x1004b115c,0x1004b1160)]:source_spans.append({'name':name,'start':hex(a),'bytes_hex':IMAGE.read(a,z-a).hex()})
 taskcase=next(c for c in profiles['cases']if c['configuration']['API_model_mode']=='task_nonnull'and c['source_index']==0);copy=next(c for c in taskcase['source_calls']if c['target']=='0x10046f89c');j=copy['source_visit_index']+1;body=[]
 for st in taskcase['source_visits'][j:]:
  pc=int(st['pc'],16)
  if pc==int(copy['pc'],16)+4:break
  body.append(st)
 assert body and body[-1]['pc']=='0x10046fa2c'
 return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in ['daemon_record40_consumer_profiles.json','daemon_mig_handover_symbolic.json','daemon_record40_consumer_sdk.c']},'literal':{'text':'com.apple.private.fpsd.client','NUL_inclusive_bytes':len(literal),'bytes_hex':literal.hex(),'caller_pointer':hex(base),'byte_writers':byte_ledger},'function_start_interval':{'start':hex(starts[ix]),'next_start':hex(starts[ix+1]),'size_bytes':starts[ix+1]-starts[ix]},'source_spans':source_spans,'unique_visited_source':source,'mode_counts':dict(mode_counts),'source_copy_call':copy,'source_copy_body':body,'API_banks':calls,'original_fixups':verify_used_fixups(used),'binds':[binding(at)for at in sorted(used)if FIXUPS[at]['kind'].endswith('bind')],'profile_ledgers':summaries,'SDK':{'path':str(sdk),'headers':[{'path':str(p),'sha256':sha(p)}for p in headers],'command':cmd,'exit_code':result.returncode,'stdout':result.stdout,'stderr':result.stderr,'LLVM_file':'daemon_record40_consumer_sdk.ll','LLVM_sha256':sha(ROOT/'daemon_record40_consumer_sdk.ll'),'target_runtime_version_matched':False},'native_target_executed':False,'host_API_executed':False,'full_goal_complete':False}
if __name__=='__main__':
 r=recover();(ROOT/'daemon_record40_consumer_contracts.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'modes':r['mode_counts'],'literal':r['literal']['text'],'unique_source':len(r['unique_visited_source']),'SDK_exit':r['SDK']['exit_code'],'audit_copy_visits':len(r['source_copy_body'])}),flush=True)
