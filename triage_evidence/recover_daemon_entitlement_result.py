#!/usr/bin/env python3
"""Recover original result-consumer bytes, bindings and ordered output/cleanup
ledgers. O(profile/source bytes) time and space. Compile a pinned SDK ABI probe;
never invoke native target or framework interfaces.
"""
import json,subprocess
from pathlib import Path
from collections import Counter
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,TABLE
from capture_daemon_record720 import sha
from recover_daemon_descriptor_producers import verify_used_fixups
from daemon_import_bindings import binding
def recover():
 p=json.loads((ROOT/'daemon_entitlement_result_profiles.json').read_text());used=set();source={};rows=[]
 for c in p['cases']:
  for s in c['source_visits']:
   assert IMAGE.read(int(s['pc'],16),4).hex()==s['bytes_hex'];source[s['pc']]=s['bytes_hex']
  for e in c['source_reads']:
   a=int(e['address'],16)
   if a in FIXUPS and e['size_bytes']==8:used.add(a)
  R=int(c['record_address'],16);out=[e for e in c['source_writes']if int(e['address'],16)in [R+8,0x6800051f2f]];flag=[e for e in out if e['address']=='0x6800051f2f'][-1]['after_hex'];returned=c['boundary']['kind']=='returned_to_original_caller';marker=c['final_record']['bytes_hex'][16:18]if returned else None
  rows.append({'scenario':c['configuration']['query_result_model'],'environment_index':c['source_index'],'source_visits':len(c['source_visits']),'boundary':c['boundary']['kind'],'output_writes':out,'final_flag_hex':flag,'final_marker_hex':marker,'caller_predicate_if_evaluated':(int(flag,16)==0 or marker=='5b')if returned else None,'cleanup_requests':[{'pc':m['pc'],'object':m['arguments8'][0],'slot':m['slot'],'modifier':m['modifier']}for m in c['API_model_events']if m['symbol']=='CoreFoundation/_CFRelease'],'API_models':c['API_model_events']})
 edges=[]
 for label,index,mod in [('query_value_no_error',0xa7c7,0xd00d),('query_other',0xa7e1,0xd00d),('Boolean_type_match',0x8a97,0x8fd0),('Boolean_type_mismatch',0x5397,0x8fd0),('caller_predicate_true',0x961d,0x6deb),('caller_predicate_false',0x960f,0x6deb)]:
  slot=TABLE+index*8;word=int.from_bytes(IMAGE.read(slot,8),'little');f=FIXUPS[slot];assert word>>63==1 and(word>>32)&65535==mod and(word>>48)&7==0;used.add(slot);edges.append({'label':label,'index':hex(index),'slot':hex(slot),'modifier':hex(mod),'target':hex(f['target']),'original_word_hex':IMAGE.read(slot,8).hex()})
 spans=[]
 for name,a,z in [('query_result_gate',0x1002b772c,0x1002b778c),('type_IDs',0x10030acb0,0x10030ad34),('Boolean_byte_and_marker',0x10052bcc4,0x10052bce0),('caller_predicate',0x1004c464c,0x1004c4680),('marker_store',0x1004b115c,0x1004b1160)]:spans.append({'name':name,'start':hex(a),'bytes_hex':IMAGE.read(a,z-a).hex()})
 sdk=Path(subprocess.run(['xcrun','--sdk','macosx','--show-sdk-path'],check=True,capture_output=True,text=True).stdout.strip());cmd=['xcrun','--sdk','macosx','clang','-target','arm64e-apple-macos11.0','-isysroot',str(sdk),'-S','-emit-llvm','-O1','-Werror',str(ROOT/'daemon_entitlement_result_sdk.c'),'-o',str(ROOT/'daemon_entitlement_result_sdk.ll')];r=subprocess.run(cmd,capture_output=True,text=True);assert r.returncode==0,(r.stdout,r.stderr);ir=(ROOT/'daemon_entitlement_result_sdk.ll').read_text();assert '@CFBooleanGetTypeID' in ir and '@CFGetTypeID' in ir and '@CFBooleanGetValue' in ir and 'icmp eq i64' in ir
 headers=[sdk/'System/Library/Frameworks/CoreFoundation.framework/Headers'/n for n in ['CFBase.h','CFNumber.h']]
 return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in ['daemon_entitlement_result_profiles.json','daemon_entitlement_result_sdk.c']},'source_spans':spans,'unique_visited_source':source,'scenario_counts':dict(Counter(r['scenario']for r in rows)),'profile_ledgers':rows,'dispatch_edges':edges,'original_fixups':verify_used_fixups(used),'binds':[binding(a)for a in sorted(used)if FIXUPS[a]['kind'].endswith('bind')],'SDK':{'path':str(sdk),'headers':[{'path':str(h),'sha256':sha(h)}for h in headers],'command':cmd,'exit_code':r.returncode,'stdout':r.stdout,'stderr':r.stderr,'LLVM_file':'daemon_entitlement_result_sdk.ll','LLVM_sha256':sha(ROOT/'daemon_entitlement_result_sdk.ll'),'target_runtime_version_matched':False},'native_target_executed':False,'host_API_executed':False,'full_goal_complete':False}
if __name__=='__main__':
 r=recover();(ROOT/'daemon_entitlement_result_contracts.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'scenarios':r['scenario_counts'],'unique_source':len(r['unique_visited_source']),'SDK_exit':r['SDK']['exit_code']}),flush=True)
