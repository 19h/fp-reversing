#!/usr/bin/env python3
"""Original-source return-flow joins, frame-state writer, token-copy lineage,
second record/key codec and exact imported/private interfaces. Pinned SDK
compile only. O(source/profile bytes) time, O(ledgers + largest profile) space.
No native target/framework/IPC execution.
"""
import json,subprocess
from pathlib import Path
from collections import Counter
from daemon_receive_tools import ROOT,SOURCE,IMAGE,FIXUPS,TABLE,selected,qword
from capture_daemon_record720 import sha
from recover_daemon_descriptor_producers import verify_used_fixups
from daemon_import_bindings import binding
FILES=['daemon_entitlement_flow_profiles.json','daemon_entitlement_flow_audit_profiles.json','daemon_entitlement_flow_string_profiles.json']
def snapshot(c,at,n,seq=None):
 data={};mask={}
 for r in c['initial_private_fixtures']+c['initial_image_fixtures']:
  a=int(r['address'],16)
  for j,b in enumerate(bytes.fromhex(r['bytes_hex'])):
   if at<=a+j<at+n:data[a+j]=b;mask[a+j]=1
 effects=[(r['source_visit_index'],r)for r in c['source_writes']]
 for e in c['API_model_events']:
  effects.extend((e['source_visit_index'],m)for m in e.get('memory_models',[]))
 for j,r in sorted(effects,key=lambda x:x[0]):
  if seq is not None and j>=seq:continue
  a=int(r['address'],16)
  for k,b in enumerate(bytes.fromhex(r['after_hex'])):
   if at<=a+k<at+n:data[a+k]=b;mask[a+k]=1
 return {'address':hex(at),'size_bytes':n,'defined_bytes_hex':bytes(data.get(at+j,0)for j in range(n)).hex(),'known_mask_hex':bytes(mask.get(at+j,0)for j in range(n)).hex()}
def copy_body(c,pc):
 call=next(e for e in c['source_calls']if e['pc']==hex(pc));body=[]
 for s in c['source_visits'][call['source_visit_index']+1:]:
  if s['pc']==hex(pc+4):break
  body.append(s)
 assert body[-1]['pc']=='0x10046fa2c';return {'call':call,'body':body}
def recover():
 groups={n:json.loads((ROOT/n).read_text())for n in FILES};source={};used=set();rows=[]
 for group,p in groups.items():
  for c in p['cases']:
   for s in c['source_visits']:
    at=int(s['pc'],16);assert IMAGE.read(at,4).hex()==s['bytes_hex'];source[s['pc']]=s['bytes_hex']
   for e in c['source_reads']:
    at=int(e['address'],16)
    if at in FIXUPS and e['size_bytes']==8:used.add(at)
   after=c['continuation_entry'];cut=after['source_visit_index']if after else len(c['source_visits']);calls=[e for e in c['source_calls']if e['source_visit_index']>=cut];r={'group':group,'configuration':c['configuration'],'environment_index':c['source_index'],'continuation_entry':after,'source_visits':len(c['source_visits']),'post_query_visits':len(c['source_visits'])-cut,'boundary':c['boundary'],'post_query_edges':[e for e in c['logical_edges']if e['source_visit_index']>=cut],'post_query_calls':calls,'state_writes':[e for e in c['source_writes']if e['address']in ['0x680004fbe8','0x6800055d0c','0x6800053384']and e['source_visit_index']>=cut],'token_at_PID_call':snapshot(c,0x680005b2f0,32),'PID_output':snapshot(c,0x6800054f8c,4),'literal':snapshot(c,0x680005f56e,16)}
   child=next((e for e in calls if e['pc']=='0x1004b52b4'),None)
   if child:r['secondary_record_at_call']=snapshot(c,int(child['arguments8'][0],16),40,child['source_visit_index'])
   rows.append(r)
 ref=groups[FILES[1]]['cases'][0];copies=[copy_body(ref,pc)for pc in [0x1004b4fd4,0x1004b5214]];sref=next(c for c in groups[FILES[2]]['cases']if c['configuration']['secondary_string_model']=='nonnull');copies.append(copy_body(sref,0x100062298));encoded=IMAGE.read(0x100fd4a3c,16);literal=b'fairplay-client\0';assert bytes((9*b+0x502a-0x6b if j==1 else 9*b-0x41)&255 for j,b in enumerate(encoded))==literal
 banks=[selected(0x100fc4130,0x101031ea0,0xbb,add)for add in [0xcaf8,0xcc07]];banks.append(selected(0x101031da0,0x100e99900,0x86,0x13,0x1010a1960,0xffffffff808ed0d5));assert banks[-1]['target']=='0x1010b9650'
 for b in banks:used.add(int(b['slot'],16))
 edges=[]
 for label,index,mod in [('Boolean_true_rejoin',0x3b0b,0xeb1c),('secondary_string_NULL',0xab91^((0xab91-0x223d)^0x891e),0xd9aa),('secondary_string_nonNULL',0xab91,0xd9aa),('post_marker_state_zero',0x502f,0x364b),('post_marker_state_nonzero',0x502a,0x364b)]:
  slot=TABLE+index*8;word=int.from_bytes(IMAGE.read(slot,8),'little');assert word>>63==1 and(word>>32)&65535==mod and(word>>48)&7==0;used.add(slot);edges.append({'label':label,'index':hex(index),'slot':hex(slot),'modifier':hex(mod),'target':hex(FIXUPS[slot]['target']),'original_word_hex':IMAGE.read(slot,8).hex()})
 spans=[]
 for name,a,z in [('caller_predicate',0x1004c464c,0x1004c4680),('Boolean_true_state',0x1004b3e6c,0x1004b3eb4),('common_stage_and_PID_ABI',0x1004b4f2c,0x1004b5040),('key_and_secondary_record',0x1004b5040,0x1004b52e4),('secondary_entry_and_codec',0x100013f0c,0x100014088),('secondary_string_result',0x1000141c4,0x1000141fc),('secondary_NULL_return',0x100067240,0x10006727c),('secondary_task_arguments',0x1000622dc,0x1000622ec),('secondary_query_arguments',0x1002382d8,0x1002382ec),('post_marker_state_consumer',0x1005aa0c8,0x1005aa0f8)]:spans.append({'name':name,'start':hex(a),'bytes_hex':IMAGE.read(a,z-a).hex()})
 sdk=Path(subprocess.run(['xcrun','--sdk','macosx','--show-sdk-path'],check=True,capture_output=True,text=True).stdout.strip());cmd=['xcrun','--sdk','macosx','clang','-target','arm64e-apple-macos11.0','-isysroot',str(sdk),'-S','-O1','-Werror',str(ROOT/'daemon_entitlement_flow_sdk.c'),'-o',str(ROOT/'daemon_entitlement_flow_sdk.s')];r=subprocess.run(cmd,capture_output=True,text=True);assert r.returncode==0,(r.stdout,r.stderr);asm=(ROOT/'daemon_entitlement_flow_sdk.s').read_text();assert 'mov\tx6, x1'in asm and'bl\t_audit_token_to_au32'in asm and'str\txzr, [sp]'in asm
 headers=[sdk/'usr/include/bsm/libbsm.h',sdk/'usr/include/mach/message.h'];return {'scope':__doc__,'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'dependencies':{n:sha(ROOT/n)for n in FILES+['daemon_entitlement_flow_sdk.c']},'source_spans':spans,'unique_visited_source':source,'profile_ledgers':rows,'groups':{n:len(p['cases'])for n,p in groups.items()},'copy_paths':copies,'literal':{'text':'fairplay-client','NUL_inclusive_bytes':16,'source_address':'0x100fd4a3c','encoded_hex':encoded.hex(),'decoded_hex':literal.hex(),'workspace_address':'0x680005f56e','second_byte_phase32':'0x502a'},'banks':banks,'dispatch_edges':edges,'original_fixups':verify_used_fixups(used),'binds':[binding(at)for at in sorted(used)if FIXUPS[at]['kind'].endswith('bind')],'SDK':{'path':str(sdk),'headers':[{'path':str(h),'sha256':sha(h)}for h in headers],'command':cmd,'exit_code':r.returncode,'stdout':r.stdout,'stderr':r.stderr,'assembly_file':'daemon_entitlement_flow_sdk.s','assembly_sha256':sha(ROOT/'daemon_entitlement_flow_sdk.s'),'target_runtime_version_matched':False},'native_target_executed':False,'host_API_executed':False,'full_goal_complete':False}
if __name__=='__main__':
 r=recover();(ROOT/'daemon_entitlement_flow_contracts.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'groups':r['groups'],'unique_source':len(r['unique_visited_source']),'literal':r['literal']['text'],'SDK_exit':r['SDK']['exit_code']}),flush=True)
