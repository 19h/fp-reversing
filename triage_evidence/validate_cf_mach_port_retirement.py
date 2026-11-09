#!/usr/bin/env python3
"""Verify recapture, SDK ABI, repeat execution and independent lifetime model.
O(source+V+J+H*R), O(source+J+R); no native target effects.
"""
import copy,json,subprocess,struct
from pathlib import Path
from recover_cf_mach_port_retirement import *
from replay_cf_mach_port_retirement import replay,semantic
from probe_cf_mach_port_retirement import Engine,PORT
SDK_C=r'''#include <stddef.h>
#include <stdint.h>
#include <mach/mach.h>
#include <CoreFoundation/CFMachPort.h>
#include <dispatch/dispatch.h>
struct selected_record { uint32_t name; uint8_t tag; uint8_t flags; uint16_t opaque; };
_Static_assert(sizeof(mach_port_t)==4,"port4");
_Static_assert(sizeof(mach_port_name_t)==4,"name4");
_Static_assert(MACH_PORT_RIGHT_RECEIVE==1,"receive1");
_Static_assert(MACH_PORT_TYPE_SEND==0x10000,"send bit");
_Static_assert(MACH_PORT_TYPE_RECEIVE==0x20000,"receive bit");
_Static_assert(MACH_PORT_TYPE_SEND_ONCE==0x40000,"send once bit");
_Static_assert(MACH_MSG_TYPE_MAKE_SEND==20,"make send20");
_Static_assert(DISPATCH_MACH_SEND_DEAD==1,"dead event1");
_Static_assert(sizeof(CFMachPortContext)==40,"context40");
_Static_assert(offsetof(CFMachPortContext,info)==8,"info8");
_Static_assert(offsetof(CFMachPortContext,retain)==16,"retain16");
_Static_assert(offsetof(CFMachPortContext,release)==24,"release24");
_Static_assert(__builtin_types_compatible_p(__typeof__(&CFMachPortInvalidate),void(*)(CFMachPortRef)),"void invalidation");
_Static_assert(sizeof(struct selected_record)==8,"selected record8");
_Static_assert(offsetof(struct selected_record,flags)==5,"flags5");
_Static_assert(offsetof(struct selected_record,opaque)==6,"opaque6");
'''
def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());p=json.loads((ROOT/(P+'_profiles.json')).read_text());fresh=build();assert fresh==s
 for o,script in[(s,'recover_'+P+'.py'),(p,'probe_'+P+'.py')]:
  assert o['generator_sha256']==sha(ROOT/script)
  for n,h in o['dependencies'].items():assert sha(ROOT/n)==h,n
  assert all(o[k]is False for k in FLAGS)
 ins={int(i['ea'],16):(i['mnemonic'],i['operands'])for f in s['retirement_library_functions_static_only']for i in f['instructions']}
 wire_assertions=[(0x180547ac8,'mov','x16, #-0x12'),(0x180547acc,'svc','#0x80'),(0x180547ad4,'mov','x16, #-0x13'),(0x180547ad8,'svc','#0x80'),(0x180549088,'mov','w8, #3'),(0x18054908c,'movk','w8, #0x1000, lsl #16'),(0x180549094,'b.ne','#0x1805490bc'),(0x1805490b8,'b','#0x18056c8a4'),(0x180548354,'b.ne','#0x180548388'),(0x180548384,'b','#0x18056c9c0'),(0x18056c8cc,'str','w1, [sp, #0x20]'),(0x18056c9e4,'stp','w1, w2, [sp, #0x20]'),(0x18056c9e8,'str','w3, [sp, #0x28]'),(0x18056c918,'bl','#0x18055a894'),(0x18056ca34,'bl','#0x18055a894'),(0x18056c958,'cmp','w8, #0xcea'),(0x18056ca74,'cmp','w8, #0xcec'),(0x18056c910,'mov','w6, #0x2c'),(0x18056ca2c,'mov','w6, #0x2c')]
 for at,m,o in wire_assertions:assert ins[at]==(m,o)
 constants={int(e['address'],16):struct.unpack('<II',bytes.fromhex(e['bytes_hex']))for e in s['retirement_RPC_constants']};assert constants=={0x18057d3e0:(0x1513,36),0x18057d608:(0,3206),0x18057d618:(0x1513,44),0x18057d620:(0,3208),0x1eb065de0:(0,1)}
 totals=replay(s,p);assert totals['cases_reexecuted']==287 and totals['original_instruction_visits_repeated']==15793 and totals['complete_final_RAM_bytes_repeated']==78761984 and totals['cleanup_flag_inputs_checked']==256
 sdk=Path(subprocess.check_output(['xcrun','--show-sdk-path'],text=True).strip());cmd=['clang','-target','arm64e-apple-macos13.0','-isysroot',str(sdk),'-std=c11','-fsyntax-only','-x','c','-'];r=subprocess.run(cmd,input=SDK_C,text=True,capture_output=True);assert r.returncode==0,r.stderr
 headers=[sdk/'usr/include/mach/port.h',sdk/'usr/include/mach/mach_port.h',sdk/'usr/include/dispatch/source.h',sdk/'System/Library/Frameworks/CoreFoundation.framework/Versions/A/Headers/CFMachPort.h'];hdr=[{'path':str(q),'size_bytes':q.stat().st_size,'sha256':sha(q)}for q in headers]
 cases={r['config']['label']:r for r in p['cases']};controls=[]
 def reject(label,row,method=semantic):
  try:method(row)
  except(AssertionError,ValueError,KeyError):controls.append(label);return
  raise AssertionError(('alteration accepted',label))
 q=copy.deepcopy(cases['borrowed_receive']);q['entries'][0]['state_after']['object128_hex']='00'*128;reject('constructed_object_identity_and_fields',q)
 q=copy.deepcopy(cases['owned_cached_reuse']);q['entries'][1]['state_after']['object128_hex']=q['entries'][1]['state_after']['object128_hex'][:96]+'2222111100000000'+q['entries'][1]['state_after']['object128_hex'][112:];reject('cached_callback_replacement',q)
 q=copy.deepcopy(cases['intent_record_source_invalid']);e=q['entries'][1]['state_after'];addr=next(iter(e['record_bytes']));raw=bytearray.fromhex(e['record_bytes'][addr]);raw[5]^=2;e['record_bytes'][addr]=raw.hex();reject('deferred_record_flags',q)
 q=copy.deepcopy(cases['cleanup_flags_24']);e=next(e for e in q['lower_events']if e['name']=='_mach_port_mod_refs');e['arguments8'][1]='0xdeadbeef';reject('cleanup_name_width_argument',q)
 q=copy.deepcopy(cases['cleanup_flags_24']);q['lower_events'].reverse();reject('receive_send_request_order',q)
 q=copy.deepcopy(cases['cleanup_flags_0']);q['final_regions'][0]['sha256']='0'*64;reject('whole_final_RAM_hash',q)
 q=copy.deepcopy(cases['owned_destroy_before_cancel']);q['entries'][-1]['state_after']['records']={'0x303':hex(PORT)};reject('rendezvous_record_retirement',q)
 q=copy.deepcopy(cases['owned_cancel_before_destroy']);e=next(e for e in q['lower_events']if e['name']=='_dispatch_source_set_cancel_handler');e['patches'][0]['after_hex']='00'*44
 reject('cancel_block_capture',q,lambda z: (_ for _ in()).throw(AssertionError())if Engine(s,z['config']).run()!=z else None)
 q=copy.deepcopy(cases['borrowed_receive']);q['entries'][0]['returned']['X31'][30]='0'
 reject('component_return_CPU',q,lambda z: (_ for _ in()).throw(AssertionError())if Engine(s,z['config']).run()!=z else None)
 altered=copy.deepcopy(s);altered['functions'][0]['bytes']='00000000'+altered['functions'][0]['bytes'][8:]
 try:assert altered==fresh
 except AssertionError:controls.append('original_source_capture')
 assert len(controls)==10
 summaries=[]
 for row in p['cases']:
  if row['config']['label'].startswith('cleanup_flags_'):continue
  raw=bytes.fromhex(row['final_state']['object128_hex']);calls=[{'name':e['name'],'arguments8':e['arguments8']}for e in row['lower_events']if e['name']in('_mach_port_mod_refs','_mach_port_deallocate')];summaries.append({'label':row['config']['label'],'original_visits':len(row['source_visits']),'final_object_state_u32':int.from_bytes(raw[16:20],'little'),'ownership_bits':int.from_bytes(raw[8:16],'little')&6,'pending_records':len(row['final_state']['records']),'right_release_requests':calls})
 counts={'complete_CF_functions_recaptured':len(s['functions']),'captured_instructions':sum(len(f['instructions'])for f in s['functions']),'retirement_library_functions_captured_static_only':len(s['retirement_library_functions_static_only']),'lower_stubs_resolved':len(s['stubs']),'cache_files_hashed':len(s['cache_files']),'daemon_bindings_checked':len(s['daemon_bindings']),'daemon_windows_checked':len(s['daemon_windows']),'retirement_wire_instructions_checked':len(wire_assertions),'retirement_wire_constants_checked':len(constants),'SDK_headers_hashed':len(hdr),'SDK_assertions_checked':SDK_C.count('_Static_assert'),'altered_evidence_controls_rejected':len(controls)}
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[P+'_source.json',P+'_profiles.json','recover_'+P+'.py','probe_'+P+'.py','replay_'+P+'.py']},'source_recapture_match':True,'verified_counts':counts,'repeat_and_independent_semantic_checks':totals,'static_retirement_wire_assertions':[{'address':hex(a),'mnemonic':m,'operands':o}for a,m,o in wire_assertions],'SDK_compile':{'command':cmd,'inline_C':SDK_C,'exit_code':r.returncode},'SDK_headers':hdr,'case_summaries':summaries,'altered_evidence_rejected':controls,'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'counts':counts,'validation':totals,'altered_controls':controls,'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
