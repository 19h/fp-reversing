#!/usr/bin/env python3
"""Verify original service registration/removal and descriptor callback joins.
Fresh source capture/SDK plus shared-engine repeat and independent service
contracts. O(S+V*F+J+H*R), O(S+J+R); no native effects.
"""
import copy,json,struct,subprocess,zlib,base64,hashlib
from pathlib import Path
from recover_daemon_service_cf_lifecycle import *
from replay_daemon_service_cf_lifecycle import replay,semantic
from probe_daemon_service_cf_lifecycle import Probe,SOBJ,SSRC,SARG,B,SET1,DICT
SDK_C='''#include <stddef.h>
#include <stdint.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include <sys/event.h>
#include <sys/signal.h>
#include <CoreFoundation/CFMachPort.h>
#include <CoreFoundation/CFRunLoop.h>
struct selected_record { void **destination; const char *name; uint32_t status,pad0; uint64_t reserved; uint32_t control,pad1; };
struct selected_header { void *arena; uint32_t count,pad; uint64_t unknown; CFMachPortRef first; unsigned char rest[64]; };
_Static_assert(sizeof(mach_port_name_t)==4,"name4");
_Static_assert(sizeof(CFMachPortContext)==40,"context40");
_Static_assert(offsetof(CFMachPortContext,info)==8,"info8");
_Static_assert(sizeof(CFRunLoopSourceContext1)==72,"source1 context72");
_Static_assert(offsetof(CFRunLoopSourceContext1,info)==8,"source1 info8");
_Static_assert(offsetof(CFRunLoopSourceContext1,getPort)==56,"getPort56");
_Static_assert(offsetof(CFRunLoopSourceContext1,perform)==64,"perform64");
_Static_assert(sizeof(CFRunLoopSourceContext)==80,"source0 context80");
_Static_assert(sizeof(struct selected_record)==40,"record40");
_Static_assert(offsetof(struct selected_record,status)==16,"status16");
_Static_assert(offsetof(struct selected_record,control)==32,"control32");
_Static_assert(sizeof(struct selected_header)==96,"header96");
_Static_assert(offsetof(struct selected_header,first)==24,"first service24");
_Static_assert(sizeof(struct kevent)==32,"kevent32");
_Static_assert(EVFILT_SIGNAL==-6,"signal filter");
_Static_assert(SIGTERM==15,"signal15");
_Static_assert(MACH_PORT_TYPE_RECEIVE==0x20000,"receive type");
_Static_assert(__builtin_types_compatible_p(__typeof__(&CFMachPortInvalidate),void(*)(CFMachPortRef)),"void invalidate");
_Static_assert(__builtin_types_compatible_p(__typeof__(&bootstrap_check_in),kern_return_t(*)(mach_port_t,const char*,mach_port_t*)),"bootstrap ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&mach_port_extract_member),kern_return_t(*)(ipc_space_t,mach_port_name_t,mach_port_name_t)),"extract ABI");
'''
def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());p=json.loads((ROOT/(P+'_profiles.json')).read_text());fresh=build();assert s==fresh
 for obj,script in((s,'recover_'+P+'.py'),(p,'probe_'+P+'.py')):
  assert obj['generator_sha256']==sha(ROOT/script)and all(obj[k]is False for k in FLAGS)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h,n
 k=json.loads((ROOT/'cf_runloop_wake_port_profiles.json').read_text())['kernel_cases'][2];totals=replay(s,p,k);assert totals['cases_reexecuted']==8 and totals['original_instruction_visits_repeated']==264564 and totals['complete_final_private_RAM_bytes_checked']==44695552 and totals['service_lower_state_CPU_and_patch_contracts_recomputed']==157
 cache=Cache()
 for f in s['CF_source']['CF_functions']+s['CF_source']['import_stubs']:assert cache.read(int(f['start'],16),int(f['end'],16)-int(f['start'],16)).hex()==f['bytes']
 for e in s['CF_source']['cache_files']:assert sha(e['path'])==e['sha256']and Path(e['path']).stat().st_size==e['size_bytes']
 old=json.loads((ROOT/'daemon_cf_descriptor_bridge_source.json').read_text())
 for f in old['original_daemon_ranges']:assert IMAGE.read(int(f['start'],16),int(f['end'],16)-int(f['start'],16)).hex()==f['bytes']
 for f in s['original_checkin_ranges']:assert IMAGE.read(int(f['start'],16),int(f['end'],16)-int(f['start'],16)).hex()==f['bytes_hex']
 first=next(CS.disasm(bytes.fromhex(next(e['prefix16_hex']for e in s['new_boundaries']if e['address']==hex(EXTRACT_TRAP))),EXTRACT_TRAP));assert(first.mnemonic,first.op_str)==('mov','x16, #-0x17')
 assert len(s['daemon_to_CF_bindings'])==12 and s['new_extract_stub']['pointer']['chain_membership_verified']and s['new_extract_stub']['target']=='0x18054b360'and s['bootstrap_port_binding']['total_addend']==0x7da61013 and (s['bootstrap_port_binding']['total_addend']-0x7da61013)&0xffffffffffffffff==0
 sdk=Path(subprocess.check_output(['xcrun','--show-sdk-path'],text=True).strip());cmd=['clang','-target','arm64e-apple-macos13.0','-isysroot',str(sdk),'-std=c11','-fsyntax-only','-x','c','-'];compile_result=subprocess.run(cmd,input=SDK_C,text=True,capture_output=True);assert compile_result.returncode==0,compile_result.stderr
 headers=[sdk/'usr/include'/n for n in('servers/bootstrap.h','mach/mach_port.h','sys/event.h','sys/signal.h')]+[sdk/'System/Library/Frameworks/CoreFoundation.framework/Versions/A/Headers'/n for n in('CFMachPort.h','CFRunLoop.h')];hdr=[{'path':str(q),'size_bytes':q.stat().st_size,'sha256':sha(q)}for q in headers]
 cases={r['configuration']['label']:r for r in p['cases']};controls=[]
 def reject(label,row,check=semantic):
  try:check(row)
  except(AssertionError,ValueError,KeyError):controls.append(label);return
  raise AssertionError(('alteration accepted',label))
 def changed_hex(s,offset,raw):return s[:2*offset]+raw.hex()+s[2*(offset+len(raw)):]
 q=copy.deepcopy(cases['registered_signal15']);e=q['service_component_entries'][0]['returned'];e['header96_hex']=changed_hex(e['header96_hex'],24,struct.pack('<Q',SOBJ+16));reject('stored_service_identity',q)
 q=copy.deepcopy(cases['registered_signal15']);e=next(e for e in q['service_frames']if'source1_input_context72_hex'in e);e['source1_input_context72_hex']=changed_hex(e['source1_input_context72_hex'],64,bytes(8));reject('source1_perform_context',q)
 q=copy.deepcopy(cases['registered_signal15']);e=q['service_component_entries'][0]['returned'];e['service_source184_hex']=changed_hex(e['service_source184_hex'],112,struct.pack('<Q',SOBJ+128));reject('source_info_other_epoch',q)
 q=copy.deepcopy(cases['bootstrap_failure']);e=q['service_component_entries'][0]['returned'];e['record40_hex']=changed_hex(e['record40_hex'],16,struct.pack('<I',0x6263fc55));reject('encoded_registration_status',q)
 q=copy.deepcopy(cases['registered_signal15']);e=q['service_before_original_callbacks'][0];e['header96_hex']=changed_hex(e['header96_hex'],24,bytes(8));reject('callback_service_pointer_substitution',q)
 q=copy.deepcopy(cases['registered_signal15']);q['final_service']['model_state']['dictionary']={'0xe03':hex(SSRC)};reject('dictionary_retirement',q)
 q=copy.deepcopy(cases['member_extract_failure']);q['final_service']['model_state']['members']=[x for x in q['final_service']['model_state']['members']if x[1]!='0xe03'];reject('failed_extract_membership',q)
 q=copy.deepcopy(cases['registered_signal15']);q['service_lower_models'][1]['service_after']['registers31'][3]='0';reject('lower_CPU_contract',q)
 q=copy.deepcopy(cases['registered_signal15']);q['original_daemon_callbacks'][0]['return_pc']='0x1847b7e08';reject('original_CF_callback_return',q)
 q=copy.deepcopy(cases['registered_signal15']);e=q['final_private_RAM'];ram=bytearray(zlib.decompress(base64.b64decode(e['zlib_base64'])));ram[SOBJ-B+128]=0;e['sha256']=hashlib.sha256(ram).hexdigest();e['zlib_base64']=base64.b64encode(zlib.compress(ram,9)).decode();reject('service_object_guard',q)
 cs={**s['CF_source'],'root_caller_options':s['root_caller_options'],'bridge_bindings':[{'slot':e['binding']['slot'],'target':hex(e['captured_CF_export']['address'])}for e in s['daemon_to_CF_bindings']]}
 def repeat_one(row):assert Probe(copy.deepcopy(row['configuration']),k,cs).run()==row
 q=copy.deepcopy(cases['bootstrap_failure']);raw=bytearray.fromhex(q['source_writes'][0]['after_hex']);raw[0]^=1;q['source_writes'][0]['after_hex']=raw.hex();reject('ordered_write_after_image',q,repeat_one)
 altered=copy.deepcopy(s);altered['daemon_to_CF_bindings'][-1]['captured_CF_export']['address']+=4
 try:assert altered==fresh
 except AssertionError:controls.append('original_CF_import_target')
 assert len(controls)==12
 counts={'complete_cache_functions_recaptured':len(s['CF_source']['CF_functions']),'captured_instructions':sum(len(f['instructions'])for f in s['CF_source']['CF_functions'])+4*len(s['CF_source']['import_stubs']),'cache_files_hashed':len(s['CF_source']['cache_files']),'selected_daemon_CF_bindings_checked':len(s['daemon_to_CF_bindings']),'original_checkin_ranges_checked':len(s['original_checkin_ranges']),'inherited_daemon_ranges_checked':len(old['original_daemon_ranges']),'new_extract_stub_and_trap_prefix_checked':1,'SDK_headers_hashed':len(hdr),'SDK_arm64e_assertions_checked':SDK_C.count('_Static_assert'),'altered_evidence_controls_rejected':len(controls)}
 summaries=[]
 for row in p['cases']:
  e=row['final_service'];obj=bytes.fromhex(e['object128_hex']);source=bytes.fromhex(e['service_source184_hex']);summaries.append({'label':row['configuration']['label'],'original_visits':len(row['source_visits']),'encoded_status_hex':bytes.fromhex(e['record40_hex'])[16:20].hex(),'service_state_u32':int.from_bytes(obj[16:20],'little'),'service_source_valid':bool(int.from_bytes(source[8:16],'little')&8),'registry':e['registry'],'dictionary':e['model_state']['dictionary'],'members':e['model_state']['members'],'state_mutations':row['service_state_mutations']})
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[P+'_source.json',P+'_profiles.json','recover_'+P+'.py','probe_'+P+'.py','replay_'+P+'.py']},'source_recapture_match':True,'verified_counts':counts,'repeat_and_independent_service_checks':totals,'SDK_headers':hdr,'SDK_compile':{'command':cmd,'inline_C':SDK_C,'exit_code':compile_result.returncode},'case_summaries':summaries,'altered_evidence_rejected':controls,'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'counts':counts,'validation':totals,'altered_controls':controls,'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
