#!/usr/bin/env python3
"""Verify static source/ABI/call bindings, algebra proofs and altered evidence.
No target instruction execution/emulation or IPC. O(source+capture+edges),
O(source+capture); compiler and SMT solver costs are separate.
"""
import ast,copy,json,struct,subprocess,hashlib
from recover_kernel_membership_removal import *
from analyze_kernel_membership_removal import analyze
SDK_C='''#include <stddef.h>
#include <stdint.h>
#include <mach/mach.h>
#include <mach/ndr.h>
struct selected_slots { uint64_t task,member,set; };
struct selected_request { mach_msg_header_t header; NDR_record_t ndr; mach_port_name_t member,set; };
struct selected_reply { mach_msg_header_t header; NDR_record_t ndr; kern_return_t result; };
_Static_assert(sizeof(mach_port_name_t)==4,"name4");
_Static_assert(sizeof(mach_port_right_t)==4,"right4");
_Static_assert(sizeof(mach_port_delta_t)==4,"delta4");
_Static_assert((mach_port_delta_t)-1<0,"signed delta");
_Static_assert(sizeof(struct selected_slots)==24,"slots24");
_Static_assert(offsetof(struct selected_slots,member)==8,"member slot8");
_Static_assert(offsetof(struct selected_slots,set)==16,"set slot16");
_Static_assert(sizeof(mach_msg_header_t)==24,"user header24");
_Static_assert(sizeof(NDR_record_t)==8,"NDR8");
_Static_assert(sizeof(struct selected_request)==40,"request40");
_Static_assert(offsetof(struct selected_request,member)==32,"member32");
_Static_assert(offsetof(struct selected_request,set)==36,"set36");
_Static_assert(sizeof(struct selected_reply)==36,"reply36");
_Static_assert(KERN_SUCCESS==0,"success0");
_Static_assert(KERN_NOT_IN_SET==12,"not in set12");
_Static_assert(KERN_INVALID_NAME==15,"invalid name15");
_Static_assert(KERN_INVALID_TASK==16,"invalid task16");
_Static_assert(KERN_INVALID_RIGHT==17,"invalid right17");
_Static_assert(MACH_SEND_INVALID_DEST==0x10000003,"fallback status");
_Static_assert(MACH_PORT_NULL==0 && MACH_PORT_DEAD==0xffffffff,"sentinel names");
_Static_assert(MACH_PORT_TYPE_RECEIVE==0x20000 && MACH_PORT_TYPE_PORT_SET==0x80000,"pair type bits");
_Static_assert(__builtin_types_compatible_p(__typeof__(&mach_port_extract_member),kern_return_t(*)(ipc_space_t,mach_port_name_t,mach_port_name_t)),"extract ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&mach_port_deallocate),kern_return_t(*)(ipc_space_t,mach_port_name_t)),"deallocate ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&mach_port_mod_refs),kern_return_t(*)(ipc_space_t,mach_port_name_t,mach_port_right_t,mach_port_delta_t)),"mod_refs ABI");
'''
def main():
 source=json.loads((ROOT/(P+'_source.json')).read_text());contracts=json.loads((ROOT/(P+'_contracts.json')).read_text());assert source==build();computed=analyze(source)
 for k,v in computed.items():assert contracts[k]==v,k
 for obj,script in((source,'recover_'+P+'.py'),(contracts,'analyze_'+P+'.py')):
  assert obj['generator_sha256']==sha(ROOT/script)and all(obj[k]is False for k in FLAGS)
  for n,h in obj['dependencies'].items():assert sha(ROOT/n)==h,n
 for f in source['kernel_functions']+source['cache_functions']:raw=bytes.fromhex(f['bytes']);assert len(raw)==int(f['end'],16)-int(f['start'],16)==4*len(f['instructions']);assert hashlib.sha256(raw).hexdigest()==f['sha256']
 assert source['kernel_sha256']=='d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe'and source['kernel_UUID']=='9b65bd6e-027b-34d1-a22b-ac03dccffc84'
 assert source['original_CF_stub']['export']['address']==0x18054b360 and source['original_CF_stub']['pointer']['chain_membership_verified']
 sdk=Path(subprocess.check_output(['xcrun','--show-sdk-path'],text=True).strip());cmd=['clang','-target','arm64e-apple-macos13.0','-isysroot',str(sdk),'-std=c11','-fsyntax-only','-x','c','-'];result=subprocess.run(cmd,input=SDK_C,text=True,capture_output=True);assert result.returncode==0,result.stderr
 headers=[sdk/'usr/include'/n for n in('mach/mach_port.h','mach/message.h','mach/kern_return.h','mach/ndr.h')];hdr=[{'path':str(q),'size_bytes':q.stat().st_size,'sha256':sha(q)}for q in headers]
 controls=[]
 def reject(label,changed,check=analyze):
  try:check(changed)
  except(AssertionError,ValueError,KeyError):controls.append(label);return
  raise AssertionError(('alteration accepted',label))
 def change(a,m=None,o=None):
  s=copy.deepcopy(source);i=next(i for f in s['kernel_functions']+s['cache_functions']for i in f['instructions']if int(i['ea'],16)==a)
  if m:i['mnemonic']=m
  if o:i['operands']=o
  return s
 s=copy.deepcopy(source);s['original_trap_bindings'][-1]['handler_pointer']['target']='0xfffffe000bcdbcc4';reject('extract_bound_to_insert_handler',s)
 s=copy.deepcopy(source);s['original_trap_bindings'][-1]['argument_count']=4;reject('extract_argument_count',s)
 reject('munger_store_width',change(0xfffffe000bf0871c,o='w8, [x0, #0x10]'))
 s=copy.deepcopy(source);s['cache_constants'][1]['bytes8_hex']=struct.pack('<II',0,3226).hex();reject('fallback_request_ID',s)
 reject('user_request_extent',change(0x18056dd14,o='x2, #0x2c, lsl #32'))
 reject('reply_ID',change(0x18056dd64,o='w8, #0xcfe'))
 reject('link_free_dispatch',change(0xfffffe000bce0074,o='#0xfffffe000bcd3cfc'))
 reject('sentinel_return_value',change(0xfffffe000bce0000,o='w0, #0'))
 reject('receive_type_bit',change(0xfffffe000bcc93b8,o='w24, #0x10, #0xfffffe000bcc93d0'))
 s=copy.deepcopy(source);s['kernel_NDR8_hex']='00'*8;reject('kernel_NDR',s)
 reject('kernel_request_extent',change(0xfffffe000bd87b88,o='w8, #0x28'))
 proof=copy.deepcopy(contracts['proofs'][0]);proof['negated_equivalence_SMT2']='\n'.join('(assert true)'if line.startswith('(assert ')else line for line in proof['negated_equivalence_SMT2'].splitlines())+'\n'
 def verify_proof(p):
  r=subprocess.run(p['command'],input=p['negated_equivalence_SMT2'],text=True,capture_output=True,timeout=15);assert r.returncode==0 and r.stdout.strip()=='unsat'
 reject('changed_algebra_query',proof,verify_proof);assert len(controls)==12
 scripts=['recover_'+P+'.py','analyze_'+P+'.py','validate_'+P+'.py']
 for name in scripts:
  tree=ast.parse((ROOT/name).read_text());assert not any(isinstance(n,ast.Attribute)and n.attr in('emu_start','mem_write','reg_write')for n in ast.walk(tree))
 counts={'kernel_functions_recaptured':len(source['kernel_functions']),'kernel_instructions_captured':sum(len(f['instructions'])for f in source['kernel_functions']),'cache_functions_recaptured':len(source['cache_functions']),'cache_instructions_captured':sum(len(f['instructions'])for f in source['cache_functions']),'cache_files_hashed':len(source['cache_files']),'trap_bindings_checked':len(source['original_trap_bindings']),'MIG_routine_bindings_checked':1,'exact_instruction_assertions':len(computed['instruction_assertions']),'direct_call_edges_recorded':len(computed['direct_call_edges']),'unresolved_indirect_sites_recorded':len(computed['unresolved_indirect_sites']),'algebra_proofs_unsat':len(computed['proofs']),'SDK_headers_hashed':len(hdr),'SDK_assertions_checked':SDK_C.count('_Static_assert'),'altered_static_controls_rejected':len(controls)}
 static={'target_instruction_visits':0,'target_instructions_emulated':0,'runtime_states_observed':0,'function_bytes_checked':sum(len(bytes.fromhex(f['bytes']))for f in source['kernel_functions']+source['cache_functions']),'analysis_scripts_checked_for_target_emulator_methods':len(scripts)}
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in[P+'_source.json',P+'_contracts.json','recover_'+P+'.py','analyze_'+P+'.py']},'source_recapture_match':True,'verified_counts':counts,'static_scope':static,'SDK_headers':hdr,'SDK_compile':{'command':cmd,'inline_C':SDK_C,'exit_code':result.returncode},'altered_evidence_rejected':controls,'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'counts':counts,'scope':static,'all_checks_pass':True}),flush=True)
if __name__=='__main__':main()
