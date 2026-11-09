#!/usr/bin/env python3
"""Read-only KernelArgs, ProcessConfig and environment-compaction capture.
O(dyld bytes + compiler starts + selected words) time/space. No target execution.
"""
import json,re,struct,subprocess
from pathlib import Path
from recover_initializer_programvars import ROOT,DYLD,DyldSlice,SDK,LLVM,sha,h,CS,commands,macho
P='kernel_args_environment'
FLAGS=['target_executed','target_emulated','native_initializer_executed','native_IPC_emitted','native_header_identity_proved','native_environment_provenance_proved','hardware_PAC_checked','IDB_mutated','full_goal_complete']
NAMES={
 'find_envp':'__ZNK5dyld410KernelArgs8findEnvpEv',
 'find_apple':'__ZNK5dyld410KernelArgs9findAppleEv',
 'config_ctor':'__ZN5dyld413ProcessConfigC2EPKNS_10KernelArgsERNS_15SyscallDelegateERN3lsl9AllocatorE',
 'process_ctor':'__ZN5dyld413ProcessConfig7ProcessC2EPKNS_10KernelArgsERNS_15SyscallDelegateERN3lsl9AllocatorE',
 'security_ctor':'__ZN5dyld413ProcessConfig8SecurityC2ERNS0_7ProcessERNS_15SyscallDelegateE',
 'prune_env':'__ZN5dyld413ProcessConfig8Security12pruneEnvVarsERNS0_7ProcessE',
 'header_from_mapped':'__ZN6mach_o6Header14fromDyldMappedEPK11mach_header',
 'header_value':'__ZNK6mach_o6Header6headerEv',
 'starts_with':'__ZNKSt3__117basic_string_viewIcNS_11char_traitsIcEEE11starts_withB9fqn220106EPKc',
 'strlen':'_strlen',
 'simple_getenv':'__simple_getenv',
 'runtime_ctor':'__ZN5dyld412RuntimeStateC2ERKNS_13ProcessConfigERNS_12RuntimeLocksERN3lsl9AllocatorE',
 'security_env_callback':'____ZN5dyld413ProcessConfig8SecurityC2ERNS0_7ProcessERNS_15SyscallDelegateE_block_invoke',
 'header_env_iterator':'__ZNK6mach_o6Header17forEachDyldEnvVarEU13block_pointerFvNSt3__117basic_string_viewIcNS1_11char_traitsIcEEEE7CStringRbE'}

def build():
 raw=DYLD.read_bytes();prior=json.loads((ROOT/'initializer_programvars_source.json').read_text());variants=[]
 for index,label in[(1,'arm64e'),(2,'arm64e.x1')]:
  d=DyldSlice(raw,index,label);roles={r:d.function(d.byname[n])for r,n in NAMES.items()}
  calls=[i for i in roles['starts_with']['instructions']if i['mnemonic']=='bl'];assert len(calls)==2
  a=int(calls[1]['operands'].removeprefix('#'),16);roles['string_compare']=d.function(a)
  assert roles['string_compare']['original_nlist']
  pv=next(v for v in prior['variants']if v['label']==label);compared=[]
  for role in['process_ctor','header_value','runtime_ctor']:
   assert roles[role]==pv['roles'][role];compared.append({'role':role,'sha256':roles[role]['sha256']})
  literals=[]
  for a in([0xae12e,0xae07a,0xae089,0xae0a1]if index==1 else[0xa956e,0xa94ba,0xa94c9,0xa94e1]):
   bb=d.read(a,200).split(b'\0')[0];literals.append({'address':hex(a),'bytes':(bb+b'\0').hex(),'text':bb.decode()})
  frontier_names=['__ZN5dyld413ProcessConfig8Security7getAMFIERKNS0_7ProcessERNS_15SyscallDelegateE']
  frontiers=[{'name':n,'address':hex(d.byname[n]),'original_nlist':d.symbols[d.byname[n]],'semantics_complete':False}for n in frontier_names]
  variants.append({'label':label,'slice':d.slice,'roles':roles,'LLVM':d.llvm_record,'compiler_starts_reference':d.starts_reference,'literals':literals,'prior_roles_recaptured':compared,'policy_frontiers':frontiers})
 daemon_path=Path(prior['daemon']['path']);bb=daemon_path.read_bytes();assert sha(daemon_path)==prior['daemon']['sha256'];dd=macho(bb,0,'daemon');cmds=list(commands(bb,0));embedded=[]
 for at,cmd,size in cmds:
  if cmd==0x27:
   off=struct.unpack_from('<I',bb,at+8)[0];assert off<size
   txt=bb[at+off:at+size].split(b'\0')[0];embedded.append({'file_offset':at,'bytes':bb[at:at+size].hex(),'text':txt.decode()})
 cmd=['/usr/bin/otool','-l',str(daemon_path)];r=subprocess.run(cmd,capture_output=True,text=True);assert r.returncode==0 and not r.stderr
 count=len(re.findall(r'^Load command \d+$',r.stdout,re.M));envcount=len(re.findall(r'^\s+cmd LC_DYLD_ENVIRONMENT$',r.stdout,re.M));assert count==len(cmds)and envcount==len(embedded)
 headers=[SDK/'usr/include/mach-o/loader.h',SDK/'usr/include/crt_externs.h',SDK/'usr/include/stddef.h',SDK/'usr/include/c++/v1/string_view']
 deps=['recover_initializer_programvars.py','initializer_programvars_source.json','initializer_programvars_checks.json','bootpolicy_cache_reader.py','resolve_kernel_collection_interfaces.py','recover_launchd_variant_binding.py']
 bodies=[f for v in variants for f in v['roles'].values()]
 return{'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in deps},'dyld_path':str(DYLD),'dyld_sha256':sha(DYLD),'variants':variants,
  'record_fields':[{'meaning':name,'KernelArgs_offset':ka,'KernelArgs_observed_load_width_bytes':iw,'Process_offset':pr,'ProcessConfig_offset':pr+16,'Process_field_width_bytes':w}for name,ka,iw,pr,w in[('header_span',0,8,0,16),('argc_u32',8,8,0xa8,4),('argv_span',16,None,0xb0,16),('environment_span',None,None,0xc0,16),('apple_span',None,None,0xd0,16)]],
  'daemon':{'path':str(daemon_path),'sha256':sha(daemon_path),'uuid':dd['uuid'],'load_commands':len(cmds),'embedded_dyld_environment_commands':embedded,'independent_otool':{'command':cmd,'exit_code':r.returncode,'stdout_sha256':h(r.stdout.encode()),'load_commands_compared':count,'embedded_environment_commands_compared':envcount},'native_effective_environment_observed':False},
  'SDK_headers':[{'path':str(p),'sha256':sha(p),'size_bytes':p.stat().st_size}for p in headers],
  'inspection_tools':[{'path':str(p),'sha256':sha(p)}for p in[LLVM,Path('/usr/bin/dyld_info'),Path('/usr/bin/otool')]],
  'verified_source_counts':{'dyld_variants':2,'complete_functions':len(bodies),'instructions':sum(len(f['instructions'])for f in bodies),'function_bytes':sum(len(bytes.fromhex(f['bytes']))for f in bodies),'LLVM_only_dyld_words':sum(len(f['extended'])for f in bodies),'compiler_starts_compared':sum(v['compiler_starts_reference']['starts_compared']for v in variants),'prior_function_bodies_recaptured':6,'record_fields':5,'literal_strings':8,'daemon_load_commands_compared':count,'daemon_embedded_environment_commands':envcount},**{k:False for k in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s['verified_source_counts']),flush=True)
