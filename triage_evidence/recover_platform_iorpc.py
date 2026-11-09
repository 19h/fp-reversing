#!/usr/bin/env python3
"""Original platform IORPC builders, local dispatch, adapters and direct thunks.
O(image+symbols+instructions), O(image+captured source); no target operations.
"""
import json,subprocess
from pathlib import Path
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kext_aes_handoff import function
P='platform_iorpc'
def main():
 im=Image();k=im.k;old=json.loads((ROOT/'aes_platform_gate_source.json').read_text());out=dict(old);funcs=list(old['functions']);e=next(e for e in k.entries if e['name']=='com.apple.driver.AppleARMPlatform')
 for a in [0xfffffe0008cfa1e8,0xfffffe0008cfa2e4,0xfffffe0008cfa5fc,0xfffffe0008cf98e8,0xfffffe0008cf9994,0xfffffe0008cf9b9c,0xfffffe0008cf9500,0xfffffe0008cf9530,0xfffffe0008cb47c0,0xfffffe0008cb47f4,0xfffffe0008cb4890,0xfffffe000c5957d4]:
  r=k.function(a,exact=True)if a==0xfffffe000c5957d4 else function(k,e,a);r['exact_symbols']=k.symbols([a])[hex(a)];funcs.append(r)
 slots=[]
 for name,a in [('default_Invoke_import',0xfffffe0008012bc8),('device_Dispatch',0xfffffe0007ff2540)]:
  p=im.pointer(a);slots.append({'name':name,'pointer':p,'exact_symbols':k.symbols([int(p['target'],16)])[p['target']]})
 h=Path('/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/System/Library/Frameworks/Kernel.framework/Headers/IOKit/IORPC.h');assert 'kernelContent'in h.read_text()
 out.update(scope=__doc__,generator_sha256=sha(__file__),dependencies={n:sha(ROOT/n)for n in ['aes_platform_gate_source.json','aes_platform_gate_profiles.json','kernel_vm_mig_tools.py','recover_kext_aes_handoff.py',P+'_prior_manifest.json']},functions=funcs,iorpc_slots=slots,iorpc_constants={'address':'0xfffffe0007172bc8','bytes_hex':k.read(0xfffffe0007172bc8,0x1c8).hex()},rpc_stubs=[{'start':'0xfffffe0008cfede8','end':'0xfffffe0008cfedf8','bytes_hex':k.read(0xfffffe0008cfede8,16).hex()}],local_route_debug={'address':'0xfffffe0007f54318','file_hex':k.read(0xfffffe0007f54318,1).hex(),'native_value_established':False},SDK_IORPC_reference={'path':str(h),'sha256':sha(h),'matched_collection_source_revision_established':False},native_remote_transport_executed=False,runtime_metaclass_hierarchy_established=False,full_goal_complete=False)
 cpp='''#include <stddef.h>
#ifdef KERNEL
#include <IOKit/IORPC.h>
static_assert(sizeof(IORPC)==32);
static_assert(offsetof(IORPC,kernelContent)==24);
static_assert(sizeof(IORPCMessage)==24);
static_assert(sizeof(mach_msg_header_t)==32);
static_assert(sizeof(mach_msg_port_descriptor_t)==16);
static_assert(sizeof(IORPCMessageMach)==36);
static_assert(offsetof(mach_msg_header_t,msgh_id)==28);
#else
#include <mach/message.h>
static_assert(sizeof(mach_msg_header_t)==24);
static_assert(sizeof(mach_msg_port_descriptor_t)==12);
static_assert(offsetof(mach_msg_header_t,msgh_id)==20);
#endif
'''
 probes=[]
 sdk=Path('/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk');headers=h.parents[1]
 for kernel in [False,True]:
  cmd=['clang++','-target','arm64e-apple-macos13.0','-isysroot',str(sdk),*(['-I',str(headers),'-DKERNEL']if kernel else[]),'-std=c++17','-fsyntax-only','-x','c++','-'];r=subprocess.run(cmd,input=cpp,capture_output=True,text=True);assert r.returncode==0,(cmd,r.stderr);probes.append({'kernel':kernel,'command':cmd,'exit_code':r.returncode,'stderr':r.stderr})
 out['SDK_layout_probe']={'source':cpp,'probes':probes,'message_headers':[{'path':str(mh),'sha256':sha(mh)}for mh in [headers/'mach/message.h',sdk/'usr/include/mach/message.h']],'matched_collection_source_revision_established':False,'native_target_executed':False}
 (ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(funcs),'instructions':sum(len(r['instructions'])for r in funcs),'iorpc_slots':len(slots)}),flush=True)
if __name__=='__main__':main()
