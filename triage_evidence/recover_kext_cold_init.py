#!/usr/bin/env python3
"""Original cold-allocation/provider ABI and matching kernel/SDK context.

Source/fixup/descriptor analysis only. Nominal vtable bindings do not identify
live receivers/PAC. No native allocator, provider, IPC, reference or IDB action.
O(B+I+N+selected pointer-chain work), bounded by consumed source pages.
"""
import hashlib,json,struct,subprocess
from pathlib import Path
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,qword
from kernel_native_reader import Kernel
from resolve_kernel_collection_interfaces import commands
SDK=Path('/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def pointer(k,a):
 base=next(s['address']for s in k.root['segments']if s['file_offset']==0);at=next(o for o,c,n in commands(k.data,0)if c==0x80000034);fo,fs=struct.unpack_from('<II',k.data,at+8);ver,starts,*rest=struct.unpack_from('<7I',k.data,fo);st=fo+starts
 j,seg=next((i,s)for i,s in enumerate(k.root['segments'])if s['address']<=a<a+8<=s['address']+s['file_size']);delta=struct.unpack_from('<I',k.data,st+4+4*j)[0];assert delta;info=st+delta;sz,ps,fmt,vmoff,mp,np=struct.unpack_from('<IHHQIH',k.data,info);assert fmt==8 and seg['address']==base+vmoff;page=(a-seg['address'])//ps;start=struct.unpack_from('<H',k.data,info+22+2*page)[0];assert start!=0xffff;chain=[]
 if start&0x8000:
  ix=start&0x7fff
  while True:
   v=struct.unpack_from('<H',k.data,info+22+2*ix)[0];chain.append(v&0x7fff);ix+=1
   if v&0x8000:break
 else:chain=[start]
 wanted=seg['file_offset']+a-seg['address'];found=None
 for start in chain:
  off=seg['file_offset']+page*ps+start
  while True:
   word=struct.unpack_from('<Q',k.data,off)[0]
   if off==wanted:found=word;break
   step=(word>>51)&0xfff
   if not step:break
   off+=step*4
   if off>=seg['file_offset']+(page+1)*ps:break
  if found is not None:break
 assert found is not None and(found>>30)&3==0;return {'slot':hex(a),'word':hex(found),'target':hex(base+(found&0x3fffffff)),'pointer_format':8,'chain_membership_verified':True,'authenticated':bool(found>>63),'diversity':hex((found>>32)&0xffff)}
def main():
 k=Kernel();descriptors=[]
 for a in[0xfffffe000847b460,0xfffffe000847b3a0]:
  raw=IMAGE.read(a,64);nameptr=struct.unpack_from('<Q',raw,16)[0];name=IMAGE.read(nameptr,128).split(b'\0')[0];flags,size=struct.unpack_from('<2I',raw,40);descriptors.append({'address':hex(a),'bytes64_hex':raw.hex(),'site_name_pointer':hex(nameptr),'site_name':name.decode(),'flags_word_at40':flags,'size_word_at44':size,'fallback_size24':size&0xffffff})
 ranges=[]
 for a,z in[(0xfffffe000a5c0178,0xfffffe000a5c0868),(0xfffffe000a508030,0xfffffe000a5081b0),(0xfffffe000a687d64,0xfffffe000a687ecc),(0xfffffe000a508c78,0xfffffe000a508cc4)]:
  raw=IMAGE.read(a,z-a);ranges.append({'start':hex(a),'end':hex(z),'bytes':raw.hex(),'sha256':hashlib.sha256(raw).hexdigest(),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(raw,a)]})
 kernel=[k.function(a)for a in[0xfffffe000c4ba154,0xfffffe000bcfeb8c,0xfffffe000c4ba368,0xfffffe000c4eb5d8]];slots=[0xfffffe000847c450,0xfffffe000847c458,0xfffffe000847c428,0xfffffe000847c608,0xfffffe000847c5b0];bindings=[]
 for a in slots:
  target=qword(a);bindings.append({'slot':hex(a),'word_hex':IMAGE.read(a,8).hex(),'target':hex(target),'symbols':k.symbols([target])[hex(target)]})
 nominal=[]
 for vt in[0xfffffe0007f8a020,0xfffffe0007f89188]:
  for off in[0x20,0x28]:e=pointer(k,vt+16+off);e.update(vtable_symbol_address=hex(vt),nominal_vptr_offset=off);e['symbols']=k.symbols([int(e['target'],16)])[e['target']];nominal.append(e)
 targets=[0xfffffe000c4ba154,0xfffffe000c4ba368,0xfffffe000c4ece88,0xfffffe000c4eb5d8,0xfffffe0007f8a020,0xfffffe0007f89188];symbols=k.symbols(targets);shift=struct.unpack('<I',k.read(0xfffffe0007e6d9c0,4))[0]
 header=SDK/'usr/include/mach/clock_types.h';probe=ROOT/'kext_cold_init_layouts.c';probe.write_text('#include <mach/clock_types.h>\n#include <stddef.h>\n_Static_assert(sizeof(mach_timespec_t)==8,"timespec8");\n_Static_assert(offsetof(mach_timespec_t,tv_sec)==0,"seconds0");\n_Static_assert(offsetof(mach_timespec_t,tv_nsec)==4,"nanoseconds4");\n_Static_assert(sizeof(((mach_timespec_t*)0)->tv_sec)==4,"seconds32");\n_Static_assert(sizeof(((mach_timespec_t*)0)->tv_nsec)==4,"nanoseconds32");\n_Static_assert((clock_res_t)-1<0,"signed nanoseconds");\n');r=subprocess.run(['clang','-target','arm64e-apple-macos13.0','-isysroot',str(SDK),'-fsyntax-only',str(probe)],capture_output=True,text=True);assert r.returncode==0,(r.stdout,r.stderr)
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'kernel_uuid':k.kernel['uuid'],'dependencies':{n:sha(ROOT/n)for n in['probe_kext_cold_init.py','kext_cold_init_profiles.json','probe_kext_close.py','kext_port_tools.py','kernel_native_reader.py','resolve_kernel_collection_interfaces.py']},'typed_descriptors':descriptors,'kext_ranges':ranges,'kernel_functions':kernel,'exact_symbols':symbols,'original_bindings':bindings,'nominal_reference_slots':nominal,'matching_string':{'address':'0xfffffe000790ba3c','bytes_hex':IMAGE.read(0xfffffe000790ba3c,17).hex(),'text':'IOAESAccelerator'},'SDK_probe':{'path':probe.name,'sha256':sha(probe),'header_path':str(header),'header_sha256':sha(header),'compile_exit':r.returncode,'stderr':r.stderr},'PAGE_SHIFT_CONST':{'address':'0xfffffe0007e6d9c0','original_word_hex':k.read(0xfffffe0007e6d9c0,4).hex(),'value':shift},'conditional_buffer_capacity_bytes':0x14000,'conditional_buffer_alignment_expression':'sign_extend64(1U << (runtime_PAGE_SHIFT_CONST & 31));runtime value unknown','native_target_executed':False,'provider_success_executed':False,'complete_initialization_proved':False,'full_goal_complete':False};(ROOT/'kext_cold_init_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'kext_ranges':len(ranges),'kernel_functions':len(kernel),'typed_descriptors':len(descriptors),'nominal_reference_slots':len(nominal),'SDK_compile_exit':r.returncode}),flush=True)
if __name__=='__main__':main()
