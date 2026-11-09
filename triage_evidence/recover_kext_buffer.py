#!/usr/bin/env python3
"""Pinned buffer factory/vtable/getter and kext caller contracts, read-only source.

No native allocation, preparation, provider, IPC, reference or IDB operation.
O(source bytes + symbol entries + selected pointer-chain work) time/space.
"""
import hashlib,json,subprocess
from pathlib import Path
from kernel_native_reader import Kernel
from kext_port_tools import SOURCE,IMAGE,CS,ROOT
from recover_kext_cold_init import pointer
SDK=Path('/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk')
HEAD=SDK/'System/Library/Frameworks/Kernel.framework/Headers'
FUNCTIONS=[0xfffffe000c526070,0xfffffe000c525c48,0xfffffe000c525694,0xfffffe000c525cd0,0xfffffe000c525d04,0xfffffe000c525f70,0xfffffe000c525fc0,0xfffffe000c5353b4,0xfffffe000c524b60,0xfffffe000c524bdc,0xfffffe000c525288,0xfffffe000c534a2c]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def sdk_command():return ['clang++','-target','arm64e-apple-macos13.0','-isysroot',str(SDK),'-I',str(HEAD),'-DKERNEL','-std=c++17','-fsyntax-only',str(ROOT/'kext_buffer_sdk_probe.cpp')]
def main():
 k=Kernel();ranges=[]
 for a,z in[(0xfffffe000a508030,0xfffffe000a5081b0),(0xfffffe000a508c78,0xfffffe000a508cc4),(0xfffffe000a5085e0,0xfffffe000a5086a0)]:
  raw=IMAGE.read(a,z-a);ranges.append({'start':hex(a),'end':hex(z),'bytes_hex':raw.hex(),'sha256':hashlib.sha256(raw).hexdigest(),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(raw,a)]})
 slots=[]
 for vt,offsets,kind in[(0xfffffe0007f85d70,[0x28,0x218,0x220,0x268,0x308],'buffer'),(0xfffffe0007f410b0,[0xa8],'buffer_metaclass'),(0xfffffe0007f89188,[0x28],'provider'),(0xfffffe0007f44080,[0x218,0x308],'base_negative_control')]:
  for off in offsets:
   p=pointer(k,vt+16+off);p.update(vtable_symbol_address=hex(vt),vptr_base_addend=16,offset_from_vptr=off,kind=kind);slots.append(p)
 addrs=FUNCTIONS+[int(e['target'],16)for e in slots]+[0xfffffe0007f85d70,0xfffffe0007f410b0,0xfffffe0007f44080,0xfffffe000cb5bdb0];symbols=k.symbols(addrs)
 for e in slots:e['exact_symbols']=symbols[e['target']]
 command=sdk_command();r=subprocess.run(command,capture_output=True,text=True);assert r.returncode==0,(r.stdout,r.stderr);version=subprocess.run(['clang++','--version'],capture_output=True,text=True);assert version.returncode==0
 headers=[HEAD/'IOKit/IOBufferMemoryDescriptor.h',HEAD/'IOKit/IOMemoryDescriptor.h',HEAD/'IOKit/IOTypes.h'];cp=Path(str(SOURCE)+'.c');lines=cp.read_text().splitlines(keepends=True);excerpt=''.join(lines[13068:13134])
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'kernel_uuid':k.kernel['uuid'],'dependencies':{n:sha(ROOT/n)for n in['recover_kext_cold_init.py','kernel_native_reader.py','kext_port_tools.py','resolve_kernel_collection_interfaces.py','kext_cold_init_contracts.json','kext_buffer_sdk_probe.cpp']},'kext_ranges':ranges,'kernel_functions':[k.function(a)for a in FUNCTIONS],'nominal_slots':slots,'exact_symbols':symbols,'SDK_probe':{'command':command,'compile_exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr,'compiler_version':version.stdout,'source_sha256':sha(ROOT/'kext_buffer_sdk_probe.cpp'),'primary_headers':[{'path':str(p),'sha256':sha(p)}for p in headers]},'associated_decompilation':{'path':str(cp),'sha256':sha(cp),'line_start':13069,'line_end':13134,'excerpt':excerpt,'excerpt_sha256':hashlib.sha256(excerpt.encode()).hexdigest(),'source_instructions_authoritative_for_arguments':True},'new_live_IDB_ranges':0,'native_target_executed':False,'native_provider_executed':False,'native_prepare_executed':False,'full_goal_complete':False};(ROOT/'kext_buffer_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'kext_ranges':len(ranges),'kernel_functions':len(FUNCTIONS),'nominal_slots':len(slots),'SDK_compile_exit':r.returncode}),flush=True)
if __name__=='__main__':main()
