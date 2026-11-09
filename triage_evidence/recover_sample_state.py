#!/usr/bin/env python3
"""Original state setup, fill/copy bindings and data-allocation ABI context.

Read-only original KC/normalized bytes, symbols and chained slots. Compile-only
SDK probe. O(B+I+256R+chain work) source time/space; no target operation.
"""
import hashlib,json,subprocess
from pathlib import Path
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,selected,qword
from kernel_native_reader import Kernel
from recover_kext_aes_handoff import function
from recover_kext_cold_init import pointer
SDK=Path('/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk');HEAD=SDK/'System/Library/Frameworks/Kernel.framework/Headers'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def sdk_command(output=None):return ['clang++','-target','arm64e-apple-macos13.0','-isysroot',str(SDK),'-I',str(HEAD),'-DKERNEL','-std=c++17','-O2','-S',str(ROOT/'sample_state_sdk_probe.cpp'),'-o',output or str(ROOT/'sample_state_sdk_probe.s')]
def span(k,a,n):
 raw=k.read(a,n);assert raw==IMAGE.read(a,n);return {'start':hex(a),'size_bytes':n,'bytes_hex':raw.hex(),'sha256':hashlib.sha256(raw).hexdigest(),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(raw,a)]}
def main():
 k=Kernel();fp=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');functions=[function(k,fp,a)for a in[0xfffffe000a6247a4,0xfffffe000a687d64,0xfffffe000a508cf4]]
 for f in functions:assert IMAGE.read(int(f['start'],16),int(f['end'],16)-int(f['start'],16)).hex()==f['bytes_hex']
 fam={'A':(0xfffffe0007949dd0,0xfffffe000792fbc0),'B':(0xfffffe0007949fd0,0xfffffe000792ffc0),'C':(0xfffffe0007949ed0,0xfffffe000792fec0),'E':(0xfffffe0007941f60,0xfffffe000794a0d0)}
 specs=[('clear','A',0xd8,0xeca),('copy16_mode3','A',0x16,0xea0),('copy32_mode3','A',0xd8,0xf08),('copy16_default','B',0x37,0xeee),('copy32_default','C',0x92,0xe86),('allocate_workspace','C',0x92,0xe6e),('free_workspace','A',0x5c,0xe48),('release_samples','E',0x98,0xe9e),('copy16_per_sample','A',0xb4,0xeba),('read_sample_size','E',5,0xf10)];rules=[]
 for label,family,key,add in specs:
  b=selected(*fam[family],key,add);b.update(label=label,original_pointer=pointer(k,int(b['slot'],16)),left256_hex=IMAGE.read(fam[family][0],256).hex(),right256_hex=IMAGE.read(fam[family][1],256).hex());rules.append(b)
 assert next(b for b in rules if b['label']=='release_samples')['target']=='0xfffffe000a509ba0';copy=pointer(k,0xfffffe000847c4c8);syms=k.symbols([0xfffffe000c647f10,0xfffffe000c4ba60c,0xfffffe000c4ba84c,0xfffffe0007f8bfb0,0xfffffe000bcfe5b8,0xfffffe000bcfec48]);assert int(copy['target'],16)==0xfffffe000c647f10;assert {s['name']for s in syms[copy['target']]}=={'_memcpy','_memmove'}
 kernels=[k.function(a)for a in[0xfffffe000c4ba60c,0xfffffe000c4ba84c,0xfffffe000c647f10]];r=subprocess.run(sdk_command(),capture_output=True,text=True);assert r.returncode==0,(r.stdout,r.stderr)
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['kext_port_tools.py','kernel_native_reader.py','recover_kext_aes_handoff.py','recover_kext_cold_init.py','sample_caller_contracts.json','sample_state_sdk_probe.cpp']},'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'functions':functions,'copy_import_stub':span(k,0xfffffe000a69f334,16),'copy_import_pointer':copy,'bank_rules':rules,'kernel_functions':kernels,'exact_symbols':syms,'deeper_allocator_abi':{'allocation_callee':'0xfffffe000bcfe5b8','free_callee':'0xfffffe000bcfec48','shared_context_operand':'0xfffffe0007f8bfb0','allocation_registers':'X0=context;X1=request64;W2=0x31000;X3=0','free_registers':'X0=context;X1=pointer64;X2=extent64','callee_and_context_names':'unknown: no exact symbols','native_heap_domain_proved':False},'state_contract':{'header_word0':128,'clear_start':4,'clear_extent':168,'mode_code_offset':36,'opaque32_length_offset':40,'opaque16_offset':4,'opaque32_offset':44,'per_sample_opaque16_offset':176,'counter_c4_offset':196,'minimum_object_access_extent':200,'minimum_header_copy_extent':89,'workspace_request_bytes':8192,'business_code_names':'unknown'},'SDK_probe':{'command':sdk_command(),'compile_exit':r.returncode,'stderr':r.stderr,'assembly_path':'sample_state_sdk_probe.s','assembly_sha256':sha(ROOT/'sample_state_sdk_probe.s'),'header_path':str(HEAD/'IOKit/IOLib.h'),'header_sha256':sha(HEAD/'IOKit/IOLib.h')},'native_target_executed':False,'native_lifetime_proved':False,'full_goal_complete':False};(ROOT/'sample_state_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'kext_functions':len(functions),'kernel_functions':len(kernels),'bank_rules':len(rules),'SDK_compile_exit':r.returncode}),flush=True)
if __name__=='__main__':main()
