#!/usr/bin/env python3
"""Original startup/constructor, lazy AES discovery, descriptor ABI and error copy.
O(image bytes+instructions), O(image bytes); no target or IOKit/PAC operation.
"""
import hashlib,json,struct
from pathlib import Path
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT,IMAGE
from recover_kext_constructor_request import sha
P='kext_startup_hardware_bridge'
def main():
 im=Image();k=im.k;ranges=[]
 for a,z in [(0xfffffe000a66a7e0,0xfffffe000a66acb0),(0xfffffe000a608108,0xfffffe000a6086c0),(0xfffffe000a687ee0,0xfffffe000a6890c0),(0xfffffe000a508030,0xfffffe000a5081b0),(0xfffffe000a508484,0xfffffe000a508534),(0xfffffe000a508c78,0xfffffe000a508cc4),(0xfffffe000c4eb5d8,0xfffffe000c4eb670)]:
  raw=k.read(a,z-a)
  if a<0xfffffe000b000000:assert IMAGE.read(a,z-a)==raw
  ranges.append({'start':hex(a),'end':hex(z),'bytes_hex':raw.hex(),'sha256':hashlib.sha256(raw).hexdigest(),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in k.cs.disasm(raw,a)]})
 slots=[]
 for name,a in [('serviceMatching',0xfffffe000847c458),('waitForService',0xfffffe000847c450),('inTaskWithOptions',0xfffffe000847c428),('kernel_task',0xfffffe000847c608),('PAGE_SHIFT_CONST',0xfffffe000847c5b0),('nominal_provider_retain',0xfffffe00085883a0),('nominal_descriptor_prepare',0xfffffe0007f85f98),('nominal_descriptor_bytes',0xfffffe0007f86088),('nominal_provider_performAES',0xfffffe0008588c10)]:
  ptr=im.pointer(a);target=int(ptr['target'],16);slots.append({'name':name,'pointer':ptr,'exact_symbols':k.symbols([target])[ptr['target']]})
 views=[]
 for a in [0xfffffe000847b460,0xfffffe000847b3a0]:
  raw=k.read(a,64);ptr=im.pointer(a+16);name=k.read(int(ptr['target'],16),100).split(b'\0')[0];views.append({'address':hex(a),'bytes64_hex':raw.hex(),'name_pointer':ptr,'name':name.decode(),'size_bytes':struct.unpack_from('<I',raw,44)[0]})
 assert all(v['name']=='site.FPAESParameters'and v['size_bytes']==104 for v in views)
 a=0xfffffe000a66ab54;instructions=[(i.mnemonic,i.op_str)for i in k.cs.disasm(k.read(a,16),a)];assert instructions==[('ldr','w27, [x20, #0x14]'),('ldr','w8, [sp, #0x48]'),('ldr','x9, [sp, #0x38]'),('str','x8, [x9]')]
 header=Path('/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/System/Library/Frameworks/Kernel.framework/Headers/mach/clock_types.h');text=header.read_text();assert 'typedef int     clock_res_t;'in text and 'unsigned int    tv_sec;'in text and 'clock_res_t     tv_nsec;'in text
 globals=[0xfffffe000cccea88,0xfffffe000ccca078,0xfffffe000ccceb00,0xfffffe000ccceb08,0xfffffe000ccceb10,0xfffffe000ccc7848]
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['kernel_vm_mig_tools.py','kext_port_tools.py','kext_provider_initialize_source.json','kext_cold_init_contracts.json','kext_aes_handoff_contracts.json']},'kernel_sha256':k.sha256,'ranges':ranges,'slots':slots,'views':views,'global_exact_symbols':k.symbols(globals),'unconditional_output_copy':{'start':hex(a),'instructions':instructions,'source_argument_record_output_offset':8,'loaded_width_bytes':4,'stored_width_bytes':8},'SDK_timespec_reference':{'path':str(header),'sha256':sha(header),'field_offsets_bytes':[0,4],'field_widths_bytes':[4,4],'tv_nsec_signed':True,'new_compile_executed':False,'matching_kernel_consumption_range':['0xfffffe000c4eb5f0','0xfffffe000c4eb604']},'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'ranges':len(ranges),'instructions':sum(len(r['instructions'])for r in ranges),'exact_slots':len(slots),'views':len(views),'new_SMT_proofs':0}),flush=True)
if __name__=='__main__':main()
