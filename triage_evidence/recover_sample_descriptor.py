#!/usr/bin/env python3
"""Original global-media-descriptor wrappers, concrete factory and SDK context.

Read-only source/ABI recovery. No task mapping, copy, reference, crypto or IDB
operation executes. O(B+N+selected pointer chains) time/source retained space.
"""
import hashlib,json,subprocess
from pathlib import Path
from kext_port_tools import ROOT,SOURCE,IMAGE,qword,CS,POOL,TABLE,selected
from kernel_native_reader import Kernel
from recover_kext_aes_handoff import function,definitions
from recover_kext_cold_init import pointer
SDK=Path('/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk');HEAD=SDK/'System/Library/Frameworks/Kernel.framework/Headers'
GROUPS={'sample_sizes':{'global':0xfffffe000ccc7858,'options':2,'create':0xfffffe000a509948,'prepare':0xfffffe000a5099b8,'read':0xfffffe000a509a60,'write':0xfffffe000a509b00,'release':0xfffffe000a509bd4,'complete':0xfffffe000a509c08},'samples':{'global':0xfffffe000ccc7860,'options':3,'create':0xfffffe000a509980,'prepare':0xfffffe000a509a0c,'read':0xfffffe000a509ab0,'write':0xfffffe000a509b50,'release':0xfffffe000a509ba0,'complete':0xfffffe000a509c48},'input':{'global':0xfffffe000ccc7868,'options':2,'create':0xfffffe000a509cc0,'prepare':0xfffffe000a509cf8,'read':0xfffffe000a509da0,'write':0xfffffe000a509e90,'release':0xfffffe000a509ee0,'complete':0xfffffe000a509f48},'output':{'global':0xfffffe000ccc7870,'options':3,'create':0xfffffe000a509c88,'prepare':0xfffffe000a509d4c,'read':0xfffffe000a509df0,'write':0xfffffe000a509e40,'release':0xfffffe000a509f14,'complete':0xfffffe000a509f88}}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def sdk_command(output=None):return ['clang++','-target','arm64e-apple-macos13.0','-isysroot',str(SDK),'-I',str(HEAD),'-DKERNEL','-std=c++17','-O2','-S',str(ROOT/'sample_descriptor_sdk_probe.cpp'),'-o',output or str(ROOT/'sample_descriptor_sdk_probe.s')]
def main():
 k=Kernel();fp=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');functions=[]
 for group,g in GROUPS.items():
  for kind in['create','prepare','read','write','release','complete']:
   r=function(k,fp,g[kind]);assert IMAGE.read(int(r['start'],16),int(r['end'],16)-int(r['start'],16)).hex()==r['bytes_hex'];r.update(group=group,kind=kind,global_pointer=hex(g['global']),options=g['options']);functions.append(r)
 for a,kind in[(0xfffffe000a509fc8,'pointer_equal'),(0xfffffe000a509fe8,'samples_bridge')]:r=function(k,fp,a);r['kind']=kind;functions.append(r)
 wanted=['__ZTV25IOGeneralMemoryDescriptor','__ZTVN25IOGeneralMemoryDescriptor9MetaClassE'];defs=definitions(k,wanted);slots=[]
 for n,offs in[(wanted[0],[0x28,0x138,0x208,0x210,0x218,0x220]),(wanted[1],[0xa8])]:
  assert len(defs[n])==1;vt=int(defs[n][0]['address'],16)
  for off in offs:p=pointer(k,vt+16+off);p.update(vtable_symbol=n,vtable_symbol_address=hex(vt),offset_from_vptr=off);p['exact_symbols']=k.symbols([int(p['target'],16)])[p['target']];slots.append(p)
 for row in slots:
  if row['offset_from_vptr']in[0x208,0x210]:
   thunk=k.function(int(row['target'],16));assert len(thunk['instructions'])==2 and thunk['instructions'][1]['mnemonic']=='b';target=int(thunk['instructions'][1]['operands'][1:],16);row['tail_target']=hex(target);row['tail_target_exact_symbols']=k.symbols([target])[hex(target)]
 kernel=[k.function(a)for a in[0xfffffe000c53a934,0xfffffe000c538da4,0xfffffe000c537720,0xfffffe000c5361cc,0xfffffe000c5361d4,0xfffffe000c5312b8,0xfffffe000c5314ec]];binding={'slot':'0xfffffe000847c420','target':hex(qword(0xfffffe000847c420)),'symbols':k.symbols([qword(0xfffffe000847c420)])[hex(qword(0xfffffe000847c420))]};symbols=k.symbols([0xfffffe000cb53108,0xfffffe000c538da4,0xfffffe000c537720]+[int(r['start'],16)for r in functions]);r=subprocess.run(sdk_command(),capture_output=True,text=True);assert r.returncode==0,(r.stdout,r.stderr)
 adapter_raw=IMAGE.read(0xfffffe000a5c22b8,0x21c);adapter={'start':'0xfffffe000a5c22b8','prefix_end':'0xfffffe000a5c24d4','bytes_hex':adapter_raw.hex(),'sha256':hashlib.sha256(adapter_raw).hexdigest(),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in CS.disasm(adapter_raw,0xfffffe000a5c22b8)],'table_base_rule':selected(0xfffffe0007949dd0,0xfffffe000792fbc0,0x73,-0x14,base=POOL,bias=-12),'bounds_target_rule':selected(qword(POOL+0x840),qword(POOL+0xbb8),0xd8,0xf01,base=TABLE),'record_min_extent_bytes':56,'address_xor32':'0x7abbf985','address_multiplier32':'0xded29631','post_guard_index':'sign_extend32(decoded_selector XOR (0xa3 * (record_pointer_at10 == 0)))','native_reachability_proved':False,'complete_role_proved':False};assert adapter['bounds_target_rule']['target']=='0xfffffe000a687ecc'
 source=ROOT/'sample_descriptor_sdk_probe.s';assembly=source.read_text();assert all(x in assembly for x in['#520','#528','#64512','#20603'])
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'kernel_uuid':k.kernel['uuid'],'dependencies':{n:sha(ROOT/n)for n in['kext_port_tools.py','kernel_native_reader.py','recover_kext_aes_handoff.py','recover_kext_cold_init.py','resolve_kernel_collection_interfaces.py','sample_descriptor_sdk_probe.cpp']},'groups':{n:{k:hex(v)if k!='options'else v for k,v in g.items()}for n,g in GROUPS.items()},'functions':functions,'kernel_functions':kernel,'nominal_slots':slots,'exact_definitions':defs,'exact_symbols':symbols,'factory_binding':binding,'partial_record_adapter':adapter,'factory_record':{'size_bytes':16,'address_offset':0,'length_offset':8,'count':1,'offset':0,'mapper':0,'raw_type_if_task_null':'0x20','raw_type_if_task_nonnull':'0x10'},'SDK_probe':{'command':sdk_command(),'compile_exit':r.returncode,'stderr':r.stderr,'assembly_path':source.name,'assembly_sha256':sha(source),'header_path':str(HEAD/'IOKit/IOMemoryDescriptor.h'),'header_sha256':sha(HEAD/'IOKit/IOMemoryDescriptor.h')},'native_target_executed':False,'native_mapping_proved':False,'complete_lifecycle_proved':False,'full_goal_complete':False};(ROOT/'sample_descriptor_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'kext_functions':len(functions),'kernel_functions':len(kernel),'nominal_slots':len(slots),'SDK_compile_exit':r.returncode}),flush=True)
if __name__=='__main__':main()
