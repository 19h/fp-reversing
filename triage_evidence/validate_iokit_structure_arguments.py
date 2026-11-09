#!/usr/bin/env python3
"""Static argument/copy/size/task checks and actual Kernel SDK ABI compilation.
No target execution/emulation or request generation. O(capture+hash bytes)
time, O(capture) space; syntax-only compiler costs separate.
"""
import copy,json,struct,subprocess,hashlib
from recover_iokit_structure_arguments import *
EXPECTED='''
c570a10|stp|w9, w8, [sp, #0x30]
c570a18|str|x19, [sp, #0x50]
c570a1c|str|w28, [sp, #0x58]
c570a20|str|x27, [sp, #0x60]
c570a24|str|w26, [sp, #0x68]
c570a28|cbz|x25, #0xfffffe000c570a34
c570a30|b.ls|#0xfffffe000c5709a8
c570a64|bl|#0xfffffe000bd7e9c4
c570a74|mov|w2, #0x20002
c570a78|bl|#0xfffffe000c53a934
c570a90|stp|x21, x0, [sp, #0x70]
c570a98|str|w25, [sp, #0x80]
c570a9c|lsl|x1, x25, #3
c570aa0|bl|#0xfffffe000c6480c0
c570aa8|str|x8, [sp, #0x88]
c570ab4|str|w24, [sp, #0x90]
c570ac8|bl|#0xfffffe000bd7e9c4
c570ad8|mov|w2, #1
c570adc|bl|#0xfffffe000c53a934
c570ae4|str|x0, [sp, #0x98]
c570afc|str|w26, [sp, #0xa0]
c570ba0|bl|#0xfffffe000c5707ec
c562c88|ldr|x10, [x2, #0x40]
c562c94|ldr|x10, [x2, #0x68]
c562e48|ldr|x11, [x16, #0x970]
c562e60|blraa|x11, x17
c562e80|ldr|w24, [x0, #0x18]
c562fd4|ldr|x2, [x23, #0x30]
c562fd8|ldr|w3, [x23, #0x38]
c562fdc|ldr|x4, [x23, #0x58]
c562fe0|add|x5, sp, #0x10
c562fec|bl|#0xfffffe000c565154
c565170|ldr|x8, [x0, #0x20]
c565174|mov|w9, #-1
c565180|ccmp|x8, x19, #4, ne
c565188|ldr|x10, [x20, #0x28]
c5651a4|cmp|x9, x10
c5651a8|b.ne|#0xfffffe000c56524c
c5651d4|mov|w7, #0x705d
c565304|mov|x1, x2
c565308|mov|x2, x4
c56530c|mov|x3, x19
c565310|mov|x4, x5
c5653b4|braa|x17, x7
c53a948|mov|x19, x3
c53a9ac|orr|w5, w8, w20
c53a9bc|mov|x4, x19
bcf4760|mov|w9, #0x2c
bcf4794|str|wzr, [x16, #0x28]
bcf4818|mov|x0, x22
bcf4824|ldr|x3, [sp, #0x20]
be38830|add|x2, x25, #0x10
be38834|add|x4, x23, #0x94
be38838|stp|x8, x24, [sp]
be3883c|bl|#0xfffffe000c5708f4
be388c8|add|w8, w19, w24
be388cc|add|w8, w8, #0x3c
a504058|ldr|x1, [x1]
a50405c|ldr|w2, [x20, #8]
a504060|ldp|x4, x3, [x0, #0xe0]
a5040b0|str|x8, [x19]
a5040b8|str|w8, [x19, #8]
a5042e0|stp|xzr, x20, [x19, #0xd8]
a5051c8|mov|x1, x20
a5051cc|mov|w2, #3
a5051d0|mov|x3, x4
a5051d4|bl|#0xfffffe000a69f1e4
'''
CACHE_EXPECTED='''
184e78dd4|mov|x4, x9
184e78dd8|mov|x5, x8
184e78de4|bl|#0x184e77d74
184e77d98|cmp|x5, #1, lsl #12
184e77d9c|csel|x4, xzr, x4, hi
184e77db4|csel|x6, x11, xzr, hi
184e77db8|csel|x7, x10, xzr, hi
184e77e28|cmp|x11, #1, lsl #12
184e77e5c|bl|#0x184e77e8c
184e77ff0|mov|x1, x27
184e77ff4|bl|#0x18806c550
184e77ffc|add|w22, w25, #0x54
184e78090|bl|#0x188088a80
184e781f8|add|x1, x8, #0x28
184e781fc|mov|x2, x20
184e78200|bl|#0x18806c550
'''
SDK_CPP='''#include <IOKit/IOUserClient.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <stddef.h>
static_assert(sizeof(void*)==8,"pointer8");
static_assert(sizeof(IOMethod)==16,"member pointer16");
static_assert(sizeof(IOOptionBits)==4,"flags4");
static_assert(sizeof(IOByteCount)==8,"byte count8");
static_assert(sizeof(IOExternalMethod)==48,"method48");
static_assert(offsetof(IOExternalMethod,func)==8,"function8");
static_assert(offsetof(IOExternalMethod,flags)==24,"flags24");
static_assert(offsetof(IOExternalMethod,count0)==32,"count0at32");
static_assert(offsetof(IOExternalMethod,count1)==40,"count1at40");
static_assert(sizeof(IOExternalMethodArguments)==248,"arguments248");
static_assert(offsetof(IOExternalMethodArguments,version)==0,"version0");
static_assert(offsetof(IOExternalMethodArguments,selector)==4,"selector4");
static_assert(offsetof(IOExternalMethodArguments,scalarInput)==32,"scalarin32");
static_assert(offsetof(IOExternalMethodArguments,scalarInputCount)==40,"scalarincount40");
static_assert(offsetof(IOExternalMethodArguments,structureInput)==48,"structurein48");
static_assert(offsetof(IOExternalMethodArguments,structureInputSize)==56,"structureinsize56");
static_assert(offsetof(IOExternalMethodArguments,structureInputDescriptor)==64,"structureinMD64");
static_assert(offsetof(IOExternalMethodArguments,scalarOutput)==72,"scalarout72");
static_assert(offsetof(IOExternalMethodArguments,scalarOutputCount)==80,"scalaroutcount80");
static_assert(offsetof(IOExternalMethodArguments,structureOutput)==88,"structureout88");
static_assert(offsetof(IOExternalMethodArguments,structureOutputSize)==96,"structureoutsize96");
static_assert(offsetof(IOExternalMethodArguments,structureOutputDescriptor)==104,"structureoutMD104");
static_assert(offsetof(IOExternalMethodArguments,structureOutputDescriptorSize)==112,"structureoutMDsize112");
static_assert(offsetof(IOExternalMethodArguments,structureVariableOutputData)==120,"variableout120");
static_assert(kIOUCStructIStructO==3,"kind3");
static_assert(kIOUCVariableStructureSize==0xffffffff,"variable sentinel");
static_assert(kIODirectionInOut==3,"inout3");
static_assert(kIODirectionOut==2,"out2");
static_assert(kIOMemoryMapCopyOnWrite==0x20000,"COW flag");
static_assert(kIOMemoryTypeVirtual==0x10,"virtual type");
'''
def verify(s):
 fs=s['kernel_functions']+s['kext_functions']+s['cache_functions'];rows={i['ea']:(i['mnemonic'],i['operands'])for f in fs for i in f['instructions']};n=0
 for text,base in((EXPECTED,0xfffffe0000000000),(CACHE_EXPECTED,0)):
  for line in text.strip().splitlines():a,m,o=line.split('|');a=hex(base+int(a,16));assert rows[a]==(m,o),(a,rows.get(a));n+=1
 for f in fs:raw=bytes.fromhex(f['bytes']);assert len(raw)==int(f['end'],16)-int(f['start'],16)==4*len(f['instructions'])and hashlib.sha256(raw).hexdigest()==f['sha256']
 m=s['method26'];raw=bytes.fromhex(m['bytes48_hex']);assert len(raw)==48 and struct.unpack_from('<I',raw,24)[0]==3 and struct.unpack_from('<QQ',raw,32)==(16,16)and struct.unpack_from('<Q',raw,16)[0]==0
 assert m['function_pointer']['target']=='0xfffffe000a504034'and m['function_pointer']['diversity']=='0x705d'and m['router_slot']['target']==m['address']
 f=s['provider_memory_factory_stub'];assert f['pointer']['target']=='0xfffffe000c53a934'and any(e['name']=='__ZN18IOMemoryDescriptor16withAddressRangeEyyjP4task'for e in f['pointer']['exact_symbols'])
 assert s['MIG_routine2865']['stub']['target']=='0xfffffe000be386b4'and s['MIG_routine2865']['reply_size_word1c']==4284
 assert any(v['name']=='__platform_memmove'for v in s['copy_stub']['pointer']['exact_nlist'])and s['copy_stub']['pointer']['chain_membership_verified']
 assert any(e['name']=='_bzero'for e in next(f for f in s['kernel_functions']if f['start']=='0xfffffe000c6480c0')['exact_symbols'])
 assert 84+16==100 and 92+16==108 and 52+16==68 and 60+16==76 and 8+4==12 and 16-12==4
 return n
def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert s==build();n=verify(s);assert all(s[k]is False for k in FLAGS)
 for name,h in s['dependencies'].items():assert sha(ROOT/name)==h
 sdk=Path(subprocess.check_output(['xcrun','--show-sdk-path'],text=True).strip());headers_root=sdk/'System/Library/Frameworks/Kernel.framework/Versions/A/Headers';cmd=['clang++','-target','arm64e-apple-macos13','-isysroot',str(sdk),'-I',str(headers_root),'-DKERNEL','-fapple-kext','-fno-exceptions','-fno-rtti','-std=c++17','-fsyntax-only','-x','c++','-'];r=subprocess.run(cmd,input=SDK_CPP,text=True,capture_output=True);assert r.returncode==0,r.stderr
 paths=[headers_root/n for n in('IOKit/IOUserClient.h','IOKit/IOMemoryDescriptor.h','IOKit/IOTypes.h','IOKit/IOService.h')];headers=[{'path':str(p),'size_bytes':p.stat().st_size,'sha256':sha(p)}for p in paths]
 sizes=[0,1,15,16,17,4095,4096,4097,0xffffffff,0x100000000,0xffffffffffffffff];classifications=[]
 for size in sizes:classifications.append({'extent_u64':size,'large_branch':size>4096,'selector26_fixed_size_match':size==16})
 negatives=[]
 def word(t,offset,value):b=bytearray.fromhex(t['method26']['bytes48_hex']);struct.pack_into('<Q',b,offset,value);t['method26']['bytes48_hex']=b.hex()
 for label,fn in [('fixed input size',lambda t:word(t,32,15)),('fixed output size',lambda t:word(t,40,17)),('member adjustment',lambda t:word(t,16,2)),('method handler',lambda t:t['method26']['function_pointer'].update(target='0x0')),('member discriminator',lambda t:t['method26']['function_pointer'].update(diversity='0x0')),('factory binding',lambda t:t['provider_memory_factory_stub']['pointer'].update(target='0x0')),('copy binding',lambda t:t['copy_stub']['pointer'].update(exact_nlist=[])),('MIG binding',lambda t:t['MIG_routine2865']['stub'].update(target='0x0')),('source bytes',lambda t:t['kext_functions'][0].update(bytes='00'+t['kext_functions'][0]['bytes'][2:])),('argument input store',lambda t:t['kernel_functions'][0]['instructions'][75].update(operands='wrong'))]:
  t=copy.deepcopy(s);fn(t)
  try:verify(t)
  except(AssertionError,KeyError,ValueError,struct.error):negatives.append(label);continue
  raise AssertionError('alteration accepted: '+label)
 fs=s['kernel_functions']+s['kext_functions']+s['cache_functions'];counts={'kernel_functions':9,'kext_functions':3,'cache_functions':3,'original_instructions':sum(len(f['instructions'])for f in fs),'original_function_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs),'exact_instruction_assertions':n,'method_records':1,'MIG_records':1,'original_factory_bindings':1,'copy_bindings':1,'SDK_assertions':SDK_CPP.count('static_assert'),'SDK_headers':4,'extent_classifications':len(classifications),'rejected_static_alterations':len(negatives)}
 out={'generator_sha256':sha(__file__),'dependencies':{P+'_source.json':sha(ROOT/(P+'_source.json'))},'verified_counts':counts,'source_recapture_match':True,'SDK_command':cmd,'SDK_source':SDK_CPP,'SDK_headers':headers,'extent_classifications':classifications,'rejected_alterations':negatives,'static_scope':{'target_instruction_visits':0,'target_instructions_emulated':0,'new_runtime_observations':0,'wire_payloads_generated':0},'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
