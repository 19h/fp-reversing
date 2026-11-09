#!/usr/bin/env python3
"""Independent static registration/cache/callback/cleanup and SDK checks.
No target execution/emulation or policy invocation. O(capture+hash bytes),
O(capture); syntax-only compiler costs are separate.
"""
import copy,json,struct,subprocess,hashlib
from recover_iokit_filter_policy import *
EXPECTED='''
c572e44|cmp|x1, #0x18
c572e48|b.lo|#0xfffffe000c572e68
c572e4c|mov|x9, #0
c572e58|casal|x9, x8, [x10]
c572e60|add|w8, w0, #0x13
c572e64|csel|w0, wzr, w8, eq
c568e90|ldr|x8, [x20, #0x88]
c568e94|ldr|x8, [x8, #8]
c568ea0|cmp|x9, x22
c568ea4|b.eq|#0xfffffe000c568ef0
c568ea8|ldr|x8, [x8, #0x10]
c568eb0|cbz|x19, #0xfffffe000c568ef4
c568ed0|bl|#0xfffffe000bcfeb8c
c568ed4|stp|x22, x19, [x0]
c568ee0|str|x8, [x0, #0x10]
c568ee8|str|x0, [x8, #8]
c568ef0|ldr|x19, [x8, #8]
c568f14|mov|x0, x19
c568530|str|x20, [x0]
c568534|str|x21, [x0, #0x18]
c56552c|ldr|x22, [x22, #0x10]
c565530|ldr|x0, [x21, #8]
c56553c|ldr|x8, [x8, #0x10]
c565544|mov|x17, #0xa98
c565548|blraa|x8, x17
c565520|bl|#0xfffffe000bcff010
c565554|str|xzr, [x19, #0x88]
c565560|bl|#0xfffffe000bcff010
c56ef68|mov|x1, x20
c56ef6c|mov|x2, #0
c56ef70|bl|#0xfffffe000c568e48
c56ef78|cbz|x0, #0xfffffe000c56f060
c56ef94|bl|#0xfffffe000c56848c
c56f06c|add|x3, sp, #0x30
c56f070|mov|x0, x20
c56f074|mov|x2, x22
c56f078|mov|x17, #0xe2e
c56f07c|blraa|x8, x17
c56f080|mov|w8, #0x2c7
c56f088|cmp|w0, w8
c56f08c|b.eq|#0xfffffe000c56ef7c
c56f094|cbnz|w0, #0xfffffe000c56f0a8
c56f0a0|bl|#0xfffffe000c568e48
c570b60|ldr|x9, [x8]
c570b64|cmp|x9, x0
c570b6c|ldr|x8, [x8, #0x10]
c570c14|ldr|x1, [x8, #8]
c570c38|cbz|x1, #0xfffffe000c570b94
c570c44|ldr|x8, [x8, #8]
c570c48|cbz|x8, #0xfffffe000c570b94
c570c50|mov|w2, #1
c570c54|ldr|w3, [sp, #0x2c]
c570c58|mov|x17, #0xb286
c570c5c|blraa|x8, x17
c570c64|cbnz|w0, #0xfffffe000c570bb4
c570ba0|bl|#0xfffffe000c5707ec
c570648|mov|w2, #1
c570654|blraa|x8, x17
c57107c|mov|w2, #2
c571088|blraa|x8, x17
c5729bc|mov|w2, #3
c5729c4|blraa|x9, x17
be385f4|bl|#0xfffffe000c570cc0
be37b00|bl|#0xfffffe000c570318
be3883c|bl|#0xfffffe000c5708f4
bcfebe8|ldp|w11, w8, [x0, #0x28]
c4ba36c|b|#0xfffffe000bcff010
b7a6cfc|adrp|x0, #0xfffffe0008a79000
b7a6d00|add|x0, x0, #0xde0
b7a6d04|mov|w1, #0x18
b7a6d08|bl|#0xfffffe000b7e42f0
b7a6d0c|cbnz|w0, #0xfffffe000b7a72a8
b790560|cmp|w2, #3
b790568|cmp|w2, #2
b790570|cmp|w2, #1
b790590|add|x1, x1, #8
b7905a4|add|x1, x1, #0x10
b7905ac|ldr|x21, [x1]
b790458|b|#0xfffffe000b79045c
b7904bc|mov|x1, x19
b7904d8|b|#0xfffffe000b7e41c0
'''
SDK_C='''#include <stddef.h>
#include <stdint.h>
#include <IOKit/IOKitLib.h>
_Static_assert(sizeof(void*)==8,"pointer8");
_Static_assert(sizeof(unsigned long)==8,"ulong8");
_Static_assert(sizeof(size_t)==8,"size8");
_Static_assert(kIOReturnBadArgument==0xe00002c2,"badarg");
_Static_assert(kIOReturnBusy==0xe00002d5,"busy");
_Static_assert(kIOReturnUnsupported==0xe00002c7,"unsupported");
_Static_assert(kIOReturnSuccess==0,"success0");
'''
def verify(s):
 fs=s['kernel_functions']+s['sandbox_functions'];rows={i['ea']:(i['mnemonic'],i['operands'])for f in fs for i in f['instructions']};n=0
 for line in EXPECTED.strip().splitlines():a,m,o=line.split('|');a=hex(0xfffffe0000000000+int(a,16));assert rows[a]==(m,o),(a,rows.get(a));n+=1
 for f in fs:raw=bytes.fromhex(f['bytes']);assert len(raw)==int(f['end'],16)-int(f['start'],16)==4*len(f['instructions'])and hashlib.sha256(raw).hexdigest()==f['sha256']
 ptr=s['callbacks'];assert[p['target']for p in ptr]==['0xfffffe000b7906d4','0xfffffe000b7904e0','0xfffffe000b790454'];assert[p['diversity']for p in ptr]==['0xe2e','0xb286','0xa98']
 names=['__ZL17iofilter_resolverP4taskP12IOUserClientjPm','__ZL16iofilter_applierP12IOUserClientm16io_filter_type_tj','__ZL16iofilter_releasem']
 for p,name in zip(ptr,names):assert any(e['name']==name and e['entry']=='com.apple.security.sandbox'for e in p['exact_symbols'])
 assert s['sandbox_registration_stub']['address']=='0xfffffe000b7e42f0'and s['sandbox_registration_stub']['binding']['target']=='0xfffffe000c572e34'
 assert s['sandbox_free_stub']['binding']['target']=='0xfffffe000c4ba368'
 assert s['root_slot']['bytes8_hex']=='0000000000000000'and not s['root_slot']['is_chained_pointer'];assert s['sandbox_function_start_count']==977 and s['sandbox_UUID']=='3db87bed-1032-30fa-906f-828b8ad70ca8'
 cls=s['allocator_classes'];assert[(c['name'],c['word44'])for c in cls]==[('site.IOUserClientOwner',48),('site.IOUCFilterPolicy',24),('site.IOUCFilterPolicy',24),('site.ExpansionData',16),('site.typeof(**(&filter))',24)]
 for c in cls:assert struct.unpack_from('<I',bytes.fromhex(c['bytes64_hex']),44)[0]==c['word44']
 assert[(r['id'],r['stub']['target'])for r in s['MIG_routines']]==[(2865,'0xfffffe000be386b4'),(2866,'0xfffffe000be383bc'),(2872,'0xfffffe000be3795c')]
 candidates=s['root_candidates']['candidates'];assert len(candidates)==7 and{c['function']for c in candidates}=={'0xfffffe000c5654a8','0xfffffe000c56e604','0xfffffe000c570318','0xfffffe000c5708f4','0xfffffe000c570cc0','0xfffffe000c572744','0xfffffe000c572e34'}
 assert 3*8==24 and 6*8==48 and 2*8==16 and 0xe00002c2+0x13==0xe00002d5
 return n
def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert s==build();n=verify(s);assert all(s[f]is False for f in FLAGS)
 for name,h in s['dependencies'].items():assert sha(ROOT/name)==h
 sdk=Path(subprocess.check_output(['xcrun','--show-sdk-path'],text=True).strip());cmd=['clang','-target','arm64e-apple-macos13','-isysroot',str(sdk),'-std=c11','-fsyntax-only','-x','c','-'];r=subprocess.run(cmd,input=SDK_C,text=True,capture_output=True);assert r.returncode==0,r.stderr
 paths=[sdk/'System/Library/Frameworks/IOKit.framework/Versions/A/Headers'/n for n in('IOKitLib.h','IOReturn.h')];hdr=[{'path':str(p),'size_bytes':p.stat().st_size,'sha256':sha(p)}for p in paths];negatives=[]
 for label,fn in [('resolver binding',lambda t:t['callbacks'][0].update(target='0x0')),('applier discriminator',lambda t:t['callbacks'][1].update(diversity='0x0')),('release binding',lambda t:t['callbacks'][2].update(target='0x0')),('registrant import',lambda t:t['sandbox_registration_stub']['binding'].update(target='0x0')),('image root',lambda t:t['root_slot'].update(bytes8_hex='01'*8)),('filter allocation size',lambda t:t['allocator_classes'][1].update(word44=48)),('filter allocation class',lambda t:t['allocator_classes'][1].update(name='site.IOUserClientOwner')),('MIG async binding',lambda t:t['MIG_routines'][1]['stub'].update(target='0x0')),('source bytes',lambda t:t['kernel_functions'][1].update(bytes='00'+t['kernel_functions'][1]['bytes'][2:])),('CAS registration',lambda t:t['kernel_functions'][0]['instructions'][9].update(operands='wrong'))]:
  t=copy.deepcopy(s);fn(t)
  try:verify(t)
  except(AssertionError,KeyError,ValueError,struct.error):negatives.append(label);continue
  raise AssertionError('alteration accepted: '+label)
 fs=s['kernel_functions']+s['sandbox_functions'];counts={'kernel_functions':14,'sandbox_functions':5,'original_instructions':sum(len(f['instructions'])for f in fs),'original_function_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs),'exact_instruction_assertions':n,'callback_bindings':3,'allocator_classes':5,'MIG_records':3,'candidate_windows':7,'sandbox_function_start_entries':977,'SDK_assertions':SDK_C.count('_Static_assert'),'SDK_headers':2,'rejected_static_alterations':len(negatives)}
 out={'generator_sha256':sha(__file__),'dependencies':{P+'_source.json':sha(ROOT/(P+'_source.json'))},'verified_counts':counts,'source_recapture_match':True,'SDK_source':SDK_C,'SDK_command':cmd,'SDK_headers':hdr,'rejected_alterations':negatives,'static_scope':{'target_instruction_visits':0,'target_instructions_emulated':0,'new_runtime_observations':0,'policy_callbacks_invoked':0},'all_checks_pass':True,**{f:False for f in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
