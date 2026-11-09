#!/usr/bin/env python3
"""Independent static bindings, routing, ownership-request and ABI checks.
No target execution/emulation. O(capture+hash bytes), O(capture); compiler separate.
"""
import ast,copy,json,struct,subprocess,hashlib
from recover_iokit_connection_lifecycle import *
EXPECTED='''
be359a0|cbz|x0, #0xfffffe000be359f4
be359b8|mov|w1, #0x27
be359bc|bl|#0xfffffe000c56114c
be359e0|blraa|x8, x16
be359e4|mov|x0, x20
be35480|cmp|w8, #0x27
be35490|movk|x17, #0x7d, lsl #48
be354dc|ldr|x16, [x8, #0x20]!
be35514|blraa|x8, x16
be35558|blraa|x8, x16
be3534c|cmp|w8, #0x28
c5611cc|mov|x1, x20
c5611d0|bl|#0xfffffe000be35a54
c5611fc|bl|#0xfffffe000bcf4fa0
c561258|cmp|x16, x0
c561268|cmp|w9, w20
be35a58|cmp|w1, #0x29
be35ab0|mov|x2, #0
be35ab8|orr|x1, x8, #0x100
be35abc|mov|w3, #0
be35ac0|b|#0xfffffe000bcf4a5c
bcf4ad0|and|x8, x20, #0xff
bcf4ad8|eor|x8, x8, x9
bcf4ae4|str|x17, [x19, #0x50]
bcf4ff0|cmp|w8, w21
bcf5004|eor|w8, w2, w8
bcf5014|ccmp|x20, x16, #4, ne
bcf5020|bl|#0xfffffe000bccfc94
be3c6bc|cmp|w8, #0x20
be3c6dc|bl|#0xfffffe000be35448
be3c6e4|bl|#0xfffffe000c56f10c
be3c6e8|str|w0, [x19, #8]
be3c70c|blraa|x8, x16
be387cc|bl|#0xfffffe000be35448
be3883c|bl|#0xfffffe000c5708f4
c570ba0|bl|#0xfffffe000c5707ec
c570834|bl|#0xfffffe000bd07048
c570850|bl|#0xfffffe000bd0655c
c570878|tbnz|w8, #1, #0xfffffe000c5708a4
c570880|ldr|x9, [x16, #0x880]
c57088c|mov|x4, #0
c570890|mov|x5, #0
c57089c|blraa|x9, x17
c5708a8|ldr|x9, [x16, #0x990]
c562bf8|cbz|x3, #0xfffffe000c562c88
c562e48|ldr|x11, [x16, #0x970]
c562e54|mov|x2, x9
c562e60|blraa|x11, x17
c56e964|add|x8, x8, #0xbc0
c56e968|cmp|x0, x8
c56e98c|mov|w8, #2
c56e9a0|and|w9, w9, #0xfffffffd
c56e9a8|strb|w8, [x0, #0x9b]
c56f200|mov|x17, #0x920
c56f214|blraa|x8, x16
c56f224|mov|w20, #0
be38dec|bl|#0xfffffe000be3599c
be38de4|bl|#0xfffffe000bcd0448
be38e0c|stur|x17, [x24, #0x24]
a503cdc|sub|w9, w2, #1
a503ce0|cmp|w9, #0x27
a503cf8|tbz|w10, #0, #0xfffffe000a503d24
a503d04|add|x10, x10, #0x770
a503d1c|ldr|x0, [x11]
a503d20|str|x8, [x1]
a50447c|mov|x17, #0x630
a504488|mov|w1, #0
a504490|blraa|x8, x16
a504494|mov|w0, #0
a5044f4|mov|x17, #0x8e8
a504510|str|w8, [x19]
'''
CACHE_EXPECTED='''
184e7b9b0|bl|#0x184e7b9dc
184e7b9c4|mov|x1, x19
184e7b9c8|bl|#0x18806c480
184e7b9cc|mov|x0, x20
184e7ba34|movk|x2, #0x18, lsl #32
184e7ba38|mov|x4, #0xb0000000000
184e7ba3c|mov|w6, #0x2c
184e7ba44|bl|#0x188088a80
'''
SDK_C='''#include <stdint.h>
#include <stddef.h>
#include <mach/mach.h>
#include <mach/ndr.h>
#include <IOKit/IOKitLib.h>
struct close_reply { mach_msg_header_t h; NDR_record_t ndr; kern_return_t result; };
_Static_assert(sizeof(mach_port_t)==4,"name4");
_Static_assert(sizeof(mach_msg_header_t)==24,"close request24");
_Static_assert(sizeof(struct close_reply)==36,"close reply36");
_Static_assert(offsetof(struct close_reply,result)==32,"result32");
_Static_assert(kIOReturnBadArgument==0xe00002c2,"badarg");
_Static_assert(kIOReturnUnsupported==0xe00002c7,"unsupported");
_Static_assert(MACH_MSG_TYPE_COPY_SEND==19,"copy send");
_Static_assert(MACH_MSG_TYPE_PORT_SEND==17,"send");
_Static_assert(__builtin_types_compatible_p(__typeof__(&IOServiceClose),kern_return_t(*)(io_connect_t)),"close ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&mach_port_deallocate),kern_return_t(*)(ipc_space_t,mach_port_name_t)),"deallocate ABI");
'''
def verify(s):
 fs=s['kernel_functions']+s['kext_functions']+s['cache_functions'];rows={i['ea']:(i['mnemonic'],i['operands'])for f in fs for i in f['instructions']};assertions=[]
 for text,base in((EXPECTED,0xfffffe0000000000),(CACHE_EXPECTED,0)):
  for line in text.strip().splitlines():
   at,m,o=line.split('|');a=hex(base+int(at,16));assert rows[a]==(m,o),(a,rows.get(a));assertions.append(a)
 for f in fs:raw=bytes.fromhex(f['bytes']);assert len(raw)==4*len(f['instructions'])==int(f['end'],16)-int(f['start'],16)and hashlib.sha256(raw).hexdigest()==f['sha256']
 bindings=s['chained_bindings'];assert len(bindings)==10;by={int(p['slot'],16):int(p['target'],16)for p in bindings};b=0xfffffe000846a868
 for off,target in[(0x630,0xfffffe000c4d6c78),(0x880,0xfffffe000c562bc8),(0x920,0xfffffe000a50445c),(0x970,0xfffffe000a503cd0),(0x990,0xfffffe000a5044c8)]:assert by[b+off]==target
 symbols=s['boundary_symbols'];assert any(e['name']=='__ZN16IOUserClient202210gMetaClassE'for e in symbols['0xfffffe000cb5bbc0'])
 assert any(e['name']=='_lck_rw_lock_shared'for e in symbols['0xfffffe000bd07048'])and any(e['name']=='_lck_rw_lock_exclusive'for e in symbols['0xfffffe000bd0655c'])
 routines={r['id']:r for r in s['MIG_routines']};assert set(routines)=={2816,2862,2865}
 for mid,target,size in[(2816,'0xfffffe000be3c6ac',44),(2862,'0xfffffe000be38c4c',64),(2865,'0xfffffe000be386b4',4284)]:assert routines[mid]['stub']['target']==target and routines[mid]['reply_size_word1c']==size
 assert[int(p['pointer']['target'],16)for p in s['cache_stubs']]==[0x18054906c,0x18055a894]
 assert any(v['name']=='_mach_port_deallocate'for v in s['cache_stubs'][0]['pointer']['exact_nlist'])and any(v['name']=='_mach_msg2_internal'for v in s['cache_stubs'][1]['pointer']['exact_nlist'])
 assert s['task_self_binding']['target']=='0x1ed83e960'
 constants=[bytes.fromhex(e['bytes8_hex'])for e in s['cache_constants']];assert struct.unpack_from('<I',constants[0])[0]==0x1513 and struct.unpack_from('<I',constants[1],4)[0]==2816
 selected=[1,6,16,18,19,20,21,22,23,26,30,31,32,33,34,35,40];decoded=[j+1 for j in range(40)if(0x87e27e8021>>j)&1];assert decoded==selected
 table=s['selector_table'];assert len(table)==40 and[r['selector']for r in table if r['pointer']is not None]==selected;assert table[25]['pointer']['target']=='0xfffffe000846b710'
 return len(assertions)
def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert s==build();n=verify(s);assert all(s[k]is False for k in FLAGS)
 for name,h in s['dependencies'].items():assert sha(ROOT/name)==h
 sdk=Path(subprocess.check_output(['xcrun','--show-sdk-path'],text=True).strip());cmd=['clang','-target','arm64e-apple-macos13.0','-isysroot',str(sdk),'-std=c11','-fsyntax-only','-x','c','-'];r=subprocess.run(cmd,input=SDK_C,text=True,capture_output=True);assert r.returncode==0,r.stderr
 paths=[sdk/'usr/include/mach/message.h',sdk/'usr/include/mach/mach_port.h',sdk/'System/Library/Frameworks/IOKit.framework/Versions/A/Headers/IOKitLib.h',sdk/'System/Library/Frameworks/IOKit.framework/Versions/A/Headers/IOReturn.h'];headers=[{'path':str(p),'size_bytes':p.stat().st_size,'sha256':sha(p)}for p in paths]
 modes=[]
 for v in range(256):
  w9=(v<<29)&0xffffffff;signed=w9 if w9<0x80000000 else w9-0x100000000;mode=(1+bool(v&8))&(signed>>31);expected=(2 if v&8 else 1)if v&4 else 0;assert mode==expected;modes.append({'byte':v,'lock_mode':mode,'dispatch_slot':hex(0x990 if v&2 else 0x880)})
 negatives=[]
 for label,fn in [('connection type',lambda t:t['kernel_functions'][1]['instructions'][14].update(operands='wrong')),('export type',lambda t:t['kernel_functions'][0]['instructions'][7].update(operands='wrong')),('method target',lambda t:t['MIG_routines'][2]['stub'].update(target='0x0')),('close target',lambda t:t['MIG_routines'][0]['stub'].update(target='0x0')),('legacy binding',lambda t:t['chained_bindings'][5].update(target='0x0')),('close binding',lambda t:t['chained_bindings'][4].update(target='0x0')),('original bytes',lambda t:t['kext_functions'][0].update(bytes='00'+t['kext_functions'][0]['bytes'][2:])),('selector26 record',lambda t:t['selector_table'][25]['pointer'].update(target='0x0')),('deallocate stub',lambda t:t['cache_stubs'][0]['pointer'].update(target='0x0')),('close emission',lambda t:t['cache_functions'][1]['instructions'][26].update(operands='wrong'))]:
  t=copy.deepcopy(s);fn(t)
  try:verify(t)
  except(AssertionError,KeyError,ValueError,struct.error):negatives.append(label);continue
  raise AssertionError('alteration accepted: '+label)
 fs=s['kernel_functions']+s['kext_functions']+s['cache_functions'];counts={'kernel_functions':17,'kext_functions':3,'cache_functions':2,'original_instructions':sum(len(f['instructions'])for f in fs),'original_function_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs),'exact_instruction_assertions':n,'chained_bindings':10,'MIG_records':3,'selector_table_slots':40,'admitted_selectors':17,'SDK_assertions':SDK_C.count('_Static_assert'),'SDK_headers':4,'rejected_static_alterations':len(negatives),'flag_bytes':256,'cache_stub_bindings':2}
 for script in('recover_'+P+'.py','validate_'+P+'.py'):ast.parse((ROOT/script).read_text())
 out={'generator_sha256':sha(__file__),'dependencies':{P+'_source.json':sha(ROOT/(P+'_source.json'))},'verified_counts':counts,'source_recapture_match':True,'SDK_source':SDK_C,'SDK_command':cmd,'SDK_headers':headers,'flag_classification':modes,'rejected_alterations':negatives,'static_scope':{'target_instruction_visits':0,'target_instructions_emulated':0,'new_runtime_observations':0},'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
