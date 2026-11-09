#!/usr/bin/env python3
"""Independent static instruction/record/layout checks; no target execution.
O(source+hash bytes), O(capture); SDK compiler cost is separate.
"""
import ast,copy,hashlib,json,struct,subprocess
from recover_kernel_iokit_open import *
ASSERTIONS='''
be38c54|tbz|w8, #0x1f, #0xfffffe000be38d0c
be38c5c|cmp|w8, #2
be38c68|cmp|w8, #0x5c
be38c78|cmp|w8, #0x110, lsl #12
be38c84|cmp|w8, #1
be38c94|cmp|w8, w9
be38d0c|mov|w8, #-0x130
be38d10|str|w8, [x3, #0x28]
be38d24|mov|w8, #-0x12c
be38d44|ldr|w2, [x22, #8]
be38d6c|add|x6, x23, #8
be38d70|add|x7, sp, #8
be38d7c|bl|#0xfffffe000c56e604
be38db0|cbz|w22, #0xfffffe000be38dc8
be38db4|str|w22, [x24, #0x28]
be38de4|bl|#0xfffffe000bcd0448
be38e0c|stur|x17, [x24, #0x24]
be38e20|orr|w8, w8, #0x80000000
be38e24|mov|w9, #0x40
be38e30|str|w8, [x24, #0x20]
c56e62c|mov|w25, #0x2bc
c56e630|movk|w25, #0xe000, lsl #16
c56e68c|add|w8, w25, #6
c56e6b8|cbz|x20, #0xfffffe000c56e690
c56e6c0|mrs|x0, tpidr_el1
c56e6c4|bl|#0xfffffe000bd7e9c4
c56e6c8|cmp|x20, x0
c56e6cc|b.eq|#0xfffffe000c56e6d8
c56e704|add|w8, w25, #0xb
c56e714|mov|x17, #0x7a0
c56e728|mov|x1, x20
c56e72c|mov|x2, x20
c56e730|mov|x3, x22
c56e734|mov|x4, #0
c56e73c|blraa|x8, x16
c56e748|cbz|w8, #0xfffffe000c56e768
c56e74c|mov|x25, x8
c56e758|mov|w8, #0
c56e75c|str|x0, [x10]
c56e760|str|w25, [x9]
c4cc0cc|blraa|x8, x16
c4cc0dc|mov|w19, #0x2c7
c4cc0e0|movk|w19, #0xe000, lsl #16
c4cc2a4|mov|x17, #0x910
c4cc2c8|blraa|x8, x16
c4cc2d8|tbz|w0, #0, #0xfffffe000c4cc334
c4cc304|tbz|w0, #0, #0xfffffe000c4cc36c
c4cc324|tbz|w0, #0, #0xfffffe000c4cc374
c4cc32c|str|x26, [x20]
c4cc340|blraa|x8, x16
c4cc344|sub|w19, w19, #5
c4cc348|mov|x0, x19
c562b40|bl|#0xfffffe000c4df840
c562b58|mov|x17, #0x918
c562b78|blraa|x8, x16
c562b7c|and|w0, w23, w0
a504110|mov|x0, x20
a504114|bl|#0xfffffe000a69f194
a504128|bl|#0xfffffe000a69f194
a50413c|bl|#0xfffffe000a69f194
a504178|b.eq|#0xfffffe000a5042f0
a50418c|b.eq|#0xfffffe000a50423c
a5042b0|ldr|x8, [x8, #0x928]
a5042cc|blraa|x8, x17
a5042d8|cbz|x20, #0xfffffe000a504220
a5042dc|cbz|w8, #0xfffffe000a504220
a5042e0|stp|xzr, x20, [x19, #0xd8]
'''
CACHE_ASSERTIONS='''
184e77b84|mov|x7, x3
184e77b98|sub|x6, x29, #4
184e77ba4|bl|#0x184e77bc0
184e77bb0|csel|w0, w8, w0, eq
184e77c14|str|w2, [sp, #0x40]
184e77c18|stur|x3, [sp, #0x44]
184e77c1c|str|w5, [sp, #0x4c]
184e77c6c|bl|#0x188088a80
184e77d08|ldr|w9, [sp, #0x18]
184e77d18|cmp|w8, #0x34
184e77d3c|ldr|w8, [sp, #0x30]
184e77d40|ldr|w9, [sp, #0x1c]
184e77d44|str|w8, [x20]
184e77d48|str|w9, [x19]
'''
SDK_C='''#include <stddef.h>
#include <stdint.h>
#include <mach/mach.h>
#include <mach/ndr.h>
#include <mach/mig_errors.h>
#include <IOKit/IOKitLib.h>
struct open_request { mach_msg_header_t h; mach_msg_body_t b; mach_msg_port_descriptor_t task; mach_msg_ool_descriptor_t properties; NDR_record_t ndr; uint32_t type; NDR_record_t explicit_ndr; uint32_t count; };
struct open_reply { mach_msg_header_t h; mach_msg_body_t b; mach_msg_port_descriptor_t connection; NDR_record_t ndr; uint32_t result; };
_Static_assert(sizeof(mach_msg_header_t)==24,"header24");
_Static_assert(sizeof(mach_msg_port_descriptor_t)==12,"port12");
_Static_assert(sizeof(mach_msg_ool_descriptor_t)==16,"OOL16");
_Static_assert(sizeof(NDR_record_t)==8,"NDR8");
_Static_assert(sizeof(struct open_request)==80,"request80");
_Static_assert(offsetof(struct open_request,task)==28,"task28");
_Static_assert(offsetof(struct open_request,properties)==40,"properties40");
_Static_assert(offsetof(struct open_request,type)==64,"type64");
_Static_assert(offsetof(struct open_request,explicit_ndr)==68,"NDR68");
_Static_assert(offsetof(struct open_request,count)==76,"count76");
_Static_assert(sizeof(struct open_reply)==52,"reply52");
_Static_assert(offsetof(struct open_reply,connection)==28,"connection28");
_Static_assert(offsetof(struct open_reply,result)==48,"result48");
_Static_assert(kIOReturnBadArgument==0xe00002c2,"bad argument");
_Static_assert(kIOReturnUnsupported==0xe00002c7,"unsupported");
_Static_assert(kIOReturnNoMemory==0xe00002bd,"no memory");
_Static_assert(kIOReturnError==0xe00002bc,"general error");
_Static_assert(MIG_BAD_ARGUMENTS==-304 && MIG_TYPE_ERROR==-300,"MIG status");
_Static_assert(MACH_MSG_TYPE_COPY_SEND==19 && MACH_MSG_TYPE_PORT_SEND==17,"port types");
_Static_assert(__builtin_types_compatible_p(__typeof__(&IOServiceOpen),kern_return_t(*)(io_service_t,task_port_t,uint32_t,io_connect_t*)),"open ABI");
'''
def verify(s):
 fs=s['kernel_functions']+s['cache_functions']+[s['kext_initializer']];rows={i['ea']:(i['mnemonic'],i['operands'])for f in fs for i in f['instructions']};n=0
 for text,base in((ASSERTIONS,0xfffffe0000000000),(CACHE_ASSERTIONS,0)):
  for line in text.strip().splitlines():
   at,m,o=line.split('|');assert rows[hex(base+int(at,16))]==(m,o),(at,rows.get(hex(base+int(at,16))));n+=1
 for f in fs:
  raw=bytes.fromhex(f['bytes']);assert hashlib.sha256(raw).hexdigest()==f['sha256']and len(raw)==int(f['end'],16)-int(f['start'],16)==4*len(f['instructions'])
 ptr=s['original_chained_bindings'];expected=[0xfffffe000c4cc010,0xfffffe000c4cc000,0xfffffe000c562b14,0xfffffe000a5040d4,0xfffffe0007f55690,0xfffffe0007f8b500,0xfffffe000c562a20];assert[int(p['target'],16)for p in ptr]==expected
 assert s['MIG_routine2862']['stub']['target']=='0xfffffe000be38c4c'and s['MIG_routine2862']['reply_size_word1c']==64 and s['MIG_routine2862']['index']==62
 req,reply=[bytes.fromhex(r['message_hex'])for r in s['trace']['messages']];u=lambda b,o:struct.unpack_from('<I',b,o)[0]
 assert(len(req),len(reply))==(80,52)and u(req,20)==2862 and u(reply,20)==2962 and u(req,24)==2 and u(reply,24)==1
 assert u(req,28)==0x203 and req[38]==19 and u(req,64)==0 and u(req,76)==0 and req[40:48]==bytes(8)and u(req,52)==0
 assert u(reply,28)==0 and reply[38:40]==bytes([17,0])and u(reply,48)==0xe00002c2 and u(reply,0)&0x80000000
 assert s['trace']['lines']==1748 and s['trace']['transport_line1742'].endswith(' = 0x0')and s['trace']['messages'][0]['line']==1726 and s['trace']['messages'][1]['line']==1736
 assert 0xe00002c7-5==0xe00002c2 and 0xe00002bc+6==0xe00002c2 and 80+8+4==92 and 52+8+4==64
 assert len(s['entitlement_strings'])==3 and all(e['text'].startswith('com.apple.private.')and e['text'].endswith('.access')for e in s['entitlement_strings'])
 return n
def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert s==build();n=verify(s);assert all(s[k]is False for k in FLAGS)
 for name,h in s['dependencies'].items():assert sha(ROOT/name)==h
 sdk=Path(subprocess.check_output(['xcrun','--show-sdk-path'],text=True).strip());cmd=['clang','-target','arm64e-apple-macos13.0','-isysroot',str(sdk),'-std=c11','-fsyntax-only','-x','c','-'];r=subprocess.run(cmd,input=SDK_C,text=True,capture_output=True);assert r.returncode==0,r.stderr
 paths=[sdk/'usr/include/mach/message.h',sdk/'usr/include/mach/mig_errors.h',sdk/'System/Library/Frameworks/IOKit.framework/Versions/A/Headers/IOKitLib.h',sdk/'System/Library/Frameworks/IOKit.framework/Versions/A/Headers/IOReturn.h'];headers=[{'path':str(p),'size_bytes':p.stat().st_size,'sha256':sha(p)}for p in paths]
 negatives=[]
 for label,fn in [('routine result store',lambda t:t['kernel_functions'][1]['instructions'][87].update(operands='wrong')),('routine binding',lambda t:t['MIG_routine2862']['stub'].update(target='0x0')),('constructor binding',lambda t:t['original_chained_bindings'][0].update(target='0x0')),('initializer binding',lambda t:t['original_chained_bindings'][3].update(target='0x0')),('superclass binding',lambda t:t['original_chained_bindings'][6].update(target='0x0')),('reply bytes',lambda t:t['trace']['messages'][1].update(message_hex=t['trace']['messages'][0]['message_hex'])),('source bytes',lambda t:t['kext_initializer'].update(bytes='00'+t['kext_initializer']['bytes'][2:])),('transport result',lambda t:t['trace'].update(transport_line1742=' = 1')),('request extent',lambda t:t['trace']['messages'][0].update(message_hex=t['trace']['messages'][0]['message_hex'][:-8])),('cache mux',lambda t:t['cache_functions'][0]['instructions'][15].update(operands='wrong'))]:
  altered=copy.deepcopy(s);fn(altered)
  try:verify(altered)
  except(AssertionError,KeyError,ValueError,struct.error):negatives.append(label);continue
  raise AssertionError('alteration accepted: '+label)
 # Boolean return composition is bitwise AND in original code, not short-circuit.
 truth=[{'property_init':p,'four_arg_init':k,'result_bit':(p&k)&1}for p in(0,1)for k in(0,1)];assert truth[-1]['result_bit']==1 and sum(r['result_bit']for r in truth)==1
 for script in('recover_'+P+'.py','validate_'+P+'.py'):ast.parse((ROOT/script).read_text())
 fs=s['kernel_functions']+s['cache_functions']+[s['kext_initializer']];counts={'kernel_functions':len(s['kernel_functions']),'kext_functions':1,'cache_functions':2,'original_instructions':sum(len(f['instructions'])for f in fs),'original_function_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs),'exact_instruction_assertions':n,'chained_bindings':7,'MIG_records':1,'trace_messages':2,'SDK_assertions':SDK_C.count('_Static_assert'),'SDK_headers':len(headers),'rejected_static_alterations':len(negatives),'Boolean_combinations':len(truth)}
 result={'generator_sha256':sha(__file__),'dependencies':{P+'_source.json':sha(ROOT/(P+'_source.json'))},'verified_counts':counts,'source_recapture_match':True,'SDK_command':cmd,'SDK_source':SDK_C,'SDK_headers':headers,'rejected_alterations':negatives,'initializer_boolean_table':truth,'static_scope':{'target_instruction_visits':0,'target_instructions_emulated':0,'new_runtime_observations':0,'historical_trace_messages_redecoded':2},'all_checks_pass':True,**{k:False for k in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
