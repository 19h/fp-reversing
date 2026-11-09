#!/usr/bin/env python3
"""Static async routing/right/reference/notification and real SDK ABI checks.
No target execution/emulation or wire generation. O(capture+hash bytes),
O(capture); syntax-only compiler cost separate.
"""
import copy,json,struct,subprocess,hashlib
from recover_iokit_async_contract import *
EXPECTED='''
be38408|cmp|w8, #1
be3846c|cmp|w8, #0x110, lsl #12
be38478|cmp|w10, #8
be3853c|bl|#0xfffffe000be35448
be385dc|add|x2, x10, #0xc
be385f4|bl|#0xfffffe000c570cc0
be38634|cbz|w0, #0xfffffe000be3864c
be38638|str|w0, [x9, #0x28]
c570d9c|cbz|w19, #0xfffffe000c57101c
c570dc0|str|x23, [x26]
c570de8|cmp|x8, x9
c570df0|orr|x8, x23, #1
c570df4|str|x8, [x26]
c570e00|stp|x23, x26, [sp, #0x58]
c570e04|str|w19, [sp, #0x68]
c570fb0|bl|#0xfffffe000c5707ec
c562d50|ldur|x10, [x22, #-0x58]
c562d64|cbz|x10, #0xfffffe000c562e44
c562d6c|ldr|x11, [x16, #0x978]
c562d84|blraa|x11, x17
c562d94|b.eq|#0xfffffe000c562e74
c562e74|add|w0, w21, #5
c56286c|mov|x17, #0x968
c562880|blraa|x8, x16
c562884|cbz|x0, #0xfffffe000c562890
c5628f4|mov|x0, #0
c5628f8|ret|
c569474|ands|x0, x8, #-4
c569488|bl|#0xfffffe000bcd0448
c569494|mov|w0, #0
c56985c|mov|w4, #0
c569860|b|#0xfffffe000c5695cc
c569868|b|#0xfffffe000c5695cc
c567a10|and|x8, x8, #3
c567a14|orr|x8, x8, x1
c567a18|stp|x8, x2, [x0]
c567a1c|str|x3, [x0, #0x10]
c567a60|str|x8, [x0]
c5695f8|ands|x10, x8, #-4
c569600|cmp|w3, #0x10
c569614|mov|w19, #0
c569644|mov|w11, #0x13
c56964c|str|x10, [sp, #0x18]
c569650|mov|w10, #0x35
c569654|str|w10, [sp, #0x2c]
c569658|tbnz|w8, #0, #0xfffffe000c5696b0
c569660|add|w1, w8, #0x4c
c56966c|mov|w8, #0x96
c5696b4|add|w1, w8, #0x70
c5696c8|mov|w10, #0x96
c5696f0|str|w9, [sp, #0x78]
c5697c0|tst|w4, #1
c5697d0|csel|x2, x9, x8, eq
c5697e0|bl|#0xfffffe000bcf55dc
c569800|tbnz|w8, #1, #0xfffffe000c569824
c569804|orr|x8, x8, #2
c569808|str|x8, [x20]
'''
CACHE_EXPECTED='''
184e9d04c|bl|#0x184e807e0
184e808bc|bl|#0x184e79d1c
184e79db4|mov|w8, #0x140000
184e79db8|str|w8, [sp, #0x44]
184e79dcc|cmp|w3, #8
184e79ed4|add|w20, w24, #0x68
184e79f28|mov|w8, #0x1513
184e79f2c|movk|w8, #0x8000, lsl #16
184e79f60|mov|x4, #0xb3200000000
184e79f6c|bl|#0x188088a80
184e79fb8|cmp|w8, #0xb96
'''
KERNEL_CPP='''#include <IOKit/IOUserClient.h>
#include <stddef.h>
struct notice64 { mach_msg_header_t h; OSNotificationHeader64 n; IOAsyncCompletionContent c; };
struct notice32 { mach_msg_header_t h; OSNotificationHeader n; IOAsyncCompletionContent c; };
static_assert(sizeof(mach_msg_header_t)==32,"kernel header32");
static_assert(sizeof(IOExternalMethodArguments)==248,"arguments248");
static_assert(offsetof(IOExternalMethodArguments,asyncWakePort)==8,"wake8");
static_assert(sizeof(((IOExternalMethodArguments*)0)->asyncWakePort)==8,"wake pointer8");
static_assert(offsetof(IOExternalMethodArguments,asyncReference)==16,"refs16");
static_assert(offsetof(IOExternalMethodArguments,asyncReferenceCount)==24,"count24");
static_assert(sizeof(OSAsyncReference64)==64,"refs64");
static_assert(kOSAsyncRef64Count==8,"reference max8");
static_assert(kMaxAsyncArgs==16,"result max16");
static_assert(kIOAsyncReservedIndex==0,"reserved0");
static_assert(kIOAsyncCalloutFuncIndex==1,"callback1");
static_assert(kIOAsyncCalloutRefconIndex==2,"refcon2");
static_assert(kOSNotificationMessageID==53,"notification53");
static_assert(kOSAsyncCompleteMessageID==57,"separate constant57");
static_assert(kIOAsyncCompletionNotificationType==150,"content150");
static_assert(sizeof(OSNotificationHeader64)==72,"notice header72");
static_assert(offsetof(IOAsyncCompletionContent,args)==4,"packed result/args");
static_assert(sizeof(notice64)==112,"kernel notice64 base112");
static_assert(sizeof(notice32)==76,"kernel notice32 base76");
static_assert(kIOReturnUnsupported==0xe00002c7,"unsupported");
static_assert(kIOReturnBadArgument==0xe00002c2,"badarg");
static_assert(kIOReturnMessageTooLarge==0xe00002e1,"too large");
'''
USER_CPP='''#include <IOKit/IOKitLib.h>
#include <IOKit/OSMessageNotification.h>
#include <stddef.h>
struct notice64 { mach_msg_header_t h; OSNotificationHeader64 n; IOAsyncCompletionContent c; };
struct notice32 { mach_msg_header_t h; OSNotificationHeader n; IOAsyncCompletionContent c; };
static_assert(sizeof(mach_msg_header_t)==24,"user header24");
static_assert(sizeof(notice64)==104,"user notice64 base104");
static_assert(sizeof(notice32)==68,"user notice32 base68");
static_assert(MACH_MSG_TYPE_MAKE_SEND==20,"wake make send20");
static_assert(MACH_MSG_TYPE_COPY_SEND==19,"destination copy send19");
static_assert(MACH_MSG_TYPE_PORT_SEND==17,"received send17");
'''
def verify(s):
 fs=s['kernel_functions']+s['cache_functions'];rows={i['ea']:(i['mnemonic'],i['operands'])for f in fs for i in f['instructions']};n=0
 for text,base in((EXPECTED,0xfffffe0000000000),(CACHE_EXPECTED,0)):
  for line in text.strip().splitlines():a,m,o=line.split('|');a=hex(base+int(a,16));assert rows[a]==(m,o),(a,rows.get(a));n+=1
 for f in fs:raw=bytes.fromhex(f['bytes']);assert len(raw)==4*len(f['instructions'])==int(f['end'],16)-int(f['start'],16)and hashlib.sha256(raw).hexdigest()==f['sha256']
 ptr=s['FairPlay_vtable_bindings'];assert[p['target']for p in ptr]==['0xfffffe000c562bc8','0xfffffe000c5628f0','0xfffffe000c562848','0xfffffe000a503cd0']
 default=next(f for f in fs if f['start']=='0xfffffe000c5628f0');assert[(i['mnemonic'],i['operands'])for i in default['instructions']]==[('bti','c'),('mov','x0, #0'),('ret','')]
 r=s['MIG_routine2866'];assert r['stub']['target']=='0xfffffe000be383bc'and r['index']==66 and r['reply_size_word1c']==4284
 assert 0xe00002c2+5==0xe00002c7 and 0xb32==2866 and 0xb96==2966 and 0x35==53 and 0x96==150
 zeroed=set()
 for a,offset,extent in[(0xfffffe000c569624,16,32),(0xfffffe000c569628,224,32),(0xfffffe000c56962c,192,32),(0xfffffe000c569630,160,32),(0xfffffe000c569634,128,32),(0xfffffe000c569638,96,32),(0xfffffe000c56963c,64,32),(0xfffffe000c569640,48,16)]:
  assert rows[hex(a)]==('stp'if extent==32 else 'str',('q0, q0, 'if extent==32 else 'q0, ')+f'[sp, #{hex(offset)}]');zeroed.update(range(offset,offset+extent))
 assert zeroed==set(range(16,256))
 return n
def main():
 s=json.loads((ROOT/(P+'_source.json')).read_text());assert s==build();n=verify(s);assert all(s[f]is False for f in FLAGS)
 for name,h in s['dependencies'].items():assert sha(ROOT/name)==h
 sdk=Path(subprocess.check_output(['xcrun','--show-sdk-path'],text=True).strip());kh=sdk/'System/Library/Frameworks/Kernel.framework/Versions/A/Headers';commands=[]
 for code,kernel in((KERNEL_CPP,True),(USER_CPP,False)):
  cmd=['clang++','-target','arm64e-apple-macos13','-isysroot',str(sdk),'-std=c++17','-fsyntax-only','-x','c++','-']
  if kernel:cmd[1:1]=['-I',str(kh),'-DKERNEL','-fapple-kext','-fno-exceptions','-fno-rtti']
  r=subprocess.run(cmd,input=code,text=True,capture_output=True);assert r.returncode==0,r.stderr;commands.append(cmd)
 paths=[kh/'IOKit/IOUserClient.h',kh/'IOKit/OSMessageNotification.h',sdk/'System/Library/Frameworks/IOKit.framework/Versions/A/Headers/OSMessageNotification.h',sdk/'usr/include/mach/message.h'];hdr=[{'path':str(p),'size_bytes':p.stat().st_size,'sha256':sha(p)}for p in paths]
 geometry=[{'argument_count':i,'kernel64_bytes':112+8*i,'user64_bytes':104+8*i,'kernel32_bytes':76+4*i,'user32_bytes':68+4*i}for i in range(17)];assert geometry[-1]['kernel64_bytes']==240 and all(g['kernel64_bytes']-g['user64_bytes']==8 and g['kernel32_bytes']-g['user32_bytes']==8 for g in geometry)
 negatives=[]
 for label,fn in [('null lookup binding',lambda t:t['FairPlay_vtable_bindings'][1].update(target='0x0')),('async adapter binding',lambda t:t['FairPlay_vtable_bindings'][2].update(target='0x0')),('sync router separation',lambda t:t['FairPlay_vtable_bindings'][3].update(target='0x0')),('MIG binding',lambda t:t['MIG_routine2866']['stub'].update(target='0x0')),('default return',lambda t:t['kernel_functions'][5]['instructions'][1].update(operands='x0, #1')),('source bytes',lambda t:t['kernel_functions'][5].update(bytes='00'+t['kernel_functions'][5]['bytes'][2:])),('completion ID',lambda t:t['kernel_functions'][9]['instructions'][33].update(operands='wrong')),('port disposition',lambda t:t['cache_functions'][2]['instructions'][39].update(operands='wrong')),('zero-store coverage',lambda t:t['kernel_functions'][9]['instructions'][22].update(operands='wrong'))]:
  t=copy.deepcopy(s);fn(t)
  try:verify(t)
  except(AssertionError,KeyError,ValueError,struct.error):negatives.append(label);continue
  raise AssertionError('alteration accepted: '+label)
 fs=s['kernel_functions']+s['cache_functions'];counts={'kernel_functions':13,'cache_functions':3,'original_instructions':sum(len(f['instructions'])for f in fs),'original_function_bytes':sum(len(bytes.fromhex(f['bytes']))for f in fs),'exact_instruction_assertions':n,'vtable_bindings':4,'MIG_records':1,'SDK_assertions':KERNEL_CPP.count('static_assert')+USER_CPP.count('static_assert'),'SDK_compilations':2,'SDK_headers':4,'notification_geometries':len(geometry),'rejected_static_alterations':len(negatives)}
 out={'generator_sha256':sha(__file__),'dependencies':{P+'_source.json':sha(ROOT/(P+'_source.json'))},'verified_counts':counts,'source_recapture_match':True,'SDK_sources':[KERNEL_CPP,USER_CPP],'SDK_commands':commands,'SDK_headers':hdr,'notification_geometry':geometry,'rejected_alterations':negatives,'static_scope':{'target_instruction_visits':0,'target_instructions_emulated':0,'new_runtime_observations':0,'wire_payloads_generated':0},'all_checks_pass':True,**{f:False for f in FLAGS}};(ROOT/(P+'_checks.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(counts),flush=True)
if __name__=='__main__':main()
