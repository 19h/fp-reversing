#!/usr/bin/env python3
"""Original CF receive, libkernel voucher wrappers/initializer and cache links.
O(source+cache-hash bytes+instructions), O(source+hash block). File-default and
valid null-callback replacement tables are local cases, not runtime identity.
"""
import json
from pathlib import Path
from daemon_receive_tools import ROOT
from bootpolicy_cache_reader import Cache,Dylib,CACHE,CS
from recover_daemon_request_consumption import FLAGS,sha
from recover_cf_receive import CF_PATH,CF_UUID,SERVICE
P='cf_receive_voucher';MACH=0x180547f94;REVERT=0x18054b32c;ADOPT=0x18054b344;INIT=0x180548154;ROOTCELL=0x1ed83e8d8
class CacheView:
 """Read-only raw source plus explicitly decoded original cache pointer cells."""
 def __init__(self,source):
  self.k=self;self.cs=CS;self.pages={int(e['address'],16):bytes.fromhex(e['bytes_hex'])for e in source['original_cache_pages']};self.pointers={int(e['pointer']['address'],16):int(e['pointer']['target'],16)for e in source['import_stubs']};r=source['original_hook_table_pointer'];self.pointers[int(r['address'],16)]=int(r['target'],16)
 def read(self,a,n):
  out=b''
  while n:
   at=a&~4095;size=min(n,4096-(a-at));out+=self.pages[at][a-at:a-at+size];a+=size;n-=size
  return out
 def logical_page(self,a):
  out=bytearray(self.pages[a])
  for slot,value in self.pointers.items():
   if slot&~4095==a:out[slot-a:slot-a+8]=value.to_bytes(8,'little')
  return bytes(out)
def build():
 c=Cache();assert c.uuid=='2bd06591-e751-3e84-963f-b08dab6af23a';cf=Dylib(c,CF_PATH);lk=Dylib(c,'/usr/lib/system/libsystem_kernel.dylib');assert cf.uuid==CF_UUID and lk.uuid=='f2bceb9a-0fec-3c92-b6ea-8e37157050a8';functions=[cf.function(SERVICE)]+[lk.function(a)for a in(REVERT,ADOPT,INIT)];stubs=[]
 for a,want,name in((0x188076b60,MACH,'_mach_msg'),(0x188081380,REVERT,'_voucher_mach_msg_revert'),(0x188081360,ADOPT,'_voucher_mach_msg_adopt')):
  raw=c.read(a,16);ins=list(CS.disasm(raw,a));assert[i.mnemonic for i in ins]==['adrp','add','ldr','braa'];slot=int(ins[0].op_str.split('#')[1],16)+int(ins[1].op_str.split('#')[1],16);ptr=c.pointer(slot);assert int(ptr['target'],16)==want and lk.exports[name]['address']==want;stubs.append({'start':hex(a),'end':hex(a+16),'bytes':raw.hex(),'pointer':ptr,'exact_export':name,'target':hex(want),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ins]})
 pointer=c.pointer(ROOTCELL);table=int(pointer['target'],16);assert table==0x18057d1a0 and c.read(table,48)==bytes(48);pointer['original_table48_hex']=c.read(table,48).hex();assert lk.exports['___libkernel_voucher_init']['address']==INIT
 addresses={int(f['start'],16)&~4095 for f in functions+stubs}|{int(f['end'],16)-1&~4095 for f in functions+stubs}|{ROOTCELL&~4095,table&~4095}|{int(s['pointer']['address'],16)&~4095 for s in stubs}|{MACH&~4095};pages=[{'address':hex(a),'bytes_hex':c.read(a,4096).hex()}for a in sorted(addresses)];files=sorted(c.used|{str(CACHE)})
 from kernel_vm_mig_tools import Image as KernelImage
 kernel=KernelImage();roles=[]
 for a,m,o in[(0xfffffe000bcc1430,'tbz','w1, #0xb, #0xfffffe000bcc1398'),(0xfffffe000bcc53a8,'orr','w8, w8, w24, lsl #16'),(0xfffffe000bcc53c4,'str','w8, [x22]'),(0xfffffe000bcda4bc,'tbz','w1, #0xb, #0xfffffe000bcda4cc'),(0xfffffe000bcc6648,'stp','w12, w8, [x0, #8]!')]:
  raw=kernel.k.read(a,4);i=next(kernel.k.cs.disasm(raw,a));assert(i.mnemonic,i.op_str)==(m,o),(hex(a),i.mnemonic,i.op_str);roles.append({'pc':hex(a),'bytes_hex':raw.hex(),'mnemonic':m,'operands':o})
 return {'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['kernel_request_delivery_source.json','kernel_request_delivery_profiles.json','kernel_request_copyin_profiles.json','cf_daemon_request_profiles.json','cf_daemon_request_checks.json','bootpolicy_cache_reader.py','probe_kernel_request_delivery.py','replay_kernel_request_delivery.py']},'kernel_sha256':kernel.k.sha256,'kernel_instruction_roles':roles,'cache_uuid':c.uuid,'CF_uuid':cf.uuid,'libkernel_uuid':lk.uuid,'functions':functions,'import_stubs':stubs,'original_hook_table_pointer':pointer,'original_cache_pages':pages,'cache_files':[{'path':n,'size_bytes':Path(n).stat().st_size,'sha256':sha(n)}for n in files],**FLAGS}
if __name__=='__main__':
 out=build();(ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'complete_functions':len(out['functions']),'captured_instructions':sum(len(f['instructions'])for f in out['functions'])+12,'import_stubs':3,'cache_pages':len(out['original_cache_pages']),'cache_files':len(out['cache_files'])}),flush=True)
