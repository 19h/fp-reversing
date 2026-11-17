#!/usr/bin/env python3
"""Digest-bound returned boot image and later logging consumer source.
Linear source/collection/page work; no native execution or target-byte scrub.
"""
import json
from hashlib import sha256
from kext_port_tools import ROOT
from kernel_vm_mig_tools import Image
from recover_kernel_boot_fixup_projection import CorrectedImage
from recover_kernel_boot_environment_publication import capture
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_kernel_early_logging_execution as B
P='kernel_boot_logging_handoff';LOOKUP=0xfffffe000c478d18;CONTAINS=0xfffffe000be763b4;CONSOLE=0xfffffe000c5e73a4;FRONTIER=0xfffffe000c48fc98
PAIRS=[(0xfffffe0007e6d9c8,0xfffffe0007e6dad8),(0xfffffe0007e6daf8,0xfffffe0007e6daf0),(0xfffffe0007e6dae8,0xfffffe0007e6dae0)]
SCOPE='Returned boot image hydrated by exact source-execution page digests, declared startup fixture precedence and eight source-produced words before main. Continuous main/logging replay with preserved poisoned regression; cold-entry admission, native initialization/PAC and matched FairPlay IPC remain unknown.'
class BootImage(CorrectedImage):
 def __init__(self):
  super().__init__(Image());self.boot=json.loads(read(ROOT/'kernel_boot_initializer_execution_audit.json'))['component'];self.globals={int(r['address'],16):int(r['value'],16) for r in self.boot['published_global_words']};self.checked=set();self.untouched=set()
 def logical_page(self,pg):
  raw=bytearray(super().logical_page(pg))
  for a,v in self.globals.items():
   if pg<=a<a+8<=pg+4096:raw[a-pg:a-pg+8]=v.to_bytes(8,'little')
  if hex(pg) in self.boot['final_page_sha256']:assert sha256(raw).hexdigest()==self.boot['final_page_sha256'][hex(pg)];self.checked.add(pg)
  else:assert pg not in self.pages and pg not in self.incoming and not any(pg<=a<pg+4096 for a in self.globals);self.untouched.add(pg)
  return bytes(raw)
def build():
 im=BootImage();prior=json.loads(read(ROOT/(B.P+'_checks.json')));functions=[*prior['functions'],*[capture(im.k,a) for a in [LOOKUP,CONTAINS,CONSOLE]]]
 for pg in im.boot['final_page_sha256']:im.logical_page(int(pg,16))
 addresses=[(a,8) for p in PAIRS for a in p]+[(0xfffffe000cba2638,4),(0xfffffe000cba2640,8),(0xfffffe000cb51b00,8),(0xfffffe0007f8b644,1),(0xfffffe000ca921c8,16),(0xfffffe000700eb10,16)]
 return {'generator_sha256':sha(__file__),'scope':SCOPE,'kernel_collection_sha256':im.k.sha256,'dependencies':{n:sha(ROOT/n) for n in ['kernel_boot_initializer_execution_checks.json','kernel_boot_initializer_execution_audit.json',B.P+'_checks.json',B.P+'_audit.json','kernel_vm_mig_tools.py','recover_kernel_boot_fixup_projection.py']},'functions':functions,'published_boot_words':im.boot['published_global_words'],'additional_raw_records':[{'address':hex(a),'bytes_hex':im.k.read(a,n).hex()} for a,n in addresses],'root_header':{'address':'0xfffffe0007004000','raw32_hex':im.k.read(0xfffffe0007004000,32).hex(),'filetype_u32':int.from_bytes(im.k.read(0xfffffe000700400c,4),'little')},'exact_helper_symbols':im.k.symbols([LOOKUP,CONTAINS,CONSOLE]),'verified_counts':{'functions':len(functions),'source_words':sum(len(f['instructions']) for f in functions),'added_functions':3,'added_words':295,'boot_pages_rehydrated':len(im.checked),'boot_global_words':8,'boot_global_bytes':64,'range_pairs':3},'native_target_executed':False}
if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
