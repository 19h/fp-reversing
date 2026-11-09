#!/usr/bin/env python3
"""Pin original complete run-loop caller and receive/source/daemon components.
O(source+symbols+cache hashes), O(source+symbols+hash block). Runtime objects,
dictionary lookup, clocks and helper outcomes remain explicit premises.
"""
import json,struct,hashlib
from pathlib import Path
import unicorn as uc
from unicorn import arm64_const as A
from daemon_receive_tools import ROOT
from bootpolicy_cache_reader import Cache,Dylib,CACHE,CS
from recover_dispatch_voucher_hooks import CacheView as PreviousView
from recover_daemon_request_consumption import FLAGS,sha
from recover_cf_receive import CF_PATH,CF_UUID,RUN
P='cf_runloop_handoff'
class CacheView(PreviousView):
 def __init__(self,source):
  super().__init__(source)
  for p in source['extra_pointer_fixups']:self.pointers[int(p['address'],16)]=int(p['target'],16)
def initial_max_engine(old,code,read,write):
 """Transfer only pre-execution loader state to a MAX-feature private CPU."""
 new=uc.Uc(uc.UC_ARCH_ARM64,uc.UC_MODE_ARM);new.ctl_set_cpu_model(A.UC_CPU_ARM64_MAX)
 for lo,hi,prot in old.mem_regions():
  new.mem_map(lo,hi-lo+1,prot);raw=bytes(old.mem_read(lo,hi-lo+1));new.mem_write(lo,raw);assert bytes(new.mem_read(lo,len(raw)))==raw
 for reg in[getattr(A,'UC_ARM64_REG_X'+str(j))for j in range(31)]+[A.UC_ARM64_REG_SP,A.UC_ARM64_REG_NZCV,A.UC_ARM64_REG_CPACR_EL1,A.UC_ARM64_REG_FPCR,A.UC_ARM64_REG_FPSR]+[getattr(A,'UC_ARM64_REG_Q'+str(j))for j in range(32)]:new.reg_write(reg,old.reg_read(reg))
 new.hook_add(uc.UC_HOOK_CODE,code);new.hook_add(uc.UC_HOOK_MEM_READ,read);new.hook_add(uc.UC_HOOK_MEM_WRITE,write);return new
def build():
 prior=json.loads((ROOT/'dispatch_voucher_hooks_source.json').read_text());cfold=json.loads((ROOT/'cf_daemon_request_source.json').read_text());c=Cache();cf=Dylib(c,CF_PATH);objc=Dylib(c,'/usr/lib/libobjc.A.dylib');assert c.uuid==prior['cache_uuid']and cf.uuid==CF_UUID
 funcs=list(prior['functions'])+list(cfold['CF_functions'])
 for lib,a in[(cf,RUN),(objc,0x18040bbec),(objc,0x18040bb98)]:f=lib.function(a);f['exact_nlist']=lib.symbols_at(a);funcs.append(f)
 stubs=list(prior['import_stubs']);symbols=[]
 for a,target,label in[(0x188076b50,0x18054808c,'_mach_absolute_time'),(0x188077380,0x180588804,'_pthread_main_np'),(0x18806ead0,0x18040bbec,'_objc_release')]:
  raw=c.read(a,16);ins=list(CS.disasm(raw,a));assert[i.mnemonic for i in ins]==['adrp','add','ldr','braa'];slot=int(ins[0].op_str.split('#')[1],16)+int(ins[1].op_str.split('#')[1],16);ptr=c.pointer(slot);assert int(ptr['target'],16)==target;stubs.append({'start':hex(a),'end':hex(a+16),'bytes':raw.hex(),'pointer':ptr,'exact_export':label,'target':hex(target),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ins]})
 for a in(0x184832bc8,0x184758240,0x184758504,0x18471b500,0x1846ddc8c,0x1846ddde4):symbols.append({'address':hex(a),'original_bytes16_hex':c.read(a,16).hex(),'exact_nlist':cf.symbols_at(a)})
 extra=[c.pointer(0x1e01c8830)];assert extra[0]['target']=='0x1855148ec';ld=Dylib(c,'/usr/lib/system/libdispatch.dylib');extra[0]['exact_nlist']=ld.symbols_at(0x1855148ec)
 pages={int(e['address'],16):bytes.fromhex(e['bytes_hex'])for e in prior['original_cache_pages']+cfold['CF_original_pages']}
 ranges=[(int(f['start'],16),int(f['end'],16)-int(f['start'],16))for f in funcs+stubs]+[(a,16)for a in(0x18054808c,0x180588804,0x184951c58,0x18494e840,0x1e01c8830)]+[(int(s['pointer']['address'],16),8)for s in stubs]+[(int(e['address'],16),16)for e in symbols]
 for a,n in ranges:
  for pg in range(a&~4095,((a+n-1)&~4095)+4096,4096):pages[pg]=c.read(pg,4096)
 files=sorted(c.used|{r['path']for r in prior['cache_files']+cfold['cache_files']}|{str(CACHE)})
 return {'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in['dispatch_voucher_hooks_source.json','dispatch_voucher_hooks_profiles.json','cf_daemon_request_source.json','probe_cf_daemon_request.py','replay_cf_daemon_request.py','kernel_request_delivery_profiles.json','bootpolicy_cache_reader.py']},'cache_uuid':c.uuid,'CF_uuid':cf.uuid,'ranges':cfold['ranges'],'cache_function':cfold['cache_function'],'CF_functions':funcs,'CF_original_pages':[{'address':hex(a),'bytes_hex':b.hex()}for a,b in sorted(pages.items())],'original_cache_pages':[{'address':hex(a),'bytes_hex':b.hex()}for a,b in sorted(pages.items())],'import_stubs':stubs,'installed_hook_table':prior['installed_hook_table'],'original_hook_table_pointer':prior['original_hook_table_pointer'],'extra_pointer_fixups':extra,'runloop_helper_boundaries':symbols,'cache_files':[{'path':n,'size_bytes':Path(n).stat().st_size,'sha256':sha(n)}for n in files],**FLAGS}
if __name__=='__main__':
 out=build();(ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'CF_cache_functions':len(out['CF_functions']),'instructions':sum(len(f['instructions'])for f in out['CF_functions'])+4*len(out['import_stubs']),'cache_files':len(out['cache_files'])}),flush=True)
