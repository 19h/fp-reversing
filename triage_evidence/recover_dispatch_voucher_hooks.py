#!/usr/bin/env python3
"""Original libSystem/dispatch installation route and voucher callback table.
O(source+symbols+cache-hash bytes), O(source+symbols+hash block). Static parent
call sites are not evidence of native startup or effective runtime identity.
"""
import json,struct
from pathlib import Path
from daemon_receive_tools import ROOT
from bootpolicy_cache_reader import Cache,Dylib,CACHE,CS
from recover_daemon_request_consumption import FLAGS,sha
from recover_cf_receive_voucher import CacheView as PreviousView
P='dispatch_voucher_hooks';DISPATCH_INIT=0x18553ac4c;DISPATCH_ADOPT=0x18553aa9c;DISPATCH_REVERT=0x18553ab70;TABLE=0x1e24b27d0
class CacheView(PreviousView):
 def __init__(self,source):
  super().__init__(source)
  for e in source['installed_hook_table']['callbacks']:self.pointers[int(e['pointer']['address'],16)]=int(e['pointer']['target'],16)
def build():
 old=json.loads((ROOT/'cf_receive_voucher_source.json').read_text());c=Cache();assert c.uuid==old['cache_uuid'];ld=Dylib(c,'/usr/lib/system/libdispatch.dylib');sy=Dylib(c,'/usr/lib/libSystem.B.dylib');assert ld.uuid=='6f5e8225-ad67-3644-afef-25a4a43bf604'and sy.uuid=='deaf2098-8edd-3e5d-a821-f63a14d6c055';funs=list(old['functions']);members=[]
 for off,a,name in[(8,0x18553a9a0,'_voucher_mach_msg_set'),(16,0x18553aa44,'_voucher_mach_msg_clear'),(24,DISPATCH_ADOPT,'_voucher_mach_msg_adopt'),(32,DISPATCH_REVERT,'_voucher_mach_msg_revert'),(40,0x18553c2a8,'_voucher_mach_msg_fill_aux')]:
  ptr=c.pointer(TABLE+off);symbols=ld.symbols_at(a);assert int(ptr['target'],16)==a and any(s['name']==name for s in symbols);f=ld.function(a);f['exact_nlist']=symbols;funs.append(f);members.append({'offset_bytes':off,'original_name':name,'pointer':ptr,'exact_nlist':symbols})
 for lib,a in[(ld,DISPATCH_INIT),(ld,0x18554a280),(sy,0x2cbbed264)]:f=lib.function(a);f['exact_nlist']=lib.symbols_at(a);funs.append(f)
 stubs=list(old['import_stubs'])
 for a,target,label in[(0x18808c2a0,0x180548154,'___libkernel_voucher_init'),(0x2d00a0a60,0x18554a280,'_libdispatch_init')]:
  raw=c.read(a,16);ins=list(CS.disasm(raw,a));assert[i.mnemonic for i in ins]==['adrp','add','ldr','braa'];slot=int(ins[0].op_str.split('#')[1],16)+int(ins[1].op_str.split('#')[1],16);ptr=c.pointer(slot);assert int(ptr['target'],16)==target;stubs.append({'start':hex(a),'end':hex(a+16),'bytes':raw.hex(),'pointer':ptr,'exact_export':label,'target':hex(target),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ins]})
 edges=[]
 for a,target in[(0x2cbbed354,0x2d00a0a60),(0x18554a460,DISPATCH_INIT),(0x18553ac54,0x18808c2a0)]:
  raw=c.read(a,4);i=next(CS.disasm(raw,a));assert i.mnemonic in('b','bl')and i.op_str=='#'+hex(target);edges.append({'pc':hex(a),'target':hex(target),'bytes_hex':raw.hex(),'mnemonic':i.mnemonic,'operands':i.op_str})
 sec=next(s for s in sy.sections if s['name']=='__init_offsets');initword=c.read(sec['address'],4);assert sy.base+struct.unpack('<I',initword)[0]==0x2cbbed264
 table=c.read(TABLE,48);assert struct.unpack_from('<Q',table)[0]==3;pages={int(e['address'],16):bytes.fromhex(e['bytes_hex'])for e in old['original_cache_pages']};root=old['original_hook_table_pointer'];current_root=c.pointer(int(root['address'],16));assert all(current_root[k]==root[k]for k in current_root)and c.read(int(root['target'],16),48).hex()==root['original_table48_hex']
 for a in(int(root['address'],16)&~4095,int(root['target'],16)&~4095):pages[a]=c.read(a,4096)
 for a,n in[(int(f['start'],16),int(f['end'],16)-int(f['start'],16))for f in funs+stubs]+[(TABLE,48),(sec['address'],4)]+[(int(s['pointer']['address'],16),8)for s in stubs]:
  for pg in range(a&~4095,((a+n-1)&~4095)+4096,4096):pages[pg]=c.read(pg,4096)
 files=sorted(c.used|{r['path']for r in old['cache_files']}|{str(CACHE)});got=[s for s in ld.sections if s['name']in('__got','__auth_got')];slot=int(stubs[-2]['pointer']['address'],16);assert not any(s['address']<=slot<s['address']+s['size']for s in got)
 return {'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in['cf_receive_voucher_source.json','cf_receive_voucher_profiles.json','cf_receive_voucher_checks.json','cf_daemon_request_source.json','cf_daemon_request_profiles.json','probe_cf_receive_voucher.py','replay_cf_receive_voucher.py','bootpolicy_cache_reader.py']},'cache_uuid':c.uuid,'dispatch_uuid':ld.uuid,'libSystem_uuid':sy.uuid,'functions':funs,'import_stubs':stubs,'dispatch_local_GOT_sections':got,'voucher_initializer_binding_outside_local_GOT':True,'original_hook_table_pointer':old['original_hook_table_pointer'],'installed_hook_table':{'address':hex(TABLE),'original_raw48_hex':table.hex(),'leading_scalar_u64':3,'callbacks':members},'parent_call_edges':edges,'libSystem_init_offset':{'section_address':hex(sec['address']),'original_word_hex':initword.hex(),'image_base':hex(sy.base),'target':'0x2cbbed264'},'original_cache_pages':[{'address':hex(a),'bytes_hex':b.hex()}for a,b in sorted(pages.items())],'cache_files':[{'path':n,'size_bytes':Path(n).stat().st_size,'sha256':sha(n)}for n in files],**FLAGS}
if __name__=='__main__':
 out=build();(ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(out['functions']),'instructions':sum(len(f['instructions'])for f in out['functions'])+4*len(out['import_stubs']),'table_members':len(out['installed_hook_table']['callbacks']),'cache_files':len(out['cache_files'])}),flush=True)
