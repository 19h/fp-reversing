#!/usr/bin/env python3
"""Original FPAppSecurityInfo views, allocation/free delegates and caller slices.
O(image bytes+captured instructions+256*banks), O(image bytes). No target effects.
"""
import hashlib,json,re,struct
from pathlib import Path
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT,IMAGE,POOL,TABLE,qword,selected
P='kext_security_record'
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 im=Image();k=im.k;views=[]
 for role,a in [('allocation',0xfffffe000847bd60),('cleanup',0xfffffe000847bc60)]:
  raw=k.read(a,64);ptrs=[]
  for off in [0x10,0x20]:
   p=im.pointer(a+off);b=k.read(int(p['target'],16),128).split(b'\0')[0];ptrs.append({'offset':hex(off),'pointer':p,'string_bytes_hex':b.hex(),'string_ascii':b.decode('ascii')})
  flags,size=struct.unpack('<II',raw[0x28:0x30]);assert(flags,size)==(0x64,0x98)and ptrs[0]['string_ascii']=='site.FPAppSecurityInfo';views.append({'role':role,'address':hex(a),'bytes64_hex':raw.hex(),'runtime_prefix16_file_hex':raw[:16].hex(),'flags_word28':flags,'size_word2c':size,'pointers':ptrs})
 assert views[0]['bytes64_hex']==views[1]['bytes64_hex']
 functions=[k.function(a)for a in [0xfffffe000c4ba154,0xfffffe000bcfeb8c,0xfffffe000c4ba368,0xfffffe000bcff010]]
 spans=[(0xfffffe000a606728,0xfffffe000a60674c),(0xfffffe000a606878,0xfffffe000a6068a0),(0xfffffe000a606ad4,0xfffffe000a606b08),(0xfffffe000a606bd4,0xfffffe000a606bdc),(0xfffffe000a60aa14,0xfffffe000a60aa1c),(0xfffffe000a60aaa0,0xfffffe000a60abb8),(0xfffffe000a60ae40,0xfffffe000a60ae4c),(0xfffffe000a6110d0,0xfffffe000a6110e0),(0xfffffe000a6165e4,0xfffffe000a616600),(0xfffffe000a5a21ec,0xfffffe000a5a2228)]
 ranges=[]
 for a,z in spans:
  raw=k.read(a,z-a);assert IMAGE.read(a,z-a)==raw;ranges.append({'start':hex(a),'end':hex(z),'bytes_hex':raw.hex(),'sha256':hashlib.sha256(raw).hexdigest(),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in k.cs.disasm(raw,a)]})
 banks=[]
 for name,l,r,key,add,base,bias in [('allocator',qword(POOL+0xb70),qword(POOL+0xa10),0x32,0xe1a,TABLE,0),('allocation_view',qword(POOL+0x458)-8,qword(POOL+0x638)-12,0x87,0x5d,POOL,-12)]:
  b=selected(l,r,key,add,base,bias);b.update(name=name,original_pointer=im.pointer(int(b['slot'],16)),left_bytes256_hex=k.read(l,256).hex(),right_bytes256_hex=k.read(r,256).hex());assert k.read(l,256)==IMAGE.read(l,256)and k.read(r,256)==IMAGE.read(r,256);banks.append(b)
 assert [b['target']for b in banks]==['0xfffffe000c4ba154','0xfffffe000847bd60']
 e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');sec=next(s for s in e['sections']if s['address']<=0xfffffe000847bd60<s['address']+s['size']);assert sec['section']=='__kalloc_type'
 roots=[{'pool_offset':hex(off),'bias':bias,'pointer':im.pointer(POOL+off)}for off,bias in [(0xb70,0),(0xa10,0),(0x458,-8),(0x638,-12)]]
 stores=[];covered=set()
 for i in ranges[-1]['instructions']:
  if '[x21'not in i['operands']:continue
  m=re.search(r'\[x21(?:, #(0x[0-9a-f]+))?\]',i['operands']);assert m
  off=int(m.group(1),16)if m.group(1)else 0;size=32 if i['mnemonic']=='stp'and i['operands'].startswith('q')else 8;assert i['mnemonic']in ['stp','str'];stores.append({'pc':i['ea'],'offset_bytes':off,'size_bytes':size});covered.update(range(off,off+size))
 assert covered==set(range(136))and len(stores)==5
 out={'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['kernel_vm_mig_tools.py','kext_port_tools.py','kext_mapped_cleanup_source.json','rpc502_reply_bridge_source.json']},'kernel_sha256':k.sha256,'views':views,'view_section':sec,'functions':functions,'ranges':ranges,'banks':banks,'bank_roots':roots,'symbols':k.symbols([0xfffffe000c4ba154,0xfffffe000bcfeb8c,0xfffffe000c4ba368,0xfffffe000bcff010]),'caller_success_slot':im.pointer(TABLE+0xc96*8),'caller_null_slot':im.pointer(TABLE+0xc97*8),'conditional_caller_W20':'0xc96; native predecessor derivation unknown','original_view_identity_does_not_prove_runtime_state_identity':True,'RPC_record_copy_stores':stores,'fixed_RPC_record_bytes':len(covered),'allocation_metadata_bytes':views[0]['size_word2c'],'unused_allocation_suffix_bytes':views[0]['size_word2c']-len(covered),'native_target_executed':False,'native_allocation_executed':False,'idb_mutated':False,'full_goal_complete':False};return out
if __name__=='__main__':
 out=main();(ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(out['functions']),'ranges':len(out['ranges']),'instructions':sum(len(x['instructions'])for x in out['functions']+out['ranges']),'views':len(out['views']),'banks256':len(out['banks'])}),flush=True)
