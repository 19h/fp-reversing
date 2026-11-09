#!/usr/bin/env python3
"""Original map constructor/root producer and downstream type2 store interface.
O(image+captured bytes+instruction words), O(image+source+bounded reference windows).
No native VM, IPC or IDB effects. ADRP page references are a syntactic inventory.
"""
import json,struct
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
P='kernel_map_store_init'
def main():
 im=Image();out=dict(json.loads((ROOT/'kernel_type2_copyout_source.json').read_text()));starts=list(dict.fromkeys([*[int(f['start'],16)for f in out['functions']],0xfffffe000bdc6eac,0xfffffe000bdc6ebc,0xfffffe000bddd56c,0xfffffe000bddf4ec,0xfffffe000bddfe6c]));funcs=[]
 for a in starts:
  f=im.k.function(a,exact=True);f['exact_symbols']=im.k.symbols([a])[hex(a)];funcs.append(f)
 hits=[];words=0
 for sec in im.k.kernel['sections']:
  if not sec['flags']&0x80000400:continue
  raw=im.k.read(sec['address'],sec['size']&~3);words+=len(raw)//4
  for j,(w,)in enumerate(struct.iter_unpack('<I',raw)):
   if w&0x9f000000!=0x90000000:continue
   imm=((w>>5)&0x7ffff)<<2|((w>>29)&3);imm-=(imm>>20)<<21;a=sec['address']+4*j;page=((a&~4095)+(imm<<12))&((1<<64)-1)
   if page!=0xfffffe0007e69000:continue
   f=im.k.function(a,exact=False);raw=im.k.read(a,96);hits.append({'pc':hex(a),'function':f['start'],'bytes_hex':raw.hex(),'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in im.k.cs.disasm(raw,a)]})
 out.update(scope=__doc__,generator_sha256=sha(__file__),dependencies={n:sha(ROOT/n)for n in ['kernel_type2_copyout_source.json','kernel_type2_copyout_profiles.json','kernel_vm_entry_copy_profiles.json','kernel_vm_mig_tools.py',P+'_prior_manifest.json']},functions=funcs,store_move_primitive={'address':'0xfffffe000c647f10','bytes_hex':im.k.read(0xfffffe000c647f10,32).hex(),'exact_symbols':im.k.symbols([0xfffffe000c647f10])['0xfffffe000c647f10']},class_bounds_page_ADRP_scan={'instruction_words':words,'target_page':'0xfffffe0007e69000','hits':hits,'direct_indirect_writer_completeness_established':False},map_constructor_file_cells=[{'address':hex(a),'bytes_hex':im.k.read(a,n).hex(),'native_runtime_value_established':False}for a,n in[(0xfffffe000caec080,16),(0xfffffe000caec200,16),(0xfffffe000caa4f9c,4),(0xfffffe000cb810e8,8)]]);(ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(funcs),'instructions':sum(len(f['instructions'])for f in funcs),'scan_words':words,'page_references':len(hits)}),flush=True)
if __name__=='__main__':main()
