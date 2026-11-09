#!/usr/bin/env python3
"""Original special IPC-space bootstrap and kernel-thread reply-port lifetime.
O(image+source+kernel instruction words), O(image+source+reference windows).
No native bootstrap, allocator, IPC, VM, scheduling, authentication or retirement.
"""
import json,struct
from kernel_vm_mig_tools import Image
from kext_port_tools import ROOT
from recover_aes_command_gate import sha
from recover_kernel_send_right_lifecycle import FLAGS
P='kernel_special_reply';BOOT=0xfffffe000c629780;SPACE_CELL=0xfffffe0007e63348
STARTS=[0xfffffe000c2ba130,BOOT,0xfffffe000bcf8e14,0xfffffe000bccef30,0xfffffe000bcced98,0xfffffe000bcceadc,0xfffffe000bcce310,0xfffffe000bd68354,0xfffffe000bd683e0,0xfffffe000bcc927c,0xfffffe000bd7deec,0xfffffe000bd6d488,0xfffffe000bd0aa54,0xfffffe000bcf837c,0xfffffe000bccdbb4,0xfffffe000bcf59e0]
SITES=[0xfffffe000c2ba194,0xfffffe000bcce87c,0xfffffe000bcce884,0xfffffe000c6297a8,0xfffffe000c6297ec,0xfffffe000c6297fc,0xfffffe000c629828,0xfffffe000bcf8e84,0xfffffe000bcf8ea4,0xfffffe000bcf8eac,0xfffffe000bcf8ec4,0xfffffe000bcf8ed0,0xfffffe000bcf8ef0,0xfffffe000bccef54,0xfffffe000bccf098,0xfffffe000bccf0c4,0xfffffe000bccf0d4,0xfffffe000bcceea0,0xfffffe000bcceb5c,0xfffffe000bcce618,0xfffffe000bcce800,0xfffffe000bcce890,0xfffffe000bcce9d0,0xfffffe000bcce9d8,0xfffffe000bd6844c,0xfffffe000bd68470,0xfffffe000bd7df44,0xfffffe000bcf839c,0xfffffe000bcf83cc]
def scan(im):
 hits=[];words=0
 for s in im.k.kernel['segments']:
  if s['name']!='__TEXT_EXEC':continue
  for off in range(s['file_offset'],s['file_offset']+s['file_size'],4):
   words+=1;w=struct.unpack_from('<I',im.k.data,off)[0]
   if w&0x9f000000!=0x90000000:continue
   a=s['address']+off-s['file_offset'];imm=((w>>29)&3)|(((w>>5)&0x7ffff)<<2);imm=imm-(1<<21)if imm&(1<<20)else imm
   if((a&~4095)+(imm<<12))&((1<<64)-1)!=SPACE_CELL&~4095:continue
   ins=list(im.k.cs.disasm(im.k.read(a,100),a));reg=ins[0].op_str.split(',')[0]
   if not any('#0x348]'in i.op_str or '#0x348'in i.op_str and reg in i.op_str for i in ins[1:]):continue
   hits.append({'pc':hex(a),'bytes100_hex':im.k.read(a,100).hex(),'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ins]})
 return {'scope':'Kernel __TEXT_EXEC ADRP target-page and 100-byte offset-mention windows; manually matched base registers at the five retained accesses','instruction_words':words,'target_cell':hex(SPACE_CELL),'hits':hits,'arbitrary_indirect_writer_completeness_established':False}
def main():
 im=Image();out=dict(json.loads((ROOT/'kernel_reply_namespace_source.json').read_text()));zs=json.loads((ROOT/'kernel_zone_startup_source.json').read_text());aa=list(dict.fromkeys([int(f['start'],16)for f in out['functions']]+[int(f['start'],16)for f in zs['functions']]+STARTS));old={int(f['start'],16)for f in out['functions']};syms=im.k.symbols(aa);fs=[]
 for a in aa:f=im.k.function(a);f['exact_symbols']=syms[hex(a)];fs.append(f)
 roles={}
 for a in SITES:i=next(im.k.cs.disasm(im.k.read(a,4),a));roles[hex(a)]={'pc':hex(a),'bytes_hex':i.bytes.hex(),'mnemonic':i.mnemonic,'operands':i.op_str}
 entries=[e for e in zs['zone_startup_entries']if e['name']in ['ipc ports','turnstiles','ipc spaces']]
 out.update(scope=__doc__,generator_sha256=sha(__file__),dependencies={n:sha(ROOT/n)for n in[P+'_prior_manifest.json','kernel_reply_namespace_source.json','kernel_reply_namespace_profiles.json','kernel_zone_startup_source.json','kernel_zone_startup_profiles.json','kext_constructor_request_profiles.json','kernel_receive_copyout_profiles.json','kernel_vm_mig_tools.py']},functions=fs,new_special_reply_functions=[hex(a)for a in aa if a not in old],special_reply_instruction_roles=roles,special_zone_entries=entries,reply_space_reference_scan=scan(im),bootstrap_file_cells=[{'address':hex(a),'bytes_hex':im.k.read(a,n).hex()}for a,n in[(0xfffffe0007e5c470,8),(0xfffffe0007e62b68,8),(SPACE_CELL,8),(0xfffffe000700dc58,16)]],native_special_reply_observed=False,**{k:False for k in FLAGS})
 (ROOT/(P+'_source.json')).write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'functions':len(fs),'instructions':sum(len(f['instructions'])for f in fs),'new_functions':len(out['new_special_reply_functions']),'scan_words':out['reply_space_reference_scan']['instruction_words'],'scan_hits':len(out['reply_space_reference_scan']['hits'])}))
if __name__=='__main__':main()
