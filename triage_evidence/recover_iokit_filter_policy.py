#!/usr/bin/env python3
"""Static IOKit filter registration/cache/callback/free interface capture.
No target execution/emulation, policy invocation, IPC or IDB mutation.
O(collection+fixups+symbols+kernel words) time; O(collection+capture) space.
"""
import bisect,hashlib,json,struct
from pathlib import Path
from kernel_vm_mig_tools import Image
from resolve_kernel_collection_interfaces import commands
ROOT=Path(__file__).resolve().parent;P='iokit_filter_policy'
FLAGS=['native_target_executed','target_instructions_emulated','native_IPC_executed','hardware_PAC_executed','idb_mutated','native_filter_registration_observed','native_policy_decision_established','complete_FairPlay_round_trip_established','full_goal_complete']
FUNCTIONS=[0xfffffe000c572e34,0xfffffe000c568e48,0xfffffe000c56848c,0xfffffe000c5654a8,0xfffffe000c56e604,0xfffffe000c5708f4,0xfffffe000c570318,0xfffffe000c570cc0,0xfffffe000c572744,0xfffffe000be383bc,0xfffffe000be3795c,0xfffffe000be386b4,0xfffffe000bcfeb8c,0xfffffe000c4ba368]
def sha(p):
 with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def entry_starts(k,e):
 base=next(s['address']for s in e['segments']if s['name']=='__TEXT');starts=[]
 for at,cmd,size in commands(k.data,e['header_offset']):
  if cmd!=0x26:continue
  off,n=struct.unpack_from('<II',k.data,at+8);pos=off;value=base
  while pos<off+n:
   delta=shift=0
   while True:
    b=k.data[pos];pos+=1;delta|=(b&127)<<shift
    if b<128:break
    shift+=7;assert shift<70
   if delta==0:break
   value+=delta;starts.append(value)
 return starts
def sandbox_function(k,starts,a):
 ix=bisect.bisect_left(starts,a);assert starts[ix]==a;end=starts[ix+1];raw=k.read(a,end-a);ins=list(k.cs.disasm(raw,a));assert len(raw)==4*len(ins)
 return {'start':hex(a),'end':hex(end),'bytes':raw.hex(),'sha256':hashlib.sha256(raw).hexdigest(),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ins]}
def root_candidates(k):
 s=next(s for s in k.kernel['segments']if s['name']=='__TEXT_EXEC');base=s['address'];raw=k.read(base,s['file_size']);rows=[]
 for j,(w,)in enumerate(struct.iter_unpack('<I',raw)):
  if w&0x9f000000!=0x90000000:continue
  imm=((w>>29)&3)|(((w>>5)&0x7ffff)<<2);imm=imm-(1<<21)if imm&(1<<20)else imm;a=base+4*j
  if(a&~4095)+(imm<<12)!=0xfffffe0007f50000:continue
  ins=list(k.cs.disasm(raw[j*4:j*4+64],a))
  if not any('#0x528'in i.op_str for i in ins):continue
  rows.append({'function':k.function(a,exact=False)['start'],'ADRP':hex(a),'window':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ins]})
 return {'scope':'kernel __TEXT_EXEC ADRP page + matching immediate in next16 instructions; candidate windows, not exhaustive semantic xrefs or writer census','segment_address':hex(base),'segment_size_bytes':len(raw),'segment_sha256':hashlib.sha256(raw).hexdigest(),'candidates':rows}
def build():
 im=Image();k=im.k;fs=[k.function(a)for a in FUNCTIONS];symbols=k.symbols(FUNCTIONS)
 for f in fs:f['exact_symbols']=symbols[f['start']]
 e=next(e for e in k.entries if e['name']=='com.apple.security.sandbox');starts=entry_starts(k,e);assert len(starts)==977;sf=[sandbox_function(k,starts,a)for a in(0xfffffe000b7a5978,0xfffffe000b7906d4,0xfffffe000b7904e0,0xfffffe000b790454,0xfffffe000b79045c)];syms=k.symbols([int(f['start'],16)for f in sf])
 for f in sf:f['exact_symbols']=syms[f['start']]
 table=[im.pointer(0xfffffe0008a79de0+8*j)for j in range(3)]
 for p in table:p['exact_symbols']=syms[p['target']]
 a=0xfffffe000b7e42f0;raw=k.read(a,16);ins=list(k.cs.disasm(raw,a));assert[i.mnemonic for i in ins]==['adrp','add','ldr','braa'];cell=int(ins[0].op_str.split('#')[1],16)+int(ins[1].op_str.split('#')[1],16);binding=im.pointer(cell)
 classes=[]
 for a in(0xfffffe0007e56d58,0xfffffe0007e56dd8,0xfffffe0007e56e18,0xfffffe0007e56e58,0xfffffe0008a7dde8):
  name=im.pointer(a+16);sig=im.pointer(a+32);classes.append({'address':hex(a),'bytes64_hex':k.read(a,64).hex(),'name_pointer':name,'name':k.read(int(name['target'],16),128).split(b'\0')[0].decode(),'signature_pointer':sig,'signature':k.read(int(sig['target'],16),128).split(b'\0')[0].decode(),'word44':int.from_bytes(k.read(a+44,4),'little')})
 sub=next(t for t in im.subsystems()if t['start']<=2865<t['end']);routines=[r for r in sub['routines']if r['id']in(2865,2866,2872)]
 free_a=0xfffffe000b7e41c0;free_raw=k.read(free_a,16);free_ins=list(k.cs.disasm(free_raw,free_a));assert[i.mnemonic for i in free_ins]==['adrp','add','ldr','braa'];free_cell=int(free_ins[0].op_str.split('#')[1],16)+int(free_ins[1].op_str.split('#')[1],16);free_binding=im.pointer(free_cell);free_binding['exact_symbols']=k.symbols([int(free_binding['target'],16)])[free_binding['target']]
 callee_symbols=k.symbols([0xfffffe000bcfeb8c,0xfffffe000bcff010,0xfffffe000bd04124,0xfffffe000bd054f8])
 return {'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in('kernel_native_reader.py','kernel_vm_mig_tools.py','resolve_kernel_collection_interfaces.py','iokit_structure_arguments_source.json','iokit_connection_lifecycle_source.json','kernel_iokit_open_source.json','xnu_namespace_reference_osfmk_kern_kalloc.h.txt','kernel_namespace_references.json','zut_xnu_reference.json')},'kernel_sha256':k.sha256,'kernel_UUID':k.kernel['uuid'],'kernel_functions':fs,'sandbox_UUID':e['uuid'],'sandbox_function_start_count':len(starts),'sandbox_functions':sf,'callbacks':table,'sandbox_registration_stub':{'address':'0xfffffe000b7e42f0','bytes16_hex':raw.hex(),'binding':binding},'sandbox_free_stub':{'address':hex(free_a),'bytes16_hex':free_raw.hex(),'binding':free_binding},'allocator_classes':classes,'MIG_routines':routines,'allocator_and_lock_symbols':callee_symbols,'root_slot':{'address':'0xfffffe0007f50528','bytes8_hex':k.read(0xfffffe0007f50528,8).hex(),'is_chained_pointer':im.offset(0xfffffe0007f50528)in im.meta},'root_candidates':root_candidates(k),**{f:False for f in FLAGS}}
if __name__=='__main__':
 s=build();(ROOT/(P+'_source.json')).write_text(json.dumps(s,indent=2)+'\n');print(json.dumps({'kernel_functions':len(s['kernel_functions']),'sandbox_functions':len(s['sandbox_functions']),'instructions':sum(len(f['instructions'])for f in s['kernel_functions']+s['sandbox_functions']),'candidate_windows':len(s['root_candidates']['candidates'])}),flush=True)
