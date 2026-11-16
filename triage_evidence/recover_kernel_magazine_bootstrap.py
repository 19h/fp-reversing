#!/usr/bin/env python3
"""Pinned capacity policy, magazine-zone producer and cache installation.
O(collection bytes + scanned words + source + fixups) time/space; read-only.
The bounded ADRP locator is an encoding-domain inventory, not all references.
"""
import json,struct
from hashlib import sha256
from capstone.arm64 import ARM64_OP_MEM
from kext_port_tools import ROOT,SOURCE
from kernel_vm_mig_tools import Image
from verify_daemon_reader_record_payloads_publication import read,sha
P='kernel_magazine_bootstrap';POLICY=0xfffffe000c631f9c;BOOT=0xfffffe000c6324a0
CREATE=0xfffffe000bd772b4;CACHEINIT=0xfffffe000bd77bb0;PARSER=0xfffffe000c5e48a4
NUMBER=0xfffffe000c5e4d20;PREDICATE=0xfffffe000c5e4f50
CAP=0xfffffe0007e6a248;COUNT=0xfffffe0007e66f38;VIEW=0xfffffe0007e66f58
ARRAY=0xfffffe000caeb480;MAGZONE=ARRAY+192*40
FUNCTIONS=[POLICY,BOOT,CREATE,CACHEINIT,PARSER,NUMBER,PREDICATE]
SPANS={
 'cpu_count':(0xfffffe000c631fb8,0xfffffe000c631fcc),
 'presence_request':(0xfffffe000c631fcc,0xfffffe000c631ff0),
 'presence_gate':(0xfffffe000c631ff0,0xfffffe000c631ff8),
 'cpu_threshold':(0xfffffe000c6320e4,0xfffffe000c6320ec),
 'capacity14':(0xfffffe000c6320ec,0xfffffe000c6320f8),
 'feature_gate':(0xfffffe000c63218c,0xfffffe000c632198),
 'capacity10':(0xfffffe000c632198,0xfffffe000c6321a8),
 'view_request':(0xfffffe000c6325ec,0xfffffe000c63261c),
 'view_publish':(0xfffffe000c63261c,0xfffffe000c632630),
 'view_lower':(0xfffffe000c632630,0xfffffe000c632640),
 'view_upper':(0xfffffe000c632640,0xfffffe000c632650),
 'view_indirect':(0xfffffe000c632650,0xfffffe000c632654),
 'minimum_floor':(0xfffffe000c632654,0xfffffe000c632660),
 'create_size_gate':(0xfffffe000bd772d8,0xfffffe000bd772e0),
 'dynamic_id':(0xfffffe000bd77380,0xfffffe000bd77398),
 'extent_store':(0xfffffe000bd77590,0xfffffe000bd77598),
 'view_self':(0xfffffe000bd77708,0xfffffe000bd7770c),
 'cache_bound':(0xfffffe000bd77bcc,0xfffffe000bd77bfc),
 'cache_request':(0xfffffe000bd77bfc,0xfffffe000bd77c10),
 'current_magazine':(0xfffffe000bd77c40,0xfffffe000bd77c58),
 'spare_magazine':(0xfffffe000bd77c58,0xfffffe000bd77c70)}
SCOPE='Original CPU-count/capacity policy prefix with original boot-token/numeric parser; original dynamic magazine-zone creation/publication and cache installation under explicit bootstrap/storage/lock/PAC premises. Source-produced policy outputs transfer between declared new-call epochs. Native boot order, storage ownership, allocation effects, authentication/exclusion and daemon transaction identity remain unknown.'
FALSE=['native_target_executed','IDB_modified','native_boot_order_established','native_allocation_effects_established',
 'native_ownership_established','native_PAC_authenticated','native_synchronization_established',
 'daemon_kext_transaction_correlated','new_Mach_port_endpoint_established','full_goal_complete']

def build():
 im=Image();k=im.k;k.cs.detail=True;functions=[k.function(a) for a in FUNCTIONS]
 prior=json.loads(read(ROOT/'kernel_zone_startup_source.json'))
 for f in functions[2:4]:assert any(all(old.get(key)==f[key] for key in f) for old in prior['functions'])
 spans=[]
 for label,(a,b) in SPANS.items():
  raw=k.read(a,b-a);ii=list(k.cs.disasm(raw,a));assert len(ii)*4==len(raw)
  spans.append({'label':label,'start':hex(a),'end_exclusive':hex(b),'bytes_hex':raw.hex(),
   'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ii]})
 sections=json.loads(read(ROOT/'kernel_zone_prefill_callers_checks.json'))['direct_branch_scan']['sections']
 refs=[];branches=[];words=0
 for sec in sections:
  a=int(sec['address'],16);raw=k.read(a,sec['bytes_scanned']);assert sha256(raw).hexdigest()==sec['sha256'];words+=len(raw)//4
  for j,(w,) in enumerate(struct.iter_unpack('<I',raw)):
   pc=a+4*j
   if w&0x7c000000==0x14000000:
    delta=w&0x3ffffff;delta-=((delta>>25)&1)<<26;target=(pc+4*delta)&((1<<64)-1)
    if target in [POLICY,BOOT]:branches.append({'entry':sec['entry'],'pc':hex(pc),'target':hex(target),'bytes_hex':raw[j*4:j*4+4].hex()})
   if w&0x9f000000!=0x90000000:continue
   imm=(((w>>5)&0x7ffff)<<2)|((w>>29)&3);imm-=((imm>>20)&1)<<21;page=((pc&~4095)+(imm<<12))&((1<<64)-1)
   if page not in [CAP&~4095,VIEW&~4095]:continue
   ii=list(k.cs.disasm(raw[j*4:min(len(raw),j*4+16)],pc));reg=ii[0].operands[0].reg
   for i in ii[1:]:
    hits=[o for o in i.operands if o.type==ARM64_OP_MEM and o.mem.base==reg and not o.mem.index and page+o.mem.disp in [CAP,VIEW]]
    for o in hits:refs.append({'entry':sec['entry'],'page_PC':hex(pc),'pc':hex(i.address),'address':hex(page+o.mem.disp),
     'instruction':i.mnemonic+' '+i.op_str,'bytes_hex':i.bytes.hex()})
    aliases={i.reg_name(reg),'w'+i.reg_name(reg)[1:]}
    if any(i.reg_name(r) in aliases for r in i.regs_access()[1]) or i.mnemonic in ['b','bl','br','blr','ret','retab'] or i.mnemonic.startswith('b.') or i.mnemonic in ['cbz','cbnz','tbz','tbnz']:break
 callbacks=[]
 for off,row in im.meta.items():
  if int(row['target'],16) not in [POLICY,BOOT]:continue
  sg=next(s for s in k.root['segments'] if s['file_offset']<=off<s['file_offset']+s['file_size']);slot=sg['address']+off-sg['file_offset']
  callbacks.append({'pointer':im.pointer(slot),'preceding8_hex':k.read(slot-8,8).hex(),'following8_hex':k.read(slot+8,8).hex()})
 globals=[{'address':hex(a),'size_bytes':n,'file_bytes_hex':k.read(a,n).hex()} for a,n in [(CAP,2),(COUNT,4),(VIEW,8),(0xfffffe0007ef8bf0,4),(0xfffffe000cb29cb4,4)]]
 return {'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'scope':SCOPE,
  'dependencies':{n:sha(ROOT/n) for n in ['kernel_native_reader.py','kernel_vm_mig_tools.py','kernel_zone_startup_source.json',
    'kernel_zone_startup_profiles.json','kernel_zone_prefill_callers_checks.json','probe_kernel_vm_mig.py','replay_kernel_vm_mig.py','audit_kernel_retirement_magazines.py','kernel_zone_bitmap_release_audit.json']},
  'functions':functions,'spans':spans,'reused_caller_spans':[],'exact_symbols':k.symbols([*FUNCTIONS,CAP,COUNT,VIEW]),
  'globals':globals,'strings':[{'address':hex(a),'bytes_hex':k.read(a,96).split(bytes(1))[0].hex()} for a in [0xfffffe0007053327,0xfffffe000705354e]],
  'bounded_ADRP_references':refs,'startup_callback_pointer_candidates':callbacks,'direct_boot_branches':branches,
  'verified_counts':{'captured_functions':len(functions),'captured_instructions':sum(len(f['instructions']) for f in functions),
   'captured_bytes':sum(len(bytes.fromhex(f['bytes'])) for f in functions),'matched_prior_functions':2,'source_blocks':len(spans),
   'block_instructions':sum(len(s['instructions']) for s in spans),'sections_rehashed':len(sections),'aligned_words_scanned':words,
   'bounded_ADRP_references':len(refs),'startup_callback_pointer_candidates':len(callbacks),'direct_boot_branches':len(branches)},
  'conditional_kernel_magazine_bootstrap_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
