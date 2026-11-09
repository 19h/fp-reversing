#!/usr/bin/env python3
"""Recover copyin policy initial data, startup binding and bounded direct refs.
Scan is O(instruction words+ADRP candidates*32), memory O(candidates+captures).
Direct-reference coverage is syntactic and excludes arbitrary indirect aliases.
"""
import json,struct
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_MEM,ARM64_OP_REG,ARM64_OP_IMM
from daemon_receive_tools import ROOT
from kernel_vm_mig_tools import Image
from capture_daemon_record720 import sha
G=0xfffffe0007e6a01c;MASK=(1<<64)-1
FUNCTIONS=[0xfffffe000bdd15a4,0xfffffe000bdc6bc8,0xfffffe000bd7e9c4,0xfffffe000c6306e0,0xfffffe000c5e48a4,0xfffffe000bc9dbf0,0xfffffe000bc9db70,0xfffffe000c5e4d20,0xfffffe000c5e4ca8,0xfffffe000c5e4f50]
def scan(k):
 cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;seen=set();sections=[];candidates=[];words=0
 for entry in k.entries:
  for s in entry['sections']:
   key=(s['address'],s['size'])
   if key in seen or not s['flags']&0x80000400:continue
   seen.add(key);raw=k.read(s['address'],s['size']&~3);words+=len(raw)//4;sections.append({'entry':entry['name'],'segment':s['segment'],'section':s['section'],'address':hex(s['address']),'size_bytes':len(raw)})
   for j,(w,)in enumerate(struct.iter_unpack('<I',raw)):
    if w&0x9f000000!=0x90000000:continue
    a=s['address']+4*j;imm=(((w>>5)&0x7ffff)<<2)|((w>>29)&3);imm-=((imm>>20)&1)<<21
    if((a&~4095)+(imm<<12))&MASK==G&~4095:candidates.append(a)
 def reg(i,r):return i.reg_name(r).replace('w','x',1)
 refs=[]
 for a in candidates:
  known={};events=[];path=[]
  for i in cs.disasm(k.read(a,128),a):
   path.append({'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str,'bytes_hex':i.bytes.hex()});ops=i.operands;new={}
   for o in ops:
    if o.type!=ARM64_OP_MEM or o.mem.index or reg(i,o.mem.base)not in known:continue
    ea=(known[reg(i,o.mem.base)]+o.mem.disp)&MASK;name=i.reg_name(ops[0].reg)if ops[0].type==ARM64_OP_REG else'';width={'w':4,'x':8,'q':16,'d':8,'s':4,'h':2,'b':1}.get(name[:1],0)
    if i.mnemonic.endswith('b'):width=1
    elif i.mnemonic.endswith('h'):width=2
    elif i.mnemonic=='ldrsw':width=4
    if i.mnemonic in ['ldp','stp','ldpsw']:width*=2
    if width and ea<G+4 and G<ea+width:events.append({'kind':'memory','pc':hex(i.address),'address':hex(ea),'width_bytes':width,'operation':'write'if i.mnemonic.startswith('st')else'read','mnemonic':i.mnemonic,'operands':i.op_str})
   if i.mnemonic=='adrp':new[reg(i,ops[0].reg)]=ops[1].imm&MASK
   elif i.mnemonic=='add'and len(ops)==3 and ops[1].type==ARM64_OP_REG and ops[2].type==ARM64_OP_IMM and reg(i,ops[1].reg)in known:
    limit=0xffffffff if i.reg_name(ops[0].reg).startswith('w')else MASK;new[reg(i,ops[0].reg)]=((known[reg(i,ops[1].reg)]&limit)+(ops[2].imm<<ops[2].shift.value))&limit
   for r in i.regs_access()[1]:known.pop(reg(i,r),None)
   known.update(new)
   if G in new.values():events.append({'kind':'address_materialization','pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str})
   if i.mnemonic in ['b','bl','blr','ret','retab','br','braa','blraa','cbz','cbnz','tbz','tbnz']or i.mnemonic.startswith('b.'):break
  if events:refs.append({'ADRP':hex(a),'events':events,'bounded_path':path})
 return {'instruction_sections':sections,'instruction_words':words,'ADRP_page_candidates':len(candidates),'maximum_following_instructions':32,'references':refs,'indirect_aliases_excluded':True,'native_reachability_established':False}
def recover():
 im=Image();k=im.k;functions=[k.function(a)for a in FUNCTIONS];assert int.from_bytes(k.read(G,4),'little')==2
 pointers=[im.pointer(a)for a in [0xfffffe000ca881c0,0xfffffe000ca881c8,0xfffffe000cbec950,0xfffffe000cbec958]];assert[int(p['target'],16)for p in pointers]==[0xfffffe000ca881a0,G,0xfffffe000c6306e0,0xfffffe000ca881c0]
 name=b'vm_map_cow_defeatured_enforce\0';assert k.read(0xfffffe000ca881a0,len(name))==name
 section=next(s for s in k.kernel['sections']if s['address']<=G<s['address']+s['size'])
 return {'scope':__doc__,'generator_sha256':sha(__file__),'dependencies':{n:sha(ROOT/n)for n in ['kernel_vm_mig_tools.py','kernel_native_reader.py','rpc502_reply_copyin_source.json','xnu_osfmk_vm_vm_map.c','kext_port_vm_public_sources.json']},'kernel_sha256':k.sha256,'functions':functions,'policy_cell':{'address':hex(G),'initial_u32':2,'bytes_hex':k.read(G,4).hex(),'section':section,'file_value_is_not_native_runtime_attestation':True},'exact_symbols':k.symbols([G,0xfffffe0007f8b0a0,0xfffffe000bc9dbf0,0xfffffe000bc9db70]),'environment_file_bytes':{hex(a):k.read(a,n).hex()for a,n in [(0xfffffe0007f8b5f0,4),(0xfffffe0007f8b0a0,8)]},'retained_public_reference_contains_parameter':b'vm_map_cow_defeatured_enforce'in(ROOT/'xnu_osfmk_vm_vm_map.c').read_bytes(),'startup':{'parameter_name':'vm_map_cow_defeatured_enforce','argument_record':'0xfffffe000ca881c0','argument_bytes_hex':k.read(0xfffffe000ca881c0,24).hex(),'startup_record':'0xfffffe000cbec948','startup_bytes_hex':k.read(0xfffffe000cbec948,24).hex(),'extent_bytes':4,'flags20':k.read(0xfffffe000ca881d4,1).hex(),'flags21':k.read(0xfffffe000ca881d5,1).hex(),'original_fixups':pointers},'direct_references':scan(k),'native_target_executed':False,'full_goal_complete':False}
if __name__=='__main__':
 r=recover();(ROOT/'kernel_copyin_policy_source.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'functions':len(r['functions']),'instructions':sum(len(f['instructions'])for f in r['functions']),'words_scanned':r['direct_references']['instruction_words'],'page_candidates':r['direct_references']['ADRP_page_candidates'],'direct_ref_groups':len(r['direct_references']['references'])}))
