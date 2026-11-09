#!/usr/bin/env python3
"""Source-frame dispatch contexts and core -> cleanup adapter record evidence.

Partial source lineages, not full reaching-definition/native execution proof.
O(B+I+R*256+selected-chain work), with bounded source/evidence space.
"""
import bisect,hashlib,json,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN,arm64_const as ca
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,POOL,TABLE,qword,selected
from kernel_native_reader import Kernel
from recover_kext_aes_handoff import starts,function
from recover_kext_cold_init import pointer
from resolve_kernel_collection_interfaces import commands
FAMILIES={'A':(0xfffffe0007949dd0,0xfffffe000792fbc0),'B':(0xfffffe0007949fd0,0xfffffe000792ffc0),'C':(0xfffffe0007949ed0,0xfffffe000792fec0),'D':(0xfffffe000792fcc0,0xfffffe00079391f0),'E':(0xfffffe0007941f60,0xfffffe000794a0d0)}
# Values are source-derived contexts. Slice runs explicitly declare them;
# aliases, mutable state, original predecessor reachability remain unproved.
CONTEXTS=[('core',0xfffffe000a606728,'B',0xac,0x2d,0xfffffe000a606904),('cleanup',0xfffffe000a62259c,'B',0xac,0x2d,0xfffffe000a62275c),('small',0xfffffe000a68223c,'A',0x5c,-0x9f,0xfffffe000a68240c),('large',0xfffffe000a6890dc,'A',0xb4,-0x3b,0xfffffe000a6892cc),('record',0xfffffe000a623314,'E',5,6,0xfffffe000a623508),('status',0xfffffe000a6247a4,'A',0x73,-0x14,0xfffffe000a624994),('record2',0xfffffe000a686620,'C',0x32,-0xc6,0xfffffe000a686818),('options',0xfffffe000a686a30,'D',0x47,-0x48,0xfffffe000a686bec)]
# (context, start, call, input W register, bank family, key, additive,
#  table register, explicit register seeds, saved frame qwords)
SITES=[('core',0xfffffe000a60db18,0xfffffe000a60db50,8,'E',0x98,0xed5,13,{}, {0x160:'L',0x168:'R'}),('cleanup',0xfffffe000a622784,0xfffffe000a6227b4,8,'C',0x32,0xe88,27,{24:POOL},{}),('small',0xfffffe000a68259c,0xfffffe000a6825d0,8,'A',0x73,0xf2f,27,{}, {0x10:'L',8:'R'}),('large',0xfffffe000a6968bc,0xfffffe000a6968f4,8,'B',0xac,0xf65,25,{}, {0x3a0:'L',0x398:'R',0x3b8:'O'}),('large',0xfffffe000a698124,0xfffffe000a698168,9,'A',0x5c,0xe99,26,{17:'R'},{0x428:'L'}),('large',0xfffffe000a698220,0xfffffe000a698258,8,'D',0x87,0xe8c,26,{}, {0x370:'L',0x378:'R',0x440:'T'}),('core',0xfffffe000a608074,0xfffffe000a6080ac,8,'D',0x87,0xeb8,13,{}, {0x1b0:'L',0x1b8:'R'}),('record',0xfffffe000a623644,0xfffffe000a623680,8,'A',0x5c,0xec3,28,{},{}),('status',0xfffffe000a6257a0,0xfffffe000a6257e8,9,'C',0x32,0xeaf,26,{}, {0x38:'L',0x40:'R'}),('record2',0xfffffe000a6869bc,0xfffffe000a6869f0,8,'A',0xb4,0xf27,28,{}, {0x10:'L',8:'R'}),('options',0xfffffe000a686c18,0xfffffe000a686c44,8,'A',0x73,0xf59,26,{27:'L',28:'R'},{})]
SPANS=[(0xfffffe000a606728,0xfffffe000a606e2c),(0xfffffe000a60802c,0xfffffe000a6080b4),(0xfffffe000a60daec,0xfffffe000a60db54),(0xfffffe000a62259c,0xfffffe000a6227b8),(0xfffffe000a68223c,0xfffffe000a6825d4),(0xfffffe000a6890dc,0xfffffe000a689860),(0xfffffe000a69688c,0xfffffe000a696904),(0xfffffe000a697fa4,0xfffffe000a698178),(0xfffffe000a6981e0,0xfffffe000a698260),(0xfffffe000a623314,0xfffffe000a623684),(0xfffffe000a6247a4,0xfffffe000a624bd0),(0xfffffe000a625778,0xfffffe000a6257ec),(0xfffffe000a686620,0xfffffe000a6869f4),(0xfffffe000a686a30,0xfffffe000a686c48)]
LINEAGES=[('core SP+160',0xc08,-8,0xfffffe000a6069b4,0xfffffe000a6069bc),('core SP+168',0x158,-4,0xfffffe000a6069d0,0xfffffe000a6069d8),('core SP+1b0',0x458,-8,0xfffffe000a606ae0,0xfffffe000a606ae8),('core SP+1b8',0x638,-12,0xfffffe000a606af8,0xfffffe000a606b00),('large SP+3a0',0x4f0,-4,0xfffffe000a6895a4,0xfffffe000a6895b0),('large SP+398',0x578,-4,0xfffffe000a6895b0,0xfffffe000a6895bc),('large SP+428',0x840,0,0xfffffe000a689444,0xfffffe000a68944c),('large SP+418',0xbb8,0,0xfffffe000a68945c,0xfffffe000a689460),('large SP+370',0x458,-8,0xfffffe000a689574,0xfffffe000a689580),('large SP+378',0x638,-12,0xfffffe000a689580,0xfffffe000a68958c),('small SP+10',0x840,0,0xfffffe000a6823a8,0xfffffe000a6823b0),('small SP+8',0xbb8,0,0xfffffe000a6823bc,0xfffffe000a6823c4),('status SP+38',0xb70,0,0xfffffe000a624ba8,0xfffffe000a624bb0),('status SP+40',0xa10,0,0xfffffe000a624bc0,0xfffffe000a624bc8),('record2 SP+10',0x840,0,0xfffffe000a6867a0,0xfffffe000a6867a8),('record2 SP+8',0xbb8,0,0xfffffe000a6867b8,0xfffffe000a6867c0),('options X27',0x840,0,0xfffffe000a686b80,0xfffffe000a686b84),('options X28',0xbb8,0,0xfffffe000a686b90,0xfffffe000a686b94)]
TRACK={'core':[0x160,0x168,0x1b0,0x1b8],'large':[0x398,0x3a0,0x418,0x428,0x370,0x378,0x440],'small':[8,0x10],'status':[0x38,0x40],'record2':[8,0x10]}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def span(a,z):
 raw=IMAGE.read(a,z-a);ins=list(CS.disasm(raw,a));assert len(ins)*4==len(raw);return {'start':hex(a),'end':hex(z),'bytes_hex':raw.hex(),'sha256':hashlib.sha256(raw).hexdigest(),'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}for i in ins]}
def census(a,z,offsets):
 cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;rows=[];indexed=[]
 for i in cs.disasm(IMAGE.read(a,z-a),a):
  if i.mnemonic not in['str','strb','strh','stur','sturb','sturh','stp']:continue
  mem=next((o.mem for o in i.operands if o.type==ca.ARM64_OP_MEM),None)
  if mem is None or mem.base!=ca.ARM64_REG_SP:continue
  if mem.index:indexed.append(hex(i.address));continue
  regs=[o.reg for o in i.operands if o.type==ca.ARM64_OP_REG];width=1 if i.mnemonic.endswith('b')else 2 if i.mnemonic.endswith('h')else 16 if cs.reg_name(regs[0]).startswith('q')else 8 if cs.reg_name(regs[0]).startswith('x')else 4
  for j,r in enumerate(regs):
   off=mem.disp+j*width
   hit=[v for v in offsets if off<v+8 and v<off+width]
   if hit:rows.append({'pc':hex(i.address),'instruction':i.mnemonic+' '+i.op_str,'source_register':cs.reg_name(r),'literal_SP_offset':off,'size_bytes':width,'tracked_qwords':hit,'frame_epoch_or_alias_proved':False})
 return {'scope':'All direct literal-SP store overlaps in the compiler envelope; not reaching definitions, prologue-SP normalization, FP aliases or alias-clobber proof.','writes':rows,'indexed_SP_store_sites':indexed}
def modifier_sites():
 out=[]
 for at,cmd,size in commands(IMAGE.data,0):
  if cmd!=0x19 or IMAGE.data[at+8:at+24].split(b'\0')[0]!=b'__TEXT_EXEC':continue
  va,vm,off,n=struct.unpack_from('<4Q',IMAGE.data,at+24);raw=IMAGE.data[off:off+n]
  for j,(w,)in enumerate(struct.iter_unpack('<I',raw[:len(raw)//4*4])):
   for tag in[0xed6d,0xd939]:
    if w==0xd2800011|(tag<<5):out.append({'modifier_pc':hex(va+j*4),'call_pc':hex(va+j*4+4),'diversity':hex(tag),'bytes8_hex':raw[j*4:j*4+8].hex()})
 return out
def main():
 k=Kernel();fp=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');catalog=starts(k,fp);contexts=[]
 for name,a,fam,key,add,pc in CONTEXTS:
  ix=catalog.index(a);z=catalog[ix+1];base=selected(*FAMILIES[fam],key,add,base=POOL,bias=-12);assert int(base['target'],16)==TABLE;contexts.append({'name':name,'compiler_start':hex(a),'compiler_end':hex(z),'compiler_source_sha256':hashlib.sha256(k.read(a,z-a)).hexdigest(),'normalized_source_equal':k.read(a,z-a)==IMAGE.read(a,z-a),'table_base_install':hex(pc),'base_rule':base,'literal_stack_store_census':census(a,z,TRACK.get(name,[]))})
 sites=[]
 for ctx,a,call,reg,fam,key,add,treg,regs,stack in SITES:
  choice=selected(*FAMILIES[fam],key,add);p=pointer(k,int(choice['slot'],16));assert p['target']==choice['target'];sites.append({'context':ctx,'start':hex(a),'call_pc':hex(call),'input_W_register':reg,'family':fam,'key':key,'additive':add,'table_X_register':treg,'extra_register_seeds':{str(n):v for n,v in regs.items()},'stack_qword_seeds':{str(n):v for n,v in stack.items()},'choice':choice,'original_slot':p,'slice':span(a,call+4),'entry_reachability_proved':False})
 addrs=[int(s['choice']['target'],16)for s in sites];symbols=k.symbols(addrs)
 for s in sites:s['exact_target_symbols']=symbols[s['choice']['target']]
 lineages=[{'role':name,'source_pool_slot':hex(POOL+off),'signed_adjustment':adjust,'source_pointer_value':hex((qword(POOL+off)+adjust)&((1<<64)-1)),'source':span(a,z),'preserved_until_call_proved':False}for name,off,adjust,a,z in LINEAGES]
 target_roles=[function(k,fp,a)for a in[0xfffffe000a5a962c,0xfffffe000a6674d0]]
 families={name:{'left':hex(l),'right':hex(r),'left256_hex':IMAGE.read(l,256).hex(),'right256_hex':IMAGE.read(r,256).hex()}for name,(l,r)in FAMILIES.items()};out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'kernel_uuid':k.kernel['uuid'],'compiler_function_starts_count':len(catalog),'dependencies':{n:sha(ROOT/n)for n in['kext_port_tools.py','kernel_native_reader.py','recover_kext_aes_handoff.py','recover_kext_cold_init.py','resolve_kernel_collection_interfaces.py','kext_aes_handoff_contracts.json']},'source_spans':[span(a,z)for a,z in SPANS],'contexts':contexts,'sites':sites,'families':families,'modifier_census':modifier_sites(),'target_roles':target_roles,'literal_bank_pointer_lineages':lineages,'cleanup_record':{'producer_start':'0xfffffe000a60802c','call_pc':'0xfffffe000a6080ac','adapter':'0xfffffe000a62259c','final_cleanup_call':'0xfffffe000a6227b4','final_cleanup':'0xfffffe000a5085e0','record_min_extent_bytes':40,'address_multiplier32':'0x51a7c57b','address_xor32':'0x908154a5','decoded_control_expression':'(caller_W19 + 0x451) mod 2^32','native_reachability_proved':False},'native_target_executed':False,'authentication_executed':False,'all_native_dispatch_contexts_proved':False,'full_goal_complete':False};(ROOT/'kext_aes_dispatch_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'contexts':len(contexts),'sites':len(sites),'source_spans':len(SPANS),'modifier_sites':len(out['modifier_census']),'bank_families':len(families)}),flush=True)
if __name__=='__main__':main()
