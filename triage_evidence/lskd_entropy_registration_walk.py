#!/usr/bin/env python3
"""Source-only PAC-token propagation from corecrypto table to kernel callback cells.

Tokens record raw symbol and modifier; they are not signed pointer bits. No
PAC/entropy/native registration executes. Normal startup/prehelper return and
successful authentication are explicit composition premises. O(I) time/space.
"""
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_REG,ARM64_OP_IMM

def walk(c):
 F=0x51000000;TABLE=F+0x20;CTX=0xfffffe000cdf0670;memory={};stores=[];auth=[];calls=[];visits=[]
 def phase(row,a,z,seeds):
  registers=dict(seeds);cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;raw=bytes.fromhex(row['bytes_hex']);start=int(row['start'],16)
  def get(i,o):return registers[i.reg_name(o.reg)]if o.type==ARM64_OP_REG else o.imm if o.type==ARM64_OP_IMM else None
  for i in cs.disasm(raw[a-start:z-start],a):
   m=i.mnemonic;o=i.operands;visits.append({'pc':hex(i.address),'bytes_hex':bytes(i.bytes).hex()})
   if m=='bl':calls.append({'pc':hex(i.address),'target':hex(o[0].imm&((1<<64)-1)),'X0':hex(registers['x0']),'X1':hex(registers['x1'])});continue
   if m=='cbz':assert get(i,o[0])!=0;continue
   if m=='str':
    at=registers[i.reg_name(o[1].mem.base)]+o[1].mem.disp;val=get(i,o[0]);memory[at]=val;stores.append({'pc':hex(i.address),'address':hex(at),'token':val});continue
   if m=='ldr':
    base=i.reg_name(o[1].mem.base);at=registers[base]+o[1].mem.disp;registers[i.reg_name(o[0].reg)]=memory[at]
    if i.writeback:registers[base]=at
    continue
   dest=i.reg_name(o[0].reg)
   if m in['adrp','mov']:registers[dest]=get(i,o[1])
   elif m=='add':registers[dest]=get(i,o[1])+get(i,o[2])
   elif m=='movk':
    shift=o[1].shift.value;registers[dest]=(registers[dest]&~(0xffff<<shift))|(o[1].imm<<shift)
   elif m=='pacia':
    value=registers[dest];modifier=get(i,o[1]);assert isinstance(value,int);registers[dest]={'raw_function':hex(value),'modifier64':hex(modifier)};auth.append({'pc':hex(i.address),'operation':'abstract_sign_token','raw_function':hex(value),'modifier64':hex(modifier)})
   elif m=='autia':
    value=registers[dest];modifier=get(i,o[1]);assert isinstance(value,dict)and value['modifier64']==hex(modifier);registers[dest]=int(value['raw_function'],16);auth.append({'pc':hex(i.address),'operation':'abstract_authenticate_token','raw_function':value['raw_function'],'modifier64':hex(modifier)})
   else:raise AssertionError((hex(i.address),m,i.op_str))
   if isinstance(registers[dest],int):registers[dest]&=(1<<64)-1
  return registers
 ctor=next(s for s in c['external_source_spans']if s['label']=='corecrypto_callback_construction');reg=next(s for s in c['external_source_spans']if s['label']=='kernel_prng_registration')
 phase(ctor,0xfffffe000baf4a30,0xfffffe000baf4ae8,{'sp':F});assert len(calls)==1 and calls[0]['X0']==hex(CTX)and calls[0]['X1']==hex(TABLE)
 # Original entry MOV X19,X1 / MOV X20,X0 precedes the returning prehelper.
 assert bytes.fromhex(reg['bytes_hex'])[0x18:0x20].hex()=='f30301aaf40300aa'
 phase(reg,0xfffffe000c6393f4,0xfffffe000c63951c,{'x19':TABLE,'x20':CTX})
 ctorstores=stores[:6];published=stores[6:];assert len(ctorstores)==6 and len(published)==7 and len(auth)==18
 for row,packed,stored in zip(c['source_callback_catalog'],ctorstores,published[1:]):
  off=row['source_table_offset_bytes'];div=int(row['PAC_diversity16'],16);cell=int(row['global_callback_cell'],16);assert int(packed['address'],16)==TABLE+off and packed['pc']==row['startup_store_PC']and stored['pc']==row['registration_store_PC']and int(stored['address'],16)==cell
  assert packed['token']=={'raw_function':row['raw_function'],'modifier64':hex(((TABLE+off)&((1<<48)-1))|(div<<48))}and stored['token']=={'raw_function':row['raw_function'],'modifier64':hex((cell&((1<<48)-1))|(div<<48))}
 assert published[0]['address']=='0xfffffe000cb88f48'and published[0]['token']==CTX
 return {'scope':__doc__,'declared_source_frame':hex(F),'source_table':hex(TABLE),'source_context':hex(CTX),'source_visits':visits,'constructor_stores':ctorstores,'registry_publications':published,'PAC_token_events':auth,'source_registration_call':calls[0],'native_registration_executed':False,'native_PAC_executed':False,'runtime_backend_observed':False}
