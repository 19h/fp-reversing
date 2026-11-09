#!/usr/bin/env python3
"""Core initializer pointers, typed view, source scratch loop and numeric guard.

O(B+I+256R) time, O(B+I) space. Frame-pointer pairs are source-local stores;
their persistence is checked separately by byte epochs. No target executes.
"""
import hashlib,json,struct,bisect
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_REG,ARM64_OP_IMM,ARM64_OP_MEM
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE,selected,qword
from recover_carrier_control import span
from recover_kext_cold_init import pointer
from recover_kext_aes_handoff import starts
T=0xfffffe000846c420;P=0xfffffe00084716e0
SPANS=[('post_allocator_initializer',0xfffffe000a5304c8,0xfffffe000a530ac4),('ordering_helper',0xfffffe000a561058,0xfffffe000a56106c),('source_scratch_clear',0xfffffe000a56d11c,0xfffffe000a56d14c),('source_input_guard',0xfffffe000a594c70,0xfffffe000a594d18)]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def pointer_pairs(k):
 cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;ins=list(cs.disasm(k.read(0xfffffe000a530634,0x48c),0xfffffe000a530634));rows=[]
 for a,b in zip(ins,ins[1:]):
  if a.mnemonic!='add'or b.mnemonic!='str'or len(a.operands)!=3 or a.operands[2].type!=ARM64_OP_IMM or b.operands[1].type!=ARM64_OP_MEM:continue
  dest=a.reg_name(a.operands[0].reg);base=a.reg_name(a.operands[1].reg);m=b.operands[1].mem
  if base not in['x23','x24']or b.reg_name(b.operands[0].reg)!=dest or b.reg_name(m.base)!='sp'or m.index:continue
  rows.append({'add_PC':hex(a.address),'store_PC':hex(b.address),'bytes_hex':(bytes(a.bytes)+bytes(b.bytes)).hex(),'region':'workspace'if base=='x23'else'typed_auxiliary','base_register':base,'region_offset_bytes':a.operands[2].imm<<a.operands[2].shift.value,'frame_SP_offset_bytes':m.disp,'size_bytes':8})
 return rows
def main():
 k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');cat=starts(k,e);ss=[]
 for label,a,z in SPANS:
  s=span(k,a,z);assert IMAGE.read(a,z-a).hex()==s['bytes_hex'];j=bisect.bisect_right(cat,a)-1;assert z<=cat[j+1];s.update(label=label,compiler_start=hex(cat[j]),compiler_end=hex(cat[j+1]));ss.append(s)
 rules=[]
 specs=[('typed_allocator',qword(P+0x150)-4,qword(P+0x2c0),0x8d,0x99d,T,0,0xfffffe000c4ba154),('typed_view',qword(P+0x308),qword(P+0x420),0x50,-0x21,P,-12,0xfffffe000847ae20),('workspace_ordering',qword(P+0x4f0)-12,qword(P+0x600)-8,0x58,0x92b,T,0,0xfffffe000a561058),('typed_ordering',qword(P+0x2f8)-4,qword(P+0x630)-12,0xbb,0x8d3,T,0,0xfffffe000a561058)]
 for name,l,r,key,add,base,bias,target in specs:
  b=selected(l,r,key,add,base=base,bias=bias);assert int(b['target'],16)==target;b.update(label=name,base=hex(base),left256_hex=IMAGE.read(l,256).hex(),right256_hex=IMAGE.read(r,256).hex(),original_pointer=pointer(k,int(b['slot'],16)));rules.append(b)
 view=0xfffffe000847ae20;vp=[pointer(k,view+off)for off in[16,32]];name=k.read(int(vp[0]['target'],16),64).split(b'\0',1)[0].decode();flags,size=struct.unpack('<II',k.read(view+40,8));assert name=='site.AllocType'and flags==0xe4 and size==4096
 slots=[pointer(k,T+ix*8)for ix in[0x4cd,0x4d2,0x4bb,0x76a]]
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['kernel_native_reader.py','kext_port_tools.py','recover_carrier_control.py','recover_kext_cold_init.py','recover_kext_aes_handoff.py']},'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'spans':ss,'bank_rules':rules,'frame_pointer_pairs':pointer_pairs(k),'typed_view':{'address':hex(view),'original64_hex':k.read(view,64).hex(),'normalized64_hex':IMAGE.read(view,64).hex(),'name':name,'original_pointer_fields':vp,'flags32':hex(flags),'size32_bytes':size,'native_runtime_links_known':False},'native_typed_allocator':k.function(0xfffffe000c4ba154),'native_type_delegate':k.function(0xfffffe000bcfeb8c),'dispatch_slots':slots,'scratch':{'frame_SP_offset_bytes':0xf68,'size_bytes':0x448,'exclusive_end_SP_offset_bytes':0x13b0,'stack_guard_SP_offset_bytes':0x13b0},'numeric_guard':{'pointer_nonzero':True,'u32_length_min_bytes':16,'u32_length_max_bytes_inclusive':65536,'accepted_index32':'0x76a','rejected_index32':'0x4bb','accepted_target':'0xfffffe000a56d1b4','rejected_target':'0xfffffe000a58c0bc','input_content_validated':False},'exact_symbols':k.symbols([0xfffffe000c4ba154,0xfffffe000c4b9a08,0xfffffe000a561058,0xfffffe000bcfeb8c]),'native_target_executed':False,'model_memory_writes':0,'full_goal_complete':False};(ROOT/'lskd_core_workspace_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'source_windows':len(ss),'pointer_pairs':len(out['frame_pointer_pairs']),'bank_rules':len(rules),'typed_bytes':size}),flush=True)
if __name__=='__main__':main()
