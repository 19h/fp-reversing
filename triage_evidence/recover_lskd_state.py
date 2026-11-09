#!/usr/bin/env python3
"""Exact state/load/kill windows, original stop caller and context-cache roots.

O(B+I+S log F+256R) time, O(B+I) space. No target, native lock/API/IPC,
cryptographic operation or IDB mutation executes.
"""
import bisect,hashlib,json
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE,selected
from recover_kext_aes_handoff import starts,function
from recover_kext_cold_init import pointer
from recover_carrier_control import span
from lskd_state_spec import SPANS,ORIGINS

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');catalog=starts(k,e);cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);cs.detail=True;ss=[]
 for row in SPANS:
  a,z=int(row['start'],16),int(row['end'],16);s=span(k,a,z);assert IMAGE.read(a,z-a).hex()==s['bytes_hex'];j=bisect.bisect_right(catalog,a)-1;assert z<=catalog[j+1];s.update(label=row['label'],compiler_start=hex(catalog[j]),compiler_end=hex(catalog[j+1]));ss.append(s)
 origins=[]
 for a,(off,n)in ORIGINS.items():
  i=next(cs.disasm(k.read(a,4),a));r,w=i.regs_access();origins.append({'pc':hex(a),'bytes_hex':k.read(a,4).hex(),'mnemonic':i.mnemonic,'operands':i.op_str,'reads':[i.reg_name(x)for x in r],'writes':[i.reg_name(x)for x in w],'SP_offset_bytes':off,'instruction_read_bytes':n,'unknown_load_bytes':8,'unknown_destination':'x13'})
 a=0xfffffe000a551f64;i=next(cs.disasm(k.read(a,4),a));r,w=i.regs_access();word=int.from_bytes(k.read(a,4),'little');assert(word&0x9f000000)==0x90000000 and word&31==13;imm=((word>>5)&0x7ffff)<<2|((word>>29)&3);imm=imm-(1<<21)if imm&(1<<20)else imm;page=((a&~4095)+(imm<<12))&((1<<64)-1);assert page==0xfffffe000ccc2000
 kill={'pc':hex(a),'bytes_hex':k.read(a,4).hex(),'mnemonic':i.mnemonic,'operands':i.op_str,'reads':[i.reg_name(x)for x in r],'writes':[i.reg_name(x)for x in w],'decoded_destination_register':13,'decoded_page_value64':hex(page),'incoming_register13_value_used':False}
 rules=[]
 for label,l,rr,key,add in[('vault_context_root',0x791d3b0,0x7920e10,0x65,-0x40),('allowed_context_root',0x79172c0,0x7919cb0,0xb5,0x14)]:
  l|=0xfffffe0000000000;rr|=0xfffffe0000000000;b=selected(l,rr,key,add,base=0xfffffe00084716e0);assert b['target']=='0xfffffe000ccc78d0';b.update(label=label,base='0xfffffe00084716e0',left256_hex=IMAGE.read(l,256).hex(),right256_hex=IMAGE.read(rr,256).hex(),original_pointer=pointer(k,int(b['slot'],16)));rules.append(b)
 slots=[pointer(k,0xfffffe000846c420+8*n)for n in[0x3f0,0x3e6,0x28e,0x47b,0x475,0x259]];caller=function(k,e,0xfffffe000a505480);syms=k.symbols([0xfffffe000a505480,0xfffffe000ccc78d0,0xfffffe000a551f64]);assert any(x['name']=='__Z13LSKDKext_stopv'for x in syms['0xfffffe000a505480'])
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['lskd_state_spec.py','kernel_native_reader.py','kext_port_tools.py','recover_kext_aes_handoff.py','recover_kext_cold_init.py','recover_carrier_control.py']},'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'spans':ss,'origins':origins,'kill':kill,'context_cache':{'address':'0xfffffe000ccc78d0','original8_hex':k.read(0xfffffe000ccc78d0,8).hex(),'native_runtime_value_known':False,'native_producer_known':False},'bank_rules':rules,'callback_and_cache_slots':slots,'stop_caller':caller,'exact_symbols':syms,'native_target_executed':False,'native_synchronization_executed':False,'full_goal_complete':False};(ROOT/'lskd_state_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'bounded_spans':len(ss),'origins':len(origins),'source_kill_instructions':1,'context_root_banks':len(rules)}),flush=True)
if __name__=='__main__':main()
