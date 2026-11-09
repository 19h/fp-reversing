#!/usr/bin/env python3
"""Original selector-0x224 append path, exact shared fragments/copy binding.

O(B+I+256R) time/source space. Read-only target sources; no native operation.
"""
import bisect,hashlib,json
from pathlib import Path
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE,selected
from recover_kext_aes_handoff import function,starts
from recover_kext_cold_init import pointer
from recover_carrier_control import span
POOL=0xfffffe00084716e0;TABLE=0xfffffe000846c420
SPANS=[('outer',0xfffffe000a50c2b0,0xfffffe000a50c508),('bridge',0xfffffe000a52fd18,0xfffffe000a5302e4),('operation_entry',0xfffffe000a55e8b0,0xfffffe000a55ea88),('shared_return',0xfffffe000a5355f4,0xfffffe000a535614),('pointer_gate',0xfffffe000a55fba0,0xfffffe000a55fbd8),('header_gate',0xfffffe000a588840,0xfffffe000a588880),('entry_gate',0xfffffe000a54f6c4,0xfffffe000a54f6f8),('byte_gate',0xfffffe000a58ffa4,0xfffffe000a590014),('append_body',0xfffffe000a51a45c,0xfffffe000a51a62c),('copy_wrapper',0xfffffe000a508cf4,0xfffffe000a508cfc),('copy_stub',0xfffffe000a69f334,0xfffffe000a69f344),('payload_symbolic',0xfffffe000a52fea4,0xfffffe000a530104),('tag_symbolic',0xfffffe000a530104,0xfffffe000a5301ac),('header_symbolic',0xfffffe000a51a460,0xfffffe000a51a5b8),('counter_symbolic',0xfffffe000a51a604,0xfffffe000a51a618)]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');catalog=starts(k,e);spans=[];parents=set()
 for label,a,z in SPANS:
  row=span(k,a,z);assert IMAGE.read(a,z-a).hex()==row['bytes_hex'];ix=bisect.bisect_right(catalog,a)-1
  if ix+1<len(catalog):row.update(label=label,compiler_start=hex(catalog[ix]),compiler_end=hex(catalog[ix+1]));assert z<=catalog[ix+1];parents.add(catalog[ix])
  else:row.update(label=label,compiler_start=None,compiler_end=None,compiler_bounds_available=False)
  spans.append(row)
 fs=[function(k,e,a)for a in sorted(parents)];kernel=k.function(0xfffffe000c647f10)
 rules=[]
 for label,l,r,key,add,bias,base in[('entry_stateA',0xfffffe0007920d10,0xfffffe00079173c0,0xbb,-0x9f,-4,POOL),('entry_stateB',0xfffffe00079172c0,0xfffffe0007919cb0,0xb5,-0x4e,0,POOL),('entry_table',0xfffffe000791d3b0,0xfffffe0007920e10,0x3b,-0x3f,-8,POOL),('payload_copy',0xfffffe00079172c0,0xfffffe0007919cb0,0xff,0x93c,0,TABLE)]:
  row=selected(l,r,key,add,base=base,bias=bias);row.update(label=label,base=hex(base),left256_hex=IMAGE.read(l,256).hex(),right256_hex=IMAGE.read(r,256).hex(),original_pointer=pointer(k,int(row['slot'],16)));rules.append(row)
 assert[int(r['target'],16)for r in rules]==[0xfffffe000ccc2cb0,0xfffffe000ccc2c60,TABLE,0xfffffe000a508cf4]
 states=[]
 for ix,want in[(0x224,0xfffffe000a5355f4),(0x24b,0xfffffe000a55fba0),(0x293,0xfffffe000a588840),(0x2bf,0xfffffe000a5355f4),(0x53f,0xfffffe000a5355f4),(0x8d4,0xfffffe000a54f6c4),(0x920,0xfffffe000a58ffa4),(0x549,0xfffffe000a51a45c)]:
  p=pointer(k,TABLE+ix*8);assert int(p['target'],16)==want;states.append({'index32':ix,'original_pointer':p})
 binding=pointer(k,0xfffffe000847c4c8);assert int(binding['target'],16)==0xfffffe000c647f10;syms=k.symbols([int(binding['target'],16)]+[a for _,a,_ in SPANS]);assert set(r['name']for r in syms[binding['target']])=={'_memcpy','_memmove'}
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['kernel_native_reader.py','kext_port_tools.py','recover_kext_aes_handoff.py','recover_kext_cold_init.py','recover_carrier_control.py','legacy_stack_contracts.json','probe_legacy_stack.py']},'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'functions':fs,'kernel_functions':[kernel],'spans':spans,'bank_rules':rules,'dispatch_slots':states,'copy_binding':binding,'exact_symbols':syms,'additional_original_bindings':[pointer(k,a)for a in[POOL+0x150,POOL+0x2c0]],'additional_mutable_global':{'address':'0xfffffe000ccc2cb0','original8_hex':k.read(0xfffffe000ccc2cb0,8).hex()},'carrier_partial_layout':{'minimum_accessed_extent_bytes':160,'header_word_offset':0,'entry_limit_offset':8,'byte_limit_offset':12,'buffer_pointer_offset':144,'entry_count_offset':152,'byte_cursor_offset':156,'native_type_name':'unknown'},'error_status32':'0x5e5571af','success_status32':'0x5e561849','outer_error_return32':'0xffff5966','outer_success_return32':0,'native_target_executed':False,'external_TLV_emission_proved':False,'cached_FairPlay_lock_publication_proved':False,'full_goal_complete':False};(ROOT/'legacy_tlv_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'compiler_envelopes':len(fs),'source_spans':len(spans),'kernel_functions':1,'new_banks':len(rules),'dispatch_slots':len(states)}),flush=True)
if __name__=='__main__':main()
