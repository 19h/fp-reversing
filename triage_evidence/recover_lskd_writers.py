#!/usr/bin/env python3
"""Selector18 core ingress, original bank publications and conditional writer roots.

O(B+I+N+256R) time, O(B+I+N) space. Exact nlist and original fixups identify
routes. No target or IDB mutation executes; writer reachability stays separate.
"""
import hashlib,json,struct,bisect
from pathlib import Path
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE,selected,qword
from resolve_kernel_collection_interfaces import string
from recover_carrier_control import span
from recover_kext_cold_init import pointer
from recover_kext_aes_handoff import starts,function
SPANS=[('selector_lookup',0xfffffe000a503cd0,0xfffffe000a503d28),('selector18_thunk',0xfffffe000a503dc4,0xfffffe000a503df0),('selector18_method',0xfffffe000a5046dc,0xfffffe000a5047d0),('selector18_provider',0xfffffe000a505828,0xfffffe000a505848),('six_register_core_prefix',0xfffffe000a5302e4,0xfffffe000a5304cc),('stack_probe',0xfffffe000a5a1cc4,0xfffffe000a5a1cf8),('conditional_input_low_byte',0xfffffe000a5898b4,0xfffffe000a5898b8),('conditional_table_pointer',0xfffffe000a589908,0xfffffe000a58993c),('candidate_indexed_store',0xfffffe000a548094,0xfffffe000a5480a4),('example_saved_right_bank_restore',0xfffffe000a589da8,0xfffffe000a589dac)]
POOL=0xfffffe00084716e0;T=0xfffffe000846c420
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');cat=starts(k,e);ss=[]
 for label,a,z in SPANS:
  s=span(k,a,z);assert IMAGE.read(a,z-a).hex()==s['bytes_hex'];j=bisect.bisect_right(cat,a)-1
  # The stack probe has two exact compiler entries, retained explicitly.
  assert z<=cat[j+1]or label=='stack_probe';s.update(label=label,compiler_start=hex(cat[j]),compiler_end=hex(cat[j+1]));ss.append(s)
 wanted={'__ZTV30com_apple_driver_FairPlayIOKit','__ZTV40com_apple_driver_FairPlayIOKitUserClient'};vtables={};so,n,st,ssz=e['symtab']
 for j in range(n):
  sx,ty,se,ds,a=struct.unpack_from('<IBBHQ',k.data,so+16*j)
  if sx and sx<ssz:
   name=string(k.data,st+sx)
   if name in wanted:vtables[name]=hex(a)
 assert set(vtables)==wanted
 provider=int(vtables['__ZTV30com_apple_driver_FairPlayIOKit'],16)+16;client=int(vtables['__ZTV40com_apple_driver_FairPlayIOKitUserClient'],16)+16
 slots=[pointer(k,client+0x9a8),pointer(k,provider+0x928),pointer(k,0xfffffe000846b7f8),pointer(k,0xfffffe000846b418),pointer(k,0xfffffe000847c610),pointer(k,0xfffffe000847c5f8),pointer(k,POOL+0x510),pointer(k,POOL+0x1a0)]
 assert slots[0]['target']=='0xfffffe000a5046dc'and slots[1]['target']=='0xfffffe000a505828'and slots[2]['target']=='0xfffffe000846b410'and slots[3]['target']=='0xfffffe000a503dc4'
 record=IMAGE.read(0xfffffe000846b410,48);words=struct.unpack('<6Q',record);assert words==(0,0xfffffe000a503dc4,0,3,3096,3096)and(0x87e27e8021>>17)&1
 rules=[]
 specs=[('entry_controller_D98',0xfffffe0007920d10,0xfffffe00079173c0,0x2f,0x1a,POOL,-4,0xfffffe000ccc2d98),('entry_controller_C60',0xfffffe0007920d10,0xfffffe00079173c0,0x2f,0x1b,POOL,0,0xfffffe000ccc2c60),('entry_dispatch_table',0xfffffe00079174c0,0xfffffe0007919db0,0x18,-0x54,POOL,-8,T),('entry_aligned_allocator',0xfffffe0007920c10,0xfffffe00079170c0,0xaa,0x956,T,0,0xfffffe000c4b9a08),('conditional_tag_table_root',0xfffffe0007920c10,0xfffffe00079170c0,0x20,0xd,POOL,-8,0xfffffe000ccc7b08)]
 for label,l,r,key,add,base,bias,target in specs:
  b=selected(l,r,key,add,base=base,bias=bias);assert int(b['target'],16)==target;b.update(label=label,base=hex(base),left256_hex=IMAGE.read(l,256).hex(),right256_hex=IMAGE.read(r,256).hex(),original_pointer=pointer(k,int(b['slot'],16)));rules.append(b)
 names=k.symbols([0xfffffe000a5302e4,0xfffffe000a505828,0xfffffe000a5046dc,0xfffffe000a503dc4,0xfffffe000c4b9a08,0xfffffe000a5a1cc4,0xfffffe000cacb000,*[int(a,16)for a in vtables.values()]])
 assert any(x['name']=='_zgcqcxw1qve0CY'for x in names['0xfffffe000a5302e4'])and any(x['name']=='_IOMallocAligned'for x in names['0xfffffe000c4b9a08'])
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['kernel_native_reader.py','kext_port_tools.py','resolve_kernel_collection_interfaces.py','recover_carrier_control.py','recover_kext_cold_init.py','recover_kext_aes_handoff.py']},'kernel_collection_sha256':k.sha256,'source_sha256':sha(SOURCE),'spans':ss,'vtables':vtables,'original_pointer_slots':slots,'selector18':{'selector':18,'lookup_mask64':'0x87e27e8021','list_slot':'0xfffffe000846b7f8','descriptor':'0xfffffe000846b410','original48_hex':k.read(0xfffffe000846b410,48).hex(),'normalized48_hex':record.hex(),'six_words':[hex(x)for x in words],'input_count_bytes':3096,'output_count_bytes':3096},'bank_rules':rules,'additional_mutable_globals':[{'address':'0xfffffe000ccc2d98','size_bytes':8,'original8_hex':k.read(0xfffffe000ccc2d98,8).hex()}],'core_entry':function(k,e,0xfffffe000a5302e4)['start'],'core_prefix_only_executed':True,'first_allocator':{'call_PC':'0xfffffe000a5304c8','target':'0xfffffe000c4b9a08','size_bytes':16384,'alignment_bytes':64,'executed':False},'bank_pointer_outputs':{'SP_plus_C28':'0xfffffe0007920c10','SP_plus_C30':'0xfffffe00079170c0'},'conditional_writer_root':{'table':'0xfffffe000ccc7b08','frame_store_PC':'0xfffffe000a589938','frame_cell_SP_offset_bytes':0xd28,'indexed_store_candidate_PC':'0xfffffe000a5480a0','required_bank_preservation_and_X26_restore':True,'same_frame_reaching_definition_proved':False,'actual_tag_table_writer_proved':False},'exact_symbols':names,'native_target_executed':False,'idb_mutated':False,'full_goal_complete':False};(ROOT/'lskd_writers_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'source_windows':len(SPANS),'root_banks':len(rules),'selector18_bytes':3096}),flush=True)
if __name__=='__main__':main()
