#!/usr/bin/env python3
"""Recover original source successors, cleanup metadata and allocation imports.

O(B+I+256R) time,O(B+I) space. No target/native heap/IPC executes.
"""
import hashlib,json,struct,bisect
from pathlib import Path
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE,selected
from recover_carrier_control import span
from recover_kext_cold_init import pointer
from recover_kext_aes_handoff import starts
T=0xfffffe000846c420;P=0xfffffe00084716e0
SPANS=[('source_shape_phase',0xfffffe000a594c70,0xfffffe000a594d18),('shape_selected_allocator_preparation',0xfffffe000a56d1b4,0xfffffe000a56d268),('shape_rejection_cleanup_epilogue',0xfffffe000a58c0bc,0xfffffe000a58c1f4)]
SPECS=[('input_allocation',0xfffffe00079171c0,0xfffffe0007919bb0,0xea,0x9c8,T,0,0xfffffe000c4ba60c),('typed_cleanup',0xfffffe0007920c10,0xfffffe00079170c0,0xaa,0x967,T,0,0xfffffe000c4ba368),('cleanup_view',0xfffffe000791d3b0,0xfffffe0007920e10,0x65,-0xdc,P,-4,0xfffffe000847aee0),('aligned_cleanup',0xfffffe000791d3b0,0xfffffe0007920e10,0x3b,0x92d,T,0,0xfffffe000c4b9a24)]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');catalog=starts(k,e);spans=[]
 for name,a,z in SPANS:
  s=span(k,a,z);assert IMAGE.read(a,z-a).hex()==s['bytes_hex'];j=bisect.bisect_right(catalog,a)-1;assert z<=catalog[j+1];s.update(label=name,compiler_start=hex(catalog[j]),compiler_end=hex(catalog[j+1]));spans.append(s)
 rules=[]
 for name,l,r,key,add,base,bias,target in SPECS:
  v=selected(l,r,key,add,base=base,bias=bias);assert int(v['target'],16)==target;v.update(label=name,base=hex(base),left256_hex=IMAGE.read(l,256).hex(),right256_hex=IMAGE.read(r,256).hex(),original_pointer=pointer(k,int(v['slot'],16)));rules.append(v)
 view=0xfffffe000847aee0;ptrs=[pointer(k,view+off)for off in[16,32]];name=k.read(int(ptrs[0]['target'],16),64).split(b'\0',1)[0].decode();flags,size=struct.unpack('<II',k.read(view+40,8));assert name=='site.AllocType'and flags==0xe4 and size==4096
 native=[k.function(a)for a in[0xfffffe000c4ba60c,0xfffffe000c4ba368,0xfffffe000c4b9a24,0xfffffe000bcff010]]
 exact=k.symbols([int(f['start'],16)for f in native]+[0xfffffe000c4b9898,0xfffffe000bcfe5b8,0xfffffe000a69f294])
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['kernel_native_reader.py','kext_port_tools.py','recover_carrier_control.py','recover_kext_cold_init.py','recover_kext_aes_handoff.py']},'kernel_collection_sha256':k.sha256,'source_sha256':sha(SOURCE),'spans':spans,'bank_rules':rules,'guard_dispatch_slots':[pointer(k,T+ix*8)for ix in[0x4bb,0x76a]],'free_view':{'address':hex(view),'original64_hex':k.read(view,64).hex(),'normalized64_hex':IMAGE.read(view,64).hex(),'name':name,'flags32':hex(flags),'size32_bytes':size,'original_pointer_fields':ptrs,'runtime_link_state_known':False,'allocation_view_address':'0xfffffe000847ae20'},'native_functions':native,'exact_symbols':exact,'rejection_return_status32':'0xffff5966','rejection_return_signed32':-42650,'selected_allocation_call':'0xfffffe000a56d228','selected_allocation_length_source':'saved input length32 zero-extended to X0','input_content_read':False,'native_target_executed':False,'model_memory_writes':0,'full_goal_complete':False};(ROOT/'lskd_core_input_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'source_spans':len(spans),'exhaustive_banks':len(rules),'native_functions':len(native)}),flush=True)
if __name__=='__main__':main()
