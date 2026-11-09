#!/usr/bin/env python3
"""Prospective response allocation, metadata getter and conditional publication.

Primary original/normalized bytes only. O(B+I+256R) time/source space. No native
heap/free, request business processing, crypto, Mach, synchronization or IDB action.
"""
import bisect,hashlib,json,struct
from pathlib import Path
from kernel_native_reader import Kernel
from kext_port_tools import ROOT,SOURCE,IMAGE,selected
from recover_kext_aes_handoff import function,starts
from recover_kext_cold_init import pointer
from recover_carrier_control import span
POOL=0xfffffe00084716e0;TABLE=0xfffffe000846c420
SPANS=[('allocation_state',0xfffffe000a5247ac,0xfffffe000a5248a0),('response_clear_record',0xfffffe000a561738,0xfffffe000a561910),('record_bridge',0xfffffe000a58a1c0,0xfffffe000a58a3e0),('inner_prefix',0xfffffe000a570f0c,0xfffffe000a5711a4),('metadata_prepare',0xfffffe000a51bdec,0xfffffe000a51bee4),('metadata_entry',0xfffffe000a54f50c,0xfffffe000a54f620),('metadata_header_gate',0xfffffe000a56b438,0xfffffe000a56b480),('metadata_copy',0xfffffe000a535338,0xfffffe000a535358),('metadata_return',0xfffffe000a54f244,0xfffffe000a54f254),('inner_return',0xfffffe000a52e4b0,0xfffffe000a52e4e4),('response_free',0xfffffe000a535640,0xfffffe000a5356e8),('conditional_publish',0xfffffe000a522e38,0xfffffe000a522e5c),('business_entry_static',0xfffffe000a59bf78,0xfffffe000a59bf84),('record_symbolic',0xfffffe000a5617b8,0xfffffe000a561828),('inner_decode_symbolic',0xfffffe000a571024,0xfffffe000a571074),('getter_record_symbolic',0xfffffe000a51bdf4,0xfffffe000a51be40),('getter_key_symbolic',0xfffffe000a54f560,0xfffffe000a54f59c),('delta_symbolic',0xfffffe000a58a3bc,0xfffffe000a58a3cc)]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');catalog=starts(k,e);parents=set();spans=[]
 for label,a,z in SPANS:
  row=span(k,a,z);assert IMAGE.read(a,z-a).hex()==row['bytes_hex'];ix=bisect.bisect_right(catalog,a)-1;assert z<=catalog[ix+1];parents.add(catalog[ix]);row.update(label=label,compiler_start=hex(catalog[ix]),compiler_end=hex(catalog[ix+1]));spans.append(row)
 specs=[('allocate',0x7920c10,0x79170c0,0x20,0x973,TABLE,0),('allocate_view',0x79171c0,0x7919bb0,0xea,0x65,POOL,-8),('clear',0x79171c0,0x7919bb0,0xea,0x9fc,TABLE,0),('displacement_seed',0x7920d10,0x79173c0,0xbb,-0x97,POOL,-4),('record_bridge',0x7920c10,0x79170c0,0x20,0x9ca,TABLE,0),('bridge_stateA',0x791d3b0,0x7920e10,0x65,-0x87,POOL,0),('bridge_stateB',0x79174c0,0x7919db0,0x18,-0x8d,POOL,0),('bridge_seed_write',0x79172c0,0x7919cb0,0x8d,0,POOL,-4),('bridge_inner',0x79172c0,0x7919cb0,0xb5,0x978,TABLE,0),('bridge_table',0x79172c0,0x7919cb0,0xff,-0x43,POOL,-8),('inner_stateA',0x79172c0,0x7919cb0,0xb5,-0x2f,POOL,0),('inner_stateB',0x79174c0,0x7919db0,0x18,-0x8d,POOL,0),('inner_bounds',0x79171c0,0x7919bb0,0xea,0x994,TABLE,0),('inner_table',0x79172c0,0x7919cb0,0xb5,-0x15,POOL,-8),('metadata_call',0x7920d10,0x79173c0,0x2f,0x9ff,TABLE,0),('metadata_table',0x7920d10,0x79173c0,0xbb,-0x58,POOL,-8),('free',0x79174c0,0x7919db0,0x18,0x92c,TABLE,0),('free_view',0x7920c10,0x79170c0,0xaa,-0x6e,POOL,-12)]
 rules=[]
 for label,l,r,key,add,base,bias in specs:
  l|=0xfffffe0000000000;r|=0xfffffe0000000000;b=selected(l,r,key,add,base=base,bias=bias);b.update(label=label,base=hex(base),left256_hex=IMAGE.read(l,256).hex(),right256_hex=IMAGE.read(r,256).hex(),original_pointer=pointer(k,int(b['slot'],16)));rules.append(b)
 targets={b['label']:int(b['target'],16)for b in rules};assert targets['allocate']==0xfffffe000c4ba154 and targets['allocate_view']==0xfffffe000847ae60 and targets['clear']==0xfffffe000a508cec and targets['record_bridge']==0xfffffe000a58a1c0 and targets['bridge_inner']==0xfffffe000a570f0c and targets['metadata_call']==0xfffffe000a54f50c and targets['free']==0xfffffe000c4ba368 and targets['free_view']==0xfffffe000847b020
 views=[]
 for use,a in [('allocate',targets['allocate_view']),('free',targets['free_view'])]:
  raw=k.read(a,64);p=pointer(k,a+16);name=k.read(int(p['target'],16),80).split(b'\0')[0];flags,size=struct.unpack_from('<II',raw,40);assert name==b'site.LSKDDispatchStream'and flags==100 and size==160;views.append({'use':use,'address':hex(a),'bytes64_hex':raw.hex(),'name_pointer':p,'name':name.decode(),'metadata_flags32':flags,'metadata_size32':size,'initial_runtime_links16_hex':raw[:16].hex()})
 slots=[{'index32':n,'original_pointer':pointer(k,TABLE+8*n)}for n in[0x99c,0x9a2,0x3be,0x3cd,0x6ef,0x6f9,0x688,0x68c,0x671,0x38c,0x3a8,0x378]];stack=json.loads((ROOT/'legacy_stack_contracts.json').read_text());helpers=[f for f in stack['functions']if int(f['start'],16)in[0xfffffe000a5a1cc4,0xfffffe000a5a1ccc]];assert len(helpers)==2
 for f in helpers:assert function(k,e,int(f['start'],16))==f
 fs=[function(k,e,a)for a in sorted(parents)];roots=[pointer(k,POOL+n)for n in[0x150,0x2c0,0x308,0x420,0x4f0,0x600,0x2f8,0x630,0x510,0x1a0]];binding=pointer(k,0xfffffe000847c610);assert binding['target']=='0xfffffe000a5a1cc4';symbols=k.symbols([int(f['start'],16)for f in fs]+[0xfffffe000a54f50c,0xfffffe000a58a1c0,0xfffffe000c4ba154,0xfffffe000c4ba368]+[int(f['start'],16)for f in helpers])
 out={'scope':__doc__,'generator_sha256':sha(Path(__file__)),'dependencies':{n:sha(ROOT/n)for n in['kernel_native_reader.py','kext_port_tools.py','recover_kext_aes_handoff.py','recover_kext_cold_init.py','recover_carrier_control.py','lskd_execute_contracts.json','lskd_fields_contracts.json','lskd_request_contracts.json','legacy_stack_contracts.json']},'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'functions':fs,'spans':spans,'bank_rules':rules,'original_bank_pointer_roots':roots,'typed_views':views,'dispatch_slots':slots,'stack_helpers':helpers,'stack_binding':binding,'additional_mutable_globals':[{'address':hex(a),'original8_hex':k.read(a,8).hex()}for a in[0xfffffe000ccc2b50,0xfffffe000ccc2b68,0xfffffe000ccc2d90,0xfffffe000ccc2cd8]],'exact_symbols':symbols,'native_target_executed':False,'native_heap_executed':False,'business_request_operation_executed':False,'external_IPC_emission_proved':False,'full_goal_complete':False};(ROOT/'lskd_response_contracts.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'compiler_envelopes':len(fs),'spans':len(spans),'new_rules':len(rules),'typed_views':len(views),'stack_helpers':len(helpers)}),flush=True)
if __name__=='__main__':main()
