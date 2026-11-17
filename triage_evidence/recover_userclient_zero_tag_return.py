#!/usr/bin/env python3
"""Freeze original frame, probe, guard and zero-tag return custody.
O(B+I+C*W) extraction time/space; original inputs remain read-only.
"""
import json
from kext_port_tools import ROOT,IMAGE,qword
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_userclient_zero_tag_unwind as Parent
P='userclient_zero_tag_return';pc=Parent.pc
SCOPE='Join the actual zero-tag command miss and complete restoration to the original frame/probe/save invariant, fourth ordinary retirement-return premise, an explicit additional frame/guard-range separation refinement, equal/unequal compiler-canary outcomes, exact local u32 status and source register/SP restoration through the RETAB boundary. Native allocation/release/guard/PAC effects, an authenticated return, public status naming and matched daemon/kext transport remain unknown.'
SPANS={n:(pc(a),pc(z))for n,a,z in [('frame_entry',0xa635208,0xa635268),('stack_probe',0xa5a1cc4,0xa5a1cf8),('guard_gate',0xa6662b4,0xa6662cc),('status_decode',0xa6662cc,0xa6662d0),('frame_exit',0xa6662d0,0xa6662fc),('guard_failure_call',0xa66692c,0xa666930),('guard_failure_veneer',0xa69f294,0xa69f2a4)]}
SAVES=[('d11',0x1070,0xa63520c),('d10',0x1078,0xa63520c),('d9',0x1080,0xa635210),('d8',0x1088,0xa635210),('x28',0x1090,0xa635214),('x27',0x1098,0xa635214),('x26',0x10a0,0xa635218),('x25',0x10a8,0xa635218),('x24',0x10b0,0xa63521c),('x23',0x10b8,0xa63521c),('x22',0x10c0,0xa635220),('x21',0x10c8,0xa635220),('x20',0x10d0,0xa635224),('x19',0x10d8,0xa635224),('x29',0x10e0,0xa635228),('signed_x30',0x10e8,0xa635228),('guard',0x1060,0xa635264)]
FALSE=Parent.FALSE+['native_zero_tag_core_return_established','native_guard_equality_established','public_error_domain_established']
DEPS=['recover_userclient_zero_tag_unwind.py','audit_userclient_zero_tag_unwind.py','userclient_zero_tag_unwind_checks.json','userclient_zero_tag_unwind_audit.json','recover_userclient_caller_return.py','userclient_caller_return_checks.json','userclient_entry_execution_checks.json','userclient_message_initialization_checks.json','userclient_early_data_checks.json']
def build():
 k=Kernel();prior=json.loads(read(ROOT/'userclient_zero_tag_unwind_checks.json'));assert prior==Parent.build();capture=Parent.Parent.Parent.capture;spans=[capture(k,n,a,z)for n,(a,z)in SPANS.items()];guard=pc(0xcacb000);segment=next(s for s in k.root['segments']if s['address']<=guard and guard+8<=s['address']+s['file_size']);external_guard={'address':hex(guard),'size_bytes':8,'original_collection_segment':{'name':segment['name'],'address':hex(segment['address']),'file_backed_size_bytes':segment['file_size']},'runtime_value_from_file_assumed':False,'additional_frame_separation_required':True}
 init=json.loads(read(ROOT/'userclient_message_initialization_checks.json'));original=json.loads(read(ROOT/'userclient_early_data_checks.json'));rows=[]
 for p in init['predecessor_states']:
  r=original['cases'][p['predecessor_case_index']];F=int(r['frame_base_SP'],16);assert int(r['entry_SP'],16)==F+0x10f0 and int(p['handoff_state']['registers31'][29],16)==F+0x10e0;assert F+0x10f0<=guard or guard+8<=F;cells=[]
  snapshot=bytes.fromhex(r['frame']['bytes_hex']);known=bytes.fromhex(r['frame']['known_mask_hex']);provenance=bytes.fromhex(r['frame']['provenance_hex'])
  for role,off,writer in SAVES:
   bs=[None]*8;touch=[]
   for w in r['source_writes']:
    at=int(w['address'],16);raw=bytes.fromhex(w['after_hex']);lo,hi=max(at,F+off),min(at+len(raw),F+off+8)
    if lo<hi:
     assert int(w['pc'],16)==pc(writer);touch.append(w)
     for j in range(lo,hi):bs[j-F-off]=raw[j-at]
   assert None not in bs and len(touch)==1;raw=bytes(bs);assert raw==snapshot[off:off+8]and known[off:off+8]==provenance[off:off+8]==bytes([1])*8
   if role.startswith('x'):assert int.from_bytes(raw,'little')==int(r['entry_registers31'][int(role[1:])],16)
   if role.startswith('d'):assert int.from_bytes(raw,'little')==int(r['entry_Q_registers32'][int(role[1:])],16)&((1<<64)-1)
   cells.append({'role':role,'frame_offset':hex(off),'size_bytes':8,'reconstructed_bytes_hex':raw.hex(),'original_store':touch[0],'native_value_established':False})
  rows.append({'predecessor_case_index':p['predecessor_case_index'],'frame_base_SP':hex(F),'entry_SP':r['entry_SP'],'boundary_FP':p['handoff_state']['registers31'][29],'saved_cells':cells,'frame_guard_range_disjoint':True,'native_frame_or_PAC_established':False})
 pointers=[pointer(k,pc(a))for a in [0x847c618,0x847c5f8,0x847c478]]
 for p in pointers:assert int(p['target'],16)==qword(int(p['slot'],16))
 assert [int(p['target'],16)for p in pointers]==[pc(0xa5a1cc4),pc(0xcacb000),pc(0xc629694)]
 return {'generator_sha256':sha(__file__),'source_sha256':prior['source_sha256'],'kernel_collection_sha256':k.sha256,'scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in DEPS},'source':{'container':prior['source']['container'],'spans':spans,'original_pointers':pointers},'external_guard_range':external_guard,'saved_cell_layout':[{'role':r,'frame_offset':hex(o),'size_bytes':8,'writer_PC':hex(pc(w))}for r,o,w in SAVES],'prefix_frames':rows,'exact_symbols':k.symbols([pc(0xcacb000),pc(0xc629694)]),'verified_counts':{'source_spans':len(spans),'captured_words':sum(len(s['instructions'])for s in spans),'prefix_states':len(rows),'saved_cells_per_prefix':len(SAVES),'reconstructed_saved_cells':len(rows)*len(SAVES),'reconstructed_bytes':8*len(rows)*len(SAVES),'original_pointer_slots':len(pointers),'frame_extent_bytes':0x10f0,'frame_pointer_offset_bytes':0x10e0,'guard_offset_bytes':0x1060,'guard_outcomes':2,'external_guard_range_bytes':8,'prefix_guard_range_separation_checks':len(rows),'carried_source_words':839,'carried_instruction_instances':1151,'native_target_calls':0,'input_content_bytes_supplied':0},'conditional_zero_tag_return_established':True,**{n:False for n in FALSE}}
if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
