#!/usr/bin/env python3
"""Freeze actual zero-tag caller, miss, restoration and retirement interfaces.
O(B+I+256R+C*W) extraction time/space; original inputs are read-only.
"""
import json
from kext_port_tools import ROOT,IMAGE,TABLE,qword
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_userclient_fallback_metadata as Parent
import recover_userclient_command_dispatch as Command
import recover_userclient_caller_return as Caller
P='userclient_zero_tag_unwind';pc=Parent.pc
SCOPE='Compose the actual zero-tag/type0x6685 fallback completion with its command-tag lookup, empty-list miss, typed-container retirement, complete 14-byte original-input restoration, buffer/context retirement and pending aligned-workspace release. Both retained predecessor modes and all five admitted body lengths are covered under explicit ordinary-return and surviving-storage premises. Native effects/ownership/PAC, transport identity, compiler guard/outer return and other tag/type paths remain unknown.'
SPANS={n:(pc(a),pc(z))for n,a,z in [
 ('caller',0xa656c08,0xa656c44),('field_gate',0xa656c44,0xa656ca0),('field_request',0xa656ca0,0xa656cfc),
 ('search_entry',0xa662ab4,0xa662b00),('search_nonnull',0xa662be0,0xa662c00),('search_node',0xa662c00,0xa662c44),('search_result',0xa662c44,0xa662c60),('search_callback',0xa662b00,0xa662b64),('field_result',0xa656cfc,0xa656d48),
 ('cleanup',0xa656f00,0xa656f4c),('destroy_request',0xa656f4c,0xa656f8c),('destroy_bridge',0xa66229c,0xa6622bc),('destroy_entry',0xa660468,0xa6604a4),('destroy_object',0xa6604a4,0xa6604fc),('destroy_head',0xa6604fc,0xa660534),('container_free',0xa660534,0xa6605c8),('container_return',0xa6605c8,0xa660614),('destroy_resume',0xa660614,0xa660630),
 ('aux_gate',0xa665e90,0xa665ee4),('primary_load',0xa665f8c,0xa665fc8),('copy_gate',0xa665fc8,0xa66609c),('copy_prepare',0xa66609c,0xa6660b4),('copy_step',0xa6660b4,0xa666118),('primary_free',0xa666118,0xa66618c),('primary_return',0xa66618c,0xa6661bc),('context_free',0xa6661bc,0xa666264),('workspace_free',0xa666264,0xa6662b4)]}
BRANCHES={a:js for table in [Command.BRANCHES,Caller.BRANCHES]for a,js in table.items()if any(lo<=a<hi for lo,hi in SPANS.values())}|{pc(0xa6622b0):[0x9a7]}
RETAGS=Parent.RETAGS|Caller.RETAGS
BANK_PCS={name:pcs for table,names in [(Command.BANK_PCS,['search_callback_value']),(Caller.BANK_PCS,['container_free','container_descriptor','primary_free','context_free','context_descriptor','workspace_free'])]for name,pcs in table.items()if name in names}
CONTROLLERS={pc(p):pc(a)for p,a in [(0xa662b08,0xccc30d0),(0xa662b10,0xccc32f8),(0xa660538,0xccc30d0),(0xa660540,0xccc32f8),(0xa666124,0xccc30d0),(0xa66612c,0xccc32f8),(0xa6661c8,0xccc30d0),(0xa6661cc,0xccc32f8),(0xa666264,0xccc30d0),(0xa666268,0xccc32f8)]}
FALSE=Parent.FALSE+['native_zero_tag_unwind_effects_established','native_zero_tag_external_error_established']
DEPS=['recover_userclient_fallback_metadata.py','audit_userclient_fallback_metadata.py','userclient_fallback_metadata_checks.json','userclient_fallback_metadata_audit.json','recover_userclient_command_dispatch.py','audit_userclient_command_dispatch.py','userclient_command_dispatch_checks.json','userclient_command_dispatch_audit.json','recover_userclient_caller_return.py','audit_userclient_caller_return.py','userclient_caller_return_checks.json','userclient_caller_return_audit.json','userclient_message_initialization_checks.json','userclient_early_data_checks.json']
def build():
 k=Kernel();prior=json.loads(read(ROOT/'userclient_fallback_metadata_checks.json'));assert prior==Parent.build();command=json.loads(read(ROOT/'userclient_command_dispatch_checks.json'));caller=json.loads(read(ROOT/'userclient_caller_return_checks.json'));assert command==Command.build()and caller==Caller.build();capture=Parent.Parent.capture
 spans=[capture(k,n,a,z)for n,(a,z)in SPANS.items()];alias=capture(k,'command_result_alias',pc(0xa635c3c),pc(0xa635c44));cells=[]
 init=json.loads(read(ROOT/'userclient_message_initialization_checks.json'));original=json.loads(read(ROOT/'userclient_early_data_checks.json'))
 for p in init['predecessor_states']:
  r=original['cases'][p['predecessor_case_index']];F=int(p['frame_base_SP'],16);C=int(p['handoff_state']['registers31'][11],16);bs=[None]*8;touch=[]
  for w in r['source_writes']:
   at=int(w['address'],16);raw=bytes.fromhex(w['after_hex']);lo,hi=max(at,F+0x5a8),min(at+len(raw),F+0x5b0)
   if lo<hi:
    touch.append(w)
    for j in range(lo,hi):bs[j-F-0x5a8]=raw[j-at]
  assert None not in bs and int.from_bytes(bytes(bs),'little')==C+0x1f8
  cells.append({'predecessor_case_index':p['predecessor_case_index'],'frame_base_SP':p['frame_base_SP'],'frame_offset':'0x5a8','context_offset':'0x1f8','size_bytes':8,'reconstructed_bytes_hex':bytes(bs).hex(),'overlapping_original_stores':touch})
 banks={};rules=[]
 for name in BANK_PCS:
  old=command if name=='search_callback_value'else caller;r=next(r for r in old['bank_rules']if r['name']==name);left,right=(int(r[s],16)for s in ['left','right'])
  for a in [left,right]:
   raw=k.read(a,256);assert raw==IMAGE.read(a,256);banks[hex(a)]=raw.hex()
  assert pointer(k,int(r['slot'],16))==r['original_pointer'];l,rr=(bytes.fromhex(banks[hex(a)])for a in [left,right]);assert all(j^rr[l[j]^int(r['key'],16)]==int(r['constant'],16)for j in range(256));rules.append(r)
 pointers=[{'source_PC':hex(a),'slot':hex(TABLE+8*j),'original_pointer':pointer(k,TABLE+8*j)}for a,js in BRANCHES.items()for j in js]
 for row in pointers:assert int(row['original_pointer']['target'],16)==qword(int(row['slot'],16))
 return {'generator_sha256':sha(__file__),'source_sha256':prior['source_sha256'],'kernel_collection_sha256':k.sha256,'scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in DEPS},'source':{'container':prior['source']['container'],'spans':spans,'pointer_observations':pointers},'prefix_source':alias,'prefix_cells':cells,'bank_rules':rules,'banks':banks,'retirement_descriptors':[r for r in caller['typed_descriptors']if r['role']in ['outer_retirement','container_retirement']],'exact_symbols':k.symbols([pc(a)for a in [0xc4ba368,0xc4ba84c,0xc4b9a24]]),'verified_counts':{'source_spans':len(spans),'captured_words':sum(len(s['instructions'])for s in spans),'carried_header_spans':15,'carried_header_words':311,'prefix_words':2,'prefix_states':len(cells),'additional_prefix_bytes':8*len(cells),'original_pointer_observations':len(pointers),'original_pointer_slots':len({r['slot']for r in pointers}),'bank_rules':len(rules),'bank_input_cases':256*len(rules),'controller_load_sites':len(CONTROLLERS),'additional_alternate_retag_words':1,'fallback_extent_bytes':14,'new_container_extent_bytes':16,'body_length_values':5,'input_content_bytes_supplied':0},'conditional_zero_tag_unwind_established':True,**{n:False for n in FALSE}}
if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
