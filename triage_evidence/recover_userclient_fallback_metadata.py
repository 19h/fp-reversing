#!/usr/bin/env python3
"""Freeze the actual fallback header continuation and publication interface.
O(B+I+C*W) extraction time/space; original inputs remain read-only.
"""
import json
from kext_port_tools import ROOT,IMAGE,CS,TABLE,qword
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read,sha
import recover_userclient_fallback_parser as Parent
import recover_userclient_record_metadata as Metadata

P='userclient_fallback_metadata';pc=Parent.pc
SCOPE='Compose the actual nonnull fallback-container cut through all ten protected header bytes, exact 14-byte body bounds, two type gates, selected type0x6685 metadata and zero-tag publication to the saved caller. Both retained modes are certified against a finite live-state projection. Other type handlers, ordinary node construction, failure cleanup beyond its entry, native effects/PAC/epochs, matched transport and the outer return remain unknown.'
SPANS={n:(pc(a),pc(z))for n,a,z in [
 ('tag_tail',0xa638dc8,0xa638e10),('decode_type',0xa63930c,0xa6393c8),
 ('type_return',0xa639dc0,0xa639e3c),('length_bridge',0xa637128,0xa637138),
 ('decode_word',0xa637138,0xa637250),('length_extent',0xa6390b4,0xa639164),
 ('type_first_gate',0xa639164,0xa639178),('type_selected_gate',0xa63a784,0xa63a790),
 ('body_publish',0xa63dc9c,0xa63dcd0),('metadata_return',0xa63dcd0,0xa63dd14),
 ('metadata_outcome_gate',0xa6423c0,0xa6423f4),('record_kind_gate',0xa6423f4,0xa642454),
 ('success',0xa6421b0,0xa6421dc),('publish',0xa660ac8,0xa660ae0),
 ('resume',0xa660ae0,0xa660af4)]}
BRANCHES={a:js for a,js in Metadata.BRANCHES.items()if any(lo<=a<hi for lo,hi in SPANS.values())}|{pc(0xa6421c8):[0x970],pc(0xa660ad4):[0x6d5]}
RETAGS=Metadata.RETAGS
FALSE=[n for n in Parent.FALSE if n!='whole_fallback_header_completed']+['all_fallback_type_handlers_completed','native_zero_tag_sentinel_meaning_established','authenticated_saved_caller_return_established']
DEPS=['recover_userclient_fallback_parser.py','audit_userclient_fallback_parser.py',
 'userclient_fallback_parser_checks.json','userclient_fallback_parser_audit.json',
 'recover_userclient_record_metadata.py','audit_userclient_record_metadata.py',
 'userclient_record_metadata_checks.json','userclient_record_metadata_audit.json',
 'audit_userclient_input_reader.py','audit_secure_tunnel_table_insertion.py',
 'lskd_values_symbolic.py','kext_port_tools.py','kernel_native_reader.py',
 'userclient_message_initialization_checks.json','userclient_early_data_checks.json']

def build():
 k=Kernel();prior=json.loads(read(ROOT/'userclient_fallback_parser_checks.json'));assert prior==Parent.build()
 spans=[Parent.capture(k,n,a,z)for n,(a,z)in SPANS.items()]
 alias=Parent.capture(k,'input_alias_root',pc(0xa635efc),pc(0xa635f04));cells=[]
 init=json.loads(read(ROOT/'userclient_message_initialization_checks.json'));original=json.loads(read(ROOT/'userclient_early_data_checks.json'))
 for p in init['predecessor_states']:
  r=original['cases'][p['predecessor_case_index']];F=int(p['frame_base_SP'],16);C=int(p['handoff_state']['registers31'][11],16);bs=[None]*8;touch=[]
  for w in r['source_writes']:
   at=int(w['address'],16);raw=bytes.fromhex(w['after_hex']);lo,hi=max(at,F+0x890),min(at+len(raw),F+0x898)
   if lo<hi:
    touch.append(w)
    for j in range(lo,hi):bs[j-F-0x890]=raw[j-at]
  assert None not in bs and int.from_bytes(bytes(bs),'little')==C+0x3d8
  cells.append({'predecessor_case_index':p['predecessor_case_index'],'frame_base_SP':p['frame_base_SP'],'frame_offset':'0x890','size_bytes':8,'context_offset':'0x3d8','reconstructed_bytes_hex':bytes(bs).hex(),'overlapping_original_stores':touch})
 pointers=[{'source_PC':hex(a),'slot':hex(TABLE+8*j),'original_pointer':pointer(k,TABLE+8*j)}for a,js in BRANCHES.items()for j in js]
 for row in pointers:assert int(row['original_pointer']['target'],16)==qword(int(row['slot'],16))
 return {'generator_sha256':sha(__file__),'source_sha256':prior['source_sha256'],'kernel_collection_sha256':k.sha256,'scope':SCOPE,'dependencies':{n:sha(ROOT/n)for n in DEPS},'source':{'container':prior['source']['container'],'spans':spans,'pointer_observations':pointers},'prefix_source':alias,'prefix_cells':cells,'verified_counts':{'source_spans':len(spans),'captured_words':sum(len(s['instructions'])for s in spans),'prefix_words':2,'original_pointer_observations':len(pointers),'original_pointer_slots':len({p['slot']for p in pointers}),'alternate_retag_words':len(RETAGS),'prefix_states':len(cells),'additional_prefix_bytes':8*len(cells),'fallback_extent_bytes':14,'header_bytes':10,'new_header_byte_indices':[4,5,6,7,8,9],'new_container_extent_bytes':16,'input_content_bytes_supplied':0},'conditional_fallback_metadata_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
