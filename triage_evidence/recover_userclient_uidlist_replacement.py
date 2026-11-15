#!/usr/bin/env python3
"""Freeze conditional existing-node lookup/removal/free and marker replacement.
O(B+I+256R) extraction time and space; no target or IDB executes.
"""
import json
from hashlib import sha256
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from kext_port_tools import ROOT,SOURCE,IMAGE,POOL,TABLE,CS,qword,selected
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read,sha

P='userclient_uidlist_replacement'
SCOPE='Conditional existing UIDList match, shared-holder nonnull continuation, two old-marker lookup records, entry payload capture, tombstone/reclamation requests, typed payload free and status-gated marker replacement. Null-holder construction, complete incoming reachability, native identity/ownership/serialization and daemon correlation remain unknown.'
SPANS={
 'saved_codec_basis':(0xfffffe000a635898,0xfffffe000a635928),
 'saved_codec_cells':(0xfffffe000a635b40,0xfffffe000a635b6c),
 'first_index_root':(0xfffffe000a635c34,0xfffffe000a635c3c),
 'payload_output_root':(0xfffffe000a635cec,0xfffffe000a635cf4),
 'first_flag_root':(0xfffffe000a635d4c,0xfffffe000a635d54),
 'second_index_root':(0xfffffe000a636094,0xfffffe000a63609c),
 'second_flag_root':(0xfffffe000a6360a4,0xfffffe000a6360ac),
 'matched_capture':(0xfffffe000a65ee68,0xfffffe000a65eee0),
 'resource_entry':(0xfffffe000a65eee8,0xfffffe000a65ef10),
 'holder_gate':(0xfffffe000a65abfc,0xfffffe000a65ac80),
 'holder_resume':(0xfffffe000a65b000,0xfffffe000a65b004),
 'processing_gate':(0xfffffe000a65b0e4,0xfffffe000a65b128),
 'first_dispatch':(0xfffffe000a65b130,0xfffffe000a65b168),
 'first_entry':(0xfffffe000a65b170,0xfffffe000a65b1a4),
 'first_header_gate':(0xfffffe000a65b3b0,0xfffffe000a65b404),
 'first_record':(0xfffffe000a65b40c,0xfffffe000a65b4dc),
 'first_call':(0xfffffe000a65b4dc,0xfffffe000a65b52c),
 'first_return':(0xfffffe000a65b530,0xfffffe000a65b560),
 'payload_address':(0xfffffe000a65b568,0xfffffe000a65b590),
 'payload_retag':(0xfffffe000a65b594,0xfffffe000a65b598),
 'payload_read':(0xfffffe000a65b598,0xfffffe000a65b5a8),
 'first_restore':(0xfffffe000a65b5b0,0xfffffe000a65b5e8),
 'first_null_trampoline':(0xfffffe000a65b5f0,0xfffffe000a65b5f4),
 'first_return_trampoline':(0xfffffe000a65b5fc,0xfffffe000a65b604),
 'first_status':(0xfffffe000a65b60c,0xfffffe000a65b648),
 'first_found':(0xfffffe000a65b650,0xfffffe000a65b6a8),
 'second_header_gate':(0xfffffe000a65b6b0,0xfffffe000a65b6f8),
 'second_record':(0xfffffe000a65b700,0xfffffe000a65b794),
 'second_call':(0xfffffe000a65b794,0xfffffe000a65b7e4),
 'second_return':(0xfffffe000a65b7e8,0xfffffe000a65b81c),
 'delete_address':(0xfffffe000a65b824,0xfffffe000a65b844),
 'delete_retag':(0xfffffe000a65b848,0xfffffe000a65b84c),
 'delete_record':(0xfffffe000a65b84c,0xfffffe000a65b89c),
 'delete_call':(0xfffffe000a65b89c,0xfffffe000a65b90c),
 'reclaim_record':(0xfffffe000a65b910,0xfffffe000a65b9c4),
 'reclaim_call':(0xfffffe000a65b9c4,0xfffffe000a65ba14),
 'reclaim_return':(0xfffffe000a65ba18,0xfffffe000a65ba30),
 'retire_status':(0xfffffe000a65ba38,0xfffffe000a65ba94),
 'retire_prepare':(0xfffffe000a65ba9c,0xfffffe000a65bac8),
 'free_alias':(0xfffffe000a65e584,0xfffffe000a65e5a4),
 'free_gate':(0xfffffe000a65e5ac,0xfffffe000a65e5d8),
 'free_request':(0xfffffe000a65e5e0,0xfffffe000a65e664),
 'free_return':(0xfffffe000a65e668,0xfffffe000a65e6a4),
 'free_join':(0xfffffe000a65e6ac,0xfffffe000a65e6c8),
 'status_gate':(0xfffffe000a65e6d0,0xfffffe000a65e70c),
 'marker_update':(0xfffffe000a65e714,0xfffffe000a65e75c),
 'lookup_decoder_key':(0xfffffe000a5ae3c8,0xfffffe000a5ae418),
 'writer_decoder_key':(0xfffffe000a5aec78,0xfffffe000a5aec98),
}
# Load PCs and finite original slot domains; all addresses are proved separately.
BRANCHES={
 0xfffffe000a65eeb8:[0xbc1,0xbc9],
 0xfffffe000a65eef4:[0x5b7],0xfffffe000a65ac0c:[0xa9],0xfffffe000a65ac78:[0x526,0x539],
 0xfffffe000a65b114:[0xac9,0xaf9],0xfffffe000a65b158:[0xd89],0xfffffe000a65b170:[0x16e],
 0xfffffe000a65b198:[0x37f],0xfffffe000a65b3bc:[0x160],0xfffffe000a65b3f0:[0x5df,0x602],
 0xfffffe000a65b558:[0x2ed,0x2f5],0xfffffe000a65b5a0:[0x2ed],0xfffffe000a65b5b8:[0x272],
 0xfffffe000a65b634:[0x146,0x988],0xfffffe000a65b690:[0x146,0x2b9],
 0xfffffe000a65b6ec:[0xea2,0xeab],0xfffffe000a65b814:[0xc95,0xcb8],
 0xfffffe000a65ba28:[0xc95],0xfffffe000a65ba68:[0x146,0xdcb],
 0xfffffe000a65bab4:[0x327],0xfffffe000a65e59c:[0xcab],0xfffffe000a65e5b4:[0x146],
 0xfffffe000a65e5d0:[0xd46,0xd72],0xfffffe000a65e69c:[0xd46],
 0xfffffe000a65e704:[0xf4,0xc0e],0xfffffe000a65e754:[0x746,0xacd],
}
BANK_PCS={
 'holder':(0xfffffe000a65ac30,0xfffffe000a65ac3c,0xfffffe000a65ac54),
 'first_lookup':(0xfffffe000a65b500,0xfffffe000a65b510,0xfffffe000a65b520),
 'second_lookup':(0xfffffe000a65b7b8,0xfffffe000a65b7c8,0xfffffe000a65b7d8),
 'writer':(0xfffffe000a65b8d8,0xfffffe000a65b8e8,0xfffffe000a65b900),
 'reclaimer':(0xfffffe000a65b9e4,0xfffffe000a65b9f4,0xfffffe000a65ba08),
 'free':(0xfffffe000a65e5fc,0xfffffe000a65e60c,0xfffffe000a65e61c),
 'free_descriptor':(0xfffffe000a65e634,0xfffffe000a65e644,0xfffffe000a65e65c),
}
TRANSFERS=[z for name,(a,z) in SPANS.items() if name not in ['saved_codec_basis','saved_codec_cells',
 'first_index_root','payload_output_root','first_flag_root','second_index_root','second_flag_root',
 'payload_retag','delete_retag','lookup_decoder_key','writer_decoder_key',
 'first_record','second_record','delete_record','reclaim_record']]
FALSE=['native_target_executed','native_PAC_authenticated','whole_dispatcher_reachability_established',
 'null_holder_construction_closed','native_payload_identity_established','native_deallocation_established',
 'native_ownership_established','native_locking_established','all_UIDList_producers_established',
 'discriminator_business_identity_established','daemon_kext_transaction_correlated',
 'new_Mach_port_endpoint_established','IDB_modified','full_goal_complete']
DEPS=['kext_port_tools.py','kernel_native_reader.py','recover_kext_cold_init.py','lskd_values_symbolic.py',
 'audit_secure_tunnel_table_insertion.py','audit_userclient_uidlist_publication.py',
 'userclient_uidlist_publication_checks.json','userclient_uidlist_publication_audit.json',
 'userclient_hash_table_lookup_checks.json','userclient_hash_table_lookup_audit.json',
 'userclient_hash_table_reclamation_checks.json','userclient_hash_table_reclamation_audit.json']

def build():
 k=Kernel();prior=json.loads(read(ROOT/'userclient_uidlist_publication_checks.json'));container=prior['function_container']
 a,z=(int(container[n],16) for n in ['start','end_exclusive']);raw=k.read(a,z-a)
 assert IMAGE.read(a,z-a)==raw and sha256(raw).hexdigest()==container['sha256']
 spans=[]
 for name,(a,z) in SPANS.items():
  raw=k.read(a,z-a);assert IMAGE.read(a,z-a)==raw;ii=list(CS.disasm(raw,a));assert 4*len(ii)==len(raw)
  spans.append({'label':name,'start':hex(a),'end_exclusive':hex(z),'bytes_hex':raw.hex(),
   'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ii]})
 # The real linear gap must preserve both pre-key inputs before their saved use.
 a,z=0xfffffe000a635928,0xfffffe000a635b40;raw=k.read(a,z-a);assert IMAGE.read(a,z-a)==raw
 dec=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);dec.detail=True;ii=list(dec.disasm(raw,a));assert 4*len(ii)==len(raw)==536
 for i in ii:
  _,writes=i.regs_access();assert not {'x8','w8','x16','w16'}&{i.reg_name(r) for r in writes}
  assert i.mnemonic!='b' and not i.mnemonic.startswith(('b.','bl','br','ret','cb','tb'))
 gap={'start':hex(a),'end_exclusive':hex(z),'bytes_hex':raw.hex(),'sha256':sha256(raw).hexdigest(),
  'instructions':len(ii),'preserved_registers':['X8','X16'],'control_transfers':0}
 roots={'TL':qword(POOL+0x840),'TR':qword(POOL+0xbb8),'VL':qword(POOL+0xc08)-8,'VR':qword(POOL+0x158)-4,
  'FL':qword(POOL+0x458)-8,'FR':qword(POOL+0x638)-12}
 rules=[]
 for name,left,right,key,add,base,bias,div in [
  ('holder','VL','VR',0x6d,0x199,POOL,-4,None),
  ('first_lookup','FL','FR',0x87,0xe3a,TABLE,0,0x6a0f),
  ('second_lookup','TL','TR',0x16,0xe91,TABLE,0,0x6a0f),
  ('writer','TL','TR',0xb4,0xeef,TABLE,0,0x3936),
  ('reclaimer','FL','FR',0x87,0xe77,TABLE,0,0xaf1c),
  ('free','TL','TR',0x73,0xee4,TABLE,0,0x4d6a),
  ('free_descriptor','VL','VR',0x98,0x82,POOL,0,None)]:
  r=selected(roots[left],roots[right],key,add,base,bias);r.update(name=name,left_name=left,right_name=right)
  r['original_pointer']=pointer(k,int(r['slot'],16));assert (int(r['original_pointer']['target'],16)+bias)&((1<<64)-1)==int(r['target'],16)
  if div is not None:assert r['original_pointer']['authenticated'] and int(r['original_pointer']['diversity'],16)==div
  rules.append(r)
 old=json.loads(read(ROOT/'userclient_hash_table_reclamation_checks.json'));desc=old['typed_free_descriptor']
 assert int(rules[-1]['target'],16)==int(desc['address'],16) and IMAGE.read(int(desc['address'],16),64).hex()==desc['normalized64_bytes_hex']
 assert k.read(int(desc['address'],16),64).hex()==desc['original64_bytes_hex']
 adapter=k.function(0xfffffe000c4ba368);assert adapter==old['free_adapter']
 transfers=[]
 for pc in TRANSFERS:
  raw=k.read(pc,4);assert IMAGE.read(pc,4)==raw;i=list(CS.disasm(raw,pc))[0]
  assert i.mnemonic in ['braa','blraa','b.eq'],(hex(pc),i.mnemonic)
  transfers.append({'ea':hex(pc),'bytes_hex':raw.hex(),'mnemonic':i.mnemonic,'operands':i.op_str})
 return {'generator_sha256':sha(__file__),'scope':SCOPE,'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,
  'function_container':container,'spans':spans,'transfers':transfers,'codec_basis_def_use_gap':gap,'dependencies':{n:sha(ROOT/n) for n in DEPS},
  'banks':{n:{'address':hex(v),'bytes_hex':IMAGE.read(v,256).hex()} for n,v in roots.items()},'bank_rules':rules,
  'branch_pointers':[pointer(k,TABLE+8*j)|{'index':j} for j in sorted({j for js in BRANCHES.values() for j in js})],
  'pool_pointers':[pointer(k,POOL+o) for o in [0x840,0xbb8,0xc08,0x158,0x458,0x638]],
  'typed_free_descriptor':desc,'free_adapter':adapter,'free_adapter_symbols':k.symbols([0xfffffe000c4ba368]),
  'verified_counts':{'source_spans':len(spans),'selected_instructions':sum(len(s['instructions']) for s in spans),
   'terminal_transfers':len(transfers),'bank_rules':len(rules),'bank_input_cases':256*len(rules),
   'typed_free_bytes':120,'lookup_record_bytes':48,'writer_record_bytes':48,'reclaimer_record_bytes':40,'entry_stride_bytes':24,
   'codec_basis_def_use_gap_instructions':134},
  'conditional_UIDList_replacement_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
