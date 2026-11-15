#!/usr/bin/env python3
"""Freeze tunnel aliases, insertion lookup/record codecs and marker writeback.
O(B+I+256R) time and O(B+I) space. No native target or IDB mutation.
"""
import json
from hashlib import sha256
from kext_port_tools import ROOT, SOURCE, IMAGE, POOL, TABLE, CS, qword, selected
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from recover_kext_aes_handoff import starts
from verify_daemon_reader_record_payloads_publication import read, sha

P='secure_tunnel_table_insertion'
SCOPE='Conditional original-source tunnel-pointer alias transfer, source-marker-derived table key, token0x541 insertion lookup, status-only gate, token0xc28 occupied-entry request and post-writer marker stores. Incoming dispatcher reachability, native allocation identity/ownership, global serialization and daemon transaction correlation remain unknown.'
SPANS={
 'record_root':(0xfffffe000a6355c4,0xfffffe000a6355c8),
 'record_root_save':(0xfffffe000a635b50,0xfffffe000a635b54),
 'saved_context_roots':(0xfffffe000a636300,0xfffffe000a636308),
 'payload_alias':(0xfffffe000a65b080,0xfffffe000a65b08c),
 'header_alias':(0xfffffe000a65b0c8,0xfffffe000a65b0cc),
 'insertion_inputs':(0xfffffe000a65bb98,0xfffffe000a65bba8),
 'key_basis':(0xfffffe000a65bbdc,0xfffffe000a65bc70),
 'payload_save':(0xfffffe000a65bd0c,0xfffffe000a65bd18),
 'payload_restore':(0xfffffe000a65bdfc,0xfffffe000a65be04),
 'lookup_prefix':(0xfffffe000a65be74,0xfffffe000a65bec0),
 'lookup_key_mix':(0xfffffe000a65bec0,0xfffffe000a65c0dc),
 'lookup_codec':(0xfffffe000a65c0dc,0xfffffe000a65c118),
 'lookup_record':(0xfffffe000a65c118,0xfffffe000a65c154),
 'lookup_call':(0xfffffe000a65c154,0xfffffe000a65c1ac),
 'lookup_return':(0xfffffe000a65c1b0,0xfffffe000a65c1f8),
 'insert_address':(0xfffffe000a65c200,0xfffffe000a65c230),
 'insert_retag':(0xfffffe000a65c234,0xfffffe000a65c238),
 'insert_codec':(0xfffffe000a65c238,0xfffffe000a65c28c),
 'insert_record':(0xfffffe000a65c28c,0xfffffe000a65c2c4),
 'insert_call':(0xfffffe000a65c2c4,0xfffffe000a65c318),
 'post_writer':(0xfffffe000a65c31c,0xfffffe000a65c350),
 'lookup_decoder_key':(0xfffffe000a5ae3c8,0xfffffe000a5ae418),
 'writer_decoder_key':(0xfffffe000a5aec78,0xfffffe000a5aec98),
}
FALSE=['native_target_executed','native_PAC_authenticated','whole_dispatcher_reachability_established',
 'native_payload_identity_established','native_ownership_established','native_locking_established',
 'all_table_writers_established','global_counter_invariant_established','UID_business_semantics_established',
 'daemon_kext_transaction_correlated','new_Mach_port_endpoint_established','IDB_modified','full_goal_complete']
DEPS=['kext_port_tools.py','kernel_native_reader.py','recover_kext_cold_init.py','recover_kext_aes_handoff.py',
 'lskd_values_symbolic.py','audit_userclient_hash_table_initializer.py','audit_userclient_hash_table_lookup.py','audit_userclient_hash_table_reclamation.py',
 'secure_tunnel_allocation_checks.json','secure_tunnel_allocation_audit.json',
 'userclient_hash_table_lookup_checks.json','userclient_hash_table_lookup_audit.json','userclient_hash_table_reclamation_audit.json']

def build():
 k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');catalog=starts(k,e)
 a,z=0xfffffe000a635208,0xfffffe000a666930;assert catalog[catalog.index(a)+1]==z
 raw=k.read(a,z-a);assert IMAGE.read(a,z-a)==raw;whole_sha=sha256(raw).hexdigest()
 spans=[]
 for label,(a,z) in SPANS.items():
  raw=k.read(a,z-a);assert IMAGE.read(a,z-a)==raw
  ii=[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(raw,a)]
  assert len(ii)*4==len(raw);spans.append({'label':label,'start':hex(a),'end_exclusive':hex(z),'bytes_hex':raw.hex(),'instructions':ii})
 # Original bytes between X16's affine definition and its saved use.
 a,z=0xfffffe000a6355c8,0xfffffe000a635b50;raw=k.read(a,z-a);assert IMAGE.read(a,z-a)==raw
 gap={'start':hex(a),'end_exclusive':hex(z),'bytes_hex':raw.hex(),'sha256':sha256(raw).hexdigest()}
 pair=(qword(POOL+0x840),qword(POOL+0xbb8));rules=[]
 for name,key,add,div in [('lookup',0xd8,0xef9,0x6a0f),('writer',0x5c,0xe8b,0x3936)]:
  r=selected(*pair,key,add);r['name']=name;r['original_pointer']=pointer(k,int(r['slot'],16))
  assert r['original_pointer']['authenticated'] and int(r['original_pointer']['diversity'],16)==div
  assert int(r['original_pointer']['target'],16)==int(r['target'],16);rules.append(r)
 transfers=[]
 for pc in [0xfffffe000a65c1ac,0xfffffe000a65c1f8,0xfffffe000a65c230,0xfffffe000a65c318]:
  raw=k.read(pc,4);assert IMAGE.read(pc,4)==raw;i=list(CS.disasm(raw,pc))[0]
  transfers.append({'ea':hex(pc),'bytes_hex':raw.hex(),'mnemonic':i.mnemonic,'operands':i.op_str})
 prior=json.loads(read(ROOT/'secure_tunnel_allocation_checks.json'));assert whole_sha==prior['function_container']['sha256']
 return {'generator_sha256':sha(__file__),'scope':SCOPE,'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,
  'dependencies':{n:sha(ROOT/n) for n in DEPS},'function_container':prior['function_container'],
  'spans':spans,'record_root_def_use_gap':gap,'transfers':transfers,
  'banks':{'TL':{'address':hex(pair[0]),'bytes_hex':IMAGE.read(pair[0],256).hex()},
   'TR':{'address':hex(pair[1]),'bytes_hex':IMAGE.read(pair[1],256).hex()}},'bank_rules':rules,
  'pool_pointers':[pointer(k,POOL+o) for o in [0x840,0xbb8]],
  'branch_pointers':[pointer(k,TABLE+8*j)|{'index':j} for j in [0x91e,0xda1]],
  'verified_counts':{'source_spans':len(spans),'selected_instructions':sum(len(s['instructions']) for s in spans),
   'terminal_transfers':len(transfers),'bank_rules':2,'bank_input_cases':512,'record_root_gap_instructions':len(bytes.fromhex(gap['bytes_hex']))//4,
   'private_record_bytes':48,'entry_stride_bytes':24,'payload_extent_bytes':120},
  'conditional_tunnel_to_table_insertion_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
