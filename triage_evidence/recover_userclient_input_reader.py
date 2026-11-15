#!/usr/bin/env python3
"""Freeze the shared tagged-node reader and caller-specific output continuation.
O(B+I+256R) extraction time/space. No target executes or IDB changes.
"""
import json
from hashlib import sha256
from kext_port_tools import ROOT,SOURCE,IMAGE,POOL,TABLE,CS,qword,selected
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read,sha

P='userclient_input_reader'
SCOPE='Conditional shared tagged-node search, protected-memory header decoding, caller output-address/continuation ABI, encoded length channel, type/extent gates, IOMallocData request, decoded reverse byte copy and hash-input publication. Whole incoming reachability, native object ownership, termination guarantee, external input identity, original tunnel-marker producer, synchronization and daemon correlation remain unknown.'
SPANS={
 'input_root':(0xfffffe000a635d5c,0xfffffe000a635d64),
 'length_root':(0xfffffe000a635bdc,0xfffffe000a635be4),
 'node_root':(0xfffffe000a636154,0xfffffe000a63615c),
 'buffer_root':(0xfffffe000a635bf4,0xfffffe000a635bfc),
 'reader_request':(0xfffffe000a63dd84,0xfffffe000a63ddcc),
 'shared_entry':(0xfffffe000a662a2c,0xfffffe000a662a7c),
 'search_setup':(0xfffffe000a662a84,0xfffffe000a662ab0),
 'search_entry':(0xfffffe000a662ab8,0xfffffe000a662afc),
 'search_nonnull':(0xfffffe000a662be4,0xfffffe000a662bfc),
 'search_node':(0xfffffe000a662c04,0xfffffe000a662c40),
 'node_decode_prepare':(0xfffffe000a662c64,0xfffffe000a662cc8),
 'word_bridge':(0xfffffe000a656ef4,0xfffffe000a656efc),
 'length_bridge':(0xfffffe000a63712c,0xfffffe000a637134),
 'decode_word':(0xfffffe000a63713c,0xfffffe000a63724c),
 'tag_match':(0xfffffe000a63d628,0xfffffe000a63d67c),
 'search_next':(0xfffffe000a63d684,0xfffffe000a63d69c),
 'search_result':(0xfffffe000a662c48,0xfffffe000a662c5c),
 'search_callback':(0xfffffe000a662b04,0xfffffe000a662b60),
 'after_search':(0xfffffe000a662ee4,0xfffffe000a662f20),
 'select_node':(0xfffffe000a662f28,0xfffffe000a662f7c),
 'header_extent':(0xfffffe000a662f84,0xfffffe000a663028),
 'header_prepare':(0xfffffe000a663030,0xfffffe000a6630dc),
 'type_prepare':(0xfffffe000a638354,0xfffffe000a6383a0),
 'decode_type':(0xfffffe000a639310,0xfffffe000a6393c4),
 'length_prepare':(0xfffffe000a639b34,0xfffffe000a639bb8),
 'payload_extent':(0xfffffe000a63c400,0xfffffe000a63c490),
 'type_switch':(0xfffffe000a63c498,0xfffffe000a63c4c0),
 'body_pointer':(0xfffffe000a63c4c0,0xfffffe000a63c4ec),
 'body_length_prepare':(0xfffffe000a63c4f4,0xfffffe000a63c524),
 'alternate_type_length_prepare':(0xfffffe000a63de14,0xfffffe000a63de48),
 'save_length':(0xfffffe000a63de50,0xfffffe000a63de64),
 'type_gate':(0xfffffe000a63de6c,0xfffffe000a63deb4),
 'body_gate':(0xfffffe000a63debc,0xfffffe000a63df00),
 'allocate_request':(0xfffffe000a63df08,0xfffffe000a63df88),
 'allocate_return':(0xfffffe000a63df8c,0xfffffe000a63dfec),
 'copy_gate':(0xfffffe000a63dff4,0xfffffe000a63e080),
 'copy_prepare':(0xfffffe000a63e088,0xfffffe000a63e098),
 'copy_step':(0xfffffe000a63e0a0,0xfffffe000a63e10c),
 'publish':(0xfffffe000a63e114,0xfffffe000a63e13c),
 'clear_outputs':(0xfffffe000a6630e4,0xfffffe000a66310c),
 'resume':(0xfffffe000a663114,0xfffffe000a66311c),
}
BRANCHES={
 0xfffffe000a63dd9c:[0x2c4],0xfffffe000a662a38:[0x133],0xfffffe000a662a60:[0x542,0x54e],
 0xfffffe000a662aa4:[0x49a],0xfffffe000a662ac0:[0x6a],0xfffffe000a662ae8:[0x630,0x63e],
 0xfffffe000a662bf4:[0x52d],0xfffffe000a662c28:[0x50c,0x50d],0xfffffe000a662c88:[0x22f],
 0xfffffe000a656ef4:[0xe07],0xfffffe000a63712c:[0xe07],0xfffffe000a63713c:[0x181,0x179,0x13d],
 0xfffffe000a63d66c:[0xeb6,0xe91],0xfffffe000a63d694:[0x52d],0xfffffe000a662c50:[0x63e],
 0xfffffe000a662f10:[0x2e6,0x7b4],0xfffffe000a662f68:[0xadf,0xb01],
 0xfffffe000a663018:[0x2e6,0xcc2],0xfffffe000a663090:[0x22f],0xfffffe000a63835c:[0x252],
 0xfffffe000a63932c:[0x1f],0xfffffe000a639bb0:[0x22e],0xfffffe000a63c478:[0x2e3,0x2e6],
 0xfffffe000a63c4e4:[0xe21],0xfffffe000a63c51c:[0x572,0x590],0xfffffe000a63de40:[0x572,0x590],
 0xfffffe000a63de5c:[0x590],0xfffffe000a63dea0:[0x22d,0x6b0],0xfffffe000a63def4:[0xa05,0xa91],
 0xfffffe000a63dfe0:[0x22d,0x23f],0xfffffe000a63e068:[0xe5d,0xe65],0xfffffe000a63e090:[0x659],
 0xfffffe000a63e104:[0x659,0x68f],0xfffffe000a63e11c:[0x54e],0xfffffe000a663104:[0x241],
}
RETAGS={0xfffffe000a637150:0xfffffe000a637154,0xfffffe000a637188:0xfffffe000a63718c,
 0xfffffe000a6371cc:0xfffffe000a6371d0,0xfffffe000a63720c:0xfffffe000a637210,
 0xfffffe000a639340:0xfffffe000a639344,0xfffffe000a639374:0xfffffe000a639378,
 0xfffffe000a63c4d8:0xfffffe000a63c4dc,0xfffffe000a63e0b8:0xfffffe000a63e0bc}
FALSE=['native_target_executed','native_PAC_authenticated','whole_dispatcher_reachability_established',
 'native_input_identity_established','native_allocation_identity_established','native_ownership_established',
 'native_locking_established','NUL_termination_guaranteed','original_marker_producer_established',
 'alias_complete_saved_status_writers_established','daemon_kext_transaction_correlated','new_Mach_port_endpoint_established','IDB_modified','full_goal_complete']
DEPS=['kext_port_tools.py','kernel_native_reader.py','recover_kext_cold_init.py','lskd_values_symbolic.py',
 'audit_secure_tunnel_table_insertion.py','userclient_discriminator_origin_checks.json','userclient_discriminator_origin_audit.json',
 'userclient_replacement_bootstrap_checks.json','userclient_replacement_bootstrap_audit.json']

def build():
 k=Kernel();old=json.loads(read(ROOT/'userclient_discriminator_origin_checks.json'));container=old['function_container']
 a,z=(int(container[n],16) for n in ['start','end_exclusive']);raw=k.read(a,z-a)
 assert IMAGE.read(a,z-a)==raw and sha256(raw).hexdigest()==container['sha256'];spans=[]
 for label,(a,z) in SPANS.items():
  b=k.read(a,z-a);assert IMAGE.read(a,z-a)==b;ii=list(CS.disasm(b,a));assert len(ii)*4==len(b)
  spans.append({'label':label,'start':hex(a),'end_exclusive':hex(z),'bytes_hex':b.hex(),
   'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ii]})
 roots={'EL':qword(POOL+0xb70),'ER':qword(POOL+0xa10),'FL':qword(POOL+0x458)-8,'FR':qword(POOL+0x638)-12};rules=[]
 for name,left,right,key,add,base,bias,div in [('allocate','EL','ER',0x32,0xe17,TABLE,0,0xca0c),('search_callback_value','FL','FR',0x87,-0x93,POOL,-4,None)]:
  r=selected(roots[left],roots[right],key,add,base,bias);r.update(name=name,left_name=left,right_name=right);r['original_pointer']=pointer(k,int(r['slot'],16))
  assert (int(r['original_pointer']['target'],16)+bias)&(2**64-1)==int(r['target'],16)
  if div is not None:assert r['original_pointer']['authenticated'] and int(r['original_pointer']['diversity'],16)==div
  rules.append(r)
 transfers=[]
 for name,(a,z) in SPANS.items():
  if name in ['input_root','length_root','node_root','buffer_root','type_switch']:continue
  b=k.read(z,4);assert IMAGE.read(z,4)==b;i=list(CS.disasm(b,z))[0];assert i.mnemonic in ['braa','blraa']
  transfers.append({'ea':hex(z),'bytes_hex':b.hex(),'mnemonic':i.mnemonic,'operands':i.op_str})
 adapter=k.function(int(rules[0]['target'],16));symbols=k.symbols([int(rules[0]['target'],16)])
 assert any(x['name']=='_IOMallocData' for x in symbols[rules[0]['target']])
 return {'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'scope':SCOPE,
  'function_container':container,'dependencies':{n:sha(ROOT/n) for n in DEPS},'spans':spans,'transfers':transfers,
  'branch_pointers':[pointer(k,TABLE+8*j)|{'index':j} for j in sorted({j for jj in BRANCHES.values() for j in jj})],
  'banks':{n:{'address':hex(v),'bytes_hex':IMAGE.read(v,256).hex()} for n,v in roots.items()},'bank_rules':rules,
  'pool_pointers':[pointer(k,POOL+o) for o in [0xb70,0xa10,0x458,0x638]],'allocator_adapter':adapter,'allocator_symbols':symbols,
  'verified_counts':{'source_spans':len(spans),'selected_instructions':sum(len(s['instructions']) for s in spans),'terminal_transfers':len(transfers),
   'bank_rules':len(rules),'bank_input_cases':256*len(rules),'alternate_retag_sites':len(RETAGS),'node_access_extent_bytes':32,'header_bytes':10},
  'conditional_input_reader_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
