#!/usr/bin/env python3
"""Freeze parser-caller lookup, scalar reader, command and status source.
O(B+I+256R) extraction time/space. No target execution or IDB mutation.
"""
import json
from hashlib import sha256
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,TABLE,qword
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read,sha

P='userclient_command_dispatch'
SCOPE='Conditional parser-caller status split, caller-specific tagged-node search, protected ten-byte header and four-byte scalar reader, two-value command switch, first-command reader handoff, second-command entry and saved-status cleanup gate. Full native entry reachability, successful daemon correlation, native pointer authentication/storage/ownership/locking, staged-buffer retirement and second-command body semantics remain unknown.'
SPANS={
 'node_output_root':(0xfffffe000a635c3c,0xfffffe000a635c44),
 'node_buffer_root':(0xfffffe000a635c64,0xfffffe000a635c6c),
 'container_root':(0xfffffe000a635e74,0xfffffe000a635e7c),
 'caller_status':(0xfffffe000a656c0c,0xfffffe000a656c40),
 'failure_second':(0xfffffe000a65f35c,0xfffffe000a65f3b0),
 'field_gate':(0xfffffe000a656c48,0xfffffe000a656c9c),
 'field_request':(0xfffffe000a656ca4,0xfffffe000a656cf8),
 'field_result':(0xfffffe000a656d00,0xfffffe000a656d44),
 'node_fields':(0xfffffe000a656d4c,0xfffffe000a656d98),
 'header_extent':(0xfffffe000a656da0,0xfffffe000a656e44),
 'header_prepare':(0xfffffe000a656e4c,0xfffffe000a656eec),
 'tag_return':(0xfffffe000a6382a4,0xfffffe000a6382f4),
 'type_return':(0xfffffe000a6370b0,0xfffffe000a637124),
 'length_extent':(0xfffffe000a637480,0xfffffe000a637510),
 'type_gate':(0xfffffe000a637518,0xfffffe000a637564),
 'payload_prepare':(0xfffffe000a63756c,0xfffffe000a6375fc),
 'payload_return':(0xfffffe000a63acd4,0xfffffe000a63acec),
 'scalar_return':(0xfffffe000a63acf4,0xfffffe000a63ad38),
 'command_gate':(0xfffffe000a63ad40,0xfffffe000a63ad64),
 'unsupported':(0xfffffe000a63ddd0,0xfffffe000a63dde8),
 'other_type_gate':(0xfffffe000a63a614,0xfffffe000a63a638),
 'first_command':(0xfffffe000a63dd14,0xfffffe000a63dd7c),
 'second_command_entry':(0xfffffe000a63ad64,0xfffffe000a63ad80),
 'cleanup_gate':(0xfffffe000a656f04,0xfffffe000a656f48),
 'null_container':(0xfffffe000a665e54,0xfffffe000a665e8c),
}
REUSED=['search_entry','search_nonnull','search_node','node_decode_prepare','word_bridge','decode_word',
 'tag_match','search_next','search_result','search_callback','decode_type','length_bridge']
BRANCHES={
 0xfffffe000a656c30:[0x68,0x71c],0xfffffe000a65f3a0:[0x840,0xb11],
 0xfffffe000a656c94:[0x300,0x316],0xfffffe000a656cb4:[0x49a],
 0xfffffe000a656d34:[0x6ba,0x95d],0xfffffe000a656d84:[0x840,0x874],
 0xfffffe000a656e34:[0x840,0xe44],0xfffffe000a656eb0:[0x22f],
 0xfffffe000a6382b4:[0x252],0xfffffe000a63711c:[0x22e],
 0xfffffe000a6374f8:[0x69d,0x6ba],0xfffffe000a637554:[0x6ba,0x6cc],
 0xfffffe000a6375c4:[0x22e],0xfffffe000a63ace4:[0x48e],
 0xfffffe000a63ad1c:[0x840,0xb47],0xfffffe000a63dd60:[0x8c4,0x8ed],
 0xfffffe000a656f3c:[0x49c,0x4a7],0xfffffe000a665e74:[0x49c],
 0xfffffe000a662ac0:[0x6b],0xfffffe000a662ae8:[0x630,0x63e],
 0xfffffe000a662bf4:[0x52d],0xfffffe000a662c28:[0x50c,0x50d],
 0xfffffe000a662c88:[0x22f],0xfffffe000a656ef4:[0xe07],
 0xfffffe000a63713c:[0x181,0x1c5,0x1d0,0x1b7],
 0xfffffe000a63d66c:[0xeb6,0xe91],0xfffffe000a63d694:[0x52d],
 0xfffffe000a662c50:[0x63e],0xfffffe000a63932c:[0x3f],0xfffffe000a63712c:[0xe07],
}
RETAGS={0xfffffe000a637150:0xfffffe000a637154,0xfffffe000a637188:0xfffffe000a63718c,
 0xfffffe000a6371cc:0xfffffe000a6371d0,0xfffffe000a63720c:0xfffffe000a637210,
 0xfffffe000a639340:0xfffffe000a639344,0xfffffe000a639374:0xfffffe000a639378}
BANK_PCS={'search_callback_value':(0xfffffe000a662b2c,0xfffffe000a662b3c,0xfffffe000a662b54)}
NO_TRANSFER={'node_output_root','node_buffer_root','container_root','command_gate','unsupported','other_type_gate','second_command_entry'}
FALSE=['native_target_executed','native_PAC_authenticated','whole_dispatcher_reachability_established',
 'native_input_identity_established','native_allocation_identity_established','native_ownership_established',
 'native_locking_established','staged_buffer_retirement_established','second_command_body_established',
 'daemon_kext_transaction_correlated','new_Mach_port_endpoint_established','IDB_modified','full_goal_complete']
DEPS=['kext_port_tools.py','kernel_native_reader.py','recover_kext_cold_init.py','lskd_values_symbolic.py',
 'audit_secure_tunnel_table_insertion.py','audit_userclient_input_reader.py','recover_userclient_input_reader.py',
 'audit_userclient_record_metadata.py','recover_userclient_record_metadata.py',
 'userclient_container_staging_checks.json','userclient_container_staging_audit.json',
 'userclient_input_reader_checks.json','userclient_input_reader_audit.json',
 'userclient_record_publication_checks.json','userclient_record_publication_audit.json',
 'userclient_parser_cleanup_checks.json','userclient_parser_cleanup_audit.json']

def build():
 k=Kernel();prior=json.loads(read(ROOT/'userclient_input_reader_checks.json'));container=prior['function_container']
 a,z=(int(container[n],16) for n in ['start','end_exclusive']);b=k.read(a,z-a)
 assert b==IMAGE.read(a,z-a) and sha256(b).hexdigest()==container['sha256'];ranges=dict(SPANS)
 for label in REUSED:
  row=next(s for s in prior['spans'] if s['label']==label);ranges[label]=(int(row['start'],16),int(row['end_exclusive'],16))
 spans=[];transfers=[]
 for label,(a,z) in ranges.items():
  b=k.read(a,z-a);assert b==IMAGE.read(a,z-a);ii=list(CS.disasm(b,a));assert len(ii)*4==len(b)
  spans.append({'label':label,'start':hex(a),'end_exclusive':hex(z),'bytes_hex':b.hex(),
   'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ii]})
  if label not in NO_TRANSFER:
   b=k.read(z,4);assert b==IMAGE.read(z,4);i=next(CS.disasm(b,z));assert i.mnemonic=='braa'
   transfers.append({'ea':hex(z),'bytes_hex':b.hex(),'mnemonic':i.mnemonic,'operands':i.op_str})
 rules=[r for r in prior['bank_rules'] if r['name']=='search_callback_value'];assert len(rules)==1
 banks={n:prior['banks'][n] for n in ['FL','FR']}
 for row in banks.values():assert k.read(int(row['address'],16),256)==IMAGE.read(int(row['address'],16),256)==bytes.fromhex(row['bytes_hex'])
 for r in rules:
  assert pointer(k,int(r['slot'],16))==r['original_pointer']
  assert (int(r['original_pointer']['target'],16)+int(r['bias'],16))%(2**64)==int(r['target'],16)
 bp=[pointer(k,TABLE+8*j)|{'index':j} for j in sorted({j for js in BRANCHES.values() for j in js})]
 for r in bp:assert int(r['target'],16)==qword(TABLE+8*r['index'])
 return {'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,
  'scope':SCOPE,'function_container':container,'dependencies':{n:sha(ROOT/n) for n in DEPS},
  'spans':spans,'transfers':transfers,'branch_pointers':bp,'banks':banks,'bank_rules':rules,
  'command_field':{'requested_encoded_tag_u32':'0x45e5918e','decoded_tag_u32':'0x744b91e8',
   'transformed_type_u16':'0xa129','payload_bytes':4,'header_bytes':10,
   'command_cases':[{'encoded_u32':'0xb9f74ad8','decoded_u32':'0x88594abe','target':'0xfffffe000a63dd14'},
    {'encoded_u32':'0x4245a078','decoded_u32':'0x73eba01e','target':'0xfffffe000a63ad64'}],
   'other_value_target':'0xfffffe000a63ddd0'},
  'verified_counts':{'source_spans':len(spans),'selected_instructions':sum(len(s['instructions']) for s in spans),
   'terminal_transfers':len(transfers),'bank_rules':len(rules),'bank_input_cases':256*len(rules),
   'alternate_retag_sites':len(RETAGS),'header_bytes':10,'scalar_bytes':4,'command_values':2},
  'conditional_command_dispatch_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
