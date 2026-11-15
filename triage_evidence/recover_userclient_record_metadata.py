#!/usr/bin/env python3
"""Freeze staged-header metadata, bounds and selected payload/cursor source.
O(B+I) extraction time/space. No target execution or IDB mutation.
"""
import json
from hashlib import sha256
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,TABLE,qword
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read,sha

P='userclient_record_metadata'
SCOPE='Conditional staged-header byte provenance, tag/type/length decoding, header/body extent predicates, selected type0x6685 payload pointer and next cursor, and metadata return to the node gate. Native input identity, pointer authentication, other type handlers, complete failure cleanup, native ownership/locking and daemon correlation remain unknown.'
SPANS={
 'input_alias_root':(0xfffffe000a635efc,0xfffffe000a635f04),
 'parser_cursor_gate':(0xfffffe000a64213c,0xfffffe000a64217c),
 'parser_input_gate':(0xfffffe000a6421e0,0xfffffe000a642244),
 'header_extent':(0xfffffe000a64224c,0xfffffe000a64232c),
 'header_prepare':(0xfffffe000a642334,0xfffffe000a6423bc),
 'word_bridge':(0xfffffe000a656ef4,0xfffffe000a656efc),
 'decode_word':(0xfffffe000a63713c,0xfffffe000a63724c),
 'tag_return':(0xfffffe000a638dbc,0xfffffe000a638e0c),
 'decode_type':(0xfffffe000a639310,0xfffffe000a6393c4),
 'type_return':(0xfffffe000a639dc4,0xfffffe000a639e38),
 'length_bridge':(0xfffffe000a63712c,0xfffffe000a637134),
 'length_extent':(0xfffffe000a6390b8,0xfffffe000a639160),
 'type_first_gate':(0xfffffe000a639168,0xfffffe000a639178),
 'type_selected_gate':(0xfffffe000a63a784,0xfffffe000a63a790),
 'body_publish':(0xfffffe000a63dc9c,0xfffffe000a63dccc),
 'metadata_return':(0xfffffe000a63dcd4,0xfffffe000a63dd10),
 'metadata_outcome_gate':(0xfffffe000a6423c4,0xfffffe000a6423f0),
 'record_kind_gate':(0xfffffe000a6423f8,0xfffffe000a642450),
}
BRANCHES={0xfffffe000a642174:[0x87f,0x893],0xfffffe000a642218:[0x560,0x593],
 0xfffffe000a64231c:[0x560,0x63c],0xfffffe000a642388:[0x22f],0xfffffe000a656ef4:[0xe07],
 0xfffffe000a63713c:[0x17a,0x1a9],0xfffffe000a638dd0:[0x252],0xfffffe000a63932c:[0x1c],
 0xfffffe000a639e30:[0x22e],0xfffffe000a63712c:[0xe07],0xfffffe000a639140:[0xe40,0xe7d],
 0xfffffe000a63dcc4:[0x514],0xfffffe000a63dcfc:[0x54d],0xfffffe000a6423e8:[0x4a9,0x88c],
 0xfffffe000a642448:[0x449,0x46d]}
RETAGS={0xfffffe000a637150:0xfffffe000a637154,0xfffffe000a637188:0xfffffe000a63718c,
 0xfffffe000a6371cc:0xfffffe000a6371d0,0xfffffe000a63720c:0xfffffe000a637210,
 0xfffffe000a639340:0xfffffe000a639344,0xfffffe000a639374:0xfffffe000a639378,
 0xfffffe000a63dcb8:0xfffffe000a63dcbc}
NO_TRANSFER={'input_alias_root','type_first_gate','type_selected_gate'}
FALSE=['native_target_executed','native_PAC_authenticated','whole_dispatcher_reachability_established',
 'complete_parser_body_established','native_input_identity_established','native_allocation_identity_established',
 'native_ownership_established','native_locking_established','all_type_handlers_established',
 'complete_failure_cleanup_established','daemon_kext_transaction_correlated','new_Mach_port_endpoint_established',
 'IDB_modified','full_goal_complete']
DEPS=['kext_port_tools.py','kernel_native_reader.py','recover_kext_cold_init.py','lskd_values_symbolic.py',
 'audit_secure_tunnel_table_insertion.py','audit_userclient_input_reader.py','recover_userclient_input_reader.py',
 'userclient_container_staging_checks.json','userclient_container_staging_audit.json',
 'userclient_input_reader_checks.json','userclient_input_reader_audit.json',
 'userclient_record_nodes_checks.json','userclient_record_nodes_audit.json',
 'userclient_record_publication_checks.json','userclient_record_publication_audit.json']

def build():
 k=Kernel();prior=json.loads(read(ROOT/'userclient_container_staging_checks.json'));container=prior['function_container']
 a,z=(int(container[n],16) for n in ['start','end_exclusive']);b=k.read(a,z-a)
 assert b==IMAGE.read(a,z-a) and sha256(b).hexdigest()==container['sha256'];spans=[];transfers=[]
 cells={'candidate_cursor':'[x4, #0xcf8]','tag':'[x4, #0xa18]','type':'[x4, #0x2a0]',
  'length':'[x4, #0xa64]','payload':'[x2, #0x280]','staged_pointer':'[x2, #0x3d8]',
  'parser_cursor':'[sp, #0xa80]','record_start':'[sp, #0xbd8]','staged_pointer_alias':'[sp, #0x890]'}
 accesses={name:[] for name in cells}
 for i in CS.disasm(b,a):
  for name,syntax in cells.items():
   if syntax in i.op_str:accesses[name].append({'ea':hex(i.address),'bytes_hex':bytes(i.bytes).hex(),
    'mnemonic':i.mnemonic,'operands':i.op_str})
 for label,(a,z) in SPANS.items():
  b=k.read(a,z-a);assert b==IMAGE.read(a,z-a);ii=list(CS.disasm(b,a));assert len(ii)*4==len(b)
  spans.append({'label':label,'start':hex(a),'end_exclusive':hex(z),'bytes_hex':b.hex(),
   'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ii]})
  if label not in NO_TRANSFER:
   b=k.read(z,4);assert b==IMAGE.read(z,4);i=next(CS.disasm(b,z));assert i.mnemonic=='braa'
   transfers.append({'ea':hex(z),'bytes_hex':b.hex(),'mnemonic':i.mnemonic,'operands':i.op_str})
 bp=[pointer(k,TABLE+8*j)|{'index':j} for j in sorted({j for js in BRANCHES.values() for j in js})]
 for r in bp:assert int(r['target'],16)==qword(TABLE+8*r['index'])
 return {'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,
  'scope':SCOPE,'function_container':container,'dependencies':{n:sha(ROOT/n) for n in DEPS},
  'spans':spans,'transfers':transfers,'branch_pointers':bp,'literal_cell_accesses':accesses,
  'verified_counts':{'source_spans':len(spans),'selected_instructions':sum(len(s['instructions']) for s in spans),
   'terminal_transfers':len(transfers),'alternate_retag_sites':len(RETAGS),'header_bytes':10,
   'literal_cell_accesses':sum(map(len,accesses.values()))},
  'conditional_record_metadata_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
