#!/usr/bin/env python3
"""Capture the selected query scalar writer and its publication request.
O(B+I) extraction time/space; no target execution or IDB mutation.
"""
import json
from hashlib import sha256
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,TABLE,qword
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read,sha

P='userclient_query_writer'
SCOPE='Conditional composition of the three query constructor requests with the alternate protected header/type/scalar writer and exact subsequent publication-request frontier. Native storage, PAC, pointer-retag alternatives, actual list publication/order/replacement, complete command semantics and daemon transaction identity remain unknown.'
SPANS={
 'query_writer_setup':(0xfffffe000a654ad8,0xfffffe000a654b94),
 'query_word_writer':(0xfffffe000a654c68,0xfffffe000a654dc8),
 'query_type_writer':(0xfffffe000a654fcc,0xfffffe000a655064),
 'query_length_bridge':(0xfffffe000a654c48,0xfffffe000a654c60),
 'query_scalar_gate':(0xfffffe000a654dd0,0xfffffe000a654e30),
 'query_scalar_bridge':(0xfffffe000a654e38,0xfffffe000a654e6c),
 'query_publication_request':(0xfffffe000a655cb8,0xfffffe000a655d34),
 'query_lookup_entry':(0xfffffe000a662ab8,0xfffffe000a662afc)}
BRANCHES={0xfffffe000a654b8c:[0x439],0xfffffe000a654c68:[0x13c,0x165,0x129],
 0xfffffe000a655044:[0x2c9],0xfffffe000a654c48:[0x439],
 0xfffffe000a654e18:[0x871,0xc44],0xfffffe000a654e48:[0x2c9],
 0xfffffe000a655ce4:[0x49a],0xfffffe000a662ac0:[0x6c],0xfffffe000a662ae8:[0x630,0x63e]}
RETAGS={0xfffffe000a654c90:0xfffffe000a654c94,0xfffffe000a654ce0:0xfffffe000a654ce4,
 0xfffffe000a654d2c:0xfffffe000a654d30,0xfffffe000a654d88:0xfffffe000a654d8c}
DEPS=['userclient_query_records_checks.json','userclient_query_records_audit.json',
 'userclient_record_writer_checks.json','userclient_record_writer_audit.json',
 'userclient_record_metadata_checks.json','userclient_record_metadata_audit.json',
 'audit_userclient_query_records.py','audit_userclient_record_metadata.py',
 'audit_secure_tunnel_table_insertion.py','lskd_values_symbolic.py',
 'kext_port_tools.py','kernel_native_reader.py','recover_kext_cold_init.py']
FALSE=['native_target_executed','IDB_modified','native_PAC_authenticated','native_storage_identity_established',
 'native_allocator_effects_established','alternate_pointer_retag_paths_established',
 'query_list_publication_established','query_record_order_established','whole_command_semantics_established',
 'daemon_kext_transaction_correlated','new_Mach_port_endpoint_established','full_goal_complete']

def build():
 k=Kernel();prior=json.loads(read(ROOT/'userclient_query_records_checks.json'));container=prior['function_container']
 a,z=(int(container[n],16) for n in ['start','end_exclusive']);raw=k.read(a,z-a)
 assert raw==IMAGE.read(a,z-a) and sha256(raw).hexdigest()==container['sha256']
 spans=[];transfers=[]
 for label,(a,z) in SPANS.items():
  b=k.read(a,z-a);assert b==IMAGE.read(a,z-a);ii=list(CS.disasm(b,a));assert len(ii)*4==len(b)
  spans.append({'label':label,'start':hex(a),'end_exclusive':hex(z),'bytes_hex':b.hex(),
   'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ii]})
  b=k.read(z,4);assert b==IMAGE.read(z,4);i=next(CS.disasm(b,z));assert i.mnemonic=='braa'
  transfers.append({'label':label,'ea':hex(z),'bytes_hex':b.hex(),'mnemonic':i.mnemonic,'operands':i.op_str})
 bp=[pointer(k,TABLE+8*j)|{'index':j} for j in sorted({j for js in BRANCHES.values() for j in js})]
 for r in bp:assert int(r['target'],16)==qword(TABLE+8*r['index'])
 return {'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,
  'scope':SCOPE,'dependencies':{n:sha(ROOT/n) for n in DEPS},'function_container':container,
  'spans':spans,'transfers':transfers,'branch_pointers':bp,
  'verified_counts':{'source_spans':len(spans),'selected_instructions':sum(len(s['instructions']) for s in spans),
   'terminal_transfers':len(transfers),'original_branch_pointers':len(bp),'nominal_pointer_guards':len(RETAGS),
   'request_cases':3,'record_extent_bytes':14},
  'conditional_query_writer_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
