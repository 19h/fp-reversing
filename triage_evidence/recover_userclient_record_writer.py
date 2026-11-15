#!/usr/bin/env python3
"""Capture protected record header writer and selected type-6685 payload path.
O(B+I) extraction time/space. No target execution or IDB mutation.
"""
import json
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,TABLE,qword
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read,sha

P='userclient_record_writer'
SCOPE='Conditional composed post-header node construction, exact protected ten-byte record header production, type-6685 zero/nonzero payload dispatch, protected reverse-copy step and publication-request frontier. Metadata production from original input, actual list publication, native pointer authentication/storage identity/lifetime/locking, original field identity and daemon correlation remain unknown.'
SPANS={
 'phase_token':(0xfffffe000a6355f4,0xfffffe000a6355fc),
 'saved_writer_controls':(0xfffffe000a635af8,0xfffffe000a635b20),
 'word_writer':(0xfffffe000a654c68,0xfffffe000a654dc8),
 'length_bridge':(0xfffffe000a654c48,0xfffffe000a654c60),
 'type_writer':(0xfffffe000a65506c,0xfffffe000a655110),
 'type_primary_gate':(0xfffffe000a654e74,0xfffffe000a654e80),
 'type_secondary_gate':(0xfffffe000a655434,0xfffffe000a655448),
 'payload_size_gate':(0xfffffe000a655d38,0xfffffe000a655df0),
 'payload_request':(0xfffffe000a655df8,0xfffffe000a655e28),
 'payload_copy':(0xfffffe000a655e30,0xfffffe000a655eec),
}
BRANCHES={0xfffffe000a654c68:[0x152,0x16c],0xfffffe000a6550f0:[0x2c9],
 0xfffffe000a654c48:[0x439],0xfffffe000a655de0:[0x757,0x76a],
 0xfffffe000a655e20:[0x8d0],0xfffffe000a655ee4:[0x87b,0x8d0]}
RETAGS={0xfffffe000a654c90:0xfffffe000a654c94,0xfffffe000a654ce0:0xfffffe000a654ce4,
 0xfffffe000a654d2c:0xfffffe000a654d30,0xfffffe000a654d88:0xfffffe000a654d8c,
 0xfffffe000a655e50:0xfffffe000a655e54,0xfffffe000a655e68:0xfffffe000a655e6c}
TRANSFERS=['word_writer','length_bridge','type_writer','payload_size_gate','payload_request','payload_copy']
DEPS=['kext_port_tools.py','kernel_native_reader.py','recover_kext_cold_init.py','lskd_values_symbolic.py',
 'audit_secure_tunnel_table_insertion.py','recover_userclient_record_nodes.py','audit_userclient_record_nodes.py',
 'userclient_record_nodes_checks.json','userclient_record_nodes_audit.json',
 'userclient_input_reader_checks.json','userclient_input_reader_audit.json']
FALSE=['native_target_executed','native_PAC_authenticated','whole_dispatcher_reachability_established',
 'complete_parser_body_established','list_publication_established','metadata_producer_established',
 'native_input_identity_established','NUL_termination_guaranteed','native_allocation_identity_established',
 'native_ownership_established','native_locking_established','original_marker_producer_established',
 'daemon_kext_transaction_correlated','new_Mach_port_endpoint_established','IDB_modified','full_goal_complete']

def build():
 k=Kernel();prior=json.loads(read(ROOT/'userclient_record_nodes_checks.json'));container=prior['function_container']
 a,z=(int(container[n],16) for n in ['start','end_exclusive']);raw=k.read(a,z-a)
 from hashlib import sha256
 assert IMAGE.read(a,z-a)==raw and sha256(raw).hexdigest()==container['sha256'];spans=[]
 for label,(a,z) in SPANS.items():
  b=k.read(a,z-a);assert b==IMAGE.read(a,z-a);ii=list(CS.disasm(b,a));assert len(ii)*4==len(b)
  spans.append({'label':label,'start':hex(a),'end_exclusive':hex(z),'bytes_hex':b.hex(),
   'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ii]})
 transfers=[]
 for label in TRANSFERS:
  pc=SPANS[label][1];b=k.read(pc,4);assert b==IMAGE.read(pc,4);i=next(CS.disasm(b,pc));assert i.mnemonic=='braa'
  transfers.append({'ea':hex(pc),'bytes_hex':b.hex(),'mnemonic':i.mnemonic,'operands':i.op_str})
 bp=[pointer(k,TABLE+8*j)|{'index':j} for j in sorted({j for js in BRANCHES.values() for j in js})]
 for r in bp:assert int(r['target'],16)==qword(TABLE+8*r['index'])
 # Token reaches the saved-control arithmetic through a straight-line region.
 from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN,CS_GRP_JUMP,CS_GRP_CALL,CS_GRP_RET,CS_GRP_INT,CS_GRP_IRET
 dec=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);dec.detail=True
 a,z=SPANS['phase_token'][1],SPANS['saved_writer_controls'][0];b=k.read(a,z-a);assert b==IMAGE.read(a,z-a)
 ii=list(dec.disasm(b,a));assert len(ii)*4==len(b)
 assert all(not {CS_GRP_JUMP,CS_GRP_CALL,CS_GRP_RET,CS_GRP_INT,CS_GRP_IRET}&set(i.groups)
  and not i.mnemonic.startswith(('b','ret')) and not {'w15','x15','sp','wsp'}&{i.reg_name(r) for r in i.regs_access()[1]} for i in ii)
 inventory=[]
 from capstone.arm64 import ARM64_OP_MEM
 for i in dec.disasm(raw,int(container['start'],16)):
  for o in i.operands:
   if o.type==ARM64_OP_MEM and i.reg_name(o.mem.base)=='sp' and o.mem.disp in [0x570,0x60c]:
    inventory.append({'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str,'offset':hex(o.mem.disp)})
 return {'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'scope':SCOPE,
  'dependencies':{n:sha(ROOT/n) for n in DEPS},'function_container':container,'spans':spans,'transfers':transfers,
  'branch_pointers':bp,'token_retention_envelope':{'start':hex(a),'end_exclusive':hex(z),'bytes_hex':b.hex(),
   'instructions':len(ii),'token_and_SP_preserved':True,'no_control_transfers':True},
  'literal_stack_cell_inventory':inventory,
  'verified_counts':{'source_spans':len(spans),'selected_instructions':sum(len(s['instructions']) for s in spans),
   'terminal_transfers':len(transfers),'header_bytes':10,'retag_sites':len(RETAGS),'token_retention_instructions':len(ii),
   'inventoried_stack_cells':2},'conditional_record_writer_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
