#!/usr/bin/env python3
"""Pin internal node transcode, terminal record, zero fill and publication.
O(B+I) extraction time/space; original and normalized sources only.
"""
import json
from hashlib import sha256
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,TABLE,qword
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read,sha

P='userclient_serializer_emission'
SCOPE='Conditional finite stable-list node-byte transcode, exact terminal tag/type/length and zero payload, output pointer/extent publication and saved callback. Original metadata-record construction, native allocation/storage/PAC/locking and daemon transaction identity remain unknown.'
SPANS={'copy_setup':(0xfffffe000a65f914,0xfffffe000a65f9a4),
 'node_gate':(0xfffffe000a6600b0,0xfffffe000a660194),'node_setup':(0xfffffe000a66019c,0xfffffe000a660200),
 'node_step':(0xfffffe000a660208,0xfffffe000a660298),'node_bridge':(0xfffffe000a6602a0,0xfffffe000a6602d4),
 'node_advance':(0xfffffe000a660060,0xfffffe000a6600a8),'header':(0xfffffe000a65f9ac,0xfffffe000a65fdb8),
 'zero_setup':(0xfffffe000a65fdc0,0xfffffe000a65fe04),'zero_step':(0xfffffe000a65fe0c,0xfffffe000a65fe68),
 'publish':(0xfffffe000a65fe70,0xfffffe000a65fe94),'return':(0xfffffe000a65fe9c,0xfffffe000a65fea4)}
BRANCHES={0xfffffe000a65f94c:[0x2a7,0x35a],0xfffffe000a66018c:[0x27d,0x2c2],
 0xfffffe000a6601e8:[0x61f],0xfffffe000a660290:[0x61d,0x61f],0xfffffe000a6602bc:[0x2c2],
 0xfffffe000a6600a0:[0x2a7,0x35a],0xfffffe000a65fd98:[0xc7d,0xc80],0xfffffe000a65fdf8:[0x4ce],
 0xfffffe000a65fe60:[0x4b8,0x4ce],0xfffffe000a65fe80:[0x614]}
RETAGS={a:a+4 for a in [0xfffffe000a660224,0xfffffe000a66023c,
 0xfffffe000a65fa00,0xfffffe000a65fa5c,0xfffffe000a65fa90,0xfffffe000a65fac4,
 0xfffffe000a65fb34,0xfffffe000a65fb70,0xfffffe000a65fc48,0xfffffe000a65fc98,
 0xfffffe000a65fcd8,0xfffffe000a65fd18,0xfffffe000a65fe28]}
FALSE=['native_target_executed','IDB_modified','native_PAC_authenticated','native_allocation_capacity_established',
 'native_list_stability_established','original_metadata_record_construction_established','complete_containing_function_established',
 'daemon_kext_transaction_correlated','new_Mach_port_endpoint_established','full_goal_complete']
DEPS=['userclient_serializer_extent_checks.json','userclient_serializer_extent_audit.json',
 'userclient_auxiliary_copy_checks.json','userclient_auxiliary_copy_audit.json','userclient_record_metadata_checks.json',
 'userclient_record_metadata_audit.json','audit_userclient_auxiliary_copy.py','audit_userclient_record_metadata.py',
 'audit_secure_tunnel_table_insertion.py','audit_userclient_input_reader.py','lskd_values_symbolic.py','kext_port_tools.py','kernel_native_reader.py']

def build():
 k=Kernel();prior=json.loads(read(ROOT/'userclient_serializer_extent_checks.json'));c=prior['function_container']
 a,z=(int(c[n],16) for n in ['start','end_exclusive']);b=k.read(a,z-a)
 assert b==IMAGE.read(a,z-a) and sha256(b).hexdigest()==c['sha256']
 spans=[];transfers=[]
 for label,(a,z) in SPANS.items():
  b=k.read(a,z-a);assert b==IMAGE.read(a,z-a);ii=list(CS.disasm(b,a));assert len(ii)*4==len(b)
  spans.append({'label':label,'start':hex(a),'end_exclusive':hex(z),'bytes_hex':b.hex(),
   'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ii]})
  b=k.read(z,4);assert b==IMAGE.read(z,4);i=next(CS.disasm(b,z));assert i.mnemonic=='braa'
  transfers.append({'label':label,'ea':hex(z),'bytes_hex':b.hex(),'mnemonic':i.mnemonic,'operands':i.op_str})
 ps=[pointer(k,TABLE+8*j)|{'index':j} for j in sorted({0x161}|{j for js in BRANCHES.values() for j in js})]
 for p in ps:assert int(p['target'],16)==qword(TABLE+8*p['index'])
 return {'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'scope':SCOPE,
  'function_container':c,'dependencies':{n:sha(ROOT/n) for n in DEPS},'spans':spans,'transfers':transfers,'branch_pointers':ps,
  'verified_counts':{'source_spans':len(spans),'selected_instructions':sum(len(s['instructions']) for s in spans),
   'terminal_transfers':len(transfers),'original_branch_pointers':len(ps),'nominal_pointer_guards':len(RETAGS)},
  'conditional_serializer_emission_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
