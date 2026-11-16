#!/usr/bin/env python3
"""Pin auxiliary serializer extent checks, allocation and copy setup.
O(B+I+256R) extraction time/space; static image/collection comparison.
"""
import json
from hashlib import sha256
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,TABLE,qword,selected
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read,sha

P='userclient_serializer_extent'
SCOPE='Conditional serializer entry, node-extent overflow step and accumulation, strict padding/alignment gate, exact IOMallocData request/result channels, node-copy/padding dispatch and source-composed consumer length admission. Node-byte serialization, complete list traversal/publication, native allocator effects and daemon transaction identity remain unknown.'
SPANS={'entry':(0xfffffe000a65f3f0,0xfffffe000a65f444),'head':(0xfffffe000a65f44c,0xfffffe000a65f490),
 'extent':(0xfffffe000a65f498,0xfffffe000a65f57c),'advance':(0xfffffe000a65f584,0xfffffe000a65f5e0),
 'size':(0xfffffe000a65f5e8,0xfffffe000a65f6fc),'request':(0xfffffe000a65f704,0xfffffe000a65f8b0),
 'result':(0xfffffe000a65f8b4,0xfffffe000a65f90c),'copy_setup':(0xfffffe000a65f914,0xfffffe000a65f9a4),
 'consumer_callback':(0xfffffe000a65feac,0xfffffe000a65ff34)}
BRANCHES={0xfffffe000a65f3fc:[0x161],0xfffffe000a65f430:[0xe10,0xe2f],0xfffffe000a65f488:[0x5c7,0x5e2],
 0xfffffe000a65f56c:[0xd5f,0xd82],0xfffffe000a65f5d8:[0x5c7,0x5e2],0xfffffe000a65f6ec:[0x217,0x237],
 0xfffffe000a65f900:[0x60a,0x614],0xfffffe000a65f94c:[0x2a7,0x35a],0xfffffe000a65fef8:[0xb6b,0xbd0]}
BANK_PCS=(0xfffffe000a65f87c,0xfffffe000a65f88c,0xfffffe000a65f8a8)
FALSE=['native_target_executed','IDB_modified','native_PAC_authenticated','complete_node_serialization_established',
 'complete_list_traversal_established','complete_serializer_publication_established','native_allocator_effects_established',
 'daemon_kext_transaction_correlated','new_Mach_port_endpoint_established','full_goal_complete']
DEPS=['userclient_query_records_checks.json','userclient_query_records_audit.json','userclient_auxiliary_copy_checks.json',
 'userclient_auxiliary_copy_audit.json','audit_userclient_query_records.py','audit_userclient_record_metadata.py',
 'audit_secure_tunnel_table_insertion.py','audit_userclient_input_reader.py','lskd_values_symbolic.py','kext_port_tools.py','kernel_native_reader.py']

def build():
 k=Kernel();prior=json.loads(read(ROOT/'userclient_query_records_checks.json'));c=prior['function_container']
 a,z=(int(c[n],16) for n in ['start','end_exclusive']);b=k.read(a,z-a)
 assert b==IMAGE.read(a,z-a) and sha256(b).hexdigest()==c['sha256']
 spans=[];transfers=[]
 for label,(a,z) in SPANS.items():
  b=k.read(a,z-a);assert b==IMAGE.read(a,z-a);ii=list(CS.disasm(b,a));assert len(ii)*4==len(b)
  spans.append({'label':label,'start':hex(a),'end_exclusive':hex(z),'bytes_hex':b.hex(),
   'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ii]})
  b=k.read(z,4);assert b==IMAGE.read(z,4);i=next(CS.disasm(b,z));assert i.mnemonic==('blraa' if label=='request' else 'braa')
  transfers.append({'label':label,'ea':hex(z),'bytes_hex':b.hex(),'mnemonic':i.mnemonic,'operands':i.op_str})
 banks={n:{'address':hex(a),'bytes_hex':IMAGE.read(a,256).hex()} for n,a in [('L',0xfffffe0007941f60),('R',0xfffffe000794a0d0)]}
 for r in banks.values():assert k.read(int(r['address'],16),256).hex()==r['bytes_hex']
 r=selected(0xfffffe0007941f60,0xfffffe000794a0d0,5,0xee3,TABLE,0);r.update(name='allocate',original_pointer=pointer(k,int(r['slot'],16)))
 assert int(r['original_pointer']['target'],16)==int(r['target'],16)==0xfffffe000c4ba60c
 assert int(r['original_pointer']['diversity'],16)==0xca0c
 ps=[pointer(k,TABLE+8*j)|{'index':j} for j in sorted({j for js in BRANCHES.values() for j in js})]
 for p in ps:assert int(p['target'],16)==qword(TABLE+8*p['index'])
 syms=k.symbols([0xfffffe000c4ba60c]);assert any(s['name']=='_IOMallocData' for s in syms['0xfffffe000c4ba60c'])
 return {'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'scope':SCOPE,
  'function_container':c,'dependencies':{n:sha(ROOT/n) for n in DEPS},'spans':spans,'transfers':transfers,
  'banks':banks,'bank_rules':[r],'branch_pointers':ps,'exact_symbols':syms,
  'verified_counts':{'source_spans':len(spans),'selected_instructions':sum(len(s['instructions']) for s in spans),
   'terminal_transfers':len(transfers),'original_branch_pointers':len(ps),'bank_rules':1,'bank_input_cases':256},
  'conditional_serializer_extent_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
