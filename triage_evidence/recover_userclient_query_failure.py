#!/usr/bin/env python3
"""Pin constructor failure custody and selected lower allocation ABI blocks.
O(B+I+256R) extraction time/space; no target execution or database mutation.
"""
import json
import struct
from hashlib import sha256
from capstone.arm64 import ARM64_OP_MEM
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,POOL,TABLE,qword,selected
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from audit_userclient_input_reader import DEC
from verify_daemon_reader_record_payloads_publication import read,sha

P='userclient_query_failure'
SCOPE='Conditional saved allocation-error producer, valid pending-node cleanup requests and callback status custody; explicit node-validity premise boundary; selected typed/data adapter flag, heap and size forwarding. Native allocator outcomes, allocator backend execution, PAC, ownership, locking, whole-command reachability and daemon transaction correlation remain unknown.'
SPANS={
 'failure_status_producer':(0xfffffe000a636678,0xfffffe000a636694),
 'cleanup_gate':(0xfffffe000a664078,0xfffffe000a6640c0),
 'cleanup_data_request':(0xfffffe000a6640c8,0xfffffe000a664134),
 'cleanup_data_return':(0xfffffe000a664138,0xfffffe000a664148),
 'cleanup_node_request':(0xfffffe000a664150,0xfffffe000a6641e4),
 'cleanup_node_return':(0xfffffe000a6641e8,0xfffffe000a664214),
 'constructor_return':(0xfffffe000a66421c,0xfffffe000a66422c),
 'request_return':(0xfffffe000a664234,0xfffffe000a664260),
 'typed_adapter_flags':(0xfffffe000c4ba158,0xfffffe000c4ba16c),
 'typed_lower_prefix':(0xfffffe000bcfeb98,0xfffffe000bcfeba8),
 'typed_statistics_load':(0xfffffe000bcfebac,0xfffffe000bcfebb0),
 'typed_zone_active':(0xfffffe000bcfebc4,0xfffffe000bcfebcc),
 'typed_zone_empty':(0xfffffe000bcfebd0,0xfffffe000bcfebdc),
 'typed_heap_request':(0xfffffe000bcfebe8,0xfffffe000bcfec20),
 'data_heap_request':(0xfffffe000c4ba620,0xfffffe000c4ba638)}
KERNEL_LABELS={n for n in SPANS if n.startswith(('typed_','data_'))}
BRANCHES={0xfffffe000a6640b0:[0xa71,0xa94],0xfffffe000a664140:[0x599],0xfffffe000a6641f4:[0x63d]}
BANK_PCS={'cleanup_data':(0xfffffe000a664108,0xfffffe000a664118,0xfffffe000a66412c),
 'cleanup_node':(0xfffffe000a664188,0xfffffe000a664198,0xfffffe000a6641a8),
 'cleanup_descriptor':(0xfffffe000a6641b4,0xfffffe000a6641c0,0xfffffe000a6641d8)}
FALSE=['native_target_executed','IDB_modified','native_PAC_authenticated','native_allocator_outcome_established',
 'native_ownership_established','native_locking_established','whole_command_reachability_established',
 'null_node_native_failure_reproduced','daemon_kext_transaction_correlated','new_Mach_port_endpoint_established','full_goal_complete']
DEPS=['userclient_query_records_checks.json','userclient_query_records_audit.json','userclient_query_publication_checks.json',
 'userclient_query_publication_audit.json','audit_userclient_query_records.py','audit_userclient_record_metadata.py',
 'audit_userclient_input_reader.py','audit_secure_tunnel_table_insertion.py','lskd_values_symbolic.py',
 'kext_port_tools.py','kernel_native_reader.py','recover_kext_cold_init.py']

def build():
 k=Kernel();old=json.loads(read(ROOT/'userclient_query_records_checks.json'));container=old['function_container']
 a,z=(int(container[n],16) for n in ['start','end_exclusive']);raw=k.read(a,z-a)
 assert raw==IMAGE.read(a,z-a) and sha256(raw).hexdigest()==container['sha256']
 spans=[];transfers=[]
 for label,(a,z) in SPANS.items():
  b=k.read(a,z-a)
  if label not in KERNEL_LABELS:assert b==IMAGE.read(a,z-a)
  ii=list(CS.disasm(b,a));assert len(ii)*4==len(b)
  spans.append({'label':label,'start':hex(a),'end_exclusive':hex(z),'bytes_hex':b.hex(),
   'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ii]})
  if label not in ['failure_status_producer','typed_statistics_load']:
   b=k.read(z,4);i=next(CS.disasm(b,z));assert i.mnemonic in ['braa','blraa','b','bl','cbz']
   if label not in KERNEL_LABELS:assert b==IMAGE.read(z,4)
   transfers.append({'label':label,'ea':hex(z),'bytes_hex':b.hex(),'mnemonic':i.mnemonic,'operands':i.op_str})
 roots={'BL':0xfffffe0007949fd0,'BR':0xfffffe000792ffc0,'TL':0xfffffe0007949dd0,'TR':0xfffffe000792fbc0}
 for a in roots.values():assert k.read(a,256)==IMAGE.read(a,256)
 rules=[]
 for name,l,r,key,add,base,div in [('cleanup_data','BL','BR',0xac,0xf14,TABLE,0x85d),
  ('cleanup_node','TL','TR',0xb4,0xebd,TABLE,0x4d6a),('cleanup_descriptor','BL','BR',0x37,0xaa,POOL,None)]:
  row=selected(roots[l],roots[r],key,add,base,0);row.update(name=name,left_name=l,right_name=r,original_pointer=pointer(k,int(row['slot'],16)))
  assert int(row['original_pointer']['target'],16)==int(row['target'],16)
  if div is not None:assert int(row['original_pointer']['diversity'],16)==div
  rules.append(row)
 desc=int(rules[-1]['target'],16);b=IMAGE.read(desc,64);pn,ps=pointer(k,desc+16),pointer(k,desc+32)
 name,sig=(IMAGE.read(int(p['target'],16),64).split(b'\0')[0] for p in [pn,ps]);flags,size=struct.unpack_from('<II',b,40)
 assert (name,sig,flags,size)==(b'site.FPTTLVNode',b'1121',0x64,32)
 for p,s in [(pn,name),(ps,sig)]:assert k.read(int(p['target'],16),len(s)+1)==s+b'\0'
 assert k.read(desc+40,8)==b[40:48]
 alloc=old['typed_descriptor'];aa=int(alloc['address'],16);assert IMAGE.read(aa,64)==b and aa!=desc
 bp=[pointer(k,TABLE+8*j)|{'index':j} for j in sorted({j for js in BRANCHES.values() for j in js})]
 for p in bp:assert int(p['target'],16)==qword(TABLE+8*p['index'])
 inventory=[]
 for i in DEC.disasm(raw,int(container['start'],16)):
  for o in i.operands:
   if o.type==ARM64_OP_MEM and i.reg_name(o.mem.base)=='sp' and o.mem.disp==0x9ec:
    inventory.append({'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str})
 stores=[r for r in inventory if r['mnemonic'].startswith('st')];assert len(stores)==1 and stores[0]['ea']=='0xfffffe000a636690'
 functions=[]
 for a in [0xfffffe000c4ba154,0xfffffe000bcfeb8c,0xfffffe000c4ba60c]:functions.append(k.function(a))
 symbols=k.symbols([int(rules[j]['target'],16) for j in [0,1]])
 for j,n in [(0,'_IOFreeData'),(1,'_IOFreeTypeImpl')]:assert any(s['name']==n for s in symbols[rules[j]['target']])
 return {'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,
  'scope':SCOPE,'dependencies':{n:sha(ROOT/n) for n in DEPS},'function_container':container,
  'spans':spans,'transfers':transfers,'branch_pointers':bp,'bank_rules':rules,
  'banks':{n:{'address':hex(a),'bytes_hex':IMAGE.read(a,256).hex()} for n,a in roots.items()},
  'cleanup_descriptor':{'address':hex(desc),'normalized64_bytes_hex':b.hex(),'original64_bytes_hex':k.read(desc,64).hex(),
   'name':name.decode(),'signature':sig.decode(),'flags_u32':flags,'size_bytes':size,'name_pointer':pn,'signature_pointer':ps,
   'allocation_descriptor_address':alloc['address'],'normalized_metadata_equal':True},
  'cleanup_symbols':symbols,'literal_error_slot_inventory':inventory,'kernel_function_containers':functions,
  'verified_counts':{'source_spans':len(spans),'selected_instructions':sum(len(s['instructions']) for s in spans),
   'terminal_transfers':len(transfers),'original_branch_pointers':len(bp),'bank_rules':len(rules),
   'bank_input_cases':256*len(rules),'cleanup_node_bytes':size,'literal_error_slot_accesses':len(inventory),
   'literal_error_slot_stores':len(stores),'kernel_function_containers':len(functions)},
  'conditional_query_failure_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
