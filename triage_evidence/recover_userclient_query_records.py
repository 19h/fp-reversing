#!/usr/bin/env python3
"""Pin second-command metadata requests and selected shared node construction.
O(B+I+256R) extraction time/space; no target execution or IDB mutation.
"""
import json
import struct
from hashlib import sha256
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,POOL,TABLE,qword,selected
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read,sha

P='userclient_query_records'
SCOPE='Conditional second command metadata adapter/leaf calls, shared record custody, three scalar construction request channels, status-driven continuations and first selected shared node/data allocation, initialization and writer-entry ABI. Complete serialization/list publication, auxiliary output production, all incoming phases, native allocator/PAC/ownership/locking and daemon transaction identity remain unknown.'
SPANS={
 'record_root':(0xfffffe000a6355c4,0xfffffe000a6355c8),'record_root_save':(0xfffffe000a635b50,0xfffffe000a635b54),
 'callback_basis':(0xfffffe000a6355f4,0xfffffe000a6355fc),'callback_basis_save':(0xfffffe000a635990,0xfffffe000a6359a0),
 'query_version':(0xfffffe000a63ad64,0xfffffe000a63ae2c),'query_capabilities':(0xfffffe000a63ae30,0xfffffe000a63aee0),
 'request_first':(0xfffffe000a63aee4,0xfffffe000a63af38),'callback_first':(0xfffffe000a656f90,0xfffffe000a656fd0),
 'request_second':(0xfffffe000a656fd8,0xfffffe000a657014),'callback_second':(0xfffffe000a65701c,0xfffffe000a657068),
 'request_third':(0xfffffe000a657070,0xfffffe000a6570c0),'callback_third':(0xfffffe000a65f35c,0xfffffe000a65f3b0),
 'post_requests':(0xfffffe000a65f3b8,0xfffffe000a65f3e8),
 'shared_entry':(0xfffffe000a661400,0xfffffe000a661454),'shared_prepare':(0xfffffe000a66145c,0xfffffe000a661494),
 'node_request_record':(0xfffffe000a66149c,0xfffffe000a66150c),'extent_gate':(0xfffffe000a661514,0xfffffe000a661598),
 'node_allocate':(0xfffffe000a6615a0,0xfffffe000a661664),'node_result':(0xfffffe000a661668,0xfffffe000a661698),
 'node_failure':(0xfffffe000a6616a0,0xfffffe000a6616d0),'node_initialize':(0xfffffe000a6616d8,0xfffffe000a661848),
 'data_result':(0xfffffe000a66184c,0xfffffe000a66187c),'writer_entry':(0xfffffe000a661884,0xfffffe000a6618e8),
 'shared_empty':(0xfffffe000a66421c,0xfffffe000a66422c),'shared_return':(0xfffffe000a664234,0xfffffe000a664260)}
NO_TRANSFER={'record_root','record_root_save','callback_basis','callback_basis_save'}
CALL_LABELS={'query_version','query_capabilities','node_allocate','node_initialize'}
BRANCHES={0xfffffe000a63af1c:[0x458],0xfffffe000a656fc0:[0x68,0x8a0],0xfffffe000a656ff0:[0x458],
 0xfffffe000a657058:[0x68,0xe9a],0xfffffe000a657098:[0x458],0xfffffe000a65f3a0:[0x840,0xb11],
 0xfffffe000a65f3cc:[0x73e],0xfffffe000a661404:[0x45,0x42,0x68],0xfffffe000a661440:[0x9dc,0x9e0],
 0xfffffe000a661474:[0x2c7],0xfffffe000a6614b0:[0x1a3],0xfffffe000a6614f8:[0xe52,0xe5c],
 0xfffffe000a661590:[0x63d,0xce0],0xfffffe000a661690:[0xaaa,0xb09],0xfffffe000a6616b4:[0x871],
 0xfffffe000a661864:[0x871,0x87c],0xfffffe000a6618b8:[0x543]}
BANK_PCS={'version':(0xfffffe000a63adf4,0xfffffe000a63ae04,0xfffffe000a63ae18),
 'capability':(0xfffffe000a63aeb0,0xfffffe000a63aec0,0xfffffe000a63aed4),
 'node_allocate':(0xfffffe000a6615e8,0xfffffe000a6615f8,0xfffffe000a661608),
 'node_descriptor':(0xfffffe000a661620,0xfffffe000a661630,0xfffffe000a661648),
 'data_allocate':(0xfffffe000a661820,0xfffffe000a66182c,0xfffffe000a66183c)}
FALSE=['native_target_executed','IDB_modified','native_PAC_authenticated','native_allocator_effects_established',
 'complete_record_serialization_established','complete_list_publication_established','auxiliary_producer_established',
 'complete_command_established','daemon_kext_transaction_correlated','new_Mach_port_endpoint_established','full_goal_complete']
DEPS=['userclient_command_dispatch_checks.json','userclient_command_dispatch_audit.json',
 'kext_query_getter_values_source.json','kext_query_getter_values_checks.json',
 'userclient_caller_return_checks.json','userclient_transfer_boundary_checks.json',
 'audit_userclient_command_dispatch.py','audit_userclient_record_metadata.py',
 'audit_secure_tunnel_table_insertion.py','lskd_values_symbolic.py','kext_port_tools.py','kernel_native_reader.py']

def build():
 k=Kernel();prior=json.loads(read(ROOT/'userclient_command_dispatch_checks.json'));container=prior['function_container']
 a,z=(int(container[n],16) for n in ['start','end_exclusive']);raw=k.read(a,z-a)
 assert raw==IMAGE.read(a,z-a) and sha256(raw).hexdigest()==container['sha256']
 spans=[];transfers=[]
 for label,(a,z) in SPANS.items():
  b=k.read(a,z-a);assert b==IMAGE.read(a,z-a);ii=list(CS.disasm(b,a));assert len(ii)*4==len(b)
  spans.append({'label':label,'start':hex(a),'end_exclusive':hex(z),'bytes_hex':b.hex(),
   'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ii]})
  if label not in NO_TRANSFER:
   b=k.read(z,4);assert b==IMAGE.read(z,4);i=next(CS.disasm(b,z));assert i.mnemonic==('blraa' if label in CALL_LABELS else 'braa')
   transfers.append({'label':label,'ea':hex(z),'bytes_hex':b.hex(),'mnemonic':i.mnemonic,'operands':i.op_str})
 families={'A':(0xfffffe0007949ed0,0xfffffe000792fec0),'B':(0xfffffe0007949fd0,0xfffffe000792ffc0),
  'T':(0xfffffe0007949dd0,0xfffffe000792fbc0),'U':(0xfffffe000792fdc0,0xfffffe00079392f0)}
 banks={n+s:{'address':hex(a),'bytes_hex':IMAGE.read(a,256).hex()} for n,ab in families.items() for s,a in zip(['L','R'],ab)}
 for r in banks.values():assert k.read(int(r['address'],16),256).hex()==r['bytes_hex']
 rules=[]
 for name,f,key,add,base,bias,div in [('version','B',0x37,0xf41,TABLE,0,0x5c97),('capability','U',0x93,0xe79,TABLE,0,0x7787),
  ('node_allocate','U',0x93,0xe27,TABLE,0,0xd0c8),('node_descriptor','A',0x32,-0x98,POOL,-8,None),('data_allocate','T',0x3e,0xebc,TABLE,0,0xca0c)]:
  r=selected(*families[f],key,add,base,bias);r.update(name=name,left_name=f+'L',right_name=f+'R',original_pointer=pointer(k,int(r['slot'],16)))
  assert (int(r['original_pointer']['target'],16)+bias)%(2**64)==int(r['target'],16)
  if div is not None:assert int(r['original_pointer']['diversity'],16)==div
  rules.append(r)
 b=IMAGE.read(0xfffffe000847b4a0,64);np=pointer(k,0xfffffe000847b4b0);p=int(np['target'],16)
 name=b'site.FPTTLVNode'
 assert struct.unpack_from('<II',b,40)==(0x64,32) and k.read(p,len(name)+1)==name+b'\0'
 desc={'address':'0xfffffe000847b4a0','normalized64_bytes_hex':b.hex(),'original64_bytes_hex':k.read(0xfffffe000847b4a0,64).hex(),
  'name_pointer':np,'name':'site.FPTTLVNode','flags_u32':0x64,'size_bytes':32}
 old=json.loads(read(ROOT/'kext_query_getter_values_source.json'));helpers=[]
 for label in ['version_adapter','capability_leaf','status_leaf']:
  f=old['fragments'][label];a=int(f['start'],16);b=bytes.fromhex(f['bytes']);assert k.read(a,len(b))==IMAGE.read(a,len(b))==b;helpers.append(f)
 structural=[];dec=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);dec.detail=True
 for label,a,z,reg in [('record_root_retention',0xfffffe000a6355c8,0xfffffe000a635b50,'16'),('callback_basis_retention',0xfffffe000a6355fc,0xfffffe000a635990,'15')]:
  b=k.read(a,z-a);assert b==IMAGE.read(a,z-a);ii=list(dec.disasm(b,a));assert len(ii)*4==len(b)
  for i in ii:
   assert not i.mnemonic.startswith(('b','cb','tb')) and i.mnemonic not in ['ret','retab','retaa','eret','svc','hvc','smc']
   assert not ({'x'+reg,'w'+reg}&{i.reg_name(x) for x in i.regs_access()[1]})
  structural.append({'label':label,'start':hex(a),'end_exclusive':hex(z),'bytes_hex':b.hex(),'instructions':len(ii),'preserved_register':'x'+reg})
 pointers=[pointer(k,TABLE+8*j)|{'index':j} for j in sorted({j for js in BRANCHES.values() for j in js})]
 for p in pointers:assert int(p['target'],16)==qword(TABLE+8*p['index'])
 syms=k.symbols([int(r['target'],16) for r in rules if r['name'] in ['node_allocate','data_allocate']])
 for a,n in [(0xfffffe000c4ba154,'_IOMallocTypeImpl'),(0xfffffe000c4ba60c,'_IOMallocData')]:assert any(s['name']==n for s in syms[hex(a)])
 return {'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'scope':SCOPE,
  'function_container':container,'dependencies':{n:sha(ROOT/n) for n in DEPS},'spans':spans,'transfers':transfers,'banks':banks,'bank_rules':rules,
  'typed_descriptor':desc,'helper_recaptures':helpers,'structural_ranges':structural,'branch_pointers':pointers,'exact_symbols':syms,
  'verified_counts':{'source_spans':len(spans),'selected_instructions':sum(len(s['instructions']) for s in spans),'terminal_transfers':len(transfers),
   'bank_rules':5,'bank_input_cases':1280,'recaptured_helpers':3,'recaptured_helper_instructions':sum(len(f['instructions']) for f in helpers),
   'structural_instruction_instances':sum(r['instructions'] for r in structural),'construction_request_cases':3},
  'conditional_query_record_request_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
