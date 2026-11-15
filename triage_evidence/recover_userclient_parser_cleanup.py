#!/usr/bin/env python3
"""Freeze parser failure, list destruction and pending-node retirement source.
O(B+I+256R) extraction time/space. No target execution or IDB mutation.
"""
import json
import struct
from hashlib import sha256
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,POOL,TABLE,qword,selected
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read,sha

P='userclient_parser_cleanup'
SCOPE='Conditional parser failure status/output, retained-container destructor with empty/list-node steps and original retirement requests, and valid pending-node cleanup. Native callee effects, allocator identity/ownership, all incoming allocation-result paths, synchronization, other type handlers and successful daemon correlation remain unknown.'
SPANS={
 'cleanup_cell_root':(0xfffffe000a635d84,0xfffffe000a635d8c),
 'retained_node_key':(0xfffffe000a641be8,0xfffffe000a641bec),
 'pending_descriptor_index':(0xfffffe000a636468,0xfffffe000a63646c),
 'pending_descriptor_producer':(0xfffffe000a6364fc,0xfffffe000a636528),
 'failure_prepare':(0xfffffe000a662444,0xfffffe000a662488),
 'failure_bridge':(0xfffffe000a6622a0,0xfffffe000a6622b8),
 'destroy_entry':(0xfffffe000a66046c,0xfffffe000a6604a0),
 'destroy_object':(0xfffffe000a6604a8,0xfffffe000a6604f8),
 'destroy_head':(0xfffffe000a660500,0xfffffe000a660530),
 'container_request':(0xfffffe000a660538,0xfffffe000a6605c4),
 'container_return':(0xfffffe000a6605c8,0xfffffe000a660610),
 'destroy_resume':(0xfffffe000a660618,0xfffffe000a66062c),
 'node_gate':(0xfffffe000a660754,0xfffffe000a66078c),
 'node_data_request':(0xfffffe000a660794,0xfffffe000a6607e8),
 'node_data_return':(0xfffffe000a6607ec,0xfffffe000a660810),
 'node_type_request':(0xfffffe000a660670,0xfffffe000a660708),
 'node_type_return':(0xfffffe000a66070c,0xfffffe000a66074c),
 'failure_return':(0xfffffe000a660a9c,0xfffffe000a660ac4),
 'parser_output':(0xfffffe000a660acc,0xfffffe000a660adc),
 'parser_resume':(0xfffffe000a660ae4,0xfffffe000a660af0),
 'pending_gate':(0xfffffe000a6622c0,0xfffffe000a66230c),
 'pending_data_request':(0xfffffe000a662314,0xfffffe000a66237c),
 'pending_data_return':(0xfffffe000a662380,0xfffffe000a662390),
 'pending_type_request':(0xfffffe000a662398,0xfffffe000a662404),
 'pending_type_return':(0xfffffe000a662408,0xfffffe000a66243c),
 'pending_buffer_result':(0xfffffe000a6427c4,0xfffffe000a642808),
}
BRANCHES={0xfffffe000a662474:[0x2b7],0xfffffe000a6622b0:[0x9a7],0xfffffe000a660470:[0x50],
 0xfffffe000a660498:[0xafb,0xafc],0xfffffe000a6604f0:[0x432,0x480],0xfffffe000a660528:[0x414,0x41e],
 0xfffffe000a6605ec:[0x247],0xfffffe000a660abc:[0x970],0xfffffe000a660ad4:[0x6d5],
 0xfffffe000a660784:[0x989,0x99e],0xfffffe000a660740:[0x414,0x41e],0xfffffe000a660808:[0x989],
 0xfffffe000a6622fc:[0x43e,0x440],0xfffffe000a662414:[0x4a9],0xfffffe000a662388:[0x440],
 0xfffffe000a6427e0:[0x766,0x7ad]}
BANK_PCS={
 'pending_descriptor':(0xfffffe000a636500,0xfffffe000a63650c,0xfffffe000a63651c),
 'container_free':(0xfffffe000a660560,0xfffffe000a660570,0xfffffe000a660580),
 'container_descriptor':(0xfffffe000a660594,0xfffffe000a66059c,0xfffffe000a6605b4),
 'node_free':(0xfffffe000a6606a0,0xfffffe000a6606ac,0xfffffe000a6606c0),
 'node_descriptor':(0xfffffe000a6606d0,0xfffffe000a6606e0,0xfffffe000a6606f8),
 'data_free':(0xfffffe000a6607bc,0xfffffe000a6607cc,0xfffffe000a6607e0),
 'pending_data_free':(0xfffffe000a662350,0xfffffe000a662360,0xfffffe000a662374),
 'pending_node_free':(0xfffffe000a6623cc,0xfffffe000a6623dc,0xfffffe000a6623f4),
}
RULES=[('pending_descriptor','T',0x5c,0xf,POOL,-12,None),
 ('container_free','A',0x92,0xe89,TABLE,0,0x4d6a),
 ('container_descriptor','A',0x92,-0x55,POOL,-4,None),
 ('node_free','B',0x37,0xef1,TABLE,0,0x4d6a),
 ('node_descriptor','F',0x47,0x149,POOL,-8,None),
 ('data_free','S',0x6d,0xf07,TABLE,0,0x85d),
 ('pending_data_free','T',0x5c,0xe48,TABLE,0,0x85d),
 ('pending_node_free','B',0xef,0xeca,TABLE,0,0x4d6a)]
NO_TRANSFER={'cleanup_cell_root','retained_node_key','pending_descriptor_index','pending_descriptor_producer'}
FALSE=['native_target_executed','native_PAC_authenticated','whole_dispatcher_reachability_established',
 'complete_parser_body_established','native_input_identity_established','native_allocation_identity_established',
 'native_ownership_established','native_locking_established','all_allocation_result_paths_composed',
 'all_type_handlers_established','daemon_kext_transaction_correlated','new_Mach_port_endpoint_established',
 'IDB_modified','full_goal_complete']
DEPS=['kext_port_tools.py','kernel_native_reader.py','recover_kext_cold_init.py','lskd_values_symbolic.py',
 'audit_secure_tunnel_table_insertion.py','audit_userclient_input_reader.py','recover_userclient_input_reader.py',
 'userclient_container_staging_checks.json','userclient_container_staging_audit.json',
 'userclient_record_nodes_checks.json','userclient_record_nodes_audit.json',
 'userclient_record_publication_checks.json','userclient_record_publication_audit.json',
 'userclient_record_metadata_checks.json','userclient_record_metadata_audit.json']

def build():
 k=Kernel();prior=json.loads(read(ROOT/'userclient_record_metadata_checks.json'));container=prior['function_container']
 a,z=(int(container[n],16) for n in ['start','end_exclusive']);b=k.read(a,z-a)
 assert b==IMAGE.read(a,z-a) and sha256(b).hexdigest()==container['sha256'];spans=[];transfers=[]
 for label,(a,z) in SPANS.items():
  b=k.read(a,z-a);assert b==IMAGE.read(a,z-a);ii=list(CS.disasm(b,a));assert len(ii)*4==len(b)
  spans.append({'label':label,'start':hex(a),'end_exclusive':hex(z),'bytes_hex':b.hex(),
   'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ii]})
  if label not in NO_TRANSFER:
   b=k.read(z,4);assert b==IMAGE.read(z,4);i=next(CS.disasm(b,z));assert i.mnemonic in ['braa','blraa']
   transfers.append({'ea':hex(z),'bytes_hex':b.hex(),'mnemonic':i.mnemonic,'operands':i.op_str})
 pairs={'A':(0xfffffe0007949ed0,0xfffffe000792fec0),'B':(0xfffffe0007949fd0,0xfffffe000792ffc0),
  'F':(0xfffffe000792fcc0,0xfffffe00079391f0),'S':(0xfffffe0007941f60,0xfffffe000794a0d0),
  'T':(0xfffffe0007949dd0,0xfffffe000792fbc0)}
 banks={pair+side:{'address':hex(a),'bytes_hex':IMAGE.read(a,256).hex()}
  for pair,ab in pairs.items() for side,a in zip(['L','R'],ab)}
 for row in banks.values():assert k.read(int(row['address'],16),256).hex()==row['bytes_hex']
 rules=[]
 for name,pair,key,add,base,bias,div in RULES:
  r=selected(*pairs[pair],key,add,base,bias);r.update(name=name,left_name=pair+'L',right_name=pair+'R')
  r['original_pointer']=pointer(k,int(r['slot'],16))
  assert (int(r['original_pointer']['target'],16)+bias)&(2**64-1)==int(r['target'],16)
  if div is not None:assert r['original_pointer']['authenticated'] and int(r['original_pointer']['diversity'],16)==div
  rules.append(r)
 descriptors=[]
 for role,address,n,sig,flags,size in [
  ('container_retirement',0xfffffe000847bde0,'site.FPTTLV','11',0xe4,16),
  ('container_allocation',0xfffffe000847b620,'site.FPTTLV','11',0xe4,16),
  ('list_node_retirement',0xfffffe000847be20,'site.FPTTLVNode','1121',0x64,32),
  ('pending_node_retirement',0xfffffe000847b6a0,'site.FPTTLVNode','1121',0x64,32),
  ('node_allocation',0xfffffe000847c020,'site.FPTTLVNode','1121',0x64,32),
  ('replacement_retirement',0xfffffe000847bce0,'site.FPTTLVNode','1121',0x64,32)]:
  b=IMAGE.read(address,64);np,sp=pointer(k,address+16),pointer(k,address+32)
  naddr,saddr=struct.unpack_from('<Q',b,16)[0],struct.unpack_from('<Q',b,32)[0]
  assert (int(np['target'],16),int(sp['target'],16))==(naddr,saddr)
  assert IMAGE.read(naddr,len(n)+1)==k.read(naddr,len(n)+1)==n.encode()+b'\0'
  assert IMAGE.read(saddr,len(sig)+1)==k.read(saddr,len(sig)+1)==sig.encode()+b'\0'
  assert struct.unpack_from('<II',b,40)==(flags,size) and k.read(address+40,8)==b[40:48]
  descriptors.append({'role':role,'address':hex(address),'normalized64_bytes_hex':b.hex(),
   'original64_bytes_hex':k.read(address,64).hex(),'name':n,'signature':sig,'flags_u32':flags,'size_bytes':size,
   'name_pointer':np,'signature_pointer':sp})
 assert len({r['normalized64_bytes_hex'] for r in descriptors if r['size_bytes']==16})==1
 assert len({r['normalized64_bytes_hex'] for r in descriptors if r['size_bytes']==32})==1
 for name,role in [('pending_descriptor','pending_node_retirement'),('container_descriptor','container_retirement'),('node_descriptor','list_node_retirement')]:
  assert next(r['target'] for r in rules if r['name']==name)==next(r['address'] for r in descriptors if r['role']==role)
 bp=[pointer(k,TABLE+8*j)|{'index':j} for j in sorted({j for js in BRANCHES.values() for j in js})]
 for r in bp:assert int(r['target'],16)==qword(TABLE+8*r['index'])
 a,z=0xfffffe000a63646c,0xfffffe000a6364fc;b=k.read(a,z-a);assert b==IMAGE.read(a,z-a)
 dec=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);dec.detail=True;gap=list(dec.disasm(b,a));assert len(gap)*4==len(b)
 retained={'x10','w10','x11','w11','x21','w21','x22','w22','x28','w28','sp','wsp'}
 for i in gap:
  assert not i.mnemonic.startswith(('b','ret')) and not retained&{i.reg_name(r) for r in i.regs_access()[1]}
 symbols=k.symbols([0xfffffe000c4ba368,0xfffffe000c4ba84c])
 for address,name in [('0xfffffe000c4ba368','_IOFreeTypeImpl'),('0xfffffe000c4ba84c','_IOFreeData')]:
  assert any(s['name']==name for s in symbols[address])
 return {'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,
  'scope':SCOPE,'function_container':container,'dependencies':{n:sha(ROOT/n) for n in DEPS},
  'spans':spans,'transfers':transfers,'branch_pointers':bp,'banks':banks,'bank_rules':rules,
  'typed_descriptors':descriptors,'retirement_symbols':symbols,
  'pending_descriptor_retention_envelope':{'start':hex(a),'end_exclusive':hex(z),'bytes_hex':b.hex(),
   'instructions':len(gap),'preserved_registers':sorted(retained),'ordinary_calls':0},
  'verified_counts':{'source_spans':len(spans),'selected_instructions':sum(len(s['instructions']) for s in spans),
   'terminal_transfers':len(transfers),'bank_rules':len(rules),'bank_input_cases':256*len(rules),
   'typed_descriptors':len(descriptors),'container_bytes':16,'node_bytes':32,'retention_envelope_instructions':len(gap)},
  'conditional_parser_cleanup_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
