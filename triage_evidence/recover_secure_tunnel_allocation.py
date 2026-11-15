#!/usr/bin/env python3
"""Freeze the original FPSecureTunnel allocation and local initialization ABI.
O(B+I+256R) extraction time and O(B+I) space. No target executes.
"""
import json
import struct
from hashlib import sha256
from kext_port_tools import ROOT, SOURCE, IMAGE, POOL, TABLE, CS, qword, selected
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from recover_kext_aes_handoff import starts
from verify_daemon_reader_record_payloads_publication import read, sha

P='secure_tunnel_allocation'
SCOPE='Conditional original-source site.FPSecureTunnel allocation, scratch publication, six-byte header alternatives and 120-byte local initialization. Whole dispatcher reachability, entry insertion, native identity/lifetime and daemon transaction correlation remain unknown.'
SPANS={
 'bank_root_left':(0xfffffe000a635490,0xfffffe000a63549c),
 'bank_root_right':(0xfffffe000a6354ac,0xfffffe000a6354b8),
 'source_field32_root':(0xfffffe000a635c74,0xfffffe000a635c7c),
 'clear_cell_root':(0xfffffe000a635d7c,0xfffffe000a635d84),
 'source_field16_root':(0xfffffe000a635ef4,0xfffffe000a635efc),
 'allocation_prepare':(0xfffffe000a65a4d0,0xfffffe000a65a4f8),
 'allocation_controller':(0xfffffe000a65a4f8,0xfffffe000a65a518),
 'allocation_select':(0xfffffe000a65a518,0xfffffe000a65a55c),
 'allocation_return':(0xfffffe000a65a560,0xfffffe000a65a5b0),
 'header_gate':(0xfffffe000a65a5b8,0xfffffe000a65a5ec),
 'header_copy':(0xfffffe000a65a5f4,0xfffffe000a65a61c),
 'default_header_allocate_select':(0xfffffe000a65a650,0xfffffe000a65a6c8),
 'default_header_allocate_return':(0xfffffe000a65a6cc,0xfffffe000a65a730),
 'default_header_copy':(0xfffffe000a65a738,0xfffffe000a65a774),
 'default_header_join':(0xfffffe000a65a780,0xfffffe000a65a7c0),
 'payload_initialize':(0xfffffe000a65a7cc,0xfffffe000a65a978),
 'payload_overlay':(0xfffffe000a65a978,0xfffffe000a65abd4),
}
FALSE=['native_target_executed','native_PAC_authenticated','whole_dispatcher_reachability_established',
 'native_payload_identity_established','native_ownership_established','native_locking_established',
 'entry_insertion_lineage_established','UID_business_semantics_established','daemon_kext_transaction_correlated',
 'all_allocation_sites_established','new_Mach_port_endpoint_established','IDB_modified','full_goal_complete']
DEPS=['kext_port_tools.py','kernel_native_reader.py','recover_kext_cold_init.py','recover_kext_aes_handoff.py',
 'lskd_values_symbolic.py','audit_userclient_hash_table_initializer.py','userclient_hash_table_reclamation_checks.json']

def descriptor(k,a):
 raw=IMAGE.read(a,64);namep,sigp=struct.unpack_from('<Q',raw,16)[0],struct.unpack_from('<Q',raw,32)[0]
 name=IMAGE.read(namep,64).split(b'\0')[0];sig=IMAGE.read(sigp,64).split(b'\0')[0]
 flags,size=struct.unpack_from('<II',raw,40)
 assert (name,sig,flags,size)==(b'site.FPSecureTunnel',b'',0x6c,120)
 pn,ps=pointer(k,a+16),pointer(k,a+32)
 assert (int(pn['target'],16),int(ps['target'],16))==(namep,sigp)
 assert k.read(a+40,8)==raw[40:48] and k.read(namep,len(name)+1)==name+b'\0' and k.read(sigp,1)==b'\0'
 return {'address':hex(a),'normalized64_bytes_hex':raw.hex(),'original64_bytes_hex':k.read(a,64).hex(),
  'name':name.decode(),'signature':sig.decode(),'flags_u32':flags,'size_bytes':size,'name_pointer':pn,'signature_pointer':ps}

def build():
 k=Kernel();e=next(e for e in k.entries if e['name']=='com.apple.driver.FairPlayIOKit');catalog=starts(k,e)
 a,z=0xfffffe000a635208,0xfffffe000a666930;assert catalog[catalog.index(a)+1]==z
 full=k.read(a,z-a);assert IMAGE.read(a,z-a)==full
 spans=[]
 for label,(lo,hi) in SPANS.items():
  raw=k.read(lo,hi-lo);assert IMAGE.read(lo,hi-lo)==raw
  ins=[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in CS.disasm(raw,lo)]
  assert len(ins)*4==len(raw)
  spans.append({'label':label,'start':hex(lo),'end_exclusive':hex(hi),'bytes_hex':raw.hex(),'instructions':ins})
 bank_addresses={'D_L':qword(POOL+0xf50)-4,'D_R':qword(POOL+0xf20)-4}
 rules=[]
 for name,left,right,key,add,base,bias,div in [
  ('allocate_adapter','D_L','D_R',0x93,0xe27,TABLE,0,0xd0c8),
  ('allocate_descriptor','D_L','D_R',0x93,-0x58,POOL,-4,None)]:
  r=selected(bank_addresses[left],bank_addresses[right],key,add,base,bias);r.update(name=name,left_name=left,right_name=right)
  p=pointer(k,int(r['slot'],16));assert (int(p['target'],16)+bias)&((1<<64)-1)==int(r['target'],16)
  if div is not None:assert p['authenticated'] and int(p['diversity'],16)==div
  r['original_pointer']=p;rules.append(r)
 adapter=k.function(0xfffffe000c4ba154);assert adapter['instructions'][-1]['operands']=='#0xfffffe000bcfeb8c'
 desc=[descriptor(k,x) for x in [0xfffffe000847c120,0xfffffe000847bf60]]
 assert desc[0]['normalized64_bytes_hex']==desc[1]['normalized64_bytes_hex'] and desc[0]['original64_bytes_hex']==desc[1]['original64_bytes_hex']
 branches=[pointer(k,TABLE+8*j)|{'index':j} for j in [0xece,0xb80,0xb97,0xa1a,0x9f3,0x797,0x794,0x93,0x8c3,0x5b7]]
 transfers=[]
 for pc in [0xfffffe000a65a55c,0xfffffe000a65a5b0,0xfffffe000a65a5ec,0xfffffe000a65a644,
  0xfffffe000a65a6c8,0xfffffe000a65a730,0xfffffe000a65a778,0xfffffe000a65a7c4,0xfffffe000a65abf4]:
  raw=k.read(pc,4);assert IMAGE.read(pc,4)==raw;i=list(CS.disasm(raw,pc))[0]
  transfers.append({'ea':hex(pc),'bytes_hex':raw.hex(),'mnemonic':i.mnemonic,'operands':i.op_str})
 cp=SOURCE.with_suffix(SOURCE.suffix+'.c');lines=cp.read_text().splitlines()
 assert '_PRnut72j9 (0xFFFFFE000A635208)' in lines[199130]
 return {'generator_sha256':sha(__file__),'scope':SCOPE,'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,
  'dependencies':{n:sha(ROOT/n) for n in DEPS},'function_container':{'name':'_PRnut72j9','start':hex(a),'end_exclusive':hex(z),
   'instruction_words':len(full)//4,'sha256':sha256(full).hexdigest(),'entry_uuid':e['uuid'],'source_starts_verified':True,
   'C_name_evidence':{'path':cp.name,'sha256':sha(cp),'line':199131,'text':lines[199130]},'full_function_semantics_established':False},
  'spans':spans,'transfers':transfers,'banks':{n:{'address':hex(v),'bytes_hex':IMAGE.read(v,256).hex()} for n,v in bank_addresses.items()},
  'bank_rules':rules,'pool_pointers':[pointer(k,POOL+o) for o in [0xf50,0xf20]],'branch_pointers':branches,
  'allocation_descriptor':desc[0],'free_descriptor':desc[1],'allocation_adapter':adapter,
  'allocation_adapter_symbols':k.symbols([0xfffffe000c4ba154]),
  'predecessor_reclamation_checks_sha256':sha(ROOT/'userclient_hash_table_reclamation_checks.json'),
  'verified_counts':{'source_spans':len(spans),'selected_instructions':sum(len(s['instructions']) for s in spans),
   'terminal_transfers':len(transfers),'bank_rules':len(rules),'bank_input_cases':256*len(rules),
   'typed_descriptors':2,'object_extent_bytes':120,'copied_field16_bytes':16,'copied_field32_bytes':32,'retained_fill_bytes':48},
  'conditional_secure_tunnel_allocation_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
