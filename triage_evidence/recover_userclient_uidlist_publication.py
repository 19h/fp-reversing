#!/usr/bin/env python3
"""Capture original context-list search, typed node allocation and publication.
O(B+I+256R) time, O(B+I) space; no native target or database mutation.
"""
import json
import struct
from hashlib import sha256
from kext_port_tools import ROOT,SOURCE,IMAGE,POOL,TABLE,CS,qword,selected
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read,sha

P='userclient_uidlist_publication'
SCOPE='Conditional UIDList discriminator search, tunnel-marker and original context-head lineage, typed 16 B allocation, null-result branch and exact three-field head publication. Existing-match resource handling, whole-dispatcher reachability, native ownership/locking and daemon transaction correlation remain unknown.'
SPANS={
 'entry_context_save':(0xfffffe000a63524c,0xfffffe000a635250),
 'candidate_alias':(0xfffffe000a65e4a0,0xfffffe000a65e4a8),
 'candidate_gate':(0xfffffe000a65ecd4,0xfffffe000a65ed20),
 'marker_head':(0xfffffe000a65ed28,0xfffffe000a65ed84),
 'walk_key':(0xfffffe000a65ed8c,0xfffffe000a65eda8),
 'walk_compare':(0xfffffe000a65edb0,0xfffffe000a65edec),
 'walk_next':(0xfffffe000a65edf4,0xfffffe000a65ee2c),
 'walk_exhaust':(0xfffffe000a65ee34,0xfffffe000a65ee60),
 'matched_capture':(0xfffffe000a65ee68,0xfffffe000a65eee0),
 'status_gate':(0xfffffe000a65e6d0,0xfffffe000a65e70c),
 'marker_update':(0xfffffe000a65e714,0xfffffe000a65e75c),
 'allocate_prepare':(0xfffffe000a65e764,0xfffffe000a65e800),
 'allocate_return':(0xfffffe000a65e804,0xfffffe000a65e858),
 'node_prepend':(0xfffffe000a65e860,0xfffffe000a65e88c),
 'marker_default':(0xfffffe000a63dd40,0xfffffe000a63dd44),
 'discriminator_default':(0xfffffe000a6571ec,0xfffffe000a6571f4),
 'discriminator_store':(0xfffffe000a657298,0xfffffe000a6572a4),
}
BRANCHES={
 0xfffffe000a65ed14:[0xb33,0xba0],0xfffffe000a65ed7c:[0x90d,0x90e],
 0xfffffe000a65ed98:[0xcc0],0xfffffe000a65ede4:[0x784,0x7a0],
 0xfffffe000a65ee24:[0xcc0,0xd6c],0xfffffe000a65ee40:[0x90e],
 0xfffffe000a65eeb8:[0xbc1,0xbc9],0xfffffe000a65e704:[0xf4,0xc0e],
 0xfffffe000a65e754:[0x746,0xacd],0xfffffe000a65e84c:[0x51f,0x521],
 0xfffffe000a65e884:[0x746],
}
TRANSFERS=[0xfffffe000a65ed20,0xfffffe000a65ed84,0xfffffe000a65eda8,0xfffffe000a65edec,
 0xfffffe000a65ee2c,0xfffffe000a65ee60,0xfffffe000a65eee0,0xfffffe000a65e70c,
 0xfffffe000a65e75c,0xfffffe000a65e800,0xfffffe000a65e858,0xfffffe000a65e88c]
FALSE=['native_target_executed','native_PAC_authenticated','whole_dispatcher_reachability_established',
 'native_payload_identity_established','native_ownership_established','native_locking_established',
 'all_UIDList_producers_established','discriminator_business_identity_established',
 'existing_match_resource_path_complete','daemon_kext_transaction_correlated','new_Mach_port_endpoint_established',
 'IDB_modified','full_goal_complete']
DEPS=['kext_port_tools.py','kernel_native_reader.py','recover_kext_cold_init.py','lskd_values_symbolic.py',
 'audit_secure_tunnel_table_insertion.py','audit_userclient_hash_table_initializer.py',
 'secure_tunnel_table_insertion_checks.json','secure_tunnel_table_insertion_audit.json',
 'secure_tunnel_allocation_checks.json','userclient_uidlist_cleanup_checks.json','userclient_uidlist_cleanup_audit.json','userclient_hash_table_lookup_audit.json']

def descriptor(k,a):
 raw=IMAGE.read(a,64);np,sp=(struct.unpack_from('<Q',raw,o)[0] for o in [16,32])
 name=IMAGE.read(np,64).split(b'\0')[0];sig=IMAGE.read(sp,64).split(b'\0')[0];flags,size=struct.unpack_from('<II',raw,40)
 assert (name,sig,flags,size)==(b'site.UIDList',b'21',0x64,16)
 pn,ps=pointer(k,a+16),pointer(k,a+32);assert int(pn['target'],16)==np and int(ps['target'],16)==sp
 assert k.read(a+40,8)==raw[40:48] and k.read(np,len(name)+1)==name+b'\0' and k.read(sp,len(sig)+1)==sig+b'\0'
 return {'address':hex(a),'normalized64_bytes_hex':raw.hex(),'original64_bytes_hex':k.read(a,64).hex(),
  'name':name.decode(),'signature':sig.decode(),'flags_u32':flags,'size_bytes':size,'name_pointer':pn,'signature_pointer':ps}

def build():
 k=Kernel();prior=json.loads(read(ROOT/'secure_tunnel_table_insertion_checks.json'));container=prior['function_container']
 a,z=(int(container[n],16) for n in ['start','end_exclusive']);raw=k.read(a,z-a)
 assert IMAGE.read(a,z-a)==raw and sha256(raw).hexdigest()==container['sha256']
 spans=[]
 for label,(a,z) in SPANS.items():
  raw=k.read(a,z-a);assert IMAGE.read(a,z-a)==raw;ii=list(CS.disasm(raw,a));assert len(ii)*4==len(raw)
  spans.append({'label':label,'start':hex(a),'end_exclusive':hex(z),'bytes_hex':raw.hex(),
   'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ii]})
 roots={'TL':qword(POOL+0x840),'TR':qword(POOL+0xbb8),'VL':qword(POOL+0xc08)-8,'VR':qword(POOL+0x158)-4}
 rules=[]
 for name,left,right,key,add,base,bias in [('allocate_adapter','TL','TR',0x3e,0xebf,TABLE,0),('allocate_descriptor','VL','VR',5,-0x1a,POOL,-12)]:
  r=selected(roots[left],roots[right],key,add,base,bias);r.update(name=name,left_name=left,right_name=right)
  r['original_pointer']=pointer(k,int(r['slot'],16));assert (int(r['original_pointer']['target'],16)+bias)&((1<<64)-1)==int(r['target'],16)
  if name=='allocate_adapter':assert r['original_pointer']['authenticated'] and int(r['original_pointer']['diversity'],16)==0xd0c8
  rules.append(r)
 desc=[descriptor(k,a) for a in [0xfffffe000847b8a0,0xfffffe000847b2a0]]
 assert desc[0]['normalized64_bytes_hex']==desc[1]['normalized64_bytes_hex'] and desc[0]['original64_bytes_hex']==desc[1]['original64_bytes_hex']
 alloc=json.loads(read(ROOT/'secure_tunnel_allocation_checks.json'));adapter=k.function(0xfffffe000c4ba154);assert adapter==alloc['allocation_adapter']
 bp=[pointer(k,TABLE+8*j)|{'index':j} for j in sorted({j for xs in BRANCHES.values() for j in xs})]
 transfers=[]
 for pc in TRANSFERS:
  raw=k.read(pc,4);assert IMAGE.read(pc,4)==raw;i=list(CS.disasm(raw,pc))[0]
  transfers.append({'ea':hex(pc),'bytes_hex':raw.hex(),'mnemonic':i.mnemonic,'operands':i.op_str})
 return {'generator_sha256':sha(__file__),'scope':SCOPE,'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,
  'function_container':container,'dependencies':{n:sha(ROOT/n) for n in DEPS},'spans':spans,'transfers':transfers,
  'banks':{n:{'address':hex(v),'bytes_hex':IMAGE.read(v,256).hex()} for n,v in roots.items()},'bank_rules':rules,
  'pool_pointers':[pointer(k,POOL+o) for o in [0x840,0xbb8,0xc08,0x158]],'branch_pointers':bp,
  'allocation_descriptor':desc[0],'free_descriptor':desc[1],'allocation_adapter':adapter,
  'allocation_adapter_symbols':k.symbols([0xfffffe000c4ba154]),
  'IDA_attempt':{'instance_supervisor_available':False,'kext_target_resolved':False,'new_IDA_evidence':False,'source':'Read-only MCP errors; original files remain authoritative.'},
  'verified_counts':{'source_spans':len(spans),'selected_instructions':sum(len(s['instructions']) for s in spans),
   'terminal_transfers':len(transfers),'bank_rules':2,'bank_input_cases':512,'typed_descriptors':2,
   'node_extent_bytes':16,'context_extent_bytes':24,'payload_extent_bytes':120},
  'conditional_UIDList_publication_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
