#!/usr/bin/env python3
"""Freeze record lookup, append/replacement and retirement request interfaces.
O(B+I+256R) extraction time/space. No target execution or IDB mutation.
"""
import json
import struct
from hashlib import sha256
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,POOL,TABLE,qword,selected
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read,sha

P='userclient_record_publication'
SCOPE='Conditional post-copy tag lookup/output/continuation ABI, selected append and doubly-linked node replacement, original data/typed retirement requests and parser cursor-gate return. Full staged-input metadata/body production, cursor advancement, all incoming/type/failure paths, native storage identity/lifetime/locking and successful daemon correlation remain unknown.'
SPANS={
 'output_root':(0xfffffe000a635e5c,0xfffffe000a635e64),
 'saved_lookup_roots':(0xfffffe000a636694,0xfffffe000a63669c),
 'saved_typed_root':(0xfffffe000a6362f0,0xfffffe000a6362f4),
 'publication_request':(0xfffffe000a655ef4,0xfffffe000a655f6c),
 'status_success_gate':(0xfffffe000a662490,0xfffffe000a6624a0),
 'status_miss_gate':(0xfffffe000a6624a0,0xfffffe000a6624b0),
 'append_prepare':(0xfffffe000a6624b0,0xfffffe000a6624f0),
 'append_tail':(0xfffffe000a6624f8,0xfffffe000a662534),
 'append_empty':(0xfffffe000a662870,0xfffffe000a66288c),
 'replace_prepare':(0xfffffe000a662538,0xfffffe000a662580),
 'replace_previous':(0xfffffe000a662588,0xfffffe000a66259c),
 'replace_next_gate':(0xfffffe000a6625a4,0xfffffe000a6625cc),
 'replace_next':(0xfffffe000a6625d4,0xfffffe000a6625f0),
 'replace_head_gate':(0xfffffe000a6625f8,0xfffffe000a662630),
 'replace_head':(0xfffffe000a662638,0xfffffe000a662650),
 'replace_tail_gate':(0xfffffe000a662658,0xfffffe000a662680),
 'replace_tail':(0xfffffe000a662688,0xfffffe000a6626a4),
 'retire_gate':(0xfffffe000a6626ac,0xfffffe000a6626fc),
 'retire_data_request':(0xfffffe000a662704,0xfffffe000a66275c),
 'retire_data_return':(0xfffffe000a662760,0xfffffe000a662788),
 'retire_node_request':(0xfffffe000a662790,0xfffffe000a6627e4),
 'retire_node_return':(0xfffffe000a6627e8,0xfffffe000a662838),
 'unexpected_lookup_status':(0xfffffe000a66283c,0xfffffe000a662868),
 'parser_cursor_gate':(0xfffffe000a64213c,0xfffffe000a64217c),
}
REUSED=['search_entry','search_nonnull','search_node','node_decode_prepare','word_bridge','decode_word',
 'tag_match','search_next','search_result','search_callback']
BRANCHES={0xfffffe000a655f20:[0x49a],0xfffffe000a662ac0:[0x7b],
 0xfffffe000a662ae8:[0x630,0x63e],0xfffffe000a662bf4:[0x52d],0xfffffe000a662c28:[0x50c,0x50d],
 0xfffffe000a662c88:[0x22f],0xfffffe000a656ef4:[0xe07],0xfffffe000a63713c:[0x181],
 0xfffffe000a63d66c:[0xe91,0xeb6],0xfffffe000a63d694:[0x52d],0xfffffe000a662c50:[0x63e],
 0xfffffe000a6624e4:[0xdb9,0xdbb],0xfffffe000a662524:[0x891],0xfffffe000a66287c:[0x891],
 0xfffffe000a662578:[0x8e0,0x8ee],0xfffffe000a662594:[0x376],0xfffffe000a6625c0:[0x57f,0x582],
 0xfffffe000a6625e8:[0x582],0xfffffe000a662628:[0x377,0x963],0xfffffe000a662648:[0x377],
 0xfffffe000a662678:[0x765,0x8f9],0xfffffe000a66269c:[0x765],0xfffffe000a6626f4:[0x9e8,0xa0d],
 0xfffffe000a662780:[0x5cb],0xfffffe000a662804:[0x891],0xfffffe000a66284c:[0x7ad],
 0xfffffe000a642174:[0x87f,0x893]}
RETAGS={0xfffffe000a637150:0xfffffe000a637154,0xfffffe000a637188:0xfffffe000a63718c,
 0xfffffe000a6371cc:0xfffffe000a6371d0,0xfffffe000a63720c:0xfffffe000a637210}
BANK_PCS={'search_callback_value':(0xfffffe000a662b2c,0xfffffe000a662b3c,0xfffffe000a662b54),
 'retire_data':(0xfffffe000a662730,0xfffffe000a662740,0xfffffe000a662754),
 'retire_node':(0xfffffe000a6627b0,0xfffffe000a6627c4,0xfffffe000a6627d8)}
FALSE=['native_target_executed','native_PAC_authenticated','whole_dispatcher_reachability_established',
 'complete_parser_body_established','metadata_producer_established','cursor_advancement_established',
 'native_input_identity_established','NUL_termination_guaranteed','native_allocation_identity_established',
 'native_ownership_established','native_locking_established','original_marker_producer_established',
 'daemon_kext_transaction_correlated','new_Mach_port_endpoint_established','IDB_modified','full_goal_complete']
DEPS=['kext_port_tools.py','kernel_native_reader.py','recover_kext_cold_init.py','lskd_values_symbolic.py',
 'audit_secure_tunnel_table_insertion.py','recover_userclient_input_reader.py','audit_userclient_input_reader.py',
 'userclient_input_reader_checks.json','userclient_input_reader_audit.json',
 'userclient_record_nodes_checks.json','userclient_record_nodes_audit.json',
 'userclient_record_writer_checks.json','userclient_record_writer_audit.json']

def build():
 k=Kernel();prior=json.loads(read(ROOT/'userclient_input_reader_checks.json'));container=prior['function_container']
 a,z=(int(container[n],16) for n in ['start','end_exclusive']);raw=k.read(a,z-a)
 assert raw==IMAGE.read(a,z-a) and sha256(raw).hexdigest()==container['sha256'];spans=[]
 ranges=dict(SPANS)
 for label in REUSED:
  row=next(s for s in prior['spans'] if s['label']==label);ranges[label]=(int(row['start'],16),int(row['end_exclusive'],16))
 for label,(a,z) in ranges.items():
  b=k.read(a,z-a);assert b==IMAGE.read(a,z-a);ii=list(CS.disasm(b,a));assert len(ii)*4==len(b)
  spans.append({'label':label,'start':hex(a),'end_exclusive':hex(z),'bytes_hex':b.hex(),
   'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ii]})
 roots={'FL':qword(POOL+0x458)-8,'FR':qword(POOL+0x638)-12,'SL':qword(POOL+0xc08)-8,
  'SR':qword(POOL+0x158)-4,'TL':qword(POOL+0x840),'TR':qword(POOL+0xbb8)};rules=[]
 for a in roots.values():assert k.read(a,256)==IMAGE.read(a,256)
 for name,l,r,key,add,base,bias,div in [('search_callback_value','FL','FR',0x87,-0x93,POOL,-4,None),
  ('retire_data','SL','SR',0x98,0xe85,TABLE,0,0x85d),('retire_node','TL','TR',0x73,0xee4,TABLE,0,0x4d6a)]:
  row=selected(roots[l],roots[r],key,add,base,bias);row.update(name=name,left_name=l,right_name=r)
  row['original_pointer']=pointer(k,int(row['slot'],16));assert (int(row['original_pointer']['target'],16)+bias)&(2**64-1)==int(row['target'],16)
  if div is not None:assert row['original_pointer']['authenticated'] and int(row['original_pointer']['diversity'],16)==div
  rules.append(row)
 a=int(rules[0]['target'],16);b=IMAGE.read(a,64);np,sp=(struct.unpack_from('<Q',b,o)[0] for o in [16,32])
 name,sig=(IMAGE.read(p,64).split(b'\0')[0] for p in [np,sp]);flags,size=struct.unpack_from('<II',b,40)
 assert (name,sig,flags,size)==(b'site.FPTTLVNode',b'1121',0x64,32)
 pn,ps=pointer(k,a+16),pointer(k,a+32);assert (int(pn['target'],16),int(ps['target'],16))==(np,sp)
 assert k.read(np,len(name)+1)==name+b'\0' and k.read(sp,len(sig)+1)==sig+b'\0' and k.read(a+40,8)==b[40:48]
 allocation=json.loads(read(ROOT/'userclient_record_nodes_checks.json'))['allocation_descriptor'];assert b.hex()==allocation['normalized64_bytes_hex'] and hex(a)!=allocation['address']
 allocation_address=int(allocation['address'],16);assert IMAGE.read(allocation_address,64)==b
 assert k.read(allocation_address+40,8)==b[40:48]
 allocation_name,allocation_signature=pointer(k,allocation_address+16),pointer(k,allocation_address+32)
 assert (int(allocation_name['target'],16),int(allocation_signature['target'],16))==(np,sp)
 bp=[pointer(k,TABLE+8*j)|{'index':j} for j in sorted({j for js in BRANCHES.values() for j in js})]
 for r in bp:assert int(r['target'],16)==qword(TABLE+8*r['index'])
 transfers=[]
 for label,(a,z) in ranges.items():
  if label in ['output_root','saved_lookup_roots','saved_typed_root','status_success_gate','status_miss_gate']:continue
  b=k.read(z,4);assert b==IMAGE.read(z,4);i=next(CS.disasm(b,z));assert i.mnemonic in ['braa','blraa']
  transfers.append({'ea':hex(z),'bytes_hex':b.hex(),'mnemonic':i.mnemonic,'operands':i.op_str})
 symbols=k.symbols([int(r['target'],16) for r in rules[1:]])
 for row,expected in zip(rules[1:],['_IOFreeData','_IOFreeTypeImpl']):assert any(s['name']==expected for s in symbols[row['target']])
 return {'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'scope':SCOPE,
  'function_container':container,'dependencies':{n:sha(ROOT/n) for n in DEPS},'spans':spans,'transfers':transfers,
  'banks':{n:{'address':hex(a),'bytes_hex':IMAGE.read(a,256).hex()} for n,a in roots.items()},'bank_rules':rules,
  'branch_pointers':bp,'pool_pointers':[pointer(k,POOL+o) for o in [0x458,0x638,0xc08,0x158,0x840,0xbb8]],
  'retirement_descriptor':{'address':hex(a:=int(rules[0]['target'],16)),'normalized64_bytes_hex':IMAGE.read(a,64).hex(),
   'original64_bytes_hex':k.read(a,64).hex(),'name':name.decode(),'signature':sig.decode(),'flags_u32':flags,'size_bytes':size,
   'name_pointer':pn,'signature_pointer':ps,'allocation_descriptor_address':allocation['address'],
   'allocation_original64_bytes_hex':k.read(allocation_address,64).hex(),'allocation_name_pointer':allocation_name,
   'allocation_signature_pointer':allocation_signature,'normalized_metadata_equal':True},
  'retirement_symbols':symbols,
  'verified_counts':{'source_spans':len(spans),'selected_instructions':sum(len(s['instructions']) for s in spans),
   'reused_reader_spans':len(REUSED),'terminal_transfers':len(transfers),'bank_rules':len(rules),'bank_input_cases':256*len(rules),
   'retirement_descriptor_bytes':size,'alternate_retag_sites':len(RETAGS)},
  'conditional_record_publication_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
