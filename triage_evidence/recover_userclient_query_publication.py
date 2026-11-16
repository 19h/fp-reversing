#!/usr/bin/env python3
"""Pin query lookup/publication, original retirement requests and return ABI.
O(B+I+256R) extraction time/space; no target execution or IDB mutation.
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
import recover_userclient_record_publication as RP

P='userclient_query_publication'
SCOPE='Conditional query lookup output-slot producer and phase retention cut, shared protected-tag search, miss append, four-position match replacement, original old-data/node retirement requests and saved constructor/request callback return. Native allocation/PAC/lifetime/locking, all failure cleanup effects, whole-command/native reachability, final list contents and daemon transaction identity remain unknown.'
SPANS={
 'query_output_root':(0xfffffe000a635e64,0xfffffe000a635e6c),
 'query_status_success':(0xfffffe000a662b68,0xfffffe000a662b78),
 'query_status_miss':(0xfffffe000a662b78,0xfffffe000a662b88),
 'query_append_prepare':(0xfffffe000a662b88,0xfffffe000a662bc0),
 'query_append_empty':(0xfffffe000a662bc8,0xfffffe000a662bdc),
 'query_append_tail':(0xfffffe000a6654e4,0xfffffe000a665504),
 'query_replace_prepare':(0xfffffe000a663d28,0xfffffe000a663d7c),
 'query_replace_previous':(0xfffffe000a663d84,0xfffffe000a663da0),
 'query_replace_next_gate':(0xfffffe000a663da8,0xfffffe000a663dd4),
 'query_replace_next':(0xfffffe000a663ddc,0xfffffe000a663df8),
 'query_replace_head_gate':(0xfffffe000a663e00,0xfffffe000a663e28),
 'query_replace_head':(0xfffffe000a663e30,0xfffffe000a663e4c),
 'query_replace_tail_gate':(0xfffffe000a663e54,0xfffffe000a663e90),
 'query_replace_tail':(0xfffffe000a663e98,0xfffffe000a663eac),
 'query_retire_gate':(0xfffffe000a663eb4,0xfffffe000a663eec),
 'query_retire_data_request':(0xfffffe000a663ef4,0xfffffe000a663f48),
 'query_retire_data_return':(0xfffffe000a663f4c,0xfffffe000a663f74),
 'query_retire_node_request':(0xfffffe000a663f7c,0xfffffe000a663ffc),
 'query_retire_node_return':(0xfffffe000a664000,0xfffffe000a664044),
 'query_unexpected_status':(0xfffffe000a664048,0xfffffe000a664070),
 'query_constructor_return':(0xfffffe000a66421c,0xfffffe000a66422c),
 'query_request_return':(0xfffffe000a664234,0xfffffe000a664260)}
REUSED=RP.REUSED
NO_TRANSFER={'query_output_root','query_status_success','query_status_miss'}
BRANCHES={pc:js for pc,js in RP.BRANCHES.items() if pc in [
 0xfffffe000a662ac0,0xfffffe000a662ae8,0xfffffe000a662bf4,0xfffffe000a662c28,
 0xfffffe000a662c88,0xfffffe000a656ef4,0xfffffe000a63713c,0xfffffe000a63d66c,
 0xfffffe000a63d694,0xfffffe000a662c50]}
BRANCHES[0xfffffe000a662ac0]=[0x6c]
BRANCHES.update({0xfffffe000a662bb8:[0xd20,0xd6a],0xfffffe000a662bcc:[0x63d],0xfffffe000a6654f4:[0x63d]})
BRANCHES.update({0xfffffe000a664054:[0x871],0xfffffe000a663d74:[0x782,0x79a],
 0xfffffe000a663dc8:[0x8a4,0x8dc],0xfffffe000a663e20:[0x88f,0xa0b],0xfffffe000a663e44:[0x88f],
 0xfffffe000a663e88:[0x554,0x569],0xfffffe000a663ea4:[0x569],0xfffffe000a663ee4:[0x9f4,0xa01],
 0xfffffe000a66401c:[0x63d],0xfffffe000a663f6c:[0x6fb],0xfffffe000a663df0:[0x8a4],0xfffffe000a663d98:[0x40b]})
RETAGS=RP.RETAGS
BANK_PCS={'search_callback_value':RP.BANK_PCS['search_callback_value'],
 'query_retire_data':(0xfffffe000a663f1c,0xfffffe000a663f2c,0xfffffe000a663f40),
 'query_retire_node':(0xfffffe000a663f98,0xfffffe000a663fa8,0xfffffe000a663fb8),
 'query_retire_descriptor':(0xfffffe000a663fcc,0xfffffe000a663fd8,0xfffffe000a663ff0)}
DEPS=['userclient_query_writer_checks.json','userclient_query_writer_audit.json',
 'userclient_query_records_checks.json','userclient_query_records_audit.json',
 'userclient_record_publication_checks.json','userclient_record_publication_audit.json',
 'userclient_serializer_extent_checks.json','userclient_serializer_extent_audit.json',
 'recover_userclient_record_publication.py','audit_userclient_record_publication.py',
 'audit_userclient_input_reader.py','audit_secure_tunnel_table_insertion.py',
 'lskd_values_symbolic.py','kext_port_tools.py','kernel_native_reader.py','recover_kext_cold_init.py']
FALSE=['native_target_executed','IDB_modified','native_PAC_authenticated','native_storage_identity_established',
 'native_allocator_effects_established','native_ownership_established','native_locking_established',
 'all_failure_cleanup_established','whole_command_reachability_established','final_list_contents_established',
 'daemon_kext_transaction_correlated','new_Mach_port_endpoint_established','full_goal_complete']

def build():
 k=Kernel();old=json.loads(read(ROOT/'userclient_query_writer_checks.json'));container=old['function_container']
 a,z=(int(container[n],16) for n in ['start','end_exclusive']);raw=k.read(a,z-a)
 assert raw==IMAGE.read(a,z-a) and sha256(raw).hexdigest()==container['sha256']
 prior=json.loads(read(ROOT/'userclient_record_publication_checks.json'));ranges=dict(SPANS)
 for label in REUSED:
  r=next(s for s in prior['spans'] if s['label']==label);ranges[label]=(int(r['start'],16),int(r['end_exclusive'],16))
 spans=[];transfers=[]
 for label,(a,z) in ranges.items():
  b=k.read(a,z-a);assert b==IMAGE.read(a,z-a);ii=list(CS.disasm(b,a));assert len(ii)*4==len(b)
  spans.append({'label':label,'start':hex(a),'end_exclusive':hex(z),'bytes_hex':b.hex(),
   'instructions':[{'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ii]})
  if label not in NO_TRANSFER:
   b=k.read(z,4);assert b==IMAGE.read(z,4);i=next(CS.disasm(b,z));assert i.mnemonic in ['braa','blraa']
   transfers.append({'label':label,'ea':hex(z),'bytes_hex':b.hex(),'mnemonic':i.mnemonic,'operands':i.op_str})
 roots={'FL':0xfffffe000792fcc0,'FR':0xfffffe00079391f0,'BL':0xfffffe0007949fd0,'BR':0xfffffe000792ffc0,
  'TL':0xfffffe0007949dd0,'TR':0xfffffe000792fbc0}
 for a in roots.values():assert k.read(a,256)==IMAGE.read(a,256)
 rules=[]
 for name,l,r,key,add,base,bias,div in [('search_callback_value','FL','FR',0x87,-0x93,POOL,-4,None),
  ('query_retire_data','BL','BR',0xef,0xeb9,TABLE,0,0x85d),('query_retire_node','TL','TR',0x16,0xea3,TABLE,0,0x4d6a),
  ('query_retire_descriptor','TL','TR',0xd8,0x172,POOL,-4,None)]:
  row=selected(roots[l],roots[r],key,add,base,bias);row.update(name=name,left_name=l,right_name=r,original_pointer=pointer(k,int(row['slot'],16)))
  assert (int(row['original_pointer']['target'],16)+bias)&(2**64-1)==int(row['target'],16)
  if div is not None:assert int(row['original_pointer']['diversity'],16)==div
  rules.append(row)
 desc=int(rules[-1]['target'],16);b=IMAGE.read(desc,64);pn,ps=pointer(k,desc+16),pointer(k,desc+32)
 name,sig=(IMAGE.read(int(p['target'],16),64).split(b'\0')[0] for p in [pn,ps]);flags,size=struct.unpack_from('<II',b,40)
 assert (name,sig,flags,size)==(b'site.FPTTLVNode',b'1121',0x64,32)
 for p,s in [(pn,name),(ps,sig)]:assert k.read(int(p['target'],16),len(s)+1)==s+b'\0'
 assert k.read(desc+40,8)==b[40:48]
 alloc=json.loads(read(ROOT/'userclient_query_records_checks.json'))['typed_descriptor'];aa=int(alloc['address'],16)
 assert IMAGE.read(aa,64)==b and k.read(aa+40,8)==b[40:48] and aa!=desc
 bp=[pointer(k,TABLE+8*j)|{'index':j} for j in sorted({j for js in BRANCHES.values() for j in js})]
 for p in bp:assert int(p['target'],16)==qword(TABLE+8*p['index'])
 inventory=[]
 for i in DEC.disasm(raw,int(container['start'],16)):
  for o in i.operands:
   if o.type==ARM64_OP_MEM and i.reg_name(o.mem.base)=='sp' and o.mem.disp==0x348:
    inventory.append({'ea':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str})
 symbols=k.symbols([int(rules[j]['target'],16) for j in [1,2]])
 for j,n in [(1,'_IOFreeData'),(2,'_IOFreeTypeImpl')]:assert any(s['name']==n for s in symbols[rules[j]['target']])
 return {'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,
  'scope':SCOPE,'dependencies':{n:sha(ROOT/n) for n in DEPS},'function_container':container,
  'spans':spans,'transfers':transfers,'branch_pointers':bp,'bank_rules':rules,
  'banks':{n:{'address':hex(a),'bytes_hex':IMAGE.read(a,256).hex()} for n,a in roots.items()},
  'retirement_descriptor':{'address':hex(desc),'normalized64_bytes_hex':b.hex(),'original64_bytes_hex':k.read(desc,64).hex(),
   'name':name.decode(),'signature':sig.decode(),'flags_u32':flags,'size_bytes':size,'name_pointer':pn,'signature_pointer':ps,
   'allocation_descriptor_address':alloc['address'],'normalized_metadata_equal':True},
  'retirement_symbols':symbols,'literal_output_slot_inventory':inventory,
  'verified_counts':{'source_spans':len(spans),'selected_instructions':sum(len(s['instructions']) for s in spans),
   'terminal_transfers':len(transfers),'original_branch_pointers':len(bp),'bank_rules':len(rules),
   'bank_input_cases':256*len(rules),'nominal_pointer_guards':len(RETAGS),'retirement_node_bytes':size,
   'inventoried_output_slot_accesses':len(inventory)},
  'conditional_query_publication_contract_established':True,**{n:False for n in FALSE}}

if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
