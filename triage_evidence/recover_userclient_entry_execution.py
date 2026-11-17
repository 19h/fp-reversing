#!/usr/bin/env python3
"""Rebuild continuous core-entry source, pointers and defined-byte cases.
O(B+I+256R+C*(B+V+E)) time/space; no native target operation.
"""
import json,struct
from hashlib import sha256
from kext_port_tools import ROOT,SOURCE,IMAGE,CS,POOL,TABLE,qword,selected
from kernel_native_reader import Kernel
from recover_kext_cold_init import pointer
from verify_daemon_reader_record_payloads_publication import read,sha
import probe_userclient_entry_execution as B

P='userclient_entry_execution'
SCOPE='Continuous original _PRnut72j9 entry through stack probing, two declared nonnull register-only allocations, original unsigned address-order helpers, source initialization and NULL/non-NULL input selection, stopping before typed release or the earlier FPTTLV allocation. Defined-byte and CPU epochs are private; full dispatcher processing, marker production, native allocation/lifetime/PAC and daemon transaction correlation remain unknown.'
DEPS=['probe_legacy_stack.py','legacy_stack_contracts.json','kext_port_tools.py','kernel_native_reader.py',
 'recover_kext_cold_init.py','probe_userclient_entry_execution.py','userclient_container_staging_checks.json',
 'userclient_replacement_bootstrap_checks.json','userclient_discriminator_origin_checks.json']
SPANS={'entry_prefix':(B.ENTRY,0xfffffe000a6355b4),'nonnull_initialization':(0xfffffe000a6355b4,0xfffffe000a636408),
 'null_cleanup_frontier':(0xfffffe000a6661bc,0xfffffe000a666264),
 'original_stack_probe':(B.PROBE,B.PROBE+0x34),'unsigned_order_helper':(B.ORDER,B.ORDER+0x14)}
FALSE=['native_target_executed','native_PAC_authenticated','native_allocation_identity_established',
 'native_lifetime_established','whole_dispatcher_reachability_established','native_input_content_validated',
 'original_marker_producer_established','alias_complete_writer_inventory_established',
 'daemon_kext_transaction_correlated','new_Mach_endpoint_established','new_Mach_emission_established','IDB_modified','full_goal_complete']
def string(a):
 b=bytearray()
 for j in range(4096):
  v=IMAGE.read(a+j,1)[0]
  if v==0:return bytes(b)
  b.append(v)
 raise AssertionError('string capture bound')
def descriptor(k,a):
 b=IMAGE.read(a,64);np,sp=[qword(a+o) for o in [16,32]];name,sig=[string(v) for v in [np,sp]];flags,n=struct.unpack_from('<II',b,40)
 ptr=[pointer(k,a+o) for o in [16,32]];assert [int(p['target'],16) for p in ptr]==[np,sp]
 assert k.read(np,len(name)+1)==name+b'\0'and k.read(sp,len(sig)+1)==sig+b'\0'and k.read(a+40,8)==b[40:48]
 return {'address':hex(a),'normalized64_hex':b.hex(),'original64_hex':k.read(a,64).hex(),'name':name.decode(),'signature':sig.decode(),'flags32':flags,'size_bytes':n,'pointer_fields':ptr}
def source(k):
 prior=json.loads(read(ROOT/'userclient_replacement_bootstrap_checks.json'));container=prior['function_container'];raw=k.read(B.ENTRY,B.END-B.ENTRY);assert IMAGE.read(B.ENTRY,len(raw))==raw and sha256(raw).hexdigest()==container['sha256']
 spans=[]
 for name,(a,z) in SPANS.items():
  b=k.read(a,z-a);assert IMAGE.read(a,z-a)==b;ii=list(CS.disasm(b,a));assert len(ii)*4==len(b)
  spans.append({'label':name,'start':hex(a),'end_exclusive':hex(z),'bytes_hex':b.hex(),'instructions':[{'pc':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ii]})
 V=(qword(POOL+0xc08)-8,qword(POOL+0x158)-4);T=(qword(POOL+0x840),qword(POOL+0xbb8));G=(qword(POOL+0x4f0)-4,qword(POOL+0x578)-4);E=(qword(POOL+0xb70),qword(POOL+0xa10));N=(qword(POOL+0xf50)-4,qword(POOL+0xf20)-4)
 specs=[('first_controller',G,0xef,0x144,POOL,0),('second_controller',V,5,-0x11,POOL,-4),('table',V,0x6d,0x20,POOL,-12),
  ('aligned_allocator',T,0x5c,0xe69,TABLE,0),('typed_allocator',G,0xef,0xeb2,TABLE,0),('typed_descriptor',T,0xd8,0x7b,POOL,-8),
  ('workspace_order',N,0x93,0xe35,TABLE,0),('typed_order',V,5,0xef4,TABLE,0),('FPTTLV_allocator',T,0x5c,0xe41,TABLE,0),
  ('FPTTLV_descriptor',E,0x32,0x107,POOL,0),('null_release',V,0x6d,0xf18,TABLE,0),('null_release_descriptor',T,0x73,0x88,POOL,-12)]
 rules=[]
 for name,(l,r),key,add,base,bias in specs:
  assert k.read(l,256)==IMAGE.read(l,256)and k.read(r,256)==IMAGE.read(r,256)
  x=selected(l,r,key,add,base,bias);x.update(name=name,left256_hex=IMAGE.read(l,256).hex(),right256_hex=IMAGE.read(r,256).hex(),original_pointer=pointer(k,int(x['slot'],16)));assert (int(x['original_pointer']['target'],16)+bias)&B.M64==int(x['target'],16);rules.append(x)
 assert [int(rules[j]['target'],16) for j in [0,1]]==B.CONTROLLERS
 pp=[pointer(k,TABLE+8*j)|{'index':j} for j in [0xc26,0xc2c,0x89b]]
 assert [int(r['target'],16) for r in pp]==[0xfffffe000a6661bc,0xfffffe000a6355b4,0xfffffe000a636338]
 descriptors=[descriptor(k,a) for a in [0xfffffe000847bea0,0xfffffe000847ba60,0xfffffe000847bb60]]
 assert [(d['name'],d['flags32'],d['size_bytes']) for d in descriptors]==[('site.AllocType',0xe4,4096),('site.AllocType',0xe4,4096),('site.FPTTLV',0xe4,16)]
 return {'container':container,'spans':spans,'bank_rules':rules,'branch_pointers':pp,'stack_probe_pointer':pointer(k,0xfffffe000847c618),'descriptors':descriptors,'exact_symbols':k.symbols([0xfffffe000c4b9a08,0xfffffe000c4ba154,0xfffffe000c4ba368,B.ORDER])}
def build():
 k=Kernel();s=source(k);rows=[]
 for c in B.cases():
  b=B.Entry(c);r=b.run();rows.append(r);del b
 counts={'cases':len(rows),'null_cases':sum(r['input']['inputs8'][0]==0 for r in rows),'nonnull_cases':sum(r['input']['inputs8'][0]!=0 for r in rows),'source_visits':sum(len(r['source_visits']) for r in rows),'source_reads':sum(len(r['source_reads']) for r in rows),'source_writes':sum(len(r['source_writes']) for r in rows),'source_spans':len(s['spans']),'captured_words':sum(len(r['instructions']) for r in s['spans']),'bank_rules':len(s['bank_rules']),'bank_input_cases':256*len(s['bank_rules']),'API_models_per_case':2}
 return {'generator_sha256':sha(__file__),'source_sha256':sha(SOURCE),'kernel_collection_sha256':k.sha256,'dependencies':{n:sha(ROOT/n) for n in DEPS},'scope':SCOPE,'source':s,'cases':rows,'verified_counts':counts,'continuous_private_entry_prefix_established':True,**{n:False for n in FALSE}}
if __name__=='__main__':
 e=build();(ROOT/(P+'_checks.json')).write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e['verified_counts']),flush=True)
